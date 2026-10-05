package networkrelay

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"golang.org/x/net/dns/dnsmessage"
)

func TestHashVerificationBudget(t *testing.T) {
	for _, replacement := range []string{"m=65537", "t=11", "p=5"} {
		old := "m=19456"
		if strings.HasPrefix(replacement, "t=") {
			old = "t=2"
		}
		if strings.HasPrefix(replacement, "p=") {
			old = "p=1"
		}
		if _, err := parsePasswordHash(strings.Replace(testHash, old, replacement, 1)); err == nil {
			t.Fatalf("over-budget hash accepted: %s", replacement)
		}
	}
}

func TestRelaySecurityDomains(t *testing.T) {
	a, err := newAuthenticator([]User{{Name: "alice", PasswordHash: testHash}})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, first, second string
		policyChange, keep  bool
	}{
		{"implicit scopes revoke", "", "", false, false},
		{"different tenants revoke", "tenant-a", "tenant-b", false, false},
		{"same tenant reload retains", "tenant-a", "tenant-a", false, true},
		{"policy change revokes", "tenant-a", "tenant-a", true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			first := &Handler{RelayID: tc.first, auth: a, UDPTemplate: DefaultUDPTemplate}
			other := &Handler{RelayID: tc.second, auth: a, UDPTemplate: DefaultUDPTemplate}
			if tc.policyChange {
				other.BlockedPorts = &[]int{443}
			}
			registerHandler(first)
			registerHandler(other)
			defer unregisterHandler(other)
			ctx, cancel := context.WithCancelCause(context.Background())
			defer cancel(nil)
			lt := &liveTunnel{acct: a.accountOf("alice"), owner: first, cancel: cancel}
			if !addTunnel(lt) {
				t.Fatal("initial add")
			}
			defer removeTunnel(lt)
			unregisterHandler(first)
			if tc.keep != (ctx.Err() == nil) {
				t.Fatalf("cancelled=%v, want keep=%v", ctx.Err(), tc.keep)
			}
			late := &liveTunnel{acct: lt.acct, owner: first, cancel: cancel}
			if added := addTunnel(late); added != tc.keep {
				t.Fatalf("late add=%v", added)
			}
			removeTunnel(late)
		})
	}
}

func TestPerUserTunnelBudget(t *testing.T) {
	h := &Handler{RelayID: "quota-test", MaxTunnelsPerUser: 1}
	release, ok := reserveUserTunnel(h, "alice")
	if !ok {
		t.Fatal("first reservation")
	}
	defer release()
	if _, ok := reserveUserTunnel(&Handler{RelayID: h.RelayID, MaxTunnelsPerUser: 1}, "alice"); ok {
		t.Fatal("reload bypasses quota")
	}
	other, ok := reserveUserTunnel(h, "bob")
	if !ok {
		t.Fatal("alice exhausted bob's quota")
	}
	other()
	release()
	release() // cleanup must be idempotent
	again, ok := reserveUserTunnel(h, "alice")
	if !ok {
		t.Fatal("quota leaked")
	}
	again()
}

// Requests waiting for another request's verification of the same header
// cost no hash, so they take none of the costly-work places (G-2). A device
// opening many tunnels at once fits within the separate cheap-waiter bound.
func TestSharedCredentialWaitersAreNotRefused(t *testing.T) {
	a, err := newAuthenticator([]User{{Name: "alice", PasswordHash: testHash}})
	if err != nil {
		t.Fatal(err)
	}
	for range cap(a.slots) {
		a.slots <- struct{}{}
	}
	good := BasicAuthorization("alice", testPassword)
	verified.Lock()
	delete(verified.m, headerID(good))
	verified.Unlock()
	conn := &connState{}
	from := requester{ip: netip.MustParseAddr("192.0.2.77"), conn: conn}
	waiters := 3 * cap(authenticationPending)
	done := make(chan error, waiters)
	for range waiters {
		go func() { _, err := a.verifyFrom(context.Background(), good, from); done <- err }()
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		a.mu.Lock()
		n := len(a.inflight)
		a.mu.Unlock()
		if n == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the verification did not start")
		}
		time.Sleep(time.Millisecond)
	}
	if n := len(authenticationPending); n != 1 {
		t.Fatalf("%d places taken for one header", n)
	}
	if n := conn.pending.Load(); n != 1 {
		t.Fatalf("the connection counts %d pending verifications for one header", n)
	}
	for range cap(a.slots) {
		<-a.slots
	}
	for range waiters {
		if err := <-done; err != nil {
			t.Fatalf("a waiter was refused: %v", err)
		}
	}
	if n := conn.pending.Load(); n != 0 {
		t.Fatalf("pending count leaked: %d", n)
	}
}

func TestSharedCredentialWaitersBoundedAndCancelled(t *testing.T) {
	a, err := newAuthenticator([]User{{Name: "alice", PasswordHash: testHash}})
	if err != nil {
		t.Fatal(err)
	}
	releaseSlots := fillSlots(a)
	defer releaseSlots()
	leaderCtx, cancelLeader := context.WithCancel(context.Background())
	defer cancelLeader()
	waiterCtx, cancelWaiters := context.WithCancel(context.Background())
	defer cancelWaiters()
	from := requester{conn: &connState{}}
	header := BasicAuthorization("alice", RandomPassword())
	leaderDone := make(chan error, 1)
	go func() { _, err := a.verifyFrom(leaderCtx, header, from); leaderDone <- err }()
	deadline := time.Now().Add(5 * time.Second)
	for {
		a.mu.Lock()
		n := len(a.inflight)
		a.mu.Unlock()
		if n == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("leader did not start")
		}
		time.Sleep(time.Millisecond)
	}
	waiters := cap(authenticationWaiters)
	done := make(chan error, waiters)
	for range waiters {
		go func() { _, err := a.verifyFrom(waiterCtx, header, from); done <- err }()
	}
	for len(authenticationWaiters) != waiters {
		if time.Now().After(deadline) {
			t.Fatalf("only %d/%d waiters admitted", len(authenticationWaiters), waiters)
		}
		time.Sleep(time.Millisecond)
	}
	if _, err := a.verifyFrom(context.Background(), header, from); !errors.Is(err, errAuthBusy) {
		t.Fatalf("excess shared waiter was not refused: %v", err)
	}
	if len(authenticationPending) != 1 || from.conn.pending.Load() != 1 {
		t.Fatal("shared waiters charged costly verification or connection places")
	}
	cancelWaiters()
	for range waiters {
		if err := <-done; !errors.Is(err, context.Canceled) {
			t.Fatalf("cancelled waiter: %v", err)
		}
	}
	if len(authenticationWaiters) != 0 {
		t.Fatal("cancelled shared waiters leaked places")
	}
	cancelLeader()
	if err := <-leaderDone; !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled leader: %v", err)
	}
	if len(authenticationPending) != 0 || from.conn.pending.Load() != 0 {
		t.Fatal("cancelled leader leaked verification places")
	}
}

type dnsCheckPeer struct {
	query  []byte
	mutate func(*dnsmessage.Message)
}

func (p *dnsCheckPeer) Send(b []byte) error { p.query = append([]byte(nil), b...); return nil }
func (p *dnsCheckPeer) Close() error        { return nil }
func (p *dnsCheckPeer) Receive(context.Context) ([]byte, error) {
	var m dnsmessage.Message
	if err := m.Unpack(p.query); err != nil {
		return nil, err
	}
	m.Response = true
	m.Answers = []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: m.Questions[0].Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}, Body: &dnsmessage.AResource{A: [4]byte{203, 0, 113, 1}}}}
	p.mutate(&m)
	return m.Pack()
}

func TestDNSHealthCheckValidatesResponse(t *testing.T) {
	for _, tc := range []struct {
		name   string
		valid  bool
		mutate func(*dnsmessage.Message)
	}{
		{"valid", true, func(*dnsmessage.Message) {}},
		{"SERVFAIL", false, func(m *dnsmessage.Message) { m.RCode = dnsmessage.RCodeServerFailure }},
		{"NXDOMAIN", false, func(m *dnsmessage.Message) { m.RCode = dnsmessage.RCodeNameError }},
		{"truncated", false, func(m *dnsmessage.Message) { m.Truncated = true }},
		{"query not response", false, func(m *dnsmessage.Message) { m.Response = false }},
		{"no question", false, func(m *dnsmessage.Message) { m.Questions = nil }},
		{"no answer", false, func(m *dnsmessage.Message) { m.Answers = nil }},
		{"wrong question", false, func(m *dnsmessage.Message) { m.Questions[0].Name = dnsmessage.MustNewName("unrelated.example.") }},
		{"unrelated answer", false, func(m *dnsmessage.Message) { m.Answers[0].Header.Name = dnsmessage.MustNewName("unrelated.example.") }},
		{"CNAME", true, func(m *dnsmessage.Message) {
			alias := dnsmessage.MustNewName("alias.example.")
			m.Answers[0].Header.Name = alias
			m.Answers = append(m.Answers, dnsmessage.Resource{Header: dnsmessage.ResourceHeader{Name: m.Questions[0].Name, Type: dnsmessage.TypeCNAME, Class: dnsmessage.ClassINET}, Body: &dnsmessage.CNAMEResource{CNAME: alias}})
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			_, err := dnsThrough(ctx, &dnsCheckPeer{mutate: tc.mutate}, nil, "example.com")
			if (err == nil) != tc.valid {
				t.Fatalf("valid=%v: %v", tc.valid, err)
			}
		})
	}
}

func FuzzCapsuleBoundaries(f *testing.F) {
	for _, seed := range [][]byte{{0, 3, 0x40, 0, 'A', 0, 2, 0, 'B'}, {0, 1, 0x40}, {0, 0}, appendDatagramCapsule(nil, []byte("hello"))} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		_ = readCapsules(bytes.NewReader(b), func(p []byte) {
			if len(p) > maxUDPPayload {
				t.Fatal(fmt.Sprintf("oversized UDP payload %d", len(p)))
			}
		})
	})
}

func TestConnectionLimitSharesPerClient(t *testing.T) {
	l := newConnectionLimit(3, 2)
	a := &net.UDPAddr{IP: net.ParseIP("192.0.2.1"), Port: 1}
	b := &net.UDPAddr{IP: net.ParseIP("2001:db8::1"), Port: 1}
	sameSubnet := &net.UDPAddr{IP: net.ParseIP("2001:db8::2"), Port: 2}
	r1, ok1 := l.acquire(a)
	_, ok2 := l.acquire(a)
	if _, ok := l.acquire(a); !ok1 || !ok2 || ok {
		t.Fatal("a client's share is not two connections")
	}
	_, ok3 := l.acquire(b)
	if _, ok := l.acquire(sameSubnet); !ok3 || ok {
		t.Fatal("the total is not three connections")
	}
	r1()
	r1() // releasing twice frees one slot
	if _, ok := l.acquire(sameSubnet); !ok || l.open() != 3 {
		t.Fatalf("released slot not reused (open %d)", l.open())
	}
}

// h3ClientLimit sets the per-client share of HTTP/3 connections for a test.
func h3ClientLimit(t *testing.T, n int) {
	h3Connections.mu.Lock()
	old := h3Connections.maxPerClient
	h3Connections.maxPerClient = n
	h3Connections.mu.Unlock()
	t.Cleanup(func() {
		h3Connections.mu.Lock()
		h3Connections.maxPerClient = old
		h3Connections.mu.Unlock()
	})
}

func TestH3ConnectionsPerClient(t *testing.T) {
	h3ClientLimit(t, 2)
	port, _ := startRelay(t, nil, nil)
	get := [][2]string{{":method", "GET"}, {":scheme", "https"}, {":authority", "relay.test"}, {":path", "/"}}
	first, second := dialRawH3(t, port), dialRawH3(t, port)
	for _, h := range []*rawH3{first, second} {
		if _, _, rsp := h.request(get); rsp.status != "200" {
			t.Fatal(rsp.status)
		}
	}
	if code := dialRawH3(t, port).connError(); code != quic.ApplicationErrorCode(0x107) {
		t.Fatalf("close code %x, want H3_EXCESSIVE_LOAD", code)
	}
	first.conn.CloseWithError(0, "")
	deadline := time.Now().Add(5 * time.Second)
	for h3Connections.open() > 1 {
		if time.Now().After(deadline) {
			t.Fatal("closed connection still counted")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if _, _, rsp := dialRawH3(t, port).request(get); rsp.status != "200" {
		t.Fatal(rsp.status)
	}
}

// retryCounter counts QUIC Retry packets a client receives.
type retryCounter struct {
	net.PacketConn
	retries atomic.Int32
}

func (c *retryCounter) ReadFrom(b []byte) (int, net.Addr, error) {
	n, a, err := c.PacketConn.ReadFrom(b)
	// Long header, QUIC version 1, packet type Retry (RFC 9000 §17.2.5).
	if n > 5 && b[0]&0xb0 == 0xb0 && binary.BigEndian.Uint32(b[1:5]) == 1 {
		c.retries.Add(1)
	}
	return n, a, err
}

// Under a handshake flood, new clients are sent a Retry and still connect;
// otherwise the handshake takes no extra round trip.
func TestQUICRetryUnderHandshakeLoad(t *testing.T) {
	port, _ := startRelay(t, nil, nil)
	connect := func() int32 {
		pc, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer pc.Close()
		rc := &retryCounter{PacketConn: pc}
		c := client(port)
		c.PacketConn = rc
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		h, err := c.dialH3(ctx)
		if err != nil {
			t.Fatal(err)
		}
		h.Close()
		return rc.retries.Load()
	}
	if n := connect(); n != 0 {
		t.Fatalf("%d Retry packets without load", n)
	}
	handshakes.Lock()
	handshakes.tokens, handshakes.last = 0, time.Now().Add(time.Hour)
	handshakes.Unlock()
	t.Cleanup(func() {
		handshakes.Lock()
		handshakes.tokens, handshakes.last = handshakeBurst, time.Time{}
		handshakes.Unlock()
	})
	// One Retry per Initial packet: a ClientHello can span two.
	if n := connect(); n < 1 {
		t.Fatal("no Retry under load")
	}
}

func TestDefaultMaxTunnelsFollowsMemory(t *testing.T) {
	for _, c := range []struct {
		memory uint64
		want   int
	}{{0, 4096}, {256 << 20, 512}, {1 << 30, 1024}, {8 << 30, 8192}, {64 << 30, 20000}} {
		if got := defaultMaxTunnels(c.memory); got != c.want {
			t.Errorf("defaultMaxTunnels(%d MiB) = %d, want %d", c.memory>>20, got, c.want)
		}
	}
	if _, err := os.Stat("/proc/meminfo"); err == nil && totalMemory() == 0 {
		t.Error("MemTotal not read from /proc/meminfo")
	}
}
