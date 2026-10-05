package networkrelay

import (
	"bytes"
	"context"
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"

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
			lt := &liveTunnel{acct: account{name: "alice", hash: testHash}, owner: first, cancel: cancel}
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
// cost no hash, so they take none of the limited places (G-2): a device
// opening many tunnels at once with new credentials is never refused.
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
