package networkrelay

import (
	"bytes"
	"context"
	"errors"
	"fmt"
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
	a, err := newAuthenticator([]User{{"alice", testHash}})
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

func TestSharedCredentialWaitersBounded(t *testing.T) {
	a, err := newAuthenticator([]User{{"alice", testHash}})
	if err != nil {
		t.Fatal(err)
	}
	for range cap(a.slots) {
		a.slots <- struct{}{}
	}
	defer func() {
		for range cap(a.slots) {
			<-a.slots
		}
	}()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, cap(authenticationPending))
	for range cap(authenticationPending) {
		go func() { _, err := a.verify(ctx, BasicAuthorization("unknown", "same")); done <- err }()
	}
	deadline := time.Now().Add(2 * time.Second)
	for len(authenticationPending) != cap(authenticationPending) {
		if time.Now().After(deadline) {
			t.Fatal("waiters did not arrive")
		}
		time.Sleep(time.Millisecond)
	}
	if _, err := a.verify(ctx, BasicAuthorization("unknown", "same")); !errors.Is(err, errAuthBusy) {
		t.Fatalf("unbounded same-header waiters: %v", err)
	}
	cancel()
	for range cap(authenticationPending) {
		if err := <-done; !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	}
	if len(authenticationPending) != 0 {
		t.Fatal("admission permits leaked")
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
