package networkrelay

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
	"golang.org/x/time/rate"
)

func TestAuthenticationFailureLogFloodBounded(t *testing.T) {
	a, err := newAuthenticator([]User{{Name: "alice", PasswordHash: testHash}})
	if err != nil {
		t.Fatal(err)
	}
	core, logs := observer.New(zap.WarnLevel)
	h := &Handler{auth: a, logger: zap.New(core)}
	time.Sleep(250 * time.Millisecond) // allow one global log token after earlier tests
	for range 200 {
		r := httptest.NewRequest(http.MethodConnect, "http://example.net:443", nil)
		r.Header.Set("Authorization", "Basic !")
		_ = h.ServeHTTP(httptest.NewRecorder(), r, nil)
	}
	if n := logs.Len(); n == 0 || n > 20 {
		t.Fatalf("cached malformed credentials produced %d warnings", n)
	}
}

func TestLogBudgetReportsSuppression(t *testing.T) {
	b := &logBudget{limiter: rate.NewLimiter(100, 1)}
	if _, ok := b.allow(); !ok {
		t.Fatal("initial log missing")
	}
	for range 10 {
		if _, ok := b.allow(); ok {
			t.Fatal("unbounded log burst")
		}
	}
	time.Sleep(20 * time.Millisecond)
	if dropped, ok := b.allow(); !ok || dropped != 10 {
		t.Fatalf("lost suppression accounting: %d, %v", dropped, ok)
	}
}

func TestTrafficBudgetSurvivesReload(t *testing.T) {
	a, err := newAuthenticator([]User{{Name: "alice", PasswordHash: testHash}, {Name: "bob", PasswordHash: testHash}})
	if err != nil {
		t.Fatal(err)
	}
	makeHandler := func(id string) *Handler {
		return &Handler{RelayID: id, auth: a, UDPTemplate: DefaultUDPTemplate,
			MaxUDPPacketsPerSecondPerUser: 1,
			traffic:                       map[string]*trafficBudget{"alice": newTrafficBudget(0, 1), "bob": newTrafficBudget(0, 1)}}
	}
	first := makeHandler("traffic-reload-test")
	registerHandler(first)
	defer unregisterHandler(first)
	if !first.traffic["alice"].allowUDP(1) || first.traffic["alice"].allowUDP(1) {
		t.Fatal("packet burst not enforced")
	}
	if !first.traffic["bob"].allowUDP(1) {
		t.Fatal("alice consumed bob's budget")
	}
	second := makeHandler(first.RelayID)
	registerHandler(second)
	defer unregisterHandler(second)
	unregisterHandler(first)
	if second.traffic["alice"] != first.traffic["alice"] || second.traffic["alice"].allowUDP(1) {
		t.Fatal("reload renewed rate burst")
	}
	changed := makeHandler(first.RelayID)
	changed.MaxUDPPacketsPerSecondPerUser = 2
	if sameRelay(second, changed) {
		t.Fatal("changed traffic policy grandfathered old tunnels")
	}
	other := makeHandler("different-traffic-tenant")
	registerHandler(other)
	defer unregisterHandler(other)
	if !other.traffic["alice"].allowUDP(1) {
		t.Fatal("budget crossed security domains")
	}
}

func TestTCPUserTrafficBudgetAllVersions(t *testing.T) {
	port, _ := startRelay(t, map[string]any{"max_bytes_per_second_per_user": 256 << 10}, nil)
	const size = 512 << 10
	sink := newSinkServer(t, 42, size)
	for _, v := range versions {
		t.Run(v.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			s, done, err := v.openTCP(ctx, client(port), sink.addr)
			if err != nil {
				t.Fatal(err)
			}
			defer done()
			defer s.Close()
			start := time.Now()
			up, down := transfer(t, s, 41, size, sink)
			elapsed := time.Since(start)
			if up != patternHash(41, size) || down != patternHash(42, size) {
				t.Fatal("shaping corrupted data")
			}
			if elapsed < 3200*time.Millisecond {
				t.Fatalf("per-user aggregate byte budget bypassed: %v", elapsed)
			}
		})
	}
}

func TestTrafficWaitCancellation(t *testing.T) {
	b := newTrafficBudget(1, 0)
	if !b.bytes.AllowN(time.Now(), 2*tcpBufferSize) {
		t.Fatal("initial burst")
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- b.waitTCP(ctx, tcpBufferSize) }()
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("rate wait ignored cancellation")
	}
}

func TestUDPTrafficBudgetAllVersions(t *testing.T) {
	port, _ := startRelay(t, map[string]any{"max_udp_packets_per_second_per_user": 1}, nil)
	sock, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { sock.Close() })
	host, p, _ := net.SplitHostPort(sock.LocalAddr().String())
	received := make(chan struct{}, 8)
	go func() {
		buf := make([]byte, 65536)
		for {
			n, peer, err := sock.ReadFrom(buf)
			if err != nil {
				return
			}
			received <- struct{}{}
			sock.WriteTo(buf[:n], peer)
		}
	}()
	for _, v := range versions {
		t.Run(v.name, func(t *testing.T) {
			time.Sleep(time.Second)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			u, done, err := v.openUDP(ctx, client(port), host, p)
			if err != nil {
				t.Fatal(err)
			}
			defer done()
			defer u.Close()
			// Upload consumes the only token; echo is a separate direction
			// on the same budget and is dropped without aborting the tunnel.
			if err := u.Send([]byte("limited")); err != nil {
				t.Fatal(err)
			}
			select {
			case <-received:
			case <-time.After(time.Second):
				t.Fatal("allowed upload never reached target")
			}
			rctx, stop := context.WithTimeout(ctx, 150*time.Millisecond)
			_, err = u.Receive(rctx)
			stop()
			if !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("UDP budget not enforced: %v", err)
			}
		})
	}
}

// A peer reset cancels credit waits even if the parent context stays alive.
type creditWaitClient struct {
	io.Reader
	reset chan struct{}
}

func (c *creditWaitClient) Write(p []byte) (int, error) { return len(p), nil }
func (c *creditWaitClient) closeWrite() bool            { return false }
func (c *creditWaitClient) abort(abortReason)           {}
func (c *creditWaitClient) close()                      {}
func (c *creditWaitClient) gone() <-chan struct{}       { return c.reset }

func TestPeerResetCancelsTrafficWait(t *testing.T) {
	budget := newTrafficBudget(1, 0)
	budget.bytes.AllowN(time.Now(), 2*tcpBufferSize)
	conn, err := net.Dial("tcp", echoTCP(t))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	cc := &creditWaitClient{Reader: bytes.NewReader(make([]byte, tcpBufferSize)), reset: make(chan struct{})}
	done := make(chan struct{})
	go func() {
		pumpTCPLimited(context.Background(), cc, conn.(*net.TCPConn), budget)
		close(done)
	}()
	deadline := time.Now().Add(time.Second)
	for budget.bytes.Tokens() >= 0 {
		if time.Now().After(deadline) {
			t.Fatal("worker did not reserve credits")
		}
		time.Sleep(time.Millisecond)
	}
	close(cc.reset)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("peer reset did not end pump")
	}
	deadline = time.Now().Add(time.Second)
	for budget.bytes.Tokens() < -1 {
		if time.Now().After(deadline) {
			t.Fatal("credit wait remained after pump returned")
		}
		time.Sleep(time.Millisecond)
	}
}
