package networkrelay

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

func reviewTCPPair(t *testing.T) (*net.TCPConn, *net.TCPConn) {
	t.Helper()
	l, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	c, err := net.DialTCP("tcp", nil, l.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatal(err)
	}
	p, err := l.AcceptTCP()
	if err != nil {
		c.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close(); p.Close() })
	return c, p
}

func reviewDialAddresses(n int) []netip.AddrPort {
	addrs := make([]netip.AddrPort, n)
	for i := range addrs {
		addrs[i] = netip.AddrPortFrom(netip.MustParseAddr("192.0.2.1"), uint16(10000+i))
	}
	return addrs
}

func TestReviewDialBoundsBlackholesAndReachesLaterAddress(t *testing.T) {
	winner, peer := reviewTCPPair(t)
	var active, peak, started atomic.Int64
	start := time.Now()
	got, err := dialTCPWith(context.Background(), reviewDialAddresses(9), 5*time.Second,
		func(ctx context.Context, addr netip.AddrPort) (*net.TCPConn, error) {
			started.Add(1)
			n := active.Add(1)
			defer active.Add(-1)
			for old := peak.Load(); n > old && !peak.CompareAndSwap(old, n); old = peak.Load() {
			}
			if addr.Port() == 10008 {
				return winner, nil
			}
			<-ctx.Done() // SYN blackhole: no OS error before cancellation
			return nil, ctx.Err()
		})
	if err != nil || got != winner {
		t.Fatalf("reachable ninth address: %v, %v", got, err)
	}
	if peak.Load() != maxParallelTCPAttempts || active.Load() != 0 || started.Load() != 9 {
		t.Fatalf("pending peak=%d remaining=%d starts=%d", peak.Load(), active.Load(), started.Load())
	}
	if time.Since(start) < 8*attemptDelay {
		t.Fatal("blackholed attempts bypassed the nominal stagger")
	}
	if _, err := got.Write([]byte("winner")); err != nil {
		t.Fatal("cleanup closed the winning connection:", err)
	}
	buf := make([]byte, len("winner"))
	if _, err := io.ReadFull(peer, buf); err != nil || string(buf) != "winner" {
		t.Fatalf("winner data: %q, %v", buf, err)
	}
}

func TestReviewDialFailureAccelerationPreservesMinimumSpacing(t *testing.T) {
	var mu sync.Mutex
	var starts []time.Time
	begin := time.Now()
	_, err := dialTCPWith(context.Background(), reviewDialAddresses(4), 2*time.Second,
		func(context.Context, netip.AddrPort) (*net.TCPConn, error) {
			mu.Lock()
			starts = append(starts, time.Now())
			mu.Unlock()
			return nil, syscall.ECONNREFUSED
		})
	if !errors.Is(err, refuseRefused) || len(starts) != 4 {
		t.Fatalf("failure result=%v starts=%d", err, len(starts))
	}
	if time.Since(begin) < 3*minimumAttemptDelay {
		t.Fatal("accelerated failures skipped the configured pacing")
	}
	for i := 1; i < len(starts); i++ {
		if gap := starts[i].Sub(starts[i-1]); gap < 10*time.Millisecond {
			t.Fatalf("RFC 8305 mandatory minimum violated: %v", gap)
		}
	}
}

func TestReviewDialWinnerJoinsWorkersAndClosesLateLoser(t *testing.T) {
	loser, loserPeer := reviewTCPPair(t)
	winner, _ := reviewTCPPair(t)
	canceled := make(chan struct{})
	allowExit := make(chan struct{})
	release := sync.OnceFunc(func() { close(allowExit) })
	t.Cleanup(release)
	type outcome struct {
		conn *net.TCPConn
		err  error
	}
	done := make(chan outcome, 1)
	go func() {
		conn, err := dialTCPWith(context.Background(), reviewDialAddresses(2), 3*time.Second,
			func(ctx context.Context, addr netip.AddrPort) (*net.TCPConn, error) {
				if addr.Port() == 10001 {
					return winner, nil
				}
				<-ctx.Done()
				close(canceled)
				<-allowExit
				return loser, nil // late success races cancellation
			})
		done <- outcome{conn, err}
	}()
	select {
	case <-canceled:
	case <-time.After(time.Second):
		t.Fatal("winner did not cancel the losing attempt")
	}
	select {
	case <-done:
		t.Fatal("dial returned before its losing worker exited")
	case <-time.After(25 * time.Millisecond):
	}
	release()
	r := <-done
	if r.err != nil || r.conn != winner {
		t.Fatalf("winner result: %v, %v", r.conn, r.err)
	}
	_ = loserPeer.SetReadDeadline(time.Now().Add(time.Second))
	var buf [1]byte
	if _, err := loserPeer.Read(buf[:]); err == nil || isTimeout(err) {
		t.Fatalf("late losing socket remains open: %v", err)
	}
}

func TestReviewDialDeadlineJoinsCancelledWorkers(t *testing.T) {
	canceled := make(chan struct{})
	allowExit := make(chan struct{})
	release := sync.OnceFunc(func() { close(allowExit) })
	t.Cleanup(release)
	done := make(chan error, 1)
	go func() {
		_, err := dialTCPWith(context.Background(), reviewDialAddresses(1), 25*time.Millisecond,
			func(ctx context.Context, _ netip.AddrPort) (*net.TCPConn, error) {
				<-ctx.Done()
				close(canceled)
				<-allowExit
				return nil, ctx.Err()
			})
		done <- err
	}()
	select {
	case <-canceled:
	case <-time.After(time.Second):
		t.Fatal("deadline did not cancel the dial worker")
	}
	select {
	case <-done:
		t.Fatal("deadline returned while its worker still owns resources")
	case <-time.After(25 * time.Millisecond):
	}
	release()
	if err := <-done; !errors.Is(err, refuseTimeout) {
		t.Fatalf("deadline refusal changed: %v", err)
	}
}
