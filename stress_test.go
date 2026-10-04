package networkrelay

// Large transfers and bad networks. The kernel here has no netem, so the
// impairments are made in the test process: a lossy, slow, reordering
// packet conn under the client's QUIC connection, and a TCP proxy that adds
// latency, limits bandwidth, stalls and cuts connections.
//
// RELAY_STRESS_MB sets the transfer size (default 64).

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"io"
	"math/rand/v2"
	"net"
	"os"
	"runtime"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
)

func stressMB() int {
	if s := os.Getenv("RELAY_STRESS_MB"); s != "" {
		n, _ := strconv.Atoi(s)
		if n > 0 {
			return n
		}
	}
	return 64
}

// pattern is a deterministic, incompressible-looking byte stream.
type pattern struct {
	seed uint64
	left int64
	n    uint64
}

func newPattern(seed uint64, size int64) *pattern { return &pattern{seed: seed, left: size} }

func (p *pattern) Read(b []byte) (int, error) {
	if p.left <= 0 {
		return 0, io.EOF
	}
	if int64(len(b)) > p.left {
		b = b[:p.left]
	}
	for i := range b {
		p.n = p.n*6364136223846793005 + p.seed + 1442695040888963407
		b[i] = byte(p.n >> 56)
	}
	p.left -= int64(len(b))
	return len(b), nil
}

func patternHash(seed uint64, size int64) string {
	h := sha256.New()
	io.Copy(h, newPattern(seed, size))
	return hex.EncodeToString(h.Sum(nil))
}

// sinkServer accepts TCP connections, reads everything a client sends,
// then sends `size` bytes of pattern back. It reports the hash of what it
// received.
type sinkServer struct {
	addr     string
	received chan string
	size     int64
	seed     uint64
	slow     atomic.Bool // read slowly, to create back-pressure
}

func newSinkServer(t *testing.T, seed uint64, size int64) *sinkServer {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	s := &sinkServer{addr: l.Addr().String(), received: make(chan string, 64), size: size, seed: seed}
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				h := sha256.New()
				buf := make([]byte, 32*1024)
				for {
					n, err := c.Read(buf)
					h.Write(buf[:n])
					if s.slow.Load() {
						time.Sleep(2 * time.Millisecond)
					}
					if err != nil {
						break
					}
				}
				s.received <- hex.EncodeToString(h.Sum(nil))
				io.Copy(c, newPattern(s.seed, s.size))
				c.(*net.TCPConn).CloseWrite()
			}()
		}
	}()
	return s
}

// transfer sends `size` pattern bytes through s, half-closes, and hashes
// what comes back. Returns (hash of what the sink received, hash of what
// came back).
func transfer(t *testing.T, s stream, seed uint64, size int64, sink *sinkServer) (string, string) {
	t.Helper()
	errs := make(chan error, 1)
	go func() {
		_, err := io.Copy(s, newPattern(seed, size))
		if err == nil {
			err = s.CloseWrite()
		}
		errs <- err
	}()
	h := sha256.New()
	n, rerr := io.Copy(h, s)
	if werr := <-errs; werr != nil {
		t.Fatalf("write: %v", werr)
	}
	if rerr != nil {
		t.Fatalf("read after %d bytes: %v", n, rerr)
	}
	select {
	case got := <-sink.received:
		return got, hex.EncodeToString(h.Sum(nil))
	case <-time.After(10 * time.Second):
		t.Fatal("the sink never finished reading")
	}
	return "", ""
}

func TestLargeTransfers(t *testing.T) {
	port, _ := startRelay(t, nil, nil)
	size := int64(stressMB()) << 20
	sink := newSinkServer(t, 2, size)
	wantUp, wantDown := patternHash(1, size), patternHash(2, size)
	for _, v := range versions {
		t.Run(v.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
			defer cancel()
			s, done, err := v.openTCP(ctx, client(port), sink.addr)
			if err != nil {
				t.Fatal(err)
			}
			defer done()
			defer s.Close()
			start := time.Now()
			gotUp, gotDown := transfer(t, s, 1, size, sink)
			d := time.Since(start)
			if gotUp != wantUp || gotDown != wantDown {
				t.Fatalf("corrupted: up %v, down %v", gotUp == wantUp, gotDown == wantDown)
			}
			t.Logf("%d MiB each way in %v (%.0f MiB/s)", size>>20, d.Round(time.Millisecond), 2*float64(size>>20)/d.Seconds())
		})
	}
	if n := openTunnels.Load(); n != 0 {
		t.Fatalf("%d tunnels still open", n)
	}
}

// Many tunnels at once, on one connection per version.
func TestConcurrentTunnels(t *testing.T) {
	port, _ := startRelay(t, nil, nil)
	size := int64(stressMB()) << 20 / 16
	sink := newSinkServer(t, 4, size)
	wantUp, wantDown := patternHash(3, size), patternHash(4, size)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	c := client(port)
	h3, err := c.dialH3(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer h3.Close()
	h2, err := c.dialH2(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer h2.Close()
	openers := []func() (stream, error){
		func() (stream, error) { return c.openTCPH3(ctx, h3, sink.addr) },
		func() (stream, error) { return c.openTCPH2(ctx, h2, sink.addr) },
		func() (stream, error) { return c.openTCPH1(ctx, sink.addr) },
	}
	var wg sync.WaitGroup
	for i := 0; i < 24; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			s, err := openers[i%3]()
			if err != nil {
				t.Error(err)
				return
			}
			defer s.Close()
			gotUp, gotDown := transfer(t, s, 3, size, sink)
			if gotUp != wantUp || gotDown != wantDown {
				t.Errorf("tunnel %d corrupted", i)
			}
		}(i)
	}
	wg.Wait()
	time.Sleep(200 * time.Millisecond)
	if n := openTunnels.Load(); n != 0 {
		t.Fatalf("%d tunnels still open", n)
	}
}

// A client that stops reading while the target floods must not make the
// relay buffer the flood: flow control pushes back to the target.
func TestBackPressureBoundsMemory(t *testing.T) {
	port, _ := startRelay(t, nil, nil)
	size := int64(256) << 20
	sink := newSinkServer(t, 5, size)
	for _, v := range versions {
		t.Run(v.name, func(t *testing.T) {
			ctx := testCtx(t)
			s, done, err := v.openTCP(ctx, client(port), sink.addr)
			if err != nil {
				t.Fatal(err)
			}
			defer done()
			defer s.Close()
			s.CloseWrite() // the sink starts sending 256 MiB
			buf := make([]byte, 4096)
			if _, err := io.ReadFull(s, buf); err != nil {
				t.Fatal(err)
			}
			runtime.GC()
			var before runtime.MemStats
			runtime.ReadMemStats(&before)
			time.Sleep(2 * time.Second) // the client reads nothing
			runtime.GC()
			var after runtime.MemStats
			runtime.ReadMemStats(&after)
			grew := int64(after.HeapInuse) - int64(before.HeapInuse)
			t.Logf("heap in use grew by %d KiB while the client stalled", grew/1024)
			if grew > 48<<20 {
				t.Fatalf("the relay buffered the flood: heap grew by %d MiB", grew>>20)
			}
		})
	}
}

// ---- impaired QUIC path ----

// lossyPacketConn drops, delays, reorders and duplicates packets in both
// directions. Delays are applied with a timestamp queue per direction, so
// packets are not serialized: a 20 ms delay costs 20 ms, not 20 ms per
// packet.
type lossyPacketConn struct {
	net.PacketConn
	loss      float64       // probability of dropping a packet
	delay     time.Duration // base one-way delay
	jitter    time.Duration
	duplicate float64

	mu        sync.Mutex
	rng       *rand.Rand
	out       *delayQueue
	in        *delayQueue
	done      chan struct{}
	closeOnce sync.Once
	deadline  atomic.Pointer[time.Time]
	deadlineC chan struct{} // a token appears when the deadline changes
	stats     struct{ sent, dropped atomic.Int64 }
}

type delayed struct {
	at   time.Time
	b    []byte
	addr net.Addr
}

// delayQueue releases packets when their time comes, keeping their order
// like a link with a FIFO buffer: a packet never overtakes an earlier one
// unless pushed with reorder set, so jitter changes latency, not order.
type delayQueue struct {
	mu   sync.Mutex
	q    []delayed
	last time.Time
	wake chan struct{}
	out  chan delayed
	done chan struct{}
}

func newDelayQueue(done chan struct{}) *delayQueue {
	q := &delayQueue{wake: make(chan struct{}, 1), out: make(chan delayed, 1024), done: done}
	go q.run()
	return q
}

func (q *delayQueue) push(p delayed, reorder bool) {
	q.mu.Lock()
	if !reorder && p.at.Before(q.last) {
		p.at = q.last
	}
	if p.at.After(q.last) {
		q.last = p.at
	}
	q.q = append(q.q, p)
	q.mu.Unlock()
	select {
	case q.wake <- struct{}{}:
	default:
	}
}

func (q *delayQueue) run() {
	for {
		q.mu.Lock()
		idx := -1
		for i := range q.q {
			if idx < 0 || q.q[i].at.Before(q.q[idx].at) {
				idx = i
			}
		}
		wait := time.Hour
		if idx >= 0 {
			wait = time.Until(q.q[idx].at)
			if wait <= 0 {
				p := q.q[idx]
				q.q = append(q.q[:idx], q.q[idx+1:]...)
				q.mu.Unlock()
				select {
				case q.out <- p:
				case <-q.done:
					return
				}
				continue
			}
		}
		q.mu.Unlock()
		select {
		case <-q.wake:
		case <-time.After(wait):
		case <-q.done:
			return
		}
	}
}

func newLossyPacketConn(t *testing.T, loss float64, delay, jitter time.Duration, duplicate float64) *lossyPacketConn {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	c := &lossyPacketConn{PacketConn: pc, loss: loss, delay: delay, jitter: jitter, duplicate: duplicate,
		rng: rand.New(rand.NewPCG(7, 11)), out: newDelayQueue(done), in: newDelayQueue(done), done: done,
		deadlineC: make(chan struct{}, 1)}
	go func() { // outgoing packets leave when their time comes
		for {
			select {
			case p := <-c.out.out:
				c.PacketConn.WriteTo(p.b, p.addr)
			case <-done:
				return
			}
		}
	}()
	go func() { // incoming packets are read at once and released later
		buf := make([]byte, 65536)
		for {
			n, addr, err := c.PacketConn.ReadFrom(buf)
			if err != nil {
				return
			}
			drop, d, _, reorder := c.impair()
			if drop {
				c.stats.dropped.Add(1)
				continue
			}
			c.in.push(delayed{time.Now().Add(d), append([]byte(nil), buf[:n]...), addr}, reorder)
		}
	}()
	t.Cleanup(func() { c.Close() })
	return c
}

// Preserve the underlying UDP socket's DF capability while keeping all reads
// and writes on the impaired path. Without this, quic-go disables path MTU
// discovery and a minimum-size outer connection can never carry inner QUIC.
func (c *lossyPacketConn) SyscallConn() (syscall.RawConn, error) {
	return c.PacketConn.(interface {
		SyscallConn() (syscall.RawConn, error)
	}).SyscallConn()
}

// Close stops the queues and unblocks ReadFrom, as quic-go's Transport
// expects when it closes the conn it was given.
func (c *lossyPacketConn) Close() error {
	c.closeOnce.Do(func() { close(c.done) })
	return c.PacketConn.Close()
}

// impair draws this packet's fate: dropped, its delay, duplicated, or
// reordered (delivered earlier than packets before it; the reorder rate
// is the duplicate rate, both rare on real links).
func (c *lossyPacketConn) impair() (drop bool, d time.Duration, dup, reorder bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	drop = c.rng.Float64() < c.loss
	d = c.delay
	if c.jitter > 0 {
		d += time.Duration(c.rng.Int64N(int64(c.jitter)))
	}
	dup = c.rng.Float64() < c.duplicate
	reorder = c.rng.Float64() < c.duplicate
	return
}

func (c *lossyPacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	drop, d, dup, reorder := c.impair()
	c.stats.sent.Add(1)
	if drop {
		c.stats.dropped.Add(1)
		return len(b), nil
	}
	p := delayed{time.Now().Add(d), append([]byte(nil), b...), addr}
	if reorder {
		p.at = time.Now().Add(d / 2)
	}
	c.out.push(p, reorder)
	if dup {
		c.out.push(delayed{time.Now().Add(d), append([]byte(nil), b...), addr}, false)
	}
	return len(b), nil
}

func (c *lossyPacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	for {
		var timeout <-chan time.Time
		if d := c.deadline.Load(); d != nil && !d.IsZero() {
			if !time.Now().Before(*d) {
				return 0, nil, timeoutError{}
			}
			timeout = time.After(time.Until(*d))
		}
		select {
		case p := <-c.in.out:
			return copy(b, p.b), p.addr, nil
		case <-timeout:
			return 0, nil, timeoutError{}
		case <-c.deadlineC:
			continue // re-evaluate the deadline
		case <-c.done:
			return 0, nil, net.ErrClosed
		}
	}
}

// SetReadDeadline: quic-go's Transport uses it to interrupt its read loop
// when it closes a conn it did not create, so a blocked ReadFrom must see
// the change.
func (c *lossyPacketConn) SetReadDeadline(t time.Time) error {
	c.deadline.Store(&t)
	select {
	case c.deadlineC <- struct{}{}:
	default:
	}
	return nil
}

type timeoutError struct{}

func (timeoutError) Error() string   { return "i/o timeout" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }

func TestHTTP3OverLossyNetwork(t *testing.T) {
	port, _ := startRelay(t, nil, nil)
	for _, c := range []struct {
		name  string
		loss  float64
		delay time.Duration
		jit   time.Duration
		dup   float64
		size  int64
	}{
		// Loss-based congestion control gives roughly 1.2*MSS/(RTT*sqrt(p)):
		// ~240 KB/s for the first case, ~25 KB/s for the second, relay or
		// not; the sizes keep the test short.
		{"3% loss, 40ms RTT, reordering", 0.03, 20 * time.Millisecond, 10 * time.Millisecond, 0.01, int64(stressMB()) << 20 / 16},
		{"10% loss, 200ms RTT", 0.10, 100 * time.Millisecond, 20 * time.Millisecond, 0, 1 << 20},
	} {
		t.Run(c.name, func(t *testing.T) {
			size := c.size
			sink := newSinkServer(t, 6, size)
			wantUp, wantDown := patternHash(5, size), patternHash(6, size)
			baseline := directQUICBaseline(t, newLossyPacketConn(t, c.loss, c.delay, c.jit, c.dup), size)
			t.Logf("direct QUIC: %d MiB each way in %v", size>>20, baseline.Round(time.Millisecond))
			pc := newLossyPacketConn(t, c.loss, c.delay, c.jit, c.dup)
			cl := client(port)
			cl.PacketConn = pc
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
			defer cancel()
			h, err := cl.dialH3(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer h.Close()
			s, err := cl.openTCPH3(ctx, h, sink.addr)
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			start := time.Now()
			gotUp, gotDown := transfer(t, s, 5, size, sink)
			if gotUp != wantUp || gotDown != wantDown {
				t.Fatal("corrupted")
			}
			d := time.Since(start)
			t.Logf("relay: %d MiB each way in %v (%.1fx direct); %d of %d packets dropped on the way out", size>>20,
				d.Round(time.Millisecond), d.Seconds()/baseline.Seconds(), pc.stats.dropped.Load(), pc.stats.sent.Load())
			if d > baseline*2+5*time.Second {
				t.Fatalf("too slow through the relay: %v vs %v direct", d, baseline)
			}
		})
	}
}

// directQUICBaseline moves `size` bytes each way on one quic-go stream over
// the impaired conn, with the relay's QUIC settings, and no relay.
func directQUICBaseline(t *testing.T, pc *lossyPacketConn, size int64) time.Duration {
	t.Helper()
	srvConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer srvConn.Close()
	cert, _ := tls.X509KeyPair([]byte(pki().certPEM), []byte(pki().keyPEM))
	str := &quic.Transport{Conn: srvConn}
	ln, err := str.Listen(&tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"x"}}, quicConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		conn, err := ln.Accept(context.Background())
		if err != nil {
			return
		}
		s, err := conn.AcceptStream(context.Background())
		if err != nil {
			return
		}
		io.Copy(io.Discard, s)
		io.Copy(s, newPattern(1, size))
		s.Close()
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	ctr := &quic.Transport{Conn: pc}
	defer ctr.Close()
	conn, err := ctr.Dial(ctx, srvConn.LocalAddr(), &tls.Config{ServerName: "relay.test", RootCAs: pki().pool, NextProtos: []string{"x"}},
		&quic.Config{InitialPacketSize: 1350})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.CloseWithError(0, "")
	s, err := conn.OpenStreamSync(ctx)
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	go func() {
		io.Copy(s, newPattern(1, size))
		s.Close()
	}()
	if _, err := io.Copy(io.Discard, s); err != nil {
		t.Fatal(err)
	}
	return time.Since(start)
}

// A QUIC connection (as a device's apps make to Google, Cloudflare, ...)
// inside the UDP tunnel, over a lossy outer path. The inner QUIC's
// packets must fit in the outer datagrams; its PMTU probes beyond that are
// dropped, not sent as capsules.
func TestQUICInsideUDPTunnelOverLossyNetwork(t *testing.T) {
	port, _ := startRelay(t, nil, nil)
	size := int64(stressMB()) << 20 / 8

	// The inner server: a QUIC echo-and-send server on loopback.
	inner, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer inner.Close()
	cert, _ := tls.X509KeyPair([]byte(pki().certPEM), []byte(pki().keyPEM))
	tr := &quic.Transport{Conn: inner}
	ln, err := tr.Listen(&tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"inner"}}, &quic.Config{})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	received := make(chan string, 1)
	go func() {
		conn, err := ln.Accept(context.Background())
		if err != nil {
			return
		}
		str, err := conn.AcceptStream(context.Background())
		if err != nil {
			return
		}
		h := sha256.New()
		io.Copy(h, str)
		received <- hex.EncodeToString(h.Sum(nil))
		io.Copy(str, newPattern(8, size))
		str.Close()
	}()
	host, uport, _ := net.SplitHostPort(inner.LocalAddr().String())

	pc := newLossyPacketConn(t, 0.03, 15*time.Millisecond, 10*time.Millisecond, 0)
	cl := client(port)
	cl.PacketConn = pc
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	h, err := cl.dialH3(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	tunnel, err := cl.openUDPH3(ctx, h, host, uport)
	if err != nil {
		t.Fatal(err)
	}
	defer tunnel.Close()

	// The inner client dials through the tunnel.
	tpc := &tunnelPacketConn{tunnel: tunnel, remote: inner.LocalAddr(), ctx: ctx}
	itr := &quic.Transport{Conn: tpc}
	defer itr.Close()
	iconn, err := itr.Dial(ctx, inner.LocalAddr(), &tls.Config{ServerName: "relay.test", RootCAs: pki().pool, NextProtos: []string{"inner"}}, &quic.Config{})
	if err != nil {
		t.Fatal(err)
	}
	defer iconn.CloseWithError(0, "")
	str, err := iconn.OpenStreamSync(ctx)
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	go func() {
		io.Copy(str, newPattern(7, size))
		str.Close()
	}()
	hs := sha256.New()
	if _, err := io.Copy(hs, str); err != nil {
		t.Fatal(err)
	}
	if got := <-received; got != patternHash(7, size) {
		t.Fatal("inner upload corrupted")
	}
	if hex.EncodeToString(hs.Sum(nil)) != patternHash(8, size) {
		t.Fatal("inner download corrupted")
	}
	t.Logf("%d MiB each way through QUIC-in-QUIC in %v; outer loss %d/%d; largest inner packet %d bytes",
		size>>20, time.Since(start).Round(time.Millisecond), pc.stats.dropped.Load(), pc.stats.sent.Load(), tpc.maxSent.Load())
	if m := tpc.maxSent.Load(); m < 1200 {
		t.Fatalf("inner packets of only %d bytes", m)
	}
}

// tunnelPacketConn is a net.PacketConn over a UDP tunnel.
type tunnelPacketConn struct {
	tunnel  packetConn
	remote  net.Addr
	ctx     context.Context
	maxSent atomic.Int64
	local   net.UDPAddr

	mu       sync.Mutex
	deadline time.Time
	cancel   context.CancelFunc // of the read in progress
}

func (c *tunnelPacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	c.mu.Lock()
	ctx, cancel := context.WithCancel(c.ctx)
	if !c.deadline.IsZero() {
		ctx, cancel = context.WithDeadline(c.ctx, c.deadline)
	}
	c.cancel = cancel
	c.mu.Unlock()
	defer cancel()
	p, err := c.tunnel.Receive(ctx)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) && c.ctx.Err() == nil {
			return 0, nil, timeoutError{}
		}
		return 0, nil, err
	}
	return copy(b, p), c.remote, nil
}

// SetReadDeadline interrupts a read in progress, as quic-go's Transport
// needs when closing.
func (c *tunnelPacketConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	c.deadline = t
	if c.cancel != nil && !t.IsZero() && !time.Now().Before(t) {
		c.cancel()
	}
	c.mu.Unlock()
	return nil
}

func (c *tunnelPacketConn) WriteTo(b []byte, _ net.Addr) (int, error) {
	if int64(len(b)) > c.maxSent.Load() {
		c.maxSent.Store(int64(len(b)))
	}
	err := c.tunnel.Send(b)
	var tooLarge *quic.DatagramTooLargeError
	if errors.As(err, &tooLarge) {
		return len(b), nil // like a path that drops oversized packets
	}
	return len(b), err
}

func (c *tunnelPacketConn) Close() error                     { return nil }
func (c *tunnelPacketConn) LocalAddr() net.Addr              { return &c.local }
func (c *tunnelPacketConn) SetDeadline(time.Time) error      { return nil }
func (c *tunnelPacketConn) SetWriteDeadline(time.Time) error { return nil }
func (c *tunnelPacketConn) SetReadBuffer(int) error          { return nil }
func (c *tunnelPacketConn) SetWriteBuffer(int) error         { return nil }
func (c *tunnelPacketConn) SyscallConn() (any, error)        { return nil, errors.New("no") }

// ---- impaired TCP path ----

// tcpImpairment proxies TCP connections to the relay with latency (a
// delay queue, so bytes in flight overlap), a bandwidth cap (token bucket),
// and on demand a stall or a cut.
type tcpImpairment struct {
	addr      string
	delay     time.Duration
	bytesPerS int64
	stall     atomic.Bool
	cut       atomic.Bool
	conns     sync.Map
	mu        sync.Mutex
	tokens    float64
	last      time.Time
}

func newTCPImpairment(t *testing.T, target string, delay time.Duration, bytesPerS int64) *tcpImpairment {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	p := &tcpImpairment{addr: l.Addr().String(), delay: delay, bytesPerS: bytesPerS, last: time.Now()}
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			up, err := net.Dial("tcp", target)
			if err != nil {
				c.Close()
				continue
			}
			p.conns.Store(c, up)
			go p.pipe(c, up)
			go p.pipe(up, c)
		}
	}()
	return p
}

// take waits until n bytes of bandwidth are available (shared by all
// connections and both directions, like a link).
func (p *tcpImpairment) take(n int) {
	if p.bytesPerS <= 0 {
		return
	}
	for {
		p.mu.Lock()
		now := time.Now()
		p.tokens += now.Sub(p.last).Seconds() * float64(p.bytesPerS)
		p.last = now
		if p.tokens > float64(p.bytesPerS)/10 { // 100 ms burst
			p.tokens = float64(p.bytesPerS) / 10
		}
		if p.tokens >= float64(n) {
			p.tokens -= float64(n)
			p.mu.Unlock()
			return
		}
		missing := float64(n) - p.tokens
		p.mu.Unlock()
		time.Sleep(time.Duration(missing / float64(p.bytesPerS) * float64(time.Second)))
	}
}

func (p *tcpImpairment) pipe(from, to net.Conn) {
	type chunk struct {
		at time.Time
		b  []byte
	}
	queue := make(chan chunk, 4096)
	go func() { // delivers delayed chunks, then passes the FIN on
		for c := range queue {
			time.Sleep(time.Until(c.at))
			if _, err := to.Write(c.b); err != nil {
				to.Close()
				return
			}
		}
		if p.cut.Load() {
			to.Close()
			return
		}
		to.(*net.TCPConn).CloseWrite()
	}()
	buf := make([]byte, 4*1024)
	for {
		n, err := from.Read(buf)
		if n > 0 {
			for p.stall.Load() {
				time.Sleep(50 * time.Millisecond)
			}
			if p.cut.Load() {
				break
			}
			p.take(n)
			queue <- chunk{time.Now().Add(p.delay), append([]byte(nil), buf[:n]...)}
		}
		if err != nil {
			break
		}
	}
	close(queue)
}

// cutAll resets every proxied connection.
func (p *tcpImpairment) cutAll() {
	p.cut.Store(true)
	p.conns.Range(func(k, v any) bool {
		for _, c := range []any{k, v} {
			if tc, ok := c.(*net.TCPConn); ok {
				tc.SetLinger(0)
				tc.Close()
			}
		}
		return true
	})
}

func TestTCPVersionsOverSlowNetwork(t *testing.T) {
	port, _ := startRelay(t, nil, nil)
	size := int64(4) << 20
	sink := newSinkServer(t, 10, size)
	wantUp, wantDown := patternHash(9, size), patternHash(10, size)
	// 60 ms one way, 8 Mbit/s: a mediocre mobile connection.
	const delay, rate = 60 * time.Millisecond, 1 << 20

	// Baseline: the same transfer over the same impairment, no relay.
	direct := newTCPImpairment(t, sink.addr, delay, rate)
	c, err := net.Dial("tcp", direct.addr)
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	transfer(t, tcpStream{c.(*net.TCPConn)}, 9, size, sink)
	baseline := time.Since(start)
	c.Close()
	t.Logf("direct: %d MiB each way in %v", size>>20, baseline.Round(time.Millisecond))

	imp := newTCPImpairment(t, "127.0.0.1:"+strconv.Itoa(port), delay, rate)
	for _, v := range versions[1:] {
		t.Run(v.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
			defer cancel()
			cl := client(port)
			cl.Address = imp.addr
			s, done, err := v.openTCP(ctx, cl, sink.addr)
			if err != nil {
				t.Fatal(err)
			}
			defer done()
			defer s.Close()
			start := time.Now()
			gotUp, gotDown := transfer(t, s, 9, size, sink)
			if gotUp != wantUp || gotDown != wantDown {
				t.Fatal("corrupted")
			}
			d := time.Since(start)
			t.Logf("%s: %d MiB each way in %v (%.1fx direct)", v.name, size>>20, d.Round(time.Millisecond), d.Seconds()/baseline.Seconds())
			if d > baseline*3/2+2*time.Second {
				t.Fatalf("too slow through the relay: %v vs %v direct", d, baseline)
			}
		})
	}
}

type tcpStream struct{ *net.TCPConn }

func (s tcpStream) CloseWrite() error { return s.TCPConn.CloseWrite() }

// A connection that stalls for a while, then continues, keeps its tunnel;
// one that is cut frees its tunnel and resets the target.
func TestStallAndCut(t *testing.T) {
	port, _ := startRelay(t, nil, nil)
	target := echoTCP(t)
	for _, v := range versions[1:] {
		t.Run(v.name+" stall", func(t *testing.T) {
			imp := newTCPImpairment(t, "127.0.0.1:"+strconv.Itoa(port), 0, 0)
			ctx := testCtx(t)
			cl := client(port)
			cl.Address = imp.addr
			s, done, err := v.openTCP(ctx, cl, target)
			if err != nil {
				t.Fatal(err)
			}
			defer done()
			defer s.Close()
			imp.stall.Store(true)
			go func() {
				time.Sleep(3 * time.Second)
				imp.stall.Store(false)
			}()
			s.Write([]byte("after the stall"))
			buf := make([]byte, 15)
			if _, err := io.ReadFull(s, buf); err != nil || string(buf) != "after the stall" {
				t.Fatalf("got %q, %v", buf, err)
			}
		})
		t.Run(v.name+" cut", func(t *testing.T) {
			imp := newTCPImpairment(t, "127.0.0.1:"+strconv.Itoa(port), 0, 0)
			ctx := testCtx(t)
			cl := client(port)
			cl.Address = imp.addr
			s, done, err := v.openTCP(ctx, cl, target)
			if err != nil {
				t.Fatal(err)
			}
			defer done()
			defer s.Close()
			s.Write([]byte("x"))
			io.ReadFull(s, make([]byte, 1))
			before := openTunnels.Load()
			imp.cutAll()
			deadline := time.Now().Add(10 * time.Second)
			for openTunnels.Load() >= before && time.Now().Before(deadline) {
				time.Sleep(50 * time.Millisecond)
			}
			if n := openTunnels.Load(); n >= before {
				t.Fatalf("tunnel not freed after the cut: %d open", n)
			}
		})
	}
	// HTTP/3: the client vanishes (no CONNECTION_CLOSE); the QUIC idle
	// timeout, not a test, bounds that. Here: an abrupt close with an
	// error frees the tunnel.
	t.Run("h3 abrupt close", func(t *testing.T) {
		ctx := testCtx(t)
		cl := client(port)
		h, err := cl.dialH3(ctx)
		if err != nil {
			t.Fatal(err)
		}
		s, err := cl.openTCPH3(ctx, h, target)
		if err != nil {
			t.Fatal(err)
		}
		s.Write([]byte("x"))
		io.ReadFull(s, make([]byte, 1))
		before := openTunnels.Load()
		h.conn.CloseWithError(0x1234, "gone")
		deadline := time.Now().Add(10 * time.Second)
		for openTunnels.Load() >= before && time.Now().Before(deadline) {
			time.Sleep(50 * time.Millisecond)
		}
		if n := openTunnels.Load(); n >= before {
			t.Fatalf("tunnel not freed: %d open", n)
		}
	})
}

// UDP datagrams over a lossy path: losses are the path's, not the relay's
// (no retransmission, no reordering by the relay), and nothing is corrupted.
func TestUDPOverLossyNetwork(t *testing.T) {
	port, _ := startRelay(t, nil, nil)
	host, uport := echoUDP(t)
	pc := newLossyPacketConn(t, 0.05, 10*time.Millisecond, 5*time.Millisecond, 0)
	cl := client(port)
	cl.PacketConn = pc
	ctx := testCtx(t)
	h, err := cl.dialH3(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	p, err := cl.openUDPH3(ctx, h, host, uport)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	const n = 400
	var got atomic.Int64
	var bad atomic.Int64
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			rctx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
			b, err := p.Receive(rctx)
			cancel()
			if err != nil {
				return
			}
			if len(b) != 1000 || !bytes.Equal(b[4:], bytes.Repeat([]byte{b[0]}, 996)) {
				bad.Add(1)
			}
			got.Add(1)
		}
	}()
	for i := 0; i < n; i++ {
		msg := append([]byte{byte(i), byte(i >> 8), 0, 0}, bytes.Repeat([]byte{byte(i)}, 996)...)
		if err := p.Send(msg); err != nil {
			t.Fatal(err)
		}
		time.Sleep(2 * time.Millisecond)
	}
	<-done
	t.Logf("%d of %d datagrams came back, %d corrupted", got.Load(), n, bad.Load())
	if bad.Load() > 0 || got.Load() < n*7/10 || got.Load() > n {
		t.Fatalf("got %d (want roughly %d minus ~10%% loss), %d corrupted", got.Load(), n, bad.Load())
	}
}
