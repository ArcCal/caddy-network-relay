package networkrelay

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/http2"
)

func TestReviewH2CancelledEstablishmentReleasesQuota(t *testing.T) {
	for _, udp := range []bool{false, true} {
		name := "TCP"
		if udp {
			name = "UDP"
		}
		t.Run(name, func(t *testing.T) {
			if udp && !http2ExtendedConnect() {
				t.Skip("extended CONNECT is disabled")
			}
			port, _ := startRelay(t, nil, nil)
			pressure, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer pressure.Close()
			begin := make(chan struct{})
			startPressure := sync.OnceFunc(func() { close(begin) })
			t.Cleanup(startPressure)
			var sent atomic.Int64
			go func() {
				c, err := pressure.Accept()
				if err != nil {
					return
				}
				defer c.Close()
				<-begin
				_ = c.(*net.TCPConn).SetWriteBuffer(64 << 10)
				_ = c.SetWriteDeadline(time.Now().Add(10 * time.Second))
				data := bytes.Repeat([]byte("x"), 64<<10)
				for range 2048 {
					n, err := c.Write(data)
					sent.Add(int64(n))
					if err != nil {
						return
					}
				}
			}()
			r := dialRawH2(t, port)
			defer r.conn.Close()
			_ = r.conn.NetConn().(*net.TCPConn).SetReadBuffer(1024)
			if err := r.fr.WriteSettings(http2.Setting{ID: http2.SettingInitialWindowSize, Val: 1 << 30}); err != nil {
				t.Fatal(err)
			}
			if err := r.fr.WriteWindowUpdate(0, (1<<30)-65535); err != nil {
				t.Fatal(err)
			}
			r.headers(1, connectTCPFields(pressure.Addr().String()))
			if headers, ok := r.next(1).(*http2.MetaHeadersFrame); !ok || headers.PseudoValue("status") != "200" {
				t.Fatal("pressure tunnel not established")
			}
			startPressure()
			deadline := time.Now().Add(5 * time.Second)
			last, stableSince := sent.Load(), time.Now()
			for {
				now, n := time.Now(), sent.Load()
				if n != last {
					last, stableSince = n, now
				}
				if n > 1<<20 && now.Sub(stableSince) >= 100*time.Millisecond {
					break
				}
				if now.After(deadline) {
					t.Fatalf("target did not encounter socket backpressure, sent=%d", n)
				}
				time.Sleep(5 * time.Millisecond)
			}
			if udp {
				host, port := echoUDP(t)
				r.headers(3, connectUDPFields(host, port))
			} else {
				other, err := net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				defer other.Close()
				accepted := make(chan struct{})
				go func() {
					c, err := other.Accept()
					if err != nil {
						return
					}
					defer c.Close()
					close(accepted)
					_, _ = io.Copy(io.Discard, c)
				}()
				r.headers(3, connectTCPFields(other.Addr().String()))
				select {
				case <-accepted:
				case <-time.After(time.Second):
					t.Fatal("second target was not dialed")
				}
			}
			deadline = time.Now().Add(time.Second)
			for openTunnels.Load() != 2 {
				if time.Now().After(deadline) {
					t.Fatal("second tunnel was not admitted")
				}
				time.Sleep(time.Millisecond)
			}
			time.Sleep(50 * time.Millisecond)
			closeAllTunnels()
			deadline = time.Now().Add(time.Second)
			for openTunnels.Load() != 0 && time.Now().Before(deadline) {
				time.Sleep(time.Millisecond)
			}
			retained := openTunnels.Load()
			// Record cleanup before the client socket helps unblock the writer.
			_ = r.conn.Close()
			if retained != 0 {
				t.Fatalf("cancelled establishment retained %d tunnel slots", retained)
			}
		})
	}
}

type reviewEstablishConn struct {
	net.Conn
	started chan struct{}
}

func (c *reviewEstablishConn) Write(p []byte) (int, error) {
	select {
	case c.started <- struct{}{}:
	default:
	}
	return c.Conn.Write(p)
}

type reviewHijackWriter struct {
	conn   net.Conn
	header http.Header
}

func (w *reviewHijackWriter) Header() http.Header     { return w.header }
func (*reviewHijackWriter) WriteHeader(int)           { panic("unexpected HTTP write") }
func (*reviewHijackWriter) Write([]byte) (int, error) { panic("unexpected HTTP write") }
func (w *reviewHijackWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return w.conn, bufio.NewReadWriter(bufio.NewReader(w.conn), bufio.NewWriter(w.conn)), nil
}

func TestReviewH1CancelledEstablishmentInterruptsReply(t *testing.T) {
	conn, peer := net.Pipe()
	defer peer.Close()
	tracked := &reviewEstablishConn{Conn: conn, started: make(chan struct{}, 1)}
	defer tracked.Close()
	w := &reviewHijackWriter{conn: tracked, header: make(http.Header)}
	r, _ := http.NewRequest(http.MethodConnect, "https://relay.test/", nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := establish(ctx, w, r, "HTTP/1.1 200 OK\r\n\r\n"); done <- err }()
	select {
	case <-tracked.started:
	case <-time.After(time.Second):
		t.Fatal("reply did not block")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("cancelled reply: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("cancelled reply retained client I/O")
	}
}

type reviewEstablishmentJoinClient struct{ reviewBlockingClient }

func (c *reviewEstablishmentJoinClient) interrupt(why abortReason) {
	c.reviewBlockingClient.interrupt(why)
	<-c.allowExit
}

func TestReviewEstablishmentCancellationCallbackJoined(t *testing.T) {
	c := &reviewEstablishmentJoinClient{reviewBlockingClient{interrupted: make(chan struct{}), allowExit: make(chan struct{})}}
	release := sync.OnceFunc(func() { close(c.allowExit) })
	t.Cleanup(release)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	writing := make(chan struct{})
	go func() {
		done <- pendingClientIO(ctx, c, func() error { close(writing); <-c.interrupted; return io.ErrClosedPipe })
	}()
	<-writing
	cancel()
	<-c.interrupted
	select {
	case <-done:
		t.Fatal("returned while cancellation callback still owns client I/O")
	case <-time.After(25 * time.Millisecond):
	}
	release()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled write: %v", err)
	}
	// An already-cancelled context must not run success writes at all.
	if err := pendingClientIO(ctx, c, func() error { t.Error("wrote after cancellation"); return nil }); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

func TestReviewEstablishmentPanicStopsCancellationCallback(t *testing.T) {
	c := &reviewBlockingClient{interrupted: make(chan struct{})}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	panicked := false
	func() {
		defer func() { panicked = recover() != nil }()
		_ = pendingClientIO(ctx, c, func() error { panic("response write failed") })
	}()
	if !panicked {
		t.Fatal("write panic was suppressed")
	}
	cancel()
	select {
	case <-c.interrupted:
		t.Fatal("panic left a callback able to touch the returned response writer")
	case <-time.After(25 * time.Millisecond):
	}
}
