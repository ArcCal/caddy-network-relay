package networkrelay

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func reviewH1ClientServer(t *testing.T, handle func(*tls.Conn, *bufio.Reader, <-chan struct{})) *relayClient {
	t.Helper()
	cert, err := tls.X509KeyPair([]byte(pki().certPEM), []byte(pki().keyPEM))
	if err != nil {
		t.Fatal(err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert}, NextProtos: []string{"http/1.1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	stop, done := make(chan struct{}), make(chan struct{})
	var mu sync.Mutex
	var active net.Conn
	go func() {
		defer close(done)
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		mu.Lock()
		active = conn
		mu.Unlock()
		defer conn.Close()
		br := bufio.NewReader(conn)
		if _, err := http.ReadRequest(br); err != nil {
			return
		}
		handle(conn.(*tls.Conn), br, stop)
	}()
	t.Cleanup(func() {
		close(stop)
		ln.Close()
		mu.Lock()
		if active != nil {
			active.Close()
		}
		mu.Unlock()
		<-done
	})
	return &relayClient{Address: ln.Addr().String(), Server: "relay.test", TLS: &tls.Config{RootCAs: pki().pool}}
}

func TestReviewH1ClientRequestCancellation(t *testing.T) {
	for _, deadline := range []bool{false, true} {
		name := "cancel"
		if deadline {
			name = "deadline"
		}
		t.Run(name, func(t *testing.T) {
			entered := make(chan struct{})
			c := reviewH1ClientServer(t, func(_ *tls.Conn, _ *bufio.Reader, stop <-chan struct{}) {
				close(entered)
				<-stop // withhold the response headers after the TLS handshake
			})
			ctx, cancel := context.WithCancel(context.Background())
			want := context.Canceled
			if deadline {
				cancel()
				ctx, cancel = context.WithTimeout(context.Background(), 250*time.Millisecond)
				want = context.DeadlineExceeded
			}
			defer cancel()
			done := make(chan error, 1)
			go func() {
				s, err := c.openTCPH1(ctx, "stall.test:443")
				if err == nil {
					s.Close()
				}
				done <- err
			}()
			select {
			case <-entered:
			case <-time.After(time.Second):
				t.Fatal("server never received the request")
			}
			if !deadline {
				cancel()
			}
			select {
			case err := <-done:
				if !errors.Is(err, want) {
					t.Fatalf("request cancellation: %v, want %v", err, want)
				}
			case <-time.After(time.Second):
				t.Fatal("HTTP/1.1 response header read ignored cancellation")
			}
		})
	}
}

func TestReviewH1ClientEstablishedStreamCancellation(t *testing.T) {
	for _, deadline := range []bool{false, true} {
		name := "cancel"
		if deadline {
			name = "deadline"
		}
		t.Run(name, func(t *testing.T) {
			c := reviewH1ClientServer(t, func(conn *tls.Conn, _ *bufio.Reader, stop <-chan struct{}) {
				_, _ = io.WriteString(conn, "HTTP/1.1 200 OK\r\n\r\n")
				<-stop
			})
			ctx, cancel := context.WithCancel(context.Background())
			if deadline {
				cancel()
				ctx, cancel = context.WithTimeout(context.Background(), 250*time.Millisecond)
			}
			defer cancel()
			s, err := c.openTCPH1(ctx, "stall.test:443")
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			done := make(chan error, 1)
			go func() { _, err := s.Read(make([]byte, 1)); done <- err }()
			if !deadline {
				cancel()
			}
			select {
			case err := <-done:
				if err == nil {
					t.Fatal("canceled stream read succeeded")
				}
			case <-time.After(time.Second):
				t.Fatal("HTTP/1.1 established stream ignored its request context")
			}
		})
	}
}

func TestReviewH1ClientBlockedWriteCancellation(t *testing.T) {
	c := reviewH1ClientServer(t, func(conn *tls.Conn, _ *bufio.Reader, stop <-chan struct{}) {
		_ = conn.NetConn().(*net.TCPConn).SetReadBuffer(4096)
		_, _ = io.WriteString(conn, "HTTP/1.1 200 OK\r\n\r\n")
		<-stop // stop reading so the client's socket reaches backpressure
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s, err := c.openTCPH1(ctx, "stall.test:443")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		// Also release the worker when exercising the unfixed client.
		_ = s.(*h1Stream).conn.NetConn().Close()
		_ = s.Close()
	}()
	_ = s.(*h1Stream).conn.NetConn().(*net.TCPConn).SetWriteBuffer(4096)
	var written atomic.Int64
	done := make(chan error, 1)
	go func() {
		payload := make([]byte, 64<<10)
		for {
			n, err := s.Write(payload)
			written.Add(int64(n))
			if err != nil {
				done <- err
				return
			}
		}
	}()
	last, stable := int64(-1), time.Now()
	until := time.Now().Add(2 * time.Second)
	for time.Now().Before(until) {
		if n := written.Load(); n != last {
			last, stable = n, time.Now()
		}
		if time.Since(stable) >= 100*time.Millisecond {
			break
		}
		time.Sleep(time.Millisecond)
	}
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("canceled blocked write succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("HTTP/1.1 backpressured write ignored cancellation")
	}
}

func TestReviewH1ClientContextPreservesHalfClose(t *testing.T) {
	const payload = "reply after the client sends TLS close_notify"
	c := reviewH1ClientServer(t, func(conn *tls.Conn, br *bufio.Reader, _ <-chan struct{}) {
		if _, err := io.WriteString(conn, "HTTP/1.1 200 OK\r\n\r\n"); err != nil {
			return
		}
		if _, err := io.Copy(io.Discard, br); err != nil {
			return
		}
		_, _ = io.WriteString(conn, payload)
	})
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	s, err := c.openTCPH1(ctx, "echo.test:443")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(s)
	if err != nil || string(got) != payload {
		t.Fatalf("half-closed TLS stream: %q, %v", got, err)
	}
}
