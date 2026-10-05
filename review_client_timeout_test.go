package networkrelay

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

func reviewH3ClientServer(t *testing.T, handler http.Handler, config *quic.Config) *relayClient {
	t.Helper()
	cert, err := tls.X509KeyPair([]byte(pki().certPEM), []byte(pki().keyPEM))
	if err != nil {
		t.Fatal(err)
	}
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &http3.Server{
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}}, QUICConfig: config,
		EnableDatagrams: true, Handler: handler,
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = server.Serve(pc)
	}()
	t.Cleanup(func() {
		_ = server.Close()
		_ = pc.Close()
		<-done
	})
	return &relayClient{Address: pc.LocalAddr().String(), Server: "relay.test", TLS: &tls.Config{RootCAs: pki().pool}}
}

func reviewH3EchoResponse(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.(http.Flusher).Flush()
	_, _ = io.Copy(w, r.Body)
}

func reviewH3EchoTunnel(t *testing.T, c *relayClient, h *h3Conn) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	s, err := c.openTCPH3(ctx, h, "echo.test:443")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	const payload = "context cancellation preserves the shared connection and directional FIN"
	if _, err := io.WriteString(s, payload); err != nil {
		t.Fatal(err)
	}
	if err := s.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(s)
	if err != nil || string(got) != payload {
		t.Fatalf("half-closed echo: %q, %v", got, err)
	}
}

func TestReviewH3ClientRequestCancellation(t *testing.T) {
	for _, deadline := range []bool{true, false} {
		name := "cancel"
		if deadline {
			name = "deadline"
		}
		t.Run(name, func(t *testing.T) {
			entered := make(chan struct{}, 1)
			c := reviewH3ClientServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Host == "stall.test:443" {
					entered <- struct{}{}
					<-r.Context().Done()
					return
				}
				reviewH3EchoResponse(w, r)
			}), nil)
			h, err := c.dialH3(testCtx(t))
			if err != nil {
				t.Fatal(err)
			}
			defer h.Close()
			ctx, cancel := context.WithCancel(context.Background())
			want := context.Canceled
			if deadline {
				cancel()
				ctx, cancel = context.WithTimeout(context.Background(), 100*time.Millisecond)
				want = context.DeadlineExceeded
			}
			defer cancel()
			done := make(chan error, 1)
			go func() {
				s, err := c.openTCPH3(ctx, h, "stall.test:443")
				if s != nil {
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
				t.Fatal("HTTP/3 request ignored cancellation while waiting for response headers")
			}
			reviewH3EchoTunnel(t, c, h)
		})
	}
}

func TestReviewH3ClientPendingStreamCancellation(t *testing.T) {
	c := reviewH3ClientServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host == "hold.test:443" {
			w.WriteHeader(http.StatusOK)
			w.(http.Flusher).Flush()
			<-r.Context().Done()
			return
		}
		reviewH3EchoResponse(w, r)
	}), &quic.Config{MaxIncomingStreams: 1})
	h, err := c.dialH3(testCtx(t))
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	held, err := c.openTCPH3(testCtx(t), h, "hold.test:443")
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	s, err := c.openTCPH3(ctx, h, "echo.test:443")
	if s != nil {
		s.Close()
	}
	if !errors.Is(err, context.DeadlineExceeded) || time.Since(start) > time.Second {
		t.Fatalf("pending stream ignored deadline: %v (%s)", err, time.Since(start))
	}
	held.Close()
	reviewH3EchoTunnel(t, c, h)
}

func TestReviewH3ClientEstablishedStreamCancellation(t *testing.T) {
	c := reviewH3ClientServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host == "stall.test:443" {
			w.WriteHeader(http.StatusOK)
			w.(http.Flusher).Flush()
			<-r.Context().Done()
			return
		}
		reviewH3EchoResponse(w, r)
	}), nil)
	h, err := c.dialH3(testCtx(t))
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s, err := c.openTCPH3(ctx, h, "stall.test:443")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	done := make(chan error, 1)
	go func() {
		_, err := s.Read(make([]byte, 1))
		done <- err
	}()
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("canceled blocked stream read succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("established HTTP/3 stream ignored request cancellation")
	}
	reviewH3EchoTunnel(t, c, h)
}

func TestReviewH3ClientBlockedHeaderWriteCancellation(t *testing.T) {
	cert, err := tls.X509KeyPair([]byte(pki().certPEM), []byte(pki().keyPEM))
	if err != nil {
		t.Fatal(err)
	}
	listener, err := quic.ListenAddr("127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert}, NextProtos: []string{http3.NextProtoH3},
	}, &quic.Config{InitialStreamReceiveWindow: 64, MaxStreamReceiveWindow: 64})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		conn, err := listener.Accept(testCtx(t))
		if err != nil {
			return
		}
		defer conn.CloseWithError(0, "")
		control, err := conn.OpenUniStream()
		if err != nil {
			return
		}
		// A control stream with empty SETTINGS completes H3 setup. Never
		// consume request streams: only 64 header bytes can be sent before
		// flow control blocks the rest of the request header write.
		if _, err := control.Write([]byte{0, 4, 0}); err != nil {
			return
		}
		<-conn.Context().Done()
	}()
	c := &relayClient{
		Address: listener.Addr().String(), Server: "relay.test", NoDatagrams: true,
		TLS: &tls.Config{RootCAs: pki().pool}, Authorization: strings.Repeat("x", 4096),
	}
	h, err := c.dialH3(testCtx(t))
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		h.Close()
		<-serverDone
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		s, err := c.openTCPH3(ctx, h, "echo.test:443")
		if s != nil {
			s.Close()
		}
		done <- err
	}()
	select {
	case err := <-done:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("blocked request header write: %v, want deadline exceeded", err)
		}
	case <-time.After(time.Second):
		t.Fatal("blocked HTTP/3 request header write ignored its deadline")
	}
	if h.conn.Context().Err() != nil {
		t.Fatal("request deadline closed the shared QUIC connection")
	}
}
