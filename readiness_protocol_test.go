package networkrelay

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"go.uber.org/zap"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

type blockedEndpointClose struct {
	net.PacketConn
	entered, proceed chan struct{}
}

func (c *blockedEndpointClose) Close() error {
	close(c.entered)
	<-c.proceed
	return c.PacketConn.Close()
}

func TestEndpointReacquireDuringClose(t *testing.T) {
	probe, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := probe.LocalAddr().String()
	probe.Close()
	old := &http3.Server{}
	ep, err := acquireEndpoint("udp", addr, endpointUser{server: old, tls: &tls.Config{}}, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	blocked := &blockedEndpointClose{PacketConn: ep.conn, entered: make(chan struct{}), proceed: make(chan struct{})}
	unblock := sync.OnceFunc(func() { close(blocked.proceed) })
	defer unblock()
	ep.conn = blocked
	released := make(chan struct{})
	go func() { ep.release(old); close(released) }()
	select {
	case <-blocked.entered:
	case <-time.After(time.Second):
		t.Fatal("endpoint close did not start")
	}
	if _, ok := ep.current(); ok {
		t.Fatal("closing endpoint still accepts users")
	}
	next := &http3.Server{}
	type result struct {
		ep  *endpoint
		err error
	}
	acquired := make(chan result, 1)
	go func() {
		e, err := acquireEndpoint("udp", addr, endpointUser{server: next, tls: &tls.Config{}}, zap.NewNop())
		acquired <- result{e, err}
	}()
	select {
	case r := <-acquired:
		unblock()
		<-released
		if r.ep != nil {
			r.ep.release(next)
		}
		t.Fatalf("reacquire did not wait for socket close: %v", r.err)
	case <-time.After(50 * time.Millisecond):
	}
	unblock()
	<-released
	select {
	case r := <-acquired:
		if r.err != nil {
			t.Fatal(r.err)
		}
		defer r.ep.release(next)
		ep.release(old) // duplicate cleanup must not delete the new endpoint.
		endpoints.Lock()
		current := endpoints.m[r.ep.key]
		endpoints.Unlock()
		if current != r.ep {
			t.Fatal("old cleanup removed the replacement endpoint")
		}
	case <-time.After(time.Second):
		t.Fatal("reacquire did not complete")
	}
}

type datagramProbeConn struct {
	*net.UDPConn
	limit   int
	dropped atomic.Int64
}

func (c *datagramProbeConn) SyscallConn() (syscall.RawConn, error) {
	return c.UDPConn.SyscallConn()
}

// Keep real socket DF support, but route every packet through the path model.
// Hiding OOB methods prevents optimized writes from bypassing this model.
type datagramProbePath struct{ conn *datagramProbeConn }

func (p datagramProbePath) ReadFrom(b []byte) (int, net.Addr, error) {
	for {
		n, a, err := p.conn.ReadFrom(b)
		if err != nil || p.conn.limit == 0 || n <= p.conn.limit {
			return n, a, err
		}
		p.conn.dropped.Add(1)
	}
}
func (p datagramProbePath) WriteTo(b []byte, a net.Addr) (int, error) {
	if p.conn.limit != 0 && len(b) > p.conn.limit {
		p.conn.dropped.Add(1)
		return len(b), nil
	}
	return p.conn.WriteTo(b, a)
}
func (p datagramProbePath) Close() error                          { return p.conn.Close() }
func (p datagramProbePath) LocalAddr() net.Addr                   { return p.conn.LocalAddr() }
func (p datagramProbePath) SetDeadline(t time.Time) error         { return p.conn.SetDeadline(t) }
func (p datagramProbePath) SetReadDeadline(t time.Time) error     { return p.conn.SetReadDeadline(t) }
func (p datagramProbePath) SetWriteDeadline(t time.Time) error    { return p.conn.SetWriteDeadline(t) }
func (p datagramProbePath) SyscallConn() (syscall.RawConn, error) { return p.conn.SyscallConn() }
func (p datagramProbePath) SetReadBuffer(n int) error             { return p.conn.SetReadBuffer(n) }
func (p datagramProbePath) SetWriteBuffer(n int) error            { return p.conn.SetWriteBuffer(n) }

func TestIdleDatagramPathMTUDiscovery(t *testing.T) {
	for _, limit := range []int{0, 1232} {
		name := "larger_path"
		if limit != 0 {
			name = "minimum_ipv6_path"
		}
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			sock, err := net.ListenPacket("udp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer sock.Close()
			server := &quic.Transport{Conn: sock}
			defer server.Close()
			cert, err := tls.X509KeyPair([]byte(pki().certPEM), []byte(pki().keyPEM))
			if err != nil {
				t.Fatal(err)
			}
			ln, err := server.Listen(&tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"mtu-test"}}, &quic.Config{InitialPacketSize: 1200, EnableDatagrams: true})
			if err != nil {
				t.Fatal(err)
			}
			defer ln.Close()
			go func() {
				conn, err := ln.Accept(ctx)
				if err != nil {
					return
				}
				for {
					b, err := conn.ReceiveDatagram(ctx)
					if err != nil {
						return
					}
					// MTU discovery is independent in each direction. The
					// client may become ready before the echo server's path.
					// Exercise the server's idle probe too, rather than silently
					// abandoning its echo on DatagramTooLargeError.
					deadline := time.Now().Add(2 * time.Second)
					for {
						err := conn.SendDatagram(b)
						if err == nil {
							break
						}
						var oversized *quic.DatagramTooLargeError
						if !errors.As(err, &oversized) || time.Now().After(deadline) {
							return
						}
						time.Sleep(10 * time.Millisecond)
					}
				}
			}()
			cs, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				t.Fatal(err)
			}
			defer cs.Close()
			path := &datagramProbeConn{UDPConn: cs, limit: limit}
			client := &quic.Transport{Conn: datagramProbePath{conn: path}}
			defer client.Close()
			conn, err := client.Dial(ctx, sock.LocalAddr(), &tls.Config{ServerName: "relay.test", RootCAs: pki().pool, NextProtos: []string{"mtu-test"}}, &quic.Config{InitialPacketSize: 1200, EnableDatagrams: true})
			if err != nil {
				t.Fatal(err)
			}
			payload := bytes.Repeat([]byte{0xa5}, 1200)
			var oversized *quic.DatagramTooLargeError
			if err := conn.SendDatagram(payload); !errors.As(err, &oversized) {
				t.Fatalf("expected initial 1200-byte path to reject 1200-byte payload: %v", err)
			}
			if limit == 0 {
				// No smaller application packets are sent to wake up probing.
				deadline := time.Now().Add(2 * time.Second)
				for {
					err = conn.SendDatagram(payload)
					if err == nil {
						break
					}
					if !errors.As(err, &oversized) || time.Now().After(deadline) {
						t.Fatalf("idle DPLPMTUD did not make progress: %v", err)
					}
					time.Sleep(10 * time.Millisecond)
				}
			} else {
				// An actual small path must stay small, with no fragmentation or
				// reliable fallback used to hide the packet-size constraint.
				time.Sleep(time.Second)
				if err := conn.SendDatagram(payload); !errors.As(err, &oversized) {
					t.Fatalf("oversized payload accepted on small path: %v", err)
				}
				if path.dropped.Load() == 0 {
					t.Fatal("path model saw no oversized probes")
				}
				payload = []byte("still usable")
				if err := conn.SendDatagram(payload); err != nil {
					t.Fatal(err)
				}
			}
			got, err := conn.ReceiveDatagram(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, payload) {
				t.Fatal("datagram corrupted")
			}
		})
	}
}

func TestH2ConnectTrailersRejected(t *testing.T) {
	port, _ := startRelay(t, nil, nil)
	target := echoTCP(t)
	r := dialRawH2(t, port)
	defer r.conn.Close()
	r.headers(1, connectTCPFields(target))
	rsp := r.next(1).(*http2.MetaHeadersFrame)
	if rsp.PseudoValue("status") != "200" {
		t.Fatal("not established")
	}
	r.encBuf.Reset()
	r.enc.WriteField(hpack.HeaderField{Name: "x-review-trailer", Value: "1"})
	r.fr.WriteHeaders(http2.HeadersFrameParam{StreamID: 1, BlockFragment: r.encBuf.Bytes(), EndHeaders: true, EndStream: true})
	for {
		f := r.next(1)
		if rst, ok := f.(*http2.RSTStreamFrame); ok {
			t.Logf("trailer resulted in reset: %s", rst.ErrCode)
			if rst.ErrCode != http2.ErrCodeProtocol {
				t.Fatalf("got %s, want PROTOCOL_ERROR", rst.ErrCode)
			}
			return
		}
		if f.Header().Flags.Has(http2.FlagDataEndStream) {
			t.Fatal("trailing HEADERS accepted as normal END_STREAM")
		}
	}
}
func TestH2TargetResetCode(t *testing.T) {
	port, _ := startRelay(t, nil, nil)
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	defer l.Close()
	go func() {
		c, err := l.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		io.ReadFull(c, make([]byte, 1))
		c.(*net.TCPConn).SetLinger(0)
	}()
	r := dialRawH2(t, port)
	defer r.conn.Close()
	r.headers(1, connectTCPFields(l.Addr().String()))
	r.next(1)
	r.fr.WriteData(1, false, []byte{'X'})
	for {
		f := r.next(1)
		if rst, ok := f.(*http2.RSTStreamFrame); ok {
			t.Logf("TCP reset produces HTTP/2 %s; required CONNECT_ERROR", rst.ErrCode)
			if rst.ErrCode != http2.ErrCodeConnect {
				t.Fatalf("got %s, want CONNECT_ERROR", rst.ErrCode)
			}
			return
		}
	}
}
func TestH2MalformedCapsuleCode(t *testing.T) {
	port, _ := startRelay(t, nil, nil)
	host, p := echoUDP(t)
	r := dialRawH2(t, port)
	defer r.conn.Close()
	if r.connectUDP(1, host, p) != "200 ?1" {
		t.Fatal("not established")
	}
	r.fr.WriteData(1, false, []byte{0, 0})
	for {
		f := r.next(1)
		if rst, ok := f.(*http2.RSTStreamFrame); ok {
			t.Logf("malformed capsule produces HTTP/2 %s; required PROTOCOL_ERROR", rst.ErrCode)
			if rst.ErrCode != http2.ErrCodeProtocol {
				t.Fatalf("got %s, want PROTOCOL_ERROR", rst.ErrCode)
			}
			return
		}
	}
}

func TestTargetFINPreservesUpload(t *testing.T) {
	port, _ := startRelay(t, nil, nil)
	for _, v := range versions {
		t.Run(v.name, func(t *testing.T) {
			l, _ := net.Listen("tcp", "127.0.0.1:0")
			defer l.Close()
			received := make(chan []byte, 1)
			go func() {
				c, err := l.Accept()
				if err != nil {
					received <- nil
					return
				}
				defer c.Close()
				c.SetDeadline(time.Now().Add(3 * time.Second))
				c.Write([]byte("bye"))
				c.(*net.TCPConn).CloseWrite()
				b, _ := io.ReadAll(c)
				received <- b
			}()
			ctx := testCtx(t)
			s, done, err := v.openTCP(ctx, client(port), l.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer done()
			defer s.Close()
			b, err := io.ReadAll(s)
			if err != nil || string(b) != "bye" {
				t.Fatalf("initial %q %v", b, err)
			}
			_, werr := s.Write([]byte("late"))
			s.CloseWrite()
			got := <-received
			t.Logf("upload after target FIN: write_error=%v target_received=%q", werr, got)
			if werr != nil || string(got) != "late" {
				t.Fatalf("late upload %q, write error %v", got, werr)
			}
		})
	}
}
func TestConnectUDPRejectsWrongScheme(t *testing.T) {
	port, _ := startRelay(t, nil, nil)
	host, uport := echoUDP(t)
	fields := connectUDPFields(host, uport)
	for i := range fields {
		if fields[i][0] == ":scheme" {
			fields[i][1] = "http"
		}
	}
	h := dialRawH3(t, port)
	expectMalformedH3(t, h, fields, false)
	r := dialRawH2(t, port)
	defer r.conn.Close()
	r.headers(1, fields)
	f, ok := r.next(1).(*http2.MetaHeadersFrame)
	if !ok {
		t.Fatal("unexpected response")
	}
	t.Logf("HTTP/2 :scheme=http on HTTPS-configured relay: %s", f.PseudoValue("status"))
	if f.PseudoValue("status") != "400" {
		t.Fatalf("wrong scheme accepted: %s", f.PseudoValue("status"))
	}
}

type reviewMTUPacketConn struct{ net.PacketConn }

func (c reviewMTUPacketConn) WriteTo(b []byte, a net.Addr) (int, error) {
	if len(b) > 1232 {
		return len(b), nil
	}
	return c.PacketConn.WriteTo(b, a)
}
func (c reviewMTUPacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	for {
		n, a, e := c.PacketConn.ReadFrom(b)
		if e != nil || n <= 1232 {
			return n, a, e
		}
	}
}
func TestQUICMinimumMTU(t *testing.T) {
	for _, sz := range []uint16{quicConfig().InitialPacketSize} {
		pc, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		tr := &quic.Transport{Conn: pc}
		conf := quicConfig()
		conf.InitialPacketSize = sz
		cert, _ := tls.X509KeyPair([]byte(pki().certPEM), []byte(pki().keyPEM))
		ln, err := tr.Listen(&tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"review"}}, conf)
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		accepted := make(chan struct{})
		go func() { _, _ = ln.Accept(ctx); close(accepted) }()
		cli, _ := net.ListenPacket("udp", "127.0.0.1:0")
		ctr := &quic.Transport{Conn: reviewMTUPacketConn{cli}}
		c, err := ctr.Dial(ctx, pc.LocalAddr(), &tls.Config{ServerName: "relay.test", RootCAs: pki().pool, NextProtos: []string{"review"}}, &quic.Config{InitialPacketSize: 1200})
		t.Logf("path carries <=1232 UDP bytes, server InitialPacketSize=%d handshake error=%v", sz, err)
		if c != nil {
			c.CloseWithError(0, "")
		}
		cancel()
		<-accepted
		ln.Close()
		tr.Close()
		pc.Close()
		ctr.Close()
		cli.Close()
		if err != nil {
			t.Fatalf("minimum-MTU handshake failed: %v", err)
		}
	}
}

func TestH3IncompleteHeadersTimeout(t *testing.T) {
	port, _ := startRelay(t, nil, map[string]any{"read_header_timeout": int64(100 * time.Millisecond)})
	h := dialRawH3(t, port)
	str, err := h.conn.OpenStreamSync(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer str.Close()
	frame := h3Frame(1, qpackHeaders([][2]string{{":method", "GET"}, {":scheme", "https"}, {":authority", "relay.test"}, {":path", "/"}}))
	if _, err = str.Write(frame[:2]); err != nil {
		t.Fatal(err)
	}
	time.Sleep(250 * time.Millisecond)
	_, _ = str.Write(frame[2:])
	str.SetReadDeadline(time.Now().Add(time.Second))
	_, err = str.Read(make([]byte, 1))
	if err == nil {
		t.Fatal("incomplete headers survived read_header_timeout")
	}
	// RFC 9114 section 4.1.1: a request cancelled without processing is
	// rejected, so the client may retry it.
	if code := streamCode(err); code != quic.StreamErrorCode(0x10b) {
		t.Fatalf("timeout code %x: %v", code, err)
	}
	// A rejected stream must not prevent a fresh request on the connection.
	_, _, rsp := h.request([][2]string{{":method", "GET"}, {":scheme", "https"}, {":authority", "relay.test"}, {":path", "/"}})
	if rsp.status != "200" {
		t.Fatal(rsp.status)
	}
}

// Apple's QUIC connection group owns client bidirectional stream 0 and never
// writes it; its first request uses stream 4, which implicitly opens stream 0
// (RFC 9000 section 3.2). Cancelling stream 0 fails the client's whole
// connection, so the header deadline starts at a stream's first byte.
func TestH3UnwrittenStreamIsLeftOpen(t *testing.T) {
	port, _ := startRelay(t, nil, map[string]any{"read_header_timeout": int64(100 * time.Millisecond)})
	h := dialRawH3(t, port)
	unwritten, err := h.conn.OpenStreamSync(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer unwritten.Close()
	if unwritten.StreamID() != 0 {
		t.Fatalf("stream ID %d", unwritten.StreamID())
	}
	get := [][2]string{{":method", "GET"}, {":scheme", "https"}, {":authority", "relay.test"}, {":path", "/"}}
	if _, _, rsp := h.request(get); rsp.status != "200" {
		t.Fatal(rsp.status)
	}
	time.Sleep(300 * time.Millisecond)
	unwritten.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	_, err = unwritten.Read(make([]byte, 1))
	if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("unwritten stream 0 was not left open: %v", err)
	}
	if _, _, rsp := h.request(get); rsp.status != "200" {
		t.Fatal(rsp.status)
	}
}

// Unwritten streams are bounded by the QUIC stream limit, not by the header
// slots: a frame for a higher stream opens every lower one (RFC 9000 section
// 3.2), which is no sign of excessive load. Requests with incomplete headers
// are still bounded per connection (TestH3IncompleteHeadersPerConnection).
func TestH3UnwrittenStreamsAreBounded(t *testing.T) {
	port, _ := startRelay(t, nil, nil)
	h := dialRawH3(t, port)
	for range 200 {
		if _, err := h.conn.OpenStreamSync(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	get := [][2]string{{":method", "GET"}, {":scheme", "https"}, {":authority", "relay.test"}, {":path", "/"}}
	// Writing a request implicitly opens the 200 unwritten streams below it.
	if _, _, rsp := h.request(get); rsp.status != "200" {
		t.Fatal(rsp.status)
	}
	time.Sleep(200 * time.Millisecond)
	if err := h.conn.Context().Err(); err != nil {
		t.Fatalf("connection closed: %v", context.Cause(h.conn.Context()))
	}
}

// One connection that starts requests without finishing their headers gets a
// bounded share of the process-wide header slots, and loses the connection
// when it asks for more; other clients are still served meanwhile.
func TestH3IncompleteHeadersPerConnection(t *testing.T) {
	port, _ := startRelay(t, nil, nil)
	slow := dialRawH3(t, port)
	frame := h3Frame(1, qpackHeaders([][2]string{{":method", "GET"}, {":scheme", "https"}, {":authority", "relay.test"}, {":path", "/"}}))
	stall := func() {
		str, err := slow.conn.OpenStreamSync(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if _, err = str.Write(frame[:2]); err != nil {
			t.Fatal(err)
		}
	}
	for range 16 {
		stall()
	}
	time.Sleep(200 * time.Millisecond)
	if slow.conn.Context().Err() != nil {
		t.Fatal("a connection within its share was closed")
	}
	other := dialRawH3(t, port)
	if _, _, rsp := other.request([][2]string{{":method", "GET"}, {":scheme", "https"}, {":authority", "relay.test"}, {":path", "/"}}); rsp.status != "200" {
		t.Fatal(rsp.status)
	}
	stall()
	if code := slow.connError(); code != quic.ApplicationErrorCode(0x107) {
		t.Fatalf("close code %x, want H3_EXCESSIVE_LOAD", code)
	}
	if _, _, rsp := other.request([][2]string{{":method", "GET"}, {":scheme", "https"}, {":authority", "relay.test"}, {":path", "/"}}); rsp.status != "200" {
		t.Fatal(rsp.status)
	}
}
