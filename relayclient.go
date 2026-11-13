package networkrelay

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/quic-go/quicvarint"
	"golang.org/x/net/http2"
)

// relayClient talks to a relay like a device does. It is used by
// `caddy network-relay check` and by the tests.
type relayClient struct {
	// Address to connect to (host:port); Server is the TLS name.
	Address string
	Server  string
	Port    int
	// Authorization header value; empty sends none.
	Authorization string
	UDPTemplate   string
	TLS           *tls.Config
	// NoDatagrams makes the HTTP/3 client not negotiate HTTP Datagrams,
	// so UDP goes in capsules.
	NoDatagrams bool
	// PacketConn, when set, carries the QUIC connection (tests use it to
	// impair the network).
	PacketConn net.PacketConn
}

// stream is an open TCP tunnel.
type stream interface {
	io.ReadWriter
	CloseWrite() error
	Close() error
}

// packetConn is an open UDP tunnel.
type packetConn interface {
	Send(payload []byte) error
	Receive(ctx context.Context) ([]byte, error)
	Close() error
}

func (c *relayClient) tlsConfig(proto string) *tls.Config {
	conf := c.TLS.Clone()
	if conf == nil {
		conf = &tls.Config{}
	}
	conf.ServerName = c.Server
	conf.NextProtos = []string{proto}
	return conf
}

func (c *relayClient) authority() string {
	if c.Port == 0 || c.Port == 443 {
		return c.Server
	}
	return net.JoinHostPort(c.Server, strconv.Itoa(c.Port))
}

func (c *relayClient) udpPath(host, port string) (string, error) {
	tmpl := c.UDPTemplate
	if tmpl == "" {
		tmpl = DefaultUDPTemplate
	}
	t, err := parseUDPTemplate(tmpl)
	if err != nil {
		return "", err
	}
	return t.Expand(host, port), nil
}

func (c *relayClient) header() http.Header {
	h := http.Header{}
	if c.Authorization != "" {
		h.Set("Authorization", c.Authorization)
	}
	return h
}

// statusError is a response that did not open the tunnel.
type statusError struct {
	Status      int
	ProxyStatus string
}

func (e *statusError) Error() string {
	s := fmt.Sprintf("relay answered %d %s", e.Status, http.StatusText(e.Status))
	if e.ProxyStatus != "" {
		s += " (Proxy-Status: " + e.ProxyStatus + ")"
	}
	return s
}

// checkResponse accepts the responses that open a tunnel: any 2xx to a
// CONNECT (RFC 9110 §9.3.6, RFC 9298 §3.5), or 101 to an HTTP/1.1 upgrade
// (RFC 9298 §3.3).
func checkResponse(rsp *http.Response, upgrade bool) error {
	ok := rsp.StatusCode/100 == 2
	if upgrade {
		ok = rsp.StatusCode == http.StatusSwitchingProtocols
	}
	if !ok {
		return &statusError{rsp.StatusCode, rsp.Header.Get("Proxy-Status")}
	}
	return nil
}

// ---- HTTP/3 ----

type h3Conn struct {
	conn *quic.Conn
	cc   *http3.ClientConn
}

func (c *relayClient) dialH3(ctx context.Context) (*h3Conn, error) {
	qconf := &quic.Config{EnableDatagrams: !c.NoDatagrams, InitialPacketSize: 1200}
	var conn *quic.Conn
	var err error
	if c.PacketConn != nil {
		addr, rerr := net.ResolveUDPAddr("udp", c.Address)
		if rerr != nil {
			return nil, rerr
		}
		tr := &quic.Transport{Conn: c.PacketConn}
		conn, err = tr.Dial(ctx, addr, c.tlsConfig(http3.NextProtoH3), qconf)
	} else {
		conn, err = quic.DialAddr(ctx, c.Address, c.tlsConfig(http3.NextProtoH3), qconf)
	}
	if err != nil {
		return nil, err
	}
	tr := &http3.Transport{EnableDatagrams: !c.NoDatagrams}
	cc := tr.NewClientConn(conn)
	select {
	case <-cc.ReceivedSettings():
	case <-ctx.Done():
		conn.CloseWithError(0, "")
		return nil, ctx.Err()
	}
	return &h3Conn{conn: conn, cc: cc}, nil
}

func (h *h3Conn) Close() error { return h.conn.CloseWithError(0, "") }

func (c *relayClient) h3Request(ctx context.Context, h *h3Conn, req *http.Request) (*h3Stream, error) {
	str, err := h.cc.OpenRequestStream(ctx)
	if err != nil {
		return nil, err
	}
	// OpenRequestStream's context only bounds allocation. Keep the request
	// context attached to this stream for headers and subsequent tunnel I/O,
	// without canceling other requests on the shared QUIC connection.
	s := &h3Stream{RequestStream: str}
	s.stopContext = context.AfterFunc(ctx, func() {
		str.CancelRead(quic.StreamErrorCode(http3.ErrCodeRequestCanceled))
		str.CancelWrite(quic.StreamErrorCode(http3.ErrCodeRequestCanceled))
	})
	failed := func(err error) (*h3Stream, error) {
		s.stopContext()
		str.CancelRead(quic.StreamErrorCode(http3.ErrCodeRequestCanceled))
		str.CancelWrite(quic.StreamErrorCode(http3.ErrCodeRequestCanceled))
		if ctx.Err() != nil {
			err = ctx.Err()
		} else if deadline, ok := ctx.Deadline(); ok && !time.Now().Before(deadline) && isTimeout(err) {
			// The QUIC deadline timer may fire before the context's timer.
			err = context.DeadlineExceeded
		}
		return nil, err
	}
	if deadline, ok := ctx.Deadline(); ok {
		if err := str.SetDeadline(deadline); err != nil {
			return failed(err)
		}
	}
	if err := str.SendRequestHeader(req); err != nil {
		return failed(err)
	}
	rsp, err := str.ReadResponse()
	if err != nil {
		return failed(err)
	}
	if err := checkResponse(rsp, false); err != nil {
		return failed(err)
	}
	return s, nil
}

type h3Stream struct {
	*http3.RequestStream
	stopContext func() bool
}

func (s *h3Stream) CloseWrite() error { return s.RequestStream.Close() }
func (s *h3Stream) Close() error {
	s.stopContext()
	s.CancelRead(0)
	s.RequestStream.Close()
	return nil
}

// OpenTCPH3 opens a TCP tunnel over an HTTP/3 connection.
func (c *relayClient) openTCPH3(ctx context.Context, h *h3Conn, target string) (stream, error) {
	req := &http.Request{Method: http.MethodConnect, Host: target,
		URL: &url.URL{Host: target}, Header: c.header()}
	str, err := c.h3Request(ctx, h, req.WithContext(ctx))
	if err != nil {
		return nil, err
	}
	return str, nil
}

func (c *relayClient) openUDPH3(ctx context.Context, h *h3Conn, host, port string) (packetConn, error) {
	path, err := c.udpPath(host, port)
	if err != nil {
		return nil, err
	}
	u, err := url.Parse("https://" + c.authority() + path)
	if err != nil {
		return nil, err
	}
	hdr := c.header()
	hdr.Set("Capsule-Protocol", "?1")
	req := &http.Request{Method: http.MethodConnect, Proto: connectUDP, Host: c.authority(), URL: u, Header: hdr}
	str, err := c.h3Request(ctx, h, req.WithContext(ctx))
	if err != nil {
		return nil, err
	}
	if !c.NoDatagrams && h.cc.Settings().EnableDatagrams {
		return newH3Datagrams(str), nil
	}
	return newCapsuleConn(str), nil
}

// h3Datagrams receives both QUIC HTTP Datagrams and DATAGRAM capsules.
// RFC 9297 section 3.5 gives them the same semantics even when QUIC
// Datagrams were negotiated. Both readers feed one bounded UDP queue.
type h3Datagrams struct {
	str     *h3Stream
	packets chan []byte
	done    chan struct{}
	err     error
}

func newH3Datagrams(str *h3Stream) *h3Datagrams {
	d := &h3Datagrams{str: str, packets: make(chan []byte, 64), done: make(chan struct{})}
	deliver := func(p []byte) {
		select {
		case d.packets <- append([]byte(nil), p...):
		default: // a full UDP receive queue drops packets
		}
	}
	nativeDone := make(chan error, 1)
	go func() {
		for {
			b, err := str.ReceiveDatagram(context.Background())
			if err != nil {
				nativeDone <- err
				return
			}
			id, n, err := quicvarint.Parse(b)
			if err != nil || id != 0 {
				continue
			}
			if len(b)-n > maxUDPPayload {
				str.CancelWrite(quic.StreamErrorCode(http3.ErrCodeMessageError))
				str.CancelRead(quic.StreamErrorCode(http3.ErrCodeMessageError))
				nativeDone <- errMalformed
				return
			}
			deliver(b[n:])
		}
	}()
	go func() {
		defer str.stopContext()
		err := readCapsules(str, deliver)
		if err == nil {
			err = io.EOF
		} else {
			// A parser failure or read deadline must also wake the native
			// receiver, which is not itself a stream Read operation.
			code := quic.StreamErrorCode(http3.ErrCodeRequestCanceled)
			if errors.Is(err, errMalformed) {
				code = quic.StreamErrorCode(http3.ErrCodeMessageError)
			}
			str.CancelWrite(code)
			str.CancelRead(code)
		}
		// Normal FIN lets quic-go drain native datagrams already queued
		// before reporting EOF. Publish completion only after both readers
		// finish, leaving their bounded merged queue available to Receive.
		nativeErr := <-nativeDone
		if errors.Is(nativeErr, errMalformed) || errors.Is(err, io.EOF) && !errors.Is(nativeErr, io.EOF) {
			err = nativeErr
		}
		d.err = err
		close(d.done)
	}()
	return d
}

func (d *h3Datagrams) Send(p []byte) error {
	return d.str.SendDatagram(append([]byte{0}, p...))
}

func (d *h3Datagrams) Receive(ctx context.Context) ([]byte, error) {
	select {
	case p := <-d.packets:
		return p, nil
	case <-d.done:
		select {
		case p := <-d.packets:
			return p, nil
		default:
		}
		return nil, d.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (d *h3Datagrams) Close() error {
	err := d.str.Close()
	<-d.done
	return err
}

// ---- HTTP/2 ----

type h2Conn struct {
	tls *tls.Conn
	cc  *http2.ClientConn
}

func (c *relayClient) dialH2(ctx context.Context) (*h2Conn, error) {
	d := tls.Dialer{Config: c.tlsConfig("h2")}
	conn, err := d.DialContext(ctx, "tcp", c.Address)
	if err != nil {
		return nil, err
	}
	tc := conn.(*tls.Conn)
	if tc.ConnectionState().NegotiatedProtocol != "h2" {
		tc.Close()
		return nil, errors.New("the server did not negotiate HTTP/2")
	}
	cc, err := (&http2.Transport{}).NewClientConn(tc)
	if err != nil {
		tc.Close()
		return nil, err
	}
	return &h2Conn{tls: tc, cc: cc}, nil
}

func (h *h2Conn) Close() error { return h.cc.Close() }

type h2Stream struct {
	body io.ReadCloser
	pw   *io.PipeWriter
}

func (s *h2Stream) Read(p []byte) (int, error)  { return s.body.Read(p) }
func (s *h2Stream) Write(p []byte) (int, error) { return s.pw.Write(p) }
func (s *h2Stream) CloseWrite() error           { return s.pw.Close() }
func (s *h2Stream) Close() error {
	s.pw.CloseWithError(errors.New("closed"))
	return s.body.Close()
}

func (c *relayClient) h2Request(ctx context.Context, h *h2Conn, req *http.Request) (*h2Stream, error) {
	pr, pw := io.Pipe()
	req.Body = pr
	req.ContentLength = -1
	rsp, err := h.cc.RoundTrip(req.WithContext(ctx))
	if err != nil {
		pw.Close()
		return nil, err
	}
	if err := checkResponse(rsp, false); err != nil {
		pw.Close()
		rsp.Body.Close()
		return nil, err
	}
	return &h2Stream{body: rsp.Body, pw: pw}, nil
}

func (c *relayClient) openTCPH2(ctx context.Context, h *h2Conn, target string) (stream, error) {
	req := &http.Request{Method: http.MethodConnect, Host: target, URL: &url.URL{Host: target}, Header: c.header()}
	return c.h2Request(ctx, h, req)
}

func (c *relayClient) openUDPH2(ctx context.Context, h *h2Conn, host, port string) (packetConn, error) {
	path, err := c.udpPath(host, port)
	if err != nil {
		return nil, err
	}
	u, err := url.Parse("https://" + c.authority() + path)
	if err != nil {
		return nil, err
	}
	hdr := c.header()
	hdr.Set(":protocol", connectUDP)
	hdr.Set("Capsule-Protocol", "?1")
	req := &http.Request{Method: http.MethodConnect, Host: c.authority(), URL: u, Header: hdr}
	s, err := c.h2Request(ctx, h, req)
	if err != nil {
		return nil, err
	}
	return newCapsuleConn(s), nil
}

// ---- HTTP/1.1 ----

type h1Stream struct {
	conn        *tls.Conn
	br          *bufio.Reader
	stopContext func() bool
}

func (s *h1Stream) Read(p []byte) (int, error)  { return s.br.Read(p) }
func (s *h1Stream) Write(p []byte) (int, error) { return s.conn.Write(p) }
func (s *h1Stream) CloseWrite() error           { return s.conn.CloseWrite() }
func (s *h1Stream) Close() error {
	defer s.stopContext()
	return s.conn.Close()
}

func (c *relayClient) h1Request(ctx context.Context, request string, upgrade bool) (*h1Stream, error) {
	d := tls.Dialer{Config: c.tlsConfig("http/1.1")}
	conn, err := d.DialContext(ctx, "tcp", c.Address)
	if err != nil {
		return nil, err
	}
	tc := conn.(*tls.Conn)
	// The dial context only covers the TLS handshake. Keep cancellation
	// attached while sending headers and for the established tunnel's I/O.
	// Closing TLS itself can wait behind a blocked write of close_notify;
	// close the transport directly so socket backpressure cannot delay it.
	stopContext := context.AfterFunc(ctx, func() { _ = tc.NetConn().Close() })
	failed := func(err error) (*h1Stream, error) {
		stopContext()
		_ = tc.NetConn().Close()
		if ctx.Err() != nil {
			err = ctx.Err()
		} else if deadline, ok := ctx.Deadline(); ok && !time.Now().Before(deadline) && isTimeout(err) {
			err = context.DeadlineExceeded
		}
		return nil, err
	}
	if deadline, ok := ctx.Deadline(); ok {
		if err := tc.SetDeadline(deadline); err != nil {
			return failed(err)
		}
	}
	if _, err := io.WriteString(tc, request); err != nil {
		return failed(err)
	}
	br := bufio.NewReader(tc)
	rsp, err := http.ReadResponse(br, nil)
	if err != nil {
		return failed(err)
	}
	if err := checkResponse(rsp, upgrade); err != nil {
		return failed(err)
	}
	if err := ctx.Err(); err != nil {
		return failed(err)
	}
	return &h1Stream{conn: tc, br: br, stopContext: stopContext}, nil
}

func (c *relayClient) authLine() string {
	if c.Authorization == "" {
		return ""
	}
	return "Authorization: " + c.Authorization + "\r\n"
}

func (c *relayClient) openTCPH1(ctx context.Context, target string) (stream, error) {
	req := "CONNECT " + target + " HTTP/1.1\r\nHost: " + target + "\r\n" + c.authLine() + "\r\n"
	return c.h1Request(ctx, req, false)
}

func (c *relayClient) openUDPH1(ctx context.Context, host, port string) (packetConn, error) {
	path, err := c.udpPath(host, port)
	if err != nil {
		return nil, err
	}
	req := "GET " + path + " HTTP/1.1\r\nHost: " + c.authority() + "\r\nConnection: Upgrade\r\nUpgrade: connect-udp\r\n" +
		"Capsule-Protocol: ?1\r\n" + c.authLine() + "\r\n"
	s, err := c.h1Request(ctx, req, true)
	if err != nil {
		return nil, err
	}
	return newCapsuleConn(s), nil
}

// ---- capsules ----

// capsuleConn carries UDP payloads as DATAGRAM capsules on a stream.
type capsuleConn struct {
	s       stream
	packets chan []byte
	errOnce sync.Once
	err     error
	done    chan struct{}
	wmu     sync.Mutex
}

func newCapsuleConn(s stream) *capsuleConn {
	c := &capsuleConn{s: s, packets: make(chan []byte, 64), done: make(chan struct{})}
	go func() {
		err := readCapsules(s, func(p []byte) {
			select {
			case c.packets <- append([]byte(nil), p...):
			default: // like a full socket buffer: drop
			}
		})
		if err == nil {
			err = io.EOF
		}
		c.errOnce.Do(func() { c.err = err; close(c.done) })
	}()
	return c
}

func (c *capsuleConn) Send(p []byte) error {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	_, err := c.s.Write(appendDatagramCapsule(nil, p))
	return err
}

func (c *capsuleConn) Receive(ctx context.Context) ([]byte, error) {
	select {
	case p := <-c.packets:
		return p, nil
	case <-c.done:
		select {
		case p := <-c.packets:
			return p, nil
		default:
		}
		return nil, c.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (c *capsuleConn) Close() error { return c.s.Close() }
