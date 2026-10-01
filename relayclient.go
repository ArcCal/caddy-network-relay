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

func checkResponse(rsp *http.Response, want int) error {
	if rsp.StatusCode != want {
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
	qconf := &quic.Config{EnableDatagrams: !c.NoDatagrams, InitialPacketSize: 1350}
	conn, err := quic.DialAddr(ctx, c.Address, c.tlsConfig(http3.NextProtoH3), qconf)
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

func (c *relayClient) h3Request(ctx context.Context, h *h3Conn, req *http.Request) (*http3.RequestStream, error) {
	str, err := h.cc.OpenRequestStream(ctx)
	if err != nil {
		return nil, err
	}
	if err := str.SendRequestHeader(req); err != nil {
		return nil, err
	}
	rsp, err := str.ReadResponse()
	if err != nil {
		return nil, err
	}
	if err := checkResponse(rsp, http.StatusOK); err != nil {
		str.CancelRead(0)
		str.Close()
		return nil, err
	}
	return str, nil
}

type h3Stream struct{ *http3.RequestStream }

func (s h3Stream) CloseWrite() error { return s.RequestStream.Close() }
func (s h3Stream) Close() error {
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
	return h3Stream{str}, nil
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
		return &h3Datagrams{str}, nil
	}
	return newCapsuleConn(h3Stream{str}), nil
}

type h3Datagrams struct{ str *http3.RequestStream }

func (d *h3Datagrams) Send(p []byte) error {
	return d.str.SendDatagram(append([]byte{0}, p...))
}

func (d *h3Datagrams) Receive(ctx context.Context) ([]byte, error) {
	for {
		b, err := d.str.ReceiveDatagram(ctx)
		if err != nil {
			return nil, err
		}
		id, n, err := quicvarint.Parse(b)
		if err == nil && id == 0 {
			return b[n:], nil
		}
	}
}

func (d *h3Datagrams) Close() error {
	d.str.CancelRead(0)
	return d.str.Close()
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
	if err := checkResponse(rsp, http.StatusOK); err != nil {
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
	conn *tls.Conn
	br   *bufio.Reader
}

func (s *h1Stream) Read(p []byte) (int, error)  { return s.br.Read(p) }
func (s *h1Stream) Write(p []byte) (int, error) { return s.conn.Write(p) }
func (s *h1Stream) CloseWrite() error           { return s.conn.CloseWrite() }
func (s *h1Stream) Close() error                { return s.conn.Close() }

func (c *relayClient) h1Request(ctx context.Context, request string, want int) (*h1Stream, error) {
	d := tls.Dialer{Config: c.tlsConfig("http/1.1")}
	conn, err := d.DialContext(ctx, "tcp", c.Address)
	if err != nil {
		return nil, err
	}
	tc := conn.(*tls.Conn)
	if deadline, ok := ctx.Deadline(); ok {
		tc.SetDeadline(deadline)
	}
	if _, err := io.WriteString(tc, request); err != nil {
		tc.Close()
		return nil, err
	}
	br := bufio.NewReader(tc)
	rsp, err := http.ReadResponse(br, nil)
	if err != nil {
		tc.Close()
		return nil, err
	}
	if err := checkResponse(rsp, want); err != nil {
		tc.Close()
		return nil, err
	}
	tc.SetDeadline(time.Time{})
	return &h1Stream{conn: tc, br: br}, nil
}

func (c *relayClient) authLine() string {
	if c.Authorization == "" {
		return ""
	}
	return "Authorization: " + c.Authorization + "\r\n"
}

func (c *relayClient) openTCPH1(ctx context.Context, target string) (stream, error) {
	req := "CONNECT " + target + " HTTP/1.1\r\nHost: " + target + "\r\n" + c.authLine() + "\r\n"
	return c.h1Request(ctx, req, http.StatusOK)
}

func (c *relayClient) openUDPH1(ctx context.Context, host, port string) (packetConn, error) {
	path, err := c.udpPath(host, port)
	if err != nil {
		return nil, err
	}
	req := "GET " + path + " HTTP/1.1\r\nHost: " + c.authority() + "\r\nConnection: Upgrade\r\nUpgrade: connect-udp\r\n" +
		"Capsule-Protocol: ?1\r\n" + c.authLine() + "\r\n"
	s, err := c.h1Request(ctx, req, http.StatusSwitchingProtocols)
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
