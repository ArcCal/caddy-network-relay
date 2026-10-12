package networkrelay

// Conformance tests at the frame level: RFC 9114 (HTTP/3 CONNECT), RFC 9297
// (HTTP Datagrams, Capsules), RFC 9298 (CONNECT-UDP), RFC 9110/9113
// (CONNECT responses). The raw clients here send what well-behaved client
// libraries never would.

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/quic-go/qpack"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/quic-go/quicvarint"
	"golang.org/x/net/http2"
)

// rawH3 is a minimal HTTP/3 client over a QUIC connection.
type rawH3 struct {
	t    *testing.T
	conn *quic.Conn
}

func dialRawH3(t *testing.T, port int) *rawH3 {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := quic.DialAddr(ctx, "127.0.0.1:"+strconv.Itoa(port),
		&tls.Config{ServerName: "relay.test", RootCAs: pki().pool, NextProtos: []string{http3.NextProtoH3}},
		&quic.Config{EnableDatagrams: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.CloseWithError(0, "") })
	ctrl, err := conn.OpenUniStream()
	if err != nil {
		t.Fatal(err)
	}
	// Control stream: type 0, SETTINGS with SETTINGS_H3_DATAGRAM = 1.
	settings := quicvarint.Append(quicvarint.Append(nil, 0x33), 1)
	b := quicvarint.Append(nil, 0x00)
	b = quicvarint.Append(b, 0x4)
	b = quicvarint.Append(b, uint64(len(settings)))
	ctrl.Write(append(b, settings...))
	return &rawH3{t: t, conn: conn}
}

func h3Frame(typ uint64, payload []byte) []byte {
	b := quicvarint.Append(nil, typ)
	b = quicvarint.Append(b, uint64(len(payload)))
	return append(b, payload...)
}

type rawResponse struct {
	status string
	fields map[string][]string
}

// request opens a stream, sends HEADERS, and reads the response HEADERS.
func (h *rawH3) request(fields [][2]string) (*quic.Stream, *bufio.Reader, rawResponse) {
	h.t.Helper()
	str, err := h.conn.OpenStreamSync(context.Background())
	if err != nil {
		h.t.Fatal(err)
	}
	str.SetDeadline(time.Now().Add(10 * time.Second))
	var buf bytes.Buffer
	enc := qpack.NewEncoder(&buf)
	for _, f := range fields {
		enc.WriteField(qpack.HeaderField{Name: f[0], Value: f[1]})
	}
	if _, err := str.Write(h3Frame(0x1, buf.Bytes())); err != nil {
		h.t.Fatal(err)
	}
	br := bufio.NewReader(str)
	rsp := h.readHeaders(br)
	return str, br, rsp
}

func (h *rawH3) readHeaders(br *bufio.Reader) rawResponse {
	h.t.Helper()
	for {
		typ, err := quicvarint.Read(br)
		if err != nil {
			h.t.Fatalf("reading the response: %v", err)
		}
		length, _ := quicvarint.Read(br)
		payload := make([]byte, length)
		if _, err := io.ReadFull(br, payload); err != nil {
			h.t.Fatal(err)
		}
		if typ != 0x1 {
			continue
		}
		rsp := rawResponse{fields: map[string][]string{}}
		decode := qpack.NewDecoder().Decode(payload)
		for {
			hf, err := decode()
			if err == io.EOF {
				break
			}
			if err != nil {
				h.t.Fatal(err)
			}
			if hf.Name == ":status" {
				rsp.status = hf.Value
			} else {
				rsp.fields[hf.Name] = append(rsp.fields[hf.Name], hf.Value)
			}
		}
		return rsp
	}
}

// readData reads DATA frame payloads until n bytes arrived.
func readData(t *testing.T, br *bufio.Reader, n int) ([]byte, error) {
	t.Helper()
	var out []byte
	for len(out) < n {
		typ, err := quicvarint.Read(br)
		if err != nil {
			return out, err
		}
		length, err := quicvarint.Read(br)
		if err != nil {
			return out, err
		}
		payload := make([]byte, length)
		if _, err := io.ReadFull(br, payload); err != nil {
			return out, err
		}
		if typ == 0x0 {
			out = append(out, payload...)
		}
	}
	return out, nil
}

func (h *rawH3) datagram(str *quic.Stream, payload []byte) {
	h.t.Helper()
	b := quicvarint.Append(nil, uint64(str.StreamID())/4)
	if err := h.conn.SendDatagram(append(b, payload...)); err != nil {
		h.t.Fatal(err)
	}
}

// connError waits for the connection to close and returns its error code.
func (h *rawH3) connError() quic.ApplicationErrorCode {
	h.t.Helper()
	select {
	case <-h.conn.Context().Done():
	case <-time.After(5 * time.Second):
		h.t.Fatal("the connection stayed open")
	}
	var ae *quic.ApplicationError
	if errors.As(context.Cause(h.conn.Context()), &ae) {
		return ae.ErrorCode
	}
	h.t.Fatalf("connection closed with %v", context.Cause(h.conn.Context()))
	return 0
}

func authField() [2]string {
	return [2]string{"authorization", BasicAuthorization("alice", testPassword)}
}

func connectTCPFields(target string) [][2]string {
	return [][2]string{{":method", "CONNECT"}, {":authority", target}, authField()}
}

func connectUDPFields(host, port string) [][2]string {
	tm, _ := parseUDPTemplate(DefaultUDPTemplate)
	return [][2]string{{":method", "CONNECT"}, {":protocol", "connect-udp"}, {":scheme", "https"},
		{":authority", "relay.test"}, {":path", tm.Expand(host, port)}, {"capsule-protocol", "?1"}, authField()}
}

// The server's SETTINGS enable extended CONNECT (RFC 9220) and HTTP
// Datagrams (RFC 9297 §2.1.1), and the QUIC DATAGRAM extension is on.
func TestHTTP3Settings(t *testing.T) {
	port, _ := startRelay(t, nil, nil)
	ctx := testCtx(t)
	h, err := client(port).dialH3(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	s := h.cc.Settings()
	if !s.EnableExtendedConnect || !s.EnableDatagrams || !h.conn.ConnectionState().SupportsDatagrams.Remote {
		t.Fatalf("settings %+v, QUIC datagrams %v", s, h.conn.ConnectionState().SupportsDatagrams)
	}
}

// RFC 9110 §9.3.6: no Content-Length or Transfer-Encoding in a 2xx answer
// to CONNECT; RFC 9297 §3.2: no Content-Length, Content-Type or
// Transfer-Encoding with the Capsule Protocol, and Capsule-Protocol only
// on 2xx/101.
func TestSuccessResponseHeaders(t *testing.T) {
	port, _ := startRelay(t, nil, nil)
	target := echoTCP(t)
	host, uport := echoUDP(t)
	forbidden := []string{"content-length", "content-type", "transfer-encoding"}
	check := func(t *testing.T, name string, status string, fields map[string][]string, wantStatus string, capsule bool) {
		t.Helper()
		if status != wantStatus {
			t.Fatalf("%s: status %s", name, status)
		}
		for _, f := range forbidden {
			if _, ok := fields[f]; ok {
				t.Errorf("%s: %s %v", name, f, fields[f])
			}
		}
		if got := fields["capsule-protocol"]; capsule != (len(got) == 1 && got[0] == "?1") {
			t.Errorf("%s: capsule-protocol %v", name, got)
		}
	}

	t.Run("h3", func(t *testing.T) {
		h := dialRawH3(t, port)
		_, _, rsp := h.request(connectTCPFields(target))
		check(t, "TCP", rsp.status, rsp.fields, "200", false)
		_, _, rsp = h.request(connectUDPFields(host, uport))
		check(t, "UDP", rsp.status, rsp.fields, "200", true)
		_, _, rsp = h.request(connectUDPFields("192.0.2.1", "25"))
		if _, ok := rsp.fields["capsule-protocol"]; ok || rsp.status == "200" {
			t.Errorf("refusal: %s %v", rsp.status, rsp.fields)
		}
	})
	t.Run("h2", func(t *testing.T) {
		if !http2ExtendedConnect() {
			t.Skip("extended CONNECT is off")
		}
		r := dialRawH2(t, port)
		defer r.conn.Close()
		get := func(stream uint32, fields [][2]string) (string, map[string][]string) {
			r.headers(stream, fields)
			f := r.next(stream).(*http2.MetaHeadersFrame)
			m := map[string][]string{}
			for _, hf := range f.RegularFields() {
				m[hf.Name] = append(m[hf.Name], hf.Value)
			}
			return f.PseudoValue("status"), m
		}
		st, m := get(1, connectTCPFields(target))
		check(t, "TCP", st, m, "200", false)
		st, m = get(3, connectUDPFields(host, uport))
		check(t, "UDP", st, m, "200", true)
	})
	t.Run("h1", func(t *testing.T) {
		for _, c := range []struct {
			req, status string
			capsule     bool
		}{
			{"CONNECT " + target + " HTTP/1.1\r\nHost: " + target + "\r\n", "200", false},
			{"GET " + mustExpand(host, uport) + " HTTP/1.1\r\nHost: relay.test\r\nConnection: Upgrade\r\nUpgrade: connect-udp\r\nCapsule-Protocol: ?1\r\n", "101", true},
		} {
			conn := tlsDial(t, port, "http/1.1")
			io.WriteString(conn, c.req+"Authorization: "+BasicAuthorization("alice", testPassword)+"\r\n\r\n")
			rsp, err := http.ReadResponse(bufio.NewReader(conn), nil)
			if err != nil {
				t.Fatal(err)
			}
			m := map[string][]string{}
			for k, v := range rsp.Header {
				m[strings.ToLower(k)] = v
			}
			check(t, c.req[:8], strconv.Itoa(rsp.StatusCode), m, c.status, c.capsule)
			if c.status == "101" && (!headerHasToken(rsp.Header, "Connection", "upgrade") || rsp.Header.Values("Upgrade")[0] != "connect-udp" || len(rsp.Header.Values("Upgrade")) != 1) {
				t.Errorf("101 headers: %v", rsp.Header)
			}
			conn.Close()
		}
	})
}

func mustExpand(host, port string) string {
	tm, _ := parseUDPTemplate(DefaultUDPTemplate)
	return tm.Expand(host, port)
}

func tlsDial(t *testing.T, port int, proto string) *tls.Conn {
	t.Helper()
	c, err := tls.Dial("tcp", "127.0.0.1:"+strconv.Itoa(port), &tls.Config{
		ServerName: "relay.test", RootCAs: pki().pool, NextProtos: []string{proto}})
	if err != nil {
		t.Fatal(err)
	}
	c.SetDeadline(time.Now().Add(10 * time.Second))
	return c
}

// RFC 9114 §4.4: after CONNECT only DATA frames; another known frame type
// is a connection error H3_FRAME_UNEXPECTED; unknown types are ignored
// (§9). §7.1: a frame cut off by the end of the stream is H3_FRAME_ERROR.
func TestHTTP3ConnectStreamFrames(t *testing.T) {
	port, _ := startRelay(t, nil, nil)
	target := echoTCP(t)

	t.Run("unknown frame types are skipped", func(t *testing.T) {
		h := dialRawH3(t, port)
		str, br, rsp := h.request(connectTCPFields(target))
		if rsp.status != "200" {
			t.Fatal(rsp.status)
		}
		str.Write(h3Frame(0x21, []byte("grease"))) // reserved for greasing (RFC 9114 §7.2.8)
		str.Write(h3Frame(0x0, nil))               // empty DATA
		str.Write(h3Frame(0x0, []byte("hello")))
		got, err := readData(t, br, 5)
		if err != nil || string(got) != "hello" {
			t.Fatalf("got %q, %v", got, err)
		}
	})
	for _, c := range []struct {
		name  string
		frame []byte
		code  quic.ApplicationErrorCode
	}{
		{"trailing HEADERS", h3Frame(0x1, qpackHeaders([][2]string{{"x-trailer", "1"}})), h3FrameUnexpected},
		{"SETTINGS", h3Frame(0x4, nil), h3FrameUnexpected},
		{"reserved HTTP/2 type", h3Frame(0x6, nil), h3FrameUnexpected},
		{"GOAWAY", h3Frame(0x7, []byte{0}), h3FrameUnexpected},
	} {
		t.Run(c.name, func(t *testing.T) {
			h := dialRawH3(t, port)
			str, br, rsp := h.request(connectTCPFields(target))
			if rsp.status != "200" {
				t.Fatal(rsp.status)
			}
			str.Write(h3Frame(0x0, []byte("ok")))
			if got, err := readData(t, br, 2); err != nil || string(got) != "ok" {
				t.Fatalf("before: %q %v", got, err)
			}
			str.Write(c.frame)
			if code := h.connError(); code != c.code {
				t.Fatalf("code %#x, want %#x", code, c.code)
			}
		})
	}
	t.Run("truncated DATA frame", func(t *testing.T) {
		h := dialRawH3(t, port)
		str, _, rsp := h.request(connectTCPFields(target))
		if rsp.status != "200" {
			t.Fatal(rsp.status)
		}
		str.Write(append(quicvarint.Append(quicvarint.Append(nil, 0x0), 10), "abc"...))
		str.Close()
		if code := h.connError(); code != h3FrameError {
			t.Fatalf("code %#x", code)
		}
	})
}

func qpackHeaders(fields [][2]string) []byte {
	var buf bytes.Buffer
	enc := qpack.NewEncoder(&buf)
	for _, f := range fields {
		enc.WriteField(qpack.HeaderField{Name: f[0], Value: f[1]})
	}
	return buf.Bytes()
}

// RFC 9297 §2.1: an HTTP Datagram on a request without datagram semantics
// aborts it with H3_DATAGRAM_ERROR; after the receive side closed it is
// dropped silently.
func TestHTTP3DatagramsOnOtherRequests(t *testing.T) {
	big := strings.Repeat("x", 4<<20)
	port, _ := startRelay(t, nil, map[string]any{
		"routes": []any{map[string]any{"handle": []any{
			map[string]any{"handler": "network_relay", "blocked_destinations": []string{},
				"users": []map[string]string{{"name": "alice", "password_hash": testHash}}},
			map[string]any{"handler": "static_response", "status_code": 200, "body": big},
		}}},
	})
	target := echoTCP(t)

	t.Run("TCP tunnel", func(t *testing.T) {
		h := dialRawH3(t, port)
		str, br, rsp := h.request(connectTCPFields(target))
		if rsp.status != "200" {
			t.Fatal(rsp.status)
		}
		h.datagram(str, []byte("not allowed"))
		_, err := readData(t, br, 1)
		if code := streamCode(err); code != h3DatagramError {
			t.Fatalf("got %v (code %#x)", err, code)
		}
		select {
		case <-str.Context().Done():
		case <-time.After(2 * time.Second):
			t.Fatal("datagram protocol error did not stop the request direction")
		}
		if _, err := str.Write([]byte("after reset")); streamCode(err) != h3DatagramError {
			t.Fatalf("request direction reset: %v, want H3_DATAGRAM_ERROR", err)
		}
	})
	t.Run("TCP tunnel after the client's FIN", func(t *testing.T) {
		h := dialRawH3(t, port)
		str, br, rsp := h.request(connectTCPFields(target))
		if rsp.status != "200" {
			t.Fatal(rsp.status)
		}
		str.Write(h3Frame(0x0, []byte("last words")))
		str.Close()
		time.Sleep(100 * time.Millisecond) // the relay reads the FIN
		h.datagram(str, []byte("late"))
		got, err := readData(t, br, 10)
		if err != nil || string(got) != "last words" {
			t.Fatalf("got %q, %v", got, err)
		}
	})
	t.Run("website download in progress", func(t *testing.T) {
		h := dialRawH3(t, port)
		str, br, rsp := h.request([][2]string{{":method", "GET"}, {":scheme", "https"}, {":authority", "relay.test"}, {":path", "/"}})
		if rsp.status != "200" {
			t.Fatal(rsp.status)
		}
		h.datagram(str, []byte("not allowed"))
		_, err := readData(t, br, len(big))
		if code := streamCode(err); code != h3DatagramError {
			t.Fatalf("got %v (code %#x)", err, code)
		}
	})
	t.Run("UDP tunnel accepts them", func(t *testing.T) {
		host, uport := echoUDP(t)
		h := dialRawH3(t, port)
		str, _, rsp := h.request(connectUDPFields(host, uport))
		if rsp.status != "200" {
			t.Fatal(rsp.status)
		}
		got := h.udpRoundTrip(str, []byte("udp ok"))
		if string(got) != "udp ok" {
			t.Fatalf("got %q", got)
		}
	})
}

// udpRoundTrip sends a UDP payload as an HTTP Datagram (context ID 0) and
// waits for the echo, retrying on loss.
func (h *rawH3) udpRoundTrip(str *quic.Stream, payload []byte) []byte {
	h.t.Helper()
	want := uint64(str.StreamID()) / 4
	for attempt := 0; attempt < 5; attempt++ {
		h.datagram(str, append([]byte{0}, payload...))
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		d, err := h.conn.ReceiveDatagram(ctx)
		cancel()
		if err != nil {
			continue
		}
		q, n, _ := quicvarint.Parse(d)
		if q == want && len(d) > n && d[n] == 0 {
			return d[n+1:]
		}
	}
	h.t.Fatal("no answer")
	return nil
}

// RFC 9298 §5: a client may send datagrams before the response; the relay
// buffers them while it authenticates.
func TestHTTP3EarlyDatagrams(t *testing.T) {
	port, _ := startRelay(t, nil, nil)
	host, uport := echoUDP(t)
	h := dialRawH3(t, port)
	str, err := h.conn.OpenStreamSync(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	// A fresh credential header, so the relay has to run Argon2id first.
	fields := connectUDPFields(host, uport)
	str.Write(h3Frame(0x1, qpackHeaders(fields)))
	// Let quic-go register the stream first: a datagram that arrives before
	// that is dropped, which RFC 9297 §2.1 allows. Authentication (tens of
	// milliseconds of Argon2id) is still running when this one arrives.
	time.Sleep(5 * time.Millisecond)
	h.datagram(str, append([]byte{0}, "early bird"...))
	br := bufio.NewReader(str)
	if rsp := h.readHeaders(br); rsp.status != "200" {
		t.Fatal(rsp.status)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	d, err := h.conn.ReceiveDatagram(ctx)
	if err != nil {
		t.Fatalf("the early datagram was not relayed: %v", err)
	}
	if _, n, _ := quicvarint.Parse(d); string(d[n+1:]) != "early bird" {
		t.Fatalf("got %q", d)
	}
}

// RFC 9298 §3.1: when the operating system reports the socket unusable
// (an ICMP Destination Unreachable, here port unreachable on loopback),
// the proxy closes the request stream.
func TestUDPUnreachableClosesTheTunnel(t *testing.T) {
	port, _ := startRelay(t, nil, nil)
	c, _ := net.ListenPacket("udp", "127.0.0.1:0")
	closed := strconv.Itoa(c.LocalAddr().(*net.UDPAddr).Port)
	c.Close()
	for _, v := range versions {
		t.Run(v.name, func(t *testing.T) {
			if v.name == "h2" && !goH2ClientExtendedConnect {
				t.Skip("Go's HTTP/2 client cannot send extended CONNECT in this build")
			}
			ctx := testCtx(t)
			p, done, err := v.openUDP(ctx, client(port), "127.0.0.1", closed)
			if err != nil {
				t.Fatal(err)
			}
			defer done()
			defer p.Close()
			for i := 0; i < 3; i++ {
				p.Send([]byte("anyone?"))
			}
			rctx, cancel := context.WithTimeout(ctx, 5*time.Second)
			defer cancel()
			_, err = p.Receive(rctx)
			if err == nil || errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("tunnel still open: %v", err)
			}
			if v.name == "h3" {
				if code := streamCode(err); code != h3ConnectError {
					t.Fatalf("code %#x (%v)", code, err)
				}
			}
		})
	}
}

// RFC 9298 §3.2: malformed HTTP/1.1 CONNECT-UDP requests get 400; the
// Connection header is a token list (RFC 9110 §7.6.1).
func TestHTTP1UpgradeRequests(t *testing.T) {
	port, _ := startRelay(t, nil, nil)
	host, uport := echoUDP(t)
	path := mustExpand(host, uport)
	auth := "Authorization: " + BasicAuthorization("alice", testPassword) + "\r\n"
	for _, c := range []struct {
		req    string
		status int
	}{
		{"GET " + path + " HTTP/1.1\r\nHost: relay.test\r\nConnection: keep-alive, Upgrade\r\nUpgrade: connect-udp\r\n", 101},
		{"GET " + path + " HTTP/1.1\r\nHost: relay.test\r\nConnection: upgrade\r\nUpgrade: foo, Connect-UDP\r\n", 101},
		{"POST " + path + " HTTP/1.1\r\nHost: relay.test\r\nConnection: Upgrade\r\nUpgrade: connect-udp\r\n", 400},
		{"GET " + path + " HTTP/1.1\r\nHost: relay.test\r\nConnection: keep-alive\r\nUpgrade: connect-udp\r\n", 400},
		{"GET " + path + " HTTP/1.1\r\nHost: relay.test\r\nConnection: Upgrade\r\nUpgrade: connect-udp\r\nContent-Length: 3\r\n\r\nabc", 400},
		{"GET " + path + " HTTP/1.1\r\nHost: relay.test\r\nHost: relay.test\r\nConnection: Upgrade\r\nUpgrade: connect-udp\r\n", 400},
	} {
		conn := tlsDial(t, port, "http/1.1")
		req := c.req
		if i := strings.Index(req, "\r\n\r\n"); i >= 0 {
			req = req[:i+2] + auth + req[i+2:]
		} else {
			req += auth + "\r\n"
		}
		io.WriteString(conn, req)
		rsp, err := http.ReadResponse(bufio.NewReader(conn), nil)
		if err != nil {
			t.Fatalf("%q: %v", c.req, err)
		}
		if rsp.StatusCode != c.status {
			t.Errorf("%q: %d, want %d", strings.SplitN(c.req, "\r\n", 4)[2:], rsp.StatusCode, c.status)
		}
		conn.Close()
	}
}

// RFC 9297 §3.2: CONNECT-UDP requests carry no content headers.
func TestCapsuleRequestsWithContentHeaders(t *testing.T) {
	port, _ := startRelay(t, nil, nil)
	host, uport := echoUDP(t)
	for _, extra := range [][2]string{{"content-length", "0"}, {"content-type", "application/octet-stream"}} {
		h := dialRawH3(t, port)
		expectMalformedH3(t, h, append(connectUDPFields(host, uport), extra), false)
		if !http2ExtendedConnect() {
			continue
		}
		r := dialRawH2(t, port)
		r.headers(1, append(connectUDPFields(host, uport), extra))
		f := r.next(1)
		if h, ok := f.(*http2.MetaHeadersFrame); !ok || h.PseudoValue("status") != "400" {
			t.Errorf("h2 with %s: %v", extra[0], f)
		}
		r.conn.Close()
	}
}

// The accessor for a request's HTTP/3 stream must keep working with the
// quic-go version in go.mod.
func TestRequestStreamAccessor(t *testing.T) {
	found := make(chan bool, 1)
	h := h3Handler{next: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		found <- requestStream(w) != nil && r.Context().Value(datagramGuardKey{}) != nil
	})}
	l, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	cert, _ := tls.X509KeyPair([]byte(pki().certPEM), []byte(pki().keyPEM))
	srv := &http3.Server{Handler: h, TLSConfig: http3.ConfigureTLSConfig(&tls.Config{Certificates: []tls.Certificate{cert}})}
	go srv.Serve(l)
	defer srv.Close()
	c := client(0)
	c.Address = l.LocalAddr().String()
	ctx := testCtx(t)
	hc, err := c.dialH3(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer hc.Close()
	req, _ := http.NewRequestWithContext(ctx, "GET", "https://relay.test/", nil)
	if _, err := hc.cc.RoundTrip(req); err != nil {
		t.Fatal(err)
	}
	if !<-found {
		t.Fatal("requestStream does not find quic-go's stream; update h3.go for this quic-go version")
	}
}

// An extended CONNECT is never answered 2xx by the website: connect-udp
// to another path gets 404 (405 without credentials); other protocols
// (for example WebSocket over HTTP/2 to a reverse proxy) reach the site.
func TestExtendedConnectOutsideTheTemplate(t *testing.T) {
	port, _ := startRelay(t, nil, nil)
	h := dialRawH3(t, port)
	other := [][2]string{{":method", "CONNECT"}, {":protocol", "connect-udp"}, {":scheme", "https"},
		{":authority", "relay.test"}, {":path", "/not/the/template"}, {"capsule-protocol", "?1"}}
	if _, _, rsp := h.request(append(other, authField())); rsp.status != "404" {
		t.Errorf("authenticated: %s", rsp.status)
	}
	if _, _, rsp := h.request(other); rsp.status != "405" {
		t.Errorf("unauthenticated: %s", rsp.status)
	}
	ws := [][2]string{{":method", "CONNECT"}, {":protocol", "websocket"}, {":scheme", "https"},
		{":authority", "relay.test"}, {":path", "/chat"}, authField()}
	if _, _, rsp := h.request(ws); rsp.status != "200" { // the test site answers everything with 200
		t.Errorf("websocket: %s", rsp.status)
	}
}

// Push is not supported: a client's CANCEL_PUSH names a push ID the relay never
// mentioned (RFC 9114 section 7.2.3) and MAX_PUSH_ID cannot be reduced
// (section 7.2.7), both H3_ID_ERROR. PUSH_PROMISE (section 7.2.5) and push
// frames on a request stream (sections 7.2.3 and 7.2.7) are
// H3_FRAME_UNEXPECTED. An increasing MAX_PUSH_ID is accepted.
func TestH3PushFramesAreChecked(t *testing.T) {
	port, _ := startRelay(t, nil, nil)
	dial := func() *quic.Conn {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		conn, err := quic.DialAddr(ctx, "127.0.0.1:"+strconv.Itoa(port),
			&tls.Config{ServerName: "relay.test", RootCAs: pki().pool, NextProtos: []string{http3.NextProtoH3}},
			&quic.Config{})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { conn.CloseWithError(0, "") })
		return conn
	}
	frame := func(typ uint64, payload ...byte) []byte { return h3Frame(typ, payload) }
	closeCode := func(conn *quic.Conn, wait time.Duration) (quic.ApplicationErrorCode, bool) {
		select {
		case <-conn.Context().Done():
		case <-time.After(wait):
			return 0, false
		}
		ae, ok := errors.AsType[*quic.ApplicationError](context.Cause(conn.Context()))
		if !ok {
			t.Fatalf("closed with %v", context.Cause(conn.Context()))
		}
		return ae.ErrorCode, true
	}
	for _, tc := range []struct {
		name    string
		control [][]byte
		request []byte
		code    quic.ApplicationErrorCode // 0: the connection stays open
	}{
		{"CANCEL_PUSH", [][]byte{frame(0x3, 0)}, nil, 0x108},
		{"MAX_PUSH_ID reduced", [][]byte{frame(0xd, 1), frame(0xd, 0)}, nil, 0x108},
		{"MAX_PUSH_ID increased", [][]byte{frame(0xd, 0), frame(0xd, 1), frame(0xd, 1)}, nil, 0},
		{"PUSH_PROMISE on the control stream", [][]byte{frame(0x5, 0)}, nil, 0x105},
		{"CANCEL_PUSH on a request stream", nil, frame(0x3, 0), 0x105},
		{"MAX_PUSH_ID on a request stream", nil, frame(0xd, 0), 0x105},
		{"PUSH_PROMISE on a request stream", nil, frame(0x5, 0), 0x105},
	} {
		t.Run(tc.name, func(t *testing.T) {
			conn := dial()
			ctrl, err := conn.OpenUniStream()
			if err != nil {
				t.Fatal(err)
			}
			b := append([]byte{0x00}, frame(0x4)...) // control stream, empty SETTINGS
			for _, f := range tc.control {
				b = append(b, f...)
			}
			if _, err := ctrl.Write(b); err != nil {
				t.Fatal(err)
			}
			if tc.request != nil {
				str, err := conn.OpenStreamSync(context.Background())
				if err != nil {
					t.Fatal(err)
				}
				if _, err := str.Write(tc.request); err != nil {
					t.Fatal(err)
				}
			}
			if tc.code == 0 {
				if code, closed := closeCode(conn, time.Second); closed {
					t.Fatalf("closed with %#x", code)
				}
				return
			}
			if code, closed := closeCode(conn, 5*time.Second); !closed || code != tc.code {
				t.Fatalf("close code %#x (closed: %v), want %#x", code, closed, tc.code)
			}
		})
	}
}
