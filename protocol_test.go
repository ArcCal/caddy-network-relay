package networkrelay

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/quic-go/masque-go"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/yosida95/uritemplate/v3"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

// quic-go's masque-go is an independent CONNECT-UDP client (with its own
// RFC 6570 implementation).
func TestMasqueGoInterop(t *testing.T) {
	port, _ := startRelay(t, nil, nil)
	host, uport := echoUDP(t)
	ctx := testCtx(t)
	c := client(port)
	h, err := c.dialH3(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	tmpl := uritemplate.MustNew("https://relay.test:" + strconv.Itoa(port) + DefaultUDPTemplate)
	req, err := masque.NewRequest(ctx, tmpl, net.JoinHostPort(host, uport))
	if err != nil {
		t.Fatal(err)
	}
	req.Header().Set("Authorization", c.Authorization)
	conn, rsp, err := masque.NewClientConn(h.cc).Dial(req)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if rsp.Header.Get("Capsule-Protocol") != "?1" {
		t.Errorf("Capsule-Protocol: %q", rsp.Header.Get("Capsule-Protocol"))
	}
	for _, size := range []int{60, 1200} {
		msg := bytes.Repeat([]byte{7}, size)
		var n int
		for attempt := 0; attempt < 5; attempt++ {
			conn.WriteTo(msg, nil)
			conn.SetReadDeadline(time.Now().Add(time.Second))
			buf := make([]byte, 2000)
			n, _, err = conn.ReadFrom(buf)
			if err == nil {
				if !bytes.Equal(buf[:n], msg) {
					t.Fatalf("size %d: wrong data", size)
				}
				break
			}
		}
		if err != nil {
			t.Fatalf("size %d: %v", size, err)
		}
	}
	// Without credentials masque-go gets an error, not a tunnel.
	req2, _ := masque.NewRequest(ctx, tmpl, net.JoinHostPort(host, uport))
	if _, rsp, err := masque.NewClientConn(h.cc).Dial(req2); err == nil || rsp.StatusCode != 405 {
		t.Fatalf("unauthenticated: %v", err)
	}
}

// rawH2 is a frame-level HTTP/2 client: it can send extended CONNECT with
// any Go version, and see stream errors.
type rawH2 struct {
	t        *testing.T
	conn     *tls.Conn
	fr       *http2.Framer
	enc      *hpack.Encoder
	encBuf   bytes.Buffer
	settings map[http2.SettingID]uint32
}

func dialRawH2(t *testing.T, port int) *rawH2 {
	t.Helper()
	c, err := tls.Dial("tcp", "127.0.0.1:"+strconv.Itoa(port), &tls.Config{
		ServerName: "relay.test", RootCAs: pki().pool, NextProtos: []string{"h2"}})
	if err != nil {
		t.Fatal(err)
	}
	c.SetDeadline(time.Now().Add(10 * time.Second))
	r := &rawH2{t: t, conn: c, fr: http2.NewFramer(c, c), settings: map[http2.SettingID]uint32{}}
	r.enc = hpack.NewEncoder(&r.encBuf)
	r.fr.ReadMetaHeaders = hpack.NewDecoder(4096, nil)
	io.WriteString(c, http2.ClientPreface)
	r.fr.WriteSettings()
	f, err := r.fr.ReadFrame()
	if err != nil {
		t.Fatal(err)
	}
	sf, ok := f.(*http2.SettingsFrame)
	if !ok {
		t.Fatalf("first frame %T", f)
	}
	sf.ForeachSetting(func(s http2.Setting) error { r.settings[s.ID] = s.Val; return nil })
	r.fr.WriteSettingsAck()
	return r
}

func (r *rawH2) headers(stream uint32, fields [][2]string) {
	r.encBuf.Reset()
	for _, f := range fields {
		r.enc.WriteField(hpack.HeaderField{Name: f[0], Value: f[1]})
	}
	if err := r.fr.WriteHeaders(http2.HeadersFrameParam{StreamID: stream, BlockFragment: r.encBuf.Bytes(), EndHeaders: true}); err != nil {
		r.t.Fatal(err)
	}
}

// next returns the next frame for stream (skipping connection frames).
func (r *rawH2) next(stream uint32) http2.Frame {
	for {
		f, err := r.fr.ReadFrame()
		if err != nil {
			r.t.Fatal(err)
		}
		if f.Header().StreamID == stream {
			return f
		}
	}
}

func (r *rawH2) connectUDP(stream uint32, host, port string) string {
	tm, _ := parseUDPTemplate(DefaultUDPTemplate)
	r.headers(stream, [][2]string{
		{":method", "CONNECT"}, {":protocol", "connect-udp"}, {":scheme", "https"},
		{":authority", "relay.test"}, {":path", tm.Expand(host, port)},
		{"authorization", BasicAuthorization("alice", testPassword)}, {"capsule-protocol", "?1"},
	})
	f := r.next(stream)
	h, ok := f.(*http2.MetaHeadersFrame)
	if !ok {
		r.t.Fatalf("response %T", f)
	}
	cp := ""
	for _, f := range h.RegularFields() {
		if f.Name == "capsule-protocol" {
			cp = f.Value
		}
	}
	return h.PseudoValue("status") + " " + cp
}

func TestHTTP2ExtendedConnectAtFrameLevel(t *testing.T) {
	port, _ := startRelay(t, nil, nil)
	if !http2ExtendedConnect() {
		t.Skip("extended CONNECT is off (Go 1.27+ without GODEBUG=http2xconnect=1)")
	}
	host, uport := echoUDP(t)
	r := dialRawH2(t, port)
	defer r.conn.Close()
	if r.settings[http2.SettingEnableConnectProtocol] != 1 {
		t.Fatal("SETTINGS_ENABLE_CONNECT_PROTOCOL not sent")
	}
	if got := r.connectUDP(1, host, uport); got != "200 ?1" {
		t.Fatalf("response: %s", got)
	}
	r.fr.WriteData(1, false, appendDatagramCapsule(nil, []byte("frame-level")))
	f := r.next(1)
	d, ok := f.(*http2.DataFrame)
	if !ok {
		t.Fatalf("got %T", f)
	}
	var got []byte
	readCapsules(bytes.NewReader(d.Data()), func(p []byte) { got = append(got, p...) })
	if string(got) != "frame-level" {
		t.Fatalf("got %q", got)
	}

	// A malformed capsule resets the stream.
	if got := r.connectUDP(3, host, uport); got != "200 ?1" {
		t.Fatalf("response: %s", got)
	}
	r.fr.WriteData(3, false, []byte{0x00, 0x00}) // DATAGRAM capsule without context ID
	for {
		f := r.next(3)
		if rst, ok := f.(*http2.RSTStreamFrame); ok {
			if rst.ErrCode == http2.ErrCodeNo {
				t.Fatal("reset with NO_ERROR")
			}
			break
		}
	}

	// The client ending the stream ends the tunnel normally.
	if got := r.connectUDP(5, host, uport); got != "200 ?1" {
		t.Fatalf("response: %s", got)
	}
	r.fr.WriteData(5, true, nil)
	for {
		f := r.next(5)
		if f.Header().Flags.Has(http2.FlagDataEndStream) {
			break
		}
		if _, ok := f.(*http2.RSTStreamFrame); ok {
			break // RST_STREAM(NO_ERROR) after the end of the response is fine too
		}
	}
}

// h3 stream errors carry the RFC 9114 code for the cause.
func TestHTTP3ErrorCodes(t *testing.T) {
	port, _ := startRelay(t, nil, nil)
	ctx := testCtx(t)
	c := client(port)
	c.NoDatagrams = true
	h, err := c.dialH3(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	host, uport := echoUDP(t)
	p, err := c.openUDPH3(ctx, h, host, uport)
	if err != nil {
		t.Fatal(err)
	}
	cc := p.(*capsuleConn)
	cc.s.Write([]byte{0x00, 0x00}) // malformed
	_, err = p.Receive(ctx)
	if code := streamCode(err); code != h3MessageError {
		t.Fatalf("malformed capsule: %v (code %#x)", err, code)
	}

	// The target resetting the connection resets the stream with
	// H3_CONNECT_ERROR.
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	defer l.Close()
	go func() {
		conn, err := l.Accept()
		if err == nil {
			conn.(*net.TCPConn).SetLinger(0)
			io.ReadFull(conn, make([]byte, 1))
			conn.Close()
		}
	}()
	s, err := c.openTCPH3(ctx, h, l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	s.Write([]byte("x"))
	_, err = io.ReadAll(s)
	if code := streamCode(err); code != h3ConnectError {
		t.Fatalf("target reset: %v (code %#x)", err, code)
	}
}

func streamCode(err error) quic.StreamErrorCode {
	var se *quic.StreamError
	if errors.As(err, &se) {
		return se.ErrorCode
	}
	var he *http3.Error
	if errors.As(err, &he) {
		return quic.StreamErrorCode(he.ErrorCode)
	}
	return 0
}

// A target that closes first: the client gets the data and then the end
// of the stream, on every version.
func TestTargetClosesFirst(t *testing.T) {
	port, _ := startRelay(t, nil, nil)
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	defer l.Close()
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			conn.Write([]byte("bye"))
			conn.Close()
		}
	}()
	for _, v := range versions {
		t.Run(v.name, func(t *testing.T) {
			ctx := testCtx(t)
			s, done, err := v.openTCP(ctx, client(port), l.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer done()
			defer s.Close()
			got, err := io.ReadAll(s)
			if err != nil || string(got) != "bye" {
				t.Fatalf("got %q, %v", got, err)
			}
		})
	}
}

func TestCaddyfile(t *testing.T) {
	input := `{
	admin off
}

relay.example.com, :443 {
	network_relay {
		user iphone ` + testHash + `
		user ipad ` + testHash + `
		udp_template /masque/{target_host}/{target_port}/
		blocked_destinations 10.0.0.0/8 fd00::/8
		blocked_ports
		connect_timeout 5s
		udp_idle_timeout 10m
		max_tunnels 100
		log_requests
	}
	root * /var/www/relay
	file_server
}`
	adapter := caddyfile.Adapter{ServerType: httpcaddyfile.ServerType{}}
	out, warnings, err := adapter.Adapt([]byte(input), nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, w := range warnings {
		if !strings.Contains(w.Message, "not formatted") {
			t.Errorf("warning: %v", w)
		}
	}
	var cfg struct {
		Apps struct {
			HTTP struct {
				Servers map[string]struct {
					Routes []struct {
						Match  []map[string]any  `json:"match"`
						Handle []json.RawMessage `json:"handle"`
					} `json:"routes"`
				} `json:"servers"`
			} `json:"http"`
		} `json:"apps"`
	}
	if err := json.Unmarshal(out, &cfg); err != nil {
		t.Fatal(err)
	}
	srv := cfg.Apps.HTTP.Servers["srv0"]
	if len(srv.Routes) != 1 || srv.Routes[0].Match != nil {
		t.Fatalf("the site must match every host (CONNECT names the target): %s", out)
	}
	handlers := srv.Routes[0].Handle
	var first Handler
	if err := json.Unmarshal(handlers[0], &first); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(handlers[0]), `"handler":"network_relay"`) {
		t.Fatalf("network_relay is not the first handler: %s", handlers[0])
	}
	if len(first.Users) != 2 || first.UDPTemplate != "/masque/{target_host}/{target_port}/" ||
		len(*first.BlockedDestinations) != 2 || len(*first.BlockedPorts) != 0 ||
		time.Duration(first.ConnectTimeout) != 5*time.Second || time.Duration(first.UDPIdleTimeout) != 10*time.Minute ||
		first.MaxTunnels != 100 || !first.LogRequests {
		t.Fatalf("options: %+v", first)
	}
	for _, bad := range []string{
		"network_relay {\n user only-name\n}", "network_relay {\n unknown 1\n}", "network_relay arg",
		"network_relay {\n max_tunnels many\n}", "network_relay {\n connect_timeout soon\n}",
	} {
		_, _, err := adapter.Adapt([]byte(":443 {\n"+bad+"\n}"), nil)
		if err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestValidation(t *testing.T) {
	for _, bad := range []map[string]any{
		{"connect_timeout": int64(time.Hour)},
		{"udp_idle_timeout": int64(time.Second)},
		{"max_tunnels": -1},
		{"udp_template": "/{target_host}"},
		{"blocked_destinations": []string{"nonsense"}},
		{"users": []map[string]string{{"name": "x", "password_hash": "plain"}}},
	} {
		h := &Handler{}
		b, _ := json.Marshal(bad)
		json.Unmarshal(b, h)
		if err := validateStandalone(h); err == nil {
			t.Errorf("%v accepted", bad)
		}
	}
}

// validateStandalone provisions the parts of a handler that need no Caddy
// context, then validates it.
func validateStandalone(h *Handler) error {
	if h.UDPTemplate == "" {
		h.UDPTemplate = DefaultUDPTemplate
	}
	if _, err := parseUDPTemplate(h.UDPTemplate); err != nil {
		return err
	}
	if h.BlockedDestinations != nil {
		if _, err := newPolicy(*h.BlockedDestinations, nil); err != nil {
			return err
		}
	}
	if _, err := newAuthenticator(h.Users); err != nil {
		return err
	}
	if h.ConnectTimeout == 0 {
		h.ConnectTimeout = 10 * 1e9
	}
	if h.UDPIdleTimeout == 0 {
		h.UDPIdleTimeout = 300 * 1e9
	}
	if h.MaxTunnels == 0 {
		h.MaxTunnels = 1
	}
	if h.MaxTunnelsPerUser == 0 {
		h.MaxTunnelsPerUser = defaultMaxUserTunnels
	}
	return h.Validate()
}
