package networkrelay

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/quicvarint"
	"golang.org/x/net/http2"
)

// RFC 9297 section 3.2 forbids the fields themselves, including an empty
// Content-Type. Sections 3.3, RFC 9113 section 8.1.1 and RFC 9114 section
// 4.1.2 require a protocol stream error in addition to any error response.
func TestCapsuleMetadataPresenceAndErrorCode(t *testing.T) {
	port, _ := startRelay(t, nil, nil)
	host, udpPort := echoUDP(t)
	for _, field := range [][2]string{{"content-type", ""}, {"content-type", "application/octet-stream"}, {"content-length", "0"}} {
		for _, fin := range []bool{false, true} {
			t.Run(fmt.Sprintf("HTTP3/%s/%s/FIN=%v", field[0], field[1], fin), func(t *testing.T) {
				expectMalformedH3(t, dialRawH3(t, port), append(connectUDPFields(host, udpPort), field), fin)
			})
		}
		if http2ExtendedConnect() {
			t.Run(fmt.Sprintf("HTTP2/%s/%s", field[0], field[1]), func(t *testing.T) {
				r := dialRawH2(t, port)
				defer r.conn.Close()
				r.headers(1, append(connectUDPFields(host, udpPort), field))
				for {
					f := r.next(1)
					if headers, ok := f.(*http2.MetaHeadersFrame); ok && headers.PseudoValue("status") != "400" {
						t.Fatalf("got status %s, want 400", headers.PseudoValue("status"))
					}
					if rst, ok := f.(*http2.RSTStreamFrame); ok {
						if rst.ErrCode != http2.ErrCodeProtocol {
							t.Fatalf("got %s, want PROTOCOL_ERROR", rst.ErrCode)
						}
						return
					}
				}
			})
		}
	}
	t.Run("HTTP1/empty-content-type", func(t *testing.T) {
		conn := tlsDial(t, port, "http/1.1")
		defer conn.Close()
		fmt.Fprintf(conn, "GET %s HTTP/1.1\r\nHost: relay.test\r\nConnection: Upgrade\r\nUpgrade: connect-udp\r\nAuthorization: %s\r\nContent-Type:\r\n\r\n", mustExpand(host, udpPort), BasicAuthorization("alice", testPassword))
		rsp, err := http.ReadResponse(bufio.NewReader(conn), nil)
		if err != nil {
			t.Fatal(err)
		}
		defer rsp.Body.Close()
		if rsp.StatusCode != http.StatusBadRequest {
			t.Fatalf("got status %d, want 400", rsp.StatusCode)
		}
	})
}

// A malformed H3 request must reset the response even if request HEADERS
// arrive with FIN: CancelRead alone is a no-op once EOF has been consumed.
// RFC 9114 §4.1.2 permits, but does not require, an error response first.
func expectMalformedH3(t *testing.T, h *rawH3, fields [][2]string, fin bool) {
	t.Helper()
	str, err := h.conn.OpenStreamSync(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	str.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := str.Write(h3Frame(1, qpackHeaders(fields))); err != nil {
		t.Fatal(err)
	}
	if fin {
		if err := str.Close(); err != nil {
			t.Fatal(err)
		}
	}
	received, err := io.ReadAll(str)
	var se *quic.StreamError
	if !errors.As(err, &se) || se.ErrorCode != h3MessageError {
		t.Fatalf("response read got %v, want H3_MESSAGE_ERROR", err)
	}
	// Reset can discard the optional response, or interrupt its transmission.
	// Check its status only when a complete HEADERS frame was delivered.
	typ, n, err := quicvarint.Parse(received)
	if err != nil {
		return
	}
	length, m, err := quicvarint.Parse(received[n:])
	if err != nil || length > uint64(len(received)-n-m) {
		return
	}
	if typ != 1 {
		t.Fatalf("unexpected response frame type %d", typ)
	}
	rsp := h.readHeaders(bufio.NewReader(bytes.NewReader(received[:n+m+int(length)])))
	if rsp.status != "400" {
		t.Fatalf("optional response got %s, want 400", rsp.status)
	}
}

func TestMalformedH3AuthorityResetsWithAndWithoutFIN(t *testing.T) {
	port, _ := startRelay(t, nil, nil)
	for _, fin := range []bool{false, true} {
		t.Run(fmt.Sprintf("FIN=%v", fin), func(t *testing.T) {
			expectMalformedH3(t, dialRawH3(t, port), connectTCPFields("bad_host!:80"), fin)
		})
	}
}

func TestHTTP10IgnoresUDPUpgrade(t *testing.T) {
	// RFC 9110 §7.8 requires ignoring Upgrade on HTTP/1.0; §15.2 forbids
	// any informational status, including 101, to an HTTP/1.0 client.
	port, _ := startRelay(t, nil, nil)
	host, udpPort := echoUDP(t)
	conn := tlsDial(t, port, "http/1.1")
	defer conn.Close()
	fmt.Fprintf(conn, "GET %s HTTP/1.0\r\nHost: relay.test\r\nConnection: Upgrade\r\nUpgrade: connect-udp\r\nAuthorization: %s\r\n\r\n", mustExpand(host, udpPort), BasicAuthorization("alice", testPassword))
	rsp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer rsp.Body.Close()
	body, err := io.ReadAll(rsp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if rsp.StatusCode != http.StatusOK || string(body) != "the website" {
		t.Fatalf("HTTP/1.0 got %d %q, want website 200", rsp.StatusCode, body)
	}
}

func TestUnsupportedExtendedConnectRefused(t *testing.T) {
	port, _ := startRelay(t, nil, nil)
	for _, protocol := range []string{"connect-ip", "connect-tcp", "unknown-protocol"} {
		for _, authenticated := range []bool{false, true} {
			fields := connectUDPFields("example.com", "443")
			fields[1][1] = protocol
			want := "501"
			if !authenticated {
				fields = fields[:len(fields)-1]
				want = "405"
			}
			t.Run(fmt.Sprintf("HTTP3/%s/auth=%v", protocol, authenticated), func(t *testing.T) {
				h := dialRawH3(t, port)
				_, _, rsp := h.request(fields)
				if rsp.status != want {
					t.Fatalf("got %s, want %s", rsp.status, want)
				}
			})
			if http2ExtendedConnect() {
				t.Run(fmt.Sprintf("HTTP2/%s/auth=%v", protocol, authenticated), func(t *testing.T) {
					r := dialRawH2(t, port)
					defer r.conn.Close()
					r.headers(1, fields)
					headers, ok := r.next(1).(*http2.MetaHeadersFrame)
					if !ok || headers.PseudoValue("status") != want {
						t.Fatalf("got %v, want %s", headers, want)
					}
				})
			}
		}
	}
	// WebSocket extended CONNECT remains available to Caddy reverse_proxy.
	fields := connectUDPFields("example.com", "443")
	fields[1][1] = "websocket"
	h := dialRawH3(t, port)
	if _, _, rsp := h.request(fields); rsp.status != "200" {
		t.Fatalf("WebSocket was not delegated to the next handler: %s", rsp.status)
	}
}

func TestNativeUDPDatagramPayloadLimit(t *testing.T) {
	u := &udpTunnel{done: make(chan struct{})}
	u.toTarget(make([]byte, maxUDPPayload+1))
	select {
	case <-u.done:
	default:
		t.Fatal("oversized context-zero payload did not abort the tunnel")
	}
	if !u.aborted || u.why != abortMalformed {
		t.Fatal("oversized context-zero payload did not report a malformed message")
	}
}

type pendingUDPClient struct {
	input               *bytes.Reader
	stop                chan struct{}
	once                sync.Once
	reading, writing    chan struct{}
	readDone, writeDone chan struct{}
}

func (c *pendingUDPClient) Read(p []byte) (int, error) {
	if c.input.Len() > 0 {
		return c.input.Read(p)
	}
	select {
	case <-c.reading:
	default:
		close(c.reading)
	}
	<-c.stop
	select {
	case <-c.readDone:
	default:
		close(c.readDone)
	}
	return 0, net.ErrClosed
}

func (c *pendingUDPClient) Write([]byte) (int, error) {
	close(c.writing)
	<-c.stop
	close(c.writeDone)
	return 0, net.ErrClosed
}

func (*pendingUDPClient) closeWrite() bool        { return false }
func (c *pendingUDPClient) close()                { c.once.Do(func() { close(c.stop) }) }
func (c *pendingUDPClient) abort(abortReason)     { c.close() }
func (c *pendingUDPClient) interrupt(abortReason) { c.close() }
func (*pendingUDPClient) gone() <-chan struct{}   { return nil }

func TestUDPCancelJoinsPendingIO(t *testing.T) {
	host, port := echoUDP(t)
	addr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(host, port))
	if err != nil {
		t.Fatal(err)
	}
	sock, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		t.Fatal(err)
	}
	defer sock.Close()
	c := &pendingUDPClient{
		input: bytes.NewReader(appendDatagramCapsule(nil, []byte("pending"))), stop: make(chan struct{}),
		reading: make(chan struct{}), writing: make(chan struct{}), readDone: make(chan struct{}), writeDone: make(chan struct{}),
	}
	u := &udpTunnel{cc: c, sock: sock, idle: 2 * time.Minute}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { u.run(ctx); close(done) }()
	for _, ready := range []<-chan struct{}{c.reading, c.writing} {
		select {
		case <-ready:
		case <-time.After(5 * time.Second):
			t.Fatal("UDP worker did not reach pending I/O")
		}
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("UDP cancellation did not release pending I/O")
	}
	for _, finished := range []<-chan struct{}{c.readDone, c.writeDone} {
		select {
		case <-finished:
		default:
			t.Fatal("UDP returned before its I/O workers exited")
		}
	}
}

func TestUDPFINReleasesFlowControlledH2Writer(t *testing.T) {
	if !http2ExtendedConnect() {
		t.Skip("HTTP/2 extended CONNECT disabled")
	}
	port, _ := startRelay(t, nil, nil)
	target, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	sent := make(chan error, 1)
	go func() {
		buf := make([]byte, 64)
		n, peer, err := target.ReadFromUDP(buf)
		if err == nil {
			_, err = target.WriteToUDP(buf[:n], peer)
		}
		sent <- err
	}()
	r := dialRawH2(t, port)
	defer r.conn.Close()
	// HEADERS can be sent, but a response Capsule receives no stream credit.
	if err := r.fr.WriteSettings(http2.Setting{ID: http2.SettingInitialWindowSize, Val: 0}); err != nil {
		t.Fatal(err)
	}
	if status := r.connectUDP(1, "127.0.0.1", strconv.Itoa(target.LocalAddr().(*net.UDPAddr).Port)); status != "200 ?1" {
		t.Fatalf("not established: %s", status)
	}
	if err := r.fr.WriteData(1, false, appendDatagramCapsule(nil, []byte("pending"))); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-sent:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("target did not receive forwarded payload")
	}
	// Allow the response writer to encounter the withheld window before FIN.
	time.Sleep(20 * time.Millisecond)
	if err := r.fr.WriteData(1, true, nil); err != nil {
		t.Fatal(err)
	}
	r.conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	for {
		f := r.next(1)
		if rst, ok := f.(*http2.RSTStreamFrame); ok {
			if rst.ErrCode != http2.ErrCodeNo {
				t.Fatalf("normal UDP completion reset with %s", rst.ErrCode)
			}
			break
		}
		if data, ok := f.(*http2.DataFrame); ok && data.StreamEnded() {
			break
		}
	}
	deadline := time.Now().Add(time.Second)
	for openTunnels.Load() != 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if openTunnels.Load() != 0 {
		t.Fatal("completed UDP tunnel retained its quota")
	}
}

func TestH2CancellationReleasesSocketBlockedWriter(t *testing.T) {
	checkH2SocketBlockedCancellation(t, false)
}

func TestH2CancellationReleasesSocketBlockedFIN(t *testing.T) {
	checkH2SocketBlockedCancellation(t, true)
}

func checkH2SocketBlockedCancellation(t *testing.T, targetFIN bool) {
	t.Helper()
	port, _ := startRelay(t, nil, nil)
	target, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	var sent atomic.Int64
	begin := make(chan struct{})
	startWrite := sync.OnceFunc(func() { close(begin) })
	defer startWrite()
	targetDone := make(chan struct{})
	go func() {
		defer close(targetDone)
		conn, err := target.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		<-begin
		_ = conn.(*net.TCPConn).SetWriteBuffer(64 << 10)
		_ = conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
		buf := bytes.Repeat([]byte{0xa5}, 64<<10)
		for i := 0; i < 2048; i++ {
			n, err := conn.Write(buf)
			sent.Add(int64(n))
			if err != nil {
				return
			}
		}
	}()
	r := dialRawH2(t, port)
	defer r.conn.Close()
	if err := r.conn.NetConn().(*net.TCPConn).SetReadBuffer(1024); err != nil {
		t.Fatal(err)
	}
	// Give H2 ample credit, so the pending writer is blocked on the TCP
	// socket rather than waiting for a stream or connection WINDOW_UPDATE.
	if err := r.fr.WriteSettings(http2.Setting{ID: http2.SettingInitialWindowSize, Val: 1 << 30}); err != nil {
		t.Fatal(err)
	}
	if err := r.fr.WriteWindowUpdate(0, (1<<30)-65535); err != nil {
		t.Fatal(err)
	}
	r.headers(1, connectTCPFields(target.Addr().String()))
	if h, ok := r.next(1).(*http2.MetaHeadersFrame); !ok || h.PseudoValue("status") != "200" {
		t.Fatal("tunnel not established")
	}
	var finish, finished chan struct{}
	var finishTarget func()
	if targetFIN {
		finTarget, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer finTarget.Close()
		finish, finished = make(chan struct{}), make(chan struct{})
		finishTarget = sync.OnceFunc(func() { close(finish) })
		defer finishTarget()
		go func() {
			defer close(finished)
			conn, err := finTarget.Accept()
			if err != nil {
				return
			}
			<-finish
			_ = conn.Close()
		}()
		r.headers(3, connectTCPFields(finTarget.Addr().String()))
		if h, ok := r.next(3).(*http2.MetaHeadersFrame); !ok || h.PseudoValue("status") != "200" {
			t.Fatal("second tunnel not established")
		}
	}
	startWrite()
	// Stop reading the client socket and wait until backpressure propagates
	// through the relay to the target's small send buffer.
	deadline := time.Now().Add(5 * time.Second)
	last, stableSince := sent.Load(), time.Now()
	for {
		now := time.Now()
		n := sent.Load()
		if n != last {
			last, stableSince = n, now
		}
		if n > 1<<20 && now.Sub(stableSince) >= 100*time.Millisecond {
			break
		}
		if now.After(deadline) {
			t.Fatalf("target did not encounter socket backpressure, sent %d bytes", n)
		}
		time.Sleep(5 * time.Millisecond)
	}
	if targetFIN {
		// The second tunnel's directional FIN must queue behind the first
		// stream's socket write. Its handler must still process cancellation.
		finishTarget()
		<-finished
		time.Sleep(50 * time.Millisecond)
	}
	closeAllTunnels()
	deadline = time.Now().Add(time.Second)
	for openTunnels.Load() != 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	retained := openTunnels.Load()
	// Close after recording the result: the client must not have to help
	// release a canceled tunnel's workers and quota.
	_ = r.conn.Close()
	select {
	case <-targetDone:
	case <-time.After(time.Second):
		t.Error("target writer did not exit after cancellation")
	}
	if retained != 0 {
		t.Fatalf("canceled socket-blocked tunnel retained %d slots", retained)
	}
}

func TestUDPTemplateRejectsInvalidLiterals(t *testing.T) {
	// RFC 6570 section 2.1 excludes these literal characters and requires
	// percent signs to introduce a complete percent-encoded triplet.
	for _, literal := range []string{"%", "%0", "%zz", "\"", "'", "<", ">", "\\", "^", "`", "|"} {
		if _, err := parseUDPTemplate("/" + literal + "/{target_host}/{target_port}/"); err == nil {
			t.Errorf("accepted invalid literal %q", literal)
		}
	}
}

func TestSuccessResponseClearsContentMetadata(t *testing.T) {
	var cfg map[string]any
	if err := json.Unmarshal(relayConfig(443, nil, nil), &cfg); err != nil {
		t.Fatal(err)
	}
	server := cfg["apps"].(map[string]any)["http"].(map[string]any)["servers"].(map[string]any)["relay"].(map[string]any)
	routes := server["routes"].([]any)
	route := routes[0].(map[string]any)
	route["handle"] = append([]any{map[string]any{
		"handler": "headers", "response": map[string]any{"set": map[string]any{
			"Content-Length": []string{"6"}, "Content-Type": []string{"application/octet-stream"}, "Transfer-Encoding": []string{"chunked"},
			"Capsule-Protocol": []string{"?1"},
		}},
	}}, route["handle"].([]any)...)
	port, _ := startRelay(t, nil, map[string]any{"routes": routes})
	target := echoTCP(t)
	host, udpPort := echoUDP(t)
	for _, udp := range []bool{false, true} {
		fields := connectTCPFields(target)
		if udp {
			fields = connectUDPFields(host, udpPort)
		}
		t.Run(fmt.Sprintf("HTTP3/UDP=%v", udp), func(t *testing.T) {
			h := dialRawH3(t, port)
			_, _, rsp := h.request(fields)
			if rsp.status != "200" {
				t.Fatalf("got status %s, want 200", rsp.status)
			}
			for _, name := range []string{"content-length", "content-type", "transfer-encoding"} {
				if _, present := rsp.fields[name]; present {
					t.Errorf("success response contains %s", name)
				}
			}
			if _, present := rsp.fields["capsule-protocol"]; present != udp {
				t.Errorf("Capsule-Protocol present=%v, want %v", present, udp)
			}
		})
		if http2ExtendedConnect() || !udp {
			t.Run(fmt.Sprintf("HTTP2/UDP=%v", udp), func(t *testing.T) {
				r := dialRawH2(t, port)
				defer r.conn.Close()
				r.headers(1, fields)
				headers, ok := r.next(1).(*http2.MetaHeadersFrame)
				if !ok || headers.PseudoValue("status") != "200" {
					t.Fatal("tunnel not established")
				}
				for _, field := range headers.Fields {
					if field.Name == "content-length" || field.Name == "content-type" || field.Name == "transfer-encoding" {
						t.Errorf("success response contains %s", field.Name)
					}
					if field.Name == "capsule-protocol" && !udp {
						t.Error("TCP success advertises Capsule-Protocol")
					}
				}
			})
		}
	}
	h := dialRawH3(t, port)
	if _, _, rsp := h.request(connectUDPFields("127.0.0.1", "25")); rsp.status != "403" {
		t.Fatalf("blocked UDP target got %s, want 403", rsp.status)
	} else if _, present := rsp.fields["capsule-protocol"]; present {
		t.Error("refusal advertises Capsule-Protocol")
	}
}
