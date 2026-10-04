package networkrelay

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	_ "github.com/caddyserver/caddy/v2/modules/standard"
)

const testPassword = "correct-horse-battery"

var testHash = HashPassword(testPassword)

// testPKI is a CA and a certificate for relay.test.
type testPKI struct {
	pool    *x509.CertPool
	certPEM string
	keyPEM  string
}

var pki = sync.OnceValue(func() testPKI {
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	caDER, _ := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	ca, _ := x509.ParseCertificate(caDER)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "relay.test"},
		DNSNames:  []string{"relay.test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	keyDER, _ := x509.MarshalECPrivateKey(key)
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	return testPKI{
		pool:    pool,
		certPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		keyPEM:  string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})),
	}
})

// freePort finds a port that is free for both TCP and UDP.
func freePort(t *testing.T) int {
	t.Helper()
	for i := 0; i < 50; i++ {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		port := l.Addr().(*net.TCPAddr).Port
		u, err := net.ListenPacket("udp", "127.0.0.1:"+strconv.Itoa(port))
		l.Close()
		if err == nil {
			u.Close()
			return port
		}
	}
	t.Fatal("no free port")
	return 0
}

// relayConfig returns a Caddy JSON config with one server on port: the
// relay handler (with the given options merged in) and a website.
func relayConfig(port int, relay map[string]any, server map[string]any) []byte {
	handler := map[string]any{
		"relay_id":             "test-relay-" + strconv.Itoa(port),
		"handler":              "network_relay",
		"users":                []map[string]string{{"name": "alice", "password_hash": testHash}},
		"blocked_destinations": []string{},
	}
	for k, v := range relay {
		handler[k] = v
	}
	srv := map[string]any{
		"listen": []string{"127.0.0.1:" + strconv.Itoa(port)},
		"routes": []any{map[string]any{"handle": []any{
			handler,
			map[string]any{"handler": "static_response", "status_code": 200, "body": "the website"},
		}}},
		"tls_connection_policies": []any{map[string]any{}},
		"automatic_https":         map[string]any{"disable": true},
	}
	for k, v := range server {
		srv[k] = v
	}
	cfg := map[string]any{
		"admin":   map[string]any{"disabled": true},
		"logging": map[string]any{"logs": map[string]any{"default": map[string]any{"level": "ERROR"}}},
		"apps": map[string]any{
			"http": map[string]any{"servers": map[string]any{"relay": srv}},
			"tls": map[string]any{"certificates": map[string]any{"load_pem": []any{
				map[string]any{"certificate": pki().certPEM, "key": pki().keyPEM},
			}}},
		},
	}
	b, err := json.Marshal(cfg)
	if err != nil {
		panic(err)
	}
	return b
}

var caddyMu sync.Mutex

// startRelay runs Caddy with the relay for the duration of the test.
func startRelay(t *testing.T, relay map[string]any, server map[string]any) (int, func(map[string]any)) {
	t.Helper()
	caddyMu.Lock()
	port := freePort(t)
	if err := caddy.Load(relayConfig(port, relay, server), true); err != nil {
		caddyMu.Unlock()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = caddy.Stop()
		caddyMu.Unlock()
	})
	reload := func(relay map[string]any) {
		if err := caddy.Load(relayConfig(port, relay, server), true); err != nil {
			t.Fatal(err)
		}
	}
	return port, reload
}

func client(port int) *relayClient {
	return &relayClient{
		Address:       "127.0.0.1:" + strconv.Itoa(port),
		Server:        "relay.test",
		Port:          port,
		Authorization: BasicAuthorization("alice", testPassword),
		TLS:           &tls.Config{RootCAs: pki().pool},
	}
}

// echoTCP serves TCP echo on loopback: it copies until EOF, then closes
// its sending side.
func echoTCP(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				io.Copy(c, c)
				c.(*net.TCPConn).CloseWrite()
				io.Copy(io.Discard, c)
			}()
		}
	}()
	return l.Addr().String()
}

// echoUDP returns each datagram to its sender.
func echoUDP(t *testing.T) (string, string) {
	t.Helper()
	c, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	go func() {
		buf := make([]byte, 65536)
		for {
			n, from, err := c.ReadFrom(buf)
			if err != nil {
				return
			}
			c.WriteTo(buf[:n], from)
		}
	}()
	host, port, _ := net.SplitHostPort(c.LocalAddr().String())
	return host, port
}

type versionCase struct {
	name    string
	openTCP func(ctx context.Context, c *relayClient, target string) (stream, func(), error)
	openUDP func(ctx context.Context, c *relayClient, host, port string) (packetConn, func(), error)
}

var versions = []versionCase{
	{"h3",
		func(ctx context.Context, c *relayClient, target string) (stream, func(), error) {
			h, err := c.dialH3(ctx)
			if err != nil {
				return nil, nil, err
			}
			s, err := c.openTCPH3(ctx, h, target)
			return s, func() { h.Close() }, err
		},
		func(ctx context.Context, c *relayClient, host, port string) (packetConn, func(), error) {
			h, err := c.dialH3(ctx)
			if err != nil {
				return nil, nil, err
			}
			p, err := c.openUDPH3(ctx, h, host, port)
			return p, func() { h.Close() }, err
		}},
	{"h2",
		func(ctx context.Context, c *relayClient, target string) (stream, func(), error) {
			h, err := c.dialH2(ctx)
			if err != nil {
				return nil, nil, err
			}
			s, err := c.openTCPH2(ctx, h, target)
			return s, func() { h.Close() }, err
		},
		func(ctx context.Context, c *relayClient, host, port string) (packetConn, func(), error) {
			h, err := c.dialH2(ctx)
			if err != nil {
				return nil, nil, err
			}
			p, err := c.openUDPH2(ctx, h, host, port)
			return p, func() { h.Close() }, err
		}},
	{"h1",
		func(ctx context.Context, c *relayClient, target string) (stream, func(), error) {
			s, err := c.openTCPH1(ctx, target)
			return s, func() {}, err
		},
		func(ctx context.Context, c *relayClient, host, port string) (packetConn, func(), error) {
			p, err := c.openUDPH1(ctx, host, port)
			return p, func() {}, err
		}},
}

func testCtx(t *testing.T) context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func TestTCPRoundTripAndHalfClose(t *testing.T) {
	port, _ := startRelay(t, nil, nil)
	target := echoTCP(t)
	for _, v := range versions {
		t.Run(v.name, func(t *testing.T) {
			ctx := testCtx(t)
			s, done, err := v.openTCP(ctx, client(port), target)
			if err != nil {
				t.Fatal(err)
			}
			defer done()
			defer s.Close()
			msg := bytes.Repeat([]byte("0123456789"), 30000) // 300 kB
			go func() {
				s.Write(msg)
				s.CloseWrite()
			}()
			got, err := io.ReadAll(s)
			if err != nil {
				t.Fatalf("read after %d bytes: %v", len(got), err)
			}
			if !bytes.Equal(got, msg) {
				t.Fatalf("got %d bytes back, want %d", len(got), len(msg))
			}
		})
	}
}

func TestUDPRoundTrip(t *testing.T) {
	port, _ := startRelay(t, nil, nil)
	host, uport := echoUDP(t)
	cases := append([]versionCase{}, versions...)
	cases = append(cases, versionCase{"h3-capsules", nil,
		func(ctx context.Context, c *relayClient, host, port string) (packetConn, func(), error) {
			c.NoDatagrams = true
			h, err := c.dialH3(ctx)
			if err != nil {
				return nil, nil, err
			}
			p, err := c.openUDPH3(ctx, h, host, port)
			return p, func() { h.Close() }, err
		}})
	for _, v := range cases {
		t.Run(v.name, func(t *testing.T) {
			ctx := testCtx(t)
			p, done, err := v.openUDP(ctx, client(port), host, uport)
			if err != nil {
				t.Fatal(err)
			}
			defer done()
			defer p.Close()
			sizes := []int{0, 1, 60, 1200}
			if v.name != "h3" {
				sizes = append(sizes, 1400, 9000) // capsules have no MTU limit
			}
			for _, size := range sizes {
				msg := bytes.Repeat([]byte{byte(size)}, size)
				// Datagrams can be lost; retry a few times.
				var got []byte
				for attempt := 0; attempt < 5; attempt++ {
					if err := p.Send(msg); err != nil {
						t.Fatalf("send %d: %v", size, err)
					}
					rctx, cancel := context.WithTimeout(ctx, time.Second)
					got, err = p.Receive(rctx)
					cancel()
					if err == nil {
						break
					}
				}
				if err != nil {
					t.Fatalf("size %d: %v", size, err)
				}
				if !bytes.Equal(got, msg) {
					t.Fatalf("size %d: got %d bytes", size, len(got))
				}
			}
		})
	}
}

func TestIPv6TargetInTemplate(t *testing.T) {
	l, err := net.ListenPacket("udp", "[::1]:0")
	if err != nil {
		t.Skip("no IPv6:", err)
	}
	l.Close()
	port, _ := startRelay(t, nil, nil)
	c, _ := net.ListenPacket("udp", "[::1]:0")
	defer c.Close()
	go func() {
		buf := make([]byte, 2000)
		n, from, err := c.ReadFrom(buf)
		if err == nil {
			c.WriteTo(buf[:n], from)
		}
	}()
	_, uport, _ := net.SplitHostPort(c.LocalAddr().String())
	ctx := testCtx(t)
	cl := client(port)
	h, err := cl.dialH3(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	p, err := cl.openUDPH3(ctx, h, "::1", uport)
	if err != nil {
		t.Fatal(err)
	}
	p.Send([]byte("v6"))
	got, err := p.Receive(ctx)
	if err != nil || string(got) != "v6" {
		t.Fatalf("got %q, %v", got, err)
	}
}

func wantStatus(t *testing.T, err error, status int, proxyStatus string) {
	t.Helper()
	var se *statusError
	if !errors.As(err, &se) {
		t.Fatalf("want status %d, got error %v", status, err)
	}
	if se.Status != status || !strings.Contains(se.ProxyStatus, proxyStatus) {
		t.Fatalf("want %d %q, got %d %q", status, proxyStatus, se.Status, se.ProxyStatus)
	}
}

func TestRefusals(t *testing.T) {
	port, _ := startRelay(t, map[string]any{
		"blocked_destinations": []string{"127.0.0.2/32", "10.0.0.0/8"},
		"blocked_ports":        []int{9},
	}, nil)
	for _, v := range versions {
		t.Run(v.name, func(t *testing.T) {
			ctx := testCtx(t)
			cases := []struct {
				target      string
				status      int
				proxyStatus string
			}{
				{"127.0.0.2:80", 403, "destination_ip_prohibited"},
				{"10.1.2.3:80", 403, "destination_ip_prohibited"},
				{"127.0.0.1:9", 403, "http_request_denied"},
				{"bad_host!:80", 400, "http_request_error"},
				{"name.invalid:80", 502, "dns_error"},
			}
			for _, c := range cases {
				s, done, err := v.openTCP(ctx, client(port), c.target)
				if err == nil {
					s.Close()
					done()
					t.Fatalf("%s: tunnel opened", c.target)
				}
				if done != nil {
					done()
				}
				if c.target == "bad_host!:80" && v.name == "h2" {
					// Go's HTTP/2 client refuses this authority itself.
					continue
				}
				wantStatus(t, err, c.status, c.proxyStatus)
			}
			// A closed port refuses.
			l, _ := net.Listen("tcp", "127.0.0.1:0")
			closed := l.Addr().String()
			l.Close()
			_, done, err := v.openTCP(ctx, client(port), closed)
			if done != nil {
				done()
			}
			wantStatus(t, err, 502, "connection_refused")
			_, done, err = v.openUDP(ctx, client(port), "10.9.9.9", "53")
			if done != nil {
				done()
			}
			wantStatus(t, err, 403, "destination_ip_prohibited")
		})
	}
}

func TestUnauthenticatedRequestsSeeTheWebsite(t *testing.T) {
	port, _ := startRelay(t, nil, nil)
	target := echoTCP(t)
	for _, v := range versions {
		t.Run(v.name, func(t *testing.T) {
			ctx := testCtx(t)
			for _, auth := range []string{"", BasicAuthorization("alice", "wrong"), BasicAuthorization("bob", testPassword), "Bearer x"} {
				c := client(port)
				c.Authorization = auth
				_, done, err := v.openTCP(ctx, c, target)
				if done != nil {
					done()
				}
				wantStatus(t, err, 405, "")
				_, done, err = v.openUDP(ctx, c, "127.0.0.1", "53")
				if done != nil {
					done()
				}
				want := 405 // like the CONNECT above
				if v.name == "h1" {
					want = 200 // a GET with Upgrade gets the page
				}
				wantStatus(t, err, want, "")
			}
		})
	}
}

func TestWebsiteAndAltSvc(t *testing.T) {
	port, _ := startRelay(t, nil, nil)
	ctx := testCtx(t)
	c := client(port)
	// HTTP/2 GET: the website, with Alt-Svc for HTTP/3.
	h2c, err := c.dialH2(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer h2c.Close()
	req, _ := http.NewRequestWithContext(ctx, "GET", "https://relay.test/anything", nil)
	rsp, err := h2c.cc.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(rsp.Body)
	if string(body) != "the website" {
		t.Fatalf("body %q", body)
	}
	if want := fmt.Sprintf(`h3=":%d"; ma=2592000`, port); rsp.Header.Get("Alt-Svc") != want {
		t.Fatalf("Alt-Svc %q, want %q", rsp.Header.Get("Alt-Svc"), want)
	}
	// HTTP/3 GET goes through the same Caddy server.
	h3c, err := c.dialH3(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer h3c.Close()
	req, _ = http.NewRequestWithContext(ctx, "GET", "https://relay.test/", nil)
	rsp, err = h3c.cc.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ = io.ReadAll(rsp.Body)
	if string(body) != "the website" || rsp.Header.Get("Alt-Svc") != "" {
		t.Fatalf("HTTP/3: body %q, Alt-Svc %q", body, rsp.Header.Get("Alt-Svc"))
	}
}

// Caddy's read/write idle timeouts must not cut idle tunnels.
func TestIdleTunnelsOutliveServerTimeouts(t *testing.T) {
	port, _ := startRelay(t, nil, map[string]any{
		"read_idle_timeout":  int64(500 * time.Millisecond),
		"write_idle_timeout": int64(500 * time.Millisecond),
		"idle_timeout":       int64(time.Minute),
		"logs":               map[string]any{}, // wraps the body for access logs
	})
	target := echoTCP(t)
	for _, v := range versions {
		t.Run(v.name, func(t *testing.T) {
			ctx := testCtx(t)
			s, done, err := v.openTCP(ctx, client(port), target)
			if err != nil {
				t.Fatal(err)
			}
			defer done()
			defer s.Close()
			time.Sleep(1500 * time.Millisecond)
			if _, err := s.Write([]byte("still here")); err != nil {
				t.Fatal(err)
			}
			buf := make([]byte, 10)
			if _, err := io.ReadFull(s, buf); err != nil || string(buf) != "still here" {
				t.Fatalf("got %q, %v", buf, err)
			}
		})
	}
}

func TestMaxTunnels(t *testing.T) {
	port, _ := startRelay(t, map[string]any{"max_tunnels": 1}, nil)
	target := echoTCP(t)
	ctx := testCtx(t)
	s, done, err := versions[1].openTCP(ctx, client(port), target)
	if err != nil {
		t.Fatal(err)
	}
	_, done2, err := versions[0].openTCP(ctx, client(port), target)
	if done2 != nil {
		done2()
	}
	wantStatus(t, err, 503, "connection_limit_reached")
	s.Close()
	done()
}

// A reload keeps tunnels of unchanged users and closes those of removed
// users.
func TestReloadRevokesRemovedUsers(t *testing.T) {
	bobHash := HashPassword("bob-password-1234")
	users := func(names ...string) map[string]any {
		var list []map[string]string
		for _, n := range names {
			h := testHash
			if n == "bob" {
				h = bobHash
			}
			list = append(list, map[string]string{"name": n, "password_hash": h})
		}
		return map[string]any{"users": list}
	}
	port, reload := startRelay(t, users("alice", "bob"), nil)
	target := echoTCP(t)
	for _, v := range versions {
		t.Run(v.name, func(t *testing.T) {
			reload(users("alice", "bob"))
			ctx := testCtx(t)
			alice, done, err := v.openTCP(ctx, client(port), target)
			if err != nil {
				t.Fatal(err)
			}
			defer done()
			bc := client(port)
			bc.Authorization = BasicAuthorization("bob", "bob-password-1234")
			bob, done2, err := v.openTCP(ctx, bc, target)
			if err != nil {
				t.Fatal(err)
			}
			defer done2()

			reload(users("alice"))

			if _, err := alice.Write([]byte("ping")); err != nil {
				t.Fatal(err)
			}
			buf := make([]byte, 4)
			if _, err := io.ReadFull(alice, buf); err != nil {
				t.Fatalf("alice's tunnel: %v", err)
			}
			bob.Write([]byte("ping"))
			if _, err := io.ReadFull(bob, buf); err == nil {
				t.Fatal("bob's tunnel survived the reload")
			}
			alice.Close()
			bob.Close()
		})
	}
}

// A reload that cannot start (here: a UDP port is taken) leaves the old
// configuration serving HTTP/3, and its tunnels open; a reload that works
// moves new connections to the new configuration.
func TestReloadKeepsHTTP3(t *testing.T) {
	port, reload := startRelay(t, nil, nil)
	target := echoTCP(t)
	ctx := testCtx(t)
	old, done, err := versions[0].openTCP(ctx, client(port), target)
	if err != nil {
		t.Fatal(err)
	}
	defer done()
	defer old.Close()

	busy, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer busy.Close()
	busyPort := busy.LocalAddr().(*net.UDPAddr).Port
	bad := relayConfig(port, nil, map[string]any{"listen": []string{
		"127.0.0.1:" + strconv.Itoa(port), "127.0.0.1:" + strconv.Itoa(busyPort)}})
	if err := caddy.Load(bad, true); err == nil || !strings.Contains(err.Error(), "HTTP/3") {
		t.Fatalf("reload with a busy UDP port: %v", err)
	}
	ping := func(s stream) {
		t.Helper()
		if _, err := s.Write([]byte("ping")); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 4)
		if _, err := io.ReadFull(s, buf); err != nil {
			t.Fatal(err)
		}
	}
	ping(old)
	fresh, done2, err := versions[0].openTCP(ctx, client(port), target)
	if err != nil {
		t.Fatalf("HTTP/3 after a failed reload: %v", err)
	}
	ping(fresh)
	fresh.Close()
	done2()

	reload(nil)
	ping(old)
	fresh, done3, err := versions[0].openTCP(ctx, client(port), target)
	if err != nil {
		t.Fatalf("HTTP/3 after a reload: %v", err)
	}
	ping(fresh)
	fresh.Close()
	done3()
}
