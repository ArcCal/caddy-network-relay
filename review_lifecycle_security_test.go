package networkrelay

import (
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/caddyserver/caddy/v2/modules/caddytls"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"go.uber.org/zap"
)

func TestReviewMappedBlockedDestinations(t *testing.T) {
	for _, entry := range []string{"::ffff:8.8.8.8", "::ffff:8.8.8.8/128", "::ffff:8.8.8.0/120"} {
		t.Run(entry, func(t *testing.T) {
			p, err := newPolicy([]string{entry}, nil)
			if err != nil {
				t.Fatal(err)
			}
			for _, addr := range []string{"8.8.8.8", "::ffff:8.8.8.8"} {
				if p.allows(netip.MustParseAddr(addr)) {
					t.Fatalf("mapped block %s allowed %s", entry, addr)
				}
			}
			if !p.allows(netip.MustParseAddr("8.8.4.4")) {
				t.Fatal("unrelated public address blocked")
			}
		})
	}
	p, err := newPolicy(DefaultBlockedDestinations, DefaultBlockedPorts)
	if err != nil {
		t.Fatal(err)
	}
	for _, addr := range []string{"8.8.8.8", "::ffff:8.8.8.8"} {
		if !p.allows(netip.MustParseAddr(addr)) {
			t.Fatalf("default policy blocks public address %s", addr)
		}
	}
	for _, addr := range []string{"127.0.0.1", "::ffff:127.0.0.1"} {
		if p.allows(netip.MustParseAddr(addr)) {
			t.Fatalf("default policy allowed loopback %s", addr)
		}
	}
}

type reviewPausedHash struct {
	started chan struct{}
	finish  chan struct{}
}

func (h *reviewPausedHash) verify([]byte) bool {
	close(h.started)
	<-h.finish
	return true
}

func TestReviewAuthenticationCancelledDuringHash(t *testing.T) {
	h := &reviewPausedHash{started: make(chan struct{}), finish: make(chan struct{})}
	a := &authenticator{
		users:  map[string]User{"alice": {Name: "alice", PasswordHash: "test-hash"}},
		hashes: map[string]passwordHash{"alice": h}, key: []byte("test-hmac-key"),
		cache: map[[32]byte]cacheEntry{}, inflight: map[[32]byte]*flight{}, slots: make(chan struct{}, 1),
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := a.verify(ctx, BasicAuthorization("alice", "valid")); done <- err }()
	<-h.started
	cancel()
	close(h.finish)
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled request authenticated after hashing: %v", err)
	}
	if len(a.slots) != 0 || len(a.inflight) != 0 {
		t.Fatal("cancelled authentication retained resources")
	}
}

func TestReviewTLSClientAuthChangeRevokesTunnels(t *testing.T) {
	a, err := newAuthenticator([]User{{Name: "alice", PasswordHash: testHash}})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, before, after string
		keep                bool
	}{
		{"unchanged client trust", `{"mode":"require_and_verify","ca":"A"}`, `{"mode":"require_and_verify","ca":"A"}`, true},
		{"new client auth requirement", "", `{"mode":"require_and_verify","ca":"A"}`, false},
		{"changed client CA", `{"mode":"require_and_verify","ca":"A"}`, `{"mode":"require_and_verify","ca":"B"}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			old := &Handler{RelayID: "review-client-trust", auth: a, tlsClientAuth: []byte(tc.before)}
			new := &Handler{RelayID: old.RelayID, auth: a, tlsClientAuth: []byte(tc.after)}
			registerHandler(old)
			registerHandler(new)
			defer unregisterHandler(new)
			ctx, cancel := context.WithCancelCause(context.Background())
			defer cancel(nil)
			lt := &liveTunnel{acct: account{name: "alice", hash: testHash}, owner: old, cancel: cancel}
			if !addTunnel(lt) {
				t.Fatal("initial tunnel was not registered")
			}
			defer removeTunnel(lt)
			unregisterHandler(old)
			if got := ctx.Err() == nil; got != tc.keep {
				t.Fatalf("existing tunnel retained=%v, want %v", got, tc.keep)
			}
			_, lateCancel := context.WithCancelCause(context.Background())
			defer lateCancel(nil)
			late := &liveTunnel{acct: lt.acct, owner: old, cancel: lateCancel}
			if got := addTunnel(late); got != tc.keep {
				t.Fatalf("old TLS connection opened new tunnel=%v, want %v", got, tc.keep)
			}
			removeTunnel(late)
		})
	}
}

func TestReviewTLSClientCAReloadChecksCertificateIdentity(t *testing.T) {
	makePool := func(serial int64) *x509.CertPool {
		t.Helper()
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		ca := &x509.Certificate{
			SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: "same subject"},
			NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
			IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
		}
		der, err := x509.CreateCertificate(rand.Reader, ca, ca, &key.PublicKey, key)
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		pool := x509.NewCertPool()
		pool.AddCert(parsed)
		return pool
	}
	first, replaced := makePool(1), makePool(2)
	newHandler := func(pool *x509.CertPool) *Handler {
		return &Handler{
			RelayID: "review-file-client-ca", tlsClientAuth: []byte(`{"ca":"/etc/relay/clients.pem"}`),
			server: &relayServer{srv: &caddyhttp.Server{TLSConnPolicies: caddytls.ConnectionPolicies{{
				TLSConfig: &tls.Config{ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool},
			}}}},
		}
	}
	old := newHandler(first)
	if !sameRelay(old, newHandler(first.Clone())) {
		t.Fatal("identical effective CA contents revoked tunnels")
	}
	if sameRelay(old, newHandler(replaced)) {
		t.Fatal("same CA file path and subject retained different trust roots")
	}
	partial := newHandler(nil)
	partial.server.srv.TLSConnPolicies[0].TLSConfig = nil
	if !sameRelayConfig(old, partial) || sameRelay(old, partial) {
		t.Fatal("incomplete TLS provisioning confused budget sharing and tunnel transfer")
	}
}

func TestReviewTLSCustomVerifierSnapshotAndLateTunnelDenial(t *testing.T) {
	p := &caddytls.ConnectionPolicy{ClientAuthentication: &caddytls.ClientAuthentication{
		Mode: "require", VerifiersRaw: []json.RawMessage{json.RawMessage(`{"verifier":"leaf"}`)},
	}}
	srv := &caddyhttp.Server{TLSConnPolicies: caddytls.ConnectionPolicies{p}}
	custom := relayTLSHasCustomVerifiers(srv)
	if !custom {
		t.Fatal("early provisioning missed verifier configuration")
	}
	p.ClientAuthentication.VerifiersRaw = nil // LoadModule clears its raw field
	a, err := newAuthenticator([]User{{Name: "alice", PasswordHash: testHash}})
	if err != nil {
		t.Fatal(err)
	}
	newHandler := func() *Handler {
		return &Handler{RelayID: "review-opaque-trust", auth: a,
			tlsClientAuth:      []byte(`{"mode":"require","verifiers":[{"verifier":"leaf"}]}`),
			tlsCustomVerifiers: custom,
			traffic:            map[string]*trafficBudget{"alice": newTrafficBudget(1, 0)},
		}
	}
	old, next := newHandler(), newHandler()
	registerHandler(old)
	registerHandler(next)
	defer unregisterHandler(next)
	if next.traffic["alice"] != old.traffic["alice"] {
		t.Fatal("opaque verifier reload renewed the user's rate burst")
	}
	ctx, cancel := context.WithCancelCause(context.Background())
	defer cancel(nil)
	lt := &liveTunnel{acct: account{name: "alice", hash: testHash}, owner: old, cancel: cancel}
	if !addTunnel(lt) {
		t.Fatal("initial tunnel was denied")
	}
	defer removeTunnel(lt)
	unregisterHandler(old)
	if !errors.Is(context.Cause(ctx), errRevoked) {
		t.Fatal("opaque verifier tunnel survived reload")
	}
	late := &liveTunnel{acct: lt.acct, owner: old, cancel: cancel}
	if addTunnel(late) {
		removeTunnel(late)
		t.Fatal("old verifier-authenticated connection opened a new tunnel")
	}
}

func TestReviewTLSLeafFileReplacementRevokesExistingTunnels(t *testing.T) {
	issuer := newClientCertificateIssuer(t, "leaf identities")
	before := issuer.issue(t, time.Now().Add(time.Hour), x509.ExtKeyUsageClientAuth)
	after := issuer.issue(t, time.Now().Add(time.Hour), x509.ExtKeyUsageClientAuth)
	path := filepath.Join(t.TempDir(), "authorized-client.pem")
	writeLeaf := func(cert tls.Certificate) {
		t.Helper()
		if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]}), 0600); err != nil {
			t.Fatal(err)
		}
	}
	writeLeaf(before)
	port, reload := startRelay(t, nil, map[string]any{
		"strict_sni_host": false,
		"tls_connection_policies": []any{map[string]any{
			"client_authentication": map[string]any{
				"mode": "require",
				"verifiers": []any{map[string]any{
					"verifier":           "leaf",
					"leaf_certs_loaders": []any{map[string]any{"loader": "file", "files": []string{path}}},
				}},
			},
		}},
	})
	target := echoTCP(t)
	var tunnels []struct {
		name string
		s    stream
	}
	for _, v := range versions {
		c := client(port)
		c.TLS.Certificates = []tls.Certificate{before}
		s, done, err := v.openTCP(testCtx(t), c, target)
		if err != nil {
			t.Fatalf("%s valid leaf: %v", v.name, err)
		}
		t.Cleanup(done)
		t.Cleanup(func() { s.Close() })
		if _, err := s.Write([]byte("ready")); err != nil {
			t.Fatal(err)
		}
		var ready [5]byte
		if _, err := io.ReadFull(s, ready[:]); err != nil || string(ready[:]) != "ready" {
			t.Fatalf("%s initial echo: %q, %v", v.name, ready, err)
		}
		tunnels = append(tunnels, struct {
			name string
			s    stream
		}{v.name, s})
	}
	// The declaration and CA pool are unchanged; the verifier's internal
	// leaf set changes at the same path after provisioning clears its JSON.
	writeLeaf(after)
	reload(nil)
	for _, tunnel := range tunnels {
		closed := make(chan error, 1)
		go func() {
			var buf [1]byte
			_, err := tunnel.s.Read(buf[:])
			closed <- err
		}()
		select {
		case err := <-closed:
			if err == nil {
				t.Fatalf("%s retained revoked leaf identity", tunnel.name)
			}
		case <-time.After(2 * time.Second):
			tunnel.s.Close()
			t.Fatalf("%s retained revoked leaf identity", tunnel.name)
		}
	}
	for _, v := range versions {
		oldClient := client(port)
		oldClient.TLS.Certificates = []tls.Certificate{before}
		oldStream, oldDone, err := v.openTCP(testCtx(t), oldClient, target)
		if oldDone != nil {
			oldDone()
		}
		if err == nil {
			oldStream.Close()
			t.Fatalf("%s accepted a fresh connection with the replaced leaf", v.name)
		}
		c := client(port)
		c.TLS.Certificates = []tls.Certificate{after}
		s, done, err := v.openTCP(testCtx(t), c, target)
		if err != nil {
			t.Fatalf("%s new authorized leaf: %v", v.name, err)
		}
		s.Close()
		done()
	}
}

func TestReviewH3HandshakeAdmissionBounded(t *testing.T) {
	ep := &endpoint{users: []endpointUser{{server: &http3.Server{}}}}
	initial := len(h3Connections)
	var cancels []context.CancelFunc
	t.Cleanup(func() {
		for _, cancel := range cancels {
			cancel()
		}
	})
	for range cap(h3Connections) - initial {
		ctx, cancel := context.WithCancel(context.Background())
		cancels = append(cancels, cancel)
		if _, err := ep.connectionContext(ctx, nil); err != nil {
			t.Fatalf("admission below limit: %v", err)
		}
	}
	if _, err := ep.connectionContext(context.Background(), nil); !errors.Is(err, errH3ConnectionLimit) {
		t.Fatalf("unfinished handshakes bypassed admission: %v", err)
	}
	for _, cancel := range cancels {
		cancel()
	}
	deadline := time.Now().Add(time.Second)
	for len(h3Connections) > initial {
		if time.Now().After(deadline) {
			t.Fatal("failed handshakes leaked admission")
		}
		time.Sleep(time.Millisecond)
	}
}

func TestReviewH3TLSGenerationMatchesHandler(t *testing.T) {
	cert, err := tls.X509KeyPair([]byte(pki().certPEM), []byte(pki().keyPEM))
	if err != nil {
		t.Fatal(err)
	}
	entered := make(chan struct{})
	proceed := make(chan struct{})
	releaseHandshake := sync.OnceFunc(func() { close(proceed) })
	t.Cleanup(releaseHandshake)
	oldPolicy := &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{http3.NextProtoH3}}
	oldTLS := http3.ConfigureTLSConfig(&tls.Config{
		Certificates: []tls.Certificate{cert},
		GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) {
			close(entered)
			<-proceed
			return oldPolicy, nil
		},
	})
	oldServer := &http3.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "old generation")
	})}
	newServer := &http3.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "new generation")
	})}
	ep, err := acquireEndpoint("udp", "127.0.0.1:0", endpointUser{oldServer, oldTLS}, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		releaseHandshake()
		ep.release(newServer)
		ep.release(oldServer)
		_ = oldServer.Close()
		_ = newServer.Close()
	})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	type dialResult struct {
		conn *quic.Conn
		err  error
	}
	dialed := make(chan dialResult, 1)
	go func() {
		conn, err := quic.DialAddr(ctx, ep.conn.LocalAddr().String(), &tls.Config{
			RootCAs: pki().pool, ServerName: "relay.test", NextProtos: []string{http3.NextProtoH3},
		}, nil)
		dialed <- dialResult{conn, err}
	}()
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal("handshake never reached TLS selection")
	}
	// Tightening TLS client authentication during the paused handshake
	// must not route its old, certificate-free TLS identity to this server.
	newTLS := http3.ConfigureTLSConfig(&tls.Config{Certificates: []tls.Certificate{cert}, ClientAuth: tls.RequireAnyClientCert})
	if _, err := acquireEndpoint("udp", "127.0.0.1:0", endpointUser{newServer, newTLS}, zap.NewNop()); err != nil {
		t.Fatal(err)
	}
	releaseHandshake()
	r := <-dialed
	if r.err != nil {
		t.Fatal(r.err)
	}
	defer r.conn.CloseWithError(0, "")
	transport := &http3.Transport{}
	cc := transport.NewClientConn(r.conn)
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://relay.test/", nil)
	rsp, err := cc.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	defer rsp.Body.Close()
	body, err := io.ReadAll(rsp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "old generation" {
		t.Fatalf("TLS from old generation reached %q", body)
	}
}

func TestReviewH3NilTLSConfigCallbackRetainsPolicy(t *testing.T) {
	cert, err := tls.X509KeyPair([]byte(pki().certPEM), []byte(pki().keyPEM))
	if err != nil {
		t.Fatal(err)
	}
	srv := &http3.Server{Handler: http.NotFoundHandler()}
	cfg := http3.ConfigureTLSConfig(&tls.Config{
		Certificates:       []tls.Certificate{cert},
		GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) { return nil, nil },
	})
	ep, err := acquireEndpoint("udp", "127.0.0.1:0", endpointUser{srv, cfg}, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ep.release(srv); _ = srv.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	conn, err := quic.DialAddr(ctx, ep.conn.LocalAddr().String(), &tls.Config{
		RootCAs: pki().pool, ServerName: "relay.test", NextProtos: []string{http3.NextProtoH3},
	}, nil)
	if err != nil {
		t.Fatalf("nil policy callback lost configured certificate: %v", err)
	}
	_ = conn.CloseWithError(0, "")
}

func TestReviewH3ECHUsesCaddyRootTLSConfig(t *testing.T) {
	cert, err := tls.X509KeyPair([]byte(pki().certPEM), []byte(pki().keyPEM))
	if err != nil {
		t.Fatal(err)
	}
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	// ECHConfigContents: X25519, HKDF-SHA256/AES-128-GCM, public name.
	contents := []byte{1, 0, 0x20}
	contents = binary.BigEndian.AppendUint16(contents, uint16(len(key.PublicKey().Bytes())))
	contents = append(contents, key.PublicKey().Bytes()...)
	contents = append(contents, 0, 4, 0, 1, 0, 1, 0, byte(len("relay.test")))
	contents = append(contents, "relay.test"...)
	contents = append(contents, 0, 0)
	config := binary.BigEndian.AppendUint16([]byte{0xfe, 0x0d}, uint16(len(contents)))
	config = append(config, contents...)
	configList := binary.BigEndian.AppendUint16(nil, uint16(len(config)))
	configList = append(configList, config...)
	srv := &http3.Server{Handler: http.NotFoundHandler()}
	cfg := http3.ConfigureTLSConfig(&tls.Config{
		MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert},
		GetEncryptedClientHelloKeys: func(*tls.ClientHelloInfo) ([]tls.EncryptedClientHelloKey, error) {
			return []tls.EncryptedClientHelloKey{{Config: config, PrivateKey: key.Bytes(), SendAsRetry: true}}, nil
		},
	})
	ep, err := acquireEndpoint("udp", "127.0.0.1:0", endpointUser{srv, cfg}, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ep.release(srv); _ = srv.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	conn, err := quic.DialAddr(ctx, ep.conn.LocalAddr().String(), &tls.Config{
		RootCAs: pki().pool, ServerName: "relay.test", NextProtos: []string{http3.NextProtoH3},
		EncryptedClientHelloConfigList: configList,
	}, nil)
	if err != nil {
		t.Fatalf("Caddy's ECH keys did not reach QUIC TLS: %v", err)
	}
	defer conn.CloseWithError(0, "")
	if !conn.ConnectionState().TLS.ECHAccepted {
		t.Fatal("server did not accept configured ECH")
	}
}

func TestReviewH3StartFailureReleasesEarlierEndpoints(t *testing.T) {
	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()
	s := &relayServer{
		srv:      &caddyhttp.Server{TLSConnPolicies: caddytls.ConnectionPolicies{{TLSConfig: &tls.Config{}}}},
		h3Listen: []string{"tcp/127.0.0.1:0", "tcp/127.0.0.1:not-a-port"},
	}
	a := &App{ctx: ctx, logger: zap.NewNop(), servers: []*relayServer{s}}
	t.Cleanup(func() { _ = a.Stop() })
	if err := a.Start(); err == nil {
		t.Fatal("invalid later address was accepted")
	}
	if len(s.endpoints) != 0 {
		t.Fatal("failed startup retained the earlier socket")
	}
	endpoints.Lock()
	_, retained := endpoints.m["udp/127.0.0.1:0"]
	endpoints.Unlock()
	if retained {
		t.Fatal("failed generation still owns endpoint registration")
	}
}

type reviewBlockingClient struct {
	readStarted  chan struct{}
	writeStarted chan struct{}
	interrupted  chan struct{}
	allowExit    chan struct{}
	once         sync.Once
}

func (c *reviewBlockingClient) Read([]byte) (int, error) {
	close(c.readStarted)
	<-c.interrupted
	<-c.allowExit
	return 0, io.ErrClosedPipe
}
func (c *reviewBlockingClient) Write([]byte) (int, error) {
	close(c.writeStarted)
	<-c.interrupted
	<-c.allowExit
	return 0, io.ErrClosedPipe
}
func (c *reviewBlockingClient) interrupt(abortReason) { c.once.Do(func() { close(c.interrupted) }) }
func (c *reviewBlockingClient) abort(why abortReason) { c.interrupt(why) }
func (c *reviewBlockingClient) close()                { c.interrupt(abortCancelled) }
func (c *reviewBlockingClient) closeWrite() bool      { return false }
func (c *reviewBlockingClient) gone() <-chan struct{} { return nil }

func TestReviewTCPReturnsAfterCopyWorkersStop(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	relay, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer relay.Close()
	peer, err := l.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	c := &reviewBlockingClient{
		readStarted: make(chan struct{}), writeStarted: make(chan struct{}),
		interrupted: make(chan struct{}), allowExit: make(chan struct{}),
	}
	release := sync.OnceFunc(func() { close(c.allowExit) })
	t.Cleanup(release)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		_, _, _, _ = pumpTCP(ctx, c, relay.(*net.TCPConn))
		close(done)
	}()
	if _, err := peer.Write([]byte("a blocked response write")); err != nil {
		t.Fatal(err)
	}
	for _, started := range []chan struct{}{c.readStarted, c.writeStarted} {
		select {
		case <-started:
		case <-time.After(time.Second):
			t.Fatal("copy worker did not start")
		}
	}
	cancel()
	select {
	case <-c.interrupted:
	case <-done:
		t.Fatal("pump returned while workers still own client I/O")
	case <-time.After(time.Second):
		t.Fatal("cancellation did not interrupt blocked client I/O")
	}
	select {
	case <-done:
		t.Fatal("pump returned before interrupted workers exited")
	case <-time.After(25 * time.Millisecond):
	}
	release()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("copy workers did not release the pump")
	}
}
