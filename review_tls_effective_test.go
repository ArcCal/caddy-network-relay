package networkrelay

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/caddyserver/caddy/v2/modules/caddytls"
)

func TestReviewEffectiveClientTrustMustBeUniform(t *testing.T) {
	first := newClientCertificateIssuer(t, "stable client trust")
	next := newClientCertificateIssuer(t, "rotated client trust")
	var calls atomic.Int32
	var rotate atomic.Bool
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		ca := first
		if n := calls.Add(1); rotate.Load() && n%2 == 0 {
			ca = next
		}
		_, _ = w.Write(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.cert.Raw}))
	}))
	defer provider.Close()
	auth := map[string]any{"mode": "require_and_verify", "ca": map[string]any{"provider": "http", "endpoints": []string{provider.URL}}}
	server := map[string]any{"strict_sni_host": false, "tls_connection_policies": []any{
		map[string]any{"match": map[string]any{"sni": []string{"unused.test"}}, "client_authentication": auth},
		map[string]any{"client_authentication": auth},
	}}
	port, _ := startRelay(t, nil, server)
	before := first.issue(t, time.Now().Add(time.Hour), x509.ExtKeyUsageClientAuth)
	c := client(port)
	c.TLS.Certificates = []tls.Certificate{before}
	s, done, err := versions[1].openTCP(testCtx(t), c, echoTCP(t))
	if err != nil {
		t.Fatal(err)
	}
	defer done()
	defer s.Close()
	rotate.Store(true)
	if err := caddy.Load(relayConfig(port, nil, server), true); err == nil || !strings.Contains(err.Error(), "same effective TLS client authentication") {
		t.Fatalf("identical CA-provider declarations loaded unequal roots: %v", err)
	}
	if calls.Load() != 4 {
		t.Fatalf("trust provider reads=%d, want4", calls.Load())
	}
	// Reject the inconsistent new generation without disrupting the valid
	// old one or its authenticated tunnels.
	payload := []byte("old trusted tunnel after rejected reload")
	if _, err := s.Write(payload); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(s, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != string(payload) {
		t.Fatal("old tunnel corrupted data")
	}
}

func TestReviewTunnelTransferChecksEveryEffectiveTrustPolicy(t *testing.T) {
	first := newClientCertificateIssuer(t, "first policy")
	other := newClientCertificateIssuer(t, "other policy")
	pool := func(ca clientCertificateIssuer) *x509.CertPool { p := x509.NewCertPool(); p.AddCert(ca.cert); return p }
	a, b := pool(first), pool(other)
	handler := func(pools ...*x509.CertPool) *Handler {
		policies := make(caddytls.ConnectionPolicies, len(pools))
		for i, pool := range pools {
			policies[i] = &caddytls.ConnectionPolicy{TLSConfig: &tls.Config{ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool}}
		}
		return &Handler{RelayID: "review-effective-policies", tlsClientAuth: []byte(`{"ca":"same provider"}`), server: &relayServer{srv: &caddyhttp.Server{TLSConnPolicies: policies}}}
	}
	if sameRelay(handler(a, a), handler(a, b)) {
		t.Fatal("later policy trust replacement retained tunnels")
	}
	if sameRelay(handler(a, b), handler(a, a)) {
		t.Fatal("inconsistent old trust retained tunnels")
	}
	if !sameRelay(handler(a), handler(a.Clone(), a.Clone())) {
		t.Fatal("adding an identity with unchanged uniform trust revoked tunnels")
	}
}
