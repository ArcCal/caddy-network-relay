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
	"encoding/base64"
	"io"
	"math/big"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/caddyserver/caddy/v2/modules/caddytls"
)

type clientCertificateIssuer struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func newClientCertificateIssuer(t *testing.T, name string) clientCertificateIssuer {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: name},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return clientCertificateIssuer{cert: cert, key: key}
}

func (ca clientCertificateIssuer) issue(t *testing.T, expires time.Time, usage x509.ExtKeyUsage) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "relay client"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: expires,
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// Caddy's TLS policy must also govern the plugin's independent QUIC listener.
// These tests exercise real TLS handshakes and TCP/UDP tunnels; they do not
// substitute for an Apple client presenting its configured identity.
func TestRelayClientCertificateAuthentication(t *testing.T) {
	ca := newClientCertificateIssuer(t, "trusted relay clients")
	other := newClientCertificateIssuer(t, "untrusted relay clients")
	valid := ca.issue(t, time.Now().Add(time.Hour), x509.ExtKeyUsageClientAuth)
	port, reload := startRelay(t, nil, map[string]any{
		"strict_sni_host": false,
		"tls_connection_policies": []any{map[string]any{
			"client_authentication": map[string]any{
				"mode": "require_and_verify",
				"ca": map[string]any{"provider": "inline", "trusted_ca_certs": []string{
					base64.StdEncoding.EncodeToString(ca.cert.Raw),
				}},
			},
		}},
	})
	target := echoTCP(t)
	host, udpPort := echoUDP(t)
	for _, v := range versions {
		t.Run(v.name, func(t *testing.T) {
			for _, tc := range []struct {
				name string
				cert *tls.Certificate
			}{
				{"missing identity", nil},
				{"untrusted issuer", new(other.issue(t, time.Now().Add(time.Hour), x509.ExtKeyUsageClientAuth))},
				{"expired identity", new(ca.issue(t, time.Now().Add(-time.Minute), x509.ExtKeyUsageClientAuth))},
				{"wrong certificate usage", new(ca.issue(t, time.Now().Add(time.Hour), x509.ExtKeyUsageServerAuth))},
			} {
				t.Run(tc.name, func(t *testing.T) {
					ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
					defer cancel()
					c := client(port)
					if tc.cert != nil {
						// Send the certificate even when the issuer isn't advertised.
						c.TLS.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
							return tc.cert, nil
						}
					}
					s, done, err := v.openTCP(ctx, c, target)
					if done != nil {
						defer done()
					}
					if err == nil {
						s.Close()
						t.Fatal("tunnel opened without a valid client identity")
					}
				})
			}
			c := client(port)
			c.TLS.Certificates = []tls.Certificate{valid}
			ctx := testCtx(t)
			s, done, err := v.openTCP(ctx, c, target)
			if err != nil {
				t.Fatal(err)
			}
			defer done()
			defer s.Close()
			msg := []byte("authenticated relay client")
			if _, err := s.Write(msg); err != nil {
				t.Fatal(err)
			}
			got := make([]byte, len(msg))
			if _, err := io.ReadFull(s, got); err != nil || !bytes.Equal(got, msg) {
				t.Fatalf("TCP echo: %q, %v", got, err)
			}
			p, udpDone, err := v.openUDP(ctx, c, host, udpPort)
			if err != nil {
				t.Fatal(err)
			}
			defer udpDone()
			defer p.Close()
			if err := p.Send(msg); err != nil {
				t.Fatal(err)
			}
			if got, err := p.Receive(ctx); err != nil || !bytes.Equal(got, msg) {
				t.Fatalf("UDP echo: %q, %v", got, err)
			}
		})
	}
	// A reload must keep the TLS client-auth policy on newly accepted sessions.
	reload(nil)
	for _, v := range versions {
		ctx := testCtx(t)
		s, done, err := v.openTCP(ctx, client(port), target)
		if done != nil {
			done()
		}
		if err == nil {
			s.Close()
			t.Fatalf("%s accepted missing identity after reload", v.name)
		}
	}
}

func TestRelayServerCertificateAuthentication(t *testing.T) {
	port, _ := startRelay(t, nil, nil)
	target := echoTCP(t)
	for _, v := range versions {
		for _, tc := range []string{"untrusted server", "wrong server name"} {
			t.Run(v.name+"/"+tc, func(t *testing.T) {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				c := client(port)
				if tc == "untrusted server" {
					c.TLS.RootCAs = x509.NewCertPool()
				} else {
					c.Server = "another.test"
				}
				s, done, err := v.openTCP(ctx, c, target)
				if done != nil {
					defer done()
				}
				if err == nil {
					s.Close()
					t.Fatal("client accepted an unauthenticated server")
				}
			})
		}
	}
}

func TestRelayTLSAuthenticationPolicy(t *testing.T) {
	auth := &caddytls.ClientAuthentication{Mode: "require_and_verify", TrustedCACerts: []string{"same CA"}}
	other := &caddytls.ClientAuthentication{Mode: "require_and_verify", TrustedCACerts: []string{"another CA"}}
	for _, tc := range []struct {
		name     string
		strict   bool
		policies caddytls.ConnectionPolicies
		valid    bool
	}{
		{"ordinary TLS", false, caddytls.ConnectionPolicies{{}}, true},
		{"strict host cannot proxy", true, caddytls.ConnectionPolicies{{}}, false},
		{"dedicated client auth", false, caddytls.ConnectionPolicies{{ClientAuthentication: auth}}, true},
		{"identical client auth", false, caddytls.ConnectionPolicies{{ClientAuthentication: auth}, {ClientAuthentication: auth}}, true},
		{"unprotected fallback", false, caddytls.ConnectionPolicies{{ClientAuthentication: auth}, {}}, false},
		{"unprotected first policy", false, caddytls.ConnectionPolicies{{}, {ClientAuthentication: auth}}, false},
		{"different client trust", false, caddytls.ConnectionPolicies{{ClientAuthentication: auth}, {ClientAuthentication: other}}, false},
		{"rejecting fallback", false, caddytls.ConnectionPolicies{{ClientAuthentication: auth}, {Drop: true}}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := validateRelayTLS(&caddyhttp.Server{StrictSNIHost: &tc.strict, TLSConnPolicies: tc.policies})
			if (err == nil) != tc.valid {
				t.Fatalf("valid=%v, error=%v", tc.valid, err)
			}
		})
	}
}
