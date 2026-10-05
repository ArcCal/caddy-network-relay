package networkrelay

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"io"
	"math/big"
	"net/http"
	"testing"
	"time"
)

// RequestClientCert proves possession of a private key without checking the
// self-signed identity's validity or purpose. Exercise those checks through
// real TLS sessions so that Basic fallback also crosses the same handshake.
func TestReviewPinnedClientCertificateValidity(t *testing.T) {
	now := time.Now()
	cases := []struct {
		name       string
		before     time.Time
		after      time.Time
		keyUsage   x509.KeyUsage
		usage      []x509.ExtKeyUsage
		unknown    []asn1.ObjectIdentifier
		extensions []pkix.Extension
		accepted   bool
		password   bool
		identity   tls.Certificate
	}{
		{name: "client-auth", before: now.Add(-time.Hour), after: now.Add(time.Hour), keyUsage: x509.KeyUsageDigitalSignature, usage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, accepted: true},
		{name: "combined-client-auth", before: now.Add(-time.Hour), after: now.Add(time.Hour), keyUsage: x509.KeyUsageDigitalSignature, usage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, accepted: true, password: true},
		{name: "unrestricted", before: now.Add(-time.Hour), after: now.Add(time.Hour), keyUsage: x509.KeyUsageDigitalSignature, accepted: true},
		{name: "no-usage-extensions", before: now.Add(-time.Hour), after: now.Add(time.Hour), accepted: true},
		{name: "any-purpose", before: now.Add(-time.Hour), after: now.Add(time.Hour), keyUsage: x509.KeyUsageDigitalSignature, usage: []x509.ExtKeyUsage{x509.ExtKeyUsageAny, x509.ExtKeyUsageServerAuth}, accepted: true},
		{name: "expired", before: now.Add(-2 * time.Hour), after: now.Add(-time.Hour), keyUsage: x509.KeyUsageDigitalSignature, usage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, password: true},
		{name: "future", before: now.Add(time.Hour), after: now.Add(2 * time.Hour), keyUsage: x509.KeyUsageDigitalSignature, usage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, password: true},
		{name: "server-only", before: now.Add(-time.Hour), after: now.Add(time.Hour), keyUsage: x509.KeyUsageDigitalSignature, usage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, password: true},
		{name: "unknown-purpose", before: now.Add(-time.Hour), after: now.Add(time.Hour), keyUsage: x509.KeyUsageDigitalSignature, unknown: []asn1.ObjectIdentifier{{1, 3, 6, 1, 4, 1, 55555, 1}}, password: true},
		{name: "wrong-key-usage", before: now.Add(-time.Hour), after: now.Add(time.Hour), keyUsage: x509.KeyUsageCertSign, usage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, password: true},
		{name: "zero-key-usage", before: now.Add(-time.Hour), after: now.Add(time.Hour), usage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, extensions: []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 15}, Critical: true, Value: []byte{3, 2, 0, 0}}}, password: true},
	}
	users := make([]map[string]string, len(cases))
	for i := range cases {
		tc := &cases[i]
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		leaf := &x509.Certificate{
			SerialNumber: big.NewInt(int64(i + 1)), Subject: pkix.Name{CommonName: tc.name},
			NotBefore: tc.before, NotAfter: tc.after, KeyUsage: tc.keyUsage,
			ExtKeyUsage: tc.usage, UnknownExtKeyUsage: tc.unknown, ExtraExtensions: tc.extensions,
		}
		der, err := x509.CreateCertificate(rand.Reader, leaf, leaf, &key.PublicKey, key)
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		tc.identity = tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: parsed}
		fp := sha256.Sum256(der)
		users[i] = map[string]string{"name": tc.name, "certificate_sha256": hex.EncodeToString(fp[:])}
		if tc.password {
			users[i]["password_hash"] = testHash
		}
	}
	port, _ := startRelay(t, map[string]any{"users": users}, map[string]any{
		"strict_sni_host":         false,
		"tls_connection_policies": []any{map[string]any{"client_authentication": map[string]any{"mode": "request"}}},
	})
	target := echoTCP(t)
	for _, v := range versions {
		t.Run(v.name, func(t *testing.T) {
			for _, tc := range cases {
				t.Run(tc.name, func(t *testing.T) {
					open := func(authorization string) error {
						c := client(port)
						c.Authorization = authorization
						c.TLS.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
							return &tc.identity, nil
						}
						s, done, err := v.openTCP(testCtx(t), c, target)
						if err != nil {
							return err
						}
						defer done()
						defer s.Close()
						payload := []byte("pinned identity")
						if _, err := s.Write(payload); err != nil {
							return err
						}
						got := make([]byte, len(payload))
						if _, err := io.ReadFull(s, got); err != nil {
							return err
						}
						if string(got) != string(payload) {
							return errors.New("pinned certificate tunnel corrupted data")
						}
						return nil
					}
					err := open("")
					if tc.accepted {
						if err != nil {
							t.Fatalf("certificate-only authentication: %v", err)
						}
						if err := open(BasicAuthorization("ignored", "wrong")); err != nil {
							t.Fatalf("valid certificate lost authentication to an invalid Basic header: %v", err)
						}
					} else {
						var denied *statusError
						if !errors.As(err, &denied) || denied.Status != http.StatusMethodNotAllowed {
							t.Fatalf("invalid pinned identity was not refused after TLS: %v", err)
						}
						if err := open(BasicAuthorization(tc.name, testPassword)); err != nil {
							t.Fatalf("valid Basic fallback with an invalid pinned certificate: %v", err)
						}
					}
				})
			}
		})
	}
}
