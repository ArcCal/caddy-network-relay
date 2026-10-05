package networkrelay

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"software.sslmate.com/src/go-pkcs12"
)

func TestIdentityDecodesWithItsPassword(t *testing.T) {
	id, err := GenerateIdentity("ipad", 365)
	if err != nil {
		t.Fatal(err)
	}
	key, cert, err := pkcs12.Decode(id.P12, id.Password)
	if err != nil {
		t.Fatal(err)
	}
	if fp := sha256.Sum256(cert.Raw); hex.EncodeToString(fp[:]) != id.Fingerprint {
		t.Fatal("fingerprint does not match the certificate")
	}
	if pub, ok := key.(*ecdsa.PrivateKey); !ok || !pub.PublicKey.Equal(cert.PublicKey) {
		t.Fatal("key does not match the certificate")
	}
	if cert.Subject.CommonName != "ipad" || !slices.Contains(cert.ExtKeyUsage, x509.ExtKeyUsageClientAuth) ||
		cert.NotAfter.Before(time.Now().AddDate(0, 0, 364)) {
		t.Fatalf("certificate: %v %v %v", cert.Subject, cert.ExtKeyUsage, cert.NotAfter)
	}
	if _, _, err := pkcs12.Decode(id.P12, "wrong"); err == nil {
		t.Fatal("decoded with the wrong password")
	}
	if _, err := GenerateIdentity("bad name", 365); err == nil {
		t.Fatal("bad user name accepted")
	}
	if _, err := GenerateIdentity("ipad", 0); err == nil {
		t.Fatal("zero days accepted")
	}
}

func TestProfileWithIdentity(t *testing.T) {
	id, err := GenerateIdentity("ipad", 30)
	if err != nil {
		t.Fatal(err)
	}
	p := Profile{Host: "relay.example.com", User: "ipad", Identity: &IdentityPayload{P12: id.P12}}
	x, err := p.Generate()
	if err != nil {
		t.Fatal(err)
	}
	// The relay refers to the identity payload by its UUID.
	ref := regexp.MustCompile(`<key>PayloadCertificateUUID</key>\s*<string>([0-9A-F-]{36})</string>`).FindStringSubmatch(x)
	if ref == nil || !strings.Contains(x, "<string>com.apple.security.pkcs12</string>\n      <key>PayloadVersion</key>\n      <integer>1</integer>\n"+
		"      <key>PayloadIdentifier</key>\n      <string>com.github.arccal.network-relay.relay.example.com.ipad.identity</string>\n"+
		"      <key>PayloadUUID</key>\n      <string>"+ref[1]+"</string>") {
		t.Fatalf("no matching identity payload:\n%s", x)
	}
	if !strings.Contains(x, "<data>"+base64.StdEncoding.EncodeToString(id.P12)+"</data>") {
		t.Error("PKCS#12 data missing")
	}
	if strings.Contains(x, "AdditionalHTTPHeaderFields") || strings.Contains(x, "<key>Password</key>") {
		t.Error("credentials that were not given")
	}
	for _, tag := range []string{"dict", "array", "plist"} {
		if strings.Count(x, "<"+tag) != strings.Count(x, "</"+tag+">") {
			t.Errorf("unbalanced %s", tag)
		}
	}
	p.Password, p.Identity.Password = "secret", "p12 <pass>"
	if x, _ = p.Generate(); !strings.Contains(x, "<key>Password</key>\n      <string>p12 &lt;pass&gt;</string>") ||
		!strings.Contains(x, "AdditionalHTTPHeaderFields") {
		t.Error("embedded password or Basic credentials missing")
	}
	if _, err := (&Profile{Host: "relay.example.com", User: "ipad"}).Generate(); err == nil {
		t.Error("a profile without credentials")
	}
	if _, err := (&Profile{Host: "relay.example.com", User: "ipad", Identity: &IdentityPayload{}}).Generate(); err == nil {
		t.Error("an empty identity")
	}
	if _, err := (&Profile{Host: "relay.example.com", User: "ipad", IdentityAsset: "id"}).Generate(); err == nil {
		t.Error("an identity asset in a .mobileconfig")
	}
}

func TestDDMDeclaration(t *testing.T) {
	yes := true
	p := Profile{Host: "Relay.example.com", User: "iphone", Password: "pw", MatchDomains: []string{"Example.COM."},
		UIToggleEnabled: &yes, RelayUUID: "00112233-4455-6677-8899-aabbccddeeff"}
	text, err := p.GenerateDDM()
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		Type, Identifier, ServerToken string
		Payload                       struct {
			VisibleName      string
			Relays           []map[string]any
			MatchDomains     []string
			UIToggleEnabled  *bool
			RelayUUID        string
			AllowDNSFailover *bool
		}
	}
	if err := json.Unmarshal([]byte(text), &v); err != nil {
		t.Fatal(err)
	}
	url := "https://relay.example.com/.well-known/masque/udp/{target_host}/{target_port}/"
	relay := v.Payload.Relays[0]
	if v.Type != "com.apple.configuration.network.relay" || v.Identifier != "com.github.arccal.network-relay.relay.example.com.iphone" ||
		!isUUID(v.ServerToken) || v.Payload.VisibleName != "relay.example.com" || len(v.Payload.Relays) != 1 ||
		relay["HTTP3RelayURL"] != url || relay["HTTP2RelayURL"] != url ||
		relay["AdditionalHTTPHeaderFields"].(map[string]any)["Authorization"] != BasicAuthorization("iphone", "pw") ||
		!slices.Equal(v.Payload.MatchDomains, []string{"example.com"}) || v.Payload.UIToggleEnabled == nil || !*v.Payload.UIToggleEnabled ||
		v.Payload.RelayUUID != "00112233-4455-6677-8899-AABBCCDDEEFF" || v.Payload.AllowDNSFailover != nil {
		t.Fatalf("%+v", v)
	}
	p.Password, p.IdentityAsset = "", "identity.ipad"
	if text, err = p.GenerateDDM(); err != nil || !strings.Contains(text, `"IdentityAssetReference": "identity.ipad"`) ||
		strings.Contains(text, "AdditionalHTTPHeaderFields") {
		t.Fatalf("%v\n%s", err, text)
	}
	p.Identity = &IdentityPayload{P12: []byte{1}}
	if _, err := p.GenerateDDM(); err == nil {
		t.Fatal("a PKCS#12 file in a DDM declaration")
	}
}

func TestIdentityAndProfileCommands(t *testing.T) {
	dir := t.TempDir()
	p12 := filepath.Join(dir, "ipad.p12")
	c := identityCommand()
	c.SetArgs([]string{"--name", "ipad", "--days", "30", "-o", p12})
	var err error
	out := captureStdout(t, func() { err = c.Execute() })
	if err != nil {
		t.Fatal(err)
	}
	line := regexp.MustCompile(`(?m)^user ipad certificate ([0-9a-f]{64})$`).FindStringSubmatch(out)
	pass := regexp.MustCompile(`(?m)^identity password: (\S+)$`).FindStringSubmatch(out)
	if line == nil || pass == nil {
		t.Fatalf("output:\n%s", out)
	}
	if fi, err := os.Stat(p12); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("p12 file: %v", err)
	}
	b, _ := os.ReadFile(p12)
	if _, cert, err := pkcs12.Decode(b, pass[1]); err != nil || hex.EncodeToString(sha256Of(cert.Raw)) != line[1] {
		t.Fatalf("printed password or fingerprint does not match: %v", err)
	}
	// A profile with only the identity needs no password; with --ddm
	// it refers to an asset instead.
	profile := filepath.Join(dir, "ipad.mobileconfig")
	c = profileCommand()
	c.SetArgs([]string{"--host", "relay.example.com", "--user", "ipad", "--identity", p12, "-o", profile})
	if err := c.Execute(); err != nil {
		t.Fatal(err)
	}
	if x, _ := os.ReadFile(profile); !bytes.Contains(x, []byte("PayloadCertificateUUID")) || bytes.Contains(x, []byte("Authorization")) {
		t.Fatalf("profile:\n%s", x)
	}
	ddm := filepath.Join(dir, "ipad.json")
	c = profileCommand()
	c.SetArgs([]string{"--host", "relay.example.com", "--user", "ipad", "--ddm", "--identity-asset", "identity.ipad", "-o", ddm})
	if err := c.Execute(); err != nil {
		t.Fatal(err)
	}
	if x, _ := os.ReadFile(ddm); !json.Valid(x) || !bytes.Contains(x, []byte("identity.ipad")) {
		t.Fatalf("declaration:\n%s", x)
	}
	for _, args := range [][]string{
		{"--identity-asset", "identity.ipad"},             // asset without --ddm
		{"--ddm", "--identity", p12},                      // a file in a declaration
		{"--embed-identity-password", "--password", "pw"}, // nothing to embed into
	} {
		c = profileCommand()
		c.SetArgs(append([]string{"--host", "relay.example.com", "--user", "ipad", "-o", filepath.Join(dir, "x")}, args...))
		c.SetOut(io.Discard)
		c.SetErr(io.Discard)
		if err := c.Execute(); err == nil {
			t.Errorf("%v accepted", args)
		}
	}
}

func sha256Of(b []byte) []byte {
	s := sha256.Sum256(b)
	return s[:]
}

// tlsIdentity is a client certificate for user, and its fingerprint.
func tlsIdentity(t *testing.T, user string) (tls.Certificate, string) {
	t.Helper()
	id, err := GenerateIdentity(user, 30)
	if err != nil {
		t.Fatal(err)
	}
	key, cert, err := pkcs12.Decode(id.P12, id.Password)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{cert.Raw}, PrivateKey: key, Leaf: cert}, id.Fingerprint
}

// Devices with an identity authenticate in the TLS handshake, over every
// HTTP version; an expired account's certificate is refused, and an
// unknown certificate does not stop a password from working.
func TestCertificateAuthentication(t *testing.T) {
	ipad, ipadFP := tlsIdentity(t, "ipad")
	old, oldFP := tlsIdentity(t, "old")
	stranger, _ := tlsIdentity(t, "stranger")
	users := []map[string]string{
		{"name": "alice", "password_hash": testHash},
		{"name": "ipad", "certificate_sha256": ipadFP},
		{"name": "old", "certificate_sha256": oldFP, "expires": time.Now().Add(-time.Hour).Format(time.RFC3339)},
	}
	clientAuth := map[string]any{
		"tls_connection_policies": []any{map[string]any{"client_authentication": map[string]any{"mode": "request"}}},
	}
	// Caddy then matches Host against the TLS server name, which a CONNECT
	// never passes: the relay refuses to start unless that is turned off.
	if err := caddy.Load(relayConfig(freePort(t), nil, clientAuth), true); err == nil || !strings.Contains(err.Error(), "strict_sni_host") {
		caddy.Stop()
		t.Fatalf("started with strict SNI-Host matching: %v", err)
	}
	clientAuth["strict_sni_host"] = false
	port, _ := startRelay(t, map[string]any{"users": users}, clientAuth)
	target := echoTCP(t)
	roundTrip := func(t *testing.T, v versionCase, cert *tls.Certificate, authorization string) error {
		c := client(port)
		c.Authorization = authorization
		if cert != nil {
			c.TLS.Certificates = []tls.Certificate{*cert}
		}
		s, done, err := v.openTCP(testCtx(t), c, target)
		if err != nil {
			return err
		}
		defer done()
		defer s.Close()
		if _, err := s.Write([]byte("ping")); err != nil {
			return err
		}
		got := make([]byte, 4)
		if _, err := io.ReadFull(s, got); err != nil || string(got) != "ping" {
			return errors.New("no echo: " + string(got))
		}
		return nil
	}
	for _, v := range versions {
		t.Run(v.name, func(t *testing.T) {
			if err := roundTrip(t, v, &ipad, ""); err != nil {
				t.Fatalf("certificate alone: %v", err)
			}
			var se *statusError
			if err := roundTrip(t, v, &old, ""); !errors.As(err, &se) || se.Status != http.StatusMethodNotAllowed {
				t.Fatalf("expired account's certificate: %v", err)
			}
			if err := roundTrip(t, v, &stranger, ""); !errors.As(err, &se) || se.Status != http.StatusMethodNotAllowed {
				t.Fatalf("unknown certificate: %v", err)
			}
			if err := roundTrip(t, v, &stranger, BasicAuthorization("alice", testPassword)); err != nil {
				t.Fatalf("password with an unknown certificate: %v", err)
			}
		})
	}
}
