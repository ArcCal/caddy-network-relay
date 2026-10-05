package networkrelay

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestProfileInstalledIdentityReference(t *testing.T) {
	const uuid = "aabbccdd-1122-3344-5566-778899aabbcc"
	p := Profile{Host: "relay.example.com", User: "ipad", IdentityCertificateUUID: uuid}
	text, err := p.Generate()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(text, "<key>PayloadCertificateUUID</key>") != 1 ||
		!strings.Contains(text, "<string>"+strings.ToUpper(uuid)+"</string>") ||
		strings.Contains(text, "AdditionalHTTPHeaderFields") || strings.Contains(text, "com.apple.security.pkcs12") {
		t.Fatalf("installed identity profile:\n%s", text)
	}
	// An installed certificate UUID cannot authenticate a DDM declaration;
	// accepting it while dropping the reference would lose authentication.
	if _, err := p.GenerateDDM(); err == nil {
		t.Error("certificate UUID accepted by DDM")
	}
	p.Password = "secret"
	if _, err := p.GenerateDDM(); err == nil {
		t.Error("certificate UUID silently ignored when a DDM password is present")
	}
	for _, q := range []Profile{
		{Host: p.Host, User: p.User, IdentityCertificateUUID: uuid, Identity: &IdentityPayload{P12: []byte{1}}},
		{Host: p.Host, User: p.User, IdentityCertificateUUID: uuid, IdentityAsset: "identity.ipad"},
	} {
		if _, err := q.Generate(); err == nil {
			t.Error("multiple identity references accepted by profile")
		}
		if _, err := q.GenerateDDM(); err == nil {
			t.Error("multiple identity references accepted by DDM")
		}
	}
}

func TestProfileInstalledIdentityCommand(t *testing.T) {
	const uuid = "aabbccdd-1122-3344-5566-778899aabbcc"
	file := filepath.Join(t.TempDir(), "ipad.mobileconfig")
	cmd := profileCommand()
	cmd.SetArgs([]string{"--host", "relay.example.com", "--user", "ipad", "--identity-certificate-uuid", uuid, "-o", file})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	text, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(text), strings.ToUpper(uuid)) || strings.Contains(string(text), "Authorization") {
		t.Fatalf("installed identity command:\n%s", text)
	}
	for _, args := range [][]string{
		{"--ddm", "--identity-certificate-uuid", uuid},
		{"--identity", "missing.p12", "--identity-certificate-uuid", uuid},
		{"--identity-certificate-uuid", "invalid"},
	} {
		cmd = profileCommand()
		cmd.SetArgs(append([]string{"--host", "relay.example.com", "--user", "ipad", "-o", file}, args...))
		cmd.SetOut(io.Discard)
		cmd.SetErr(io.Discard)
		if err := cmd.Execute(); err == nil {
			t.Errorf("%v accepted", args)
		}
	}
}
