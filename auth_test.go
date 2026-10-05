package networkrelay

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
)

// The fast hash is the Rust relay's format: a hash made by either verifies
// in the other.
func TestFastHashMatchesTheRustRelay(t *testing.T) {
	const rust = "$pbkdf2-sha256$i=1000,l=32$c2FsdFNBTFRzYWx0U0FMVA$RviVuqoYXwJlwdpwjXmZU95ZL1dsRTi366mc7XAO51s"
	h, err := parsePasswordHash(rust)
	if err != nil || !h.verify([]byte("password")) || h.verify([]byte("Password")) {
		t.Fatalf("Rust hash: %v", err)
	}
	secret := RandomPassword()
	mine, err := HashGeneratedSecret(secret)
	if err != nil {
		t.Fatal(err)
	}
	if h, err := parsePasswordHash(mine); err != nil || !h.verify([]byte(secret)) || h.verify([]byte(secret+"x")) {
		t.Fatalf("own hash: %v", err)
	}
	if _, err := HashGeneratedSecret("too-short"); err == nil {
		t.Error("a short secret got the fast hash")
	}
	for _, bad := range []string{
		"$pbkdf2-sha256$i=10,l=32$c2FsdFNBTFRzYWx0U0FMVA$RviVuqoYXwJlwdpwjXmZU95ZL1dsRTi366mc7XAO51s",
		"$pbkdf2-sha256$i=100000000,l=32$c2FsdFNBTFRzYWx0U0FMVA$RviVuqoYXwJlwdpwjXmZU95ZL1dsRTi366mc7XAO51s",
		"$pbkdf2-sha256$i=1000,l=16$c2FsdFNBTFRzYWx0U0FMVA$RviVuqoYXwJlwdpwjXmZU95ZL1dsRTi366mc7XAO51s",
		"$pbkdf2-sha256$i=1000,l=32$c2FsdA$RviVuqoYXwJlwdpwjXmZU95ZL1dsRTi366mc7XAO51s",
	} {
		if _, err := parsePasswordHash(bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

// fillSlots takes every hashing slot, so that only checks that need no hash
// can finish; it returns the function that frees them.
func fillSlots(a *authenticator) func() {
	for range cap(a.slots) {
		a.slots <- struct{}{}
	}
	return func() {
		for range cap(a.slots) {
			<-a.slots
		}
	}
}

func verifyWithin(a *authenticator, header string, from requester) (account, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	return a.verifyFrom(ctx, header, from)
}

// A reload that leaves a user alone keeps its devices' verified headers: no
// new hash. One that changes or removes the user does not (G-2).
func TestVerifiedHeadersSurviveReloadsOfUnchangedUsers(t *testing.T) {
	secret := RandomPassword()
	hash, _ := HashGeneratedSecret(secret)
	users := []User{{Name: "carol", PasswordHash: hash}, {Name: "dave", PasswordHash: testHash}}
	first, err := newAuthenticator(users)
	if err != nil {
		t.Fatal(err)
	}
	good := BasicAuthorization("carol", secret)
	if _, err := first.verify(context.Background(), good); err != nil {
		t.Fatal(err)
	}
	reloaded, err := newAuthenticator(users)
	if err != nil {
		t.Fatal(err)
	}
	release := fillSlots(reloaded)
	acct, err := verifyWithin(reloaded, good, requester{})
	release()
	if err != nil || acct.name != "carol" {
		t.Fatalf("an unchanged user verified again after a reload: %v", err)
	}
	newHash, _ := HashGeneratedSecret(RandomPassword())
	changed, err := newAuthenticator([]User{{Name: "carol", PasswordHash: newHash}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := changed.verify(context.Background(), good); !errors.Is(err, errBadCredentials) {
		t.Fatalf("the old password still works after a change: %v", err)
	}
	removed, err := newAuthenticator([]User{{Name: "dave", PasswordHash: testHash}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := removed.verify(context.Background(), good); !errors.Is(err, errBadCredentials) {
		t.Fatalf("a removed user still works: %v", err)
	}
}

// New credentials are limited per client address and per connection; the
// limits never touch credentials that already passed (X-1).
func TestNewCredentialsAreLimitedPerClient(t *testing.T) {
	secret := RandomPassword()
	hash, _ := HashGeneratedSecret(secret)
	a, err := newAuthenticator([]User{{Name: "erin", PasswordHash: hash}})
	if err != nil {
		t.Fatal(err)
	}
	attacker := requester{ip: netip.MustParseAddr("198.51.100.7")}
	throttled := 0
	for i := range attemptBurst + 10 {
		if _, err := a.verifyFrom(context.Background(), BasicAuthorization("erin", fmt.Sprint("guess-", i)), attacker); errors.Is(err, errAuthBusy) {
			throttled++
		}
	}
	if throttled < 9 {
		t.Fatalf("only %d of the guesses beyond the burst were refused", throttled)
	}
	// The same /64 is the same client for IPv6.
	v6 := requester{ip: netip.MustParseAddr("2001:db8:1:2::1")}
	for i := range attemptBurst {
		_, _ = a.verifyFrom(context.Background(), BasicAuthorization("erin", fmt.Sprint("v6-", i)), v6)
	}
	sibling := requester{ip: netip.MustParseAddr("2001:db8:1:2::ffff")}
	if _, err := a.verifyFrom(context.Background(), BasicAuthorization("erin", "one more"), sibling); !errors.Is(err, errAuthBusy) {
		t.Fatalf("another address in the same /64 is not limited: %v", err)
	}
	good := BasicAuthorization("erin", secret)
	device := requester{ip: netip.MustParseAddr("203.0.113.9")}
	if _, err := a.verifyFrom(context.Background(), good, device); err != nil {
		t.Fatalf("another client: %v", err)
	}
	if _, err := a.verifyFrom(context.Background(), good, attacker); err != nil {
		t.Fatalf("verified credentials are refused at a limited address: %v", err)
	}

	conn := &connState{}
	conn.pending.Store(pendingPerConnection)
	busy := requester{ip: netip.MustParseAddr("203.0.113.10"), conn: conn}
	if _, err := a.verifyFrom(context.Background(), BasicAuthorization("erin", "new"), busy); !errors.Is(err, errAuthBusy) {
		t.Fatalf("over the connection's limit: %v", err)
	}
	if n := conn.pending.Load(); n != pendingPerConnection {
		t.Fatalf("a refused request changed the connection's count to %d", n)
	}
}

// Accounts expire; certificates authenticate on their own; a user needs a
// credential (X-3).
func TestExpiryAndCertificates(t *testing.T) {
	fp := "00112233445566778899aabbccddeeff00112233445566778899AABBCCDDEEFF"
	a, err := newAuthenticator([]User{
		{Name: "old", PasswordHash: testHash, Expires: time.Now().Add(-time.Minute).Format(time.RFC3339)},
		{Name: "soon", PasswordHash: testHash, Expires: time.Now().Add(time.Hour).Format(time.RFC3339)},
		{Name: "ipad", CertificateSHA256: fp},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.verify(context.Background(), BasicAuthorization("old", testPassword)); !errors.Is(err, errBadCredentials) {
		t.Fatalf("an expired account works: %v", err)
	}
	acct, err := a.verify(context.Background(), BasicAuthorization("soon", testPassword))
	if err != nil || acct.expires.IsZero() || !a.has(acct) {
		t.Fatalf("an account before its expiry: %v", err)
	}
	parsed, _ := parseFingerprint(fp)
	if acct, ok := a.verifyCertificate(parsed); !ok || acct.name != "ipad" {
		t.Fatal("certificate not recognized")
	}
	if _, ok := a.verifyCertificate([32]byte{1}); ok {
		t.Fatal("unknown certificate accepted")
	}
	for _, bad := range [][]User{
		{{Name: "none"}},
		{{Name: "x", PasswordHash: testHash, Expires: "soon"}},
		{{Name: "x", CertificateSHA256: "abc"}},
		{{Name: "x", CertificateSHA256: fp}, {Name: "y", CertificateSHA256: fp}},
	} {
		if _, err := newAuthenticator(bad); err == nil {
			t.Errorf("accepted %+v", bad)
		}
	}
}

func TestCaddyfileUserOptions(t *testing.T) {
	fp := "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
	for _, tc := range []struct {
		line string
		want User
		ok   bool
	}{
		{"user a " + testHash, User{Name: "a", PasswordHash: testHash}, true},
		{"user a " + testHash + " expires 2027-01-31T00:00:00Z", User{Name: "a", PasswordHash: testHash, Expires: "2027-01-31T00:00:00Z"}, true},
		{"user a certificate " + fp, User{Name: "a", CertificateSHA256: fp}, true},
		{"user a " + testHash + " certificate " + fp + " expires 2027-01-31T00:00:00Z",
			User{Name: "a", PasswordHash: testHash, CertificateSHA256: fp, Expires: "2027-01-31T00:00:00Z"}, true},
		{"user a", User{}, false},
		{"user a certificate", User{}, false},
		{"user a " + testHash + " colour blue", User{}, false},
	} {
		h := new(Handler)
		err := h.UnmarshalCaddyfile(caddyfile.NewTestDispenser("network_relay {\n" + tc.line + "\n}"))
		if (err == nil) != tc.ok {
			t.Errorf("%q: %v", tc.line, err)
			continue
		}
		if tc.ok && (len(h.Users) != 1 || h.Users[0] != tc.want) {
			t.Errorf("%q: %+v", tc.line, h.Users)
		}
	}
}

func TestPasswdGivesGeneratedPasswordsTheFastHash(t *testing.T) {
	out := captureStdout(t, func() {
		c := passwdCommand()
		c.SetArgs([]string{"--name", "frank", "--expires", "2027-01-31T00:00:00Z"})
		if err := c.Execute(); err != nil {
			t.Fatal(err)
		}
	})
	var password, line string
	for _, l := range strings.Split(strings.TrimSpace(out), "\n") {
		if p, ok := strings.CutPrefix(l, "password: "); ok {
			password = p
		} else {
			line = l
		}
	}
	fields := strings.Fields(line)
	if len(fields) != 5 || fields[0] != "user" || fields[1] != "frank" || fields[3] != "expires" {
		t.Fatalf("unexpected output %q", out)
	}
	h, err := parsePasswordHash(fields[2])
	if _, fast := h.(*pbkdf2Hash); err != nil || !fast || !h.verify([]byte(password)) {
		t.Fatalf("generated password hash %q: %v", fields[2], err)
	}
	c := passwdCommand()
	c.SetArgs([]string{"--name", "frank", "--fast-hash"})
	c.SilenceUsage, c.SilenceErrors = true, true
	if err := c.Execute(); err == nil {
		t.Error("--fast-hash without --stdin accepted")
	}
}

// captureStdout returns what f prints to standard output.
func captureStdout(t *testing.T, f func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stdout
	os.Stdout = w
	done := make(chan string)
	go func() {
		b, _ := io.ReadAll(r)
		done <- string(b)
	}()
	defer func() { os.Stdout = old }()
	f()
	w.Close()
	os.Stdout = old
	return <-done
}
