package networkrelay

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/quic-go/quic-go/quicvarint"
	"golang.org/x/crypto/bcrypt"
)

func TestTemplates(t *testing.T) {
	tm, err := parseUDPTemplate(DefaultUDPTemplate)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct{ path, host, port string }{
		{"/.well-known/masque/udp/192.0.2.6/443/", "192.0.2.6", "443"},
		{"/.well-known/masque/udp/2001%3Adb8%3A%3A42/53/", "2001:db8::42", "53"},
		{"/.well-known/masque/udp/2001:db8::42/53/", "2001:db8::42", "53"}, // lenient: ':' unencoded
		{"/.well-known/masque/udp/dns.example/53/", "dns.example", "53"},
	} {
		host, port, ok := tm.Match(c.path)
		if !ok || host != c.host || port != c.port {
			t.Errorf("%s: got %q %q %v", c.path, host, port, ok)
		}
	}
	for _, bad := range []string{
		"/.well-known/masque/udp/192.0.2.6/443", "/.well-known/masque/udp//443/",
		"/.well-known/masque/udp/a/b/443/", "/other/192.0.2.6/443/", "/.well-known/masque/udp/192.0.2.6/443/?x",
	} {
		if _, _, ok := tm.Match(bad); ok {
			t.Errorf("%s matched", bad)
		}
	}
	if got := tm.Expand("2001:db8::1", "443"); got != "/.well-known/masque/udp/2001%3Adb8%3A%3A1/443/" {
		t.Errorf("expand: %s", got)
	}

	q, err := parseUDPTemplate("/masque{?target_host,target_port}")
	if err != nil {
		t.Fatal(err)
	}
	if h, p, ok := q.Match("/masque?target_host=192.0.2.1&target_port=53"); !ok || h != "192.0.2.1" || p != "53" {
		t.Errorf("query template: %q %q %v", h, p, ok)
	}
	if _, err := parseUDPTemplate("/x?h={target_host}{&target_port}"); err != nil {
		t.Errorf("query continuation: %v", err)
	}
	for _, bad := range []string{
		"no-slash/{target_host}/{target_port}", "/{target_host}{target_port}", "/{target_host}/",
		"/{target_host}/{target_port}/{other}", "/{+target_host}/{target_port}", "/{target_host}/{target_port",
		"/{target_host}/{target_host}/{target_port}", "/{&target_host,target_port}",
	} {
		if _, err := parseUDPTemplate(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestTargets(t *testing.T) {
	good := map[string]target{
		"example.com:443":       {"example.com", 443},
		"Example.COM.:80":       {"example.com", 80},
		"192.0.2.1:8443":        {"192.0.2.1", 8443},
		"[2001:db8::1]:443":     {"2001:db8::1", 443},
		"_srv.example.com:5060": {"_srv.example.com", 5060},
	}
	for in, want := range good {
		if got, ok := parseAuthority(in); !ok || got != want {
			t.Errorf("%s: %v %v", in, got, ok)
		}
	}
	for _, bad := range []string{
		"example.com", "example.com:", "example.com:0", "example.com:65536", "example.com:+443",
		"example.com:44a", "2001:db8::1:443", "[2001:db8::1]", "[example.com]:443", "[2001:db8::1]443",
		":443", "exa mple.com:443", "-bad.example:443", "a..b:443", "user@example.com:443",
		"[fe80::1%eth0]:443", "[192.0.2.1]:443",
	} {
		if _, ok := parseAuthority(bad); ok {
			t.Errorf("%s accepted", bad)
		}
	}
	if _, ok := newTarget("[2001:db8::42]", "53"); ok {
		t.Error("brackets accepted in target_host")
	}
	if got := (target{"2001:db8::1", 443}).String(); got != "[2001:db8::1]:443" {
		t.Error(got)
	}
}

type fakeResolver map[string][]netip.Addr

func (f fakeResolver) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	if host == "slow.example" {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	addrs, ok := f[host]
	if !ok {
		return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
	}
	return addrs, nil
}

func TestPolicy(t *testing.T) {
	p, err := newPolicy(DefaultBlockedDestinations, DefaultBlockedPorts)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{"127.0.0.1", "10.1.2.3", "::1", "::ffff:127.0.0.1", "::ffff:10.0.0.1", "fd00::1", "fe80::1", "169.254.169.254", "100.64.0.1"} {
		if p.allows(netip.MustParseAddr(s)) {
			t.Errorf("%s allowed", s)
		}
	}
	for _, s := range []string{"1.1.1.1", "2606:4700:4700::1111", "::ffff:1.1.1.1"} {
		if !p.allows(netip.MustParseAddr(s)) {
			t.Errorf("%s blocked", s)
		}
	}
	// The IPv4 rule applies to mapped addresses even with the mapped
	// range unblocked.
	only, _ := newPolicy([]string{"127.0.0.0/8"}, nil)
	if only.allows(netip.MustParseAddr("::ffff:127.0.0.1")) {
		t.Error("mapped loopback allowed")
	}

	p.resolver = fakeResolver{
		"rebind.example": {netip.MustParseAddr("127.0.0.1")},
		"mixed.example":  {netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("93.184.216.34"), netip.MustParseAddr("::ffff:93.184.216.34")},
	}
	ctx := context.Background()
	check := func(host string, port uint16, want *refusal) {
		t.Helper()
		_, err := p.resolve(ctx, target{host, port})
		var r *refusal
		if want == nil {
			if err != nil {
				t.Errorf("%s:%d: %v", host, port, err)
			}
			return
		}
		if !errors.As(err, &r) || r.errorType != want.errorType {
			t.Errorf("%s:%d: got %v, want %s", host, port, err, want.errorType)
		}
	}
	check("192.0.2.1", 25, refusePort)
	check("127.0.0.1", 80, refuseAddress)
	check("rebind.example", 80, refuseAddress)
	check("unknown.example", 80, refuseDNS(errors.New("")))
	check("slow.example", 80, refuseDNSTimeout)
	got, err := p.resolve(ctx, target{"mixed.example", 80})
	if err != nil || len(got) != 1 || got[0].String() != "93.184.216.34:80" {
		t.Errorf("mixed: %v %v", got, err)
	}
	if _, err := newPolicy([]string{"10.0.0.1/8"}, nil); err == nil {
		t.Error("host bits accepted")
	}
	if _, err := newPolicy(nil, []int{70000}); err == nil {
		t.Error("bad port accepted")
	}
	if p2, err := newPolicy([]string{"192.0.2.7"}, nil); err != nil || p2.allows(netip.MustParseAddr("192.0.2.7")) {
		t.Error("single address not blocked")
	}
}

func TestInterleave(t *testing.T) {
	a := func(s string) netip.AddrPort { return netip.MustParseAddrPort(s) }
	v6 := []netip.AddrPort{a("[2001:db8::1]:1"), a("[2001:db8::2]:1")}
	v4 := []netip.AddrPort{a("192.0.2.1:1"), a("192.0.2.2:1"), a("192.0.2.3:1")}
	got := interleave([]netip.AddrPort{v6[0], v6[1], v4[0], v4[1], v4[2]})
	want := []netip.AddrPort{v6[0], v4[0], v6[1], v4[1], v4[2]}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v", got)
		}
	}
}

func TestDialTCP(t *testing.T) {
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	defer l.Close()
	good := netip.MustParseAddrPort(l.Addr().String())
	cl, _ := net.Listen("tcp", "127.0.0.1:0")
	closed := netip.MustParseAddrPort(cl.Addr().String())
	cl.Close()
	c, err := dialTCP(context.Background(), []netip.AddrPort{closed, good}, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	if _, err := dialTCP(context.Background(), []netip.AddrPort{closed}, 5*time.Second); dialRefusal(err) != refuseRefused {
		t.Fatalf("closed port: %v", err)
	}
	start := time.Now()
	_, err = dialTCP(context.Background(), []netip.AddrPort{netip.MustParseAddrPort("192.0.2.1:9"), netip.MustParseAddrPort("192.0.2.2:9")}, 300*time.Millisecond)
	if err == nil || time.Since(start) > 2*time.Second {
		t.Fatalf("deadline: %v after %v", err, time.Since(start))
	}
}

// A hash made by the Rust network-relay (argon2 crate) must keep working.
func TestPasswordHashes(t *testing.T) {
	h, err := parsePasswordHash(HashPassword("secret password"))
	if err != nil || !h.verify([]byte("secret password")) || h.verify([]byte("wrong")) {
		t.Fatal("argon2id round trip", err)
	}
	// From `network-relay passwd` (Rust argon2 crate), password "password-from-rust".
	rust := "$argon2id$v=19$m=19456,t=2,p=1$ISwbUozmbqzGVCuWFmY3vw$TZUMO53leFEfvemdM2eykaQlUqtYn9USK4r4pWiS/JQ"
	if h, err := parsePasswordHash(rust); err != nil || !h.verify([]byte("password-from-rust")) {
		t.Fatal("Rust-format hash", err)
	}
	b, _ := bcrypt.GenerateFromPassword([]byte("bcrypt pw"), bcrypt.MinCost)
	if h, err := parsePasswordHash(string(b)); err != nil || !h.verify([]byte("bcrypt pw")) {
		t.Fatal("bcrypt", err)
	}
	if h, err := parsePasswordHash(base64.StdEncoding.EncodeToString(b)); err != nil || !h.verify([]byte("bcrypt pw")) {
		t.Fatal("base64 bcrypt (caddy hash-password)", err)
	}
	for _, bad := range []string{"", "plain", "$argon2i$v=19$m=19456,t=2,p=1$c2FsdHNhbHQ$aGFzaGhhc2hoYXNoaGFzaA",
		"$argon2id$v=16$m=19456,t=2,p=1$c2FsdHNhbHQ$aGFzaGhhc2hoYXNoaGFzaA",
		"$argon2id$v=19$m=19456,t=0,p=1$c2FsdHNhbHQ$aGFzaGhhc2hoYXNoaGFzaA",
		"$argon2id$v=19$m=999999999,t=2,p=1$c2FsdHNhbHQ$aGFzaGhhc2hoYXNoaGFzaA",
		"$argon2id$v=19$m=19456,t=2,p=1,x=1$c2FsdHNhbHQ$aGFzaGhhc2hoYXNoaGFzaA"} {
		if _, err := parsePasswordHash(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestAuthenticator(t *testing.T) {
	a, err := newAuthenticator([]User{{"alice", testHash}})
	if err != nil {
		t.Fatal(err)
	}
	good := BasicAuthorization("alice", testPassword)
	if acct, ok := a.verify(good); !ok || acct.name != "alice" || !a.has(acct) {
		t.Fatal("good credentials rejected")
	}
	if _, ok := a.verify("basic " + strings.TrimPrefix(good, "Basic ")); !ok {
		t.Fatal("scheme is case-insensitive")
	}
	for _, bad := range []string{"", BasicAuthorization("alice", "nope"), BasicAuthorization("bob", testPassword), "Bearer abc", "Basic !!!"} {
		if _, ok := a.verify(bad); ok {
			t.Errorf("%q accepted", bad)
		}
	}
	// Cached: the second check is fast.
	start := time.Now()
	for i := 0; i < 100; i++ {
		a.verify(good)
	}
	if time.Since(start) > 50*time.Millisecond {
		t.Errorf("cache not used: %v", time.Since(start))
	}
	// Failures never evict successes from a full cache.
	for i := 0; i < maxCacheItems+10; i++ {
		var id [32]byte
		copy(id[:], []byte{byte(i), byte(i >> 8), byte(i >> 16), 1})
		a.mu.Lock()
		a.remember(id, account{}, false)
		a.mu.Unlock()
	}
	a.mu.Lock()
	oks := 0
	for _, e := range a.cache {
		if e.ok {
			oks++
		}
	}
	a.mu.Unlock()
	if oks != 2 { // "Basic" and "basic" are different headers
		t.Errorf("success entries: %d", oks)
	}
	if _, err := newAuthenticator([]User{{"a", testHash}, {"a", testHash}}); err == nil {
		t.Error("duplicate user accepted")
	}
	if _, err := newAuthenticator([]User{{".x", testHash}}); err == nil {
		t.Error("bad user name accepted")
	}
}

func capsule(typ uint64, value []byte) []byte {
	b := quicvarint.Append(nil, typ)
	b = quicvarint.Append(b, uint64(len(value)))
	return append(b, value...)
}

func TestCapsules(t *testing.T) {
	var stream []byte
	stream = append(stream, capsule(0x1234, bytes.Repeat([]byte{1}, 100000))...) // unknown, large: skipped
	stream = appendDatagramCapsule(stream, []byte("one"))
	stream = append(stream, capsule(0, append(quicvarint.Append(nil, 5), "other context"...))...) // skipped
	stream = appendDatagramCapsule(stream, nil)                                                   // empty payload
	stream = appendDatagramCapsule(stream, bytes.Repeat([]byte{2}, maxUDPPayload))
	var got [][]byte
	err := readCapsules(bytes.NewReader(stream), func(p []byte) { got = append(got, append([]byte(nil), p...)) })
	if err != nil || len(got) != 3 || string(got[0]) != "one" || len(got[1]) != 0 || len(got[2]) != maxUDPPayload {
		t.Fatalf("err %v, %d payloads", err, len(got))
	}
	malformed := [][]byte{
		appendDatagramCapsule(nil, []byte("truncated"))[:5],
		capsule(0, nil), // no context ID
		capsule(0, append([]byte{0}, make([]byte, maxUDPPayload+1)...)),
		{0x40}, // truncated type
	}
	for i, m := range malformed {
		if err := readCapsules(bytes.NewReader(m), func([]byte) {}); !errors.Is(err, errMalformed) {
			t.Errorf("case %d: %v", i, err)
		}
	}
	// The size limit is checked from the declared length, before reading.
	huge := quicvarint.Append(quicvarint.Append(nil, 0), 1<<40)
	if err := readCapsules(io.MultiReader(bytes.NewReader(append(huge, 0)), neverEnding{}), func([]byte) {}); !errors.Is(err, errMalformed) {
		t.Errorf("huge: %v", err)
	}
}

type neverEnding struct{}

func (neverEnding) Read(p []byte) (int, error) { return len(p), nil }

func TestProfile(t *testing.T) {
	no := false
	p := Profile{Host: "Relay.Example.com", User: "iphone", Password: "p&ss<word>",
		MatchDomains: []string{"IfConfig.me."}, UIToggleEnabled: &no, RelayUUID: "00112233-4455-6677-8899-aabbccddeeff"}
	x, err := p.Generate()
	if err != nil {
		t.Fatal(err)
	}
	url := "https://relay.example.com/.well-known/masque/udp/{target_host}/{target_port}/"
	for _, want := range []string{
		"<string>com.apple.relay.managed</string>",
		"<key>HTTP3RelayURL</key>\n          <string>" + url + "</string>",
		"<key>HTTP2RelayURL</key>\n          <string>" + url + "</string>",
		"<string>" + xmlEscape(BasicAuthorization("iphone", "p&ss<word>")) + "</string>",
		"<key>MatchDomains</key>\n      <array>\n        <string>ifconfig.me</string>",
		"<key>UIToggleEnabled</key>\n      <false/>",
		"<string>00112233-4455-6677-8899-AABBCCDDEEFF</string>",
		"<string>com.github.arccal.network-relay.relay.example.com.iphone</string>",
	} {
		if !strings.Contains(x, want) {
			t.Errorf("missing %q", want)
		}
	}
	if strings.Contains(x, "ExcludedDomains") || strings.Contains(x, "AllowDNSFailover") || strings.Contains(x, "p&ss") {
		t.Error("unexpected content")
	}
	for _, tag := range []string{"dict", "array", "plist"} {
		if strings.Count(x, "<"+tag) != strings.Count(x, "</"+tag+">") {
			t.Errorf("unbalanced %s", tag)
		}
	}
	p.Port = 8443
	p.NoHTTP2 = true
	x, _ = p.Generate()
	if strings.Contains(x, "HTTP2RelayURL") || !strings.Contains(x, "relay.example.com:8443/") {
		t.Error("port / no-http2")
	}
	for _, bad := range []Profile{
		{Host: "relay.example.com", User: "a b", Password: "x"},
		{Host: "relay_example", User: "a", Password: "x"},
		{Host: "relay.example.com", User: "a", Password: "x", NoHTTP2: true, NoHTTP3: true},
		{Host: "relay.example.com", User: "a", Password: "x", MatchDomains: []string{"*.example.com"}},
		{Host: "relay.example.com", User: "a", Password: "x", RelayUUID: "nope"},
		{Host: "relay.example.com", User: "a", Password: "x\x01"},
		{Host: "relay.example.com", User: "a", Password: "x", UDPTemplate: "/{target_host}"},
	} {
		if _, err := bad.Generate(); err == nil {
			t.Errorf("%+v accepted", bad)
		}
	}
}

func TestDomainLists(t *testing.T) {
	got := parseDomainList("# comment\nExample.com\nexample.com # dup\n1.2.3.4\nlocalhost\nbad_label.com\nsub.example.org.\n")
	if strings.Join(got, ",") != "example.com,sub.example.org" {
		t.Errorf("list: %v", got)
	}
	plain := "[AutoProxy 0.2.9]\n! comment\n||google.com\n|https://www.nytimes.com/section\n.wikipedia.org\n@@||cn.example.com\n/^https?:\\/\\/x/\n||1.2.3.4\nexample.net\n"
	enc := base64.StdEncoding.EncodeToString([]byte(plain))
	text, err := decodeGFWList([]byte(enc[:20] + "\n" + enc[20:]))
	if err != nil || text != plain {
		t.Fatalf("decode: %v", err)
	}
	hosts, stats := extractGFWList(text)
	if strings.Join(hosts, ",") != "example.net,google.com,wikipedia.org,www.nytimes.com" {
		t.Errorf("hosts: %v", hosts)
	}
	if stats["exception rules ignored"] != 1 || stats["regular expressions dropped"] != 1 ||
		stats["IP addresses and other patterns dropped"] != 1 || stats["path-limited rules widened to their domain"] != 1 {
		t.Errorf("stats: %v", stats)
	}
	if got := collapseDomains([]string{"a.example.com", "example.com", "b.c.example.org", "c.example.org", "x.org"}); strings.Join(got, ",") != "c.example.org,example.com,x.org" {
		t.Errorf("collapse: %v", got)
	}
}
