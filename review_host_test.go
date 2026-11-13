package networkrelay

import (
	"bufio"
	"fmt"
	"io"
	"net/http"
	"testing"

	"golang.org/x/net/http/httpguts"
	"golang.org/x/net/http2"
)

// RFC 9112 section 3.2 requires 400 for an invalid Host field value.
func TestHTTP1HostSyntax(t *testing.T) {
	port, _ := startRelay(t, nil, nil)
	for _, host := range []string{"user@relay.test", "relay.test:abc", "[not-ipv6]"} {
		t.Run(host, func(t *testing.T) {
			conn := tlsDial(t, port, "http/1.1")
			defer conn.Close()
			if _, err := io.WriteString(conn, fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", host)); err != nil {
				t.Fatal(err)
			}
			rsp, err := http.ReadResponse(bufio.NewReader(conn), nil)
			if err != nil {
				t.Fatal(err)
			}
			defer rsp.Body.Close()
			if rsp.StatusCode != http.StatusBadRequest {
				t.Fatalf("invalid Host %q got %d, want 400", host, rsp.StatusCode)
			}
		})
	}
}

// RFC 9113 sections 8.1.1/8.3.1 and RFC 9114 sections 4.1.2/4.3.1
// require malformed authority values to fail their request stream.
func TestHTTP2AndHTTP3AuthoritySyntax(t *testing.T) {
	port, _ := startRelay(t, nil, nil)
	for _, authority := range []string{"user@relay.test", "relay.test:abc", "[not-ipv6]"} {
		fields := [][2]string{{":method", "GET"}, {":scheme", "https"}, {":authority", authority}, {":path", "/"}}
		t.Run("HTTP2/"+authority, func(t *testing.T) {
			r := dialRawH2(t, port)
			defer r.conn.Close()
			r.headers(1, fields)
			for {
				f := r.next(1)
				if h, ok := f.(*http2.MetaHeadersFrame); ok && h.PseudoValue("status") != "400" {
					t.Fatalf("invalid authority got status %s", h.PseudoValue("status"))
				}
				if rst, ok := f.(*http2.RSTStreamFrame); ok {
					if rst.ErrCode != http2.ErrCodeProtocol {
						t.Fatalf("invalid authority got reset %s", rst.ErrCode)
					}
					return
				}
			}
		})
		for _, fin := range []bool{false, true} {
			t.Run(fmt.Sprintf("HTTP3/%s/FIN=%v", authority, fin), func(t *testing.T) {
				expectMalformedH3(t, dialRawH3(t, port), fields, fin)
			})
		}
	}
}

func TestRequestAuthorityContext(t *testing.T) {
	for _, tc := range []struct {
		value, scheme  string
		classic, valid bool
	}{
		{"relay.test", "https", false, true},
		{"relay.test:", "http", false, true},
		{"relay.test:0", "", true, true},
		{"relay.test:443", "", true, true},
		{"[::1]:443", "", true, true},
		{"relay.test", "", true, false},
		{"relay.test:", "", true, false},
		{"[::1]", "", true, false},
		{"[::1]:", "", true, false},
		{":443", "https", false, false},
		{":443", "http", false, false},
		{"", "https", false, false},
		{"user@relay.test", "https", false, false},
		{"user:pass%40word@relay.test", "ftp", false, true},
		{"user@relay.test:abc", "ftp", false, false},
		{"user@[not-ipv6]", "ftp", false, false},
		{"user%zz@relay.test", "ftp", false, false},
		{"user@@relay.test", "ftp", false, false},
	} {
		if got := httpguts.ValidRequestAuthority(tc.value, tc.scheme, tc.classic); got != tc.valid {
			t.Errorf("authority=%q scheme=%q classic=%v: valid=%v, want %v", tc.value, tc.scheme, tc.classic, got, tc.valid)
		}
	}
}

func TestHTTP2AndHTTP3AuthorityContext(t *testing.T) {
	port, _ := startRelay(t, nil, nil)
	cases := []struct {
		name   string
		fields [][2]string
	}{}
	for _, authority := range []string{"relay.test", "relay.test:", ":443", "[::1]", "[::1]:"} {
		cases = append(cases, struct {
			name   string
			fields [][2]string
		}{"CONNECT/" + authority, connectTCPFields(authority)})
	}
	for _, field := range []string{":scheme", ":path", ":protocol"} {
		cases = append(cases, struct {
			name   string
			fields [][2]string
		}{"CONNECT/empty-" + field, [][2]string{{":method", "CONNECT"}, {":authority", "relay.test:443"}, {field, ""}}})
	}
	for _, protocol := range []string{"", " ", "invalid/proto", "\u00e9proto"} {
		cases = append(cases, struct {
			name   string
			fields [][2]string
		}{"CONNECT/bad-protocol/" + protocol, [][2]string{{":method", "CONNECT"}, {":protocol", protocol}, {":scheme", "https"}, {":authority", "relay.test"}, {":path", "/"}}})
	}
	cases = append(cases, struct {
		name   string
		fields [][2]string
	}{"GET/empty-protocol", [][2]string{{":method", "GET"}, {":scheme", "https"}, {":authority", "relay.test"}, {":path", "/"}, {":protocol", ""}}})
	cases = append(cases, struct {
		name   string
		fields [][2]string
	}{"GET/empty-authority-with-host", [][2]string{{":method", "GET"}, {":scheme", "https"}, {":authority", ""}, {":path", "/"}, {"host", "relay.test"}}})
	for _, scheme := range []string{"http", "https"} {
		cases = append(cases, struct {
			name   string
			fields [][2]string
		}{scheme + "/empty-host", [][2]string{{":method", "GET"}, {":scheme", scheme}, {":authority", ":443"}, {":path", "/"}}})
	}
	for _, authority := range []string{"user@relay.test:abc", "user@[not-ipv6]", "user%zz@relay.test", "user@@relay.test"} {
		cases = append(cases, struct {
			name   string
			fields [][2]string
		}{"ftp/" + authority, [][2]string{{":method", "GET"}, {":scheme", "ftp"}, {":authority", authority}, {":path", "/"}}})
	}
	for _, tc := range cases {
		t.Run("HTTP2/"+tc.name, func(t *testing.T) {
			r := dialRawH2(t, port)
			defer r.conn.Close()
			r.headers(1, tc.fields)
			for {
				f := r.next(1)
				if h, ok := f.(*http2.MetaHeadersFrame); ok && h.PseudoValue("status") != "400" {
					t.Fatalf("invalid authority got %s", h.PseudoValue("status"))
				}
				if rst, ok := f.(*http2.RSTStreamFrame); ok {
					if rst.ErrCode != http2.ErrCodeProtocol {
						t.Fatalf("reset=%s", rst.ErrCode)
					}
					return
				}
			}
		})
		for _, fin := range []bool{false, true} {
			t.Run(fmt.Sprintf("HTTP3/%s/FIN=%v", tc.name, fin), func(t *testing.T) { expectMalformedH3(t, dialRawH3(t, port), tc.fields, fin) })
		}
	}
}

func TestHTTP2AuthorityFallbackAndSchemeCase(t *testing.T) {
	port, _ := startRelay(t, nil, nil)
	for _, fields := range [][][2]string{
		{{":method", "GET"}, {":scheme", "https"}, {":path", "/"}, {"host", "relay.test"}},
		{{":method", "GET"}, {":scheme", "HTTPS"}, {":authority", "relay.test"}, {":path", "/"}},
	} {
		r := dialRawH2(t, port)
		r.headers(1, fields)
		frame := r.next(1)
		h, ok := frame.(*http2.MetaHeadersFrame)
		if !ok || h.PseudoValue("status") != "200" {
			t.Fatalf("valid request got %T %#v", frame, frame)
		}
		r.conn.Close()
	}
}

func TestHTTP1RejectsEmptyAbsoluteHost(t *testing.T) {
	port, _ := startRelay(t, nil, nil)
	for _, scheme := range []string{"http", "https"} {
		conn := tlsDial(t, port, "http/1.1")
		_, err := fmt.Fprintf(conn, "GET %s://:443/ HTTP/1.1\r\nHost: relay.test\r\nConnection: close\r\n\r\n", scheme)
		if err != nil {
			t.Fatal(err)
		}
		rsp, err := http.ReadResponse(bufio.NewReader(conn), nil)
		if err != nil {
			t.Fatal(err)
		}
		rsp.Body.Close()
		conn.Close()
		if rsp.StatusCode != 400 {
			t.Fatalf("empty absolute host got %d", rsp.StatusCode)
		}
	}
}

func TestHostFieldGrammar(t *testing.T) {
	for _, value := range []string{
		"", ":", "relay.test", "relay.test:", "relay.test:443", "relay.test:999999",
		"192.0.2.1", "[::1]", "[::1]:", "[2001:db8::1]:443", "[::ffff:192.0.2.1]",
		"[v1.a:b]", "[VfF.test!$&'()*+,;=]:443", "a%20b.test", "!$&'()*+,;=.test",
	} {
		if !validHostField(value) {
			t.Errorf("valid Host rejected: %q", value)
		}
	}
	for _, value := range []string{
		"user@relay.test", "relay.test:abc", "relay.test:-1", "relay.test:443:80",
		"[not-ipv6]", "[192.0.2.1]", "[::1", "[::1]junk", "[::1]:abc", "[fe80::1%eth0]",
		"[v.a]", "[v1.]", "[vg.a]", "[v1.a%20b]", "a%b", "a%2g", "a%2", "a/b", "a?b", "a#b",
	} {
		if validHostField(value) {
			t.Errorf("invalid Host accepted: %q", value)
		}
	}
}

func TestOtherSchemeAuthorityGrammar(t *testing.T) {
	for _, value := range []string{"relay.test:21", "user:password@relay.test:21", "user%40id@relay.test", "@relay.test"} {
		if !validAuthority(value, true) {
			t.Errorf("valid non-HTTP authority rejected: %q", value)
		}
	}
	for _, value := range []string{"user@@relay.test", "user/name@relay.test", "user%GG@relay.test", "user@relay.test:abc", "user@[not-ipv6]"} {
		if validAuthority(value, true) {
			t.Errorf("invalid non-HTTP authority accepted: %q", value)
		}
	}
	if validAuthority("user@relay.test", false) {
		t.Error("HTTP authority accepted userinfo")
	}
}

func TestHTTP3OtherSchemeUserinfo(t *testing.T) {
	port, _ := startRelay(t, nil, nil)
	h := dialRawH3(t, port)
	str, br, rsp := h.request([][2]string{{":method", "GET"}, {":scheme", "ftp"}, {":authority", "user@relay.test"}, {":path", "/"}})
	defer str.Close()
	// Caddy's existing Host policy refuses this valid non-HTTP authority
	// with an ordinary 400. It must not become an H3_MESSAGE_ERROR reset.
	if rsp.status != "400" {
		t.Fatalf("valid non-HTTP authority got %s", rsp.status)
	}
	if _, err := io.ReadAll(br); err != nil {
		t.Fatalf("valid non-HTTP authority was reset: %v", err)
	}
}

func TestHTTP3RequestSchemeSyntax(t *testing.T) {
	port, _ := startRelay(t, nil, nil)
	for _, scheme := range []string{"missing", "", "1https", "https:", "ht tp", "https/", "\u212Ahttps", "\u0130https"} {
		fields := [][2]string{{":method", "GET"}, {":authority", "relay.test"}, {":path", "/"}}
		if scheme != "missing" {
			fields = append(fields, [2]string{":scheme", scheme})
		}
		for _, fin := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/FIN=%v", scheme, fin), func(t *testing.T) {
				expectMalformedH3(t, dialRawH3(t, port), fields, fin)
			})
		}
	}
}

func BenchmarkHostFieldValidation(b *testing.B) {
	for _, value := range []string{"relay.test", "relay.test:443", "[2001:db8::1]:443", "[v1.a:b]:443", "a%20b.test"} {
		b.Run(value, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				if !validHostField(value) {
					b.Fatal("valid Host rejected")
				}
			}
		})
	}
}
