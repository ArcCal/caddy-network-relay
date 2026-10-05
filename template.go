package networkrelay

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

// DefaultUDPTemplate is the path of the default CONNECT-UDP URI template
// (RFC 9298 §3).
const DefaultUDPTemplate = "/.well-known/masque/udp/{target_host}/{target_port}/"

// uriTemplate is the path-and-query part of a CONNECT-UDP URI template
// (RFC 9298 §2, RFC 6570). It supports the expressions such templates use in
// practice: simple string expansion "{var}" and form-style query expansion
// "{?a,b}" / "{&a,b}". The only variables are target_host and target_port.
type uriTemplate struct {
	raw    string
	match  *regexp.Regexp
	groups []string // variable name of each capture group
	parts  []templatePart
}

type templatePart struct {
	literal string
	op      byte // 0 for a literal, ' ' for "{var}", '?' or '&' for queries
	vars    []string
}

var templateVars = map[string]bool{"target_host": true, "target_port": true}

func parseUDPTemplate(raw string) (*uriTemplate, error) {
	if !strings.HasPrefix(raw, "/") {
		return nil, fmt.Errorf("UDP template %q must start with /", raw)
	}
	// RFC 9298 §2: printable ASCII only. Anything else would be sent
	// percent-encoded and never match the template.
	for i := 0; i < len(raw); i++ {
		if raw[i] < 0x21 || raw[i] > 0x7e {
			return nil, fmt.Errorf("UDP template %q: only printable ASCII is allowed (percent-encode other characters)", raw)
		}
	}
	t := &uriTemplate{raw: raw}
	var pattern strings.Builder
	pattern.WriteString("^")
	seen := map[string]bool{}
	inQuery := false
	rest := raw
	for rest != "" {
		open := strings.IndexByte(rest, '{')
		if open < 0 {
			open = len(rest)
		}
		if lit := rest[:open]; lit != "" {
			// RFC 6570 §2.1 defines the literal grammar. In particular,
			// malformed percent escapes cannot be repaired by URI parsing,
			// and would make profiles point at a path this server never sees.
			for i := 0; i < len(lit); i++ {
				if strings.ContainsRune("\"'<>\\^`|}#", rune(lit[i])) {
					return nil, fmt.Errorf("UDP template %q: invalid character in %q", raw, lit)
				}
				if lit[i] == '%' {
					if i+2 >= len(lit) || !isHex(lit[i+1]) || !isHex(lit[i+2]) {
						return nil, fmt.Errorf("UDP template %q: invalid percent escape in %q", raw, lit)
					}
					i += 2
				}
			}
			if strings.Contains(lit, "?") {
				inQuery = true
			}
			t.parts = append(t.parts, templatePart{literal: lit})
			pattern.WriteString(regexp.QuoteMeta(lit))
			rest = rest[open:]
			continue
		}
		end := strings.IndexByte(rest, '}')
		if end < 0 {
			return nil, fmt.Errorf("UDP template %q: unclosed {", raw)
		}
		expr := rest[1:end]
		rest = rest[end+1:]
		if n := len(t.parts); n > 0 && t.parts[n-1].op == ' ' && (expr == "" || (expr[0] != '?' && expr[0] != '&')) {
			return nil, fmt.Errorf("UDP template %q: two variables need a separator between them", raw)
		}
		op := byte(' ')
		if expr != "" && (expr[0] == '?' || expr[0] == '&') {
			op = expr[0]
			expr = expr[1:]
		} else if expr != "" && strings.IndexByte("+#./;=,!@|", expr[0]) >= 0 {
			return nil, fmt.Errorf("UDP template %q: the {%c...} operator is not supported", raw, expr[0])
		}
		if op == '?' && inQuery {
			return nil, fmt.Errorf("UDP template %q: {?...} after the query has started", raw)
		}
		if op == '&' && !inQuery {
			return nil, fmt.Errorf("UDP template %q: {&...} needs a query before it", raw)
		}
		part := templatePart{op: op}
		for i, name := range strings.Split(expr, ",") {
			if !templateVars[name] {
				return nil, fmt.Errorf("UDP template %q: unknown variable %q (only target_host and target_port)", raw, name)
			}
			if seen[name] {
				return nil, fmt.Errorf("UDP template %q: variable %q appears twice", raw, name)
			}
			seen[name] = true
			part.vars = append(part.vars, name)
			switch op {
			case ' ':
				pattern.WriteString(`([^/?#&]+)`)
			case '?', '&':
				sep := "&"
				if i == 0 {
					sep = string(op)
				}
				pattern.WriteString(regexp.QuoteMeta(sep + name + "="))
				pattern.WriteString(`([^&#]+)`)
			}
			t.groups = append(t.groups, name)
		}
		if op == '?' {
			inQuery = true
		}
		t.parts = append(t.parts, part)
	}
	for name := range templateVars {
		if !seen[name] {
			return nil, fmt.Errorf("UDP template %q must contain {%s}", raw, name)
		}
	}
	pattern.WriteString("$")
	t.match = regexp.MustCompile(pattern.String())
	if err := t.checkRoundTrip(); err != nil {
		return nil, err
	}
	return t, nil
}

func isHex(c byte) bool {
	return '0' <= c && c <= '9' || 'a' <= c && c <= 'f' || 'A' <= c && c <= 'F'
}

// Match reports the target of a request path (with its query, if any, as
// sent on the wire). Values are percent-decoded.
func (t *uriTemplate) Match(pathAndQuery string) (host, port string, ok bool) {
	m := t.match.FindStringSubmatch(pathAndQuery)
	if m == nil {
		return "", "", false
	}
	for i, name := range t.groups {
		v, err := url.PathUnescape(m[i+1])
		if err != nil {
			return "", "", false
		}
		if name == "target_host" {
			host = v
		} else {
			port = v
		}
	}
	return host, port, true
}

// Expand fills the template in as a client does (RFC 6570 simple and
// form-style expansion: everything but unreserved characters is encoded).
func (t *uriTemplate) Expand(host, port string) string {
	values := map[string]string{"target_host": host, "target_port": port}
	var b strings.Builder
	for _, p := range t.parts {
		switch p.op {
		case 0:
			b.WriteString(p.literal)
		case ' ':
			b.WriteString(encodeUnreserved(values[p.vars[0]]))
		default:
			for i, name := range p.vars {
				if i == 0 {
					b.WriteByte(p.op)
				} else {
					b.WriteByte('&')
				}
				b.WriteString(name + "=" + encodeUnreserved(values[name]))
			}
		}
	}
	return b.String()
}

// checkRoundTrip makes sure requests built from the template lead back to
// the same target, so a template that cannot work is refused at load time.
func (t *uriTemplate) checkRoundTrip() error {
	for _, c := range [][2]string{{"example.com", "443"}, {"192.0.2.1", "53"}, {"2001:db8::1", "8443"}} {
		host, port, ok := t.Match(t.Expand(c[0], c[1]))
		if !ok || host != c[0] || port != c[1] {
			return fmt.Errorf("UDP template %q: requests built from it cannot be parsed back (try %q)", t.raw, DefaultUDPTemplate)
		}
	}
	return nil
}

func encodeUnreserved(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9' || c == '-' || c == '.' || c == '_' || c == '~' {
			b.WriteByte(c)
		} else {
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}
