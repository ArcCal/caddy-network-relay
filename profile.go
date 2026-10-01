package networkrelay

import (
	"crypto/rand"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"
)

// identifierPrefix starts the PayloadIdentifier. Installing a profile with
// the same identifier replaces the old one, so the identifier is built only
// from the relay's host and the user name.
const identifierPrefix = "com.github.arccal.network-relay"

// Profile describes a configuration profile (.mobileconfig) with a
// com.apple.relay.managed payload for iOS/iPadOS 17+, macOS 14+.
type Profile struct {
	Host     string
	Port     int // 443 when 0
	User     string
	Password string
	// UDPTemplate is the path of the CONNECT-UDP URI template; the
	// default one when empty.
	UDPTemplate string
	// Domains (with their subdomains) that use the relay. When both these
	// and MatchFQDNs are empty, all traffic uses the relay.
	MatchDomains    []string
	ExcludedDomains []string
	// Exact host names (iOS 18.4, macOS 15.4 and later).
	MatchFQDNs    []string
	ExcludedFQDNs []string
	// UIToggleEnabled lets the user turn the relay off in Settings (iOS
	// and macOS 26; the system default is true). Nil leaves it out.
	UIToggleEnabled *bool
	// AllowDNSFailover lets the device fall back to the default DNS
	// resolver (iOS and macOS 26; the system default is false).
	AllowDNSFailover *bool
	// RelayUUID for managed-app routing; required by user enrollment.
	RelayUUID string
	// Name shown in Settings; the host when empty.
	Name string
	// Which relay URLs to include; both when both are false.
	NoHTTP3, NoHTTP2 bool
}

// RelayURL is the relay URL, which is the full CONNECT-UDP URI template.
func (p *Profile) RelayURL() string {
	port := ""
	if p.Port != 0 && p.Port != 443 {
		port = ":" + strconv.Itoa(p.Port)
	}
	tmpl := p.UDPTemplate
	if tmpl == "" {
		tmpl = DefaultUDPTemplate
	}
	return "https://" + strings.ToLower(p.Host) + port + tmpl
}

func xmlEscape(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;", "'", "&apos;").Replace(s)
}

func newUUID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	h := fmt.Sprintf("%X", b)
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
}

func checkDomain(d string) error {
	ok := d != "" && len(d) <= 253
	for _, label := range strings.Split(d, ".") {
		if !ok {
			break
		}
		ok = label != "" && len(label) <= 63 && label[0] != '-' && label[len(label)-1] != '-'
		for i := 0; ok && i < len(label); i++ {
			c := label[i]
			ok = 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9' || c == '-'
		}
	}
	if !ok {
		return fmt.Errorf("%q is not a domain name", d)
	}
	return nil
}

func normalizeDomain(d string) string { return strings.ToLower(strings.TrimSuffix(d, ".")) }

func isUUID(s string) bool {
	groups := strings.Split(s, "-")
	if len(groups) != 5 {
		return false
	}
	for i, n := range []int{8, 4, 4, 4, 12} {
		if len(groups[i]) != n || strings.Trim(groups[i], "0123456789abcdefABCDEF") != "" {
			return false
		}
	}
	return true
}

func xmlSafe(s string) bool {
	if !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if r < ' ' && r != '\t' && r != '\n' && r != '\r' || r == 0xFFFE || r == 0xFFFF {
			return false
		}
	}
	return true
}

// Generate returns the profile as XML.
func (p *Profile) Generate() (string, error) {
	if p.NoHTTP3 && p.NoHTTP2 {
		return "", errors.New("the profile needs HTTP/3, HTTP/2 or both")
	}
	if p.Port < 0 || p.Port > 65535 {
		return "", errors.New("the relay port must be between 1 and 65535")
	}
	if err := validateUserName(p.User); err != nil {
		return "", err
	}
	if strings.ContainsAny(p.Password, "\r\n") || !utf8.ValidString(p.Password) {
		return "", errors.New("the password contains characters that cannot be sent in a header")
	}
	if err := checkDomain(p.Host); err != nil {
		return "", err
	}
	for _, list := range [][]string{p.MatchDomains, p.ExcludedDomains, p.MatchFQDNs, p.ExcludedFQDNs} {
		for _, d := range list {
			if err := checkDomain(strings.TrimSuffix(d, ".")); err != nil {
				return "", err
			}
		}
	}
	if p.RelayUUID != "" && !isUUID(p.RelayUUID) {
		return "", errors.New("the relay UUID must be a UUID")
	}
	if !xmlSafe(p.Name) || !xmlSafe(p.Password) {
		return "", errors.New("the profile contains a character XML cannot represent")
	}
	tmpl := p.UDPTemplate
	if tmpl == "" {
		tmpl = DefaultUDPTemplate
	}
	if _, err := parseUDPTemplate(tmpl); err != nil {
		return "", err
	}
	host := strings.ToLower(p.Host)
	name := p.Name
	if name == "" {
		name = host
	}
	id := identifierPrefix + "." + host + "." + p.User
	scope := "all of this device's traffic"
	if matches := append(append([]string{}, p.MatchDomains...), p.MatchFQDNs...); len(matches) > 0 {
		for i := range matches {
			matches[i] = normalizeDomain(matches[i])
		}
		scope = "this device's traffic to " + strings.Join(matches, ", ")
	}
	description := fmt.Sprintf("Sends %s through the relay %s as user %s.", scope, host, p.User)

	url := xmlEscape(p.RelayURL())
	var b strings.Builder
	w := func(format string, args ...any) { fmt.Fprintf(&b, format, args...) }
	w(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>PayloadContent</key>
  <array>
    <dict>
      <key>PayloadType</key>
      <string>com.apple.relay.managed</string>
      <key>PayloadVersion</key>
      <integer>1</integer>
      <key>PayloadIdentifier</key>
      <string>%s.relay</string>
      <key>PayloadUUID</key>
      <string>%s</string>
      <key>PayloadDisplayName</key>
      <string>%s</string>
      <key>Relays</key>
      <array>
        <dict>
`, xmlEscape(id), newUUID(), xmlEscape(name))
	if !p.NoHTTP3 {
		w("          <key>HTTP3RelayURL</key>\n          <string>%s</string>\n", url)
	}
	if !p.NoHTTP2 {
		w("          <key>HTTP2RelayURL</key>\n          <string>%s</string>\n", url)
	}
	w(`          <key>AdditionalHTTPHeaderFields</key>
          <dict>
            <key>Authorization</key>
            <string>%s</string>
          </dict>
        </dict>
      </array>
`, xmlEscape(BasicAuthorization(p.User, p.Password)))
	for _, list := range []struct {
		key    string
		values []string
	}{{"MatchDomains", p.MatchDomains}, {"ExcludedDomains", p.ExcludedDomains},
		{"MatchFQDNs", p.MatchFQDNs}, {"ExcludedFQDNs", p.ExcludedFQDNs}} {
		if len(list.values) == 0 {
			continue
		}
		w("      <key>%s</key>\n      <array>\n", list.key)
		for _, v := range list.values {
			w("        <string>%s</string>\n", xmlEscape(normalizeDomain(v)))
		}
		w("      </array>\n")
	}
	for _, c := range []struct {
		key   string
		value *bool
	}{{"UIToggleEnabled", p.UIToggleEnabled}, {"AllowDNSFailover", p.AllowDNSFailover}} {
		if c.value != nil {
			w("      <key>%s</key>\n      <%t/>\n", c.key, *c.value)
		}
	}
	if p.RelayUUID != "" {
		w("      <key>RelayUUID</key>\n      <string>%s</string>\n", strings.ToUpper(p.RelayUUID))
	}
	w(`    </dict>
  </array>
  <key>PayloadDisplayName</key>
  <string>%s</string>
  <key>PayloadDescription</key>
  <string>%s</string>
  <key>PayloadIdentifier</key>
  <string>%s</string>
  <key>PayloadType</key>
  <string>Configuration</string>
  <key>PayloadUUID</key>
  <string>%s</string>
  <key>PayloadVersion</key>
  <integer>1</integer>
</dict>
</plist>
`, xmlEscape(name), xmlEscape(description), xmlEscape(id), newUUID())
	return b.String(), nil
}
