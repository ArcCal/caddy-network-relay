package networkrelay

import (
	"encoding/base64"
	"net/netip"
	"regexp"
	"sort"
	"strings"
)

// GFWListURL is where `profile --gfwlist` downloads the list from.
const GFWListURL = "https://raw.githubusercontent.com/gfwlist/gfwlist/refs/heads/master/list.txt"

var dnsLabel = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// cleanHost returns a lower-case DNS name that MatchDomains accepts, or ""
// for IP addresses and anything else.
func cleanHost(host string) string {
	host = strings.Trim(strings.ToLower(strings.TrimSpace(host)), ".")
	if !strings.Contains(host, ".") || len(host) > 253 {
		return ""
	}
	if _, err := netip.ParseAddr(strings.Trim(host, "[]")); err == nil {
		return ""
	}
	labels := strings.Split(host, ".")
	for _, l := range labels {
		if !dnsLabel.MatchString(l) {
			return ""
		}
	}
	if strings.Trim(labels[len(labels)-1], "0123456789") == "" {
		return ""
	}
	return host
}

// parseDomainList reads a list with one domain per line; '#' starts a
// comment.
func parseDomainList(text string) []string {
	var out []string
	seen := map[string]bool{}
	// The caller has already read the complete, bounded input. Splitting
	// directly avoids Scanner's token limit silently discarding later routes
	// after a long comment or an unsupported rule.
	for raw := range strings.SplitSeq(text, "\n") {
		line, _, _ := strings.Cut(raw, "#")
		if h := cleanHost(line); h != "" && !seen[h] {
			seen[h] = true
			out = append(out, h)
		}
	}
	return out
}

// decodeGFWList accepts the official base64 list and the plain AutoProxy
// text some mirrors publish.
func decodeGFWList(raw []byte) (string, error) {
	text := string(raw)
	if strings.HasPrefix(strings.TrimSpace(text), "[") {
		return text, nil
	}
	clean := strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' || r == ' ' || r == '\t' {
			return -1
		}
		return r
	}, text)
	b, err := base64.StdEncoding.DecodeString(clean)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

var (
	gfwAnchored = regexp.MustCompile(`^\|\|([^/^*?:|]+)(.*)$`)
	gfwURL      = regexp.MustCompile(`^\|?https?://([^/^*?:|]+)(.*)$`)
	gfwPlain    = regexp.MustCompile(`^\.?([A-Za-z0-9.-]+)()$`)
)

// extractGFWList returns the host names of AutoProxy rules. Apple's
// MatchDomains can only hold domains: regular expressions, IP addresses and
// exception rules are dropped, and a rule limited to a URL path relays its
// whole domain. stats counts what was dropped or widened.
func extractGFWList(text string) (hosts []string, stats map[string]int) {
	stats = map[string]int{}
	set := map[string]bool{}
	for raw := range strings.SplitSeq(text, "\n") {
		line := strings.TrimSpace(raw)
		switch {
		case line == "" || line[0] == '!' || line[0] == '[':
			continue
		case strings.HasPrefix(line, "@@"):
			stats["exception rules ignored"]++
			continue
		case len(line) > 1 && line[0] == '/' && line[len(line)-1] == '/':
			stats["regular expressions dropped"]++
			continue
		}
		var m []string
		for _, re := range []*regexp.Regexp{gfwAnchored, gfwURL, gfwPlain} {
			if m = re.FindStringSubmatch(line); m != nil {
				break
			}
		}
		host := ""
		if m != nil {
			host = cleanHost(m[1])
		}
		if host == "" {
			stats["IP addresses and other patterns dropped"]++
			continue
		}
		if strings.Trim(m[2], "^/ ") != "" {
			stats["path-limited rules widened to their domain"]++
		}
		set[host] = true
	}
	for h := range set {
		hosts = append(hosts, h)
	}
	sort.Strings(hosts)
	return hosts, stats
}

// collapseDomains drops names whose parent domain is also listed (a parent
// already matches its subdomains) and sorts the rest.
func collapseDomains(domains []string) []string {
	set := map[string]bool{}
	for _, d := range domains {
		set[d] = true
	}
	var out []string
	for d := range set {
		covered := false
		labels := strings.Split(d, ".")
		for i := 1; i < len(labels)-1 && !covered; i++ {
			covered = set[strings.Join(labels[i:], ".")]
		}
		if !covered {
			out = append(out, d)
		}
	}
	sort.Strings(out)
	return out
}
