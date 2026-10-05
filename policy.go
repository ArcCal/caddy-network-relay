package networkrelay

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

// DefaultBlockedDestinations keeps clients away from the relay's own host,
// private networks, cloud metadata services, and the reserved,
// benchmarking, documentation and other ranges that the IANA
// special-purpose registries mark as not globally reachable. With the
// default list, the addresses of this host's network interfaces are blocked
// too: a connection to the host's own public address stays on the host (on
// Linux it goes over the loopback interface, which firewalls such as ufw
// let through), so it would reach services that only the firewall keeps
// from the internet. IPv6 forms that carry an IPv4 address (NAT64, 6to4,
// Teredo) are checked by the IPv4 address they carry as well.
var DefaultBlockedDestinations = []string{
	"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
	"172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24", "192.168.0.0/16", "198.18.0.0/15",
	"198.51.100.0/24", "203.0.113.0/24", "192.88.99.0/24", "224.0.0.0/4", "240.0.0.0/4",
	"::/127", "64:ff9b:1::/48", "100::/64", "100:0:0:1::/64", "2001:2::/48",
	"2001:10::/28", "2001:20::/28", "2001:db8::/32", "3fff::/20", "5f00::/16",
	"fc00::/7", "fe80::/10", "ff00::/8",
}

// DefaultBlockedPorts: 25 (mail) so the relay cannot be used to send spam.
var DefaultBlockedPorts = []int{25}

const dnsTimeout = 5 * time.Second

// target is a destination as the client named it: a DNS name or an IP
// address (IPv6 without brackets), and a port.
type target struct {
	host string
	port uint16
}

func (t target) String() string {
	return net.JoinHostPort(t.host, strconv.Itoa(int(t.port)))
}

// parseAuthority parses the authority of a classic CONNECT request,
// "host:port"; the port is required (RFC 9110 §9.3.6) and IPv6 addresses are
// in brackets.
func parseAuthority(authority string) (target, bool) {
	var host, port string
	if rest, ok := strings.CutPrefix(authority, "["); ok {
		h, after, ok := strings.Cut(rest, "]")
		if !ok {
			return target{}, false
		}
		if ip, err := netip.ParseAddr(h); err != nil || !ip.Is6() || ip.Zone() != "" {
			return target{}, false
		}
		p, ok := strings.CutPrefix(after, ":")
		if !ok {
			return target{}, false
		}
		host, port = h, p
	} else {
		i := strings.LastIndexByte(authority, ':')
		if i < 0 || strings.IndexByte(authority[:i], ':') >= 0 {
			return target{}, false
		}
		host, port = authority[:i], authority[i+1:]
	}
	return newTarget(host, port)
}

// newTarget builds a target from the target_host and target_port variables
// of a CONNECT-UDP request, already percent-decoded (RFC 9298 §2).
func newTarget(host, port string) (target, bool) {
	if port == "" || len(port) > 5 || strings.Trim(port, "0123456789") != "" {
		return target{}, false
	}
	p, err := strconv.Atoi(port)
	if err != nil || p < 1 || p > 65535 {
		return target{}, false
	}
	host = strings.TrimSuffix(host, ".")
	if ip, err := netip.ParseAddr(host); err == nil {
		if ip.Zone() != "" {
			return target{}, false
		}
	} else if !isDNSName(host) {
		return target{}, false
	}
	return target{host: strings.ToLower(host), port: uint16(p)}, true
}

func isDNSName(s string) bool {
	if s == "" || len(s) > 253 {
		return false
	}
	for _, label := range strings.Split(s, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if !('a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9' || c == '-' || c == '_') {
				return false
			}
		}
	}
	return true
}

// refusal is why a tunnel could not be opened. Each maps to a status code
// and an RFC 9209 Proxy-Status error type.
type refusal struct {
	status    int
	errorType string
	detail    string
}

func (r *refusal) Error() string { return r.detail }

func (r *refusal) proxyStatus() string { return "network-relay; error=" + r.errorType }

var (
	refuseBadTarget   = &refusal{http.StatusBadRequest, "http_request_error", "invalid target"}
	refuseRequest     = &refusal{http.StatusBadRequest, "http_request_error", "malformed request"}
	refusePort        = &refusal{http.StatusForbidden, "http_request_denied", "port blocked by blocked_ports"}
	refuseAddress     = &refusal{http.StatusForbidden, "destination_ip_prohibited", "address blocked by blocked_destinations"}
	refuseDNSTimeout  = &refusal{http.StatusGatewayTimeout, "dns_timeout", "DNS lookup timed out"}
	refuseNoAddresses = &refusal{http.StatusBadGateway, "destination_not_found", "the name has no addresses"}
	refuseRefused     = &refusal{http.StatusBadGateway, "connection_refused", "connection refused"}
	refuseTimeout     = &refusal{http.StatusGatewayTimeout, "connection_timeout", "connection timed out"}
	refuseTooMany     = &refusal{http.StatusServiceUnavailable, "connection_limit_reached", "max_tunnels reached"}
)

func refuseDNS(err error) *refusal {
	return &refusal{http.StatusBadGateway, "dns_error", "DNS lookup failed: " + err.Error()}
}

func refuseUnreachable(err error) *refusal {
	return &refusal{http.StatusBadGateway, "destination_unavailable", "unreachable: " + err.Error()}
}

// policy decides which destinations clients may reach. Every address a
// name resolves to is checked, so a DNS answer pointing to 127.0.0.1 cannot
// get through ("DNS rebinding").
type policy struct {
	blocked      []netip.Prefix
	blockedPorts map[uint16]bool
	resolver     interface {
		LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
	}
	// hostAddrs returns this host's own addresses, which are blocked too;
	// nil when they are not.
	hostAddrs func() []netip.Addr
}

// hostAddrsTTL is how long the list of this host's addresses is reused.
const hostAddrsTTL = 10 * time.Second

var hostAddrCache struct {
	sync.Mutex
	addrs   []netip.Addr
	fetched time.Time
}

// interfaceAddrs returns the addresses of this host's network interfaces,
// read again at most every hostAddrsTTL so that address changes are seen.
// If they cannot be read, the last list is kept.
func interfaceAddrs() []netip.Addr {
	hostAddrCache.Lock()
	defer hostAddrCache.Unlock()
	if !hostAddrCache.fetched.IsZero() && time.Since(hostAddrCache.fetched) < hostAddrsTTL {
		return hostAddrCache.addrs
	}
	hostAddrCache.fetched = time.Now()
	ifaddrs, err := net.InterfaceAddrs()
	if err != nil {
		return hostAddrCache.addrs
	}
	var addrs []netip.Addr
	for _, a := range ifaddrs {
		if n, ok := a.(*net.IPNet); ok {
			if ip, ok := netip.AddrFromSlice(n.IP); ok {
				addrs = append(addrs, ip.Unmap())
			}
		}
	}
	hostAddrCache.addrs = addrs
	return addrs
}

func newPolicy(blocked []string, ports []int) (*policy, error) {
	p := &policy{blockedPorts: map[uint16]bool{}, resolver: net.DefaultResolver}
	for _, s := range blocked {
		prefix, err := netip.ParsePrefix(s)
		if err != nil {
			ip, err2 := netip.ParseAddr(s)
			if err2 != nil {
				return nil, fmt.Errorf("blocked destination %q is not an address or CIDR range", s)
			}
			prefix = netip.PrefixFrom(ip, ip.BitLen())
		}
		if prefix != prefix.Masked() {
			return nil, fmt.Errorf("blocked destination %q has host bits set (did you mean %s?)", s, prefix.Masked())
		}
		// allows checks mapped IPv6 destinations as IPv4. Apply the same
		// normalization to configured ranges, otherwise a mapped-address
		// block never matches the destination it names.
		if prefix.Addr().Is4In6() && prefix.Bits() >= 96 {
			prefix = netip.PrefixFrom(prefix.Addr().Unmap(), prefix.Bits()-96)
		}
		p.blocked = append(p.blocked, prefix)
	}
	for _, port := range ports {
		if port < 1 || port > 65535 {
			return nil, fmt.Errorf("blocked port %d is not between 1 and 65535", port)
		}
		p.blockedPorts[uint16(port)] = true
	}
	return p, nil
}

// embeddedIPv4 returns the IPv4 addresses carried inside an IPv6 address
// that the network translates or tunnels to that IPv4 address: the NAT64
// well-known prefix (RFC 6052), 6to4 (RFC 3056), Teredo server and client
// (RFC 4380), and deprecated IPv4-compatible addresses (RFC 4291
// §2.5.5.1).
func embeddedIPv4(ip netip.Addr) []netip.Addr {
	if !ip.Is6() || ip.Is4In6() {
		return nil
	}
	o := ip.As16()
	zero := func(b []byte) bool { return strings.Trim(string(b), "\x00") == "" }
	v4 := func(b []byte) netip.Addr { return netip.AddrFrom4([4]byte(b)) }
	switch {
	case o[0] == 0x00 && o[1] == 0x64 && o[2] == 0xff && o[3] == 0x9b && zero(o[4:12]):
		return []netip.Addr{v4(o[12:16])}
	case o[0] == 0x20 && o[1] == 0x02:
		return []netip.Addr{v4(o[2:6])}
	case o[0] == 0x20 && o[1] == 0x01 && o[2] == 0x00 && o[3] == 0x00:
		return []netip.Addr{v4(o[4:8]), netip.AddrFrom4([4]byte{^o[12], ^o[13], ^o[14], ^o[15]})}
	case zero(o[:12]):
		return []netip.Addr{v4(o[12:16])}
	}
	return nil
}

// allows reports whether ip may be reached. IPv4-mapped IPv6 addresses are
// checked as the IPv4 address they are, and IPv6 addresses that carry an
// IPv4 address (NAT64, 6to4, Teredo) also by that address.
func (p *policy) allows(ip netip.Addr) bool {
	ip = ip.Unmap().WithZone("")
	candidates := append([]netip.Addr{ip}, embeddedIPv4(ip)...)
	for _, c := range candidates {
		for _, prefix := range p.blocked {
			if prefix.Contains(c) {
				return false
			}
		}
	}
	if p.hostAddrs != nil {
		ownAddrs := p.hostAddrs()
		if len(ownAddrs) == 0 {
			return false // fail closed if interface discovery never succeeded
		}
		for _, own := range ownAddrs {
			if slices.Contains(candidates, own.Unmap().WithZone("")) {
				return false
			}
		}
	}
	return true
}

// resolve returns the addresses the target may be reached at, in the order
// the resolver gave them.
func (p *policy) resolve(ctx context.Context, t target) ([]netip.AddrPort, error) {
	// RFC 6761 section 6.4: .invalid is reserved to produce negative
	// answers. Do not depend on external resolver availability for it.
	if t.host == "invalid" || strings.HasSuffix(t.host, ".invalid") {
		return nil, refuseDNS(&net.DNSError{Name: t.host, Err: "reserved invalid domain", IsNotFound: true})
	}
	if p.blockedPorts[t.port] {
		return nil, refusePort
	}
	var addrs []netip.Addr
	if ip, err := netip.ParseAddr(t.host); err == nil {
		addrs = []netip.Addr{ip}
	} else {
		ctx, cancel := context.WithTimeout(ctx, dnsTimeout)
		found, err := p.resolver.LookupNetIP(ctx, "ip", t.host)
		cancel()
		var dnsErr *net.DNSError
		switch {
		case errors.Is(err, context.DeadlineExceeded) || errors.As(err, &dnsErr) && dnsErr.IsTimeout:
			return nil, refuseDNSTimeout
		case err != nil:
			return nil, refuseDNS(err)
		}
		addrs = found
	}
	if len(addrs) == 0 {
		return nil, refuseNoAddresses
	}
	allowed := make([]netip.AddrPort, 0, len(addrs))
	for _, ip := range addrs {
		ap := netip.AddrPortFrom(ip.Unmap(), t.port)
		if p.allows(ip) && !containsAddrPort(allowed, ap) {
			allowed = append(allowed, ap)
		}
	}
	if len(allowed) == 0 {
		return nil, refuseAddress
	}
	return allowed, nil
}

func containsAddrPort(list []netip.AddrPort, a netip.AddrPort) bool {
	for _, x := range list {
		if x == a {
			return true
		}
	}
	return false
}
