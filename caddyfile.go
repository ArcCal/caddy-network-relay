package networkrelay

import (
	"strconv"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func init() {
	httpcaddyfile.RegisterHandlerDirective("network_relay", parseCaddyfile)
	// Relay requests are handled before anything else in the site, so
	// the website's directives (headers, redirects, rewrites) never touch
	// them; every other request continues down the site as usual.
	httpcaddyfile.RegisterDirectiveOrder("network_relay", httpcaddyfile.Before, "map")
}

// UnmarshalCaddyfile sets up the handler from Caddyfile tokens:
//
//	network_relay {
//		user <name> [<password_hash>] [certificate <sha256>] [expires <time>]
//		udp_template <path>
//		blocked_destinations [<cidr>...]
//		blocked_ports [<port>...]
//		connect_timeout <duration>
//		udp_idle_timeout <duration>
//		max_tunnels <number>
//		log_requests
//	}
func (h *Handler) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	d.Next() // directive name
	if d.NextArg() {
		return d.ArgErr()
	}
	for d.NextBlock(0) {
		switch d.Val() {
		case "relay_id":
			if !d.AllArgs(&h.RelayID) || h.RelayID == "" {
				return d.ArgErr()
			}
		case "user":
			args := d.RemainingArgs()
			usage := "user <name> [<password hash>] [certificate <sha256>] [expires <RFC 3339 time>]"
			if len(args) < 2 {
				return d.Errf("user needs a name and a credential: %s", usage)
			}
			u := User{Name: args[0]}
			rest := args[1:]
			if rest[0] != "certificate" && rest[0] != "expires" {
				u.PasswordHash, rest = rest[0], rest[1:]
			}
			for len(rest) > 0 {
				if len(rest) < 2 {
					return d.Errf("%q needs a value: %s", rest[0], usage)
				}
				switch rest[0] {
				case "certificate":
					u.CertificateSHA256 = rest[1]
				case "expires":
					u.Expires = rest[1]
				default:
					return d.Errf("unknown user option %q: %s", rest[0], usage)
				}
				rest = rest[2:]
			}
			h.Users = append(h.Users, u)
		case "udp_template":
			if !d.AllArgs(&h.UDPTemplate) {
				return d.ArgErr()
			}
		case "blocked_destinations":
			list := d.RemainingArgs()
			if list == nil {
				list = []string{}
			}
			h.BlockedDestinations = &list
		case "blocked_ports":
			ports := []int{}
			for _, a := range d.RemainingArgs() {
				p, err := strconv.Atoi(a)
				if err != nil {
					return d.Errf("blocked_ports: %q is not a port number", a)
				}
				ports = append(ports, p)
			}
			h.BlockedPorts = &ports
		case "connect_timeout", "udp_idle_timeout":
			name := d.Val()
			var s string
			if !d.AllArgs(&s) {
				return d.ArgErr()
			}
			dur, err := caddy.ParseDuration(s)
			if err != nil {
				return d.Errf("%s: %v", name, err)
			}
			if name == "connect_timeout" {
				h.ConnectTimeout = caddy.Duration(dur)
			} else {
				h.UDPIdleTimeout = caddy.Duration(dur)
			}
		case "max_tunnels", "max_tunnels_per_user":
			name := d.Val()
			var s string
			if !d.AllArgs(&s) {
				return d.ArgErr()
			}
			n, err := strconv.Atoi(s)
			if err != nil {
				return d.Errf("max_tunnels: %q is not a number", s)
			}
			if name == "max_tunnels" {
				h.MaxTunnels = n
			} else {
				h.MaxTunnelsPerUser = n
			}
		case "max_bytes_per_second_per_user", "max_udp_packets_per_second_per_user":
			name := d.Val()
			var s string
			if !d.AllArgs(&s) {
				return d.ArgErr()
			}
			n, err := strconv.ParseInt(s, 10, 64)
			if err != nil {
				return d.Errf("%s: invalid integer %q", name, s)
			}
			if name == "max_bytes_per_second_per_user" {
				h.MaxBytesPerSecondPerUser = n
			} else {
				h.MaxUDPPacketsPerSecondPerUser = n
			}
		case "log_requests":
			if d.NextArg() {
				return d.ArgErr()
			}
			h.LogRequests = true
		default:
			return d.Errf("unknown network_relay option %q", d.Val())
		}
	}
	return nil
}

func parseCaddyfile(helper httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	h := new(Handler)
	err := h.UnmarshalCaddyfile(helper.Dispenser)
	return h, err
}

var _ caddyfile.Unmarshaler = (*Handler)(nil)
