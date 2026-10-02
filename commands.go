package networkrelay

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	caddycmd "github.com/caddyserver/caddy/v2/cmd"
	"github.com/spf13/cobra"
	"golang.org/x/net/dns/dnsmessage"
	"golang.org/x/term"
)

func init() {
	caddycmd.RegisterCommand(caddycmd.Command{
		Name:  "network-relay",
		Usage: "<passwd|profile|check> [flags]",
		Short: "Tools for the network_relay plugin: users, device profiles, self-test",
		Long: `
passwd   creates a user: a random password and the line for the Caddyfile.
profile  writes the .mobileconfig that sets up an iPhone, iPad or Mac.
check    tests a running relay like a device would, over HTTP/3, HTTP/2 and HTTP/1.1.

Run "caddy network-relay <command> --help" for the flags of each command.`,
		CobraFunc: func(cmd *cobra.Command) {
			cmd.AddCommand(passwdCommand(), profileCommand(), checkCommand())
		},
	})
}

// readPassword reads a password: the first line of standard input when it
// is not a terminal, otherwise a prompt without echo.
func readPassword(prompt string) (string, error) {
	if term.IsTerminal(int(os.Stdin.Fd())) {
		fmt.Fprint(os.Stderr, prompt)
		b, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		return string(b), err
	}
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil && !(errors.Is(err, io.EOF) && line != "") {
		return "", fmt.Errorf("reading the password from standard input: %w", err)
	}
	return strings.TrimRight(line, "\r\n"), nil
}

func passwdCommand() *cobra.Command {
	var name string
	var stdin bool
	c := &cobra.Command{
		Use:   "passwd --name <user> [--stdin]",
		Short: "Create a user: random password and Argon2id hash",
		Long: `Creates a user for the network_relay directive. Prints a random password
(144 random bits) and the line to put in the Caddyfile:

    user <name> <argon2id hash>

With --stdin, reads your own password (at least 12 characters) from standard
input instead and prints only the Caddyfile line.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := validateUserName(name); err != nil {
				return err
			}
			password := RandomPassword()
			if stdin {
				var err error
				if password, err = readPassword("Password: "); err != nil {
					return err
				}
				if len(password) < 12 {
					return errors.New("the password must be at least 12 characters")
				}
			}
			if !stdin {
				fmt.Printf("password: %s\n", password)
			}
			fmt.Printf("user %s %s\n", name, HashPassword(password))
			return nil
		},
	}
	c.Flags().StringVar(&name, "name", "", "user name (letters, digits, - _ .)")
	c.Flags().BoolVar(&stdin, "stdin", false, "read the password from standard input")
	_ = c.MarkFlagRequired("name")
	return c
}

type optionalBool struct{ v **bool }

func (o optionalBool) String() string {
	if *o.v == nil {
		return ""
	}
	return strconv.FormatBool(**o.v)
}

func (o optionalBool) Set(s string) error {
	b, err := strconv.ParseBool(s)
	if err != nil {
		return err
	}
	*o.v = &b
	return nil
}

func (o optionalBool) Type() string { return "true|false" }

func profileCommand() *cobra.Command {
	var p Profile
	var out, gfwFile string
	var domainFiles []string
	var gfwlist, passwordStdin bool
	c := &cobra.Command{
		Use:   "profile --host <domain> --user <name> [flags]",
		Short: "Write a .mobileconfig for iPhone, iPad and Mac",
		Long: `Writes a configuration profile with a com.apple.relay.managed payload
(iOS/iPadOS 17+, macOS 14+). It contains the password in clear text: keep it
private and delete copies after installing it.

Without any --match-* option, all traffic goes through the relay (except
--exclude-*). The password is asked for, or read from standard input with
--password-stdin; it never needs to be on the command line.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			var err error
			if p.Password == "" || passwordStdin {
				if p.Password, err = readPassword("Password for " + p.User + ": "); err != nil {
					return err
				}
			}
			if p.Password == "" {
				return errors.New("the password is empty")
			}
			// Asked for a list of domains: an empty result must not turn into
			// a profile that relays everything.
			selective := len(p.MatchDomains) > 0 || len(p.MatchFQDNs) > 0 ||
				len(domainFiles) > 0 || gfwlist || gfwFile != ""
			for _, f := range domainFiles {
				b, err := os.ReadFile(f)
				if err != nil {
					return err
				}
				p.MatchDomains = append(p.MatchDomains, parseDomainList(string(b))...)
			}
			if gfwlist || gfwFile != "" {
				raw, err := loadGFWList(gfwFile)
				if err != nil {
					return fmt.Errorf("gfwlist: %w", err)
				}
				text, err := decodeGFWList(raw)
				if err != nil {
					return fmt.Errorf("gfwlist: %w", err)
				}
				hosts, stats := extractGFWList(text)
				p.MatchDomains = append(p.MatchDomains, hosts...)
				for k, v := range stats {
					fmt.Fprintf(os.Stderr, "gfwlist: %s: %d\n", k, v)
				}
			}
			if len(p.MatchDomains) > 0 {
				// The relay itself must never go through the relay.
				host := normalizeDomain(p.Host)
				var kept []string
				for _, d := range collapseDomains(normalizedAll(p.MatchDomains)) {
					if d != host {
						kept = append(kept, d)
					}
				}
				p.MatchDomains = kept
				if !containsString(normalizedAll(p.ExcludedDomains), host) {
					p.ExcludedDomains = append(p.ExcludedDomains, host)
				}
			}
			if selective && len(p.MatchDomains) == 0 && len(p.MatchFQDNs) == 0 {
				// Apple's rule: no MatchDomains and no MatchFQDNs relays all traffic.
				return errors.New("no domain to relay is left (empty lists, or only the relay itself); " +
					"leave out every --match-* and list option to relay all traffic")
			}
			xml, err := p.Generate()
			if err != nil {
				return err
			}
			if out == "" {
				out = normalizeDomain(p.Host) + "-" + p.User + ".mobileconfig"
			}
			if err := writePrivateFile(out, []byte(xml)); err != nil {
				return err
			}
			fmt.Fprintf(os.Stderr, "wrote %s (contains the password; mode 600): %d match domains\n", out, len(p.MatchDomains))
			return nil
		},
	}
	f := c.Flags()
	f.StringVar(&p.Host, "host", "", "the relay's domain (the name on its certificate)")
	f.StringVar(&p.User, "user", "", "user name")
	f.StringVar(&p.Password, "password", "", "password (better: leave out and type it, or --password-stdin)")
	f.BoolVar(&passwordStdin, "password-stdin", false, "read the password from standard input")
	f.IntVar(&p.Port, "port", 443, "the relay's port")
	f.StringArrayVar(&p.MatchDomains, "match-domain", nil, "relay this domain and its subdomains (repeatable)")
	f.StringArrayVar(&p.ExcludedDomains, "exclude-domain", nil, "never relay this domain and its subdomains (repeatable)")
	f.StringArrayVar(&p.MatchFQDNs, "match-fqdn", nil, "relay exactly this host name (iOS 18.4/macOS 15.4+; repeatable)")
	f.StringArrayVar(&p.ExcludedFQDNs, "exclude-fqdn", nil, "never relay exactly this host name (repeatable)")
	f.StringArrayVar(&domainFiles, "domains-file", nil, "file with one domain per line to relay (repeatable)")
	f.BoolVar(&gfwlist, "gfwlist", false, "also relay the domains of the gfwlist (downloaded now)")
	f.StringVar(&gfwFile, "gfwlist-file", "", "like --gfwlist, from a file already downloaded")
	f.Var(optionalBool{&p.UIToggleEnabled}, "ui-toggle-enabled", "allow turning the relay off in Settings (iOS/macOS 26+; default true)")
	f.Var(optionalBool{&p.AllowDNSFailover}, "allow-dns-failover", "allow falling back to the system DNS (iOS/macOS 26+; default false)")
	f.StringVar(&p.RelayUUID, "relay-uuid", "", "relay UUID for managed apps (user enrollment)")
	f.StringVar(&p.Name, "name", "", "name shown in Settings (default: the host)")
	f.StringVar(&p.UDPTemplate, "udp-template", "", "the udp_template of the server, if changed")
	f.BoolVar(&p.NoHTTP3, "no-http3", false, "only use HTTP/2 (for networks that block UDP)")
	f.BoolVar(&p.NoHTTP2, "no-http2", false, "only use HTTP/3")
	f.StringVarP(&out, "out", "o", "", "file to write (default <host>-<user>.mobileconfig)")
	_ = c.MarkFlagRequired("host")
	_ = c.MarkFlagRequired("user")
	return c
}

func normalizedAll(list []string) []string {
	out := make([]string, len(list))
	for i, d := range list {
		out[i] = normalizeDomain(d)
	}
	return out
}

func containsString(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func loadGFWList(file string) ([]byte, error) {
	if file != "" {
		return os.ReadFile(file)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, GFWListURL, nil)
	if err != nil {
		return nil, err
	}
	rsp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer rsp.Body.Close()
	if rsp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: %s", GFWListURL, rsp.Status)
	}
	return io.ReadAll(io.LimitReader(rsp.Body, 16<<20))
}

// writePrivateFile replaces path atomically with a file only the owner can
// read. It refuses to replace a symbolic link.
func writePrivateFile(path string, data []byte) error {
	if fi, err := os.Lstat(path); err == nil && fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%s is a symbolic link; refusing to overwrite it", path)
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".profile-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

func checkCommand() *cobra.Command {
	var c relayClient
	var user, password, ca, tcpTarget, udpTarget, dnsName string
	var addresses []string
	var timeout time.Duration
	var passwordStdin bool
	cmd := &cobra.Command{
		Use:   "check --server <domain> --user <name> [flags]",
		Short: "Test a running relay over HTTP/3, HTTP/2 and HTTP/1.1",
		Long: `Tests a running relay like a device does: on each HTTP version, a TCP tunnel
(an HTTP request to --tcp-target) and a UDP tunnel (a DNS query to
--udp-target), and that a CONNECT without the password does not open a tunnel.
Exits with 0 when everything passed.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if password == "" || passwordStdin {
				var err error
				if password, err = readPassword("Password for " + user + ": "); err != nil {
					return err
				}
			}
			c.Authorization = BasicAuthorization(user, password)
			c.TLS = &tls.Config{}
			if ca != "" {
				pem, err := os.ReadFile(ca)
				if err != nil {
					return err
				}
				pool := x509.NewCertPool()
				if !pool.AppendCertsFromPEM(pem) {
					return fmt.Errorf("%s holds no PEM certificates", ca)
				}
				c.TLS.RootCAs = pool
			}
			if len(addresses) == 0 {
				addresses = []string{c.Server}
			}
			failed := 0
			for _, addr := range addresses {
				cl := c
				cl.Address = net.JoinHostPort(addr, strconv.Itoa(c.Port))
				fmt.Printf("== %s\n", cl.Address)
				failed += runChecks(&cl, tcpTarget, udpTarget, dnsName, timeout)
			}
			if failed > 0 {
				return fmt.Errorf("%d checks failed", failed)
			}
			fmt.Println("all checks passed")
			return nil
		},
	}
	f := cmd.Flags()
	f.StringVar(&c.Server, "server", "", "the relay's domain")
	f.StringArrayVar(&addresses, "address", nil, "connect to this IP address instead of resolving --server (repeatable)")
	f.IntVar(&c.Port, "port", 443, "the relay's port")
	f.StringVar(&user, "user", "", "user name")
	f.StringVar(&password, "password", "", "password (better: leave out and type it)")
	f.BoolVar(&passwordStdin, "password-stdin", false, "read the password from standard input")
	f.StringVar(&c.UDPTemplate, "udp-template", "", "the udp_template of the server, if changed")
	f.StringVar(&tcpTarget, "tcp-target", "example.com:80", "web server to reach through the TCP tunnel")
	f.StringVar(&udpTarget, "udp-target", "1.1.1.1:53", "DNS server to query through the UDP tunnel")
	f.StringVar(&dnsName, "dns-name", "example.com", "name to look up")
	f.StringVar(&ca, "ca", "", "trust only this CA (PEM file; for tests)")
	f.DurationVar(&timeout, "timeout", 10*time.Second, "time limit for each step")
	_ = cmd.MarkFlagRequired("server")
	_ = cmd.MarkFlagRequired("user")
	return cmd
}

// runChecks runs every check against one address and returns how many
// failed.
func runChecks(c *relayClient, tcpTarget, udpTarget, dnsName string, timeout time.Duration) int {
	udpHost, udpPort, err := net.SplitHostPort(udpTarget)
	if err != nil {
		fmt.Printf("bad --udp-target: %v\n", err)
		return 1
	}
	failed := 0
	report := func(name string, err error, detail string) {
		if err != nil {
			failed++
			fmt.Printf("FAIL %-28s %v\n", name, err)
		} else {
			fmt.Printf("ok   %-28s %s\n", name, detail)
		}
	}
	step := func() (context.Context, context.CancelFunc) {
		return context.WithTimeout(context.Background(), timeout)
	}

	// HTTP/3
	ctx, cancel := step()
	h3, err := c.dialH3(ctx)
	cancel()
	if err != nil {
		report("HTTP/3 connect", err, "")
	} else {
		ctx, cancel = step()
		s, err := c.openTCPH3(ctx, h3, tcpTarget)
		detail, err := httpThrough(ctx, s, err, tcpTarget)
		report("HTTP/3 TCP "+tcpTarget, err, detail)
		cancel()
		ctx, cancel = step()
		p, err := c.openUDPH3(ctx, h3, udpHost, udpPort)
		mode := "datagrams"
		if _, ok := p.(*capsuleConn); ok {
			mode = "capsules"
		}
		detail, err = dnsThrough(ctx, p, err, dnsName)
		report("HTTP/3 UDP "+udpTarget, err, detail+" ("+mode+")")
		cancel()
		h3.Close()
	}

	// HTTP/2
	ctx, cancel = step()
	h2, err := c.dialH2(ctx)
	cancel()
	if err != nil {
		report("HTTP/2 connect", err, "")
	} else {
		ctx, cancel = step()
		s, err := c.openTCPH2(ctx, h2, tcpTarget)
		detail, err := httpThrough(ctx, s, err, tcpTarget)
		report("HTTP/2 TCP "+tcpTarget, err, detail)
		cancel()
		ctx, cancel = step()
		p, err := c.openUDPH2(ctx, h2, udpHost, udpPort)
		detail, err = dnsThrough(ctx, p, err, dnsName)
		report("HTTP/2 UDP "+udpTarget, err, detail)
		cancel()
		h2.Close()
	}

	// HTTP/1.1
	ctx, cancel = step()
	s, err := c.openTCPH1(ctx, tcpTarget)
	detail, err := httpThrough(ctx, s, err, tcpTarget)
	report("HTTP/1.1 TCP "+tcpTarget, err, detail)
	cancel()
	ctx, cancel = step()
	p, err := c.openUDPH1(ctx, udpHost, udpPort)
	detail, err = dnsThrough(ctx, p, err, dnsName)
	report("HTTP/1.1 UDP "+udpTarget, err, detail)
	cancel()

	// Without the password, a CONNECT must not open a tunnel.
	ctx, cancel = step()
	anon := *c
	anon.Authorization = ""
	s, err = anon.openTCPH1(ctx, tcpTarget)
	var se *statusError
	switch {
	case err == nil:
		s.Close()
		report("no password: refused", errors.New("the tunnel opened without a password"), "")
	case errors.As(err, &se):
		report("no password: refused", nil, fmt.Sprintf("%d %s", se.Status, http.StatusText(se.Status)))
	default:
		report("no password: refused", err, "")
	}
	cancel()
	return failed
}

// httpThrough sends an HTTP/1.1 request through a TCP tunnel and returns
// the status line of the answer.
func httpThrough(ctx context.Context, s stream, err error, target string) (string, error) {
	if err != nil {
		return "", err
	}
	defer s.Close()
	host, _, _ := net.SplitHostPort(target)
	if _, err := io.WriteString(s, "HEAD / HTTP/1.1\r\nHost: "+host+"\r\nConnection: close\r\n\r\n"); err != nil {
		return "", err
	}
	type result struct {
		line string
		err  error
	}
	ch := make(chan result, 1)
	go func() {
		line, err := bufio.NewReader(s).ReadString('\n')
		ch <- result{strings.TrimSpace(line), err}
	}()
	select {
	case r := <-ch:
		if r.line == "" && r.err != nil {
			return "", r.err
		}
		// Bytes alone do not show that the tunnel reached the target: the
		// answer must be an HTTP status line.
		if f := strings.Fields(r.line); len(f) < 2 || !strings.HasPrefix(f[0], "HTTP/1.") ||
			len(f[1]) != 3 || strings.Trim(f[1], "0123456789") != "" {
			return "", fmt.Errorf("not an HTTP response: %q", r.line)
		}
		return r.line, nil
	case <-ctx.Done():
		return "", ctx.Err()
	}
}

// dnsThrough sends a DNS query for an A record through a UDP tunnel.
func dnsThrough(ctx context.Context, p packetConn, err error, name string) (string, error) {
	if err != nil {
		return "", err
	}
	defer p.Close()
	qname, err := dnsmessage.NewName(strings.TrimSuffix(name, ".") + ".")
	if err != nil {
		return "", err
	}
	msg := dnsmessage.Message{
		Header:    dnsmessage.Header{ID: 0x5250, RecursionDesired: true},
		Questions: []dnsmessage.Question{{Name: qname, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}},
	}
	query, err := msg.Pack()
	if err != nil {
		return "", err
	}
	for {
		if err := p.Send(query); err != nil {
			return "", err
		}
		rctx, cancel := context.WithTimeout(ctx, 2*time.Second)
		answer, err := p.Receive(rctx)
		cancel()
		if err != nil {
			if ctx.Err() != nil {
				return "", ctx.Err()
			}
			if errors.Is(err, context.DeadlineExceeded) {
				continue // the query or answer was lost; ask again
			}
			return "", err
		}
		var rsp dnsmessage.Message
		if err := rsp.Unpack(answer); err != nil || rsp.ID != msg.ID {
			continue
		}
		var addrs []string
		for _, a := range rsp.Answers {
			if r, ok := a.Body.(*dnsmessage.AResource); ok {
				addrs = append(addrs, net.IP(r.A[:]).String())
			}
		}
		return fmt.Sprintf("%s: %s %s", name, rsp.RCode, strings.Join(addrs, " ")), nil
	}
}
