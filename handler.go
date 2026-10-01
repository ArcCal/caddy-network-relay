// Package networkrelay is a Caddy plugin that turns a site into a relay for
// Apple's Network Relay (com.apple.relay.managed profiles): TCP over HTTP
// CONNECT and UDP over CONNECT-UDP (RFC 9298), on HTTP/3, HTTP/2 and
// HTTP/1.1. Requests without valid credentials go on to the rest of the
// site, so the relay looks like an ordinary website.
package networkrelay

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/quic-go/quic-go/http3"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func init() {
	caddy.RegisterModule(Handler{})
}

const (
	defaultConnectTimeout = 10 * time.Second
	defaultUDPIdleTimeout = 5 * time.Minute
	defaultMaxTunnels     = 20000

	// connectUDP is the upgrade token / :protocol of CONNECT-UDP.
	connectUDP = "connect-udp"
)

// Handler relays TCP and UDP for authenticated clients and passes every
// other request on to the next handler (the website).
type Handler struct {
	// Accounts allowed to use the relay; one per device.
	Users []User `json:"users,omitempty"`

	// Path of the CONNECT-UDP URI template (RFC 9298 §2). It must contain
	// {target_host} and {target_port}; the profile must use the same one.
	// Default: /.well-known/masque/udp/{target_host}/{target_port}/
	UDPTemplate string `json:"udp_template,omitempty"`

	// Addresses (CIDR ranges) clients may not reach. Every address a name
	// resolves to is checked. Default: loopback, private, link-local,
	// multicast and other special-purpose ranges. An empty list blocks
	// nothing, which exposes services on the relay's own host.
	BlockedDestinations *[]string `json:"blocked_destinations,omitempty"`

	// Ports clients may not reach, TCP and UDP. Default: [25].
	BlockedPorts *[]int `json:"blocked_ports,omitempty"`

	// Timeout for connecting to a TCP target (1s to 2m). Default: 10s.
	ConnectTimeout caddy.Duration `json:"connect_timeout,omitempty"`

	// A UDP tunnel with no packets in either direction for this long is
	// closed (2m to 1h; RFC 4787 asks for at least 2 minutes). Default: 5m.
	UDPIdleTimeout caddy.Duration `json:"udp_idle_timeout,omitempty"`

	// Most tunnels (TCP connections and UDP flows) open at once, across all
	// users. Default: 20000.
	MaxTunnels int `json:"max_tunnels,omitempty"`

	// Log every proxy request with its headers (credentials reduced to
	// the user name). Noisy; for finding out what a device sends.
	LogRequests bool `json:"log_requests,omitempty"`

	template *uriTemplate
	policy   *policy
	auth     *authenticator
	server   *relayServer
	logger   *zap.Logger
}

// CaddyModule returns the Caddy module information.
func (Handler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.network_relay",
		New: func() caddy.Module { return new(Handler) },
	}
}

// Provision sets up the handler.
func (h *Handler) Provision(ctx caddy.Context) error {
	h.logger = ctx.Logger()
	if h.UDPTemplate == "" {
		h.UDPTemplate = DefaultUDPTemplate
	}
	var err error
	if h.template, err = parseUDPTemplate(h.UDPTemplate); err != nil {
		return err
	}
	blocked := DefaultBlockedDestinations
	if h.BlockedDestinations != nil {
		blocked = *h.BlockedDestinations
	}
	ports := DefaultBlockedPorts
	if h.BlockedPorts != nil {
		ports = *h.BlockedPorts
	}
	if h.policy, err = newPolicy(blocked, ports); err != nil {
		return err
	}
	if h.ConnectTimeout == 0 {
		h.ConnectTimeout = caddy.Duration(defaultConnectTimeout)
	}
	if h.UDPIdleTimeout == 0 {
		h.UDPIdleTimeout = caddy.Duration(defaultUDPIdleTimeout)
	}
	if h.MaxTunnels == 0 {
		h.MaxTunnels = defaultMaxTunnels
	}
	if h.auth, err = newAuthenticator(h.Users); err != nil {
		return err
	}
	if len(h.Users) == 0 {
		h.logger.Warn("network_relay has no users; it only serves the website")
	}
	if !http2ExtendedConnect() {
		h.logger.Warn("UDP over HTTP/2 (extended CONNECT) is off; start Caddy with GODEBUG=http2xconnect=1 to turn it on")
	}
	if h.BlockedDestinations != nil && len(*h.BlockedDestinations) == 0 {
		h.logger.Warn("blocked_destinations is empty: clients can reach services on this host and its private network")
	}

	// Take over HTTP/3 for the server this handler is in: Caddy's own
	// HTTP/3 server does not support HTTP Datagrams (RFC 9297), which
	// CONNECT-UDP needs.
	if srv, ok := ctx.Value(caddyhttp.ServerCtxKey).(*caddyhttp.Server); ok {
		appIface, err := ctx.App("network_relay")
		if err != nil {
			return err
		}
		h.server = appIface.(*App).addServer(srv)
	}
	registerHandler(h)
	return nil
}

// Validate checks the configuration.
func (h *Handler) Validate() error {
	if d := time.Duration(h.ConnectTimeout); d < time.Second || d > 2*time.Minute {
		return fmt.Errorf("connect_timeout must be between 1s and 2m, not %s", d)
	}
	if d := time.Duration(h.UDPIdleTimeout); d < 2*time.Minute || d > time.Hour {
		return fmt.Errorf("udp_idle_timeout must be between 2m and 1h, not %s", d)
	}
	if h.MaxTunnels < 1 {
		return fmt.Errorf("max_tunnels must be at least 1")
	}
	return nil
}

// Cleanup closes the tunnels of users the new configuration no longer has.
func (h *Handler) Cleanup() error {
	unregisterHandler(h)
	return nil
}

type requestKind int

const (
	notRelay requestKind = iota
	tcpRequest
	udpRequest
)

// classify tells relay requests from website requests (RFC 9114 §4.4,
// RFC 9113 §8.5, RFC 9110 §9.3.6, RFC 9298 §3).
func (h *Handler) classify(r *http.Request) (requestKind, target, bool) {
	var protocol string
	switch r.ProtoMajor {
	case 3:
		if r.Method == http.MethodConnect && r.Proto != "HTTP/3.0" {
			protocol = r.Proto
		}
	case 2:
		protocol = r.Header.Get(":protocol")
	}
	switch {
	case r.Method == http.MethodConnect && protocol == "":
		t, ok := parseAuthority(r.Host)
		return tcpRequest, t, ok
	case r.Method == http.MethodConnect && protocol == connectUDP && r.ProtoMajor >= 2,
		r.ProtoMajor == 1 && r.Method == http.MethodGet && isUDPUpgrade(r.Header):
		pathAndQuery := r.URL.EscapedPath()
		if r.URL.RawQuery != "" {
			pathAndQuery += "?" + r.URL.RawQuery
		}
		host, port, ok := h.template.Match(pathAndQuery)
		if !ok {
			return notRelay, target{}, false
		}
		t, ok := newTarget(host, port)
		return udpRequest, t, ok
	}
	return notRelay, target{}, false
}

func isUDPUpgrade(hdr http.Header) bool {
	return headerHasToken(hdr, "Upgrade", connectUDP) && headerHasToken(hdr, "Connection", "upgrade")
}

func headerHasToken(hdr http.Header, name, token string) bool {
	for _, v := range hdr.Values(name) {
		for _, t := range strings.Split(v, ",") {
			if strings.EqualFold(strings.TrimSpace(t), token) {
				return true
			}
		}
	}
	return false
}

// ServeHTTP implements caddyhttp.MiddlewareHandler.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	if r.ProtoMajor < 3 && r.TLS != nil && h.server != nil {
		if v := h.server.altSvc(r); v != "" {
			w.Header().Set("Alt-Svc", v)
		}
	}
	kind, t, validTarget := h.classify(r)
	if kind == notRelay {
		return next.ServeHTTP(w, r)
	}
	creds := credentials(r)
	acct, ok := h.auth.verify(creds)
	if h.LogRequests {
		h.logRequest(r, kind, ok)
	}
	if !ok {
		if creds != "" {
			h.logger.Warn("relay authentication failed",
				zap.String("user", acct.name), zap.String("remote", r.RemoteAddr))
		}
		if r.Method == http.MethodConnect {
			// What a static Caddy site answers to CONNECT. Passing it on
			// could let a handler answer 2xx, which means "tunnel open".
			w.Header().Set("Allow", "GET, HEAD")
			return caddyhttp.Error(http.StatusMethodNotAllowed, nil)
		}
		// A GET with Upgrade: connect-udp is answered by the website.
		return next.ServeHTTP(w, r)
	}
	if !validTarget {
		return h.refuse(w, r, refuseBadTarget)
	}
	if kind == udpRequest && (r.ContentLength > 0 || len(r.TransferEncoding) > 0 ||
		r.Header.Get("Content-Length") != "" || r.Header.Get("Content-Type") != "") {
		// RFC 9297 §3.2-3.3: capsule protocol requests have no content.
		return h.refuse(w, r, refuseRequest)
	}
	if openTunnels.Add(1) > int64(h.MaxTunnels) {
		openTunnels.Add(-1)
		return h.refuse(w, r, refuseTooMany)
	}
	defer openTunnels.Add(-1)

	// Until the tunnel is established, a client that goes away (the request
	// context) cancels it. After that the request context means different
	// things per HTTP version (Go's HTTP/1.1 server cancels it when a
	// hijacked client half-closes, quic-go when the relay half-closes), so
	// each clientConn reports a vanished client itself. The user being
	// revoked and Caddy exiting cancel ctx at any time.
	ctx, cancel := context.WithCancelCause(context.WithoutCancel(r.Context()))
	defer cancel(nil)
	unfollow := context.AfterFunc(r.Context(), func() { cancel(context.Canceled) })
	defer unfollow()

	lt := &liveTunnel{acct: acct, owner: h, cancel: cancel}
	if !addTunnel(lt) {
		return h.refuse(w, r, &refusal{http.StatusForbidden, "http_request_denied", errRevoked.Error()})
	}
	defer removeTunnel(lt)

	addrs, err := h.policy.resolve(ctx, t)
	if err != nil {
		return h.refuse(w, r, dialRefusal(err))
	}
	start := time.Now()
	log := h.logger.With(zap.String("user", acct.name), zap.String("proto", r.Proto),
		zap.String("target", t.String()), zap.String("remote", r.RemoteAddr))
	if kind == tcpRequest {
		return h.serveTCP(ctx, w, r, addrs, log, start, unfollow)
	}
	return h.serveUDP(ctx, w, r, addrs, log, start, unfollow)
}

func (h *Handler) refuse(w http.ResponseWriter, r *http.Request, why *refusal) error {
	if c := h.logger.Check(zapcore.DebugLevel, "relay request refused"); c != nil {
		c.Write(zap.String("proto", r.Proto), zap.String("host", r.Host), zap.String("path", r.URL.Path),
			zap.Int("status", why.status), zap.String("reason", why.detail))
	}
	w.Header().Set("Proxy-Status", why.proxyStatus())
	w.WriteHeader(why.status)
	return nil
}

func (h *Handler) serveTCP(ctx context.Context, w http.ResponseWriter, r *http.Request,
	addrs []netip.AddrPort, log *zap.Logger, start time.Time, established func() bool) error {
	conn, err := dialTCP(ctx, addrs, time.Duration(h.ConnectTimeout))
	if err != nil {
		return h.refuse(w, r, dialRefusal(err))
	}
	cc, err := establish(w, r, "HTTP/1.1 200 OK\r\n\r\n")
	established()
	if err != nil {
		conn.Close()
		log.Debug("could not start the tunnel", zap.Error(err))
		return nil
	}
	up, down, why, aborted := pumpTCP(ctx, cc, conn)
	h.logEnd(log, "tcp", start, up, down, ctx, why, aborted)
	if aborted {
		cc.abort(why)
	} else {
		cc.close()
	}
	return nil
}

func (h *Handler) serveUDP(ctx context.Context, w http.ResponseWriter, r *http.Request,
	addrs []netip.AddrPort, log *zap.Logger, start time.Time, established func() bool) error {
	sock, err := dialUDP(addrs)
	if err != nil {
		return h.refuse(w, r, dialRefusal(err))
	}
	datagrams := r.ProtoMajor == 3 && datagramsNegotiated(ctx, baseWriter(w))
	w.Header().Set("Capsule-Protocol", "?1")
	cc, err := establish(w, r,
		"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: connect-udp\r\nCapsule-Protocol: ?1\r\n\r\n")
	established()
	if err != nil {
		sock.Close()
		log.Debug("could not start the tunnel", zap.Error(err))
		return nil
	}
	u := &udpTunnel{cc: cc, sock: sock, idle: time.Duration(h.UDPIdleTimeout)}
	if datagrams {
		u.h3 = cc.(*h3Client).str
	}
	up, down, why, aborted := u.run(ctx)
	h.logEnd(log, "udp", start, up, down, ctx, why, aborted)
	if aborted {
		cc.abort(why)
	} else {
		cc.close()
	}
	return nil
}

// datagramsNegotiated reports whether the HTTP/3 client enabled HTTP
// Datagrams (SETTINGS_H3_DATAGRAM, which quic-go only accepts together with
// the QUIC DATAGRAM extension). Without them, UDP goes in capsules.
func datagramsNegotiated(ctx context.Context, w http.ResponseWriter) bool {
	s, ok := w.(http3.Settingser)
	if !ok {
		return false
	}
	select {
	case <-s.ReceivedSettings():
		return s.Settings().EnableDatagrams
	case <-time.After(3 * time.Second):
		return false
	case <-ctx.Done():
		return false
	}
}

// establish sends the success response and takes over the stream or
// connection. h1Response is the raw response for HTTP/1.1, where the
// connection is hijacked.
func establish(w http.ResponseWriter, r *http.Request, h1Response string) (clientConn, error) {
	base := baseWriter(w)
	switch r.ProtoMajor {
	case 1:
		conn, brw, err := http.NewResponseController(base).Hijack()
		if err != nil {
			return nil, err
		}
		_ = conn.SetDeadline(time.Time{})
		if _, err := conn.Write([]byte(h1Response)); err != nil {
			conn.Close()
			return nil, err
		}
		return &h1Client{conn: conn, r: brw.Reader}, nil
	case 2:
		w.WriteHeader(http.StatusOK)
		if err := http.NewResponseController(w).Flush(); err != nil {
			return nil, err
		}
		rc := http.NewResponseController(base)
		clearDeadlines(rc)
		return &h2Client{body: rawBody(r.Body), w: base, rc: rc, done: r.Context().Done()}, nil
	case 3:
		streamer, ok := base.(http3.HTTPStreamer)
		if !ok {
			return nil, errHijackFailed
		}
		w.WriteHeader(http.StatusOK)
		str := streamer.HTTPStream()
		_ = str.SetDeadline(time.Time{})
		return &h3Client{str: str}, nil
	}
	return nil, errHijackFailed
}

func (h *Handler) logEnd(log *zap.Logger, kind string, start time.Time, up, down int64,
	ctx context.Context, why abortReason, aborted bool) {
	c := log.Check(zapcore.DebugLevel, "tunnel closed")
	if c == nil {
		return
	}
	outcome := "closed"
	if aborted {
		outcome = [...]string{"malformed", "target failed", "cancelled"}[why]
		if cause := context.Cause(ctx); cause != nil && cause != context.Canceled {
			outcome += ": " + cause.Error()
		}
	}
	c.Write(zap.String("kind", kind), zap.Duration("duration", time.Since(start)),
		zap.Int64("bytes_up", up), zap.Int64("bytes_down", down), zap.String("outcome", outcome))
}

// logRequest logs a proxy request as the device sent it, with credentials
// reduced to the user name.
func (h *Handler) logRequest(r *http.Request, kind requestKind, authenticated bool) {
	headers := make(map[string]string, len(r.Header))
	for name, values := range r.Header {
		v := strings.Join(values, ", ")
		if name == "Authorization" || name == "Proxy-Authorization" {
			user, _, ok := parseBasic(v)
			if ok {
				v = "Basic (user " + strconv.Quote(user) + ")"
			} else {
				v = "(hidden)"
			}
		}
		headers[name] = v
	}
	h.logger.Info("relay request",
		zap.String("proto", r.Proto), zap.String("method", r.Method), zap.String("host", r.Host),
		zap.String("path", r.URL.RequestURI()), zap.Bool("udp", kind == udpRequest),
		zap.Bool("authenticated", authenticated), zap.Any("headers", headers),
		zap.String("remote", r.RemoteAddr))
}

// altSvcValue advertises HTTP/3 on port.
func altSvcValue(port int) string {
	return `h3=":` + strconv.Itoa(port) + `"; ma=2592000`
}

func localPort(r *http.Request) int {
	addr, ok := r.Context().Value(http.LocalAddrContextKey).(net.Addr)
	if !ok {
		return 0
	}
	switch a := addr.(type) {
	case *net.TCPAddr:
		return a.Port
	}
	_, p, err := net.SplitHostPort(addr.String())
	if err != nil {
		return 0
	}
	n, _ := strconv.Atoi(p)
	return n
}

// Interface guards
var (
	_ caddy.Provisioner           = (*Handler)(nil)
	_ caddy.Validator             = (*Handler)(nil)
	_ caddy.CleanerUpper          = (*Handler)(nil)
	_ caddyhttp.MiddlewareHandler = (*Handler)(nil)
)
