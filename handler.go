// Package networkrelay is a Caddy plugin that turns a site into a relay for
// Apple's Network Relay (com.apple.relay.managed profiles): TCP over HTTP
// CONNECT and UDP over CONNECT-UDP (RFC 9298), on HTTP/3, HTTP/2 and
// HTTP/1.1. Requests without valid credentials go on to the rest of the
// site, so the relay looks like an ordinary website.
package networkrelay

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"golang.org/x/net/http/httpguts"
)

func init() {
	caddy.RegisterModule(Handler{})
}

const (
	defaultConnectTimeout = 10 * time.Second
	defaultUDPIdleTimeout = 5 * time.Minute
	defaultMaxUserTunnels = 512

	// connectUDP is the upgrade token / :protocol of CONNECT-UDP.
	connectUDP = "connect-udp"
)

// Handler relays TCP and UDP for authenticated clients and passes every
// other request on to the next handler (the website).
type Handler struct {
	// Stable security domain for retaining tunnels across reloads. Omit it
	// to revoke this handler's tunnels on every reload. Never reuse across tenants.
	RelayID string `json:"relay_id,omitempty"`
	// Accounts allowed to use the relay; one per device.
	Users []User `json:"users,omitempty"`

	// Path of the CONNECT-UDP URI template (RFC 9298 §2). It must contain
	// {target_host} and {target_port}; the profile must use the same one.
	// Default: /.well-known/masque/udp/{target_host}/{target_port}/
	UDPTemplate string `json:"udp_template,omitempty"`

	// Addresses (CIDR ranges) clients may not reach. Every address a name
	// resolves to is checked. Default: this host's own addresses, loopback,
	// private, link-local, multicast and other special-purpose ranges. A
	// list given here replaces all of that; an empty list blocks
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
	// users. Default: a quarter of the machine's memory at 256 KiB per
	// tunnel, between 512 and 20000 (4096 when memory is unknown).
	MaxTunnels int `json:"max_tunnels,omitempty"`
	// Most tunnels one user has open at once; a device that relays all its
	// traffic can have hundreds. Default: 512.
	MaxTunnelsPerUser int `json:"max_tunnels_per_user,omitempty"`
	// Shared upload/download payload budgets per user. Zero disables a budget.
	MaxBytesPerSecondPerUser      int64 `json:"max_bytes_per_second_per_user,omitempty"`
	MaxUDPPacketsPerSecondPerUser int64 `json:"max_udp_packets_per_second_per_user,omitempty"`

	// Sample proxy requests with redacted headers. Bounded process-wide;
	// for finding out what a device sends, not a complete access log.
	LogRequests bool `json:"log_requests,omitempty"`

	template *uriTemplate
	policy   *policy
	auth     *authenticator
	server   *relayServer
	logger   *zap.Logger
	traffic  map[string]*trafficBudget
	// Client authentication changes revoke retained tunnels without tying
	// their lifetime to ordinary server certificate renewal.
	tlsClientAuth []byte
	// Opaque verifier trust cannot be compared after module provisioning.
	// Its tunnels are consequently nontransferable across generations.
	tlsCustomVerifiers bool
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
	if h.BlockedDestinations == nil {
		h.policy.hostAddrs = interfaceAddrs
	}
	if h.ConnectTimeout == 0 {
		h.ConnectTimeout = caddy.Duration(defaultConnectTimeout)
	}
	if h.UDPIdleTimeout == 0 {
		h.UDPIdleTimeout = caddy.Duration(defaultUDPIdleTimeout)
	}
	if h.MaxTunnels == 0 {
		h.MaxTunnels = defaultMaxTunnels(totalMemory())
	}
	if h.MaxTunnelsPerUser == 0 {
		h.MaxTunnelsPerUser = defaultMaxUserTunnels
	}
	if h.auth, err = newAuthenticator(h.Users); err != nil {
		return err
	}
	h.traffic = make(map[string]*trafficBudget, len(h.Users))
	for _, u := range h.Users {
		h.traffic[u.Name] = newTrafficBudget(h.MaxBytesPerSecondPerUser, h.MaxUDPPacketsPerSecondPerUser)
	}
	if len(h.Users) == 0 {
		h.logger.Warn("network_relay has no users; it only serves the website")
	}
	if !http2ExtendedConnect() {
		h.logger.Warn("UDP over HTTP/2 (extended CONNECT) is off because GODEBUG sets http2xconnect=0; remove that setting to turn it on")
	}
	if h.BlockedDestinations != nil && len(*h.BlockedDestinations) == 0 {
		h.logger.Warn("blocked_destinations is empty: clients can reach services on this host and its private network")
	}

	// Take over HTTP/3 for the server this handler is in: Caddy's own
	// HTTP/3 server does not support HTTP Datagrams (RFC 9297), which
	// CONNECT-UDP needs.
	if srv, ok := ctx.Value(caddyhttp.ServerCtxKey).(*caddyhttp.Server); ok {
		if err := validateRelayTLS(srv); err != nil {
			return err
		}
		if h.tlsClientAuth, err = relayTLSClientAuth(srv); err != nil {
			return err
		}
		h.tlsCustomVerifiers = relayTLSHasCustomVerifiers(srv)
		appIface, err := ctx.App("network_relay")
		if err != nil {
			return err
		}
		app := appIface.(*App)
		if err := app.claimRelayID(h.RelayID); err != nil {
			return err
		}
		h.server = app.addServer(srv)
	}
	registerHandler(h)
	return nil
}

// Validate checks the configuration.
func (h *Handler) Validate() error {
	if len(h.RelayID) > 256 || strings.TrimSpace(h.RelayID) != h.RelayID {
		return fmt.Errorf("relay_id must have at most 256 bytes and no leading or trailing whitespace")
	}
	if d := time.Duration(h.ConnectTimeout); d < time.Second || d > 2*time.Minute {
		return fmt.Errorf("connect_timeout must be between 1s and 2m, not %s", d)
	}
	if d := time.Duration(h.UDPIdleTimeout); d < 2*time.Minute || d > time.Hour {
		return fmt.Errorf("udp_idle_timeout must be between 2m and 1h, not %s", d)
	}
	if h.MaxTunnels < 1 {
		return fmt.Errorf("max_tunnels must be at least 1")
	}
	if h.MaxTunnelsPerUser < 1 {
		return fmt.Errorf("max_tunnels_per_user must be at least 1")
	}
	if h.MaxBytesPerSecondPerUser < 0 || h.MaxBytesPerSecondPerUser > 1<<40 ||
		h.MaxUDPPacketsPerSecondPerUser < 0 || h.MaxUDPPacketsPerSecondPerUser > 1<<30 {
		return fmt.Errorf("per-user traffic limits must be nonnegative and within supported ranges")
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
	// An extended CONNECT for connect-udp whose path is not the template:
	// no tunnel here, and the website must not see it either, since any
	// 2xx answer would mean "tunnel open".
	udpUnknownPath
	unsupportedProtocol
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
		// HTTP/1.1 CONNECT names its target in authority form (RFC 9112
		// section 3.2.3). net/http falls back to the Host field for any other form,
		// which names no target.
		if r.ProtoMajor == 1 && (strings.HasPrefix(r.RequestURI, "/") || strings.Contains(r.RequestURI, "://")) {
			return tcpRequest, target{}, false
		}
		t, ok := parseAuthority(r.Host)
		return tcpRequest, t, ok
	case r.Method == http.MethodConnect && protocol == connectUDP && r.ProtoMajor >= 2,
		r.ProtoMajor == 1 && r.ProtoMinor >= 1 && headerHasToken(r.Header, "Upgrade", connectUDP):
		pathAndQuery := r.URL.EscapedPath()
		if r.URL.RawQuery != "" {
			pathAndQuery += "?" + r.URL.RawQuery
		}
		host, port, ok := h.template.Match(pathAndQuery)
		if !ok {
			if r.Method == http.MethodConnect {
				return udpUnknownPath, target{}, false
			}
			return notRelay, target{}, false // a GET for the website
		}
		t, ok := newTarget(host, port)
		return udpRequest, t, ok
	case r.Method == http.MethodConnect && protocol != "" && protocol != "websocket":
		// A static site's 2xx would falsely accept an unknown tunnel
		// protocol. Caddy's reverse_proxy can handle the known WebSocket
		// extension; other extensions require an implementation here.
		return unsupportedProtocol, target{}, false
	}
	return notRelay, target{}, false
}

// malformedUpgrade reports an HTTP/1.1 CONNECT-UDP request that breaks
// RFC 9298 §3.2: the method must be GET and Connection must list Upgrade.
func malformedUpgrade(r *http.Request) bool {
	return r.ProtoMajor == 1 && (r.Method != http.MethodGet || !headerHasToken(r.Header, "Connection", "upgrade"))
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
	// net/http checks Host's bytes but accepts invalid ports and bracketed
	// non-IP literals. RFC 9112 section 3.2 requires 400 for an invalid Host.
	badHTTP1Host := r.ProtoMajor == 1 && !validHostField(r.Host)
	if r.ProtoMajor == 1 && (strings.EqualFold(r.URL.Scheme, "http") || strings.EqualFold(r.URL.Scheme, "https")) {
		badHTTP1Host = badHTTP1Host || !httpguts.ValidRequestAuthority(r.URL.Host, r.URL.Scheme, false)
	}
	if badHTTP1Host {
		w.Header().Set("Connection", "close")
		w.WriteHeader(http.StatusBadRequest)
		return nil
	}
	if r.ProtoMajor < 3 && r.TLS != nil && h.server != nil {
		if v := h.server.altSvc(r); v != "" {
			w.Header().Set("Alt-Svc", v)
		}
	}
	// RFC 9931 section 6.3: data a client sends after an HTTP/1.1 connect-udp
	// upgrade request must never be read as further requests, so any answer
	// but the 101 (written directly to the hijacked connection) closes it.
	// Rejected CONNECTs close too (RFC 9931 section 8), as net/http does for them.
	if r.ProtoMajor == 1 && headerHasToken(r.Header, "Upgrade", connectUDP) {
		w.Header().Set("Connection", "close")
	}
	kind, t, validTarget := h.classify(r)
	if kind == notRelay {
		return next.ServeHTTP(w, r)
	}
	// Only a successful CONNECT-UDP response may advertise the Capsule
	// Protocol; discard any value set earlier by website middleware.
	w.Header().Del("Capsule-Protocol")
	creds := credentials(r)
	var acct account
	var err error
	if certAcct, ok := h.clientCertificate(r); ok {
		acct = certAcct
	} else {
		acct, err = h.auth.verifyFrom(r.Context(), creds, clientOf(r))
	}
	if h.LogRequests {
		h.logRequest(r, kind, err == nil)
	}
	if err != nil {
		var suppressed uint64
		var logAllowed bool
		if errors.Is(err, errAuthBusy) || errors.Is(err, errBadCredentials) && creds != "" {
			suppressed, logAllowed = authenticationLogs.allow()
		}
		switch {
		case logAllowed && errors.Is(err, errAuthBusy):
			h.logger.Warn("relay authentication refused: too many verifications waiting",
				zap.String("remote", r.RemoteAddr), zap.Uint64("suppressed", suppressed))
		case logAllowed && errors.Is(err, errBadCredentials) && creds != "":
			h.logger.Warn("relay authentication failed",
				zap.String("user", acct.name), zap.String("remote", r.RemoteAddr), zap.Uint64("suppressed", suppressed))
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
	if kind == udpUnknownPath {
		return caddyhttp.Error(http.StatusNotFound, nil)
	}
	if kind == unsupportedProtocol {
		// RFC 9220 section 3: an unsupported :protocol gets 501; no Proxy-Status
		// error type fits, so the detail says why (as network-relay does).
		w.Header().Set("Proxy-Status", `network-relay; details="unsupported :protocol"`)
		w.WriteHeader(http.StatusNotImplemented)
		return nil
	}
	if kind == udpRequest && malformedUpgrade(r) {
		return h.refuseMalformed(w, r, refuseRequest)
	}
	if kind == udpRequest && r.ProtoMajor >= 2 && r.URL.Scheme != "https" {
		return h.refuseMalformed(w, r, refuseRequest)
	}
	// A target that is well formed but unusable (port 0, a name that is not
	// a host name, an IPv6 zone) is refused with 400, as RFC 9110 section 9.3.6 asks
	// for CONNECT; it is not a malformed message, so HTTP/2 and HTTP/3 do
	// not reset the stream and the client gets the response.
	if !validTarget {
		return h.refuse(w, r, refuseBadTarget)
	}
	if kind == udpRequest && (r.ContentLength > 0 || len(r.TransferEncoding) > 0 ||
		len(r.Header.Values("Content-Length")) > 0 || len(r.Header.Values("Content-Type")) > 0 ||
		len(r.Header.Values("Transfer-Encoding")) > 0) {
		// RFC 9297 §3.2-3.3: capsule protocol requests have no content.
		return h.refuseMalformed(w, r, refuseRequest)
	}
	if openTunnels.Add(1) > int64(h.MaxTunnels) {
		openTunnels.Add(-1)
		return h.refuse(w, r, refuseTooMany)
	}
	defer openTunnels.Add(-1)
	releaseUser, admitted := reserveUserTunnel(h, acct.name)
	if !admitted {
		return h.refuse(w, r, refuseTooMany)
	}
	defer releaseUser()

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

	if !acct.expires.IsZero() {
		expiry := time.AfterFunc(time.Until(acct.expires), func() { cancel(errExpired) })
		defer expiry.Stop()
	}

	lt := &liveTunnel{acct: acct, owner: h, cancel: cancel, done: make(chan struct{})}
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
		return h.serveTCP(ctx, w, r, addrs, log, start, unfollow, h.traffic[acct.name])
	}
	return h.serveUDP(ctx, w, r, addrs, log, start, unfollow, h.traffic[acct.name])
}

// clientCertificate returns the account of the client certificate the
// request's TLS connection presented, if a user has its fingerprint. Caddy
// requests certificates only when the TLS connection policy says so
// (client_auth); Go's TLS has checked that the client holds the key. A
// request-only TLS policy does not validate the certificate's lifetime or
// purpose, so a pinned identity must check those here as well.
func (h *Handler) clientCertificate(r *http.Request) (account, bool) {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return account{}, false
	}
	cert := r.TLS.PeerCertificates[0]
	if cert == nil {
		return account{}, false
	}
	now := time.Now()
	if now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
		return account{}, false
	}
	if cert.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		for _, extension := range cert.Extensions {
			if extension.Id.Equal([]int{2, 5, 29, 15}) {
				return account{}, false
			}
		}
	}
	if len(cert.ExtKeyUsage) != 0 || len(cert.UnknownExtKeyUsage) != 0 {
		clientAuth := false
		for _, usage := range cert.ExtKeyUsage {
			if usage == x509.ExtKeyUsageClientAuth || usage == x509.ExtKeyUsageAny {
				clientAuth = true
				break
			}
		}
		if !clientAuth {
			return account{}, false
		}
	}
	return h.auth.verifyCertificate(sha256.Sum256(cert.Raw))
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

// refuseMalformed may send an error response before reporting the mandatory
// stream error (RFC 9113 §8.1.1, RFC 9114 §4.1.2). HTTP/3 aborts both directions
// because CancelRead cannot report the error after the request's FIN has been
// consumed. Its optional response may be discarded by the write reset.
// HTTP/1.1 closes after sending its error response.
func (h *Handler) refuseMalformed(w http.ResponseWriter, r *http.Request, why *refusal) error {
	if r.ProtoMajor == 1 {
		w.Header().Set("Connection", "close")
	}
	_ = h.refuse(w, r, why)
	resetMalformedRequest(w, r)
	return nil
}

func resetMalformedRequest(w http.ResponseWriter, r *http.Request) {
	base := baseWriter(w)
	switch r.ProtoMajor {
	case 2:
		_ = http.NewResponseController(w).Flush()
		if resetter, ok := base.(interface{ ResetStream(uint32) error }); ok {
			_ = resetter.ResetStream(1) // PROTOCOL_ERROR
		} else {
			panic(http.ErrAbortHandler)
		}
	case 3:
		if str := requestStream(base); str != nil {
			str.CancelRead(h3MessageError)
			str.CancelWrite(h3MessageError)
		}
	}
}

func (h *Handler) serveTCP(ctx context.Context, w http.ResponseWriter, r *http.Request,
	addrs []netip.AddrPort, log *zap.Logger, start time.Time, established func() bool, budget *trafficBudget) error {
	conn, err := dialTCP(ctx, addrs, time.Duration(h.ConnectTimeout))
	if err != nil {
		return h.refuse(w, r, dialRefusal(err))
	}
	cc, err := establish(ctx, w, r, "HTTP/1.1 200 OK\r\n\r\n")
	established()
	if err != nil {
		conn.Close()
		log.Debug("could not start the tunnel", zap.Error(err))
		return nil
	}
	up, down, why, aborted := pumpTCPLimited(ctx, cc, conn, budget)
	h.logEnd(log, "tcp", start, up, down, ctx, why, aborted)
	if aborted {
		cc.abort(why)
	} else {
		cc.close()
	}
	return nil
}

func (h *Handler) serveUDP(ctx context.Context, w http.ResponseWriter, r *http.Request,
	addrs []netip.AddrPort, log *zap.Logger, start time.Time, established func() bool, budget *trafficBudget) error {
	sock, err := dialUDP(addrs)
	if err != nil {
		return h.refuse(w, r, dialRefusal(err))
	}
	datagrams := r.ProtoMajor == 3 && datagramsNegotiated(ctx, baseWriter(w))
	w.Header().Set("Capsule-Protocol", "?1")
	cc, err := establish(ctx, w, r,
		"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: connect-udp\r\nCapsule-Protocol: ?1\r\n\r\n")
	established()
	if err != nil {
		sock.Close()
		log.Debug("could not start the tunnel", zap.Error(err))
		return nil
	}
	u := &udpTunnel{cc: cc, sock: sock, idle: time.Duration(h.UDPIdleTimeout), budget: budget}
	if datagrams {
		u.h3 = cc.(*h3Client).str
	}
	up, down, why, aborted := u.run(ctx)
	if n := u.dropped.Load(); n > 0 {
		log.Debug("UDP payloads dropped by per-user traffic budget", zap.Int64("dropped", n))
	}
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
func establish(ctx context.Context, w http.ResponseWriter, r *http.Request, h1Response string) (clientConn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	// Website middleware can populate these fields before the relay runs.
	// Tunnel bytes carry no HTTP content (RFC 9110 §9.3.6, RFC 9297 §3.2).
	w.Header().Del("Content-Length")
	w.Header().Del("Content-Type")
	w.Header().Del("Transfer-Encoding")
	base := baseWriter(w)
	switch r.ProtoMajor {
	case 1:
		conn, brw, err := http.NewResponseController(base).Hijack()
		if err != nil {
			return nil, err
		}
		_ = conn.SetDeadline(time.Time{})
		cc := &h1Client{conn: conn, r: brw.Reader}
		if err := pendingClientIO(ctx, cc, func() error {
			_, err := conn.Write([]byte(h1Response))
			return err
		}); err != nil {
			conn.Close()
			return nil, err
		}
		return cc, nil
	case 2:
		rc := http.NewResponseController(base)
		cc := &h2Client{body: rawBody(r.Body), w: base, rc: rc, done: r.Context().Done()}
		if err := pendingClientIO(ctx, cc, func() error {
			w.WriteHeader(http.StatusOK)
			return http.NewResponseController(w).Flush()
		}); err != nil {
			return nil, err
		}
		clearDeadlines(rc)
		return cc, nil
	case 3:
		streamer, ok := base.(http3.HTTPStreamer)
		if !ok {
			return nil, errHijackFailed
		}
		str := requestStream(base)
		if str == nil {
			return nil, errHijackFailed
		}
		conn, _ := r.Context().Value(quicConnKey{}).(*quic.Conn)
		guard, _ := r.Context().Value(datagramGuardKey{}).(*datagramGuard)
		cc := &h3Client{str: str, body: newH3Body(str, conn, guard)}
		if err := pendingClientIO(ctx, cc, func() error {
			w.WriteHeader(http.StatusOK)
			_ = streamer.HTTPStream()
			return nil
		}); err != nil {
			return nil, err
		}
		_ = str.SetDeadline(time.Time{})
		return cc, nil
	}
	return nil, errHijackFailed
}

// Success headers can block on client flow control before the tunnel pump
// starts. Interrupt only transport-owned I/O from the cancellation callback,
// and join that callback before the handler can return or reuse its writer.
func pendingClientIO(ctx context.Context, cc clientConn, write func() error) (err error) {
	if err := ctx.Err(); err != nil {
		interruptClient(cc, abortCancelled)
		return err
	}
	interrupted := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		defer close(interrupted)
		interruptClient(cc, abortCancelled)
	})
	defer func() {
		stopped := stop()
		if !stopped {
			<-interrupted
		}
		if ctxErr := ctx.Err(); ctxErr != nil {
			if stopped {
				interruptClient(cc, abortCancelled)
			}
			err = ctxErr
		}
	}()
	return write()
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
	suppressed, allowed := diagnosticLogs.allow()
	if !allowed {
		return
	}
	headers := make(map[string]string, len(r.Header))
	for name, values := range r.Header {
		v := strings.Join(values, ", ")
		canonical := http.CanonicalHeaderKey(name)
		if canonical == "Authorization" || canonical == "Proxy-Authorization" {
			user, _, ok := parseBasic(v)
			if ok {
				v = "Basic (user " + strconv.Quote(user) + ")"
			} else {
				v = "(hidden)"
			}
		} else if canonical == "Cookie" || canonical == "Set-Cookie" ||
			strings.Contains(strings.ToLower(name), "token") || strings.Contains(strings.ToLower(name), "api-key") {
			v = "(hidden)"
		}
		headers[name] = v
	}
	h.logger.Info("relay request",
		zap.String("proto", r.Proto), zap.String("method", r.Method), zap.String("host", r.Host),
		zap.String("path", r.URL.RequestURI()), zap.Bool("udp", kind == udpRequest),
		zap.Bool("authenticated", authenticated), zap.Any("headers", headers), zap.Uint64("suppressed", suppressed),
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
