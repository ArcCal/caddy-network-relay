package networkrelay

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(new(App))
}

// App serves HTTP/3 for the HTTP servers that contain a network_relay
// handler. It is set up automatically; there is nothing to configure.
//
// Caddy's own HTTP/3 server does not enable HTTP Datagrams (RFC 9297),
// which CONNECT-UDP relies on, so for those servers the relay takes over
// HTTP/3: it listens on the same UDP ports Caddy would have used, with
// Caddy's certificates, and hands every request to the same Caddy server.
type App struct {
	mu       sync.Mutex
	servers  []*relayServer
	ctx      caddy.Context
	logger   *zap.Logger
	relayIDs map[string]struct{}
}

func (a *App) claimRelayID(id string) error {
	if id == "" {
		return nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.relayIDs == nil {
		a.relayIDs = make(map[string]struct{})
	}
	if _, exists := a.relayIDs[id]; exists {
		return fmt.Errorf("relay_id %q is used by multiple handlers; each security domain needs a unique ID", id)
	}
	a.relayIDs[id] = struct{}{}
	return nil
}

// CaddyModule returns the Caddy module information.
func (*App) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "network_relay",
		New: func() caddy.Module { return new(App) },
	}
}

// Provision sets up the app.
func (a *App) Provision(ctx caddy.Context) error {
	a.ctx = ctx
	a.logger = ctx.Logger()
	return nil
}

// relayServer is a Caddy HTTP server with at least one relay handler.
type relayServer struct {
	srv       *caddyhttp.Server
	h3Listen  []string // listen addresses on which Caddy would serve HTTP/3
	h3        *http3.Server
	endpoints []*endpoint
	ports     atomic.Pointer[map[int]bool] // UDP ports serving HTTP/3
}

// altSvc returns the Alt-Svc header advertising HTTP/3 for a request that
// arrived over TCP, if HTTP/3 is served on the same port.
func (s *relayServer) altSvc(r *http.Request) string {
	ports := s.ports.Load()
	if ports == nil {
		return ""
	}
	if port := localPort(r); (*ports)[port] {
		return altSvcValue(port)
	}
	return ""
}

// addServer is called while the HTTP app provisions srv, before it
// starts: it turns off Caddy's HTTP/3 for srv, which this app serves
// instead.
func (a *App) addServer(srv *caddyhttp.Server) *relayServer {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, s := range a.servers {
		if s.srv == srv {
			return s
		}
	}
	s := &relayServer{srv: srv}
	if srv.ReadHeaderTimeout <= 0 {
		srv.ReadHeaderTimeout = caddy.Duration(10 * time.Second)
	}
	if srv.MaxHeaderBytes <= 0 {
		srv.MaxHeaderBytes = 32 << 10
	}
	for i, addr := range srv.Listen {
		protocols := &srv.Protocols
		if i < len(srv.ListenProtocols) && srv.ListenProtocols[i] != nil {
			protocols = &srv.ListenProtocols[i]
		}
		if hasProtocol(*protocols, "h3") {
			s.h3Listen = append(s.h3Listen, addr)
		}
	}
	srv.Protocols = withoutProtocol(srv.Protocols, "h3")
	for i := range srv.ListenProtocols {
		if srv.ListenProtocols[i] != nil {
			srv.ListenProtocols[i] = withoutProtocol(srv.ListenProtocols[i], "h3")
		}
	}
	// Per-connection state for the limits on new credentials (HTTP/1.1 and
	// HTTP/2; HTTP/3 connections get theirs in withQUICConn).
	srv.RegisterConnContext(func(ctx context.Context, _ net.Conn) context.Context { return withConnState(ctx) })
	// Caddy waits for open requests when it exits; tunnels would keep it
	// waiting forever.
	srv.RegisterOnShutdown(func() {
		if caddy.Exiting() {
			closeAllTunnels()
		}
	})
	a.servers = append(a.servers, s)
	return s
}

func hasProtocol(list []string, p string) bool {
	for _, x := range list {
		if x == p {
			return true
		}
	}
	return false
}

func withoutProtocol(list []string, p string) []string {
	out := make([]string, 0, len(list))
	for _, x := range list {
		if x != p {
			out = append(out, x)
		}
	}
	return out
}

// Start starts serving HTTP/3.
func (a *App) Start() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, s := range a.servers {
		if len(s.h3Listen) == 0 {
			continue
		}
		if len(s.srv.TLSConnPolicies) == 0 {
			a.logger.Warn("server has no TLS; not serving HTTP/3", zap.String("server", s.srv.Name()))
			continue
		}
		tlsConf := http3.ConfigureTLSConfig(s.srv.TLSConnPolicies.TLSConfig(a.ctx))
		s.h3 = &http3.Server{
			Handler:           h3Handler{next: s.srv},
			ConnContext:       withQUICConn,
			EnableDatagrams:   true,
			MaxHeaderBytes:    s.srv.MaxHeaderBytes,
			ReadHeaderTimeout: time.Duration(s.srv.ReadHeaderTimeout),
			IdleTimeout:       time.Duration(s.srv.IdleTimeout),
		}
		ports := map[int]bool{}
		if s.h3.ReadHeaderTimeout <= 0 {
			s.h3.ReadHeaderTimeout = 10 * time.Second
		}
		if s.h3.MaxHeaderBytes <= 0 {
			s.h3.MaxHeaderBytes = 32 << 10
		}
		for _, addr := range s.h3Listen {
			na, err := caddy.ParseNetworkAddressWithDefaults(addr, "tcp", 443)
			if err != nil {
				return fmt.Errorf("server %s: %v", s.srv.Name(), err)
			}
			network, ok := udpNetwork(na.Network)
			if !ok {
				continue
			}
			for port := na.StartPort; port <= na.EndPort; port++ {
				hostport := net.JoinHostPort(na.Host, strconv.Itoa(int(port)))
				ep, err := acquireEndpoint(network, hostport, endpointUser{s.h3, tlsConf}, a.logger)
				if err != nil {
					// The previous configuration keeps running (and its
					// tunnels stay open); only undo what this one started.
					a.stopLocked(false)
					return fmt.Errorf("HTTP/3 for server %s: %v", s.srv.Name(), err)
				}
				s.endpoints = append(s.endpoints, ep)
				ports[int(port)] = true
				a.logger.Info("serving HTTP/3 with datagrams", zap.String("server", s.srv.Name()),
					zap.String("address", network+"/"+hostport))
			}
		}
		s.ports.Store(&ports)
	}
	return nil
}

func udpNetwork(network string) (string, bool) {
	switch network {
	case "tcp", "udp":
		return "udp", true
	case "tcp4", "udp4":
		return "udp4", true
	case "tcp6", "udp6":
		return "udp6", true
	}
	return "", false
}

// Stop stops serving HTTP/3. On a config reload, connections that are
// already open finish with the old configuration, like Caddy's own
// servers; new connections go to the new configuration.
func (a *App) Stop() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.stopLocked(caddy.Exiting())
	return nil
}

func (a *App) stopLocked(exiting bool) {
	for _, s := range a.servers {
		for _, ep := range s.endpoints {
			ep.release(s.h3)
		}
		s.endpoints = nil
		if s.h3 == nil {
			continue
		}
		if exiting {
			closeAllTunnels()
			_ = s.h3.Close()
		} else {
			go s.h3.Shutdown(context.Background())
		}
	}
}

// endpoint is a UDP socket with a QUIC listener. It outlives config
// reloads, so the socket never has to be closed and reopened (which would
// fail while the old configuration still holds it); each new connection
// goes to the HTTP/3 server of the newest configuration.
type endpoint struct {
	key  string
	conn net.PacketConn
	tr   *quic.Transport
	ln   *quic.EarlyListener
	// users holds one entry per configuration using the endpoint, oldest
	// first; the newest one gets new connections. Guarded by endpoints.
	users   []endpointUser
	logger  *zap.Logger
	closing bool
	closed  chan struct{}
}

type endpointUser struct {
	server *http3.Server
	tls    *tls.Config
}

// current returns the newest configuration's server and TLS config; false
// once the last one was released, which can happen while a connection is
// being accepted or a handshake is under way.
func (ep *endpoint) current() (endpointUser, bool) {
	endpoints.Lock()
	defer endpoints.Unlock()
	if len(ep.users) == 0 {
		return endpointUser{}, false
	}
	return ep.users[len(ep.users)-1], true
}

var errEndpointClosed = errors.New("HTTP/3 is no longer served on this address")

var endpoints = struct {
	sync.Mutex
	m map[string]*endpoint
}{m: map[string]*endpoint{}}

// Process-wide admission, including old configurations during reload.
var h3Connections = make(chan struct{}, 1024)

// Start at QUIC's minimum datagram size and let path MTU discovery grow
// packets. The inner datagram size must not dictate the outer handshake
// size: an IPv6 minimum-MTU path cannot carry a 1350-byte UDP payload.
// No 0-RTT: a replayed CONNECT would open a second tunnel.
func quicConfig() *quic.Config {
	return &quic.Config{
		EnableDatagrams:                true,
		InitialPacketSize:              1200,
		MaxIncomingStreams:             1024,
		MaxIncomingUniStreams:          16,
		InitialStreamReceiveWindow:     1 << 20,
		MaxStreamReceiveWindow:         4 << 20,
		InitialConnectionReceiveWindow: 4 << 20,
		MaxConnectionReceiveWindow:     32 << 20,
		MaxIdleTimeout:                 5 * time.Minute,
		// QUIC closes a connection after MaxIdleTimeout without packets,
		// whatever streams are open; tunnels can be idle for longer (an
		// idle TCP connection inside the relay). TCP keepalives do the same
		// for HTTP/2 connections (Go sends them every 15 seconds).
		KeepAlivePeriod: 30 * time.Second,
	}
}

// acquireEndpoint opens the endpoint for network/hostport, or reuses the
// one an earlier configuration opened, and makes u the server for new
// connections until it is released.
func acquireEndpoint(network, hostport string, u endpointUser, logger *zap.Logger) (*endpoint, error) {
	key := network + "/" + hostport
	endpoints.Lock()
	for ep := endpoints.m[key]; ep != nil && ep.closing; ep = endpoints.m[key] {
		closed := ep.closed
		endpoints.Unlock()
		<-closed
		endpoints.Lock()
	}
	defer endpoints.Unlock()
	if ep, ok := endpoints.m[key]; ok {
		ep.users = append(ep.users, u)
		return ep, nil
	}
	conn, err := net.ListenPacket(network, hostport)
	if err != nil {
		return nil, fmt.Errorf("%v (is something else, such as Caddy's own HTTP/3, using this UDP port?)", err)
	}
	ep := &endpoint{key: key, conn: conn, users: []endpointUser{u}, logger: logger, closed: make(chan struct{})}
	ep.tr = &quic.Transport{Conn: conn}
	ep.ln, err = ep.tr.ListenEarly(&tls.Config{
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			u, ok := ep.current()
			if !ok {
				return nil, errEndpointClosed
			}
			c := u.tls
			if c.GetConfigForClient != nil {
				return c.GetConfigForClient(hello)
			}
			return c, nil
		},
	}, quicConfig())
	if err != nil {
		conn.Close()
		return nil, err
	}
	endpoints.m[key] = ep
	go ep.accept()
	return ep, nil
}

func (ep *endpoint) accept() {
	for {
		conn, err := ep.ln.Accept(context.Background())
		if err != nil {
			return
		}
		u, ok := ep.current()
		if !ok {
			_ = conn.CloseWithError(quic.ApplicationErrorCode(http3.ErrCodeNoError), "")
			return
		}
		s := u.server
		select {
		case h3Connections <- struct{}{}:
		default:
			_ = conn.CloseWithError(quic.ApplicationErrorCode(http3.ErrCodeExcessiveLoad), "connection limit")
			continue
		}
		go func() {
			defer func() { <-h3Connections }()
			if err := s.ServeQUICConn(conn); err == http.ErrServerClosed {
				_ = conn.CloseWithError(quic.ApplicationErrorCode(http3.ErrCodeNoError), "")
			}
		}()
	}
}

// release removes s; new connections go to the newest remaining server.
// Removing the last one closes the socket.
func (ep *endpoint) release(s *http3.Server) {
	endpoints.Lock()
	if ep.closing {
		endpoints.Unlock()
		return
	}
	found := false
	for i, u := range ep.users {
		if u.server == s {
			ep.users = append(ep.users[:i], ep.users[i+1:]...)
			found = true
			break
		}
	}
	if !found || len(ep.users) > 0 {
		endpoints.Unlock()
		return
	}
	ep.closing = true
	endpoints.Unlock()
	// Closing a transport can wait for TLS callbacks, which call current
	// and need endpoints' lock. Never close while holding that lock.
	ep.ln.Close()
	ep.tr.Close()
	ep.conn.Close()
	endpoints.Lock()
	delete(endpoints.m, ep.key)
	close(ep.closed)
	endpoints.Unlock()
}

// Interface guards
var (
	_ caddy.App         = (*App)(nil)
	_ caddy.Provisioner = (*App)(nil)
)
