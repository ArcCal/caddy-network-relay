package networkrelay

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"reflect"
	"sync"
	"sync/atomic"
)

var (
	errRevoked = errors.New("user removed or password changed")
	errExpired = errors.New("the account expired")
	errExiting = errors.New("Caddy is exiting")
)

// liveTunnel is an open tunnel. Tunnels outlive the configuration that
// opened them: a config reload keeps them open as long as some handler of
// the new configuration still has the same user with the same password.
type liveTunnel struct {
	acct   account
	owner  *Handler
	cancel context.CancelCauseFunc
}

// registry tracks the provisioned handlers and the open tunnels of the
// whole process, across config reloads.
var registry = struct {
	sync.Mutex
	handlers map[*Handler]struct{}
	tunnels  map[*liveTunnel]struct{}
}{handlers: map[*Handler]struct{}{}, tunnels: map[*liveTunnel]struct{}{}}

// openTunnels counts open tunnels for max_tunnels.
var openTunnels atomic.Int64

func registerHandler(h *Handler) {
	registry.Lock()
	for old := range registry.handlers {
		// TLS policies finish provisioning after HTTP handlers. Sharing a
		// traffic budget needs the declared policy identity; tunnel transfer
		// below additionally checks the effective, provisioned trust roots.
		if sameRelayConfig(old, h) {
			for name := range h.traffic {
				if old.auth.has(h.auth.accountOf(name)) && old.traffic[name] != nil {
					h.traffic[name] = old.traffic[name]
				}
			}
		}
	}
	registry.handlers[h] = struct{}{}
	registry.Unlock()
}

// unregisterHandler hands the handler's tunnels to a handler that still
// accepts their account, and closes the others.
func unregisterHandler(h *Handler) {
	registry.Lock()
	defer registry.Unlock()
	delete(registry.handlers, h)
	for t := range registry.tunnels {
		if t.owner != h {
			continue
		}
		t.owner = nil
		for other := range registry.handlers {
			if sameRelay(h, other) && other.auth.has(t.acct) {
				t.owner = other
				break
			}
		}
		if t.owner == nil {
			t.cancel(errRevoked)
		}
	}
}

// addTunnel registers a tunnel, unless the handler was already replaced by
// a configuration without this account (the user was revoked while the
// tunnel was being set up).
func addTunnel(t *liveTunnel) bool {
	registry.Lock()
	defer registry.Unlock()
	if _, live := registry.handlers[t.owner]; !live {
		old := t.owner
		t.owner = nil
		for other := range registry.handlers {
			if sameRelay(old, other) && other.auth.has(t.acct) {
				t.owner = other
				break
			}
		}
		if t.owner == nil {
			return false
		}
	}
	registry.tunnels[t] = struct{}{}
	return true
}

// Policy changes revoke existing tunnels rather than grandfathering targets
// newly forbidden by the next configuration. An explicit ID is needed: a
// password hash is not a tenant identifier.
func sameRelay(a, b *Handler) bool {
	if !sameRelayConfig(a, b) {
		return false
	}
	if a.tlsCustomVerifiers || b.tlsCustomVerifiers {
		return false
	}
	left, right := relayTLSConfig(a), relayTLSConfig(b)
	if left == nil || right == nil {
		return left == right
	}
	return left.ClientAuth == right.ClientAuth && left.ClientCAs.Equal(right.ClientCAs)
}

func relayTLSConfig(h *Handler) *tls.Config {
	if h.server == nil || h.server.srv == nil {
		return nil
	}
	for _, p := range h.server.srv.TLSConnPolicies {
		if !p.Drop {
			return p.TLSConfig
		}
	}
	return nil
}

func sameRelayConfig(a, b *Handler) bool {
	return a != nil && b != nil && a.RelayID != "" && a.RelayID == b.RelayID &&
		bytes.Equal(a.tlsClientAuth, b.tlsClientAuth) &&
		a.UDPTemplate == b.UDPTemplate &&
		a.MaxBytesPerSecondPerUser == b.MaxBytesPerSecondPerUser &&
		a.MaxUDPPacketsPerSecondPerUser == b.MaxUDPPacketsPerSecondPerUser &&
		reflect.DeepEqual(a.BlockedDestinations, b.BlockedDestinations) &&
		reflect.DeepEqual(a.BlockedPorts, b.BlockedPorts)
}

func removeTunnel(t *liveTunnel) {
	registry.Lock()
	delete(registry.tunnels, t)
	registry.Unlock()
}

// closeAllTunnels ends every tunnel; used when Caddy exits, so that the
// HTTP servers' graceful shutdown does not wait for tunnels forever.
func closeAllTunnels() {
	registry.Lock()
	defer registry.Unlock()
	for t := range registry.tunnels {
		t.cancel(errExiting)
	}
}
