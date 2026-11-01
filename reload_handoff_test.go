package networkrelay

import (
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
)

// Hold an actual listener close in progress to expose a reload returning
// before net/http has stopped accepting on the retiring configuration.
type reloadCloseGate struct {
	entered chan struct{}
	release chan struct{}
	closed  chan struct{}
}

var reloadCloseGates sync.Map

type reloadGateWrapper struct {
	Gate string `json:"gate,omitempty"`
}

func init() { caddy.RegisterModule(reloadGateWrapper{}) }

func (reloadGateWrapper) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "caddy.listeners.test_relay_reload_gate",
		New: func() caddy.Module { return new(reloadGateWrapper) },
	}
}

func (w *reloadGateWrapper) WrapListener(ln net.Listener) net.Listener {
	if gate, ok := reloadCloseGates.Load(w.Gate); ok {
		return &reloadGateListener{Listener: ln, gate: gate.(*reloadCloseGate)}
	}
	return ln
}

type reloadGateListener struct {
	net.Listener
	gate *reloadCloseGate
}

func (ln *reloadGateListener) Close() error {
	close(ln.gate.entered)
	<-ln.gate.release
	err := ln.Listener.Close()
	close(ln.gate.closed)
	return err
}

func TestReloadWaitsForRetiringTCPListener(t *testing.T) {
	gate := &reloadCloseGate{make(chan struct{}), make(chan struct{}), make(chan struct{})}
	name := t.Name()
	reloadCloseGates.Store(name, gate)
	defer reloadCloseGates.Delete(name)
	release := sync.OnceFunc(func() { close(gate.release) })
	defer release()
	server := map[string]any{"listener_wrappers": []any{map[string]any{
		"wrapper": "test_relay_reload_gate", "gate": name,
	}}}
	port, _ := startRelay(t, nil, server)
	target := echoTCP(t)
	ctx := testCtx(t)
	var old []stream
	for _, v := range versions {
		s, done, err := v.openTCP(ctx, client(port), target)
		if err != nil {
			t.Fatal(err)
		}
		defer done()
		defer s.Close()
		old = append(old, s)
	}
	// Only the old listener is gated. Add an account so fresh requests also
	// prove that the new generation handles them after reload returns.
	server["listener_wrappers"] = nil
	users := map[string]any{"users": []map[string]string{
		{"name": "alice", "password_hash": testHash},
		{"name": "bob", "password_hash": testHash},
	}}
	loaded := make(chan error, 1)
	go func() { loaded <- caddy.Load(relayConfig(port, users, server), true) }()
	select {
	case <-gate.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("retiring listener did not begin closing")
	}
	returned := false
	select {
	case err := <-loaded:
		returned = true
		t.Errorf("reload returned while its old listener was still open: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	release()
	if !returned {
		select {
		case err := <-loaded:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("reload did not finish after listener closure")
		}
	}
	select {
	case <-gate.closed:
	case <-time.After(5 * time.Second):
		t.Fatal("retiring listener did not close")
	}
	check := func(t *testing.T, s stream) {
		t.Helper()
		if _, err := s.Write([]byte("ping")); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 4)
		if _, err := io.ReadFull(s, buf); err != nil || string(buf) != "ping" {
			t.Fatalf("tunnel after reload: %q, %v", buf, err)
		}
	}
	for _, s := range old {
		check(t, s)
	}
	for _, v := range versions {
		t.Run(v.name, func(t *testing.T) {
			c := client(port)
			c.Authorization = BasicAuthorization("bob", testPassword)
			s, done, err := v.openTCP(ctx, c, target)
			if err != nil {
				t.Fatal(err)
			}
			defer done()
			defer s.Close()
			check(t, s)
		})
	}
}
