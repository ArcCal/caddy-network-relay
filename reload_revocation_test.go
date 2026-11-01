package networkrelay

import (
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// logEnd runs after the canceled pump joins its workers but before the
// client transport is reset. Pause there to make incomplete revocation
// observable independently of scheduler timing.
type reloadEndLogGate struct {
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (g *reloadEndLogGate) Write(p []byte) (int, error) {
	if strings.Contains(string(p), "tunnel closed") {
		g.once.Do(func() { close(g.entered); <-g.release })
	}
	return len(p), nil
}

func TestReloadWaitsForRevokedTunnelTransport(t *testing.T) {
	port, _ := startRelay(t, nil, nil)
	gate := &reloadEndLogGate{entered: make(chan struct{}), release: make(chan struct{})}
	release := sync.OnceFunc(func() { close(gate.release) })
	defer release()
	// No requests have started yet. Only the old handler gets the gate;
	// the next configuration keeps its ordinary logger.
	registry.Lock()
	for h := range registry.handlers {
		if h.RelayID == "test-relay-"+strconv.Itoa(port) {
			h.logger = zap.New(zapcore.NewCore(zapcore.NewJSONEncoder(zap.NewProductionEncoderConfig()), zapcore.AddSync(gate), zapcore.DebugLevel))
		}
	}
	registry.Unlock()
	old, done, err := versions[0].openTCP(testCtx(t), client(port), echoTCP(t))
	if err != nil {
		t.Fatal(err)
	}
	defer done()
	defer old.Close()
	loaded := make(chan error, 1)
	go func() {
		loaded <- caddy.Load(relayConfig(port, map[string]any{"users": []map[string]string{}}, nil), true)
	}()
	select {
	case <-gate.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("revoked tunnel did not begin cleanup")
	}
	returned := false
	select {
	case err := <-loaded:
		returned = true
		t.Errorf("reload returned before the revoked client transport closed: %v", err)
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
			t.Fatal("reload did not finish after tunnel cleanup")
		}
	}
	_ = old.(*h3Stream).SetReadDeadline(time.Now().Add(2 * time.Second))
	_, err = io.ReadFull(old, make([]byte, 1))
	if err == nil {
		t.Fatal("revoked tunnel delivered data")
	}
	if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
		t.Fatalf("revoked client transport remained open: %v", err)
	}
}
