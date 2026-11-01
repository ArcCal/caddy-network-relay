package networkrelay

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"go.uber.org/zap"
)

func TestAppExitNotifiesHTTP3PeersBeforeClosingEndpoint(t *testing.T) {
	cert, err := tls.X509KeyPair([]byte(pki().certPEM), []byte(pki().keyPEM))
	if err != nil {
		t.Fatal(err)
	}
	srv := &http3.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})}
	tlsConfig := http3.ConfigureTLSConfig(&tls.Config{Certificates: []tls.Certificate{cert}})
	ep, err := acquireEndpoint("udp", "127.0.0.1:0", endpointUser{srv, tlsConfig}, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	a := &App{servers: []*relayServer{{h3: srv, endpoints: []*endpoint{ep}}}}
	t.Cleanup(func() { a.stopLocked(true) })
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := quic.DialAddr(ctx, ep.conn.LocalAddr().String(), &tls.Config{
		RootCAs: pki().pool, ServerName: "relay.test", NextProtos: []string{http3.NextProtoH3},
	}, &quic.Config{MaxIdleTimeout: 2 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.CloseWithError(0, "")
	transport := &http3.Transport{}
	client := transport.NewClientConn(conn)
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://relay.test/", nil)
	rsp, err := client.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(io.Discard, rsp.Body); err != nil {
		t.Fatal(err)
	}
	_ = rsp.Body.Close()

	a.stopLocked(true)
	select {
	case <-conn.Context().Done():
		var closed *quic.ApplicationError
		if err := context.Cause(conn.Context()); !errors.As(err, &closed) ||
			!closed.Remote || closed.ErrorCode != quic.ApplicationErrorCode(http3.ErrCodeNoError) {
			t.Fatalf("expected a remote H3_NO_ERROR close, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("HTTP/3 peer was left waiting for its idle timeout after app exit")
	}
}
