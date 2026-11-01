package networkrelay

import (
	"crypto/tls"
	"io"
	"net"
	"testing"
	"time"
)

func TestH1TLSAbortDoesNotSendCleanShutdown(t *testing.T) {
	cert, err := tls.X509KeyPair([]byte(pki().certPEM), []byte(pki().keyPEM))
	if err != nil {
		t.Fatal(err)
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	done := make(chan error, 1)
	go func() {
		raw, err := l.Accept()
		if err != nil {
			done <- err
			return
		}
		defer raw.Close()
		_ = raw.SetDeadline(time.Now().Add(5 * time.Second))
		conn := tls.Server(raw, &tls.Config{Certificates: []tls.Certificate{cert}})
		if err := conn.Handshake(); err != nil {
			done <- err
			return
		}
		// Model an established tunnel whose destination failed. A TLS
		// close_notify would tell the client this direction ended cleanly.
		(&h1Client{conn: conn}).abort(abortFailed)
		done <- nil
	}()
	client, err := tls.Dial("tcp", l.Addr().String(), &tls.Config{
		RootCAs: pki().pool, ServerName: "relay.test",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	_ = client.SetDeadline(time.Now().Add(5 * time.Second))
	_, readErr := io.ReadAll(client)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if readErr == nil {
		t.Fatal("aborted HTTP/1.1 TLS tunnel ended with a clean EOF")
	}
	if err, ok := readErr.(net.Error); ok && err.Timeout() {
		t.Fatalf("aborted HTTP/1.1 TLS tunnel did not terminate: %v", readErr)
	}
}
