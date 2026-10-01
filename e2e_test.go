package networkrelay

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"os"
	"strconv"
	"testing"
	"time"
)

// TestRealServerHTTP3 moves a large amount of data through a relay that
// is already running (the real caddy binary), over HTTP/3. It is skipped
// unless RELAY_E2E_PORT, RELAY_E2E_CA (PEM file) and RELAY_E2E_PASSWORD
// are set; RELAY_E2E_USER defaults to alice, RELAY_E2E_MB to 200.
func TestRealServerHTTP3(t *testing.T) {
	port, _ := strconv.Atoi(os.Getenv("RELAY_E2E_PORT"))
	if port == 0 {
		t.Skip("RELAY_E2E_PORT not set")
	}
	pem, err := os.ReadFile(os.Getenv("RELAY_E2E_CA"))
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(pem)
	user := os.Getenv("RELAY_E2E_USER")
	if user == "" {
		user = "alice"
	}
	mb, _ := strconv.Atoi(os.Getenv("RELAY_E2E_MB"))
	if mb == 0 {
		mb = 200
	}
	size := int64(mb) << 20
	sink := newSinkServer(t, 2, size)
	c := &relayClient{Address: "127.0.0.1:" + strconv.Itoa(port), Server: "relay.test", Port: port,
		Authorization: BasicAuthorization(user, os.Getenv("RELAY_E2E_PASSWORD")), TLS: &tls.Config{RootCAs: pool}}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	h, err := c.dialH3(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	for i := 0; i < 2; i++ {
		s, err := c.openTCPH3(ctx, h, sink.addr)
		if err != nil {
			t.Fatal(err)
		}
		start := time.Now()
		up, down := transfer(t, s, 1, size, sink)
		s.Close()
		if up != patternHash(1, size) || down != patternHash(2, size) {
			t.Fatal("corrupted")
		}
		t.Logf("HTTP/3 to the real server: %d MiB each way in %v", mb, time.Since(start).Round(time.Millisecond))
	}
}
