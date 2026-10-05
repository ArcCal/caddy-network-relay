package networkrelay

import (
	"testing"
	"time"
)

// Exercise independent connections on one server: each malformed datagram
// wakes tunnel cleanup while the guard resets both directions. Reusing the
// verified account keeps this a reset race test rather than a hash benchmark.
func TestReviewH3DatagramResetPreservesBothDirections(t *testing.T) {
	port, _ := startRelay(t, nil, nil)
	target := echoTCP(t)
	for i := range 32 {
		h := dialRawH3(t, port)
		str, br, rsp := h.request(connectTCPFields(target))
		if rsp.status != "200" {
			t.Fatal(rsp.status)
		}
		h.datagram(str, []byte("not allowed"))
		if _, err := readData(t, br, 1); streamCode(err) != h3DatagramError {
			t.Fatalf("connection %d response reset: %v", i, err)
		}
		select {
		case <-str.Context().Done():
		case <-time.After(2 * time.Second):
			t.Fatalf("connection %d request direction remained open", i)
		}
		if _, err := str.Write([]byte("after reset")); streamCode(err) != h3DatagramError {
			t.Fatalf("connection %d request reset: %v", i, err)
		}
		_ = h.conn.CloseWithError(0, "")
	}
}
