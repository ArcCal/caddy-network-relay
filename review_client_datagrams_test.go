package networkrelay

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

func TestReviewH3ClientMixedDatagramsDrainAfterFIN(t *testing.T) {
	finish := make(chan struct{})
	var finishOnce sync.Once
	c := reviewH3ClientServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host == "echo.test:443" {
			reviewH3EchoResponse(w, r)
			return
		}
		w.Header().Set("Capsule-Protocol", "?1")
		w.WriteHeader(http.StatusOK)
		str := w.(http3.HTTPStreamer).HTTPStream()
		defer str.Close()
		if err := str.SendDatagram(append([]byte{0}, []byte("native")...)); err != nil {
			t.Error(err)
			return
		}
		// A native datagram with an unregistered context must be ignored.
		_ = str.SendDatagram([]byte{1, 'x'})
		for _, payload := range [][]byte{[]byte("capsule"), {}} {
			if _, err := str.Write(appendDatagramCapsule(nil, payload)); err != nil {
				t.Error(err)
				return
			}
		}
		select {
		case <-finish:
		case <-r.Context().Done():
		}
	}), nil)
	t.Cleanup(func() { finishOnce.Do(func() { close(finish) }) })
	h, err := c.dialH3(testCtx(t))
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	p, err := c.openUDPH3(testCtx(t), h, "127.0.0.1", "53")
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	d, ok := p.(*h3Datagrams)
	if !ok {
		t.Fatal("HTTP Datagrams were not negotiated")
	}
	deadline := time.Now().Add(2 * time.Second)
	for len(d.packets) < 3 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if len(d.packets) != 3 {
		t.Fatalf("mixed UDP transports queued %d payloads, want native, capsule and empty capsule", len(d.packets))
	}
	finishOnce.Do(func() { close(finish) })
	select {
	case <-d.done:
	case <-time.After(time.Second):
		t.Fatal("response FIN did not finish both UDP readers")
	}
	seen := map[string]bool{}
	for range 3 {
		payload, err := p.Receive(context.Background())
		if err != nil {
			t.Fatalf("queued payload was lost on FIN: %v", err)
		}
		seen[string(payload)] = true
	}
	if !seen["native"] || !seen["capsule"] || !seen[""] || len(seen) != 3 {
		t.Fatalf("mixed payloads after FIN: %v", seen)
	}
	if _, err := p.Receive(context.Background()); !errors.Is(err, io.EOF) {
		t.Fatalf("drained UDP stream: %v, want EOF", err)
	}
	reviewH3EchoTunnel(t, c, h)
}

func TestReviewH3ClientCapsuleReceiveQueueBounded(t *testing.T) {
	c := reviewH3ClientServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Capsule-Protocol", "?1")
		w.WriteHeader(http.StatusOK)
		str := w.(http3.HTTPStreamer).HTTPStream()
		defer str.Close()
		for i := range 256 {
			if _, err := str.Write(appendDatagramCapsule(nil, []byte(strconv.Itoa(i)))); err != nil {
				return
			}
		}
	}), nil)
	h, err := c.dialH3(testCtx(t))
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	p, err := c.openUDPH3(testCtx(t), h, "127.0.0.1", "53")
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	d := p.(*h3Datagrams)
	select {
	case <-d.done:
	case <-time.After(2 * time.Second):
		t.Fatal("bounded UDP receive queue stopped the stream reader from finishing")
	}
	if got := len(d.packets); got != 64 {
		t.Fatalf("UDP queue retained %d payloads from a 256-packet burst, want its 64-packet bound", got)
	}
	for i := range 64 {
		payload, err := p.Receive(context.Background())
		if err != nil || string(payload) != strconv.Itoa(i) {
			t.Fatalf("queued packet %d: %q, %v", i, payload, err)
		}
	}
	if _, err := p.Receive(context.Background()); !errors.Is(err, io.EOF) {
		t.Fatalf("drained bounded queue: %v, want EOF", err)
	}
}

func TestReviewH3ClientMalformedCapsuleStopsBothReceivers(t *testing.T) {
	c := reviewH3ClientServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Capsule-Protocol", "?1")
		w.WriteHeader(http.StatusOK)
		str := w.(http3.HTTPStreamer).HTTPStream()
		defer str.Close()
		// A context-0 datagram declared larger than the maximum UDP payload.
		if _, err := str.Write(appendDatagramCapsule(nil, make([]byte, maxUDPPayload+1))); err != nil {
			return
		}
		<-str.Context().Done()
	}), &quic.Config{})
	h, err := c.dialH3(testCtx(t))
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	p, err := c.openUDPH3(testCtx(t), h, "127.0.0.1", "53")
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	d := p.(*h3Datagrams)
	select {
	case <-d.done:
	case <-time.After(time.Second):
		t.Fatal("malformed capsule left the native datagram receiver running")
	}
	if _, err := p.Receive(context.Background()); !errors.Is(err, errMalformed) {
		t.Fatalf("malformed capsule: %v", err)
	}
	if h.conn.Context().Err() != nil {
		t.Fatal("malformed UDP capsule closed the shared QUIC connection")
	}
}

func TestReviewH3ClientCloseJoinsUnreadReceivers(t *testing.T) {
	for _, queued := range []bool{false, true} {
		name := "idle peer"
		if queued {
			name = "unread mixed packets"
		}
		t.Run(name, func(t *testing.T) {
			c := reviewH3ClientServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Host == "echo.test:443" {
					reviewH3EchoResponse(w, r)
					return
				}
				w.Header().Set("Capsule-Protocol", "?1")
				w.WriteHeader(http.StatusOK)
				str := w.(http3.HTTPStreamer).HTTPStream()
				defer str.Close()
				if queued {
					_ = str.SendDatagram([]byte{0, 'n'})
					_, _ = str.Write(appendDatagramCapsule(nil, []byte("c")))
				}
				<-str.Context().Done()
			}), nil)
			h, err := c.dialH3(testCtx(t))
			if err != nil {
				t.Fatal(err)
			}
			defer h.Close()
			p, err := c.openUDPH3(testCtx(t), h, "127.0.0.1", "53")
			if err != nil {
				t.Fatal(err)
			}
			defer p.Close()
			d := p.(*h3Datagrams)
			if queued {
				deadline := time.Now().Add(time.Second)
				for len(d.packets) < 2 && time.Now().Before(deadline) {
					time.Sleep(time.Millisecond)
				}
				if len(d.packets) != 2 {
					t.Fatal("peer's mixed packets did not arrive before Close")
				}
			}
			done := make(chan error, 1)
			go func() { done <- p.Close() }()
			select {
			case err := <-done:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(time.Second):
				t.Fatal("Close did not interrupt and join both unread UDP receivers")
			}
			select {
			case <-d.done:
			default:
				t.Fatal("Close returned before both UDP receivers finished")
			}
			reviewH3EchoTunnel(t, c, h)
		})
	}
}
