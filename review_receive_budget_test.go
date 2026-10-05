package networkrelay

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"golang.org/x/net/http2"
)

type reviewObservedReceiveBudget struct {
	*receiveBufferBudget
	peak atomic.Int64
}

func (b *reviewObservedReceiveBudget) TryAcquire(n int64) bool {
	if !b.receiveBufferBudget.TryAcquire(n) {
		return false
	}
	used := b.used.Load()
	for peak := b.peak.Load(); used > peak; peak = b.peak.Load() {
		if b.peak.CompareAndSwap(peak, used) {
			break
		}
	}
	return true
}

func reviewWaitReceiveBudget(t *testing.T, b *reviewObservedReceiveBudget, want int64) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for b.used.Load() != want {
		if time.Now().After(deadline) {
			t.Fatalf("receive buffers retain %d bytes, want %d (cap %d)", b.used.Load(), want, b.limit)
		}
		time.Sleep(time.Millisecond)
	}
	if b.peak.Load() > b.limit {
		t.Fatalf("receive buffers exceeded shared cap: peak %d, cap %d", b.peak.Load(), b.limit)
	}
}

func reviewBudgetH2Server(t *testing.T, budget http2.ReceiveBufferBudget, handler http.Handler) int {
	t.Helper()
	cert, err := tls.X509KeyPair([]byte(pki().certPEM), []byte(pki().keyPEM))
	if err != nil {
		t.Fatal(err)
	}
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert}, NextProtos: []string{http2.NextProtoTLS},
	})
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var accepted net.Conn
	closing := false
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		mu.Lock()
		if closing {
			mu.Unlock()
			_ = conn.Close()
			return
		}
		accepted = conn
		mu.Unlock()
		defer conn.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := conn.(*tls.Conn).HandshakeContext(ctx); err != nil {
			return
		}
		server := &http2.Server{
			ReceiveBufferBudget: budget, MaxUploadBufferPerStream: 1 << 20, MaxUploadBufferPerConnection: 1 << 20,
		}
		server.ServeConn(conn, &http2.ServeConnOpts{Handler: handler})
	}()
	t.Cleanup(func() {
		_ = listener.Close()
		mu.Lock()
		closing = true
		if accepted != nil {
			_ = accepted.Close()
		}
		mu.Unlock()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Error("HTTP/2 fixture did not stop")
		}
	})
	_, port, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	n, err := strconv.Atoi(port)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func reviewBudgetH2Response(t *testing.T, r *rawH2, streamID uint32) []byte {
	t.Helper()
	var body []byte
	for {
		switch f := r.next(streamID).(type) {
		case *http2.DataFrame:
			body = append(body, f.Data()...)
			if f.StreamEnded() {
				return body
			}
		case *http2.MetaHeadersFrame:
			if f.StreamEnded() {
				return body
			}
		case *http2.RSTStreamFrame:
			t.Fatalf("HTTP/2 stream %d reset unexpectedly: %v", streamID, f.ErrCode)
		}
	}
}

func TestReviewSharedReceiveBudgetAcrossHTTP2AndHTTP3(t *testing.T) {
	budget := &reviewObservedReceiveBudget{receiveBufferBudget: &receiveBufferBudget{limit: 128 << 10}}
	readAllowed := make(chan struct{})
	releaseRead := sync.OnceFunc(func() { close(readAllowed) })
	defer releaseRead()
	cancelled := make(chan struct{})
	finClosed := make(chan struct{})
	type bodyResult struct {
		data []byte
		err  error
	}
	finBody := make(chan bodyResult, 1)
	h2Handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		if r.Host == "cancel.test:443" {
			<-r.Context().Done()
			close(cancelled)
			return
		}
		if r.Host == "hold.test:443" {
			context.AfterFunc(r.Context(), func() { close(finClosed) })
			if err := w.(interface{ CloseWrite() error }).CloseWrite(); err != nil {
				finBody <- bodyResult{err: err}
				return
			}
			// Both directional FINs close the stream's HTTP context, but
			// the body must remain readable by the handler until it finishes.
			<-readAllowed
			data, err := io.ReadAll(r.Body)
			finBody <- bodyResult{data, err}
			return
		}
		data, err := io.ReadAll(r.Body)
		if err == nil {
			sum := sha256.Sum256(data)
			_, _ = w.Write(sum[:])
		}
	})
	port := reviewBudgetH2Server(t, budget, h2Handler)
	r := dialRawH2(t, port)
	defer r.conn.Close()
	config := quicConfig()
	config.ReceiveBufferBudget = budget
	c := reviewH3ClientServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host == "hold.test:443" {
			w.WriteHeader(http.StatusOK)
			w.(http.Flusher).Flush()
			<-r.Context().Done()
			return
		}
		reviewH3EchoResponse(w, r)
	}), config)
	healthy, err := c.dialH3(testCtx(t))
	if err != nil {
		t.Fatal(err)
	}
	defer healthy.Close()
	offender, err := c.dialH3(testCtx(t))
	if err != nil {
		t.Fatal(err)
	}
	defer offender.Close()
	upload, err := c.openTCPH3(testCtx(t), offender, "hold.test:443")
	if err != nil {
		t.Fatal(err)
	}
	defer upload.Close()
	reviewWaitReceiveBudget(t, budget, 0)
	r.headers(1, connectTCPFields("hold.test:443"))
	if f, ok := r.next(1).(*http2.MetaHeadersFrame); !ok || f.PseudoValue("status") != "200" {
		t.Fatal("held HTTP/2 upload did not establish")
	}
	// FIN returns flow-control credit independently of the unread buffer.
	// The handler must still own every byte, charged to the shared cap.
	payload := bytes.Repeat([]byte("h"), 96<<10)
	for off := 0; off < len(payload); off += 16 << 10 {
		end := off + (16 << 10)
		if err := r.fr.WriteData(1, end == len(payload), payload[off:end]); err != nil {
			t.Fatal(err)
		}
	}
	reviewWaitReceiveBudget(t, budget, int64(len(payload)))
	if got := reviewBudgetH2Response(t, r, 1); len(got) != 0 {
		t.Fatalf("HTTP/2 server FIN contained unexpected body: %x", got)
	}
	select {
	case <-finClosed:
	case <-time.After(time.Second):
		t.Fatal("both directional HTTP/2 FINs did not close the stream context")
	}
	reviewWaitReceiveBudget(t, budget, int64(len(payload)))
	writeDone := make(chan error, 1)
	if err := upload.(*h3Stream).SetWriteDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	go func() {
		_, err := upload.Write(bytes.Repeat([]byte("q"), 256<<10))
		writeDone <- err
	}()
	select {
	case <-offender.conn.Context().Done():
	case <-time.After(3 * time.Second):
		t.Fatal("HTTP/3 upload bypassed the shared receive cap")
	}
	var transportError *quic.TransportError
	if cause := context.Cause(offender.conn.Context()); !errors.As(cause, &transportError) || transportError.ErrorCode != quic.InternalError {
		t.Fatalf("receive pressure closed HTTP/3 with unexpected error: %v", cause)
	}
	select {
	case <-writeDone:
	case <-time.After(time.Second):
		t.Fatal("HTTP/3 writer survived connection teardown")
	}
	reviewWaitReceiveBudget(t, budget, int64(len(payload)))
	if healthy.conn.Context().Err() != nil {
		t.Fatal("receive pressure closed an unrelated HTTP/3 connection")
	}
	releaseRead()
	select {
	case got := <-finBody:
		if got.err != nil || !bytes.Equal(got.data, payload) {
			t.Fatalf("HTTP/2 FIN lost unread data: %d bytes, %v", len(got.data), got.err)
		}
	case <-time.After(time.Second):
		t.Fatal("HTTP/2 FIN body did not remain readable")
	}
	reviewWaitReceiveBudget(t, budget, 0)
	reviewH3EchoTunnel(t, c, healthy)
	reviewWaitReceiveBudget(t, budget, 0)
	// An explicit HTTP/2 cancellation must also discard charged buffers,
	// then leave its connection usable for a fresh request.
	r.headers(3, connectTCPFields("cancel.test:443"))
	if f, ok := r.next(3).(*http2.MetaHeadersFrame); !ok || f.PseudoValue("status") != "200" {
		t.Fatal("cancelled HTTP/2 upload did not establish")
	}
	if err := r.fr.WriteData(3, false, payload[:16<<10]); err != nil {
		t.Fatal(err)
	}
	reviewWaitReceiveBudget(t, budget, 16<<10)
	if err := r.fr.WriteRSTStream(3, http2.ErrCodeCancel); err != nil {
		t.Fatal(err)
	}
	select {
	case <-cancelled:
	case <-time.After(time.Second):
		t.Fatal("HTTP/2 cancellation did not reach the handler")
	}
	reviewWaitReceiveBudget(t, budget, 0)
	r.headers(5, connectTCPFields("healthy.test:443"))
	if f, ok := r.next(5).(*http2.MetaHeadersFrame); !ok || f.PseudoValue("status") != "200" {
		t.Fatal("HTTP/2 connection did not recover after receive pressure")
	}
	const fresh = "the same HTTP/2 connection remains usable"
	if err := r.fr.WriteData(5, true, []byte(fresh)); err != nil {
		t.Fatal(err)
	}
	want := sha256.Sum256([]byte(fresh))
	if got := reviewBudgetH2Response(t, r, 5); !bytes.Equal(got, want[:]) {
		t.Fatalf("HTTP/2 recovery response: %x", got)
	}
	reviewWaitReceiveBudget(t, budget, 0)
}

func TestReviewReceiveBudgetConcurrentCapAndRecovery(t *testing.T) {
	budget := &reviewObservedReceiveBudget{receiveBufferBudget: &receiveBufferBudget{limit: 32 << 10}}
	const workers = 32
	release := make(chan struct{})
	results := make(chan bool, workers)
	var wg sync.WaitGroup
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ok := budget.TryAcquire(4 << 10)
			results <- ok
			<-release
			if ok {
				budget.Release(4 << 10)
			}
		}()
	}
	admitted := 0
	for range workers {
		if <-results {
			admitted++
		}
	}
	used, peak := budget.used.Load(), budget.peak.Load()
	close(release)
	wg.Wait()
	if admitted != 8 || used != budget.limit || peak > budget.limit {
		t.Fatalf("concurrent reservations: admitted %d, used %d, peak %d, cap %d", admitted, used, peak, budget.limit)
	}
	reviewWaitReceiveBudget(t, budget, 0)
	if !budget.TryAcquire(budget.limit) {
		t.Fatal("released receive capacity could not be reused")
	}
	budget.Release(budget.limit)
}

func TestReviewReceiveBudgetTinyMemoryHasNoFloor(t *testing.T) {
	for _, memory := range []uint64{1, 32 << 10, 1 << 20} {
		budget := &receiveBufferBudget{limit: receiveBufferLimit(memory)}
		if budget.TryAcquire(int64(memory/4 + 1)) {
			t.Fatalf("memory=%d admitted more than its receive allowance", memory)
		}
		if n := int64(memory / 4); n > 0 {
			if !budget.TryAcquire(n) {
				t.Fatalf("memory=%d could not use its receive allowance", memory)
			}
			budget.Release(n)
		}
	}
}
