package networkrelay

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net/http"
	"sync/atomic"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/quic-go/quicvarint"
)

// HTTP/3 connection error codes (RFC 9114 §8.1).
const (
	h3FrameUnexpected quic.ApplicationErrorCode = 0x105
	h3FrameError      quic.ApplicationErrorCode = 0x106
)

var (
	errFrameUnexpected = errors.New("HTTP/3 frame not allowed on a CONNECT stream")
	errFrameTruncated  = errors.New("HTTP/3 stream ended in the middle of a frame")
)

type quicConnKey struct{}

// withQUICConn is the http3.Server's ConnContext: handlers find the QUIC
// connection of a request, to close it on connection errors, and the
// connection's state for the limits on new credentials.
func withQUICConn(ctx context.Context, c *quic.Conn) context.Context {
	return withConnState(context.WithValue(ctx, quicConnKey{}, c))
}

// h3Body reads what the client sends on an HTTP/3 CONNECT stream once the
// tunnel is established. quic-go would accept a trailing HEADERS frame as
// trailers; RFC 9114 §4.4 allows only DATA frames (and extension frames
// that permit it) after CONNECT, and makes any other known frame type a
// connection error of type H3_FRAME_UNEXPECTED. Unknown frame types are
// skipped (§9). A stream that ends cleanly in the middle of a frame is a
// connection error of type H3_FRAME_ERROR (§7.1).
type h3Body struct {
	r         *bufio.Reader
	conn      *quic.Conn // nil if unknown; then only the stream fails
	remaining uint64     // bytes left in the current DATA frame
	guard     *datagramGuard
}

func newH3Body(str *http3.Stream, conn *quic.Conn, guard *datagramGuard) *h3Body {
	return &h3Body{r: bufio.NewReaderSize(str.QUICStream(), 16*1024), conn: conn, guard: guard}
}

// isKnownH3Frame reports frame types defined by RFC 9114 (including the
// reserved HTTP/2 ones, §7.2.8) and RFC 9218, none of which may appear on
// a CONNECT stream after the request.
func isKnownH3Frame(t uint64) bool {
	switch t {
	case 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xd, 0xf0700, 0xf0701:
		return true
	}
	return false
}

func (b *h3Body) fail(code quic.ApplicationErrorCode, err error) (int, error) {
	if b.conn != nil {
		_ = b.conn.CloseWithError(code, "")
	}
	return 0, err
}

func (b *h3Body) Read(p []byte) (int, error) {
	for b.remaining == 0 {
		if _, err := b.r.Peek(1); err != nil {
			if err == io.EOF {
				b.guard.receiveClosed()
			}
			return 0, err // FIN between frames: the client is done sending
		}
		typ, err := quicvarint.Read(b.r)
		if err != nil {
			return b.truncated(err)
		}
		length, err := quicvarint.Read(b.r)
		if err != nil {
			return b.truncated(err)
		}
		switch {
		case typ == 0x0: // DATA
			b.remaining = length
		case isKnownH3Frame(typ):
			return b.fail(h3FrameUnexpected, errFrameUnexpected)
		default:
			if _, err := io.CopyN(io.Discard, b.r, int64(length)); err != nil {
				return b.truncated(err)
			}
		}
	}
	if uint64(len(p)) > b.remaining {
		p = p[:b.remaining]
	}
	n, err := b.r.Read(p)
	b.remaining -= uint64(n)
	if err == io.EOF {
		if n > 0 {
			return n, nil // the truncation is reported by the next call
		}
		return b.truncated(err) // FIN inside a DATA frame
	}
	return n, err
}

func (b *h3Body) truncated(err error) (int, error) {
	if err == io.EOF || err == io.ErrUnexpectedEOF {
		return b.fail(h3FrameError, errFrameTruncated)
	}
	return 0, err
}

// datagramGuard enforces RFC 9297 §2.1 on HTTP/3 requests whose semantics
// do not include HTTP Datagrams (everything but extended CONNECT): an HTTP
// Datagram for such a request aborts its stream with H3_DATAGRAM_ERROR,
// unless the stream's receive side is already closed, in which case it is
// dropped silently.
type datagramGuard struct {
	closed atomic.Bool
	failed atomic.Bool
}

type datagramGuardKey struct{}

// receiveClosed records that the client finished sending (nil-safe).
func (g *datagramGuard) receiveClosed() {
	if g != nil {
		g.closed.Store(true)
	}
}

// h3Handler is the handler of the relay's HTTP/3 server: it guards
// requests against HTTP Datagrams and hands them to the Caddy server.
type h3Handler struct {
	next http.Handler
}

func (h h3Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	extendedConnect := r.Method == http.MethodConnect && r.Proto != "HTTP/3.0"
	if !extendedConnect {
		if str := requestStream(w); str != nil {
			guard := &datagramGuard{}
			ctx, cancel := context.WithCancel(r.Context())
			defer cancel()
			go guard.watch(ctx, str)
			r = r.WithContext(context.WithValue(r.Context(), datagramGuardKey{}, guard))
		}
	}
	h.next.ServeHTTP(w, r)
}

func (g *datagramGuard) watch(ctx context.Context, str *http3.Stream) {
	for {
		if _, err := str.ReceiveDatagram(ctx); err != nil {
			return // the request ended, or quic-go saw the receive side close
		}
		if g.closed.Load() {
			continue
		}
		// Publish the protocol error before either cancellation wakes the
		// tunnel pump or establishment watcher. Their generic cleanup must
		// preserve this code on both stream directions.
		g.failed.Store(true)
		str.CancelWrite(h3DatagramError)
		str.CancelRead(h3DatagramError)
		return
	}
}

// requestStream returns the HTTP/3 stream of a request without taking it
// over: quic-go's HTTPStreamer also sends the response header. RequestStream
// is in the patched quic-go in third_party.
func requestStream(w http.ResponseWriter) *http3.Stream {
	if rs, ok := w.(interface{ RequestStream() *http3.Stream }); ok {
		return rs.RequestStream()
	}
	return nil
}
