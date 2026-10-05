package networkrelay

import (
	"bufio"
	"errors"
	"io"
	"net"
	"net/http"
	"reflect"
	"time"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

// abortReason is why a tunnel is reset instead of being closed normally.
type abortReason int

const (
	// The client sent something malformed (a bad capsule or datagram).
	abortMalformed abortReason = iota
	// The connection to the target failed (TCP reset, socket error).
	abortFailed
	// The client went away, the user was removed, or Caddy is exiting.
	abortCancelled
)

// HTTP/3 error codes (RFC 9114 §8.1, RFC 9297 §5.2).
const (
	h3RequestCancelled quic.StreamErrorCode = 0x10c
	h3MessageError     quic.StreamErrorCode = 0x10e
	h3ConnectError     quic.StreamErrorCode = 0x10f
	h3DatagramError    quic.StreamErrorCode = 0x33
)

func (a abortReason) h3Code() quic.StreamErrorCode {
	switch a {
	case abortMalformed:
		return h3MessageError
	case abortFailed:
		return h3ConnectError
	default:
		return h3RequestCancelled
	}
}

// clientConn is the client side of an established tunnel, whatever the
// HTTP version: a byte stream in each direction.
type clientConn interface {
	// Read returns data from the client; io.EOF when it finished sending.
	io.Reader
	// Write sends data to the client right away.
	io.Writer
	// closeWrite ends the relay-to-client direction normally. It returns
	// true when that ends the whole tunnel (HTTP/2, where a handler cannot
	// half-close its stream).
	closeWrite() (endsTunnel bool)
	// abort resets the tunnel. It must be called from the handler's
	// goroutine, as the last thing before the handler returns.
	abort(abortReason)
	// close releases the tunnel after it ended normally.
	close()
	// gone is closed when the client resets the stream or the connection
	// closes, while the relay is still sending; nil when that can only be
	// seen from Read and Write errors.
	gone() <-chan struct{}
}

// h1Client is a hijacked HTTP/1.1 connection.
type h1Client struct {
	conn net.Conn
	r    *bufio.Reader
}

func (c *h1Client) Read(p []byte) (int, error)  { return c.r.Read(p) }
func (c *h1Client) Write(p []byte) (int, error) { return c.conn.Write(p) }

func (c *h1Client) closeWrite() bool {
	if cw, ok := c.conn.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
		return false
	}
	return true
}

func (c *h1Client) abort(abortReason) {
	if tc, ok := netConn(c.conn).(*net.TCPConn); ok {
		_ = tc.SetLinger(0)
	}
	c.conn.Close()
}

func (c *h1Client) interrupt(why abortReason) { c.abort(why) }

func (c *h1Client) close() { c.conn.Close() }

func (c *h1Client) gone() <-chan struct{} { return nil }

func netConn(c net.Conn) net.Conn {
	for {
		u, ok := c.(interface{ NetConn() net.Conn })
		if !ok {
			return c
		}
		c = u.NetConn()
	}
}

// h2Client is an HTTP/2 stream: the request body and the response.
type h2Client struct {
	body io.ReadCloser
	w    http.ResponseWriter
	rc   *http.ResponseController
	done <-chan struct{} // the request context: reset stream or closed connection
}

func (c *h2Client) Read(p []byte) (int, error) { return c.body.Read(p) }

func (c *h2Client) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	if err == nil {
		err = c.rc.Flush()
	}
	return n, err
}

func (c *h2Client) closeWrite() bool {
	if w, ok := c.w.(interface{ CloseWrite() error }); ok {
		_ = w.CloseWrite()
		return false
	}
	return true
}

// abort resets the stream. Go's HTTP/2 server picks the code
// (INTERNAL_ERROR); a handler cannot send CONNECT_ERROR itself.
func (c *h2Client) abort(why abortReason) {
	if w, ok := c.w.(interface{ ResetStream(uint32) error }); ok {
		code := uint32(8) // CANCEL
		if why == abortMalformed {
			code = 1 // PROTOCOL_ERROR
		} else if why == abortFailed {
			code = 10 // CONNECT_ERROR
		}
		_ = w.ResetStream(code)
		return
	}
	panic(http.ErrAbortHandler)
}

// interrupt is safe while the copy worker is writing. ResetStream also
// changes the response writer's handler-owned state, so it is deferred
// until the worker has returned.
func (c *h2Client) interrupt(why abortReason) {
	_ = c.body.Close()
	if w, ok := c.w.(interface{ InterruptStream(uint32) error }); ok {
		code := uint32(8) // CANCEL
		if why == abortMalformed {
			code = 1 // PROTOCOL_ERROR
		} else if why == abortFailed {
			code = 10 // CONNECT_ERROR
		}
		_ = w.InterruptStream(code)
		return
	}
	// Standard-library HTTP/2 does not expose reset codes. A write
	// deadline still releases a blocked writer before its handler exits.
	_ = c.rc.SetWriteDeadline(time.Now().Add(-time.Second))
}

func (c *h2Client) close() {}

func (c *h2Client) gone() <-chan struct{} { return c.done }

// h3Client is an HTTP/3 request stream taken over from the server.
type h3Client struct {
	str  *http3.Stream
	body *h3Body
}

func (c *h3Client) Read(p []byte) (int, error)  { return c.body.Read(p) }
func (c *h3Client) Write(p []byte) (int, error) { return c.str.Write(p) }

func (c *h3Client) closeWrite() bool {
	_ = c.str.Close()
	return false
}

func (c *h3Client) abort(why abortReason) {
	c.str.CancelRead(why.h3Code())
	c.str.CancelWrite(why.h3Code())
}

func (c *h3Client) interrupt(why abortReason) { c.abort(why) }

// Stop both I/O directions before waiting for copy workers. All production
// client implementations provide interrupt; test clients with no blocking
// I/O can simply close.
func interruptClient(c clientConn, why abortReason) {
	if c, ok := c.(interface{ interrupt(abortReason) }); ok {
		c.interrupt(why)
		return
	}
	c.close()
}

// gone: quic-go cancels the stream context when the write side ends: after
// STOP_SENDING, a reset or a closed connection, and also after the relay's
// own FIN, after which callers stop watching it.
func (c *h3Client) gone() <-chan struct{} { return c.str.Context().Done() }

func (c *h3Client) close() {
	_ = c.str.Close()
	// Stop receiving whatever the client may still send.
	c.str.CancelRead(quic.StreamErrorCode(http3.ErrCodeNoError))
}

// baseWriter strips Caddy's response writer wrappers (access logging, write
// idle timeouts) so tunnel data goes straight to the server's writer. The
// idle timeout is meant for slow clients of a website, not for tunnels that
// legitimately sit idle for hours.
func baseWriter(w http.ResponseWriter) http.ResponseWriter {
	for {
		u, ok := w.(interface{ Unwrap() http.ResponseWriter })
		if !ok {
			return w
		}
		w = u.Unwrap()
	}
}

// rawBody strips Caddy's request body wrappers for the same reason: Caddy
// sets a read deadline before every Read of a wrapped body, which would cut
// tunnels that are idle for longer than the server's read idle timeout.
func rawBody(b io.ReadCloser) io.ReadCloser {
	for {
		switch v := b.(type) {
		case *caddyhttp.IdleTimeoutReader:
			b = v.ReadCloser
			continue
		}
		// Caddy's access log counts body bytes with an unexported
		// wrapper whose exported Source field holds the body.
		rv := reflect.ValueOf(b)
		if rv.Kind() == reflect.Pointer && rv.Elem().Kind() == reflect.Struct {
			t := rv.Elem().Type()
			if t.PkgPath() == "github.com/caddyserver/caddy/v2/modules/caddyhttp" {
				if f := rv.Elem().FieldByName("Source"); f.IsValid() && f.CanInterface() {
					if inner, ok := f.Interface().(io.ReadCloser); ok && inner != nil {
						b = inner
						continue
					}
				}
			}
		}
		return b
	}
}

// clearDeadlines removes the read and write deadlines Caddy may have set
// on the stream or connection.
func clearDeadlines(rc *http.ResponseController) {
	_ = rc.SetReadDeadline(time.Time{})
	_ = rc.SetWriteDeadline(time.Time{})
}

var errHijackFailed = errors.New("cannot take over the connection")
