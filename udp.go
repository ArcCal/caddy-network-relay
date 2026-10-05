package networkrelay

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/quic-go/quicvarint"
)

// maxUDPPayload is the largest UDP payload (RFC 9298 §5: 65527 bytes).
const maxUDPPayload = 65527

// capsuleDatagram is the DATAGRAM capsule type (RFC 9297 §3.5).
const capsuleDatagram = 0x00

var errMalformed = errors.New("malformed capsule or datagram")

// readCapsules reads the capsule stream from the client and passes the UDP
// payloads of DATAGRAM capsules with context ID 0 to deliver. Unknown
// capsules, and datagrams with other context IDs, are skipped without
// buffering them, so they are not subject to the UDP size limit. It returns
// nil when the client ends the stream between capsules.
func readCapsules(r io.Reader, deliver func([]byte)) error {
	br := bufio.NewReaderSize(r, 16*1024)
	buf := make([]byte, maxUDPPayload)
	for {
		if _, err := br.Peek(1); err == io.EOF {
			return nil // the client ended the stream between capsules
		}
		typ, err := quicvarint.Read(br)
		if err != nil {
			return truncated(err)
		}
		length, err := quicvarint.Read(br)
		if err != nil {
			return truncated(err)
		}
		if typ != capsuleDatagram {
			if err := discard(br, length); err != nil {
				return err
			}
			continue
		}
		if length == 0 {
			return errMalformed // no room for the context ID
		}
		// A varint need not use its shortest encoding (RFC 9000 §16): the
		// size of the context ID is what its first byte says, and it must
		// fit in the capsule.
		first, err := br.Peek(1)
		if err != nil {
			return truncated(err)
		}
		idLen := uint64(1) << (first[0] >> 6)
		if idLen > length {
			return errMalformed
		}
		ctxID, err := quicvarint.Read(br)
		if err != nil {
			return truncated(err)
		}
		if ctxID != 0 {
			if err := discard(br, length-idLen); err != nil {
				return err
			}
			continue
		}
		size := length - idLen
		if size > maxUDPPayload {
			return errMalformed
		}
		if _, err := io.ReadFull(br, buf[:size]); err != nil {
			return truncated(err)
		}
		deliver(buf[:size])
	}
}

func discard(br *bufio.Reader, n uint64) error {
	for n > 0 {
		chunk := n
		if chunk > 1<<30 {
			chunk = 1 << 30
		}
		m, err := br.Discard(int(chunk))
		n -= uint64(m)
		if err != nil {
			return truncated(err)
		}
	}
	return nil
}

// truncated turns an end of stream in the middle of a capsule into a
// malformed-message error; other errors (resets) pass through.
func truncated(err error) error {
	if err == io.EOF || err == io.ErrUnexpectedEOF {
		return errMalformed
	}
	return err
}

// appendDatagramCapsule appends a DATAGRAM capsule carrying payload with
// context ID 0.
func appendDatagramCapsule(b, payload []byte) []byte {
	b = quicvarint.Append(b, capsuleDatagram)
	b = quicvarint.Append(b, uint64(len(payload))+1)
	b = append(b, 0) // context ID 0
	return append(b, payload...)
}

// udpTunnel relays UDP payloads between a client and a connected UDP
// socket: as HTTP/3 datagrams when the client negotiated them, otherwise as
// DATAGRAM capsules on the request stream (HTTP/2, HTTP/1.1, or HTTP/3
// without datagrams).
type udpTunnel struct {
	cc      clientConn
	h3      *http3.Stream // set when HTTP/3 datagrams are in use
	sock    *net.UDPConn
	idle    time.Duration
	budget  *trafficBudget
	dropped atomic.Int64

	last     atomic.Int64 // unix nanoseconds of the last packet either way
	up, down atomic.Int64
	done     chan struct{}
	once     sync.Once
	why      abortReason
	aborted  bool
}

func (u *udpTunnel) finish(why abortReason, aborted bool) {
	u.once.Do(func() {
		u.why, u.aborted = why, aborted
		close(u.done)
	})
}

func (u *udpTunnel) touch() { u.last.Store(time.Now().UnixNano()) }

// toTarget sends one payload to the target. A datagram too big for the
// path (the socket never fragments) or a full send buffer drops it; any
// other error means the socket is unusable, which closes the tunnel.
func (u *udpTunnel) toTarget(p []byte) {
	// Capsules validate their declared length before buffering. Native HTTP
	// Datagrams have the same bound, independently of transport packet limits.
	if len(p) > maxUDPPayload {
		u.finish(abortMalformed, true)
		return
	}
	if !u.budget.allowUDP(len(p)) {
		u.dropped.Add(1)
		return
	}
	u.touch()
	if _, err := u.sock.Write(p); err != nil {
		if isPerDatagramError(err) {
			return
		}
		u.finish(abortFailed, true)
		return
	}
	u.up.Add(int64(len(p)))
}

// isPerDatagramError reports errors that concern a single datagram. ICMP
// Destination Unreachable errors (ECONNREFUSED, EHOSTUNREACH, ENETUNREACH
// on a connected socket) are not among them: RFC 9298 §3.1 requires the
// proxy to close the request stream when the operating system reports the
// socket unusable, with exactly that example.
func isPerDatagramError(err error) bool {
	return errors.Is(err, syscall.EMSGSIZE) || errors.Is(err, syscall.ENOBUFS) ||
		errors.Is(err, syscall.EAGAIN) || errors.Is(err, syscall.EINTR)
}

// run relays until the client ends the stream, the tunnel is idle for too
// long, the socket fails or ctx ends.
func (u *udpTunnel) run(ctx context.Context) (up, down int64, why abortReason, aborted bool) {
	u.done = make(chan struct{})
	u.touch()
	var workers sync.WaitGroup
	workers.Add(2)

	// Client to target: capsules on the stream (always allowed, RFC 9297
	// §3.5), plus HTTP/3 datagrams when negotiated.
	go func() {
		defer workers.Done()
		err := readCapsules(u.cc, u.toTarget)
		switch {
		case err == nil:
			u.finish(0, false)
		case errors.Is(err, errMalformed):
			u.finish(abortMalformed, true)
		default:
			u.finish(abortCancelled, true)
		}
	}()
	dctx, cancel := context.WithCancel(ctx)
	defer cancel()
	if u.h3 != nil {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for {
				d, err := u.h3.ReceiveDatagram(dctx)
				if err != nil {
					return
				}
				ctxID, n, err := quicvarint.Parse(d)
				if err != nil {
					u.finish(abortMalformed, true)
					return
				}
				if ctxID != 0 {
					continue
				}
				u.toTarget(d[n:])
			}
		}()
	}

	// Target to client.
	go func() {
		defer workers.Done()
		buf := make([]byte, maxUDPPayload+16)
		var capsule []byte
		for {
			n, err := u.sock.Read(buf[1:])
			if err != nil {
				if isPerDatagramError(err) {
					continue
				}
				select {
				case <-u.done:
				default:
					u.finish(abortFailed, true)
				}
				return
			}
			u.touch()
			if n > maxUDPPayload {
				continue // never send an oversized context-zero datagram
			}
			payload := buf[1 : 1+n]
			if !u.budget.allowUDP(n) {
				u.dropped.Add(1)
				continue
			}
			if u.h3 != nil {
				buf[0] = 0 // context ID 0
				err = u.h3.SendDatagram(buf[:1+n])
				var tooLarge *quic.DatagramTooLargeError
				if errors.As(err, &tooLarge) {
					// Never fall back to the reliable stream: QUIC inside
					// a reliable stream fights its own congestion control.
					continue
				}
			} else {
				capsule = appendDatagramCapsule(capsule[:0], payload)
				_, err = u.cc.Write(capsule)
			}
			if err != nil {
				u.finish(abortCancelled, true)
				return
			}
			u.down.Add(int64(n))
		}
	}()

	tick := u.idle / 8
	if tick > 5*time.Second {
		tick = 5 * time.Second
	}
	ticker := time.NewTicker(tick)
	defer ticker.Stop()
	for {
		select {
		case <-u.done:
			u.sock.Close()
			cancel()
			if u.aborted {
				interruptClient(u.cc, u.why)
				workers.Wait()
			} else {
				finishUDPWorkers(u.cc, &workers)
			}
			return u.up.Load(), u.down.Load(), u.why, u.aborted
		case <-ctx.Done():
			u.finish(abortCancelled, true)
		case <-u.cc.gone():
			u.finish(abortCancelled, true)
		case <-ticker.C:
			if time.Since(time.Unix(0, u.last.Load())) > u.idle {
				u.finish(0, false)
			}
		}
	}
}

// finishUDPWorkers preserves FIN when the final Capsule can be delivered.
// A peer withholding flow-control credit must not retain a writer, its tunnel
// quota or a pooled HTTP/2 response writer after the handler returns. After a
// short grace period, discard pending packets with a no-error stream reset.
func finishUDPWorkers(cc clientConn, workers *sync.WaitGroup) {
	past := time.Now().Add(-time.Second)
	switch c := cc.(type) {
	case *h1Client:
		_ = c.conn.SetReadDeadline(past)
	case *h2Client:
		_ = c.body.Close()
	case *h3Client:
		c.str.CancelRead(quic.StreamErrorCode(http3.ErrCodeNoError))
	default:
		cc.close()
	}
	done := make(chan struct{})
	go func() { workers.Wait(); close(done) }()
	timer := time.NewTimer(100 * time.Millisecond)
	defer timer.Stop()
	select {
	case <-done:
		return
	case <-timer.C:
	}
	switch c := cc.(type) {
	case *h1Client:
		_ = c.conn.SetWriteDeadline(past)
	case *h2Client:
		if w, ok := c.w.(interface{ InterruptStream(uint32) error }); ok {
			_ = w.InterruptStream(0) // NO_ERROR
		} else {
			_ = c.rc.SetWriteDeadline(past)
		}
	case *h3Client:
		c.str.CancelWrite(quic.StreamErrorCode(http3.ErrCodeNoError))
	default:
		cc.close()
	}
	<-done
}
