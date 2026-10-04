package networkrelay

import (
	"context"
	"io"
	"net"
	"sync/atomic"
)

const tcpBufferSize = 64 * 1024

// direction outcomes of a TCP tunnel.
type copyResult struct {
	up       bool  // client to target
	n        int64 // bytes copied
	err      error // nil when the direction ended normally
	targetEr bool  // the error came from the target side
}

// pumpTCP relays bytes in both directions, passing half-closes through: a
// FIN from one side shuts down the other side's sending direction while the
// other direction keeps going. An error on either side resets both: the
// client stream with the reason, the target with a TCP RST.
func pumpTCP(ctx context.Context, cc clientConn, t *net.TCPConn) (up, down int64, why abortReason, aborted bool) {
	return pumpTCPLimited(ctx, cc, t, nil)
}

func pumpTCPLimited(ctx context.Context, cc clientConn, t *net.TCPConn, budget *trafficBudget) (up, down int64, why abortReason, aborted bool) {
	// Returning on a peer reset must also release a worker waiting for credits,
	// even when the caller's request context is still alive.
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	results := make(chan copyResult, 2)
	go func() {
		buf := make([]byte, tcpBufferSize)
		var n int64
		for {
			m, rerr := cc.Read(buf)
			if m > 0 {
				if err := budget.waitTCP(ctx, m); err != nil {
					results <- copyResult{up: true, n: n, err: err}
					return
				}
				if _, werr := t.Write(buf[:m]); werr != nil {
					results <- copyResult{up: true, n: n, err: werr, targetEr: true}
					return
				}
				n += int64(m)
			}
			if rerr == io.EOF {
				results <- copyResult{up: true, n: n}
				return
			}
			if rerr != nil {
				results <- copyResult{up: true, n: n, err: rerr}
				return
			}
		}
	}()
	var downN atomic.Int64
	go func() {
		buf := make([]byte, tcpBufferSize)
		for {
			m, rerr := t.Read(buf)
			if m > 0 {
				if err := budget.waitTCP(ctx, m); err != nil {
					results <- copyResult{n: downN.Load(), err: err}
					return
				}
				if _, werr := cc.Write(buf[:m]); werr != nil {
					results <- copyResult{n: downN.Load(), err: werr}
					return
				}
				downN.Add(int64(m))
			}
			if rerr == io.EOF {
				results <- copyResult{n: downN.Load()}
				return
			}
			if rerr != nil {
				results <- copyResult{n: downN.Load(), err: rerr, targetEr: true}
				return
			}
		}
	}()

	upDone, downDone := false, false
	gone := cc.gone()
	fail := func(r abortReason) (int64, int64, abortReason, bool) {
		_ = t.SetLinger(0)
		t.Close()
		return up, downN.Load(), r, true
	}
	for !upDone || !downDone {
		select {
		case <-ctx.Done():
			return fail(abortCancelled)
		case <-gone:
			return fail(abortCancelled)
		case r := <-results:
			if r.up {
				up, upDone = r.n, true
			} else {
				down, downDone = r.n, true
			}
			switch {
			case r.err != nil && r.targetEr:
				return fail(abortFailed)
			case r.err != nil:
				return fail(abortCancelled)
			case r.up:
				_ = t.CloseWrite()
			default:
				gone = nil // closing our side may fire it
				if cc.closeWrite() {
					t.Close()
					return up, down, 0, false
				}
			}
		}
	}
	t.Close()
	return up, down, 0, false
}
