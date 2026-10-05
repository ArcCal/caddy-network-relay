package networkrelay

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"syscall"
	"time"
)

// attemptDelay is how long a TCP connection attempt runs alone before the
// next address is tried as well (Happy Eyeballs, RFC 8305 §5).
const attemptDelay = 250 * time.Millisecond

const (
	minimumAttemptDelay    = 100 * time.Millisecond
	maxParallelTCPAttempts = 8
)

// interleave alternates address families, starting with the family of the
// first address (RFC 8305 §4).
func interleave(addrs []netip.AddrPort) []netip.AddrPort {
	if len(addrs) == 0 {
		return nil
	}
	firstIs6 := addrs[0].Addr().Is6()
	var same, other []netip.AddrPort
	for _, a := range addrs {
		if a.Addr().Is6() == firstIs6 {
			same = append(same, a)
		} else {
			other = append(other, a)
		}
	}
	out := make([]netip.AddrPort, 0, len(addrs))
	for len(same) > 0 || len(other) > 0 {
		if len(same) > 0 {
			out = append(out, same[0])
			same = same[1:]
		}
		if len(other) > 0 {
			out = append(out, other[0])
			other = other[1:]
		}
	}
	return out
}

func dialRefusal(err error) *refusal {
	var r *refusal
	switch {
	case errors.As(err, &r):
		return r
	case errors.Is(err, syscall.ECONNREFUSED):
		return refuseRefused
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, syscall.ETIMEDOUT), isTimeout(err):
		return refuseTimeout
	default:
		return refuseUnreachable(err)
	}
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// dialTCP connects to the first address that answers, normally staggering
// attempts by attemptDelay. Failure acceleration still waits at least 100ms,
// exceeding RFC 8305's mandatory 10ms minimum and meeting its recommended
// minimum. At most eight sockets are pending per tunnel: when another address
// is due, retire and join the oldest attempt before starting its replacement.
// This bound is a local resource policy, not an RFC requirement. With many
// pending addresses it can retire an attempt after two seconds; when no more
// addresses are waiting, attempts retain the full connection deadline.
func dialTCP(ctx context.Context, addrs []netip.AddrPort, timeout time.Duration) (*net.TCPConn, error) {
	conn, err := dialTCPWith(ctx, addrs, timeout, func(ctx context.Context, addr netip.AddrPort) (*net.TCPConn, error) {
		var d net.Dialer
		c, err := d.DialContext(ctx, "tcp", addr.String())
		if err != nil {
			return nil, err
		}
		return c.(*net.TCPConn), nil
	})
	if err == nil {
		tuneTCP(conn)
	}
	return conn, err
}

// dialTCPWith accepts a dial function locally so scheduling, bounded pending
// sockets and cancellation cleanup can be tested without an external network.
func dialTCPWith(ctx context.Context, addrs []netip.AddrPort, timeout time.Duration,
	dial func(context.Context, netip.AddrPort) (*net.TCPConn, error)) (*net.TCPConn, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	type attempt struct {
		cancel context.CancelFunc
		done   chan struct{}
	}
	type result struct {
		attempt *attempt
		conn    *net.TCPConn
		err     error
	}
	results := make(chan result, maxParallelTCPAttempts)
	var workers sync.WaitGroup
	var active []*attempt
	defer func() {
		cancel()
		for _, a := range active {
			a.cancel()
		}
		workers.Wait()
		// A losing connection can complete as cancellation starts. Close
		// every result not handed to the caller before releasing admission.
		for {
			select {
			case r := <-results:
				if r.conn != nil {
					r.conn.Close()
				}
			default:
				return
			}
		}
	}()
	pending := interleave(addrs)
	var lastStart, nextLaunch time.Time
	start := func() {
		addr := pending[0]
		pending = pending[1:]
		actx, acancel := context.WithCancel(ctx)
		a := &attempt{cancel: acancel, done: make(chan struct{})}
		active = append(active, a)
		lastStart = time.Now()
		nextLaunch = lastStart.Add(attemptDelay)
		workers.Add(1)
		go func() {
			defer workers.Done()
			defer close(a.done)
			defer acancel()
			conn, err := dial(actx, addr)
			if actx.Err() != nil {
				if conn != nil {
					conn.Close()
					conn = nil
				}
				err = actx.Err()
			}
			select {
			case results <- result{a, conn, err}:
			case <-ctx.Done():
				if conn != nil {
					conn.Close()
				}
			}
		}()
	}
	var lastErr error
	timer := time.NewTimer(attemptDelay)
	defer timer.Stop()
	accept := func(r result) (*net.TCPConn, bool) {
		for i, a := range active {
			if a != r.attempt {
				continue
			}
			active = append(active[:i], active[i+1:]...)
			if r.err == nil {
				return r.conn, true
			}
			lastErr = r.err
			if accelerated := lastStart.Add(minimumAttemptDelay); accelerated.Before(nextLaunch) {
				nextLaunch = accelerated
			}
			return nil, false
		}
		// This attempt was retired to admit a later address.
		if r.conn != nil {
			r.conn.Close()
		}
		return nil, false
	}
	for {
		if err := ctx.Err(); err != nil {
			if lastErr != nil && !errors.Is(err, context.DeadlineExceeded) {
				return nil, dialRefusal(lastErr)
			}
			return nil, dialRefusal(err)
		}
		// Prefer a completed attempt over launching or retiring another.
		select {
		case r := <-results:
			if conn, ok := accept(r); ok {
				return conn, nil
			}
			continue
		default:
		}
		if len(active) == 0 && len(pending) == 0 {
			if lastErr == nil {
				return nil, refuseNoAddresses
			}
			return nil, dialRefusal(lastErr)
		}
		if len(pending) > 0 && (lastStart.IsZero() || !time.Now().Before(nextLaunch)) {
			if len(active) == maxParallelTCPAttempts {
				oldest := active[0]
				oldest.cancel()
				<-oldest.done
				active = active[1:]
				// A TCP success can have entered the buffered results just
				// before retirement canceled it. Close retired results before
				// opening a replacement socket; other successes still win.
			drainRetired:
				for {
					select {
					case r := <-results:
						if conn, ok := accept(r); ok {
							return conn, nil
						}
					default:
						break drainRetired
					}
				}
			}
			start()
			continue
		}
		var tick <-chan time.Time
		if len(pending) > 0 {
			timer.Reset(time.Until(nextLaunch))
			tick = timer.C
		}
		select {
		case r := <-results:
			if conn, ok := accept(r); ok {
				return conn, nil
			}
		case <-tick:
		case <-ctx.Done():
		}
	}
}

// tuneTCP turns off Nagle (the device's TCP already coalesced the data)
// and turns on keepalives, so a vanished peer does not pin the tunnel.
func tuneTCP(c *net.TCPConn) {
	_ = c.SetNoDelay(true)
	_ = c.SetKeepAliveConfig(net.KeepAliveConfig{Enable: true, Idle: 2 * time.Minute, Interval: 30 * time.Second, Count: 4})
}

// dialUDP opens a connected UDP socket to the first address with a route.
// Connecting only picks a route; it fails at once when there is none, for
// example for IPv6 on a host without it.
func dialUDP(addrs []netip.AddrPort) (*net.UDPConn, error) {
	var lastErr error
	for _, a := range addrs {
		c, err := net.DialUDP("udp", nil, net.UDPAddrFromAddrPort(a))
		if err != nil {
			lastErr = err
			continue
		}
		if err := forbidFragmentation(c, a.Addr().Is6()); err != nil {
			c.Close()
			lastErr = err
			continue
		}
		_ = c.SetReadBuffer(1 << 20)
		_ = c.SetWriteBuffer(1 << 20)
		return c, nil
	}
	if lastErr == nil {
		return nil, refuseNoAddresses
	}
	return nil, dialRefusal(lastErr)
}
