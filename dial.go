package networkrelay

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"syscall"
	"time"
)

// attemptDelay is how long a TCP connection attempt runs alone before the
// next address is tried as well (Happy Eyeballs, RFC 8305 §5).
const attemptDelay = 250 * time.Millisecond

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

// dialTCP connects to the first address that answers, starting a new
// attempt every attemptDelay, or at once when one fails (RFC 8305).
func dialTCP(ctx context.Context, addrs []netip.AddrPort, timeout time.Duration) (*net.TCPConn, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	type result struct {
		conn *net.TCPConn
		err  error
	}
	results := make(chan result)
	pending := interleave(addrs)
	running := 0
	start := func() {
		addr := pending[0]
		pending = pending[1:]
		running++
		go func() {
			var d net.Dialer
			c, err := d.DialContext(ctx, "tcp", addr.String())
			var tc *net.TCPConn
			if err == nil {
				tc = c.(*net.TCPConn)
			}
			select {
			case results <- result{tc, err}:
			case <-ctx.Done():
				if tc != nil {
					tc.Close()
				}
			}
		}()
	}
	var lastErr error
	timer := time.NewTimer(attemptDelay)
	defer timer.Stop()
	for {
		if running == 0 {
			if len(pending) == 0 {
				if lastErr == nil {
					return nil, refuseNoAddresses
				}
				return nil, dialRefusal(lastErr)
			}
			start()
			timer.Reset(attemptDelay)
		}
		select {
		case r := <-results:
			running--
			if r.err == nil {
				tuneTCP(r.conn)
				return r.conn, nil
			}
			lastErr = r.err
			if len(pending) > 0 {
				start()
				timer.Reset(attemptDelay)
			}
		case <-timer.C:
			if len(pending) > 0 {
				start()
				timer.Reset(attemptDelay)
			}
		case <-ctx.Done():
			if lastErr != nil && !errors.Is(ctx.Err(), context.DeadlineExceeded) {
				return nil, dialRefusal(lastErr)
			}
			return nil, dialRefusal(ctx.Err())
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
