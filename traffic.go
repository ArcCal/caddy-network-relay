package networkrelay

import (
	"context"
	"sync/atomic"
	"time"

	"golang.org/x/time/rate"
)

// One budget per configured user, shared by both directions and all tunnels.
// It persists when a tunnel closes, so reconnecting cannot renew its burst.
type trafficBudget struct {
	bytes   *rate.Limiter
	packets *rate.Limiter
}

func newTrafficBudget(bytesPerSecond, packetsPerSecond int64) *trafficBudget {
	b := &trafficBudget{}
	if bytesPerSecond > 0 {
		b.bytes = rate.NewLimiter(rate.Limit(bytesPerSecond), 2*tcpBufferSize)
	}
	if packetsPerSecond > 0 {
		b.packets = rate.NewLimiter(rate.Limit(packetsPerSecond), int(min(packetsPerSecond, 1024)))
	}
	return b
}

func (b *trafficBudget) waitTCP(ctx context.Context, n int) error {
	if b == nil || b.bytes == nil {
		return nil
	}
	return b.bytes.WaitN(ctx, n)
}

func (b *trafficBudget) allowUDP(n int) bool {
	if b == nil {
		return true
	}
	now := time.Now()
	if b.packets != nil && !b.packets.AllowN(now, 1) {
		return false
	}
	return b.bytes == nil || b.bytes.AllowN(now, n)
}

// A fixed process-wide budget avoids attacker-controlled maps and survives
// configuration reload. Detailed diagnostic logging has its own budget.
type logBudget struct {
	limiter    *rate.Limiter
	suppressed atomic.Uint64
}

func (b *logBudget) allow() (uint64, bool) {
	if !b.limiter.Allow() {
		b.suppressed.Add(1)
		return 0, false
	}
	return b.suppressed.Swap(0), true
}

var authenticationLogs = &logBudget{limiter: rate.NewLimiter(5, 10)}
var diagnosticLogs = &logBudget{limiter: rate.NewLimiter(10, 20)}
