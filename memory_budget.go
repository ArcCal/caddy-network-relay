package networkrelay

import "sync/atomic"

// receiveBuffers is shared by every HTTP/2 and QUIC connection and survives
// configuration reloads. Flow-control credit is independent: an orderly FIN
// can return credit while its unread bytes still occupy memory.
var receiveBuffers = &receiveBufferBudget{limit: receiveBufferLimit(totalMemory())}

type receiveBufferBudget struct {
	limit int64
	used  atomic.Int64
}

func receiveBufferLimit(memory uint64) int64 {
	if memory == 0 {
		return 256 << 20
	}
	return int64(min(memory/4, uint64(1<<63-1)))
}

func (b *receiveBufferBudget) TryAcquire(n int64) bool {
	if n < 0 || n > b.limit {
		return false
	}
	for {
		used := b.used.Load()
		if n > b.limit-used {
			return false
		}
		if b.used.CompareAndSwap(used, used+n) {
			return true
		}
	}
}

func (b *receiveBufferBudget) Release(n int64) {
	if n < 0 || b.used.Add(-n) < 0 {
		panic("relay receive buffer accounting underflow")
	}
}
