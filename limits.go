package networkrelay

import (
	"bufio"
	"os"
	"strconv"
	"strings"
	"sync"
)

// memoryPerTunnel is planned per tunnel when sizing the default
// max_tunnels: copy buffers, flow-control windows in use and kernel
// socket buffers.
const memoryPerTunnel = 256 << 10

// defaultMaxTunnels is the max_tunnels default for a machine with memory
// bytes (0 when unknown): a quarter of it at memoryPerTunnel each, between
// 512 and 20000.
func defaultMaxTunnels(memory uint64) int {
	if memory == 0 {
		return 4096
	}
	return int(min(max(memory/4/memoryPerTunnel, 512), 20000))
}

// totalMemory is this machine's memory from /proc/meminfo, or 0.
func totalMemory() uint64 {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if rest, ok := strings.CutPrefix(sc.Text(), "MemTotal:"); ok {
			kib, err := strconv.ParseUint(strings.TrimSuffix(strings.TrimSpace(rest), " kB"), 10, 64)
			if err != nil {
				return 0
			}
			return kib << 10
		}
	}
	return 0
}

type userTunnelKey struct {
	relay string
	owner *Handler
	user  string
}

var userTunnels = struct {
	sync.Mutex
	counts map[userTunnelKey]int
}{counts: make(map[userTunnelKey]int)}

// Reserve before DNS or dialing. Stable IDs share a budget during reload;
// handlers without an ID have independent, nontransferable security domains.
func reserveUserTunnel(h *Handler, user string) (func(), bool) {
	k := userTunnelKey{relay: h.RelayID, user: user}
	if k.relay == "" {
		k.owner = h
	}
	userTunnels.Lock()
	if userTunnels.counts[k] >= h.MaxTunnelsPerUser {
		userTunnels.Unlock()
		return nil, false
	}
	userTunnels.counts[k]++
	userTunnels.Unlock()
	return sync.OnceFunc(func() {
		userTunnels.Lock()
		defer userTunnels.Unlock()
		if userTunnels.counts[k]--; userTunnels.counts[k] == 0 {
			delete(userTunnels.counts, k)
		}
	}), true
}
