package networkrelay

import "sync"

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
