package networkrelay

import (
	"errors"
	"testing"

	"github.com/KimMachineGun/automemlimit/memlimit"
)

func TestEffectiveMemoryRespectsContainerHardLimit(t *testing.T) {
	const host = 64 << 30
	for _, tc := range []struct {
		name        string
		limit       uint64
		wantMemory  uint64
		wantTunnels int
	}{
		{"512 MiB container", 512 << 20, 512 << 20, 512},
		{"1 GiB container", 1 << 30, 1 << 30, 1024},
		{"larger than host", 128 << 30, host, 20000},
	} {
		t.Run(tc.name, func(t *testing.T) {
			memory := effectiveMemory(host, func() (uint64, error) { return tc.limit, nil })
			if memory != tc.wantMemory {
				t.Fatalf("available memory = %d, want %d", memory, tc.wantMemory)
			}
			if got := defaultMaxTunnels(memory); got != tc.wantTunnels {
				t.Fatalf("default max_tunnels = %d, want %d", got, tc.wantTunnels)
			}
		})
	}
}

func TestEffectiveMemoryFallbacks(t *testing.T) {
	for _, tc := range []struct {
		name  string
		host  uint64
		limit uint64
		err   error
		want  uint64
	}{
		{"unlimited cgroup", 8 << 30, 0, memlimit.ErrNoLimit, 8 << 30},
		{"unsupported platform", 0, 0, memlimit.ErrCgroupsNotSupported, 0},
		{"cgroup unavailable", 8 << 30, 0, errors.New("permission denied"), 8 << 30},
		{"zero cgroup limit", 8 << 30, 0, nil, 8 << 30},
		{"host unknown with valid cgroup", 0, 512 << 20, nil, 512 << 20},
		{"both unknown", 0, 0, memlimit.ErrNoCgroup, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := effectiveMemory(tc.host, func() (uint64, error) { return tc.limit, tc.err })
			if got != tc.want {
				t.Fatalf("available memory = %d, want %d", got, tc.want)
			}
		})
	}
	if got := defaultMaxTunnels(effectiveMemory(0, func() (uint64, error) {
		return 0, memlimit.ErrCgroupsNotSupported
	})); got != 4096 {
		t.Fatalf("unknown-memory default = %d, want 4096", got)
	}
}
