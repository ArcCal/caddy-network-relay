package networkrelay

import (
	"errors"
	"net"
	"testing"

	"golang.org/x/sys/unix"
)

func TestUDPSocketsForbidFragmentation(t *testing.T) {
	for _, tc := range []struct {
		network, address    string
		ipv6                bool
		level, option, want int
	}{
		{"udp4", "127.0.0.1:0", false, unix.IPPROTO_IP, unix.IP_MTU_DISCOVER, unix.IP_PMTUDISC_PROBE},
		{"udp6", "[::1]:0", true, unix.IPPROTO_IPV6, unix.IPV6_MTU_DISCOVER, unix.IPV6_PMTUDISC_PROBE},
	} {
		t.Run(tc.network, func(t *testing.T) {
			addr, err := net.ResolveUDPAddr(tc.network, tc.address)
			if err != nil {
				t.Fatal(err)
			}
			sock, err := net.ListenUDP(tc.network, addr)
			if err != nil && tc.ipv6 && (errors.Is(err, unix.EAFNOSUPPORT) || errors.Is(err, unix.EADDRNOTAVAIL)) {
				t.Skipf("no IPv6 loopback on this host: %v", err)
			}
			if err != nil {
				t.Fatal(err)
			}
			defer sock.Close()
			if err := forbidFragmentation(sock, tc.ipv6); err != nil {
				t.Fatal(err)
			}
			raw, err := sock.SyscallConn()
			if err != nil {
				t.Fatal(err)
			}
			var got int
			var optionErr error
			if err := raw.Control(func(fd uintptr) {
				got, optionErr = unix.GetsockoptInt(int(fd), tc.level, tc.option)
			}); err != nil {
				t.Fatal(err)
			}
			if optionErr != nil {
				t.Fatal(optionErr)
			}
			if got != tc.want {
				t.Fatalf("socket policy %d, want no-fragmentation policy %d", got, tc.want)
			}
		})
	}
}
