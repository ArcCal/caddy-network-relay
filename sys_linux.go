package networkrelay

import (
	"net"

	"golang.org/x/sys/unix"
)

// forbidFragmentation sets the Don't Fragment policy on a target UDP socket:
// datagrams larger than the path MTU are dropped instead of being sent as IP
// fragments (RFC 9298 §3.1 discourages fragmentation).
func forbidFragmentation(c *net.UDPConn, ipv6 bool) error {
	raw, err := c.SyscallConn()
	if err != nil {
		return err
	}
	var sockErr error
	err = raw.Control(func(fd uintptr) {
		if ipv6 {
			sockErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_MTU_DISCOVER, unix.IPV6_PMTUDISC_PROBE)
		} else {
			sockErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_MTU_DISCOVER, unix.IP_PMTUDISC_PROBE)
		}
	})
	if err != nil {
		return err
	}
	return sockErr
}
