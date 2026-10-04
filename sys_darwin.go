//go:build darwin

package networkrelay

import (
	"net"

	"golang.org/x/sys/unix"
)

// Darwin exposes DF controls for both address families. Fail the dial if
// setting the required policy fails rather than silently permitting fragments.
func forbidFragmentation(c *net.UDPConn, ipv6 bool) error {
	raw, err := c.SyscallConn()
	if err != nil {
		return err
	}
	level, option := unix.IPPROTO_IP, unix.IP_DONTFRAG
	if ipv6 {
		level, option = unix.IPPROTO_IPV6, unix.IPV6_DONTFRAG
	}
	var sockErr error
	err = raw.Control(func(fd uintptr) {
		sockErr = unix.SetsockoptInt(int(fd), level, option, 1)
	})
	if err != nil {
		return err
	}
	return sockErr
}
