//go:build !linux && !darwin

package networkrelay

import (
	"errors"
	"net"
)

func forbidFragmentation(*net.UDPConn, bool) error {
	return errors.New("CONNECT-UDP is unavailable: this platform cannot guarantee no IP fragmentation")
}
