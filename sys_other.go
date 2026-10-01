//go:build !linux

package networkrelay

import "net"

func forbidFragmentation(*net.UDPConn, bool) error { return nil }
