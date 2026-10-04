package networkrelay

import (
	"os"
	"strings"
	_ "unsafe" // for go:linkname

	_ "golang.org/x/net/http2" // Caddy's HTTP/2 server
)

// CONNECT-UDP over HTTP/2 is an extended CONNECT request (RFC 8441, RFC
// 9298 §3.5), which needs the server to send SETTINGS_ENABLE_CONNECT_PROTOCOL.
// golang.org/x/net/http2, which Caddy uses for HTTP/2, supports it but
// keeps it off unless the environment says GODEBUG=http2xconnect=1. The
// relay turns it on, unless GODEBUG explicitly says http2xconnect=0.
//
//go:linkname http2DisableExtendedConnect golang.org/x/net/http2.disableExtendedConnectProtocol
var http2DisableExtendedConnect bool

func init() {
	if !strings.Contains(os.Getenv("GODEBUG"), "http2xconnect=0") {
		http2DisableExtendedConnect = false
	}
}

func http2ExtendedConnect() bool { return !http2DisableExtendedConnect }

// goH2ClientExtendedConnect: the HTTP/2 client can send extended CONNECT
// (used by `caddy network-relay check` and the tests).
const goH2ClientExtendedConnect = true
