package networkrelay

import (
	"os"
	"strings"

	"golang.org/x/net/http2" // Caddy's HTTP/2 server, from third_party/x-net
)

// CONNECT-UDP over HTTP/2 is an extended CONNECT request (RFC 8441, RFC
// 9298 §3.5), which needs the server to send SETTINGS_ENABLE_CONNECT_PROTOCOL.
// golang.org/x/net/http2, which Caddy uses for HTTP/2, supports it but
// keeps it off unless the environment says GODEBUG=http2xconnect=1. The
// relay turns it on, unless GODEBUG's last http2xconnect setting is 0.
//
// SetExtendedConnectProtocol and the server defaults below exist only in
// the patched x/net in third_party: a build without it (an ordinary
// `xcaddy --with`, which ignores this module's replace directives) fails
// to compile instead of silently losing the patches.
func init() {
	if godebug(os.Getenv("GODEBUG"), "http2xconnect") != "0" {
		http2.SetExtendedConnectProtocol(true)
	}
	// Every relayed TCP connection or UDP flow is a stream; a device that
	// relays all its traffic has hundreds at once, and uploads share the
	// connection's window. x/net's defaults (250 streams, 1 MiB windows)
	// would queue them. These apply to the other sites in this Caddy too.
	http2.DefaultServerMaxConcurrentStreams = 1024
	http2.DefaultServerMaxUploadBufferPerStream = 4 << 20
	http2.DefaultServerMaxUploadBufferPerConnection = 16 << 20
	http2.DefaultServerReceiveBufferBudget = receiveBuffers
}

func http2ExtendedConnect() bool { return http2.ExtendedConnectProtocol() }

// godebug returns the value GODEBUG gives a setting, "" if none: settings
// are comma-separated name=value pairs, and the last one for a name wins.
func godebug(env, name string) string {
	value := ""
	for _, setting := range strings.Split(env, ",") {
		if n, v, ok := strings.Cut(strings.TrimSpace(setting), "="); ok && n == name {
			value = v
		}
	}
	return value
}
