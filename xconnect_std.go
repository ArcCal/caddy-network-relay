//go:build go1.27 && !http2legacy

package networkrelay

import (
	"os"
	"strings"
)

// From Go 1.27, golang.org/x/net/http2 hands HTTP/2 to the standard
// library, which enables extended CONNECT (needed for CONNECT-UDP over
// HTTP/2, RFC 8441) only when the process starts with
// GODEBUG=http2xconnect=1 in its environment. Build with Go 1.26 or with
// -tags http2legacy to have the relay turn it on by itself.
func http2ExtendedConnect() bool {
	return strings.Contains(os.Getenv("GODEBUG"), "http2xconnect=1")
}
