package networkrelay

import (
	"crypto/tls"
	"net/http"
)

// Both the reviewed standard-library source and its retained policy tag are
// required for every build, including external xcaddy-generated entry points.
const _ = tls.RelayTLSKeyUsagePolicy
const _ = http.RelayHTTP1HostPolicy
const _ = relayTLS9846BuildTag
