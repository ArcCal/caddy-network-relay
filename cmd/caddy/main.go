// Command caddy is Caddy with the standard modules and the network_relay
// plugin. Build it with `go build -o caddy ./cmd/caddy` (no xcaddy needed).
package main

import (
	caddycmd "github.com/caddyserver/caddy/v2/cmd"

	_ "github.com/arccal/caddy-network-relay"
	_ "github.com/caddyserver/caddy/v2/modules/standard"
)

func main() {
	caddycmd.Main()
}
