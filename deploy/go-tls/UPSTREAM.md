# Reviewed Go TLS sender policy

Policy: `rfc9846-v1`; required retained build tag: `relay_tls9846_v1`.

The release compiler, tools and all source other than the four listed TLS and HTTP files
remain from the selected official Go distribution. `prepare.py` copies the source
into a private GOROOT, checks the exact official input and reviewed output hashes
in `source-manifest.json`, and never changes an installed toolchain. Go 1.26.11
and 1.27.4 are the only reviewed source versions. Future releases require review
and new exact hashes; the helper fails closed on unknown or modified inputs.
Preparation and reuse also compare every file in the copied source tree with
the selected distribution plus the four reviewed replacements. Extra files,
modified unpatched files, symbolic links and non-regular source entries are
rejected. The selected installed distribution remains the trust boundary for
the unchanged compiler and tools.

Official input sources:
- https://go.googlesource.com/go/+/refs/tags/go1.26.11/src/crypto/tls/conn.go
- https://go.googlesource.com/go/+/refs/tags/go1.27.4/src/crypto/tls/conn.go
- https://www.rfc-editor.org/rfc/rfc9846.html#section-5.5
- https://www.rfc-editor.org/rfc/rfc9846.html#section-4.7.3

The local policy initiates an unrequested TLS 1.3 sending-key update before
2^24 AES-GCM records, reserves the old-key record for the update, advances the
traffic secret only after successful transport write, and respects the outgoing
2^48-1 epoch limit. It does not limit incoming updates or change QUIC protection.
The separate helper and changed Go source retain Go's BSD-style license in
`LICENSE`. This source policy is not a Go module and does not replace any of the
four independently reviewed local dependency snapshots.

Build with `GOROOT` set to the prepared directory, `GOTOOLCHAIN=local`, and
`-tags http2legacy,relay_tls9846_v1`. The package compile guard requires both the
patched TLS constant and policy tag; artifact/install checks require that exact
tag in retained Go metadata. A release version alone does not prove this policy.

The composed `net/http` policy, `rfc9112-host-v1`, validates the original
HTTP/1 Host field before absolute-form target processing can hide an invalid
value, and requires Host on HTTP/1.1 CONNECT as RFC 9112 Section 3.2 requires.
The grammar preserves valid empty names and ports, percent-encoded names, IPv6
and IPvFuture literals. It adds the compile marker
`http.RelayHTTP1HostPolicy`. Original source snapshots:
- https://go.googlesource.com/go/+/refs/tags/go1.26.11/src/net/http/server.go
- https://go.googlesource.com/go/+/refs/tags/go1.27.4/src/net/http/server.go
- https://www.rfc-editor.org/rfc/rfc9112.html#section-3.2
- https://www.rfc-editor.org/rfc/rfc9110.html#section-7.2
- https://www.rfc-editor.org/rfc/rfc3986.html#section-3.2.2

Both components are checked and applied together into a new private root.
Neither preparation nor reuse accepts only one component. The retained tag
continues to be `relay_tls9846_v1` for this combined reviewed build policy.
