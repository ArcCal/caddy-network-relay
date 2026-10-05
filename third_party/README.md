# Pinned transport sources

These are source snapshots, not new upstream releases:

| Directory | Upstream module | Original version |
|---|---|---|
| quic-go | github.com/quic-go/quic-go | v0.63.0 |
| x-net | golang.org/x/net | v0.59.0 |

Original LICENSE/PATENTS files are retained. Only source files and required
embedded data are included; upstream tests are not shipped. `provenance.json`
records the original module sums and per-file original/source hashes.

Local changes:

- quic-go: on a path-size rejection of an application DATAGRAM, wake bounded
  DPLPMTUD on its next probe deadline even without smaller application traffic.
  Respect DF capability, disabled discovery, congestion pacing and probe loss.
- quic-go/http3: normalize whitespace in an upstream ABNF comment; no behavior
  change, recorded in the source provenance manifest.
- quic-go/http3: expose ReadHeaderTimeout, apply a stream read deadline while
  receiving HEADERS, clear it before calling the handler, bound incomplete
  headers per connection (16; more closes the connection with
  H3_EXCESSIVE_LOAD) and across connections (4096), and preserve extended
  CONNECT's original scheme.
- quic-go/http3: expose the request stream to handlers (RequestStream) without
  sending the response header, so the relay needs no reflection.
- x-net/http2: expose CloseWrite and ResetStream to handlers; retain and accept
  the receive direction after a CONNECT FIN; release stream state after both
  directions finish; reject CONNECT trailers; preserve the original scheme.
- x-net/http2: use the reviewed HTTP/2 implementation on Go 1.27 as well, instead
  of forwarding to the standard library which lacks these handler extensions.
- x-net/http2: SetExtendedConnectProtocol/ExtendedConnectProtocol replace a
  go:linkname to the unexported switch; DefaultServerMaxConcurrentStreams and
  DefaultServerMaxUploadBuffer{PerConnection,PerStream} set the server
  defaults that Caddy leaves unset; a Write after the handler finished panics
  with its intended message instead of a nil dereference.

The application exercises these changes through actual H2/H3 frames in
`readiness_protocol_test.go`, in addition to existing interoperability, reload
and impairment tests. Never update the snapshots by copying files over them
without rebasing these changes and rerunning the regressions.

Run `python3 third_party/test_upstream.py` from the repository root. It verifies
the complete local file list and hashes, the original module checksum and source
hashes, then runs the original QUIC, HTTP/3 and HTTP/2 tests with the patches.
Two HTTP/3 assertions are updated to require the intentionally preserved scheme
instead of an empty scheme; all other upstream assertions are retained.

Go ignores replace directives in dependencies. Builds must use this repository
as the main module or repeat both replacements in the main module. An ordinary
xcaddy --with build will silently omit the patches. Deployment instructions use
the repository-root build. Review the upstream diff when updating versions,
rerun the upstream transport test suites and dependency vulnerability scanning,
and retire these patches when equivalent upstream APIs become available.
