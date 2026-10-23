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
  CONNECT's original scheme. An unwritten request stream (such as client
  stream 0, which Apple's QUIC connection group implicitly opens and never
  writes) is left open and does not hold the connection out of its idle
  timeout, but it takes one of the connection's 16 slots like a request with
  incomplete headers; the global slot and the deadline start at a request
  stream's first byte. A request whose headers do not arrive in time is
  rejected in both directions with H3_REQUEST_REJECTED (RFC 9114 section
  4.1.1); one whose stream ends without complete headers gets
  H3_REQUEST_INCOMPLETE.
- quic-go/http3: the frame parser no longer skips push frames, so they are
  rejected as RFC 9114 requires. Push is not supported, so on the server's
  control stream a CANCEL_PUSH names a push ID never mentioned (section
  7.2.3) and is H3_ID_ERROR, as is a MAX_PUSH_ID smaller than one received
  before (section 7.2.7). The parser closes the connection with
  H3_FRAME_UNEXPECTED as soon as it reads the type of a PUSH_PROMISE received
  by a server or on a control stream (section 7.2.5), or of CANCEL_PUSH,
  SETTINGS, GOAWAY, MAX_PUSH_ID or PRIORITY_UPDATE on a request stream
  (sections 4.1, 7.2.3, 7.2.4, 7.2.6 and 7.2.7), whatever the payload. The
  client, which never sends MAX_PUSH_ID, treats CANCEL_PUSH and a PUSH_PROMISE
  on a request stream as H3_ID_ERROR. The single-integer payloads of
  CANCEL_PUSH, GOAWAY and MAX_PUSH_ID are read only within their declared
  length; an empty, shorter or longer payload is H3_FRAME_ERROR (section
  7.1). The upstream test that required push frames to be skipped is
  replaced by `quic_push_frames_test.go.txt`.
- quic-go/http3: expose the request stream to handlers (RequestStream) without
  sending the response header, so the relay needs no reflection.
- x-net/http2: expose CloseWrite, ResetStream and concurrent-write-safe
  InterruptStream to handlers, releasing local stream state even when the peer
  stops reading the underlying socket; retain and accept the receive direction after a
  CONNECT FIN; release stream state after both directions finish and return
  connection flow-control credits exactly once, including pending body reads;
  close the receive direction if a handler returns after CloseWrite; reject
  CONNECT trailers; preserve the original scheme; tolerate a peer reset while
  an asynchronous handler-panic reset is still being written.
- x-net/http2: optional ReceiveBufferBudget and DefaultServerReceiveBufferBudget
  account for full request DATA chunk capacity across connections, independently
  of flow-control credits. Buffered DATA retained after orderly FIN stays charged
  until consumed or discarded. Allocation exhaustion resets only the affected
  stream with ENHANCE_YOUR_CALM and closes it locally even with socket backpressure.
- x-net/http2: use the reviewed HTTP/2 implementation on Go 1.27 as well, instead
  of forwarding to the standard library which lacks these handler extensions.
- x-net/http2: security fixes backported from x/net v0.60.0 without its other
  changes: per-declared-trailer allocation budgeting (GO-2026-6603, frame.go);
  response Content-Length validation and removal of connection-specific fields
  in the client and reverse-proxy response path (GO-2026-6610, transport.go);
  SETTINGS_INITIAL_WINDOW_SIZE changes applied through shared accounting
  instead of every active stream (GO-2026-6611, flow.go, server.go,
  transport.go, writesched.go); and HPACK encoder table-size changes deferred
  until no frame is being written (GO-2026-6617, server.go). x/net v0.60.0's
  frame_test.go, flow_test.go, writesched_test.go and
  writesched_priority_rfc7540_test.go replace their v0.59.0 versions during
  `test_upstream.py` (their SHA-256 values are checked), and
  `http2_security_test.go.txt` and `http2_security_internal_test.go.txt` add
  the upstream regression tests for the other advisories and a bounded
  128-stream shared-accounting check. GO-2026-6612 is not backported: its
  upstream repair replaces a refund path the relay does not use. The relay's
  closeStream returns each closed stream's unread credit once, and x/net
  v0.60.0's TestServerResetStreamUnreadBody passes with only the moment of the
  refund adapted for a reset stream whose handler never started. The reviewed
  advisories are recorded in `provenance.json`; the CI version query fails on
  any other advisory for a recorded snapshot.
- x-net/http2: SetExtendedConnectProtocol/ExtendedConnectProtocol replace a
  go:linkname to the unexported switch; DefaultServerMaxConcurrentStreams and
  DefaultServerMaxUploadBuffer{PerConnection,PerStream} set the server
  defaults that Caddy leaves unset; a Write after the handler finished panics
  with its intended message instead of a nil dereference.

- quic-go: optional ReceiveBufferBudget accounts for retained stream buffer
  capacity and estimated frame bookkeeping across connections. FIN data stays
  charged until consumed; cancellation, effective reset and shutdown discard
  unread frames and release their reservations. Exhaustion closes the affected
  connection with INTERNAL_ERROR.

The application exercises these changes through actual H2/H3 frames in
`readiness_protocol_test.go`, in addition to existing interoperability, reload
and impairment tests. Never update the snapshots by copying files over them
without rebasing these changes and rerunning the regressions.

Run `python3 third_party/test_upstream.py` from the repository root. It verifies
the complete local file list and hashes, the original module checksum and source
hashes, then runs the original QUIC, HTTP/3 and HTTP/2 tests with the patches.
Two HTTP/3 assertions are updated to require the intentionally preserved scheme
instead of an empty scheme; the Config reflection fixture initializes the new
optional ReceiveBufferBudget field. All other upstream assertions are retained.
The harness also copies `http2_regression_test.go.txt` into the upstream HTTP/2
test package to verify flow-control credits for both FIN orders, cleanup after
handler return, cancellation of a blocked response write under the race
detector, and the reset code after a directional FIN.
It also copies `http2_buffer_regression_test.go.txt` into the internal test
package. The fixtures cover chunk capacity, partial allocation failures and
padding credits, EOF and discard, retained FIN buffers across connections,
handler cleanup before a blocked final response, and late panic-reset completion.
The QUIC receive-budget fixture checks retained buffers, overlaps, FIN,
cancellation, reset, shutdown and configuration propagation.

Go ignores replace directives in dependencies. Builds must use this repository
as the main module or repeat both replacements in the main module. An ordinary
xcaddy --with build will silently omit the patches. Deployment instructions use
the repository-root build. Review the upstream diff when updating versions,
rerun the upstream transport test suites and dependency vulnerability scanning,
and retire these patches when equivalent upstream APIs become available.

## Conformance fixtures

`fixture-patches.json` defines additional generated IDNA data and fixture patches
applied during upstream verification. Go string values retain identical runtime
bytes. The upstream test runner verifies the pinned baseline, strict patch
replay, and resulting hashes; arbitrary source changes fail verification.
