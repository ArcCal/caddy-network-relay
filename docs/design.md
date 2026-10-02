# Design

## 1. Goals

Apple's Network Relay (from iOS/iPadOS 17 and macOS 14): the `com.apple.relay.managed` payload in a configuration profile tells the system the address of an HTTP proxy (the relay), and the system hands matching connections to it for forwarding, with no VPN app needed. This plugin makes Caddy such a relay:

- One profile is all that is needed: `HTTP3RelayURL` / `HTTP2RelayURL` are RFC 9298 URI templates, and `AdditionalHTTPHeaderFields` holds a Basic authentication header that the device sends on every request on its own.
- Caddy handles the certificates (automatic HTTPS), receives TCP traffic (HTTP/2, HTTP/1.1) and serves the website; HTTP/3 is received by the plugin inside the Caddy process (§3).
- Compatible with the Rust version, [network-relay](https://github.com/ArcCal/network-relay), in protocol behavior, defaults, profile format and password hashes.

For what each profile key means and research into device behavior, see §1 of the Rust version's design document; the profiles this project generates are the same (including the identifier `com.github.arccal.network-relay.<domain>.<user>`).

## 2. Protocol

### 2.1 Classifying requests

| HTTP version | TCP tunnel | UDP tunnel |
|---|---|---|
| HTTP/3 | `CONNECT`, no `:protocol`, `:authority = host:port` (RFC 9114 §4.4) | Extended CONNECT, `:protocol = connect-udp`, `:path` matches the template (RFC 9298 §3.4, RFC 9220) |
| HTTP/2 | Same as above (RFC 9113 §8.5) | Same as above (RFC 8441) |
| HTTP/1.1 | `CONNECT host:port` (RFC 9110 §9.3.6) | `GET path` + `Upgrade: connect-udp` + `Connection: Upgrade` (RFC 9298 §3.2), answered with 101 |

Other requests are passed unchanged to the handlers after it in the site, with two exceptions: classic CONNECT is always answered by the plugin (§2.2 step 2); an extended CONNECT with `:protocol = connect-udp` whose path does not match the template gets 404 (405 without credentials), because the website answering an extended CONNECT with any 2xx would be understood as "tunnel established". Other values of `:protocol` (for example WebSocket over HTTP/2) are passed to the website, and `reverse_proxy` can handle them. An HTTP/1.1 request whose `Upgrade` contains `connect-udp` but whose path does not match the template is an ordinary web request.

### 2.2 Handling a request

1. **Classify** (table above).
2. **Authenticate**: look at `Proxy-Authorization` first, then `Authorization` if it is absent, and parse it as Basic. On failure: `CONNECT` (classic or extended) gets 405 with `Allow: GET, HEAD`, the same answer a Caddy static website gives to CONNECT (produced by Caddy's error handling, so `handle_errors` applies too); it is not passed to the following handlers, because one of them might answer 2xx, and a 2xx to CONNECT means "tunnel established". `GET` + `Upgrade` is passed to the website. Wrong credentials (as opposed to none) log a warning (the user name is escaped by zap).
3. **Target**: for TCP, from `:authority` (the port is required; IPv6 in brackets); for UDP, from the template variables (percent-decoded; IPv6 without brackets). Malformed → 400. A CONNECT-UDP request with `Content-Length`, `Content-Type`, `Transfer-Encoding` or a request body → 400 (RFC 9297 §3.2). An HTTP/1.1 CONNECT-UDP request whose method is not GET or whose `Connection` has no `Upgrade` → 400 (RFC 9298 §3.2: malformed requests must get an error, and 400 is recommended); `Connection` and `Upgrade` are compared as comma-separated tokens, case-insensitively.
4. **Capacity**: the number of concurrent tunnels has reached `max_tunnels` → 503.
5. **Policy**: port in `blocked_ports` → 403; resolve the domain (5 seconds); check every address against `blocked_destinations`, IPv4-mapped addresses as IPv4; none left → 403 (guards against DNS rebinding).
6. **Connect**: TCP uses Happy Eyeballs (RFC 8305): the two address families alternate, one more attempt starts every 250 milliseconds, a failed attempt immediately moves on to the next, and the whole thing is bounded by `connect_timeout`. Connections have Nagle off and keepalive on (from 2 minutes). UDP creates a connected socket (it only receives packets from the destination), using the first address that has a route; on Linux, don't-fragment is set (`IP_PMTUDISC_PROBE`), so packets over the MTU are dropped instead of fragmented (RFC 9298 §3.1).
7. **Respond**: TCP gets 200; UDP gets 200 (on HTTP/1.1, 101 with `Connection: Upgrade` and exactly one `Upgrade: connect-udp`) with `Capsule-Protocol: ?1`. Successful responses carry no `Content-Length`, `Content-Type` or `Transfer-Encoding` (RFC 9110 §9.3.6, RFC 9297 §3.2), and failure responses carry no `Capsule-Protocol` (RFC 9297 §3.4); the tests check this byte for byte on the wire for all three versions. Failures get the status codes from §2.2 and an RFC 9209 `Proxy-Status: network-relay; error=...` (table in the README).

### 2.3 TCP forwarding

- 64 KiB buffers, copying in both directions.
- **Half-close**: the device sends FIN (end of the HTTP/3 stream, HTTP/2 END_STREAM, TLS close_notify on HTTP/1.1) → `shutdown(SHUT_WR)` on the destination side, while the other direction carries on; the destination sends FIN → HTTP/3 sends FIN (the other direction carries on), HTTP/1.1 sends close_notify, HTTP/2 ends the response (see the limitations in §5).
- **Errors**: an error on the destination side (RST) → on HTTP/3, the request stream is reset with `H3_CONNECT_ERROR` (RFC 9114 §4.4); an error on the device side, a revoked user, or Caddy exiting → on HTTP/3, `H3_REQUEST_CANCELLED`, and a TCP RST to the destination (`SO_LINGER=0`).
- A device going away is noticed on HTTP/2 through the request context (stream reset or connection closed), on HTTP/3 through the stream's context (STOP_SENDING, reset, connection closed), and on HTTP/1.1 through read and write errors.

### 2.4 UDP forwarding

- Datagram format (RFC 9298 §5): Context ID (variable-length integer) + UDP payload; only Context ID 0 is handled, others are dropped; an empty payload is valid; anything over 65527 bytes aborts.
- **HTTP/3**: when the device's SETTINGS include `SETTINGS_H3_DATAGRAM` (quic-go only accepts that when QUIC DATAGRAM was negotiated too), HTTP Datagrams are used; otherwise DATAGRAM Capsules on the request stream. When Datagrams are used, Capsules on the request stream are still read (RFC 9297 §3.5 allows mixing the two). Datagrams the device sends before it receives the response (allowed by RFC 9298 §5) are buffered per stream by quic-go (at most 32 per stream) and forwarded as usual once authentication completes; datagrams that arrive even before the request stream itself, when quic-go does not yet know the stream, are dropped (RFC 9297 §2.1 and RFC 9298 §5 allow dropping or buffering).
- **HTTP/2, HTTP/1.1**: DATAGRAM Capsules.
- Capsule parsing is streaming: Capsules of unknown types or other Context IDs are skipped according to their declared length and are not subject to the UDP size limit; for context 0 the limit is checked as early as possible from the declared length; format errors such as a disconnect in the middle of a Capsule or a missing Context ID → `H3_MESSAGE_ERROR` (for HTTP/2 see §5).
- Packets from the destination that are too large to fit in one QUIC DATAGRAM are dropped rather than sent over the reliable stream instead (RFC 9297 §3.5, RFC 9298 §6.1: with QUIC inside QUIC, the two layers of congestion control interfere with each other, and DPLPMTUD breaks). A packet over the path MTU (EMSGSIZE) or a full send buffer drops only that packet.
- When the operating system reports the socket unusable, the tunnel is closed (on HTTP/3 with `H3_CONNECT_ERROR`): RFC 9298 §3.1 requires this, and its example is exactly ICMP Destination Unreachable, which Linux reports on a connected UDP socket as ECONNREFUSED, EHOSTUNREACH or ENETUNREACH.
- Packets sent to the destination have ECN Not-ECT (the socket default), and the ECN of packets from the destination is not forwarded (RFC 9298 §6.2); the outer QUIC connection keeps its congestion control.
- When there have been no packets in either direction for `udp_idle_timeout`, the tunnel is closed normally (RFC 4787 requires NAT mappings to last at least 2 minutes; the default is 5 minutes). When the device ends the request stream, the tunnel is closed normally.

### 2.5 URI templates

Supports RFC 6570 simple expansion `{var}` and form-style queries `{?a,b}` and `{&a,b}`. The only variables are `target_host` and `target_port`; both must appear, exactly once each, and two `{var}` expressions must be separated by something. On load, `example.com:443`, `192.0.2.1:53` and `2001:db8::1:8443` are expanded through the template and parsed back, and the results must match, or the template is rejected. Matching is lenient: an unencoded `:` (IPv6) is accepted too.

## 3. Structure inside Caddy

### 3.1 Modules

| Module | ID | Purpose |
|---|---|---|
| `Handler` | `http.handlers.network_relay` | Middleware: classification, authentication, tunnels; other requests go to the next handler. Caddyfile directive `network_relay`, automatically ordered before `map` (first in the site) |
| `App` | `network_relay` | Created automatically by the handler, no configuration: provides HTTP/3 for the servers that contain the handler |

### 3.2 HTTP/3

Caddy 2.11's HTTP/3 server (`http3.Server`) has no `EnableDatagrams`, and its QUIC configuration is hard-coded inside Caddy with no extension point; yet Apple devices depend on HTTP Datagrams to relay UDP over HTTP/3. So:

1. When the handler is provisioned, it takes the `caddyhttp.Server` it belongs to from the context (Caddy puts it in the context while provisioning each server's routes), records which listener addresses were meant to serve HTTP/3, and removes `h3` from that server's `protocols` (and `listen_protocols`). At this point Caddy has not started the server yet, so Caddy never listens on those UDP ports. For servers where the user removed `h3`, the plugin does not serve HTTP/3 either.
2. When the `App` starts, it opens a UDP socket and a QUIC listener (quic-go, the same library Caddy uses) for each such address, with `EnableDatagrams`, at most 1024 concurrent streams, a 4 MiB per-stream window, a 32 MiB connection window, a 5-minute idle timeout, an initial packet size of 1350 (relayed QUIC packets are at least 1200 bytes, RFC 9000 §14.1, and the outer packet also has to fit the QUIC header, the DATAGRAM frame and the Context ID), and 0-RTT not allowed. The TLS configuration comes from the server's `TLSConnPolicies`, i.e. Caddy's certificates.
3. Every request is handed to the same `caddyhttp.Server`'s `ServeHTTP`: routes, matchers, access logs, the website and error handling are exactly as on TCP.
4. Responses over TCP get `Alt-Svc: h3=":port"; ma=2592000` from the handler (Caddy no longer adds it once its own HTTP/3 is off).
5. **reload**: UDP endpoints are process-wide and shared by address; each records the configuration generations using it, and new connections go to the newest generation; old generations end gracefully with `Shutdown` (existing connections stay on the old generation). If a new configuration fails to start, only its own registration is undone, and the old configuration keeps serving. The socket is closed only when the last generation releases it. So a reload never runs into "the old configuration still holds the port, so the new one cannot bind it".

### 3.3 Rules for HTTP/3 CONNECT streams and HTTP Datagrams

The plugin performs HTTP/3 checks that quic-go does not:

- **Frames on CONNECT streams** (RFC 9114 §4.4, §7.1, §9): once the tunnel is up, the plugin parses the device-side frames itself: only DATA carries data; known types such as HEADERS (which quic-go would accept as trailers), SETTINGS, GOAWAY, reserved HTTP/2 frame types and PRIORITY_UPDATE → connection error `H3_FRAME_UNEXPECTED`; unknown types (including reserved values used for greasing) are skipped; a stream that ends in the middle of a frame → connection error `H3_FRAME_ERROR`.
- **Requests that must not carry Datagrams** (RFC 9297 §2.1): when classic CONNECT or any non-CONNECT request (a web page) receives an HTTP Datagram, the request stream is aborted with `H3_DATAGRAM_ERROR`; datagrams that arrive after the receiving side of the request has ended (the device has sent FIN) are silently dropped. Extended CONNECT is exempt (its protocol may define Datagrams). quic-go only hands over the request stream when it is taken over (and taking it over sends the response headers immediately), so the plugin gets the stream out of quic-go's `ResponseWriter` by type; a test pins this down, so if it stops working after a quic-go upgrade, the test fails.
- Errors in the datagram format itself (a Quarter Stream ID that cannot be parsed or is out of range → connection error `H3_DATAGRAM_ERROR`; the corresponding stream does not exist yet → dropped; the receiving side is closed → dropped) are handled by quic-go, in line with RFC 9297 §2.1.
- **Keepalive**: a QUIC connection with no packets for longer than the idle timeout (5 minutes) is closed, whether or not it has streams; a tunnel can be idle for longer (for example an idle TCP connection inside the relay). The plugin sends a QUIC PING every 30 seconds; on HTTP/2 connections Go sends TCP keepalives every 15 seconds, with the same effect. HTTP/3 connections without request streams are still closed after Caddy's `idle_timeout` (5 minutes by default).

### 3.4 HTTP/2 extended CONNECT

CONNECT-UDP over HTTP/2 needs the server to send `SETTINGS_ENABLE_CONNECT_PROTOCOL`. Caddy uses `golang.org/x/net/http2`; it supports extended CONNECT, but since Go issue #71128 it is off by default and only honors the environment variable `GODEBUG=http2xconnect=1`.

- Built with Go 1.26, or with Go 1.27+ and `-tags http2legacy`: `x/net/http2` uses its own implementation, and the plugin flips the switch in `init` through `go:linkname` (unless `GODEBUG` explicitly says `http2xconnect=0`).
- Built with Go 1.27+ without that tag: `x/net/http2` uses the standard library's internal implementation instead, the linker does not allow linkname into the standard library, and only the environment variable works. When the plugin detects that it is not on, it logs a warning; `deploy/caddy.service` always sets the environment variable.

With extended CONNECT on, browsers may also use WebSocket over HTTP/2 with this server (which is why Go turns it off by default). Caddy's `reverse_proxy` supports it; purely static websites are not affected.

### 3.5 Getting around timeouts Caddy designed for websites

By default, Caddy 2.11 puts a 1-minute "idle timeout" on reading request bodies and writing responses (against slowloris), resetting the deadline before every read and write. For a tunnel, a minute without data is perfectly normal. So once a tunnel is up:

- The response headers are written through Caddy's wrappers (so the access log can record the status code); after that, data goes directly through the innermost `ResponseWriter` (with the `Unwrap` chain stripped) and the innermost request body (with `IdleTimeoutReader` and the access log's counting wrapper stripped), and the stream's or connection's read and write deadlines are cleared.
- HTTP/1.1 hijacks the connection; HTTP/3 takes over the request stream (`HTTPStreamer`).

### 3.6 Tunnel lifecycle

- A tunnel belongs to the handler of the configuration generation that established it. When the old handler is cleaned up after a reload, the tunnel is handed to a handler in the new configuration that **still has the same user with the same password hash**; if there is none (the user was removed or the password changed), it is closed immediately. A tunnel whose configuration was replaced while it was being established is checked the same way.
- When Caddy exits (`caddy stop`, SIGTERM), the HTTP server's shutdown hook closes all tunnels; otherwise Caddy would keep waiting for open HTTP/2 requests to end.
- Before the tunnel is established, a device disconnecting (request context canceled) cancels the DNS lookup and the connection attempt. After that, the tunnel no longer follows the request context: Go's HTTP/1.1 server cancels it when the device half-closes a hijacked connection, and quic-go cancels it when the relay half-closes, and neither means the device is gone; instead, a device going away is noticed as in §2.3.

## 4. Authentication

- Only hashes are stored. New hashes use Argon2id (19 MiB, 2 iterations, 1 thread, as OWASP recommends, the same as the Rust version, in PHC format); bcrypt and the base64 output of `caddy hash-password` are verified too. `passwd` generates 144-bit random passwords, which cannot be guessed online, so neither IPs nor accounts are locked out.
- Verification results are cached by request header: successes for 10 minutes, failures for 1 minute. The key is an HMAC-SHA256 of the request header (with a random key each time the configuration loads), so the cache holds no passwords. Concurrent requests with the same header compute the hash only once; no more than twice the number of CPU cores of hashes are computed at the same time. The cache holds at most 4096 entries; when it is full, expired entries are cleared first; failure results never push out success results.
- For a user name that does not exist, a hash is still computed against a random hash, so response times do not reveal which user names exist.

## 5. Known limitations

| Limitation | Reason | Impact |
|---|---|---|
| On HTTP/2, when the destination closes first, the relay ends the whole stream (END_STREAM, followed by RST_STREAM(NO_ERROR) if the device is still sending); it cannot close just one direction | Go's HTTP/2 server only ends the response when the handler returns | Rare: protocols that keep receiving data from the device after the destination half-closes. HTTP/3 and HTTP/1.1 are not affected |
| The RST_STREAM code when an HTTP/2 tunnel ends abnormally is `INTERNAL_ERROR`; RFC 9113 §8.5 calls for `CONNECT_ERROR` when the destination TCP fails, and RFC 9297 §3.3 / RFC 9113 §8.1.1 call for `PROTOCOL_ERROR` for malformed Capsules | Go's HTTP/2 server (`x/net/http2`, which Caddy uses) does not let handlers choose the reset code; when a handler aborts it always sends `INTERNAL_ERROR` | The device still sees the stream reset and the destination still gets a TCP RST; only the detail of why is lost. On HTTP/3 all three codes are correct |
| Trailing HEADERS on an HTTP/2 CONNECT stream are treated as the end of the stream (like FIN) rather than as a stream error as RFC 9113 §8.5 requires | Same as above: `x/net/http2` treats them as END_STREAM before the handler sees them | Only clients that violate the protocol send them. On HTTP/3 they are `H3_FRAME_UNEXPECTED` |
| The `:scheme` of extended CONNECT is not checked to be `https` (RFC 9298 §3.4) | `x/net/http2` and quic-go only check that it is present and do not pass its value to the handler | Clients all send `https` |
| HTTP/2 flow control windows and the concurrent stream limit are `x/net/http2`'s defaults (about 1 MiB per stream/per connection, at most 250 streams) | Caddy does not expose these settings | Throughput of large uploads over HTTP/2 is bounded by the RTT; HTTP/3 is not affected |
| Reaching, through the relay, the domain of another site on the same Caddy fails | CONNECT uses the destination as the host name, so that site receives it | Put those domains in the profile's `--exclude-domain` |
| After a user is revoked, an authentication already in progress may have let one request through | A race between authentication and establishing the tunnel | The configuration generation is checked again when the tunnel is established (§3.6); the window is only a few milliseconds |

## 6. Testing

`go test ./...` (in CI with `-race`, and on Go 1.27 run separately with `-tags http2legacy` and with `GODEBUG=http2xconnect=1`):

- **Unit**: URI templates (expansion, matching, IPv6, query forms, rejected forms), target parsing, policy (mapped addresses, DNS rebinding, DNS timeouts), Happy Eyeballs, password hashes (including hashes generated by the Rust version's `network-relay passwd`, bcrypt, base64), the authentication cache, Capsules (large unknown Capsules, other contexts, empty payloads, the 65527 limit, truncation), profiles, and parsing of domain lists and the gfwlist.
- **Integration** (a real Caddy started in-process, real TLS/QUIC): TCP round trips and half-close over all three HTTP versions, the destination closing first, UDP round trips (HTTP/3 Datagrams, HTTP/3 Capsules, HTTP/2, HTTP/1.1; 0, 1, 60 and 1200 bytes, and for Capsules also 1400 and 9000 bytes), IPv6 destinations, refusals (403/400/502 and `Proxy-Status`), unauthenticated requests seeing the website, the website over HTTP/3 and `Alt-Svc`, Caddy's read/write idle timeouts not cutting idle tunnels, `max_tunnels`, a reload revoking a removed user while keeping the others, HTTP/3 and tunnels surviving a failed reload, and Caddyfile parsing and directive order.
- **Frame-level protocol conformance** (`compliance_test.go`, with hand-written frame-level HTTP/3 and HTTP/2 clients that can send things normal client libraries never would): server SETTINGS (extended CONNECT, H3_DATAGRAM, QUIC DATAGRAM); headers of successful responses over all three versions (no Content-Length/Content-Type/Transfer-Encoding, exactly one `Capsule-Protocol: ?1` for UDP, the headers of HTTP/1.1's 101, no `Capsule-Protocol` on refusals); unknown frames on CONNECT streams skipped, trailing HEADERS/SETTINGS/GOAWAY/reserved types → `H3_FRAME_UNEXPECTED`, truncated DATA → `H3_FRAME_ERROR`; datagrams received on TCP tunnels and on web pages being downloaded → `H3_DATAGRAM_ERROR`, datagrams after FIN dropped; datagrams sent before the response forwarded; ICMP unreachable closing UDP tunnels on all three versions (`H3_CONNECT_ERROR` on HTTP/3); malformed HTTP/1.1 Upgrade requests → 400, token-list forms of `Connection`/`Upgrade` accepted, duplicate `Host` → 400; CONNECT-UDP with content headers → 400 (HTTP/3, HTTP/2); connect-udp outside the template → 404/405, other values of `:protocol` passed to the website.
- **Interoperability**: quic-go's [masque-go](https://github.com/quic-go/masque-go) (an independent CONNECT-UDP client and RFC 6570 implementation) sending and receiving datagrams over HTTP/3; a frame-level HTTP/2 client checking `SETTINGS_ENABLE_CONNECT_PROTOCOL`, extended CONNECT, Capsule round trips, the RST_STREAM caused by malformed Capsules, and normal termination (this test does not depend on Go's HTTP/2 client, so it also verifies the server under Go 1.27's standard library implementation); HTTP/3's `H3_MESSAGE_ERROR` and `H3_CONNECT_ERROR`.
- **Heavy traffic and bad networks** (`stress_test.go`; 64 MiB per transfer by default, adjustable with `RELAY_STRESS_MB`): 64 MiB up + 64 MiB down over each of the three versions, verified byte for byte (SHA-256), at about 160–200 MiB/s locally; 24 concurrent tunnels (mixing the three versions); when the client stops reading while the destination keeps sending, the relay process's heap does not grow (flow control pushes back on the destination, nothing is buffered); after the transfers the tunnel count returns to 0. Bad networks are simulated inside the test process (this machine's kernel has no netem): UDP packets under QUIC are dropped with some probability, delayed FIFO with jitter, and a few are reordered and duplicated; TCP goes through a proxy that adds delay, limits bandwidth, and can stall or cut the connection. Each case first runs the same transfer without the relay as a baseline, then through the relay, and the relay must not be noticeably slower. Covered: HTTP/3 round trips at 3% loss/40 ms RTT and 10% loss/200 ms RTT (through the relay they take 1.0x and 0.9x as long as direct; throughput itself is limited by loss-based congestion control, roughly 1.2·MSS/(RTT·√p), and the former measures about 220 KB/s, in line with that bound); HTTP/2 and HTTP/1.1 at 60 ms one-way delay and 8 Mbit/s taking the same time as direct; tunnels carrying on after a 3-second stall; tunnels released immediately and the destination getting an RST after the connection is cut; tunnels released after an HTTP/3 connection is closed abruptly; UDP tunnels at 5% loss losing only what the path loses, with nothing corrupted; **QUIC inside QUIC**: a QUIC connection on the device going through a UDP tunnel across an outer path with 3% loss, 8 MiB each way, inner packets at most 1280 bytes (fitting in the outer 1350-byte datagrams), and larger inner PMTU probe packets dropped rather than turned into Capsules.
- **Install script**: `python3 deploy/test_install.py`, with system commands replaced by stubs that record their calls and Caddy being the real built binary: fresh install, upgrade keeping everything, writing nothing on every kind of refusal, not taking over someone else's Caddyfile, replacing the Rust version, rollback on a failed start (fresh install and upgrade), a failed configuration check, and keeping the service when the self-check fails.
- **Manual end-to-end** (the built `caddy` run with a Caddyfile): `caddy network-relay check` passing TCP and UDP over all three versions (with DNS queries to 1.1.1.1 over the real internet); curl downloading and uploading a 200 MB file through CONNECT over HTTP/1.1 and HTTP/2, with matching checksums, and the same with 8 concurrent 200 MB downloads; for HTTP/3, `go test -run TestRealServerHTTP3` (`e2e_test.go`, which needs the `RELAY_E2E_*` environment variables) transferring 200 MiB each way twice against a running server, about 6 seconds each time; and with an HTTP/2 tunnel open, Caddy exiting within about 1 second of SIGTERM.

**Not done yet**: tests with a real iPhone and Mac.
