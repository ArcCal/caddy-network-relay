# Production validation and rollout

This branch fixes identified audit defects. It is not a claim that all possible
defects are eliminated, or that Apple devices and a particular production
network have been certified. No production service has been deployed.

## Configuration migration

- Assign a unique `relay_id` to each security domain if its valid tunnels should
  survive reload. Without it, reload revokes all old tunnels. Reusing an ID in
  multiple handlers in one configuration is rejected. Never reuse IDs across
  unrelated tenants. Changing destination policy revokes existing tunnels.
- Fresh installs generate `relay_id <domain>`. Upgrades preserve the existing
  Caddyfile; add the ID deliberately before relying on retained tunnels.
- Changing TLS client authentication or its effective CA roots revokes old
  tunnels. Custom certificate verifiers, including file-backed leaf pinning,
  revoke tunnels on every reload because their effective trust data is opaque.
  This also prevents an old handler from establishing a late tunnel after reload.
- The default process tunnel ceiling is a quarter of available memory
  (the smaller of MemTotal and the cgroup hard limit) at 256 KiB per tunnel,
  between 512 and 20000 (4096 when memory is unknown), with 512 tunnels per
  user. Small containers still need an explicit max_tunnels if the 512 minimum
  exceeds their resource budget. The process count is checked against each
  handler's configured ceiling; use the same ceiling across handlers. Size
  limits against memory, CPU, descriptors, network capacity and the largest
  expected user workload.
- Admission limits bound counts, not an exact RSS budget. Apply cgroup/systemd
  resource budgets after staging tests.
- TCP establishment has at most eight pending address attempts per tunnel.
  Starts are normally 250ms apart, with a 100ms minimum after failure. When
  more addresses are waiting, the oldest attempt is canceled and joined before
  replacement; it may be retired after two seconds. This is a local socket
  budget, not a cap specified by RFC 8305. With no waiting addresses, attempts
  retain the configured connection deadline. All losing sockets and workers
  are cleaned up before tunnel admission is released.
- Authentication computations are process-wide, limited to min(4,GOMAXPROCS).
  New credentials are limited per client address (burst 30, then 1/s), per
  connection (4 at once) and process-wide; duplicate in-flight verifications
  also have a finite waiter budget. Verified credentials are cached for
  the process with a sliding 10-minute lifetime and survive reloads that keep
  the user. Generated passwords use PBKDF2-SHA256 (1000 iterations); supported
  Argon2 parameters are at most 64MiB, ten iterations and four lanes; bcrypt
  cost is at most 14. Regenerate over-budget hashes before upgrading.
- Request headers default to 32KiB and a ten-second read timeout. Explicit Caddy
  settings are honored. H3 bounds incomplete headers per connection (16) and
  process-wide (4096), separately bounds unfinished handshakes (1024), admits
  connections after the handshake (4096 across
  overlapping configurations, 64 per client address) and answers handshake
  floods (over 200/s) with Retry.
- HTTP/2 servers in the process default to 1024 concurrent streams and 4 MiB
  stream / 16 MiB connection receive windows (explicit Caddy settings win).
- Client certificates need `client_auth { mode request }` in the site's TLS
  options and the global `servers { strict_sni_host insecure_off }`; the relay
  refuses to start under strict SNI-Host matching. Do not rely on client_auth
  for access control in other sites on the same listener.
- The installer keeps no plaintext password; the generated profiles hold it
  until the operator deletes them.
- Linux and Darwin enforce no-fragmentation UDP socket policy. Other platforms
  fail CONNECT-UDP closed instead of silently permitting fragmentation.
- Service units no longer print the environment or grant CAP_NET_ADMIN.

## Required automated checks

Run from the repository root so local transport replacements are applied:

```sh
go vet ./...
python3 third_party/test_upstream.py
go run golang.org/x/vuln/cmd/govulncheck@v1.8.0 ./...
go test -race -count=1 -timeout=40m ./...
go test -run '^$' -fuzz '^FuzzCapsuleBoundaries$' -fuzztime=60s .
shellcheck -S warning -e SC1111,SC1091 deploy/install.sh
python3 deploy/test_install.py -v
```

For constrained test environments `RELAY_STRESS_MB=4` reduces configurable
transfer sizes; the fixed impairment cases still run. Increasing the transfer
budget is required for the intended production capacity. Go VCS stamping may
need `GOFLAGS=-buildvcs=false` in managed nested worktrees; this is a build
environment constraint, not a passing test result.

CI also queries vulnerability records for the upstream transport versions in
`third_party/provenance.json`: local replacements lack version information in
the source scanner. A matching record blocks release until it is evaluated.
Release builds use the exact commit that passed verification, even if the branch
moves while the jobs run. These checks do not replace staging validation.

## Verification in the audit environment (2026-10-04)

- Go 1.26.8 and Go 1.27.0 complete race suites passed: 74 top-level tests and 84 subtests, with
  the external real-server HTTP/3 test skipped. Endpoint lifecycle fixes also
  passed separate five-run race regressions. No race was reported.
- Five runs of nested QUIC, minimum-MTU handshake and idle datagram DPLPMTUD
  tests passed. A small path continues rejecting oversized payloads while
  delivering small packets; no reliable fallback hides the path constraint.
- The 16MiB large-transfer, concurrent-tunnel and backpressure checks passed.
  These are functional stress checks, not a large-production capacity test.
- Four release targets compiled: Linux and Darwin, amd64 and arm64. Linux IPv4
  and IPv6 sockets expose the required no-fragmentation policy. Darwin behavior
  still requires native testing, and Apple client compatibility requires devices.
- The installer has 16 passing tests, using the real build with service-manager
  stubs. Additional native Debian 12 systemd fault injection verified failed
  upgrades from active/enabled, inactive/enabled and inactive/disabled states,
  plus failed fresh-install cleanup. The lab used preinstalled prerequisites and
  an injected startup-failing candidate, with real validation and service manager.
  External package downloads, ACME and native Rust migration remain staging gates.
- Patched upstream QUIC, H3 and H2 tests passed via the reproducible snapshot
  checker. Two H3 assertions explicitly require the preserved CONNECT scheme.
- govulncheck v1.8.0 ran against the official golang/vulndb GitHub OSV snapshot
  at commit `5cd8418cf9c867d344fda07a73ea844b0f34bca2`; the hosted database is
  blocked in this environment. No reachable finding was reported. The OpenPGP
  deprecation record GO-2026-5932 matches x/crypto at module level, but no
  affected OpenPGP package is in the dependency graph. Explicit queries for the
  two replaced upstream module versions returned no records. This snapshot
  check is not a guarantee against future advisories or defects in local patches.
- Official Go 1.27.0 was downloaded from dl.google.com and verified against
  the SHA-256 published by go.dev. Its transport regressions and patched upstream
  tests passed, including explicit http2legacy tests. Full suite results are
  recorded separately in the verification artifacts. The 1.26 run initially
  exposed a test echo-server defect: peer MTU discovery completes independently
  in each direction. The corrected test keeps its original time bounds and
  passed 20 consecutive Go 1.26 and ten Go 1.27 race-enabled runs. The
  corrected Go 1.26 complete suite subsequently passed (266.277 s); the
  Go 1.27 complete suite passed in 306.541 s.

## Verification after the interoperability review (2026-10-05)

- The final Go 1.26.8 complete race suite passed: 102 top-level tests and
  147 subtests, in 306.827 seconds. The Go 1.27.0 complete `http2legacy`
  suite passed the same cases; its additional default-mode HTTP/2 checks
  passed 33 top-level tests and 62 subtests. No race was reported.
- Final Linux/Darwin amd64/arm64 binaries compiled. The separately running
  final Linux binary passed authenticated TCP/UDP checks over H1/H2/H3 with
  IPv4, IPv6 and DNS-name targets, plus two H3 tunnels carrying 64MiB in
  each direction and clean SIGTERM shutdown. The external-server test was
  skipped in the main suites and passed separately with the race detector.
- Valid and invalid TLS server/client certificates, client-CA identity changes,
  file-backed leaf verifier rotation, ECH, and malformed H3 HEADERS with FIN
  have real TLS/QUIC regressions. TCP dialing has bounded pending sockets,
  RFC 8305 pacing, later-address fallback and joined cancellation regressions.
- The unchanged 1,000-account/H3-connection capacity test passed without race
  instrumentation in 15.11 seconds, including reload, data integrity and quota
  cleanup. Combined client/server heap growth was 262.3MiB and FD growth 5,000.
  Two race-instrumented 1,000-client runs exceeded the existing two-minute
  admission deadline, including an isolated run; that capacity under race
  instrumentation is not verified. The full race suite's 128-client case passed.
- `go vet`, ShellCheck, all 16 installer tests, patched upstream QUIC/H3/H2
  race tests and a 60-second capsule fuzz run passed. The hosted Go vulnerability
  database was accessible: no reachable findings, and no advisory records for
  the pinned transport versions. The module-level OpenPGP deprecation advisory
  remains outside the imported dependency graph.

These checks do not verify actual Apple clients, native Darwin socket behavior,
public-PKI deployment, NAT64, mobile handoff or production capacity. No service
was deployed by this review.

## Verification of the 2026-10-05 changes

Admission limits, certificate users, profiles with identities, DDM
declarations and the installer without a stored password were checked in a
Linux build container (Go 1.26.8) without IPv6 sockets:

- The complete race-enabled suite passed (`RELAY_STRESS_MB=4`, 248 s),
  including certificate login over HTTP/3, HTTP/2 and HTTP/1.1, per-client
  HTTP/3 connection and header limits, Retry under a handshake flood, and the
  128-device capacity test dialing from distinct loopback addresses.
- Patched upstream QUIC, HTTP/3 and HTTP/2 suites passed; quic-go's IPv6 and
  dual-stack socket tests were skipped because the container has no IPv6.
- The 17 installer tests and shellcheck passed. OpenSSL decoded the generated
  PKCS#12 files (3DES/SHA-1, client-auth EKU). The real binary validated a
  Caddyfile with `client_auth` and `strict_sni_host insecure_off`, and refused
  one without the latter.
- govulncheck could not reach vuln.go.dev from the container; CI runs it.
- Nothing was tried on Apple devices or an MDM server.

## Required staging checks before rollout

1. Test real iPhone/iPad/Mac supported OS versions: profile installation, routing
   scope, DNS privacy, H3 and H2 fallback, Wi-Fi/cellular switching, IPv6/NAT64,
   minimum MTU, revocation, reload and certificate rotation. Check minimum OS
   versions for every emitted profile key and the applicable enrollment mode.
   Client-certificate profiles (`--identity`, PKCS#12 with 3DES/SHA-1
   protection) and DDM declarations (`--ddm`) have not been tried on devices
   or with an MDM server; nested QUIC through HTTP/3 datagrams before path MTU
   discovery has grown the outer packets is also unverified on devices.
2. Exercise the expected concurrent devices, users and tunnel mix. Measure RSS,
   CPU, FD count, packet/byte rate, rejection rate and p99. Test slow peers,
   blackholes, high-rate UDP, and a compromised account. Configure the per-user payload and UDP packet budgets for expected use;
   both default to unlimited. They share credits across directions, tunnels and
   unchanged same-domain reloads, and do not reset on reconnect. This is an
   aggregate ceiling, not scheduling fairness between a user's tunnels. Also
   deploy ingress rate limits appropriate for the expected shared NAT population.
3. Audit destination allow/block policy and egress firewall, including local
   public addresses, cloud-NAT public mappings, metadata and adjacent networks.
   A custom blocked_destinations list replaces default protections. Interface
   addresses refresh every ten seconds, so newly assigned addresses require
   firewall protection during the refresh window.
4. Test install/restart/reload/rollback using actual systemd and target OS. The
   automated installer tests and limited native recovery lab cannot certify every
   firewall, privilege, ACME or packet behavior. Check memory and socket limits.
5. Run govulncheck and the upstream transport tests in an environment with access
   to the relevant databases. Review the pinned dependency patches independently.
6. Roll out to a canary with defined abort thresholds and an available old binary,
   configuration and rollback procedure. Expand only after observation.

## Availability and rollback behavior

The installer prepares and validates the new binary before stopping the old Rust
service. Startup failure restores old files and service state, including a
migrated Rust service. Recovery failures explicitly report incomplete rollback;
the script does not promise that a failed recovery left the old service running.
External DNS/Internet checks may fail independently of relay health; inspect
their cause instead of treating an open socket as proof of success.

## Additional hardening and capacity checks (2026-10-04)

Repeated cached invalid credentials previously produced 200 warnings for 200
requests. Authentication warnings now have a process-wide 5/s budget (burst 10),
with suppressed counts. Optional diagnostic requests have a separate 10/s
budget (burst 20), applied before header formatting. These logs are sampled;
use external counters when exact incident accounting is required.

Optional per-user byte and UDP packet ceilings constrain compromised accounts.
Payload bytes exclude transport headers and refused or dropped traffic; UDP
attempts can consume credits even if a later socket write fails. UDP packet
credits cover zero-byte packets too. A byte burst permits 128 KiB; packet burst
is min(configured rate, 1024). TCP backpressure and cancellation remain intact.
Changing either budget revokes old tunnels rather than grandfathering old policy.
Three-protocol TCP integrity and UDP excess-drop regressions passed.

A race-enabled test held 1,000 distinct accounts and H3 connections simultaneously,
checked data integrity, reloaded, verified the global ceiling, exchanged more
data on every existing tunnel, and checked tunnel/H3/user-quota counts returned
to zero. Combined in-process client and server heap growth was 260.6 MiB and
FD growth was 5,000; admission p50 was 1.433 s and p99 2.009 s with 16 admission
workers. These are laboratory measurements, not production SLOs or server-only
resource estimates.

A separately running Caddy under actual systemd passed authenticated and
unauthenticated HTTP/1.1, HTTP/2 and HTTP/3 TCP/UDP CLI checks, plus the previously
external-only H3 test with two tunnels carrying 64 MiB in each direction.
The fixture used a locally trusted certificate and local TCP/DNS targets.
It does not verify Apple devices, public PKI, NAT64 or mobile network handoff.

Installer transactions now hold a root-owned private lock throughout detection,
build and replacement, use private unique backup directories, preserve enabled
and active state separately, and stop/disable the failed candidate before
removing its unit during fresh-install rollback.
