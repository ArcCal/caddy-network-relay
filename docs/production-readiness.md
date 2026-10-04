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
- The default process tunnel ceiling is 1024, with 128 tunnels per user. The
  process count is checked against each handler's configured ceiling; use the
  same ceiling across handlers. Size limits against memory, CPU, descriptors,
  network capacity and the largest expected user workload.
- Two 64KiB buffers per TCP tunnel consume about 128MiB at the default ceiling,
  before QUIC/TLS/socket/runtime overhead. Admission limits bound counts, not
  an exact RSS budget. Apply cgroup/systemd resource budgets after staging tests.
- Authentication computations are process-wide, limited to min(4,GOMAXPROCS).
  All uncached waiters, including duplicate headers, have a shared finite budget.
  Supported Argon2 parameters are at most 64MiB, ten iterations and four lanes;
  bcrypt cost is at most 14. Regenerate over-budget hashes before upgrading.
- Request headers default to 32KiB and a ten-second read timeout. Explicit Caddy
  settings are honored. H3 has a process-wide 256 incomplete-header budget and
  1024 admitted connections across overlapping configurations.
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

- The final complete race suite passed: 66 top-level tests and 78 subtests, with
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
- The installer has 14 passing tests, using the real build with service-manager
  stubs. Native systemd recovery is an independent staging requirement.
- Patched upstream QUIC, H3 and H2 tests passed via the reproducible snapshot
  checker. Two H3 assertions explicitly require the preserved CONNECT scheme.
- govulncheck v1.8.0 ran against the official golang/vulndb GitHub OSV snapshot
  at commit `5cd8418cf9c867d344fda07a73ea844b0f34bca2`; the hosted database is
  blocked in this environment. No reachable finding was reported. The OpenPGP
  deprecation record GO-2026-5932 matches x/crypto at module level, but no
  affected OpenPGP package is in the dependency graph. Explicit queries for the
  two replaced upstream module versions returned no records. This snapshot
  check is not a guarantee against future advisories or defects in local patches.
- Go 1.27 could not be downloaded through the configured proxy; it remains
  unverified here. All current checks used Go 1.26.8.

## Required staging checks before rollout

1. Test real iPhone/iPad/Mac supported OS versions: profile installation, routing
   scope, DNS privacy, H3 and H2 fallback, Wi-Fi/cellular switching, IPv6/NAT64,
   minimum MTU, revocation, reload and certificate rotation. Check minimum OS
   versions for every emitted profile key and the applicable enrollment mode.
2. Exercise the expected concurrent devices, users and tunnel mix. Measure RSS,
   CPU, FD count, packet/byte rate, rejection rate and p99. Test slow peers,
   blackholes, high-rate UDP, and a compromised account. Limits do not provide
   bandwidth/PPS fairness; deploy per-tenant traffic shaping and ingress rate
   limits appropriate for the expected shared NAT population.
3. Audit destination allow/block policy and egress firewall, including local
   public addresses, cloud-NAT public mappings, metadata and adjacent networks.
   A custom blocked_destinations list replaces default protections. Interface
   addresses refresh every ten seconds, so newly assigned addresses require
   firewall protection during the refresh window.
4. Test install/restart/reload/rollback using actual systemd and target OS. The
   automated installer tests use stubs; they cannot certify service manager,
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
