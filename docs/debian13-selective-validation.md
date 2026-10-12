# Debian 13 selective installer validation

The installer was derived from Caddy Network Relay main ef245375aa67eecde830a5bcd5044b34cca52c4d. The domain helper and data were copied without modification from Rust Network Relay main a8cc0e8f3b3949de83634f52ff422c41cb87615d. Original worktrees were preserved.

Executed successfully:

- Fourteen domain/profile tests, including the actual Caddy profile CLI: source-copy hashes, exact source selection, Rust pipeline parity, malformed or missing sources, output preservation, empty/all-traffic refusal, HTTP/2-only policy, credential/template validation, exclusions, profile-size cap, and private atomic writes.
- Fourteen installer transaction tests: real Caddy profile generation and configuration adaptation, with apt/systemd/service validation/network probes stubbed. Covered bootstrap ordering, credential privacy, permissions, conflicting installations, all eighteen offline source fixtures, malformed lists, startup rollback and retry, early unit-copy failure, H2 failures, auth-rejection failures, and H3 diagnostics that must not prevent H2 readiness.
- Replayed all fourteen installer transaction tests against the exact unpacked script payload: passed.
- Downloaded and parsed the real gfwlist and all eighteen service lists: 4863 registered roots; generated a real Caddy mobileconfig of 143728 bytes, with HTTP2RelayURL only and relay hostname excluded. Domain/subdomain match and unmatched/excluded examples were checked against Apple MatchDomains semantics. These are list/structure checks, not observations on an iPhone.
- Go 1.26.8 checksum independently matched the live official checksum database; the exact installer verification/extraction code passed and produced the expected Go version.
- All 780 production/module/third-party source files checked against the original Caddy snapshot are byte-identical. All 790 packaged payload files match the reviewed implementation.
- Compiled the exact extracted source bundle with the pinned Go 1.26.8, CGO_ENABLED=0 and http2legacy tag: static Linux x64 binary. Its real profile CLI generated the full 4863-root H2-only profile successfully.
- Bash syntax, Python compilation, package extraction, --help and script SHA-256 verification passed. The deployment-only patch passed git apply --check.

Not executed: privileged installation on a real fresh VPS, public ACME issuance/renewal, provider firewall configuration, and profile installation/domain routing on a physical Apple device. The runtime installer requires real H2 TCP/UDP probes plus the existing H1 anonymous rejection check before reporting readiness. A source-list download failure does not silently produce a partial profile.

The script is a source snapshot and first-install tool. It refuses to overwrite an existing deployment. It does not repair or claim to repair existing server protocol/security findings from previous reviews.
