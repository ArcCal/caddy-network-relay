# Read-only Go toolchain preparation

## Verified failure and targeted repair

Automatically downloaded Go toolchains have read-only source files and
source directories. The original `shutil.copytree` preserved these modes in
the private GOROOT. Applying the reviewed TLS/HTTP files then failed, and
cleanup of the read-only copy could replace that error with another permission
error naming a source file such as `iter_test.go`.

The new copy helper creates private writable directories, preserves file
contents and executable bits, and grants owner write permission only to the
new file copies. It never changes the installed toolchain. Both initial
preparation and reuse retain the complete source inventory check, exact Go
version and asset hashes, rejection of symbolic links and non-regular source
entries, and the retained TLS policy marker. The source manifest and all
reviewed TLS/HTTP implementation bytes are unchanged.

Before editing, the build design, preparation implementation and history,
Apple's Relay schema and the retained RFC 9846 TLS policy requirements were
reviewed. This repair changes filesystem preparation, not server protocol,
certificate trust, authentication, TLS key limits or network permissions.

## Local verification

- The old helper fails the new read-only regression for both supported Go
  versions and obscures an injected policy-copy error during cleanup.
- All 13 policy tests pass with official Go 1.26.11 and 1.27.4 inputs, including
  exact output/reuse checks, rejection controls, unchanged installed content
  and modes, retained executability, and failure cleanup.
- A real automatically downloaded Go 1.27.4 Linux toolchain reproduces the old
  permission failure. The repaired helper prepares and reuses its full source
  tree successfully without changing original content or permissions.
- All 149 applicable deployment tests pass; 10 environment/privilege cases are
  explicitly skipped. These tests use a retained reviewed-policy server binary.
- All eight packaging tests pass. The regenerated standalone installer has
  902 embedded files matching current source; only the preparation helper and
  its upstream-policy explanation changed. Its SHA-256 and shell syntax pass.
- The actual `network-relay` preparation, build and collection functions produce
  both Linux x64 and arm64 Caddy binaries with Cloudflare DNS support. Static
  ELF architecture, the retained TLS policy tag and all five required module
  replacements pass the original artifact checks. These are Linux-hosted
  builds; the arm64 binary is inspected, not executed on arm64 hardware.
  Full source inventories and original permissions still match after builds.
- The freshly built x64 server passes 14 profile tests and three admin socket
  tests; two admin ownership cases require isolated root execution and are
  skipped. All expected relay and Cloudflare DNS modules are registered.

Logs and source/mode inventories are retained under the audit workspace's
`go-source-permissions-20261114` directory. Failed setup attempts are retained
separately and are not counted as passes.

## Native macOS validation is blocked

[Workflow 43553666626](https://github.com/ArcCal/caddy-network-relay/actions/runs/43553666626)
was rejected before a runner was assigned: GitHub reported failed account
payments or an insufficient spending limit. No macOS test ran. The diagnostic
branch retains a workflow that reproduces the old error with an automatically
downloaded read-only macOS Go toolchain, runs the policy tests and builds both
Linux architectures. It uses only the private Caddy repository and public
Cloudflare source, without cross-repository credentials. No native macOS
acceptance is claimed until that workflow can run.
