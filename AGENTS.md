# Agent instructions for caddy-network-relay

## Project context

- This Caddy plugin implements authenticated classic CONNECT and CONNECT-UDP
  over H1/H2/H3. It does not use the CONNECT-IP server's TUN/NAT architecture.
- Start with `docs/USER_GUIDE.md`, `commands.go`, `caddyfile.go`, `handler.go`
  and `app.go`. Preserve local QUIC/x/net replacements; patched x/net is used
  regardless of the retained `http2legacy` compatibility tag.
- CONNECT authority differs from TLS SNI. Preserve listener matching,
  destination protections, bounded resources and reload ownership. A stable
  unique `relay_id` supports eligible tunnel retention, not every security change.
- Keep the Debian 13 selective first-install/H2-profile workflow distinct from
  general `deploy/install.sh` upgrades. Standalone payloads are generated snapshots.
- Relay authentication does not protect Caddy's administration API. Distinguish
  protocol tests, stubbed installers, native service observations and physical
  Apple-device acceptance when reporting results.

## Repository-wide contribution rules

The following six rules apply to this repository and all its subdirectories.

### 1. Anonymity and English

- Maintain complete anonymity in contributions and change metadata.
- Use exactly `Anonymous <anonymous@example.invalid>` as both the raw Git
  author and committer of every new commit, and as the tagger of annotated tags.
  Keep commits and tags unsigned. Do not add personal attribution, identity
  trailers, agent session identifiers or personal account details. Preserve
  required legal attribution.
- Keep repository text and change metadata in English. Do not introduce Chinese,
  Korean or Russian content, Han, Hangul or Cyrillic characters, or dedicated
  CJK/fullwidth punctuation. Use ASCII punctuation for new prose. Preserve
  protocol data, existing test semantics and required legal notices.

### 2. Read before editing and preserve design objectives

Before making any change, read the project's design objectives, commit history,
change history and entire codebase. No change may violate the design objectives
unless the user explicitly requests changing those objectives.

### 3. Minimal necessary changes

- Every change must be minimal and necessary for the requested task.
- Do not perform large refactors unless the user explicitly requests them.

### 4. Server requirements

All MASQUE-related servers must have no violations of applicable IETF
specifications, no known performance or security issues, and no regressions.

All network-relay-related servers must have no violations of applicable IETF
specifications and Apple's specifications, no known performance or security
issues, and no regressions.

### 5. Client requirements

Clients are not required to strictly follow IETF or Apple specifications, but
must remain fully compatible and interoperable with their corresponding
servers, with no serious performance or security issues and no regressions.

### 6. Test before committing

- No change may introduce new problems or regressions.
- Test changes before committing. Commit only after the tests appropriate to
  the change pass and no new issues are found.
- Failed, skipped, unavailable or interrupted tests do not count as passes.
  Do not commit changes whose required validation is incomplete.
