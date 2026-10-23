# Domain selection provenance

The Debian one-click installer uses the same default sources and cleaning pipeline as `ArcCal/network-relay/deploy/install.py` at commit `a8cc0e8f3b3949de83634f52ff422c41cb87615d` (verified 2026-10-12).

`deploy/global-profile.py` and `google-ai-social.txt` retain the original copied bytes. `public-suffix-icann.dat` uses equivalent ASCII DNS A-labels; its normalized ICANN rules are identical to the upstream snapshot. The helper is imported by `deploy/selective-profile.py`; its Rust-specific command-line entry point is not invoked. Existing Caddy `global-services.txt` remains unchanged and is not added to the one-click installer base.

The default combines the 106-name Google/AI base with gfwlist and all eighteen blackmatrix7 sources: Cloudflare, Gemini, OpenAI, Anthropic, Google, GitHub, Twitter, Jsdelivr, Pandora, Spotify, Reddit, Discord, iCloudPrivateRelay, Claude, AppleNews, AppleProxy, TikTok, and TigerFintech. No Loyalsoldier proxy list is included.

The copied helper retains source validation, reported unsupported-rule omissions, ICANN-only root-domain widening, child collapse, sorting/deduplication, `.adult` exclusions, and relay-host exclusion. Root widening deliberately includes other tenants on shared hosting/CDN roots. The generated profile has nonempty `MatchDomains`, excludes the relay hostname and its subdomains, and is smaller than 524288 bytes. Other device VPN/proxy configurations may still affect unmatched traffic.

Data attribution and licensing are retained in `LICENSE.domain-list-community` and the Public Suffix List file's MPL-2.0 notice. The PSL snapshot was fetched 2026-10-06: version `2026-10-01_23-02-52_UTC`, upstream commit `6cd82aff889e3d64e5e03bc5c1f43da1934a960a`.

SHA-256 of the original upstream copies:

```text
18ec3021e176033b17a4226c63bab2c0a8f46029b5138e62950ec5a12144b64a  deploy/global-profile.py
b85cc1cedd63e8160a621c79e710f7a49d48c06871b0837e7d93816d986d73fc  deploy/domains/google-ai-social.txt
c296bb2831fb2828dc9eaea2db9c937b3171744c56624446be31b5f739bb2db0  deploy/domains/public-suffix-icann.dat
```

SHA-256 of the current bundled suffix data:

```text
e25e17e28343951cd1b34423c3e74b08d23ba183a232edb13583040c6a4b26e8  deploy/domains/public-suffix-icann.dat
```
