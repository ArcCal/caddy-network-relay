# Domain lists

`google-ai-social.txt` is used to generate Apple `MatchDomains`: each line matches a domain and its subdomains, and connections that match nothing are not proxied by this relay configuration. Keep the match list non-empty; do not use an empty list to mean "everything direct", because for Apple an empty match list means exactly the opposite.

It covers Google/Gemini sign-in and common resources, Gmail, Drive, Photos, Maps and YouTube; Claude and artifacts/MCP content; X/Twitter/Grok; and OpenAI/ChatGPT/Sora with their common voice endpoints. Including ChatGPT is a choice of this general-purpose AI routing preset; services you do not need can be deleted group by group.

On 2026-10-01 the service endpoints were selected by comparing against the `google`, `youtube`, `anthropic`, `twitter`, `xai` and `openai` data in [v2fly/domain-list-community](https://github.com/v2fly/domain-list-community/tree/2d71342eea1720da57261b55663c9d55619e9b1c/data). The source is community-maintained domain data, **not an official allowlist that each vendor guarantees to be complete**; attempts to read Google's and Claude's official help pages returned 403 in the environment used. The source data's MIT license is kept in `LICENSE.domain-list-community`.

The whole Google corporate asset list and ad list were not imported, and neither all of `cloudflare.com`, `amazonaws.com`, `azure.com`, `appspot.com` nor `livekit.cloud` is proxied. Only clear-cut service domains and a few specific CDN/voice hosts were added. Apple MatchDomains does not support the regular expressions in the community rules, so the regular expression for ChatGPT's dynamic Azure WebPubSub hosts was not crudely widened to the whole Azure domain.

Domains change, and this is not a complete list of each app's hosts captured release by release. For Google's regional domains only the common ones are listed; redirects in other regions, payment flows or dynamic third-party endpoints may still need to be added. If some feature does not go through the relay, temporarily add `log_requests` to `network_relay`, check the domains against the device's actual connections, and then add the narrowest rule that works.

This is **domain-based routing**, not routing by app identity: other apps that use the same Google APIs, shared verification codes or CDNs match too. Targeting a single app without affecting others needs separate device management configuration. This preset also does not override routing rules that other VPNs/proxies on the device already have.

After making changes, regenerate the profile and install it; an installed profile does not update itself when the text files change. To generate one, use `caddy network-relay profile --domains-file my-list.txt` (it can be given several times).

## Global services + gfwlist

`global-services.txt` (Meta AI/Instagram, Spotify, Pandora, NYT, Wikipedia, YouTube Music and more) plus `google-ai-social.txt` and the [gfwlist](https://github.com/gfwlist/gfwlist) make up the `-global` profile that the install script generates:

```bash
caddy network-relay profile --host relay.example.com --user iphone \
  --domains-file deploy/domains/google-ai-social.txt --domains-file deploy/domains/global-services.txt \
  --gfwlist --ui-toggle-enabled false
```

- The password is prompted for when it runs (input not shown), or read from standard input with `--password-stdin`.
- The gfwlist is downloaded at run time (`--gfwlist-file` uses a local file); the list itself is not in the repository. Both the official base64 version and the plain-text version can be read.
- Apple's `MatchDomains` can only hold domains: the gfwlist's regular expressions, IP addresses and `@@` exception rules are dropped, and rules limited to a URL path send the whole domain through the relay; counts for each kind are printed at the end. Subdomains whose parent domain is already in the list are merged.
- The relay's own domain goes into `ExcludedDomains`. `--ui-toggle-enabled false` keeps the relay from being turned off in Settings on the device (iOS/macOS 26+); the profile itself can still be removed.
- Profiles contain the password in plain text; they are ignored by `.gitignore`. Do not commit them or pass them around.
