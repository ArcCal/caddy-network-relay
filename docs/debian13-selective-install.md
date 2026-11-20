# Fresh Debian 13 x64 installation with selective HTTP/2 routing

This installer deploys Caddy Network Relay on a fresh Debian 13 x86_64 VPS.
The single uploadable Bash file includes the private repository's source,
local Go library replacements, deployment tools and bundled domain data.
A source build requires GitHub access to this private repository through Git
credentials, a signed-in `gh`, or `CADDY_NETWORK_RELAY_TOKEN`. Each run downloads
complete latest `main` to `/tmp/YYYYMMDD-HHMMSS.RANDOM/`. It also downloads the
verified Go toolchain, public Go dependencies, gfwlist and public service lists.
A supplied `--binary` and `--extract` keep their existing behavior and do not
fetch build source.

The deployment additions do not change the relay protocol implementation or
any other application's source. Bundled domain-data provenance remains in
`deploy/selective-source.json`. The embedded snapshot supports extraction and
prebuilt-binary deployment; default compilation uses freshly downloaded main.
Source, private compiler work and newly downloaded toolchains/caches are cleaned
on success, failure and normal signals. Existing tools and caches are preserved.

## Preparation and installation

1. Create a DNS-only A record for the relay hostname pointing to this VPS.
   An AAAA record, if present, must point to a reachable IPv6 address on the
   same VPS. On Cloudflare use the grey cloud, not its HTTP reverse proxy.
2. Allow inbound TCP 80 and 443 in the cloud provider's firewall. Caddy issues
   and renews a publicly trusted certificate automatically using public ACME
   challenges. No Cloudflare API key or Certbot is needed for this mode.
   UDP 443 is optional for the generated Apple profile, which only uses H2;
   enable it if other clients need the server's H3 listener.
3. While signed into GitHub with access to this private repository, download the
   [standalone script](../caddy-network-relay-install-debian13.sh) and
   [checksum](../caddy-network-relay-install-debian13.sh.sha256) using GitHub's
   Download raw file button. Anonymous curl requests cannot access this private
   repository. Save both to the Mac's Downloads folder. Upload them, replacing
   `VPS_IP` and the SSH account as needed:

```bash
scp ~/Downloads/caddy-network-relay-install-debian13.sh \
    ~/Downloads/caddy-network-relay-install-debian13.sh.sha256 root@VPS_IP:/tmp/
ssh root@VPS_IP
```

On the VPS:

```bash
cd /tmp
sha256sum --check caddy-network-relay-install-debian13.sh.sha256
sudo bash /tmp/caddy-network-relay-install-debian13.sh \
    --domain relay.example.com --email you@example.com --user iphone
```

Or run without arguments for hostname and optional email prompts. A random
account password is generated without printing it or putting it in command
arguments. It is stored in the generated private profile, not a separate
plaintext password file. No existing Caddy installation, Caddy package or
running Rust relay is overwritten. This script is for first installation;
it deliberately refuses a rerun over an existing deployment.

The installed service uses a Unix admin socket in `/run/caddy/`,
whose directory is mode 700 and belongs to `caddy`. `systemctl reload caddy`
inherits that default; other local users cannot use the default TCP admin API
to change relay credentials or routing. Explicit custom `admin` settings take
precedence. See [local administration and migration](deploy.md#local-administration)
before changing that setting or replacing an older service unit.

Building is serial and can take several minutes. `--binary /tmp/caddy` instead
uses an uploaded Linux x64 Caddy executable containing `network_relay`, checks
its ELF architecture and module, and stages it away from a possibly `noexec`
upload directory. It never silently switches a supplied binary to a build.

## Routing: copied from the Rust installer

The default base is the Rust repository's `google-ai-social.txt`, including
its Google/AI/X and user-selected GreatFire entries. It is combined with
gfwlist and all eighteen blackmatrix7 sources:

Cloudflare, Gemini, OpenAI, Anthropic, Google, GitHub, Twitter, Jsdelivr,
Pandora, Spotify, Reddit, Discord, iCloudPrivateRelay, Claude, AppleNews,
AppleProxy, TikTok and TigerFintech.

`deploy/global-profile.py` is copied unchanged from Rust Network Relay.
`deploy/selective-profile.py` adapts its existing domain functions to Caddy's
profile command. The same pipeline applies:

- Keep representable domain rules; print counts for discarded regex, IP,
  process, keyword and other unsupported rules. Gfwlist exception rules are
  discarded; path-limited rules become whole-domain rules.
- Normalize to registered roots with the bundled **ICANN** Public Suffix
  List. Private hosting suffixes are deliberately ignored, as in the Rust
  installer. A specific shared hosting/CDN host can therefore widen to a
  root such as `windows.net`, `github.io` or `cloudflare.com` and include
  unrelated services under that root.
- Sort, deduplicate and collapse redundant subdomains; remove `adult` and
  its subdomains. Exclude the relay's own hostname.
- Require every enabled source to succeed. Missing, malformed or empty
  sources stop installation; no partial fallback profile is installed.
- Require nonempty `MatchDomains` and one compact profile smaller than
  524288 bytes. An empty Apple match list would relay all traffic, so it is
  refused rather than used as a direct-routing fallback.

Each final `MatchDomains` root and its subdomains is relayed; every unmatched
domain is left direct by **this profile**. Routing is by domain, not app
identity or arbitrary destination IP. This profile does not override other
installed VPNs or proxies. It does not install a global DNS configuration.

The resulting relay dictionary has `HTTP2RelayURL` and **no** `HTTP3RelayURL`.
There is no invented `DisableHTTP3` payload key. TLS certificate verification
and password authentication stay enabled. UDP applications use CONNECT-UDP
capsules over HTTP/2. The server retains H1/H2/H3 for other clients.

Optional inputs, matching the Rust pipeline, are `--domains FILE`,
`--gfwlist-file FILE`, `--rules-dir DIRECTORY` (all eighteen YAML files),
`--no-gfwlist` and `--no-service-rules`. The two omit flags are explicit choices,
not automatic reactions to a download failure. An installed device profile
does not refresh its domain rules by itself.

## Download and observe

On the Mac, replace the hostname/account and VPS address:

```bash
scp root@VPS_IP:/etc/caddy/relay/relay.example.com-iphone.mobileconfig ~/Downloads/
```

The file contains recoverable credentials. Install it on the device, remove
old relay profiles, and keep it private. It is mode 600 under a mode 700
directory on the VPS; it is never published through the website. With an SSH
account such as `ubuntu` instead of root, use `sudo install -m 600 -o ubuntu
-g ubuntu SOURCE /home/ubuntu/device.mobileconfig` on the VPS, download that
private copy, then remove the temporary copy. Caddy's ordinary file server
does not implement the Rust server's expiring one-time profile links.

```bash
systemctl status caddy --no-pager -l
journalctl -u caddy -n 100 --no-pager -l
cat /var/cache/caddy-network-relay/check.log
```

Readiness requires real authenticated HTTP/2 TCP and UDP relay probes plus
the existing CLI's HTTP/1.1 unauthenticated-request rejection check. The CLI
also records H1/H3 diagnostics, but an H3 failure does not make an H2-only
profile installation fail. If H2 readiness fails, the service and private
profile remain for diagnosis and the installer exits nonzero. After fixing
DNS or cloud firewall settings, rerun `caddy network-relay check --server
relay.example.com --user iphone`; it prompts for the account password.

A successful readiness check covers the CLI's own H2 probes. If a device loses 63-byte outgoing UDP payloads on native H2, compare an H3-only copy of its private profile on a path with UDP 443 available. Keep its credentials, certificate settings and domain selection. [Transport options for an existing profile](https://github.com/ArcCal/network-relay/blob/main/docs/config.md#choosing-a-transport-for-an-existing-apple-profile).

## Installed files and failure behavior

| Path | Purpose |
| --- | --- |
| `/usr/local/bin/caddy` | Bundled Caddy Network Relay build or supplied binary |
| `/etc/caddy/Caddyfile` | Domain and hashed account credential, root:caddy 640 |
| `/etc/caddy/relay/HOST-USER.mobileconfig` | H2-only selective profile, root-only 600 |
| `/etc/systemd/system/caddy.service` | Unprivileged service with bind capability |
| `/var/lib/caddy/` | Caddy-managed certificates and ACME state |
| `/var/www/relay/index.html` | Default ordinary website |
| `/var/cache/caddy-network-relay/` | Build cache, normalized domains and check logs |
| Private compiler workspace | Verified build toolchain and caches; removed after the run |
| `/etc/sysctl.d/60-caddy-network-relay.conf` | UDP buffer limits, retaining higher values |

Domain gathering and profile validation precede account/service installation.
Configuration or profile failure does not start a service. A startup failure
removes the new binary, unit, account configuration and profile. Dependency
packages, build cache, system user, website and host firewall/sysctl changes
are not rolled back. The script only adds UFW port rules when UFW is already
active; it cannot configure the provider's external firewall.

## Packaging and test boundaries

```bash
python3 deploy/package-debian13-installer.py
bash caddy-network-relay-install-debian13.sh --help
bash caddy-network-relay-install-debian13.sh --extract /tmp/caddy-relay-source
```

The self-extracting payload has an embedded SHA-256 check and a separate
script checksum. After packaging, every folder in the repository and the output
folder keeps its existing permissions. Source code, helper behavior, real Caddy profile generation,
configuration adaptation and installer transaction paths can be tested
without deploying a public server. Scratch installer tests substitute apt,
systemd, port inspection and network self-check commands. They do not prove
public ACME issuance, privileged VPS service startup, or Apple-device routing;
those require deployment and an actual device.

Apple's normative payload reference is
[`com.apple.relay.managed`](https://github.com/apple/device-management/blob/release/mdm/profiles/com.apple.relay.managed.yaml).
This installer supplies that mobileconfig payload; it does not silently
replace it with declarative device management.
