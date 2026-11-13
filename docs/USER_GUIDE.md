# Caddy Network Relay practical user guide

This guide covers deployment, profiles, routine administration, recovery and
verification of the `network_relay` Caddy plugin. It distinguishes the selective
first-install script from the general installer and manual integration.

Replace `relay.example.com`, `203.0.113.10`, usernames and paths with your own
values. The example address is reserved for documentation, not a working server.
Run administrative commands on the VPS and SCP downloads on your own computer.

## Contents

- [Purpose and component selection](#purpose-and-component-selection)
- [Choose an installation method](#choose-an-installation-method)
- [Prepare DNS and network access](#prepare-dns-and-network-access)
- [Fresh selective Debian 13 installation](#fresh-selective-debian-13-installation)
- [Manual build and Caddy integration](#manual-build-and-caddy-integration)
- [Create and install profiles](#create-and-install-profiles)
- [Verify the complete path](#verify-the-complete-path)
- [Manage users and server policy](#manage-users-and-server-policy)
- [Reload, upgrade and migrate](#reload-upgrade-and-migrate)
- [Stop, recover and uninstall](#stop-recover-and-uninstall)
- [Troubleshooting](#troubleshooting)
- [Tests and acceptance evidence](#tests-and-acceptance-evidence)

## Purpose and component selection

The plugin carries TCP through classic HTTP CONNECT and UDP through CONNECT-UDP
(RFC 9298), over HTTP/1.1, HTTP/2 and HTTP/3. UDP uses HTTP Datagrams on H3 or
capsules on stream-based transports. Caddy manages HTTPS certificates and the
ordinary website. Apple's built-in relay feature uses a generated mobileconfig;
no additional client application is required for that mode.

This is separate from the standalone Rust
[network-relay](https://github.com/ArcCal/network-relay) server. Compatible hashes
and the client-facing protocol can migrate, but configuration, service ownership,
TLS management and reload policy differ. Network Relay NF/RS are compatible
explicit SOCKS clients in the Rust repository; their platform acceptance is
separate from this server's.

This plugin is not CONNECT-IP, a TUN VPN or a WARP client. The all-traffic Apple
relay setting selects eligible application traffic; it does not transport ICMP
or guarantee that every application with an independent networking stack obeys
the OS relay. Forwarded Internet traffic leaves from this server's network.
The Rust repository's experimental WARP-egress relay is a different application.

## Choose an installation method

| Method | Intended deployment | Important boundary |
| --- | --- | --- |
| Root `caddy-network-relay-install-debian13.sh` | Fresh Debian 13 x86_64 VPS, selective H2-only Apple profile | Bundled source snapshot; refuses existing installations; not an upgrade script |
| `deploy/install.sh` from a checkout | Managed Debian 12+/Ubuntu 22.04+ x86_64/arm64, upgrades and optional Rust replacement | Separate profile/upgrade workflow; uses source in that checkout |
| Manual build/integration | Existing Caddy or custom deployment | Operator owns service, TLS, routing, rollback and credential handling |

Use one coherent installation method. Do not apply one script's upgrade
instructions to another script's installation. Check the actual Release asset
or Actions artifact list before expecting a prebuilt download; a build workflow
or source archive alone is not an uploaded binary. Ordinary upstream/package
Caddy does not contain this plugin.

## Prepare DNS and network access

Before installing:

1. Reserve a public address and create a DNS-only A record. Any AAAA record must
   also lead to a reachable address on this server. Cloudflare's HTTP proxy must
   be disabled for this hostname.
2. Allow TCP 80 and 443 in the provider firewall for Caddy's public certificate
   challenges and H2 relay. Allow UDP 443 for H3 clients. The selective H2-only
   Apple profile does not require a working H3 path.
3. Keep SSH allowed in both provider and host firewalls. The installer cannot
   configure the provider firewall. Preserve a working administrative session
   while checking installation.
4. Identify existing owners of TCP 80/443 and UDP 443. Rust Network Relay, nginx,
   another Caddy installation or another QUIC service may conflict.
5. Provide the documented build resources: at least 1 GiB RAM, approximately
   3 GiB free disk and swap when needed. A serial build can take several minutes.

On the VPS:

```bash
cat /etc/os-release
```

```bash
uname -m
```

```bash
getent ahosts relay.example.com
```

```bash
ss -lntup
```

Resolve listener conflicts rather than letting an installer stop unrelated
services. Normal forwarding does not require host IP forwarding, a TUN device
or `CAP_NET_ADMIN`. Installation requires root for packages, service ownership
and port allowances; the installed network process runs as `caddy` with low-port
bind capability.

## Fresh selective Debian 13 installation

Use the [complete selective deployment instructions](debian13-selective-install.md)
for optional source-list inputs, packaging and failure behavior.

### Download, verify and run

Using a browser signed into GitHub with repository access, download:

- [caddy-network-relay-install-debian13.sh](../caddy-network-relay-install-debian13.sh)
- [caddy-network-relay-install-debian13.sh.sha256](../caddy-network-relay-install-debian13.sh.sha256)

An already-authenticated GitHub CLI is another option. Anonymous raw-file URLs
can return 404 because this repository is private. Keep the original filenames.

On a Mac, verify:

```bash
shasum -a 256 -c caddy-network-relay-install-debian13.sh.sha256
```

Upload from your computer:

```bash
scp caddy-network-relay-install-debian13.sh caddy-network-relay-install-debian13.sh.sha256 root@203.0.113.10:/tmp/
```

On the VPS, verify again:

```bash
cd /tmp
sha256sum -c caddy-network-relay-install-debian13.sh.sha256
```

Continue only after `OK`:

```bash
sudo bash /tmp/caddy-network-relay-install-debian13.sh --domain relay.example.com --email you@example.com --user iphone
```

The script embeds its source, local transport replacements, helpers and domain
data. It downloads the verified Go toolchain, public dependencies and enabled
domain sources, builds Caddy, installs the private configuration/profile and
starts the service. No private GitHub token is required on the VPS. Its payload
is a fixed source snapshot, not an automatic fetch of future `main` revisions.

`--binary /tmp/caddy` can use an existing Linux x64 executable. The script
checks architecture and module presence, stages it away from a possibly noexec
upload directory, and never silently replaces that choice with source building.

### Routing selected by this installer

It combines the bundled base list, gfwlist and eighteen service lists. Domains
are normalized with bundled ICANN Public Suffix List data, sorted, deduplicated,
collapsed and matched as registered roots plus subdomains. The relay hostname
is excluded. The result must be nonempty and smaller than 524288 bytes.

This is not a complete implementation of the source rule engines: unsupported
regex/IP/process/keyword rules are discarded, exception rules are discarded,
and path rules become whole-domain rules. A shared-hosting/CDN hostname can
widen to a registered root used by unrelated services. Inspect the final roots
before treating the profile as precise per-service isolation.

Every enabled source must succeed; download failures do not silently install a
partial profile. Explicit `--no-gfwlist` and `--no-service-rules` are operator
choices. Offline inputs are available through the documented flags.

The generated profile contains **HTTP2RelayURL only**. UDP applications still
use CONNECT-UDP capsules over H2. H1/H2/H3 remain available to other server
clients. Profile changes must be reinstalled on devices; installed profiles
do not refresh domain lists automatically.

### Retrieve the profile privately

On your computer:

```bash
scp root@203.0.113.10:/etc/caddy/relay/relay.example.com-iphone.mobileconfig ~/Downloads/
```

For ordinary-user SSH, use `sudo install -m 600` on the VPS to make a temporary
copy owned by that user, retrieve it and delete the copy. The profile contains
the recoverable password; do not put it under the public website or paste it
into a support request. This Caddy plugin does not implement the Rust server's
expiring one-use profile links.

Install through device profile settings and remove obsolete profiles. Delete
server/computer copies after installation or retain an intentionally protected
credential backup. The Caddyfile stores only a hash; if neither password nor
profile survives, rotate the account to create a replacement.

### Installed state and failure behavior

| Path | Purpose |
| --- | --- |
| `/usr/local/bin/caddy` | Caddy with the plugin |
| `/etc/caddy/Caddyfile` | Hostname and hashed credential, normally root:caddy 640 |
| `/etc/caddy/relay/` | Root-only profile directory; files mode 600 |
| `/etc/systemd/system/caddy.service` | Unprivileged service with bind capability |
| `/var/lib/caddy/` | Service home, ACME account and certificate state |
| `/var/www/relay/index.html` | Ordinary website |
| `/var/cache/caddy-network-relay/` | Build cache, normalized domains and diagnostics |
| `/opt/caddy-network-relay/go/` | Verified build toolchain |
| `/etc/sysctl.d/60-caddy-network-relay.conf` | Persistent UDP buffer settings |

The selective script refuses existing Caddy installations/packages or an active
Rust relay. It validates profile inputs before starting a service. Startup
failure removes the new candidate binary/unit/configuration/profile, but
dependencies, cache, service user, website and host firewall/sysctl changes are
not fully rolled back. A running candidate whose H2 readiness fails remains for
diagnosis and the script exits nonzero. Inspect actual state; neither a complete
install nor a pristine host is implied by an error exit.

## Manual build and Caddy integration

Use official Go 1.26.11 or 1.27.4 and Python 3. From the repository
root, prepare the exact reviewed standard-library policy without changing the
installed toolchain:

```bash
relay_go_work=$(mktemp -d)
python3 deploy/go-tls/prepare.py "$(go env GOROOT)" "$relay_go_work/go"
export GOROOT="$relay_go_work/go" GOTOOLCHAIN=local
export GOFLAGS=-tags=relay_tls9846_v1
CGO_ENABLED=0 go build -tags http2legacy,relay_tls9846_v1 -trimpath -o caddy ./cmd/caddy
```

```bash
./caddy version
```

```bash
./caddy list-modules
```

Confirm `http.handlers.network_relay` is present. No xcaddy is required for this
build. Check the built dependency metadata as well:

```bash
go version -m ./caddy
```

The `build` record must retain `-tags=http2legacy,relay_tls9846_v1`.
The package requires both reviewed TLS and HTTP/1 standard-library constants;
a stock compiler or missing policy tag fails compilation. Unsupported Go source
versions require review before the preparer accepts them. See
[source policy and provenance](../deploy/go-tls/UPSTREAM.md).

Each module must be immediately followed by its reviewed local replacement:

| Module | Replacement |
| --- | --- |
| `github.com/quic-go/quic-go` | `./third_party/quic-go` |
| `golang.org/x/net` | `./third_party/x-net` |
| `github.com/go-jose/go-jose/v3` | `./third_party/go-jose-v3` |
| `github.com/go-jose/go-jose/v4` | `./third_party/go-jose-v4` |

Build from the repository root so all four replacements apply. Go ignores a
dependency's replacements: a custom main module must apply all four itself.
Unpatched copies can compile successfully while losing protocol or security fixes.

The documented build retains the accepted `http2legacy` tag for compatibility.
The patched x/net HTTP/2 implementation is used on all supported Go versions
regardless of that tag. The supplied service also sets
`GODEBUG=http2xconnect=1` for extended CONNECT. Preserve the reviewed module
replacements instead of assuming that changing a build tag selects them.

Generate an account:

```bash
./caddy network-relay passwd --name iphone
```

Use the complete generated user line in a Caddyfile:

```caddyfile
relay.example.com, :443 {
    network_relay {
        relay_id relay.example.com
        user iphone REPLACE_WITH_COMPLETE_GENERATED_HASH
    }
    root * /var/www/relay
    file_server
}
```

The hash is a placeholder, not a working credential. Provide the real hostname,
a readable website `index.html` and reachable ACME challenge ports. The
`, :443` matters: CONNECT's HTTP authority is the **target**, while TLS SNI is
the relay hostname; a hostname-only site may never receive those requests.

The plugin is ordered ahead of ordinary website handlers. It serves H3 on the
same UDP port with Datagrams enabled while retaining Caddy's TLS and routing.
If the server's protocol settings disable H3, the plugin does not re-enable it;
generate profiles accordingly. Other websites can share the process, subject to
compatible listener/trust policies. Exclude other hostnames served by the same
Caddy from the relay profile when their own site handlers would intercept
CONNECT requests to them.

Validate with the candidate executable before installing or reloading:

```bash
./caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile
```

For a foreground test with the documented environment:

```bash
GODEBUG=http2xconnect=1 ./caddy run --config /etc/caddy/Caddyfile --adapter caddyfile
```

Do not run a second instance over an active service. Use the
[service template](../deploy/caddy.service) and [deployment details](deploy.md)
for permissions and systemd installation instead of permanently running the
network process as root.

Keep Caddy's administration endpoint on loopback or an appropriately protected
administrative socket. Its ordinary local admin API is not authenticated by
relay passwords. Do not expose it to the public network; restrict local access
as needed for the host's trust model. Protecting profile files does not by
itself protect configuration access through Caddy's administration interface.

## Create and install profiles

| Feature | Apple OS requirement |
| --- | --- |
| Basic managed relay profile | iOS/iPadOS 17+, macOS 14+ |
| Exact FQDN match/exclusion | iOS 18.4+, macOS 15.4+ |
| User toggle and DNS-failover fields | iOS/macOS 26+ |
| DDM declaration output | OS 27+ management workflow; installation acceptance separate |

For a first explicit-domain test, run on the VPS as root:

```bash
sudo caddy network-relay profile --host relay.example.com --user iphone --match-domain example.com --exclude-domain relay.example.com --no-http3 --ui-toggle-enabled true -o /etc/caddy/relay/iphone.mobileconfig
```

Type the password at the non-echoing prompt. `--password-stdin` supports
controlled automation. Prefer these to `--password`, which exposes the secret
in command arguments and shell history.

| Option | Effect |
| --- | --- |
| `--match-domain DOMAIN` | Domain plus subdomains; repeatable |
| `--match-fqdn HOST` | Exact hostname on supported OS versions |
| `--exclude-domain` / `--exclude-fqdn` | Corresponding exclusions |
| `--domains-file FILE` | Domain lines/comments; repeatable |
| `--gfwlist` / `--gfwlist-file FILE` | Download or use existing converted list input |
| No match/list inputs | All eligible traffic; not "match nothing" |
| `--no-http3` / `--no-http2` | Write only one relay URL mode; do not disable both |
| `--ui-toggle-enabled true` | Preserve supported manual disable control |
| `--allow-dns-failover true` | Explicit system DNS fallback on supported OS; omitted default false |
| `--port` / `--udp-template` | Must agree with the server |
| `--identity FILE.p12` | Include a client identity |
| `--ddm` / `--identity-asset ID` | Management declaration path, not a normal manually installed profile |

Avoid exact-FQDN-only profiles on OS versions that ignore that field. An empty
match list can unexpectedly widen traffic selection. Start with a supported
explicit domain and enabled toggle before rolling out broad lists or disabling
user control.

Transfer privately, then finish profile installation in iPhone/iPad Settings
or macOS System Settings's profile/device-management pane. Labels vary by OS.
A regenerated file does not update an already installed device automatically.
Same-domain/user profiles retain their identifier for replacement. Remove
obsolete, conflicting profiles; avoid dotted usernames that can create
host/user identifier collisions across multiple relay deployments.

Removing a device profile stops that relay configuration. Stopping only the VPS
service can leave matching applications unable to connect. UI-toggle false
intentionally removes the simpler supported switch. OS relay selection does not
override other installed VPNs or proxies.

## Verify the complete path

Check service state and recent logs on the VPS:

```bash
systemctl status caddy --no-pager -l
```

```bash
journalctl -u caddy -n 100 --no-pager -l
```

Check listeners with `ss -lntup` and the ordinary HTTPS website. These establish
process/listener/TLS behavior, not authenticated relay forwarding.

Run a local end-to-end relay check retaining the TLS hostname:

```bash
caddy network-relay check --server relay.example.com --address 127.0.0.1 --user iphone
```

It tests TCP and UDP over H1/H2/H3 plus anonymous CONNECT rejection. Defaults
are a TCP fetch from `example.com:80` and a UDP DNS query to `1.1.1.1:53` for
`example.com`. Select permitted targets with `--tcp-target`, `--udp-target`
and `--dns-name`; other options include `--port`, `--udp-template`,
`--ca` and duration-valued `--timeout 10s`. A private `--ca` changes trusted
roots, not hostname verification. Do not clear destination protections merely
to satisfy a test fixture.

Repeat from another network without the loopback override to verify public
DNS/routing/provider firewall access. Local loopback success cannot establish
that a phone on another network can connect.

The selective installer gates readiness on H2 TCP/UDP and the existing H1
anonymous rejection check. H1/H3 diagnostics remain recorded, but an H3 failure
does not invalidate its intentional H2-only profile. The standalone helper
still reports its complete three-protocol result. Interpret rows against the
intended mode rather than discarding arbitrary failures.

For actual Apple-device acceptance, install one profile, disable competing
VPN/proxy apps for the experiment, access a matched domain, and correlate the
destination with temporary `log_requests` journal entries. Test an unmatched
and an excluded domain too. Follow the [on-device procedure](test-on-device.md).
The log is sampled at 10/s process-wide with burst 20; it is useful positive
evidence, not complete accounting. A working webpage or IP-check site alone
does not establish relay selection, UDP correctness or DNS-failover policy.

## Manage users and server policy

### Password users

Use one account per device:

```bash
caddy network-relay passwd --name ipad
```

Add the complete printed `user NAME HASH` inside `network_relay`, validate and
reload, then generate that user's profile. The generated high-entropy password
uses PBKDF2-SHA256. `--stdin` hashes a chosen password with Argon2id;
`--fast-hash` is only for an explicitly supplied random secret of at least
24 characters. `--expires RFC3339` ends the account and its existing tunnels
at the specified instant.

For rotation, replace the existing user line, validate/reload, regenerate and
reinstall the profile. For revocation, remove the line and reload. Changed or
removed credentials revoke active tunnels. The server cannot reconstruct the
original password from its hash.

### Important directives

| Directive | Default or operational meaning |
| --- | --- |
| `relay_id ID` | Unique security-domain ID; needed to retain eligible tunnels across reload |
| `udp_template PATH` | Standard `/.well-known/masque/udp/{target_host}/{target_port}/`; client must match |
| `blocked_destinations CIDR...` | Private/loopback/own-address/special protections; explicit list replaces default |
| `blocked_ports PORT...` | Port 25 by default, for TCP and UDP |
| `connect_timeout DURATION` | `10s`, range 1s-2m |
| `udp_idle_timeout DURATION` | `5m`, range 2m-1h |
| `max_tunnels COUNT` | Memory-derived admission ceiling; not exact RSS budget |
| `max_tunnels_per_user COUNT` | `512` |
| `max_bytes_per_second_per_user N` | `0` unlimited; aggregate payload both directions; TCP waits, excess UDP drops |
| `max_udp_packets_per_second_per_user N` | `0` unlimited; aggregate UDP packet budget |
| `log_requests` | Off by default; sampled diagnostic request logging |

A bare `blocked_destinations` disables the default list and can expose loopback
services/cloud metadata to relay users. Keep defaults unless private destinations
are an explicit requirement with a restricted trust boundary. Every DNS result
is checked, as are embedded IPv4 addresses in supported IPv6 transition forms.

Admission and queued-data limits do not account for every process/kernel byte.
Size memory, descriptors, CPU and network limits using staging workloads rather
than treating a synthetic concurrency pass as a capacity guarantee for any VPS.

### Certificate authentication

`caddy network-relay identity --name ipad -o ipad.p12` creates an encrypted
PKCS#12 and prints its fingerprint user line and password. Add the certificate
fingerprint to the user and create the profile with `--identity`.

The listener also needs Caddy TLS client-certificate settings and explicit
`strict_sni_host insecure_off` handling for CONNECT authorities. The plugin
refuses the incompatible strict-SNI/Host setup. Use the complete
[TLS client-certificate procedure](deploy.md#tls-client-certificates), not just
an identity-bearing profile. Use a dedicated listener/security boundary rather
than relying on different client-auth requirements across unrelated websites on
one listener.

`--identity-certificate-uuid` and DDM `--identity-asset` refer to different
management mechanisms. Protect PKCS#12/profile copies; embedding the identity
password changes the protection they provide. Native Apple certificate-auth
acceptance remains separate from generated-file/parser tests.

## Reload, upgrade and migrate

### Validate and reload

```bash
caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile
```

Only after validation succeeds:

```bash
systemctl reload caddy
```

Invalid reloads retain the running configuration. Valid tunnels survive only
when explicit `relay_id`, credentials, destination policy and relevant
traffic/trust policy remain compatible. Without an ID, old tunnels are revoked.
Never reuse IDs across tenants. Security changes can intentionally disconnect
traffic; do not assume every successful reload is seamless.

### Daily operation and certificates

Preserve `/var/lib/caddy` across binary upgrades: it contains certificate/ACME
state. Keep DNS/challenge reachability valid and inspect renewal errors in the
journal. Deleting state and reinstalling repeatedly can hit public CA limits.

Check status, recent logs, disk use, account expiry and an external relay probe.
For incidents, record build/module identity, source version, transport, test
location, exact symptom and sanitized logs/configuration. Never share profiles,
passwords, private keys or unredacted authorization headers. Request logging
can reveal usernames and destination metadata even when secrets are redacted;
disable it after diagnosis.

### Upgrade the matching deployment

For a deployment managed by `deploy/install.sh`, use a new source checkout and
the documented no-argument upgrade. It preserves managed configuration/profiles,
builds a candidate and uses its own rollback path. Read actual service/check
output; a running-but-unready candidate is not automatic success.

The selective Debian 13 script is first-install only and refuses reruns. Upgrade
its installed binary deliberately with a reviewed manual procedure. Do not
delete its Caddyfile to make it appear to be a fresh installation.

For manual upgrade, save the known-good executable and private configuration,
then build a candidate from the intended checkout:

```bash
relay_go_work=$(mktemp -d)
python3 deploy/go-tls/prepare.py "$(go env GOROOT)" "$relay_go_work/go"
export GOROOT="$relay_go_work/go" GOTOOLCHAIN=local
export GOFLAGS=-tags=relay_tls9846_v1
CGO_ENABLED=0 go build -tags http2legacy,relay_tls9846_v1 -trimpath -o caddy.new ./cmd/caddy
```

Check `go version -m ./caddy.new` against the four reviewed replacement pairs in
the [manual build checks](#manual-build-and-caddy-integration).

```bash
./caddy.new validate --config /etc/caddy/Caddyfile --adapter caddyfile
```

Verify the module, install the candidate and restart during a planned outage.
Confirm local/external relay checks. Restore the saved executable/configuration
and restart if needed. A configuration reload does not replace the running
program after an on-disk binary update.

Regenerate domain-list profiles intentionally and reinstall on each device.
Passwords are still required; refreshing lists is not permission to expose
credentials in shell arguments. Developers changing source/helper/data snapshots
must repackage the standalone installer and verify its payload; an existing
download does not follow the repository automatically.

### Migrate from the Rust server

The general installer's `--replace-network-relay` disables the old Rust service
to free its port, retaining files for rollback. The new first-install credential
differs, so old profiles cease working unless you deliberately retain compatible
hash, host, user and port. Hash compatibility does not recover the old password.
Caddy manages its own certificates independently of Certbot.

Back up the old service/configuration and identify which program owns port 443.
Test all intended protocols and device profiles before removing the previous
deployment. The selective first-install script is not the Rust-replacement
installer.

## Stop, recover and uninstall

Disable/remove the corresponding device profiles first, or keep the supported
toggle available. An unavailable server can leave matching applications offline.

For a dedicated deployment:

```bash
sudo systemctl disable --now caddy
```

This stops **all websites and tenants in that Caddy process**. On shared Caddy,
remove only this handler and reload instead. Process exit releases listeners;
it does not remove profiles, packages, certificates or firewall allowances.

For full removal of a dedicated installation, save necessary private state,
stop/disable it, remove its owned binary/unit and run `systemctl daemon-reload`.
Then deliberately remove owned configuration/profiles, website, cache/toolchain,
sysctl file and certificates only after checking sharing and recovery needs.
Removing the sysctl file alone does not restore previous runtime values. Do not
delete shared Caddy state, other websites or SSH rules indiscriminately.

If rollback reports failure, inspect the running/enabled service state, unit,
candidate executable and backup paths. A recovery message does not prove the
old process is available. The selective installer's narrower cleanup contract
is described above and in its deployment guide.

## Troubleshooting

| Symptom | Check | Next action |
| --- | --- | --- |
| Private script/source download returns 404 | Signed-in repository access and download method | Use authenticated browser/CLI; never publish a credential-bearing URL |
| `unrecognized directive: network_relay` | `caddy list-modules`, executable path | Use this repository's plugin build |
| Installer refuses existing Caddy/Rust | Installer chosen, service/package/Caddyfile ownership | Use matching upgrade/migration; do not erase config to bypass protection |
| Build killed or fails | Toolchain, first compiler error, RAM/swap/disk | Match go.mod, provide resources; retain reviewed replacements |
| Public TLS unavailable | A/AAAA, DNS-only state, ACME log, TCP reachability | Correct DNS/firewall; avoid repeated certificate-state deletion |
| Website works but CONNECT fails | `, :443`, account, expiry and profile password | Fix site matching and credentials; website success is weaker evidence |
| CONNECT 421 with client auth | Strict SNI/Host policy | Follow dedicated-listener proxy-authority setup |
| Bad credentials get an ordinary response | Actual account versus installed profile | Cover behavior is intentional, not tunnel admission |
| H2 works, H3 fails | Provider/host UDP 443, client network UDP policy | Keep deliberate H2-only operation while diagnosing QUIC |
| TCP works, H2 UDP fails | Extended CONNECT/build mode, target policy | Use documented build/service environment and permitted UDP probe |
| Loopback passes, remote fails | Public DNS/address/firewall | Test from another network; local check does not test ingress boundary |
| Webpage works but relay use uncertain | Match list and temporary sampled request logs | Observe a matched destination; test unmatched/excluded controls |
| Profile captures everything | Empty match list, unsupported FQDN-only fields | Remove/regenerate explicit supported selection and reinstall |
| Too many domains use relay | Registered-root/shared CDN widening | Review generated roots; choose narrower inputs deliberately |
| 403 / destination denial | DNS results, blocked addresses/ports | Keep protection unless private access is an intentional restricted requirement |
| 503 / resets under load | User/tunnel/data budgets, cgroup, descriptors | Stage capacity and tune from evidence |
| UDP gaps under load | Rate budgets, MTU, flow idle age | Excess packets drop by policy; TCP success does not prove lossless UDP |
| Reload disconnects all tunnels | Missing/changing relay ID, policy/trust changes | Set unique stable ID intentionally; revocation can be expected |
| Rotated password still fails | Server user line and installed profile | Validate/reload, then regenerate/reinstall |
| New binary seems inactive | Running process version/start time | Restart; config reload does not execute the new binary |

## Tests and acceptance evidence

These are existing records and reproducible procedures, not fresh deployment
tests performed while writing this guide. Each report belongs to its recorded
source, toolchain and environment; an old pass is not certification of every
later build.

| Evidence | Established coverage | Remaining boundary |
| --- | --- | --- |
| [Production readiness](production-readiness.md) | Local race/protocol/fault/MTU/resource checks, independent clients, upstream transport checks and limited native systemd observations | Complete Apple acceptance, arbitrary WAN paths and production capacity |
| [Hardening report](production-hardening-report.md) | Recorded 1,000-account synthetic H3 run, real Debian systemd process checks and selected rollback faults | Not a production RAM estimate or every download/ACME/device scenario |
| [Selective installer validation](debian13-selective-validation.md) | 48 local installer/domain/profile checks, real Caddy profile generation/adaptation, source payload verification | Fresh public VPS/ACME and physical Apple routing not executed; recorded toolchain snapshot predates current Go 1.26.11 selection |
| [Test workflow](../.github/workflows/test.yml) | Intended lint/race/vulnerability/build recipe | Workflow existence does not prove execution; selective validation records an Actions-budget-blocked run |
| [On-device procedure](test-on-device.md) | Repeatable native acceptance steps | A procedure itself is not a recorded pass |

Representative checks from the repository root, after the private Go
preparation above (keep `GOROOT`, `GOTOOLCHAIN=local`, and the policy `GOFLAGS`):

```bash
go vet ./...
python3 third_party/test_upstream.py
RELAY_STRESS_MB=16 go test -race -count=1 -timeout 40m ./...
python3 deploy/test_install.py -v
python3 deploy/test_selective_profile.py -v
python3 deploy/test_debian13_selective_install.py -v
```

Read fixture prerequisites: some checks use a real built Caddy binary while
package/service/network commands are stubbed. Installer transaction tests do not
deploy a real public VPS. Workflows also scan application and pinned upstream
transport advisories; source scanning alone is insufficient with local module
replacements. Use the workflow's versioned commands to repeat that coverage.

Before relying on a deployment, separately test current physical Apple devices,
profile installation/replacement, exact matches/exclusions, TCP/UDP, network
switches, public certificate renewal, intended IPv6/NAT64 and long-held active
and idle traffic. Local synthetic success, cross-compilation and a single H2
check each establish a useful but limited part of that acceptance.

For architecture see [design.md](design.md). For all directives/options consult
the [README reference](../README.md#configuration-reference), [deploy.md](deploy.md)
and each installed command's `--help`.
