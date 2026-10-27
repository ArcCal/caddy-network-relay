# caddy-network-relay

**Practical manual:** [installation, profiles, configuration, operations,
recovery, troubleshooting and validation evidence](docs/USER_GUIDE.md).

A [Caddy](https://caddyserver.com/) plugin that turns your server into a proxy for Apple's Network Relay. An iPhone, iPad or Mac **only needs one configuration profile (.mobileconfig)**, and no app, to send chosen websites (or all of its traffic) through your server.

- **Caddy handles certificates and incoming traffic**: Let's Encrypt certificates are obtained and renewed automatically; HTTP/2 and HTTP/1.1 on TCP 443 are received by Caddy itself; HTTP/3 on UDP 443 is received by the plugin inside the Caddy process (see [below](#why-the-plugin-serves-http3) for why), using Caddy's certificates, and its requests are likewise handled by Caddy.
- **Standard protocols**: TCP goes over HTTP CONNECT (RFC 9110/9113/9114) and UDP over CONNECT-UDP (RFC 9298); UDP packets travel as HTTP Datagrams (RFC 9297) on HTTP/3 and as Capsules on HTTP/2 and HTTP/1.1. This matches what `HTTP3RelayURL` and `HTTP2RelayURL` in Apple's profiles require.
- **Looks like an ordinary website**: requests without the right password get your website's answer (by default a "Welcome" page).
- This is a Go rewrite of [network-relay](https://github.com/ArcCal/network-relay) (a standalone program written in Rust) with the same features, running as a Caddy plugin. The relay protocol implementations are separate; the Debian 13 selective installer reuses the Rust deployment domain tooling. Password hashes from the old version work here as they are.

**Fresh Debian 13 x64, selective domains and HTTP/2-only Apple profiles:** download the
[standalone installer](caddy-network-relay-install-debian13.sh) and its
[SHA-256 checksum](caddy-network-relay-install-debian13.sh.sha256), then follow the
[deployment guide](docs/debian13-selective-install.md). The script includes the private
source tree, builds on the VPS, and uses the Rust installer's base list, gfwlist,
eighteen service lists and domain-cleaning pipeline.

> This project has not yet been verified with real traffic from an actual iPhone/Mac (for the automated tests and protocol interoperability tests, see the [design document](docs/design.md#6-testing)).

---

## Contents

- [Before you start](#before-you-start)
- [One-step install (Debian / Ubuntu)](#one-step-install-debian--ubuntu)
- [Installing the profile on iPhone / iPad / Mac](#installing-the-profile-on-iphone--ipad--mac)
- [Switching from the old network-relay (Rust version)](#switching-from-the-old-network-relay-rust-version)
- [Day-to-day operations](#day-to-day-operations): add users, client certificates, remove users, change passwords, upgrade, read logs, regenerate profiles, uninstall
- [Testing on a real device](docs/test-on-device.md): steps and troubleshooting for checking an iPhone/Mac after deploying
- [Common pitfalls (read this)](#common-pitfalls-read-this)
- [Already using Caddy: manual integration](#already-using-caddy-manual-integration)
- [Configuration reference](#configuration-reference)
- [Command reference](#command-reference)
- [Why the plugin serves HTTP/3](#why-the-plugin-serves-http3)

---

## Before you start

| What you need | Notes |
|---|---|
| A VPS | Debian 12 or newer, or Ubuntu 22.04 or newer (including 24.04, 26.04 and future releases), x86_64 or arm64, **at least 1 GB of memory** (building Caddy needs it; on a 512 MB machine add swap first), 3 GB of free disk |
| A domain | For example `relay.example.com`. Replace `relay.example.com` in every command below with yours |
| Firewall | The cloud provider's security group/firewall must allow **TCP 80, TCP 443 and UDP 443** (UDP 443 is the one most often forgotten) |
| Your computer | A Mac (or any computer that can run `scp`), for uploading the source and downloading the profiles |

### Step 1: DNS

At your DNS provider, add an **A record**: `relay.example.com` → the server's public IPv4 address.

- On Cloudflare, the record must be **"DNS only" (grey cloud)**. The orange cloud (proxied) makes everything fail.
- Wait for it to take effect: run `dig +short relay.example.com` on the Mac, and continue once it shows the server's IP.

### Step 2: Download the source and upload it

The repository is private: sign in to GitHub in a browser on your computer, open this repository, and click the green **Code → Download ZIP** to get `caddy-network-relay-main.zip`. Upload it from the Mac's Terminal (replace `SERVER_IP` with yours):

```bash
scp ~/Downloads/caddy-network-relay-main.zip root@SERVER_IP:/root/
```

- Google Cloud's browser SSH has an "Upload file" button at the top right; the file lands in your login user's home directory (for example `/home/YOUR_USER/`).
- On machines where you can only log in as a regular user (common on Google Cloud and AWS), replace `root@` above with `YOUR_USER@` and the path with `/home/YOUR_USER/`.

---

## One-step install (Debian / Ubuntu)

Log in to the server and become root:

```bash
sudo -i
```

Start a screen session so that a dropped connection does not interrupt the install (`-U` turns on UTF-8):

```bash
screen -U
```

Unzip (if the file is in another directory, change the path):

```bash
cd /root && apt-get install -y unzip && unzip -o caddy-network-relay-main.zip
```

Run it (replace `relay.example.com` with your domain; `iphone` is the user name and can be left out):

```bash
cd /root/caddy-network-relay-main && bash deploy/install.sh --domain relay.example.com --user iphone
```

The script: checks the system, DNS and ports (and stops without changing anything if something is wrong) → installs dependencies → downloads and verifies Go → builds Caddy with the plugin → generates a random password (**not shown**) → writes the Caddyfile → starts the service → waits for Let's Encrypt to issue the certificate → self-checks TCP and UDP over all three HTTP versions from the server itself → generates two profiles. At the end it prints the download command.

- The build takes from a few minutes to over ten minutes; lines of `go: downloading ...` scrolling past are normal.
- `all checks passed` at the end means it worked.
- Optional flags: `--email you@example.com` (Let's Encrypt uses it to tell you about certificate problems), `--no-gfwlist` (do not download the gfwlist). All flags: `bash deploy/install.sh --help`.

### The two generated profiles

Both are in `/etc/caddy/relay/`, readable only by root, and **contain the password in plain text**. The password is stored nowhere else on the server (the Caddyfile only has its hash), so once the devices have the profile, delete the files: `rm /etc/caddy/relay/*.mobileconfig`. For a new profile later, create a new password as in [Adding a user](#adding-a-user).

| File | What goes through the relay | Can it be turned off in Settings |
|---|---|---|
| `relay.example.com-iphone.mobileconfig` | Google/Gemini/YouTube, Claude, ChatGPT, X/Grok and more ([list](deploy/domains/google-ai-social.txt)) | Yes (system default) |
| `relay.example.com-iphone-global.mobileconfig` | All of the above + Spotify, Instagram, Meta AI, NYT, Wikipedia, Pandora and more ([list](deploy/domains/global-services.txt)) + every domain in the [gfwlist](https://github.com/gfwlist/gfwlist) | **No** (from iOS/macOS 26) |

**Install only one of them on each device.**

### Downloading to the Mac

Run this in the **Mac's Terminal** (not on the server). It is the command the script prints at the end:

```bash
scp root@SERVER_IP:/etc/caddy/relay/relay.example.com-iphone-global.mobileconfig ~/Downloads/
```

On machines where you can only log in as a regular user, first copy the file to that user on the server (replace `YOUR_USER`):

```bash
install -m 600 -o YOUR_USER /etc/caddy/relay/relay.example.com-iphone-global.mobileconfig /home/YOUR_USER/
```

Then on the Mac:

```bash
scp YOUR_USER@SERVER_IP:relay.example.com-iphone-global.mobileconfig ~/Downloads/
```

Afterwards, remember to delete the copy in `/home/YOUR_USER/` on the server.

---

## Installing the profile on iPhone / iPad / Mac

**First remove any old relay profile from the device** (Settings → General → VPN & Device Management). A profile with the same domain and user name replaces the old one automatically, but different profiles are all active at the same time and fight each other.

- **iPhone / iPad**: AirDrop the file from the Mac to the phone (or save it to iCloud Drive or the Files app and tap it there) → open Settings, where "Profile Downloaded" appears at the top → Install → enter the passcode.
- **Mac**: double-click the file → System Settings → General → Device Management (or Privacy & Security → Profiles) → Install.

Once installed, it is listed under Settings → General → VPN & Device Management. Open a site from the list (Gemini, for example) to try it.

**After installing, delete the copy in `~/Downloads/` on the Mac**: anyone who gets it can use your relay. Do not send this file through messaging services or email.

---

## Switching from the old network-relay (Rust version)

On the same machine, the old service holds port 443. With `--replace-network-relay`, the script disables the old service (`systemctl disable --now network-relay`; **its files are not deleted**):

```bash
cd /root/caddy-network-relay-main && bash deploy/install.sh --domain relay.example.com --user iphone --replace-network-relay
```

- The new install generates a **new random password**, and all old profiles stop working. Remove the old profile from each device first, then install the new one.
- Caddy obtains its own certificate (independent of certbot's). At most 5 certificates are issued per week for the same domain, so do not reinstall over and over.
- To keep the old password: the old version's `password_hash` (`$argon2id$...`) can go straight into a `user` line in the Caddyfile, see [Adding a user](#adding-a-user); the old profiles then keep working too (as long as the domain, user name and port stay the same).
- The old version's files (`/etc/network-relay`, `/usr/local/bin/network-relay`, the certbot certificates) are all still there. Once you are sure the new version works, you can remove them as the old version's documentation describes.

---

## Day-to-day operations

All of the commands below run on the server, as root.

### Adding a user

Use one user per device, so that retiring a device means deleting only its line.

```bash
caddy network-relay passwd --name ipad
```

It prints two lines: `password: ...` (the password, shown only this once) and `user ipad $pbkdf2-sha256$...` (a generated password is too random to guess, so a fast hash protects it as well as a slow one would, and checking it costs the server almost nothing). `--expires 2027-01-31T00:00:00Z` adds an expiry: from then on the account stops working and its open tunnels close. Add the whole `user ...` line to `/etc/caddy/Caddyfile`, below the existing `user` line inside `network_relay { ... }`:

```bash
nano /etc/caddy/Caddyfile
```

Then apply it (existing connections stay up):

```bash
systemctl reload caddy
```

Generate a profile for the new user (when prompted, paste the password from above and press Enter; it is not shown):

```bash
caddy network-relay profile --host relay.example.com --user ipad --domains-file /root/caddy-network-relay-main/deploy/domains/google-ai-social.txt --domains-file /root/caddy-network-relay-main/deploy/domains/global-services.txt --gfwlist --ui-toggle-enabled false -o /etc/caddy/relay/relay.example.com-ipad-global.mobileconfig
```

### Using a client certificate instead of a password

A device can authenticate with a certificate in the TLS handshake instead of a password in every request. Generated profiles set `KeyIsExtractable` to false for macOS 10.15+; the PKCS#12 file still contains the private key, so protect it and delete it after installation. Create it (prints the Caddyfile line and the certificate's password, shown only this once):

```bash
caddy network-relay identity --name ipad -o /etc/caddy/relay/ipad.p12
```

Add the printed `user ipad certificate <sha256>` line to `network_relay { ... }` (or add `certificate <sha256>` to an existing user line to allow both), and let Caddy ask devices for certificates. Both settings below are needed: `client_auth` with `mode request` asks for a certificate without requiring one (browsers and password users are unaffected), and because Caddy otherwise requires every request's host name to equal the TLS server name when `client_auth` is on (a CONNECT's host name is its destination), the relay refuses to start until `strict_sni_host insecure_off` is set. Do not rely on `client_auth` for access control in other sites on the same port.

```caddyfile
{
	servers {
		strict_sni_host insecure_off
	}
}

relay.example.com, :443 {
	tls {
		client_auth {
			mode request
		}
	}
	network_relay {
		user ipad certificate 3f1c...
	}
}
```

Then `systemctl reload caddy` and make the profile (the device asks for the certificate's password while installing it; `--embed-identity-password` puts it in the profile instead):

```bash
caddy network-relay profile --host relay.example.com --user ipad --identity /etc/caddy/relay/ipad.p12 -o /etc/caddy/relay/relay.example.com-ipad.mobileconfig
```

Delete the `.p12` and the profile once installed. Certificate authentication has not been verified on Apple devices by this project yet; test it on one device before relying on it.

### Removing a user / changing a password

Delete that user's line from the Caddyfile (to change the password, replace it with the line a new `passwd` prints), then run `systemctl reload caddy`. That user's open connections **are closed immediately**. Other users retain their tunnels only when `relay_id` and destination and traffic-budget policies are unchanged; without `relay_id`, all old tunnels are revoked. After changing a password, regenerate the profile and install it again.

### Upgrading

Download the new source ZIP, upload it and unzip it (as in [Step 2](#step-2-download-the-source-and-upload-it)), then run the script **without any flags**:

```bash
cd /root/caddy-network-relay-main && bash deploy/install.sh
```

Users, passwords, the Caddyfile and the profiles all stay as they are; it only rebuilds, replaces the binary and restarts. If the new version fails to start, the old one is put back automatically. The installer does not keep the password, so after an upgrade it prints the self-check command to run yourself. (Installers before October 2026 kept it in `/etc/caddy/relay/<user>.password`; an upgrade still uses that file for the self-check and reminds you to delete it.)

### Status and logs

```bash
systemctl status caddy --no-pager
```

```bash
journalctl -u caddy -n 100 --no-pager
```

Self-check (asks for the password; it is not shown):

```bash
caddy network-relay check --server relay.example.com --address 127.0.0.1 --user iphone
```

To see which requests a device actually sends: add a `log_requests` line inside `network_relay { ... }`, run `systemctl reload caddy`, then read the log. It samples at most 10 requests per second process-wide (burst 20), reports suppressed counts, and is not a complete access log; remove it when you are done.

### Regenerating the profiles

After the service lists or the gfwlist change, delete the old file and generate it again (a new file for the same domain and user replaces the old one when it is installed). It asks for the user's password; if nobody has it any more, give the user a new one first ([Removing a user / changing a password](#removing-a-user--changing-a-password)):

```bash
caddy network-relay profile --host relay.example.com --user iphone --domains-file /root/caddy-network-relay-main/deploy/domains/google-ai-social.txt --domains-file /root/caddy-network-relay-main/deploy/domains/global-services.txt --gfwlist --ui-toggle-enabled false -o /etc/caddy/relay/relay.example.com-iphone-global.mobileconfig
```

### Uninstalling

```bash
systemctl disable --now caddy
```

```bash
rm -rf /usr/local/bin/caddy /etc/systemd/system/caddy.service /etc/caddy /var/lib/caddy /var/www/relay /opt/caddy-network-relay /var/cache/caddy-network-relay /etc/sysctl.d/60-caddy-network-relay.conf
```

```bash
systemctl daemon-reload && deluser --system caddy
```

`/var/lib/caddy` holds the certificates Caddy obtained; once it is deleted, a reinstall requests new ones (mind the limit of 5 per week).

---

## Common pitfalls (read this)

| Symptom | Cause and fix |
|---|---|
| The script says "does not point to this machine" | DNS has not taken effect yet, or the A record is wrong. `dig +short DOMAIN` must equal the server's public IP |
| The script sits at "Waiting for the certificate" and the self-check finally fails | (1) The cloud firewall does not allow TCP 80/443; (2) Cloudflare's orange cloud is on; (3) more than 5 certificates were issued for the same domain within a week (`journalctl -u caddy` shows `rateLimited`) |
| The TCP self-checks all pass, but UDP/HTTP/3 fails | The cloud firewall does not allow **UDP 443**. iPhones then fall back to HTTP/2, which works but is somewhat slower |
| Ports in use | nginx/apache/the old relay is running on the machine. This plugin needs TCP 80, 443 and UDP 443 to itself; for the old Rust version use `--replace-network-relay` |
| "The apt caddy package is installed" | Run `apt remove caddy` first. The Caddy this script installs is `/usr/local/bin/caddy`, and its service is also named `caddy` |
| Nothing on the device goes through the relay | (1) Two profiles are installed and fight each other: keep only one; (2) the site you opened is not in the list (the basic profile only has Google/AI/X and the like); (3) the password was changed but the profile was not reinstalled |
| Garbled characters on screen | `screen` was started without `-U`. If you are already inside screen: press `Ctrl+A`, type `:encoding UTF-8` and press Enter |
| The browser SSH session disconnects | The script keeps running inside screen. Log in again, run `sudo -i`, then `screen -r` to get back to it |
| The build gets killed (`signal: killed`) | Not enough memory. Add 2 GB of swap: `fallocate -l 2G /swapfile && chmod 600 /swapfile && mkswap /swapfile && swapon /swapfile`, then run it again |
| `scp` says No such file | `scp` must run on the **Mac**; the path must be complete; on machines with regular-user login, copy the file to the home directory first (see above) |
| reload fails after you edited the Caddyfile | `caddy validate --config /etc/caddy/Caddyfile` shows what is wrong. A failed reload does not affect the old configuration that is running |
| Changing the site address to just the domain | **Don't.** It must be `relay.example.com, :443`: a device's CONNECT request uses the destination (for example `www.google.com:443`) as its host name, so a site that only matches your domain never receives them |
| Pasting the password or a profile to anyone (including an AI chat) | They can then use your relay. If it leaks, [change the password](#removing-a-user--changing-a-password) |

---

## Already using Caddy: manual integration

### Downloading a prebuilt binary

The test workflow builds Linux artifacts for applicable source pushes and pull requests; documentation-only changes are excluded. The release workflow can attach platform archives after successful verification and builds. Check the actual **Releases** asset list before choosing a prebuilt binary. When available, use `caddy-network-relay-<version>-linux-amd64.tar.gz` for x86_64 or `-linux-arm64.tar.gz` for ARM (`-darwin-arm64` can run `check` on a Mac), unpack `caddy`, and install it at `/usr/local/bin/caddy`. Otherwise build from source below. The repository is private: download through a signed-in browser and upload to the server.

Maintainers can request release builds in three ways. Successful jobs attach archives for Linux x86_64/arm64 and macOS Apple silicon/Intel with checksums; failed or unavailable Actions runs do not produce those downloads:

- On the GitHub website: on the right of the repository home page, **Releases → Draft a new release → Choose a tag**, type a new tag (for example `v1.0.0`) → **Create new tag on publish** → fill in a title → **Publish release**.
- Locally: `git tag v1.0.0 && git push origin v1.0.0`.
- For a tag that has no Release: **Actions → release → Run workflow**, then enter the tag name.

### Building

Needs Go 1.26 (the exact version is in `go.mod`; with `GOTOOLCHAIN=auto` it is downloaded automatically):

```bash
go build -tags http2legacy -o caddy ./cmd/caddy
```

`cmd/caddy` includes Caddy's standard modules and this plugin. Build from this
repository root: the `go.mod` replacements select the reviewed transport sources
in `third_party`. Go ignores a dependency's replacements, so an ordinary xcaddy
`--with` build does **not** include these fixes. Custom builds must apply both
replacements in their main module. The patched x/net HTTP/2 implementation is
used on all supported Go versions; the `http2legacy` tag remains accepted for
existing build scripts. See [transport patch provenance](third_party/README.md).

To build static Linux x64 and arm64 binaries of both this server and the Rust
`network-relay` from fresh sources, run this on Debian 13 or Ubuntu 26.04:

```bash
bash build-linux-servers-on-linux.sh
```

It keeps its checkout in `~/caddy-network-relay` (change it with `--repo`),
installs missing prerequisites, and writes the four binaries, logs,
`MANIFEST.txt` and `SHA256SUMS` to a new `relay-servers-*` folder. The Caddy
binaries include the Cloudflare DNS plugin. Run it with `--help` for all
options. When it ends, successfully or not, every folder in the checkout and
the results is mode 777, so other users and file synchronization tools such as
Syncthing can use them.

### Caddyfile

See [deploy/Caddyfile.example](deploy/Caddyfile.example):

```caddyfile
relay.example.com, :443 {
	network_relay {
		user iphone $pbkdf2-sha256$i=1000,l=32$...
	}
	root * /var/www/relay
	file_server
}
```

Key points:

1. **The site address must include `:443`** (or be just `:443`, with `tls` naming the certificate). The pitfalls table above explains why.
2. `network_relay` is automatically ordered before every other directive in the site (no `order` needed). Requests without the right password are passed to the directives after it (your website); CONNECT requests without a password get 405 (just like an ordinary Caddy static site) and are not passed on, so that no directive can answer 2xx and have that taken as "tunnel established".
3. The plugin **automatically takes over HTTP/3 for the server this site belongs to** (Caddy's own HTTP/3 is turned off for that server, and the plugin serves it on the same UDP port instead); no extra configuration is needed. If you removed `h3` from `servers { protocols ... }`, the plugin does not serve HTTP/3 either, and the profile then needs `--no-http3`.
4. Other sites on the same Caddy keep working as usual. But if a device goes through the relay to **another domain served by the same Caddy**, the CONNECT is received by that domain's site and fails: add those domains to the profile with `--exclude-domain`.
5. On reload, a tunnel stays up only when its explicit `relay_id`, destination policy and credentials remain valid. Omitting the ID or tightening destination policy revokes old tunnels; removed users and changed passwords revoke their tunnels immediately.

---

## Configuration reference

The `network_relay` directive (`"handler": "network_relay"` in JSON):

| Option | Default | Description |
|---|---|---|
| `user <name> [<hash>] [certificate <sha256>] [expires <time>]` | none | One user; may be repeated. The name is 1–64 letters, digits, `-` `_` `.`, and does not start with `.`. The hash is printed by `caddy network-relay passwd` (PBKDF2-SHA256 for generated passwords, Argon2id for your own; hashes from the Rust version work too); bcrypt and the output of `caddy hash-password` are also accepted. `certificate` pins a client certificate by its SHA-256 fingerprint (see [Using a client certificate](#using-a-client-certificate-instead-of-a-password)); a user needs a hash, a certificate or both. `expires` (RFC 3339) ends the account and closes its tunnels at that time |
| `udp_template <path>` | `/.well-known/masque/udp/{target_host}/{target_port}/` | The URI template path for CONNECT-UDP (RFC 9298). If you change it, generate the profiles with the same value in `--udp-template`. Supports `{var}` and the `{?a,b}` / `{&a,b}` forms |
| `blocked_destinations [<CIDR>...]` | Loopback (including the public addresses on the server's own interfaces), private networks, link-local (including cloud metadata at 169.254.169.254), multicast, reserved and documentation addresses, and so on | Addresses devices may not reach. Every address a domain resolves to is checked; IPv4-mapped IPv6 addresses are checked as IPv4, and IPv6 addresses that carry an IPv4 address (NAT64 `64:ff9b::/96`, 6to4, Teredo, IPv4-compatible) also by that IPv4 address. Setting it **replaces** the default list; the option name without any addresses blocks nothing (**dangerous**: devices can then reach services on the server that only listen on 127.0.0.1) |
| `blocked_ports [<port>...]` | `25` | Ports devices may not reach (TCP and UDP). 25 is the port for sending mail; it is blocked so that the relay cannot be used to send spam |
| `connect_timeout <duration>` | `10s` | Timeout for connecting to a TCP destination, 1s–2m |
| `udp_idle_timeout <duration>` | `5m` | How long a UDP flow may go without packets in either direction before it is closed, 2m–1h |
| `max_tunnels <count>` | a quarter of the server's memory at an estimated 256 KiB per tunnel, 512–20000 (4096 when memory is unknown) | Limit on the TCP connections and UDP flows forwarded at the same time, across all users; beyond it the answer is 503. Queued HTTP/2 and HTTP/3 receive buffers share a separate process-wide cap of a quarter of available memory (256 MiB when unknown), including across reloads |
| `relay_id <id>` | none | Unique security-domain ID. Matching IDs, unchanged destination policy and unchanged credentials allow tunnels to survive reload. Without an ID, reload revokes all old tunnels. Do not share IDs across tenants |
| `max_tunnels_per_user <count>` | `512` | Per-user concurrent tunnel budget, shared across reloads of the same relay ID; a device relaying all its traffic can have hundreds |
| `max_bytes_per_second_per_user <bytes>` | `0` (unlimited) | Aggregate TCP/UDP payload budget across upload, download and all tunnels of one user; TCP waits with cancellation, UDP drops excess packets. Burst: 128 KiB |
| `max_udp_packets_per_second_per_user <packets>` | `0` (unlimited) | Aggregate UDP upload/download packet budget per user; burst is min(rate, 1024) |
| `log_requests` | off | Sample redacted requests, process-wide limit 10/s and burst 20; suppressed counts accompany the next sample |

Status codes and `Proxy-Status` (RFC 9209) on refusal:

| Case | Status | `error=` in `Proxy-Status` |
|---|---|---|
| Malformed target; CONNECT-UDP with content headers or a request body; an HTTP/1.1 CONNECT-UDP that is not a GET or has no `Upgrade` in `Connection` | 400 (optional with HTTP/3 stream reset) | `http_request_error` |
| The CONNECT-UDP path does not match `udp_template` | 404 | — |
| Unsupported extended CONNECT protocol | 501 | — |
| Port blocked; user just removed | 403 | `http_request_denied` |
| Address blocked | 403 | `destination_ip_prohibited` |
| DNS lookup failed / timed out (5 seconds) | 502 / 504 | `dns_error` / `dns_timeout` |
| Connection refused / timed out / unreachable | 502 / 504 / 502 | `connection_refused` / `connection_timeout` / `destination_unavailable` |
| Over `max_tunnels` | 503 | `connection_limit_reached` |

Problems after the tunnel is up (the destination disconnects, the destination port is unreachable, the device sends malformed data) reset the stream or close the connection as RFC 9114 / 9297 / 9298 specify; for which error code is used in each case, see the [design document](docs/design.md).

Only authenticated requests ever see any of this; requests without a password only ever see the website.

---

## Command reference

All of them are `caddy network-relay <command>`, and each has `--help`.

### `passwd`

```bash
caddy network-relay passwd --name iphone
```

Generates a 144-bit random password and its (fast, PBKDF2-SHA256) hash. `--stdin`: read your own password from standard input (at least 12 characters), hash it with Argon2id and print only the `user` line; add `--fast-hash` when that password is itself a random secret of at least 24 characters. `--expires <RFC 3339 time>`: the account stops working then.

### `identity`

```bash
caddy network-relay identity --name ipad -o ipad.p12
```

Creates an ECDSA P-256 key and a self-signed client certificate (`--days`, default 825) in a password-protected PKCS#12 file, and prints the `user <name> certificate <sha256>` line and the file's password. See [Using a client certificate](#using-a-client-certificate-instead-of-a-password).

### `profile`

```bash
caddy network-relay profile --host relay.example.com --user iphone
```

| Flag | Description |
|---|---|
| `--host`, `--user` | Required |
| `--password` / `--password-stdin` | Without either, you are prompted for it (input not shown), which is recommended; `--password-stdin` reads the first line of standard input. `--password` warns: other users of the machine can see it, and it stays in the shell history |
| `--identity F.p12` | Install this client certificate (from `identity`) with the profile and authenticate with it (`PayloadCertificateUUID`); no password is needed then, unless one is given too |
| `--embed-identity-password` | Put the certificate's password (asked for) into the profile; without it, the device asks for it while installing |
| `--ddm` | Write the declarative device management declaration `com.apple.configuration.network.relay` (JSON, for an MDM server; iOS/macOS 27 deprecate the `com.apple.relay.managed` profile payload) instead of a `.mobileconfig` |
| `--identity-asset ID` | With `--ddm`: the identifier of the MDM's identity asset declaration to authenticate with (`IdentityAssetReference`) |
| `--port` | Set it when the port is not 443 |
| `--match-domain D` | This domain and its subdomains go through the relay; repeatable. **When none of `--match-*`, `--domains-file` and `--gfwlist` is given, all traffic goes through the relay** |
| `--domains-file F` | One domain per line in the file; `#` starts a comment; repeatable |
| `--gfwlist` / `--gfwlist-file F` | Add the gfwlist's domains (downloaded at run time / from a file you already downloaded). Regular expressions, IP addresses and `@@` exception rules are dropped; rules limited to a path are widened to the whole domain; counts for each kind are printed at the end |
| `--exclude-domain D` | Does not go through the relay; repeatable. When lists are used, the relay's own domain is excluded automatically |
| `--match-fqdn`, `--exclude-fqdn` | Match the exact host name, without subdomains (from iOS 18.4 and macOS 15.4) |
| `--ui-toggle-enabled true\|false` | Whether the relay can be turned off by hand in Settings (from iOS/macOS 26); when not given, the system default is true |
| `--allow-dns-failover true\|false` | Whether falling back to the system's default DNS is allowed (from iOS/macOS 26); when not given, the system default is false |
| `--relay-uuid` | For managed app routing (required for user enrollment; not supported on macOS) |
| `--identity-certificate-uuid` | UUID of an installed identity certificate payload; emits Apple's `PayloadCertificateUUID` for TLS client authentication. Provision the identity separately and pin its certificate for the relay user or configure Caddy's client CA trust with Basic authentication. Cannot be combined with `--identity` or `--ddm` |
| `--name` | The name shown in Settings |
| `--udp-template` | Set the same value when the server's `udp_template` was changed |
| `--no-http3` / `--no-http2` | Write only one kind of relay URL |
| `-o` | Output file, default `DOMAIN-USER.mobileconfig`; mode 600, written atomically, refuses to overwrite a symbolic link |

The profile identifier is `com.github.arccal.network-relay.<domain>.<user>` (the same as in the old Rust version), so a new profile for the same domain and user replaces the old one when it is installed.

### `check`

```bash
caddy network-relay check --server relay.example.com --user iphone
```

Tests the way a device would: over each of HTTP/3, HTTP/2 and HTTP/1.1, it tests TCP once (CONNECT to `--tcp-target`, default `example.com:80`, and sends one HTTP request) and UDP once (CONNECT-UDP to `--udp-target`, default `1.1.1.1:53`, and makes one DNS query), then confirms that a CONNECT without a password cannot open a tunnel. `--address IP` connects to that address directly (for example `127.0.0.1`, to test from the server itself). The exit code is 0 when everything passes. It works on a Mac too (build it first, and quit proxy software such as Clash first).

---

## Why the plugin serves HTTP/3

When an Apple device relays UDP over HTTP/3, the UDP packets travel in QUIC DATAGRAMs (RFC 9297 HTTP Datagrams). Caddy's built-in HTTP/3 server does not enable this and has no setting to enable it, so for servers that contain `network_relay` the plugin turns off Caddy's own HTTP/3 and serves HTTP/3 with Datagrams enabled on the same UDP port, using quic-go (the same library Caddy itself uses):

- Certificates come from Caddy's TLS settings (automatic HTTPS and renewal work as usual);
- Every request received is handled by the same Caddy server, so routing, logging and the website are exactly the same as on TCP;
- On a configuration reload the UDP port is not closed: existing connections stay on the old configuration, and new connections use the new one.

UDP over HTTP/2 needs extended CONNECT (RFC 8441), which Go's HTTP/2 implementation turns off by default; the plugin turns it on at startup (details in the [design document](docs/design.md)).

More: the [design document](docs/design.md) (protocol details, spec conformance, known limitations, tests), [deployment details](docs/deploy.md) (which files the script writes, manual upgrades, changing the domain), and [notes on the domain lists](deploy/domains/README.md).

### Production validation

See [production readiness and rollout](docs/production-readiness.md) for resource
budgets, transport patch maintenance, configuration migration and outstanding
Apple/device and staging checks. Passing automated tests is not a guarantee of
production readiness for an untested deployment.
