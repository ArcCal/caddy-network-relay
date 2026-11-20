# Deploying and testing on a real device

From scratch: from an Ubuntu (22.04 or newer) or Debian (12 or newer) x86_64 VPS to an iPhone/Mac actually browsing through the relay. Every step says "what you should see" and "what to do if it's wrong". The whole thing takes about 30 minutes, of which building takes 5–15.

Below, replace `relay.example.com` with your domain and `SERVER_IP` with the VPS's public IPv4 address.

## 0. Before you start

| What you need | How to check |
|---|---|
| VPS: Ubuntu 22.04 or newer or Debian 12 or newer, x86_64, ≥ 1 GB of memory, ≥ 3 GB of free disk | After logging in: `cat /etc/os-release \| head -2`, `free -m`, `df -h /` |
| The domain's A record points to the VPS | On the Mac, `dig +short relay.example.com` prints the server's IP. On Cloudflare it must be "DNS only" (grey cloud) |
| The cloud firewall allows TCP 80, TCP 443 and UDP 443 | The security group/firewall rules in the cloud provider's console. **UDP 443 is the one most easily missed** |
| Port 443 is free | On the VPS, `sudo ss -lntup \| grep ':443\|:80'` prints nothing (if nginx/apache is there, stop it first) |
| A test device | An iPhone/iPad (iOS 17+) or Mac (macOS 14+), and a way to get files onto it (AirDrop, iCloud Drive, emailing yourself) |

On a machine with only 512 MB of memory, add swap first, or the build gets killed:

```bash
sudo fallocate -l 2G /swapfile && sudo chmod 600 /swapfile && sudo mkswap /swapfile && sudo swapon /swapfile
```

## 1. Getting the source onto the VPS

Sign in to GitHub in a browser on your computer, open this repository, and use **Code → Download ZIP** to get `caddy-network-relay-main.zip`. Upload it from the Mac's Terminal (Ubuntu cloud servers usually log in as the `ubuntu` user; if you can use root directly, write `root@`):

```bash
scp ~/Downloads/caddy-network-relay-main.zip ubuntu@SERVER_IP:~/
```

Log in to the VPS, become root, and start a screen session (so a dropped connection does not interrupt anything; `-U` turns on UTF-8):

```bash
ssh ubuntu@SERVER_IP
```

```bash
sudo -i
```

```bash
screen -U
```

Unzip (the file is in the `ubuntu` user's home directory):

```bash
apt-get install -y unzip && cd /root && unzip -o /home/ubuntu/caddy-network-relay-main.zip && cd caddy-network-relay-main
```

You should see: `ls` lists `deploy/`, `cmd/` and `go.mod`.

## 2. Installing

```bash
bash deploy/install.sh --domain relay.example.com --user iphone
```

Optional: `--email you@example.com` (Let's Encrypt uses it to tell you about certificate problems).

**What you should see along the way** (each step starts with `==>`):

1. `This machine's public IPv4: x.x.x.x; relay.example.com resolves to: x.x.x.x` — the two IPs are the same. If they differ, it stops without having changed anything: fix the DNS, wait until `dig` shows the new IP, and run it again.
2. `==> Installing dependencies`, `==> Preparing Go 1.26.11` (a download of about 70 MB).
3. `==> Building Caddy with the network_relay plugin` — lots of `go: downloading ...` lines scroll by, then it is quiet for a few minutes. This is the slowest step: about 10 minutes on a machine with 1 GB of memory.
4. `==> Generating a random password for user iphone (not shown; it is only put into the profiles)`.
5. `==> Checking the configuration`, `==> Installing and starting the service`.
6. `==> Waiting for the certificate and running the self-check` — the first time it waits for Let's Encrypt to issue the certificate, from tens of seconds to 3 minutes. It should end with:

```
ok   HTTP/3 TCP example.com:80    HTTP/1.1 200 OK
ok   HTTP/3 UDP 1.1.1.1:53        example.com: RCodeSuccess ... (datagrams)
ok   HTTP/2 TCP example.com:80    HTTP/1.1 200 OK
ok   HTTP/2 UDP 1.1.1.1:53        example.com: RCodeSuccess ...
ok   HTTP/1.1 TCP example.com:80  HTTP/1.1 200 OK
ok   HTTP/1.1 UDP 1.1.1.1:53      example.com: RCodeSuccess ...
ok   no password: refused         405 Method Not Allowed
all checks passed
```

7. `==> Generating profiles`, then `Done.`, and finally the download command.

**If the self-check shows FAIL** (the service keeps running so you can investigate):

| You see | Cause | Fix |
|---|---|---|
| Every line FAILs, with `connection refused` or certificate errors | The certificate is not issued yet | Wait a minute or two and run the "manual self-check" below |
| Everything FAILs, and the log shows `rateLimited` | More than 5 certificates were issued for this domain within a week | Use another subdomain, or wait a week |
| Only the two `HTTP/3` lines FAIL (`timeout`) | The local self-check goes to 127.0.0.1, so this is rare; most likely `sysctl` was refused | Look at `journalctl -u caddy -n 50` and send me the error |
| Everything FAILs, and `journalctl` shows `acme ... connection` errors | The VPS cannot reach Let's Encrypt, or TCP 80 is blocked by the cloud firewall | Allow TCP 80, then `systemctl restart caddy` |

Manual self-check (the password is taken from the profile, the only place it is stored, and not shown):

```bash
sed -n 's|.*<string>Basic \(.*\)</string>|\1|p' /etc/caddy/relay/relay.example.com-iphone.mobileconfig | base64 -d | cut -d: -f2- | caddy network-relay check --server relay.example.com --address 127.0.0.1 --user iphone --password-stdin
```

## 3. Checking the ports from outside

A passing local self-check only shows that the service is fine; it does not prove that the cloud firewall lets traffic in. On the **Mac**:

```bash
curl -sI https://relay.example.com/ | head -3
```

You should see `HTTP/2 200` and an `alt-svc: h3=":443"` line. No `alt-svc` means HTTP/3 is not on (look at the log from step 2); no connection at all means TCP 443 is not allowed or DNS has not taken effect.

To test UDP 443 from outside, build a copy on the Mac (only needed once; it needs the Xcode command line tools and Go first), then use `check`:

```bash
xcode-select --install; brew install go
```

```bash
cd ~/Downloads && unzip -o caddy-network-relay-main.zip && cd caddy-network-relay-main
relay_go_work=$(mktemp -d)
python3 deploy/go-tls/prepare.py "$(go env GOROOT)" "$relay_go_work/go"
export GOROOT="$relay_go_work/go" GOTOOLCHAIN=local
export GOFLAGS=-tags=relay_tls9846_v1
go build -tags http2legacy,relay_tls9846_v1 -o caddy ./cmd/caddy
```

Use Go 1.26.11, Go 1.27.4 or a newer stable release. Check the resulting binary:

```bash
go version -m ./caddy
```

Its module records must retain the local quic-go, x/net, go-jose/v3 and
go-jose/v4 replacements listed in [the source provenance](../third_party/README.md).

```bash
./caddy network-relay check --server relay.example.com --user iphone
```

(Paste the password when prompted; on the VPS, `sed -n 's|.*<string>Basic \(.*\)</string>|\1|p' /etc/caddy/relay/relay.example.com-iphone.mobileconfig | base64 -d | cut -d: -f2-` shows it. **Quit proxy software such as Clash/Stash on the Mac first**, or you will be testing them instead.)

- All 7 lines `ok`: the cloud firewall, DNS and certificate are all right.
- If only the two HTTP/3 checks fail, check that UDP 443 is reachable from this network and that the server listens on it. An H2 URL can still carry traffic over TCP 443.

## 4. Downloading the profiles

Both files are in `/etc/caddy/relay/` on the VPS, readable only by root, and **contain the password in plain text**:

| File | What goes through the relay | Can be turned off in Settings |
|---|---|---|
| `relay.example.com-iphone.mobileconfig` | Google/Gemini/YouTube, Claude, ChatGPT, X/Grok and more | Yes |
| `relay.example.com-iphone-global.mobileconfig` | The above + Spotify, Instagram, Meta AI, NYT, Wikipedia and more + the gfwlist | No (iOS/macOS 26+) |

**For the first test, use the first one** (the basic profile): if something goes wrong you can turn it off in Settings, and its narrower scope makes it easier to tell whether the relay is doing anything.

Ubuntu machines usually do not allow scp as root, so first copy the file to the login user on the VPS:

```bash
install -m 600 -o ubuntu /etc/caddy/relay/relay.example.com-iphone.mobileconfig /home/ubuntu/
```

On the Mac:

```bash
scp ubuntu@SERVER_IP:relay.example.com-iphone.mobileconfig ~/Downloads/
```

Once it is downloaded, delete the copy on the VPS: `rm /home/ubuntu/relay.example.com-iphone.mobileconfig`.

## 5. Testing on the Mac (easiest place to see details; do this first)

1. Double-click `~/Downloads/relay.example.com-iphone.mobileconfig`.
2. System Settings → General → Device Management (before macOS 13: Privacy & Security → Profiles) → double-click it → Install → enter your login password.
3. Watch the VPS's log (in another terminal):

```bash
journalctl -u caddy -f
```

4. On the Mac, open Safari and go to https://gemini.google.com or https://www.youtube.com .

**You should see**: the page opens normally, and the VPS log has no `relay authentication failed`. At the default log level individual tunnels are not logged, so "the page opens" does not by itself prove the relay was used (the relay is transparent to apps, and what-is-my-IP pages cannot tell either). To confirm, temporarily turn on request logging as in step 7: when the device visits Gemini, `relay request` lines with destinations like `gemini.google.com:443` should scroll by on the VPS.

5. The profile is listed under System Settings → General → Device Management; from macOS 26 the relay also shows up in the network settings.

## 6. Testing on the iPhone

1. AirDrop the file to the iPhone (or save it to iCloud Drive and tap it in the Files app).
2. The iPhone says "Profile Downloaded" → open Settings, tap "Profile Downloaded" at the top → Install → enter the passcode.
3. Open Safari and go to https://gemini.google.com , or open the YouTube app.
4. The profile is listed under Settings → General → VPN & Device Management; from iOS 26 the relay also appears under Settings → VPN.

**Test on Wi-Fi first, then turn Wi-Fi off and test again on cellular**: both networks should work.

## 7. Seeing what the device actually sends

On the VPS, edit `/etc/caddy/Caddyfile` and add a `log_requests` line inside `network_relay {`:

```
	network_relay {
		user iphone $pbkdf2-sha256$...
		log_requests
	}
```

Then:

```bash
systemctl reload caddy && journalctl -u caddy -f
```

Every request from a device logs a `relay request` line: the HTTP version (`proto`), the `CONNECT` target, whether `udp` is true or false, and whether it was `authenticated`. When you are done, **remember to remove that line and reload again**; it is noisy.

Reading the log:

| You see | Meaning |
|---|---|
| Requests with `"proto":"HTTP/3.0"` or `"proto":"connect-udp"` | The request used HTTP/3. An authenticated request with `"udp":true` identifies CONNECT-UDP. An echo from the target confirms payload delivery |
| Only `"proto":"HTTP/2.0"` | The request used HTTP/2. Check whether the installed profile is H2-only before investigating UDP 443 |
| `relay authentication failed` | The password in the profile does not match the server's: the password was changed without regenerating the profile, or an old file is installed |
| `"authenticated":false` and no `Authorization` | Not from the device but from a scanner; that is normal |
| Nothing at all, yet the device is online | The profile is not in effect: the domain is not in the list (the basic profile only has Google/AI/X and the like), or two profiles are installed and fight each other. Keep only one |

## 8. Common problems

| Symptom | Fix |
|---|---|
| Installing the profile says "Unverified" or "Unsigned" | Normal: this project's profiles are not signed. Tap "Install Anyway" |
| After installing, Google does not open but other sites do | Most likely a password mismatch; see step 7 |
| Works on the iPhone but not the Mac (or the other way round) | Two devices can share the profile for the same domain and user; check whether the other one has another relay/VPN installed that is competing |
| Suddenly stops working after a while | `systemctl status caddy`; for failed certificate renewals, look at `journalctl -u caddy \| grep -i acme` |
| You want to stop using the relay | Remove the profile on the device (Settings → VPN & Device Management → this profile → Remove) |

For a transport comparison, use the same device, profile settings, destination and network. Record request and reply sizes separately for UDP. For large downloads record the byte count, elapsed time and final digest, including whether a transfer was still progressing at the cutoff. [Profile options and measured limitations](../README.md#choosing-h2-or-h3-for-an-apple-profile).

## 9. After testing

- Delete the profile from `~/Downloads/` on the Mac (it contains the password in plain text).
- Once the basic profile checks out, install the global one (remove the basic one first).
- Send me the results (what works, what doesn't, and log excerpts from step 7); `Authorization` in the log only shows the user name, never the password, so it is safe to paste.
