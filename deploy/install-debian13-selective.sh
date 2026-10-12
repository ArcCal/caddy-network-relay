#!/usr/bin/env bash
# Fresh Debian 13 x86_64 installation. Builds the bundled Caddy sources,
# combines the Rust installer's domain lists, and emits one HTTP/2-only profile.
# Does not modify an existing Caddy or Rust network-relay installation.
set +x
set -Eeuo pipefail
export LANG=C.UTF-8 LC_ALL=C.UTF-8

usage() {
    cat <<'HELP'
Usage: sudo bash caddy-network-relay-install-debian13.sh [options]
  --domain HOST          Relay domain (prompted for if omitted)
  --user NAME            Initial account name (default: iphone)
  --email ADDRESS        ACME email (prompted for if omitted; may be blank)
  --binary FILE          Use an already compiled Linux x64 Caddy binary
  --domains FILE         Replace the bundled Google/AI base domain list
  --gfwlist-file FILE    Use a local gfwlist instead of downloading it
  --no-gfwlist           Explicitly omit gfwlist
  --rules-dir DIRECTORY Use all 18 local service YAML files
  --no-service-rules     Explicitly omit the 18 service lists
  --skip-dns-check       Skip the public IPv4 comparison (TLS still verifies)
  -h, --help            Show this help

Default routing: Google/AI base + gfwlist + all 18 Rust service lists.
The same ICANN root normalization is used. Selected roots and their
subdomains use the relay; unmatched domains are left direct by this profile.
HTTP3RelayURL is omitted; HTTPS certificate verification remains enabled.
The server retains HTTP/1.1, HTTP/2 and HTTP/3 support for other clients.
This is a fresh-install script, not an upgrader or password-reset command.
HELP
}
say() { printf '%s\n' "$*"; }
die() { printf 'Error: %s\n' "$*" >&2; exit 1; }
value() { [[ $# == 2 && -n $2 && $2 != --* ]] || die "Missing value for $1."; }
apt_install() { DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=1800 "$@"; }

SRC=$(cd "$(dirname "$0")/.." && pwd)
ROOT=${RELAY_TEST_ROOT:-}
ETC=$ROOT/etc/caddy
SECRETS=$ETC/relay
CADDYFILE=$ETC/Caddyfile
BIN=$ROOT/usr/local/bin/caddy
UNIT=$ROOT/etc/systemd/system/caddy.service
SYSCTL=$ROOT/etc/sysctl.d/60-caddy-network-relay.conf
WWW=$ROOT/var/www/relay
DATA=$ROOT/var/lib/caddy
CACHE=$ROOT/var/cache/caddy-network-relay
OPT=$ROOT/opt/caddy-network-relay
DOMAIN='' RELAY_USER=iphone EMAIL='' EMAIL_GIVEN=0 BINARY='' DNS_CHECK=1
DOMAIN_ARGS=()
while (($#)); do
    case $1 in
        --domain) value "$1" "${2:-}"; DOMAIN=$2; shift 2 ;;
        --user) value "$1" "${2:-}"; RELAY_USER=$2; shift 2 ;;
        --email) [[ $# -ge 2 ]] || die 'Missing value for --email.'; EMAIL=$2; EMAIL_GIVEN=1; shift 2 ;;
        --binary) value "$1" "${2:-}"; BINARY=$2; shift 2 ;;
        --domains|--gfwlist-file|--rules-dir) value "$1" "${2:-}"; DOMAIN_ARGS+=("$1" "$2"); shift 2 ;;
        --no-gfwlist|--no-service-rules) DOMAIN_ARGS+=("$1"); shift ;;
        --skip-dns-check) DNS_CHECK=0; shift ;;
        -h|--help) usage; exit 0 ;;
        *) die "Unknown option: $1 (see --help)." ;;
    esac
done

[[ $EUID == 0 || -n $ROOT ]] || die 'Run this script with sudo or as root.'
. "${RELAY_TEST_OS_RELEASE:-/etc/os-release}"
[[ ${ID:-} == debian && ${VERSION_ID:-} == 13 ]] || die 'This installer requires Debian 13.'
[[ $(uname -m) == x86_64 ]] || die 'This installer requires x86_64 (amd64).'
[[ -n $ROOT || -d /run/systemd/system ]] || die 'A VPS booted with systemd is required.'
[[ -f $SRC/go.mod && -f $SRC/deploy/selective-profile.py ]] || die 'The bundled source tree is incomplete.'
command -v flock >/dev/null || die 'flock (util-linux) is required.'
install -d -m 700 "$ROOT/run/caddy-network-relay-install"
exec {install_lock}>"$ROOT/run/caddy-network-relay-install/lock"
flock -n "$install_lock" || die 'Another caddy-network-relay installer is running.'

# Refuse to overwrite another deployment, even when its service is stopped.
for path in "$CADDYFILE" "$BIN" "$UNIT"; do
    [[ ! -e $path && ! -L $path ]] || die "An installation already exists at $path. This script only handles a fresh VPS."
done
dpkg -s caddy >/dev/null 2>&1 && die 'The apt caddy package is already installed.'
if systemctl is-active --quiet network-relay 2>/dev/null; then
    die 'The Rust network-relay service is running; use a fresh VPS.'
fi
if [[ -z $DOMAIN ]]; then
    [[ -t 0 ]] || die 'A noninteractive install needs --domain.'
    read -r -p 'Relay domain (DNS must point to this VPS): ' DOMAIN
fi
if ((!EMAIL_GIVEN)) && [[ -t 0 ]]; then
    read -r -p 'ACME email (optional; press Enter to omit): ' EMAIL
fi
DOMAIN=${DOMAIN,,}
DOMAIN=${DOMAIN%.}
[[ ${#DOMAIN} -le 253 && $DOMAIN =~ ^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$ ]] || die 'Use a valid DNS hostname for --domain, not an IP address.'
[[ $RELAY_USER =~ ^[A-Za-z0-9_-][A-Za-z0-9._-]{0,63}$ ]] || die 'Invalid account name (allowed: letters, digits, dot, underscore, hyphen).'
[[ -z $EMAIL || $EMAIL =~ ^[^@[:space:]]+@[^@[:space:]]+\.[^@[:space:]]+$ ]] || die 'Invalid email address.'
[[ -z $BINARY || -f $BINARY ]] || die "Precompiled binary not found: $BINARY"

# Minimal Debian images may not have curl, Python or ss yet.
say '==> Installing bootstrap dependencies'
apt_install update -qq
apt_install install -y -qq ca-certificates curl python3 iproute2 adduser >/dev/null
busy=$(ss -Hlnptu | awk '($1=="tcp" && ($5 ~ /:(80|443)$/)) || ($1=="udp" && $5 ~ /:443$/) {print $1, $5, $7}')
[[ -z $busy ]] || die "TCP 80/443 or UDP 443 is already in use:
$busy"
public_ip=''
if ((DNS_CHECK)); then
    public_ip=$(curl -4 -fsS --max-time 10 https://api.ipify.org || curl -4 -fsS --max-time 10 https://ifconfig.me || true)
    dns_ips=$(getent ahostsv4 "$DOMAIN" | awk '{print $1}' | sort -u | tr '\n' ' ' || true)
    say "Public IPv4: ${public_ip:-lookup unavailable}; $DOMAIN resolves to: ${dns_ips:-nothing}"
    [[ -n $dns_ips ]] || die 'The relay domain has no IPv4 address. Add its DNS-only A record first.'
    [[ -z $public_ip || " $dns_ips " == *" $public_ip "* ]] || die 'The relay A record does not point to this VPS. For Cloudflare, use DNS only (grey cloud).'
fi

install -d -m 755 "$CACHE" "$OPT"
say '==> Combining the Rust installer domain lists (all enabled sources must succeed)'
python3 "$SRC/deploy/selective-profile.py" domains --host "$DOMAIN" --out "$CACHE/selected-domains.json" "${DOMAIN_ARGS[@]}"
install -m 644 "$SRC/deploy/selective-source.json" "$CACHE/install-source.json"

if [[ -n $BINARY ]]; then
    say '==> Preparing the supplied Linux x64 Caddy binary'
    # Stage on the installation filesystem: uploaded files may lose x bits,
    # and /tmp may be mounted noexec. Never execute the uploaded path directly.
    python3 - "$BINARY" "$CACHE/caddy.new" <<'PY'
from pathlib import Path
import shutil
import sys
source, target = map(Path, sys.argv[1:])
with source.open('rb') as f:
    header = f.read(20)
if len(header) != 20 or header[:6] != b'\x7fELF\x02\x01' or int.from_bytes(header[18:20], 'little') != 62:
    sys.exit('Expected a Linux x86_64 ELF binary, not an archive or ARM/macOS build.')
if source.resolve() == target.resolve():
    sys.exit('The supplied binary must not be the installer staging file.')
shutil.copyfile(source, target)
target.chmod(0o755)
PY
else
    GO_VERSION=1.26.8
    GO_SUM='h1:ZOmGe1OnfREDMIdb1Qi4G9JSuDPBLGExZMQ4nis1RXM='
    GO=$OPT/go/bin/go
    if [[ -n ${RELAY_TEST_GO:-} ]]; then
        GO=$RELAY_TEST_GO
    elif [[ ! -x $GO || $("$GO" env GOVERSION 2>/dev/null) != "go$GO_VERSION" ]]; then
        say "==> Downloading and verifying Go $GO_VERSION"
        module=golang.org/toolchain@v0.0.1-go$GO_VERSION.linux-amd64
        zip=$CACHE/go-toolchain.zip
        curl -fsSL --max-time 900 -o "$zip" "https://proxy.golang.org/golang.org/toolchain/@v/v0.0.1-go$GO_VERSION.linux-amd64.zip"
        rm -rf "$OPT/go.new"
        python3 - "$zip" "$OPT/go.new" "$module" "$GO_SUM" <<'PY'
import base64
import hashlib
import os
import sys
import zipfile
path, dest, prefix, want = sys.argv[1:]
with zipfile.ZipFile(path) as archive:
    files = sorted(n for n in archive.namelist() if not n.endswith('/'))
    summary = ''.join(f'{hashlib.sha256(archive.read(n)).hexdigest()}  {n}\n' for n in files)
    got = 'h1:' + base64.b64encode(hashlib.sha256(summary.encode()).digest()).decode()
    if got != want:
        sys.exit(f'Toolchain checksum mismatch: {got} != {want}')
    for info in archive.infolist():
        if not info.filename.startswith(prefix + '/') or info.filename.endswith('/'):
            continue
        relative = info.filename[len(prefix) + 1:]
        if '..' in relative.split('/'):
            sys.exit('Unsafe toolchain archive path.')
        target = os.path.join(dest, relative)
        os.makedirs(os.path.dirname(target), exist_ok=True)
        with open(target, 'wb') as f:
            f.write(archive.read(info))
        os.chmod(target, (info.external_attr >> 16) & 0o777 or 0o644)
PY
        rm -rf "$OPT/go" "$zip"
        mv "$OPT/go.new" "$OPT/go"
    fi
    say '==> Building Caddy with the bundled network_relay and shared library patches'
    (
        cd "$SRC"
        env GOTOOLCHAIN=local GOFLAGS=-mod=readonly CGO_ENABLED=0 GOMAXPROCS=2 \
            GOPATH="$CACHE/gopath" GOMODCACHE="$CACHE/gomod" GOCACHE="$CACHE/gocache" \
            "$GO" build -p 1 -buildvcs=false -tags http2legacy -trimpath -ldflags '-s -w' -o "$CACHE/caddy.new" ./cmd/caddy
    ) || die 'Build failed; no service or account has been installed. See the build output.'
fi
modules=$("$CACHE/caddy.new" list-modules 2>/dev/null)
grep -qx 'http.handlers.network_relay' <<<"$modules" || die 'The binary has no network_relay module.'

if ! getent passwd caddy >/dev/null; then
    adduser --system --group --home /var/lib/caddy --shell /usr/sbin/nologin caddy >/dev/null
fi
install -d -m 755 "$ETC" "$WWW" "$DATA" "$(dirname "$BIN")" "$(dirname "$UNIT")" "$(dirname "$SYSCTL")"
install -d -m 700 "$SECRETS"
chown caddy:caddy "$DATA"
profile=$SECRETS/$DOMAIN-$RELAY_USER.mobileconfig
[[ ! -e $profile && ! -L $profile ]] || die 'An existing device profile would be overwritten.'
started=0
profile_written=0
config_written=0
config_stage=''
cleanup() {
    local status=$?
    [[ -z $config_stage ]] || rm -f -- "$config_stage"
    if ((status != 0 && !started)); then
        ((config_written == 0)) || rm -f -- "$CADDYFILE"
        ((profile_written == 0)) || rm -f -- "$profile"
    fi
    return "$status"
}
trap cleanup EXIT
say "==> Generating a private HTTP/2-only mobileconfig for $RELAY_USER"
out=$("$CACHE/caddy.new" network-relay passwd --name "$RELAY_USER")
password=$(sed -n 's/^password: //p' <<<"$out")
user_line=$(grep '^user ' <<<"$out")
unset out
[[ -n $password && -n $user_line ]] || die 'Generating the account failed.'
printf '%s\n' "$password" | python3 "$SRC/deploy/selective-profile.py" profile \
    --host "$DOMAIN" --user "$RELAY_USER" --binary "$CACHE/caddy.new" \
    --domains "$CACHE/selected-domains.json" --out "$profile"
profile_written=1

config_stage=$(mktemp "$ETC/.Caddyfile.XXXXXX")
email_line=''
[[ -z $EMAIL ]] || email_line=$'\temail '"$EMAIL"
cat >"$config_stage" <<EOF
# Managed by caddy-network-relay install-debian13-selective.sh
# domain: $DOMAIN
# user: $RELAY_USER
{
$email_line
}

# CONNECT authority names the destination, so :443 must accept that host.
$DOMAIN, :443 {
    network_relay {
        relay_id $DOMAIN
        $user_line
    }
    root * /var/www/relay
    file_server
}
EOF
"$CACHE/caddy.new" fmt --overwrite "$config_stage" >/dev/null 2>&1
chmod 640 "$config_stage"
chown root:caddy "$config_stage"
mv "$config_stage" "$CADDYFILE"
config_stage=''
config_written=1
[[ -e $WWW/index.html ]] || printf '<!doctype html>\n<title>Welcome</title>\n<h1>Welcome</h1>\n' >"$WWW/index.html"
say '==> Validating the configuration as the unprivileged service user'
if ! runuser -u caddy -- env HOME=/var/lib/caddy "$CACHE/caddy.new" validate --config "$CADDYFILE" --adapter caddyfile >"$CACHE/validate.log" 2>&1; then
    tail -20 "$CACHE/validate.log" >&2
    die 'Configuration validation failed; no service was started.'
fi

# Retain the server's HTTP/3 support for other clients. Only the Apple profile
# is HTTP/2-only. Preserve higher existing buffer limits.
{
    echo '# Caddy QUIC UDP buffer limits; never lower existing runtime values.'
    for key in net.core.rmem_max net.core.wmem_max; do
        current=$(sysctl -n "$key" 2>/dev/null || echo 0)
        [[ $current =~ ^[0-9]+$ ]] || current=0
        ((current >= 7500000)) || current=7500000
        echo "$key = $current"
    done
} >"$SYSCTL"
sysctl -p "$SYSCTL" >/dev/null 2>&1 || say 'UDP buffer settings were not applied; system defaults remain.'
if command -v ufw >/dev/null && grep -q '^Status: active' <<<"$(ufw status 2>/dev/null || true)"; then
    ufw allow 80/tcp >/dev/null
    ufw allow 443/tcp >/dev/null
    ufw allow 443/udp >/dev/null
fi

rollback() {
    set +e
    journalctl -u caddy -n 40 --no-pager >&2
    local failed=0
    if [[ -e $UNIT ]]; then
        systemctl stop caddy || failed=1
        systemctl disable caddy || failed=1
    fi
    rm -f -- "$BIN" "$UNIT" "$CADDYFILE" "$profile" || failed=1
    systemctl daemon-reload || failed=1
    ((failed == 0)) || die 'Startup failed and rollback was incomplete; inspect the preceding errors.'
    die 'Startup failed. The new service, configuration, binary and profile were removed.'
}
say '==> Installing and starting the Caddy service'
started=1
install -m 755 "$CACHE/caddy.new" "$BIN" || rollback
install -m 644 "$SRC/deploy/caddy.service" "$UNIT" || rollback
systemctl daemon-reload || rollback
systemctl enable caddy >/dev/null 2>&1 || rollback
systemctl restart caddy || rollback
sleep "${RELAY_TEST_SLEEP:-2}"
systemctl is-active --quiet caddy || rollback

say '==> Waiting for ACME and testing authenticated HTTP/2 TCP and UDP'
check_ok=0
for _ in $(seq "${RELAY_TEST_TRIES:-12}"); do
    # The existing CLI also probes H1/H3. Those outcomes are diagnostic;
    # readiness requires H2 TCP/UDP plus H1 unauthenticated-request rejection.
    printf '%s\n' "$password" | "$BIN" network-relay check --server "$DOMAIN" --address 127.0.0.1 \
        --user "$RELAY_USER" --password-stdin --timeout 5s >"$CACHE/check.log" 2>&1 || true
    if grep -qE '^ok[[:space:]]+HTTP/2 TCP ' "$CACHE/check.log" \
        && grep -qE '^ok[[:space:]]+HTTP/2 UDP ' "$CACHE/check.log" \
        && grep -qE '^ok[[:space:]]+no password: refused' "$CACHE/check.log"; then
        check_ok=1
        break
    fi
    systemctl is-active --quiet caddy || rollback
    sleep "${RELAY_TEST_SLEEP:-5}"
done
grep -E '^(ok|FAIL)[[:space:]]+(HTTP/2|no password:)' "$CACHE/check.log" || true
unset password user_line
cat <<EOF

Device profile: $profile
Routing audit:  $CACHE/selected-domains.json
Configuration:  $CADDYFILE
Service logs:   journalctl -u caddy -n 100 --no-pager -l
Full self-test: $CACHE/check.log

The mobileconfig contains only HTTP2RelayURL and a nonempty MatchDomains.
Download it privately (it contains the account password); install it on
the device and remove any old relay profile. Unmatched domains are not
relayed by this profile. Do not put this file in /var/www/relay.
From your Mac: scp root@SERVER_IP:$profile ~/Downloads/
The cloud firewall must allow TCP 80/443 for ACME and relay access.
UDP 443 is needed only for other clients that use the server's HTTP/3.
EOF
if ((!check_ok)); then
    say 'HTTP/2 readiness checks did not pass. The service and private profile remain for diagnosis.'
    say "After checking DNS, A/AAAA records and the cloud firewall, run: $BIN network-relay check --server $DOMAIN --user $RELAY_USER"
    say 'The fresh-install script cannot be rerun over an existing installation.'
    exit 1
fi
say 'Done: Caddy starts at boot; authenticated HTTP/2 TCP and UDP checks passed.'
