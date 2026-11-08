#!/usr/bin/env bash
# Installs or upgrades Caddy with the network_relay plugin on Debian 12 or
# newer and Ubuntu 22.04 or newer (x86_64 or arm64), from a fresh complete main checkout in /tmp.
#
# First install:
#     sudo bash deploy/install.sh --domain relay.example.com [--user iphone] [--email you@example.com]
# Upgrade (rebuild latest main; users, passwords and Caddyfile stay):
#     sudo bash deploy/install.sh
#
# Options:
#     --domain D                the relay's domain; its A record must point here
#     --user U                  first user (default iphone)
#     --email E                 address for Let's Encrypt (optional)
#     --no-gfwlist              do not download the gfwlist for the "global" profile
#     --replace-network-relay   stop and disable the old Rust network-relay service
#     --skip-dns-check          do not compare the domain's A record with this host's IP
#
# Everything it writes is listed in docs/deploy.md.
set -Eeuo pipefail
unset CDPATH
export LANG=C.UTF-8 LC_ALL=C.UTF-8

GO_VERSION=1.26.10
# h1 hashes of golang.org/toolchain@v0.0.1-go$GO_VERSION.linux-* from
# sum.golang.org.
declare -A GO_SUMS=(
    [amd64]='h1:5VAGHlY8yl8pTPVSNIez3SNMy6fWabs+QMR25f3oMT0='
    [arm64]='h1:TuAzKmE5TqYnXpnhgY3GtBJCVg4AfNDA/K1gLyX5Hig='
)
# For tests: all paths under this directory, and no real downloads.
ROOT=${RELAY_TEST_ROOT:-}
BIN=$ROOT/usr/local/bin/caddy
ETC=$ROOT/etc/caddy
CADDYFILE=$ETC/Caddyfile
SECRETS=$ETC/relay
UNIT=$ROOT/etc/systemd/system/caddy.service
SYSCTL=$ROOT/etc/sysctl.d/60-caddy-network-relay.conf
WWW=$ROOT/var/www/relay
DATA=$ROOT/var/lib/caddy
OPT=$ROOT/opt/caddy-network-relay
CACHE=$ROOT/var/cache/caddy-network-relay
MARKER='# Managed by caddy-network-relay deploy/install.sh'

say() { printf '%s\n' "$*"; }
die() { printf 'Error: %s\n' "$*" >&2; exit 1; }
run_apt() { DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=1800 -o Acquire::Retries=3 "$@"; }

SRC=$(cd "$(dirname "$0")/.." && pwd)
CADDY_SOURCE_WORK='' CADDY_BUILD_WORK=''
if [[ ${1:-} == --fresh-source-run ]]; then
    [[ $# -ge 3 ]] || die 'Invalid fresh-source invocation.'
    # shellcheck source=deploy/fresh-source.sh
    source "$SRC/deploy/fresh-source.sh"
    caddy_accept_source "$SRC" "$2" "$3" || die 'Invalid private source workspace.'
    shift 3
fi
build_args=("$@")
DOMAIN='' RELAY_USER='' EMAIL='' GFWLIST=1 REPLACE_OLD=0 DNS_CHECK=1
while (($#)); do
    case $1 in
        --domain) DOMAIN=${2:-}; shift 2 ;;
        --user) RELAY_USER=${2:-}; shift 2 ;;
        --email) EMAIL=${2:-}; shift 2 ;;
        --no-gfwlist) GFWLIST=0; shift ;;
        --replace-network-relay) REPLACE_OLD=1; shift ;;
        --skip-dns-check) DNS_CHECK=0; shift ;;
        -h|--help) sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) die "Unknown option $1 (see --help)." ;;
    esac
done

# ---- checks that change nothing ----
[[ $EUID == 0 || -n $ROOT ]] || die 'Run this as root: sudo -i first, then run this script.'
if [[ -z $CADDY_SOURCE_WORK ]]; then
    # shellcheck source=deploy/fresh-source.sh
    source "$SRC/deploy/fresh-source.sh"
    caddy_latest_entry deploy/install.sh "${build_args[@]}" || die 'Downloading latest build source failed.'
fi
grep -q '^module github.com/arccal/caddy-network-relay$' "$SRC/go.mod" 2>/dev/null \
    || die "Source not found: run bash deploy/install.sh from inside the unzipped caddy-network-relay directory."
# Debian 12 or newer, Ubuntu 22.04 or newer: anything with systemd, apt and
# a glibc the static binary does not even need. Newer releases are accepted
# as they come out.
# shellcheck source=/dev/null # os-release only sets variables; tests point it elsewhere
. "${RELAY_TEST_OS_RELEASE:-/etc/os-release}"
os_ok=0
os_version=${VERSION_ID:-}
os_major=${os_version%%.*}
case ${ID:-} in
    debian)
        # Debian testing/unstable have no VERSION_ID; they are newer than any release.
        if [[ -z $os_version ]] || { [[ $os_major =~ ^[0-9]+$ ]] && ((os_major >= 12)); }; then os_ok=1; fi ;;
    ubuntu)
        if [[ $os_version =~ ^[0-9]+\.[0-9]+$ ]] && ((os_major >= 22)); then os_ok=1; fi ;;
esac
((os_ok)) || die "Only Debian 12 or newer and Ubuntu 22.04 or newer are supported (this machine runs ${PRETTY_NAME:-an unknown system})."
case $(uname -m) in
    x86_64) GOARCH=amd64 ;;
    aarch64) GOARCH=arm64 ;;
    *) die "Only x86_64 and arm64 are supported (this machine is $(uname -m))." ;;
esac

# Serialize the complete transaction, including detection of an existing
# installation. /run is root-owned; a private directory protects the lock
# from symlink replacement by an unprivileged local user.
command -v flock >/dev/null || die 'flock is required (provided by util-linux).'
install -d -m 700 "$ROOT/run/caddy-network-relay-install"
exec {install_lock}>"$ROOT/run/caddy-network-relay-install/lock"
flock -n "$install_lock" || die 'Another caddy-network-relay installer is running.'

UPGRADE=0
if [[ -e $CADDYFILE ]]; then
    grep -qxF "$MARKER" "$CADDYFILE" || die "$CADDYFILE exists but was not generated by this script. To avoid overwriting your configuration, the script does not handle this case; see \"Manual upgrade\" in docs/deploy.md."
    UPGRADE=1
    old_domain=$(sed -n 's/^# domain: //p' "$CADDYFILE")
    old_user=$(sed -n 's/^# user: //p' "$CADDYFILE")
    [[ -z $DOMAIN || $DOMAIN == "$old_domain" ]] || die "This machine is already set up for $old_domain; it cannot be changed to $DOMAIN. To change the domain, see docs/deploy.md."
    [[ -z $RELAY_USER || $RELAY_USER == "$old_user" ]] || die "User $old_user already exists; to add a user, see docs/deploy.md instead of using --user."
    DOMAIN=$old_domain RELAY_USER=$old_user
else
    [[ -n $DOMAIN ]] || die 'A first install needs a domain: bash deploy/install.sh --domain relay.example.com'
fi
DOMAIN=${DOMAIN,,}
DOMAIN=${DOMAIN%.}
RELAY_USER=${RELAY_USER:-iphone}
[[ $DOMAIN =~ ^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$ ]] || die "$DOMAIN is not a domain name."
[[ $RELAY_USER =~ ^[A-Za-z0-9_-][A-Za-z0-9._-]{0,63}$ ]] || die "User name $RELAY_USER may only contain letters, digits, - _ . and must not start with a dot."
[[ -z $EMAIL || $EMAIL =~ ^[^@[:space:]]+@[^@[:space:]]+\.[^@[:space:]]+$ ]] || die "$EMAIL is not an email address."

if dpkg -s caddy >/dev/null 2>&1; then
    die 'The apt caddy package is installed; it would compete with the Caddy this script installs for the ports and the service name. Run apt remove caddy first (its /etc/caddy/Caddyfile is kept), then run this again.'
fi
if systemctl is-active --quiet network-relay 2>/dev/null; then
    ((REPLACE_OLD)) || die 'The old network-relay (Rust version) is running and holds port 443. To switch to the Caddy version, run again with --replace-network-relay (it only disables the old service and does not delete its files).'
fi

# Who holds the ports, other than the Caddy this script manages.
port_users() {
    ss -Hlnptu 2>/dev/null | awk '($1=="tcp" && ($5 ~ /:(80|443)$/)) || ($1=="udp" && $5 ~ /:443$/) {print $1, $5, $7}' \
        | grep -v '"caddy"' | grep -v '"network-relay"' || true
}
busy=$(port_users)
[[ -z $busy ]] || die "Ports are in use by other programs (TCP 80, 443 and UDP 443 are needed):
$busy"

if ((DNS_CHECK)) && ((!UPGRADE)); then
    public_ip=$(curl -4 -fsS --max-time 10 https://api.ipify.org || curl -4 -fsS --max-time 10 https://ifconfig.me || true)
    dns_ips=$(getent ahostsv4 "$DOMAIN" | awk '{print $1}' | sort -u | tr '\n' ' ' || true)
    say "This machine's public IPv4: ${public_ip:-lookup failed}; $DOMAIN resolves to: ${dns_ips:-nothing}"
    [[ -n $dns_ips ]] || die "$DOMAIN has no DNS record yet: first add an A record pointing to ${public_ip:-the public IP of this machine} (on Cloudflare, choose \"DNS only\", the grey cloud)."
    if [[ -n $public_ip && " $dns_ips " != *" $public_ip "* ]]; then
        die "$DOMAIN does not point to this machine ($public_ip). Fix the DNS record, wait for it to take effect, then run this again. Nothing was changed."
    fi
fi

# ---- install ----
say "==> Installing dependencies"
run_apt update -qq
run_apt install -y -qq ca-certificates curl git procps python3 iproute2 >/dev/null
mkdir -p "$CACHE"
caddy_new_build_work "$CACHE" || die 'Cannot create private compiler workspace.'

old_stopped=0
old_enabled=0
if ((REPLACE_OLD)) && systemctl is-enabled --quiet network-relay 2>/dev/null; then
    old_enabled=1
fi

say "==> Preparing Go $GO_VERSION (only used in this build)"
GO=$CADDY_BUILD_WORK/go/bin/go
if [[ -n ${RELAY_TEST_GO:-} ]]; then
    GO=$RELAY_TEST_GO
elif [[ -x $OPT/go/bin/go && $("$OPT/go/bin/go" env GOVERSION 2>/dev/null) == "go$GO_VERSION" ]]; then
    GO=$OPT/go/bin/go
else
    # The official toolchain, from the Go module proxy (which the build
    # needs anyway), checked against the hash in Go's checksum database.
    module=golang.org/toolchain@v0.0.1-go$GO_VERSION.linux-$GOARCH
    mkdir -p "$CACHE"
    zip=$CADDY_BUILD_WORK/go-toolchain.zip
    caddy_run_build curl -fsSL --retry 3 --retry-delay 5 --max-time 900 -o "$zip" "https://proxy.golang.org/golang.org/toolchain/@v/v0.0.1-go$GO_VERSION.linux-$GOARCH.zip" \
        || die 'Downloading Go failed: this machine must be able to reach proxy.golang.org.'
    rm -rf "$CADDY_BUILD_WORK/go.new"
    caddy_run_build python3 - "$zip" "$CADDY_BUILD_WORK/go.new" "$module" "${GO_SUMS[$GOARCH]}" <<'PY' || die 'Verifying the Go toolchain failed: the download is incomplete or has been tampered with.'
import base64, hashlib, os, sys, zipfile
path, dest, prefix, want = sys.argv[1:]
z = zipfile.ZipFile(path)
files = sorted(n for n in z.namelist() if not n.endswith('/'))
summary = ''.join(f'{hashlib.sha256(z.read(n)).hexdigest()}  {n}\n' for n in files)
got = 'h1:' + base64.b64encode(hashlib.sha256(summary.encode()).digest()).decode()
if got != want:
    sys.exit(f'{got} != {want}')
for info in z.infolist():
    rel = info.filename[len(prefix) + 1:]
    if info.filename.endswith('/') or not info.filename.startswith(prefix + '/') or '..' in rel.split('/'):
        continue
    target = os.path.join(dest, rel)
    os.makedirs(os.path.dirname(target), exist_ok=True)
    with open(target, 'wb') as f:
        f.write(z.read(info))
    os.chmod(target, (info.external_attr >> 16) & 0o777 or 0o644)
PY
    rm -f "$zip"
    mv "$CADDY_BUILD_WORK/go.new" "$CADDY_BUILD_WORK/go"
fi

say "==> Building Caddy with the network_relay plugin (takes several minutes on machines with little memory)"
mkdir -p "$CACHE"
jobs=(-p "$CADDY_BUILD_JOBS")
caddy_run_build caddy_build_in_source "$SRC" env GOTOOLCHAIN=local GOFLAGS=-mod=readonly CGO_ENABLED=0 GOMAXPROCS="$CADDY_BUILD_JOBS" GOWORK=off GOOS=linux GOARCH="$GOARCH" \
        GOPATH="$CADDY_BUILD_WORK/gopath" GOMODCACHE="$CADDY_BUILD_WORK/gomod" GOCACHE="$CADDY_BUILD_WORK/gocache" \
        "$GO" build "${jobs[@]}" -tags http2legacy -trimpath -ldflags '-s -w' -o "$CACHE/caddy.new" ./cmd/caddy || die 'Build failed (the reason is above). If memory is short, add swap first; if it is a network problem, check that proxy.golang.org is reachable.'
# Read the whole list before searching it: with pipefail, "| grep -q" can fail
# when grep exits at the match and the writer then dies of SIGPIPE.
modules=$("$CACHE/caddy.new" list-modules 2>/dev/null || true)
grep -qx 'http.handlers.network_relay' <<<"$modules" || die 'The built Caddy has no network_relay module.'

if ! getent passwd caddy >/dev/null; then
    say "==> Creating the system user caddy"
    adduser --system --group --home /var/lib/caddy --shell /usr/sbin/nologin caddy >/dev/null
fi
mkdir -p "$ETC" "$SECRETS" "$WWW" "$DATA" "$(dirname "$BIN")" "$(dirname "$UNIT")" "$(dirname "$SYSCTL")"
chmod 700 "$SECRETS"
chown caddy:caddy "$DATA"
[[ -e $WWW/index.html ]] || printf '<!doctype html>\n<title>Welcome</title>\n<h1>Welcome</h1>\n' >"$WWW/index.html"

backup=$(mktemp -d "$CACHE/backup.XXXXXXXX")
for f in "$BIN" "$CADDYFILE" "$UNIT"; do
    [[ -e $f ]] && cp -p "$f" "$backup/"
done
was_active=0
systemctl is-active --quiet caddy 2>/dev/null && was_active=1
was_enabled=0
systemctl is-enabled --quiet caddy 2>/dev/null && was_enabled=1

# The password exists only in this script's memory: it goes into the
# profiles and is not stored anywhere else on the server. Installers before
# 2026-10 kept it in this file; an upgrade still uses it for the self-check.
legacy_password_file=$SECRETS/$RELAY_USER.password
password=''
if ((UPGRADE)) && [[ -f $legacy_password_file ]]; then
    password=$(head -n 1 "$legacy_password_file")
fi
# A first install that stops before the service starts leaves nothing
# behind, so the next run is a first install again.
started=0
generated_profiles=()
undo_fresh() {
    local status=$?
    if ((status != 0 && !UPGRADE && !started)); then
        rm -f "$CADDYFILE"
        for f in "${generated_profiles[@]}"; do rm -f "$f"; done
    fi
    if declare -F caddy_source_cleanup >/dev/null; then caddy_source_cleanup || status=1; fi
    return "$status"
}
trap undo_fresh EXIT
if ((!UPGRADE)); then
    say "==> Generating a random password for user $RELAY_USER (not shown; it is only put into the profiles)"
    out=$("$CACHE/caddy.new" network-relay passwd --name "$RELAY_USER")
    password=$(sed -n 's/^password: //p' <<<"$out")
    user_line=$(grep '^user ' <<<"$out")
    [[ -n $password && -n $user_line ]] || die 'Generating the password failed.'
    unset out
    email_line=''
    [[ -n $EMAIL ]] && email_line=$'\temail '"$EMAIL"
    tmp=$(mktemp "$ETC/.Caddyfile.XXXXXX")
    cat >"$tmp" <<EOF
$MARKER
# domain: $DOMAIN
# user: $RELAY_USER
#
# Add a user: caddy network-relay passwd --name ipad, put the "user ..."
# line it prints below the others, then: systemctl reload caddy

{
$email_line
}

# ":443" makes the site match every host name: a device's CONNECT request
# names the destination (for example www.google.com:443) as its host.
$DOMAIN, :443 {
	network_relay {
		relay_id $DOMAIN
		$user_line
	}

	root * /var/www/relay
	file_server
}
EOF
    "$CACHE/caddy.new" fmt --overwrite "$tmp" 2>/dev/null || true
    chmod 640 "$tmp"
    chown root:caddy "$tmp"
    mv -f "$tmp" "$CADDYFILE"
fi

say "==> Checking the configuration"
if ! runuser -u caddy -- env HOME=/var/lib/caddy "$CACHE/caddy.new" validate --config "$CADDYFILE" --adapter caddyfile \
    >"$CACHE/validate.log" 2>&1; then
    tail -20 "$CACHE/validate.log" >&2
    die "The configuration check failed (the reason is above). The service was not touched; the old version (if any) keeps running."
fi

# quic-go wants large UDP buffers; only raise the limits, never lower them.
want=7500000
{
    echo '# UDP buffers for HTTP/3 (quic-go); written by caddy-network-relay install.sh'
    for key in net.core.rmem_max net.core.wmem_max; do
        current=$(sysctl -n "$key" 2>/dev/null || echo 0)
        # Persist raised values even when a previous install already applied
        # them at runtime; otherwise an upgrade erases them for the next boot.
        ((current >= want)) || current=$want
        echo "$key = $current"
    done
} >"$SYSCTL"
sysctl -p "$SYSCTL" >/dev/null 2>&1 || say "(This machine does not allow changing the UDP buffer limits; keeping the system defaults.)"

if command -v ufw >/dev/null && grep -q '^Status: active' <<<"$(ufw status 2>/dev/null || true)"; then
    say "==> Allowing TCP 80, TCP 443 and UDP 443 in ufw"
    ufw allow 80/tcp >/dev/null
    ufw allow 443/tcp >/dev/null
    ufw allow 443/udp >/dev/null
fi

# Defined before anything is replaced: every failure from here on, including
# a restart that exits non-zero (set -e would otherwise stop the script right
# there), restores the state from before the install.
rollback() {
    set +e # restore as much as possible, whatever fails along the way
    restore_failed=0
    say "The service did not start; restoring the state from before the install. Log:"
    journalctl -u caddy -n 40 --no-pager 2>/dev/null || true
    # Stop and disable the candidate while its unit still exists. On a fresh
    # install, restoring files removes that unit; systemd cannot stop it then.
    if [[ -e $UNIT ]]; then
        systemctl stop caddy >/dev/null 2>&1 || restore_failed=1
        systemctl disable caddy >/dev/null 2>&1 || restore_failed=1
    fi
    for f in "$BIN" "$CADDYFILE" "$UNIT"; do
        if [[ -e $backup/$(basename "$f") ]]; then
            cp -p "$backup/$(basename "$f")" "$f" || restore_failed=1
        elif ((!UPGRADE)); then
            rm -f "$f" || restore_failed=1
        fi
    done
    if ((!UPGRADE)); then
        for f in "${generated_profiles[@]}"; do rm -f "$f" || restore_failed=1; done
    fi
    systemctl daemon-reload || restore_failed=1
    if ((was_active)); then
        systemctl restart caddy || restore_failed=1
        systemctl is-active --quiet caddy || restore_failed=1
    fi
    if ((was_enabled)); then
        systemctl enable caddy >/dev/null 2>&1 || restore_failed=1
    fi
    if ((old_stopped)); then
        if ((old_enabled)); then systemctl enable network-relay || restore_failed=1; fi
        systemctl restart network-relay || restore_failed=1
        systemctl is-active --quiet network-relay || restore_failed=1
    fi
    ((restore_failed == 0)) || die 'Install failed; rollback is incomplete. Manual service recovery is required. The preceding log shows the failures.'
    if ((was_active)); then
        die 'Install failed and was rolled back. The old version keeps running.'
    fi
    die 'Install failed and was rolled back. Caddy was not running before the install and remains stopped.'
}

# Complete the credential-bearing profile before replacing or starting the
# service. Losing the only password here would otherwise leave a running
# first installation that neither a device nor a retry can authenticate to.
lists=("$SRC/deploy/domains/google-ai-social.txt")
profile=$SECRETS/$DOMAIN-$RELAY_USER.mobileconfig
global=$SECRETS/$DOMAIN-$RELAY_USER-global.mobileconfig
if [[ -n $password ]]; then
    say "==> Generating profiles"
    if ((!UPGRADE)) || [[ ! -e $profile ]]; then
        printf '%s\n' "$password" | "$CACHE/caddy.new" network-relay profile --host "$DOMAIN" --user "$RELAY_USER" --password-stdin \
            --domains-file "${lists[0]}" -o "$profile"
        generated_profiles+=("$profile")
    fi
    if ((!UPGRADE)) || [[ ! -e $global ]]; then
        gfw=()
        ((GFWLIST)) && gfw=(--gfwlist)
        if printf '%s\n' "$password" | "$CACHE/caddy.new" network-relay profile --host "$DOMAIN" --user "$RELAY_USER" --password-stdin \
            --domains-file "${lists[0]}" --domains-file "$SRC/deploy/domains/global-services.txt" "${gfw[@]}" \
            --ui-toggle-enabled false --name "$DOMAIN (global services)" -o "$global"; then
            generated_profiles+=("$global")
        else
            # A fresh account has new credentials; a leftover profile for
            # that filename must not be offered with the previous password.
            if ((!UPGRADE)); then rm -f "$global"; fi
            say "(The global profile was not generated, most likely because downloading the gfwlist failed. The primary profile contains the credentials; keep it until installed.)"
            say "(To retry, run caddy network-relay profile with the account password. Re-running the installer cannot regenerate a missing profile without that password.)"
        fi
    fi
fi

say "==> Installing and starting the service"
started=1
install -m 755 "$CACHE/caddy.new" "$BIN.new" || rollback
mv -f "$BIN.new" "$BIN" || rollback
install -m 644 "$SRC/deploy/caddy.service" "$UNIT" || rollback
systemctl daemon-reload || rollback
systemctl enable caddy >/dev/null 2>&1 || rollback
if ((REPLACE_OLD)) && systemctl is-active --quiet network-relay 2>/dev/null; then
    say "==> Disabling the old network-relay service (its files stay where they are)"
    old_stopped=1
    systemctl disable --now network-relay || rollback
fi
systemctl restart caddy || rollback
sleep "${RELAY_TEST_SLEEP:-2}"
systemctl is-active --quiet caddy || rollback

manual_check="$BIN network-relay check --server $DOMAIN --address 127.0.0.1 --user $RELAY_USER"
check_ok=0
if [[ -n $password ]]; then
    say "==> Waiting for the certificate and running the self-check (a first install waits for Let's Encrypt, up to 3 minutes)"
    for _ in $(seq "${RELAY_TEST_TRIES:-36}"); do
        # A pipe, not a file: the password is never written to disk.
        if printf '%s\n' "$password" | "$BIN" network-relay check --server "$DOMAIN" --address 127.0.0.1 \
            --user "$RELAY_USER" --password-stdin --timeout 10s >"$CACHE/check.log" 2>&1; then
            check_ok=1
            break
        fi
        systemctl is-active --quiet caddy || rollback
        sleep "${RELAY_TEST_SLEEP:-5}"
    done
    cat "$CACHE/check.log"
else
    check_ok=1
    say "==> The installer does not keep the password, so it cannot test the relay with it. Test it with (asks for the password):"
    say "      $manual_check"
fi

unset password

host_ip=$(tailscale ip -4 2>/dev/null | head -1 || true)
host_ip=${host_ip:-${public_ip:-SERVER_IP}}
cat <<MSG

Done. Caddy with network_relay is running and starts at boot.
  Configuration: $CADDYFILE      Log: journalctl -u caddy -n 100 --no-pager
MSG
if [[ -e $profile || -e $global ]]; then
    say '  Profiles (they contain the password, which is stored nowhere else on this server; only root can read them):'
    [[ ! -e $profile ]] || say "    $profile           Google/AI/X and more go through the relay"
    [[ ! -e $global ]] || say "    $global    the listed services + gfwlist go through the relay; cannot be turned off in Settings"
    download_profile=$profile
    [[ ! -e $global ]] || download_profile=$global
    cat <<MSG
  To download to a Mac (run this in the Mac's Terminal):
    scp root@$host_ip:$download_profile ~/Downloads/
  Before installing on a device, remove any old relay profile from it. Once the devices have it, delete
  the profiles here and on the Mac: rm $SECRETS/*.mobileconfig (for another device, create a user as in docs/deploy.md).
MSG
fi
if [[ -f $legacy_password_file ]]; then
    cat <<MSG
  An earlier version of this installer kept the password in $legacy_password_file.
  It is no longer needed; delete it once you no longer use it: rm $legacy_password_file
MSG
fi
if ((!check_ok)); then
    cat <<MSG

Note: the local self-check did not fully pass (see the FAIL lines above). The service keeps running so you can investigate:
  - If the certificate is not issued yet, wait a minute or two, then run (it asks for the password)
      $manual_check
  - The cloud provider's firewall/security group must allow TCP 80, TCP 443 and UDP 443.
MSG
    exit 1
fi
