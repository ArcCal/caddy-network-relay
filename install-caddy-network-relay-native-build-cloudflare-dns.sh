#!/usr/bin/env bash
# Interactive native Caddy relay build with the Cloudflare DNS plugin and ACME.
# Debian 12+ / Ubuntu 22.04+, amd64/arm64, Bash 4+, systemd; fresh installs only.
# Keep Cloudflare DNS records DNS-only and allow inbound TCP/UDP 443.
# Token: Zone:DNS:Edit + Zone:Zone:Read, scoped to the relay's zone.
# No Certbot: Caddy obtains and renews certificates using its DNS plugin.
set +x
set +v

SERVICE=caddy-network-relay
PLUGIN_TAG=v0.2.4
PLUGIN_COMMIT=a8737d095ad5a48ca031cea6ab704057dbc2d250
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
ETC=/etc/$SERVICE
CONFIG=$ETC/Caddyfile
TOKEN_FILE=$ETC/cloudflare.env
PROFILE=$ETC/relay/device.mobileconfig
CLIENT_CONFIG=$ETC/relay/network-relay-rs-client.toml
BIN=/usr/local/bin/$SERVICE
UNIT=/etc/systemd/system/$SERVICE.service
DATA=/var/lib/$SERVICE
TOOLS=/opt/$SERVICE
WWW=/var/www/$SERVICE
SYSCTL=/etc/sysctl.d/90-caddy-network-relay-cloudflare-dns.conf
work=
startup_pending=0

cr_die() { printf 'Error: %s\n' "$*" >&2; exit 1; }
cr_usage() {
    cat <<EOF
Usage: sudo bash ${0##*/}
       bash ${0##*/} --plan

Interactively build this checkout for native amd64/arm64 with the pinned
caddy-dns/cloudflare plugin. Configure DNS-01 certificate issuance and renewal,
a relay user, private Apple and Rust client configurations, systemd and protocol
self-checks. The Rust TOML is generated after the protocol checks succeed.
Requires Debian 12+ or Ubuntu 22.04+, systemd and at least 5 GiB of free disk.

Only two prompts: relay domain and hidden CF_API_TOKEN.
Defaults: user iphone, one build job, bundled selected-domain device profile.
Running the installer accepts the ACME CA terms. No confirmation prompt.
Fresh installations only; existing $SERVICE files/services are refused.
Caddyfile uses: tls { dns cloudflare {env.CF_API_TOKEN} }
The token is loaded from a root-only systemd EnvironmentFile for renewal.
DNS-only A/AAAA records must point here. Open TCP/UDP 443 in the provider firewall.
No inbound port 80 is needed; automatic HTTP redirects are disabled.
Binary: $BIN
Configuration and private client files: $ETC
Service/account: $SERVICE; state/certificates: $DATA; build tools/cache: $TOOLS
Service logs: journalctl -u $SERVICE
EOF
}
cr_host() {
    [[ $(uname -s) == Linux ]] || cr_die 'Run this on the Linux server.'
    case $(uname -m) in
        x86_64) arch=amd64; triple=x86_64-unknown-linux-gnu ;;
        aarch64|arm64) arch=arm64; triple=aarch64-unknown-linux-gnu ;;
        *) cr_die 'Only x86_64/amd64 and aarch64/arm64 are supported.' ;;
    esac
    local ID= VERSION_ID= major minor
    # shellcheck source=/dev/null
    . /etc/os-release
    [[ $VERSION_ID =~ ^[0-9]+([.][0-9]+)?$ ]] || cr_die 'A released Debian/Ubuntu version is required.'
    major=${VERSION_ID%%.*}; minor=${VERSION_ID#*.}
    case $ID in
        debian) (( 10#$major >= 12 )) || cr_die 'Debian 12+ is required.' ;;
        ubuntu)
            [[ $VERSION_ID == *.* ]] || cr_die 'Ubuntu 22.04+ is required.'
            (( 10#$major > 22 || (10#$major == 22 && 10#$minor >= 4) )) || cr_die 'Ubuntu 22.04+ is required.' ;;
        *) cr_die 'Only Debian 12+ and Ubuntu 22.04+ are supported.' ;;
    esac
}
cr_domain() {
    local value=$1
    (( ${#value} <= 253 )) && [[ $value =~ ^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?[.])+[a-z]{2,63}$ ]]
}
cr_ask() {
    local prompt=$1 default=${2:-}
    if [[ -n $default ]]; then prompt+=" [$default]"; fi
    read -r -p "$prompt: " REPLY </dev/tty || cr_die 'Interactive terminal input is required.'
    REPLY=${REPLY:-$default}
}
cr_fresh() {
    local path loaded
    local paths=("$ETC" "$BIN" "$UNIT" "$DATA" "$WWW" "$SYSCTL"
        "/lib/systemd/system/$SERVICE.service" "/usr/lib/systemd/system/$SERVICE.service" "/run/systemd/system/$SERVICE.service")
    for path in "${paths[@]}"; do
        [[ ! -e $path && ! -L $path ]] || cr_die "Existing installation/file: $path. Fresh installs only."
    done
    loaded=$(systemctl show "$SERVICE" --property=LoadState --value) || cr_die 'Cannot inspect systemd.'
    [[ -z $loaded || $loaded == not-found ]] || cr_die "An existing $SERVICE unit is loaded."
    local sockets=(/proc/net/tcp /proc/net/udp) file
    for file in /proc/net/tcp6 /proc/net/udp6; do [[ ! -r $file ]] || sockets+=("$file"); done
    for file in "${sockets[@]}"; do
        [[ -r $file ]] || cr_die "Cannot inspect listening sockets: $file is unreadable."
    done
    local port_state
    port_state=$(awk 'FNR > 1 && $2 ~ /:01BB$/ && (FILENAME ~ /udp/ || $4 == "0A") {busy=1} END {print busy+0}' "${sockets[@]}") \
        || cr_die 'Cannot inspect listening sockets; port availability is unknown.'
    if [[ $port_state != 0 ]]; then
        cr_die 'TCP or UDP 443 is busy. Stop the conflicting service yourself.'
    fi
}
cr_download() {
    curl --proto '=https' --proto-redir '=https' --tlsv1.2 --fail --show-error --location \
        --retry 3 --connect-timeout 20 --max-time 900 --output "$2" "$1"
}
cr_verify() {
    local actual
    [[ $2 =~ ^[a-f0-9]{64}$ ]] || cr_die 'Invalid checksum metadata.'
    actual=$(sha256sum -- "$1"); actual=${actual%% *}
    [[ $actual == "$2" ]] || cr_die 'Download checksum mismatch; refusing to use the artifact.'
}
cr_new_file() {
    local path=$1 mode=$2 group=${3:-root}
    [[ ! -e $path && ! -L $path ]] || cr_die "Refusing to replace $path."
    # noclobber also prevents following an existing symlink or truncating a file.
    (set -o noclobber; umask 077; cat > "$path")
    chmod "$mode" "$path"
    chown root:"$group" "$path"
}
cr_cleanup() {
    local status=$?
    trap - EXIT
    if (( startup_pending )); then systemctl disable --now "$SERVICE" >/dev/null 2>&1 || true; fi
    [[ -z $work ]] || rm -rf -- "$work"
    if (( status )); then
        printf 'Deployment incomplete (exit %s). No existing installation was replaced.\n' "$status" >&2
        printf 'Packages, certificates and partial files may remain. Inspect the last completed step before retrying.\n' >&2
        printf 'If already generated, the credential-bearing device profile is %s.\n' "$PROFILE" >&2
    fi
    exit "$status"
}
cr_check_replacement() {
    local info=$1 module=$2 replacement=$3
    awk -F '\t' -v module="$module" -v replacement="$replacement" '
        ($2 == "dep" || $2 == "mod") && $3 == module { pending=1; next }
        pending { if ($2 == "=>" && $3 == replacement) found=1; pending=0 }
        END { exit !found }
    ' <<< "$info"
}
cr_build() {
    local jobs=$1 version expected modules info module
    mkdir "$work/source"
    tar -C "$REPO" --exclude=.git --exclude=target --exclude=__pycache__ --exclude=.venv \
        --exclude='relay-servers-*' -cf - . | tar -C "$work/source" -xf -
    version=$(sed -n 's/^toolchain \(go[0-9][0-9.]*\)$/\1/p' "$work/source/go.mod")
    [[ $version =~ ^go[0-9]+[.][0-9]+[.][0-9]+$ ]] || cr_die 'go.mod must pin a release Go toolchain.'
    cr_download 'https://go.dev/dl/?mode=json&include=all' "$work/go-releases.json"
    expected=$(jq -er --arg version "$version" --arg arch "$arch" \
        '[.[] | select(.version == $version) | .files[] | select(.os == "linux" and .arch == $arch and .kind == "archive" and .filename == ($version + ".linux-" + $arch + ".tar.gz"))] | if length == 1 then .[0].sha256 else error("No unique Go archive") end' "$work/go-releases.json")
    cr_download "https://dl.google.com/go/$version.linux-$arch.tar.gz" "$work/go.tar.gz"
    cr_verify "$work/go.tar.gz" "$expected"
    tar --no-same-owner -C "$work" -xzf "$work/go.tar.gz"
    # Pin the same reviewed DNS plugin release and commit as the repository builder.
    GIT_TERMINAL_PROMPT=0 git clone --depth 1 --branch "$PLUGIN_TAG" --single-branch \
        https://github.com/caddy-dns/cloudflare.git "$work/cloudflare-src"
    [[ $(git -C "$work/cloudflare-src" rev-parse --verify HEAD) == "$PLUGIN_COMMIT" ]] || cr_die 'Cloudflare plugin commit does not match the reviewed release.'
    [[ -f $work/cloudflare-src/go.mod ]] || cr_die 'Incomplete Cloudflare plugin source.'
    unset GOOS GOARCH GOFLAGS GOWORK GOROOT GOENV
    export GOTOOLCHAIN=local GOWORK=off GOENV=off GOFLAGS='' GOOS=linux GOARCH=$arch CGO_ENABLED=0
    export GOAMD64=v1 GOARM64=v8.0 GOPATH=$TOOLS/gopath GOCACHE=$TOOLS/gocache
    local go=$work/go/bin/go mod=$work/source/cloudflare-build.mod
    "$go" version
    # All build overlays live in the temporary snapshot, never in this checkout.
    for module in cloudflare-build.mod cloudflare-build.sum cmd/caddy/cloudflare_dns_build.go; do
        [[ ! -e $work/source/$module && ! -L $work/source/$module ]] || cr_die "Build overlay already exists: $module."
    done
    cp "$work/source/go.mod" "$mod"
    cp "$work/source/go.sum" "$work/source/cloudflare-build.sum"
    printf 'package main\n\nimport _ "github.com/caddy-dns/cloudflare"\n' > "$work/source/cmd/caddy/cloudflare_dns_build.go"
    (
        cd "$work/source"
        "$go" mod edit -modfile "$mod" -replace github.com/caddy-dns/cloudflare=../cloudflare-src
        "$go" get -modfile "$mod" github.com/caddy-dns/cloudflare@"$PLUGIN_TAG"
        "$go" mod edit -modfile "$mod" -json | jq -e '
            any(.Replace[]; .Old.Path == "golang.org/x/net" and .New.Path == "./third_party/x-net") and
            any(.Replace[]; .Old.Path == "github.com/quic-go/quic-go" and .New.Path == "./third_party/quic-go") and
            any(.Replace[]; .Old.Path == "github.com/caddy-dns/cloudflare" and .New.Path == "../cloudflare-src")' >/dev/null
        "$go" build -modfile "$mod" -mod=readonly -tags http2legacy -trimpath -p "$jobs" -o "$work/$SERVICE" ./cmd/caddy
    )
    modules=$("$work/$SERVICE" list-modules)
    for module in network_relay http.handlers.network_relay dns.providers.cloudflare; do
        grep -Fxq "$module" <<< "$modules" || cr_die "Built Caddy is missing $module."
    done
    info=$("$go" version -m "$work/$SERVICE")
    cr_check_replacement "$info" github.com/caddy-dns/cloudflare ../cloudflare-src || cr_die 'Missing Cloudflare build replacement.'
    cr_check_replacement "$info" golang.org/x/net ./third_party/x-net || cr_die 'Missing patched HTTP/2 transport.'
    cr_check_replacement "$info" github.com/quic-go/quic-go ./third_party/quic-go || cr_die 'Missing patched QUIC transport.'
    grep -Eq "^[[:space:]]*build[[:space:]]+GOARCH=$arch$" <<< "$info" || cr_die 'Wrong binary architecture.'
    grep -Eq '^[[:space:]]*build[[:space:]]+CGO_ENABLED=0$' <<< "$info" || cr_die 'Binary unexpectedly requires CGO.'
    "$work/$SERVICE" version
}
cr_config_text() {
    cat <<EOF
# Managed by install-caddy-network-relay-native-build-cloudflare-dns.sh
{
    auto_https disable_redirects
}
# Catch-all :443 is required for CONNECT requests naming destination hosts.
$domain, :443 {
    tls {
        dns cloudflare {env.CF_API_TOKEN}
    }
    network_relay {
        relay_id $domain
        $account
    }
    root * $WWW
    file_server
}
EOF
}
cr_unit_text() {
    # Adapt the repository's unit without changing the shared deployment template.
    # EnvironmentFile is read by systemd as root, not by the service user.
    awk -v service="$SERVICE" -v binary="$BIN" -v config="$CONFIG" \
        -v token="$TOKEN_FILE" -v data="$DATA" -v unit="$UNIT" '
        /^# Installed by / {
            print "# Installed by install-caddy-network-relay-native-build-cloudflare-dns.sh as " unit "."
            next
        }
        /^User=/ { print "User=" service; next }
        /^Group=/ { print "Group=" service; next }
        /^ExecStart=/ { print "ExecStart=" binary " run --config " config " --adapter caddyfile"; next }
        /^ExecReload=/ { print "ExecReload=" binary " reload --config " config " --adapter caddyfile --force"; next }
        { print }
        /^\[Service\]$/ {
            print "EnvironmentFile=" token
            print "Environment=HOME=" data
            print "Environment=XDG_DATA_HOME=" data "/.local/share"
            print "Environment=XDG_CONFIG_HOME=" data "/.config"
        }
    ' "$REPO/deploy/caddy.service"
}
cr_profile_args() {
    profile_args=(network-relay profile --host "$domain" --user "$device_user" --password-stdin
        --exclude-domain "$domain" --ui-toggle-enabled true --out "$PROFILE")
    if [[ $scope == selected ]]; then
        profile_args+=(--domains-file "$REPO/deploy/domains/google-ai-social.txt"
            --domains-file "$REPO/deploy/domains/global-services.txt")
        # Both files must have rules: an empty MatchDomains means all traffic.
        local file
        for file in google-ai-social.txt global-services.txt; do
            grep -Eq '^[[:space:]]*[a-zA-Z0-9]' "$REPO/deploy/domains/$file" || cr_die "Empty bundled domain list: $file."
        done
    fi
}
cr_account() {
    if id -u "$SERVICE" >/dev/null 2>&1; then
        [[ $(id -u "$SERVICE") != 0 && $(id -g "$SERVICE") != 0 && $(id -gn "$SERVICE") == "$SERVICE" ]] || cr_die 'Refusing a privileged or mismatched Caddy account.'
    else
        useradd --system --user-group --no-create-home --home-dir "$DATA" --shell /usr/sbin/nologin "$SERVICE"
    fi
}
cr_client_config_text() {
    # Domain/user were validated and the generated password is hexadecimal,
    # so these strings need no additional TOML escaping.
    cat <<EOF
# Network Relay RS client configuration. Contains a password: keep private.
# Import into Network Relay RS, or run network-relay-rs --config FILE.
uri_template = "https://$domain/.well-known/masque/udp/{target_host}/{target_port}/"
username = "$device_user"
password = "$relay_password"
transport = "auto"
mode = "socks"

[socks]
listen = ["127.0.0.1:1080"]
EOF
}
cr_deploy() {
    local relay_password account key current response ready=0 attempt
    cr_account
    install -d -o root -g "$SERVICE" -m 750 "$ETC"
    install -d -o root -g root -m 700 "${PROFILE%/*}"
    install -d -o "$SERVICE" -g "$SERVICE" -m 750 "$DATA"
    [[ -d ${WWW%/*} ]] || install -d -m 755 "${WWW%/*}"
    install -d -m 755 "$WWW"
    printf '<!doctype html>\n<title>Welcome</title>\n<h1>Welcome</h1>\n' | cr_new_file "$WWW/index.html" 644
    printf 'CF_API_TOKEN=%s\n' "$cf_token" | cr_new_file "$TOKEN_FILE" 600
    relay_password=$(openssl rand -hex 24)
    account=$(printf '%s\n' "$relay_password" | "$work/$SERVICE" network-relay passwd --name "$device_user" --stdin --fast-hash)
    [[ $account =~ ^user[[:space:]]$device_user[[:space:]]\$[A-Za-z0-9\$=,+/._-]+$ ]] || cr_die 'Unexpected password hash output.'
    cr_config_text | cr_new_file "$CONFIG" 640 "$SERVICE"
    cr_profile_args
    printf '%s\n' "$relay_password" | "$work/$SERVICE" "${profile_args[@]}"
    chmod 600 "$PROFILE"
    install -m 755 "$work/$SERVICE" "$BIN"
    cr_unit_text | cr_new_file "$UNIT" 644
    # Caddy must see the same token and storage paths during validation and runtime.
    # The assignment is an environment binding, never a command-line argument.
    CF_API_TOKEN=$cf_token runuser -u "$SERVICE" -- env HOME="$DATA" XDG_DATA_HOME="$DATA/.local/share" \
        XDG_CONFIG_HOME="$DATA/.config" "$BIN" validate --config "$CONFIG" --adapter caddyfile
    unset cf_token
    {
        printf '# UDP buffer limits for Caddy network relay.\n'
        for key in net.core.rmem_max net.core.wmem_max; do
            current=$(sysctl -n "$key")
            [[ $current =~ ^[0-9]+$ ]] || cr_die 'Cannot read UDP buffer limits.'
            (( current >= 8388608 )) || current=8388608
            printf '%s = %s\n' "$key" "$current"
        done
    } | cr_new_file "$SYSCTL" 644
    sysctl -p "$SYSCTL" || printf 'Warning: UDP buffer tuning was denied; using system defaults.\n'
    systemctl daemon-reload
    startup_pending=1
    systemctl enable --now "$SERVICE"
    printf 'Waiting for DNS challenge and trusted HTTPS (up to about eight minutes)...\n'
    for ((attempt=0; attempt<60; attempt++)); do
        systemctl is-active --quiet "$SERVICE" || cr_die "$SERVICE stopped during certificate issuance; inspect journalctl -u $SERVICE."
        if response=$(curl --noproxy '*' --fail --silent --show-error --max-time 3 \
            --resolve "$domain:443:127.0.0.1" "https://$domain/" 2>/dev/null); then
            if [[ $response == *'<h1>Welcome</h1>'* ]]; then ready=1; break; fi
        fi
        sleep 5
    done
    (( ready )) || cr_die "Certificate/HTTPS readiness failed. Check Cloudflare permissions, DNS propagation and journalctl -u $SERVICE. The new service will be stopped."
    startup_pending=0
    printf 'Trusted local HTTPS works. Protected device profile: %s\n' "$PROFILE"
    if ! printf '%s\n' "$relay_password" | "$BIN" network-relay check --server "$domain" --address 127.0.0.1 \
        --user "$device_user" --password-stdin; then
        cr_die "$SERVICE remains running, but protocol checks failed. Check outbound TCP 80/UDP 53 and journalctl -u $SERVICE. Do not rerun this fresh installer."
    fi
    cr_client_config_text | cr_new_file "$CLIENT_CONFIG" 600
    unset relay_password
    printf 'All built-in TCP/UDP checks passed. Verify external access on a real device.\n'
    printf 'Download %s over SSH, install it, then delete the profile copies.\n' "$PROFILE"
    printf 'Rust client configuration: %s (contains the same credentials; mode 600).\n' "$CLIENT_CONFIG"
    printf 'Download it over SSH; import into Network Relay RS or use network-relay-rs --config FILE.\n'
    printf 'Caddy renews certificates automatically. Keep %s and %s.\n' "$TOKEN_FILE" "$DATA"
}
cr_inputs() {
    cr_ask 'Relay domain'; domain=${REPLY,,}; domain=${domain%.}
    cr_domain "$domain" || cr_die 'Invalid DNS hostname; omit scheme, port and wildcard.'
    printf 'Use a zone-scoped Cloudflare token with Zone:DNS:Edit and Zone:Zone:Read.\n'
    if [[ -z $cf_token ]]; then
        read -r -s -p 'CF_API_TOKEN (hidden): ' cf_token </dev/tty || cr_die 'Could not read token.'
        printf '\n'
    fi
    [[ $cf_token =~ ^[A-Za-z0-9_-]{20,256}$ ]] || cr_die 'Expected a Cloudflare API Token.'
}
cr_noninteractive() {
    # Only the domain/token prompts may read from the terminal. All subsequent
    # commands get EOF unless explicitly fed a generated secret through a pipe.
    exec </dev/null
    export GIT_TERMINAL_PROMPT=0 GIT_ASKPASS=/bin/false SSH_ASKPASS=/bin/false
    export DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a APT_LISTCHANGES_FRONTEND=none
}
cr_main() {
    case ${1:-} in
        -h|--help) cr_usage; return ;;
        --plan) [[ $# == 1 ]] || cr_die 'Unexpected extra arguments.'; cr_host
            printf 'Native Linux/%s Caddy build with Cloudflare DNS plugin %s, DNS-01, systemd and protocol checks.\n' "$arch" "$PLUGIN_TAG"; return ;;
        '') ;;
        *) cr_die 'Unknown option; use --help or --plan.' ;;
    esac
    cr_host
    [[ $EUID == 0 && -d /run/systemd/system ]] || cr_die 'Run as root on a server booted with systemd.'
    local cf_token=${CF_API_TOKEN:-} jobs path free_kib
    unset CF_API_TOKEN
    export -n cf_token
    umask 077
    command -v flock >/dev/null || cr_die 'flock from util-linux is required.'
    install -d -m 700 "/run/$SERVICE-install"
    exec {install_lock}>"/run/$SERVICE-install/lock"
    flock -n "$install_lock" || cr_die 'Another installer is running.'
    cr_fresh
    cr_inputs
    cr_noninteractive
    device_user=iphone
    scope=selected
    jobs=1
    printf 'Defaults: user iphone, one build job, bundled selected-domain profile.\n'
    printf 'Set DNS-only A/AAAA records to this server; open TCP/UDP 443 in the provider firewall.\n'
    printf 'Installing Caddy with Cloudflare DNS-01 and automatic certificate renewal.\n'
    local required=(go.mod go.sum cmd/caddy/main.go third_party/quic-go/go.mod third_party/x-net/go.mod
        deploy/caddy.service deploy/domains/google-ai-social.txt deploy/domains/global-services.txt)
    for path in "${required[@]}"; do [[ -f $REPO/$path ]] || cr_die "Complete checkout required; missing $path."; done
    free_kib=$(df -Pk /opt | awk 'NR==2 {print $4}')
    [[ $free_kib =~ ^[0-9]+$ ]] && (( free_kib >= 5*1024*1024 )) || cr_die 'At least 5 GiB free under /opt is required.'
    local apt=(apt-get -o DPkg::Lock::Timeout=1800 -o Acquire::Retries=3
        -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold)
    DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a APT_LISTCHANGES_FRONTEND=none "${apt[@]}" update
    DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a APT_LISTCHANGES_FRONTEND=none "${apt[@]}" install -y --no-install-recommends ca-certificates curl git jq openssl iproute2
    install -d -m 700 "$TOOLS"
    work=$(mktemp -d "$TOOLS/build.XXXXXXXX")
    trap cr_cleanup EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM
    cr_build "$jobs"
    cr_deploy
}

# Sourcing exposes helpers for isolated tests without installing anything.
if [[ ${BASH_SOURCE[0]} == "$0" ]]; then
    set -Eeuo pipefail
    unset CDPATH
    export LC_ALL=C
    cr_main "$@"
fi
