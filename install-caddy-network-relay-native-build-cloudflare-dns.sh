#!/usr/bin/env bash
# Interactive native Caddy relay build with the Cloudflare DNS plugin and ACME.
# Debian 12+ / Ubuntu 24.04+, amd64/arm64, Bash 4+, systemd; install/upgrade/repair.
# Keep Cloudflare DNS records DNS-only and allow inbound TCP/UDP 443.
# Token: Zone:DNS:Edit + Zone:Zone:Read, scoped to the relay's zone.
# No Certbot: Caddy obtains and renews certificates using its DNS plugin.
#
# Run this file from a complete checkout on the target server. It performs:
#   1. Read-only platform, safe-path/account and port checks, then two inputs.
#   2. Noninteractive package installation and a verified native Go build.
#   3. Candidate preparation/validation while the previous service keeps running.
#   4. Root-only backup, atomic file replacement and service/protocol checks.
#   5. Export of the Rust client configuration with the same relay credentials.
# The Apple profile is created before startup so its password is recoverable if
# later checks fail. Rerunning also repairs missing dedicated files and upgrades
# an existing dedicated installation. General-purpose Caddy is never changed.
#
# Tracing must be disabled before reading secrets, including when invoked with
# bash -x or bash -v. Neither tokens nor generated passwords belong in logs.
set +x
set +v

# Select trusted system utilities before resolving REPO or running checks. Keep
# proxy/CA settings intact. Sourcing helpers leaves the caller's PATH untouched.
if [[ ${BASH_SOURCE[0]} == "$0" ]]; then
    export PATH=/usr/sbin:/usr/bin:/sbin:/bin
    unset CDPATH
fi

# Keep the account, unit and installed paths separate from a general Caddy
# installation. These defaults are intentionally fixed; they add no prompts.
SERVICE=caddy-network-relay
# Check both the release label and its commit: a moved tag must not silently
# change which DNS provider source is incorporated into the binary.
PLUGIN_TAG=v0.2.4
PLUGIN_COMMIT=a8737d095ad5a48ca031cea6ab704057dbc2d250
# Resolve relative to this script, not the caller's working directory.
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
ETC=/etc/$SERVICE
CONFIG=$ETC/Caddyfile
TOKEN_FILE=$ETC/cloudflare.token
# Client exports contain the plaintext relay password and remain root-only.
PROFILE=$ETC/relay/device.mobileconfig
CLIENT_CONFIG=$ETC/relay/network-relay-rs-client.toml
BIN=/usr/local/bin/$SERVICE
UNIT=/etc/systemd/system/$SERVICE.service
# DATA survives restarts for ACME accounts/certificates; RUNTIME is temporary
# and holds the local management socket. Build caches live outside both.
DATA=/var/lib/$SERVICE
RUNTIME=/run/$SERVICE
ADMIN_ADDRESS=unix/$RUNTIME/admin.sock
TOOLS=/opt/$SERVICE
WWW=/var/www/$SERVICE
SYSCTL=/etc/sysctl.d/90-caddy-network-relay-cloudflare-dns.conf
# The EXIT trap removes only this run's scratch directory. Once replacement
# starts, transaction_started requires restoration of files and service state.
work=
transaction_started=0
backup_dir=
was_active=0
was_enabled=disabled
credentials_reused=0
certificate_available=0
existing_certificate=

# Diagnostics must describe the failed step without embedding secret values.
cr_die() { printf 'Error: %s\n' "$*" >&2; exit 1; }
# --help describes prerequisites and outputs without installing anything.
cr_usage() {
    cat <<EOF
Usage: sudo bash ${0##*/}
       bash ${0##*/} --plan

Interactively build this checkout for native amd64/arm64 with the pinned
caddy-dns/cloudflare plugin. Configure DNS-01 certificate issuance and renewal,
a relay user, private Apple and Rust client configurations, systemd and protocol
self-checks. The Rust TOML is generated after the protocol checks succeed.
Requires Debian 12+ or Ubuntu 24.04+, systemd 249+ and 5 GiB of free disk.

Only two prompts: relay domain and hidden CF_API_TOKEN.
Defaults: user iphone, one build job, bundled selected-domain device profile.
Running the installer accepts the ACME CA terms. No confirmation prompt.
Existing dedicated files are automatically replaced from the current script. A compatible
private client export preserves its relay password; otherwise a new 22-character
password is generated and both client files are refreshed. Dedicated service
files/drop-ins are backed up privately before replacement; ACME state and website
content stay in place. Existing valid Caddy certificates are detected and reused
without a forced certificate request. Unsafe paths or shared/login accounts are rejected.
Caddy reads the DNS token from systemd credentials, not its environment.
The root-only token source is $TOKEN_FILE and is retained for renewal.
The service has a read-only host filesystem, private state/runtime directories,
and only the capability needed to bind port 443.
DNS-only A/AAAA records must point here. Open TCP/UDP 443 in the provider firewall.
No inbound port 80 is needed; automatic HTTP redirects are disabled.
Binary: $BIN
Configuration and private client files: $ETC
Service/account: $SERVICE; state/certificates: $DATA; build tools/cache: $TOOLS
Local management socket: $ADMIN_ADDRESS
Service logs: journalctl -u $SERVICE
EOF
}
# Detect the host rather than cross-compiling. The Go build and downloaded
# toolchain use arch; triple records the corresponding native GNU target.
# Only the package-manager/systemd combinations supported here are accepted.
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
            [[ $VERSION_ID == *.* ]] || cr_die 'Ubuntu 24.04+ is required.'
            (( 10#$major > 24 || (10#$major == 24 && 10#$minor >= 4) )) || cr_die 'Ubuntu 24.04+ is required.' ;;
        *) cr_die 'Only Debian 12+ and Ubuntu 24.04+ are supported.' ;;
    esac
}
# Accept a bare ASCII DNS hostname, not a URL, IP address or wildcard. Inputs
# are lowercased first. This also excludes Caddyfile/TOML injection characters.
cr_domain() {
    local value=$1
    (( ${#value} <= 253 )) && [[ $value =~ ^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?[.])+[a-z]{2,63}$ ]]
}
# Read deliberately from the controlling terminal. Later subprocesses receive
# EOF on stdin, so only this helper and the hidden token read are interactive.
cr_ask() {
    local prompt=$1 default=${2:-}
    if [[ -n $default ]]; then prompt+=" [$default]"; fi
    read -r -p "$prompt: " REPLY </dev/tty || cr_die 'Interactive terminal input is required.'
    REPLY=${REPLY:-$default}
}
# Reuse only a genuinely dedicated service identity. Its UID/GID must be
# unique, its home must be private service state (or /nonexistent), and it must
# have no login shell, group aliases, extra members or supplementary groups.
# Never "fix" an unsafe existing identity: it may belong to another workload.
cr_check_account() {
    local entry name ignored uid gid gecos home shell members aliases group_entry primary users groups item
    entry=$(getent passwd "$SERVICE" || true)
    group_entry=$(getent group "$SERVICE" || true)
    if [[ -z $entry ]]; then
        if [[ -n $group_entry ]]; then
            IFS=: read -r name ignored gid members <<< "$group_entry"
            [[ $gid =~ ^[0-9]+$ && $gid != 0 && -z $members ]] || cr_die 'Existing dedicated group is not safe to reuse.'
            aliases=$(getent group | awk -F: -v gid="$gid" '$3 == gid {n++} END {print n+0}')
            users=$(getent passwd | awk -F: -v gid="$gid" '$4 == gid {n++} END {print n+0}')
            [[ $aliases == 1 && $users == 0 ]] || cr_die 'Existing dedicated group is shared by another identity.'
        fi
        return
    fi
    IFS=: read -r name ignored uid gid gecos home shell <<< "$entry"
    [[ $uid =~ ^[0-9]+$ && $gid =~ ^[0-9]+$ && $uid != 0 && $gid != 0 ]] || cr_die 'Dedicated account must not be privileged.'
    [[ $home == "$DATA" || $home == /nonexistent ]] || cr_die 'Existing service account has an unrelated home directory.'
    case $shell in /usr/sbin/nologin|/sbin/nologin|/bin/false|/usr/bin/false) ;; *) cr_die 'Existing service account has a login shell.' ;; esac
    [[ -n $group_entry ]] || cr_die 'Dedicated primary group is missing.'
    IFS=: read -r name ignored primary members <<< "$group_entry"
    [[ $primary == "$gid" && -z $members && $(id -gn "$SERVICE") == "$SERVICE" ]] || cr_die 'Existing service account/group is shared or mismatched.'
    aliases=$(getent passwd | awk -F: -v uid="$uid" '$3 == uid {n++} END {print n+0}')
    users=$(getent passwd | awk -F: -v gid="$gid" '$4 == gid {n++} END {print n+0}')
    [[ $aliases == 1 && $users == 1 ]] || cr_die 'Existing service UID/GID is shared by another account.'
    aliases=$(getent group | awk -F: -v gid="$gid" '$3 == gid {n++} END {print n+0}')
    [[ $aliases == 1 ]] || cr_die 'Existing primary GID has another group alias.'
    groups=$(id -G "$SERVICE")
    for item in $groups; do [[ $item == "$gid" ]] || cr_die 'Dedicated account has supplementary groups.'; done
}
# Kept as an alias for older callers; existing safe accounts are now accepted.
cr_require_new_account() { cr_check_account; }
# A root-owned leaf is insufficient when another service can rename it through
# a writable parent. In particular, file_server follows symlinks: replacing the
# web root could otherwise expose files readable by the relay account. Check
# both lexical and resolved ancestors so a symlink cannot hide an unsafe parent.
# Refuse unsafe shared directories instead of changing their ownership or mode.
cr_check_parent_dirs() {
    local path=$1 parent resolved metadata owner mode
    [[ $path == /* ]] || cr_die 'Installation paths must be absolute.'
    parent=${path%/*}; [[ -n $parent ]] || parent=/
    resolved=$(readlink -m -- "$parent") || cr_die "Cannot resolve parent of $path."
    for parent in "$parent" "$resolved"; do
        while :; do
            if [[ -e $parent || -L $parent ]]; then
                [[ -d $parent ]] || cr_die "Installation parent is not a directory: $parent."
                metadata=$(stat -Lc '%u %a' -- "$parent") || cr_die "Cannot inspect installation parent: $parent."
                read -r owner mode <<< "$metadata"
                [[ $owner == 0 && $mode =~ ^[0-7]{3,4}$ ]] && (( (8#$mode & 0022) == 0 )) \
                    || cr_die "Installation parent must be root-owned and not group/other writable: $parent."
            fi
            [[ $parent != / ]] || break
            parent=${parent%/*}; [[ -n $parent ]] || parent=/
        done
    done
}
# Validate dedicated path types/ownership, while permitting prior installations
# and incomplete attempts. Never walk DATA recursively or follow an unknown leaf
# symlink. Shared parent directories retain their existing permissions.
cr_check_leaf() {
    local path=$1 kind=$2 owner mode metadata service_uid=0
    cr_check_parent_dirs "$path"
    [[ ! -L $path ]] || cr_die "Refusing an unknown installation symlink: $path."
    [[ -e $path ]] || return 0
    metadata=$(stat -Lc '%u %a' -- "$path") || cr_die "Cannot inspect $path."
    read -r owner mode <<< "$metadata"
    [[ $mode =~ ^[0-7]{3,4}$ ]] && (( (8#$mode & 0022) == 0 )) || cr_die "Dedicated path is group/other writable: $path."
    case $kind in
        file) [[ -f $path && $owner == 0 ]] || cr_die "Dedicated file is not a root-owned regular file: $path." ;;
        private) [[ -f $path && $owner == 0 ]] && (( (8#$mode & 0077) == 0 )) || cr_die "Private export/token is not root-only: $path." ;;
        rootdir) [[ -d $path && $owner == 0 ]] || cr_die "Dedicated directory is not root-owned: $path." ;;
        statedir)
            service_uid=$(id -u "$SERVICE" 2>/dev/null || printf 0)
            [[ -d $path && ( $owner == 0 || $owner == "$service_uid" ) ]] || cr_die "Dedicated state/runtime directory has an unrelated owner: $path." ;;
    esac
}
cr_port_inodes() {
    local sockets=(/proc/net/tcp /proc/net/udp) file
    for file in /proc/net/tcp6 /proc/net/udp6; do [[ ! -r $file ]] || sockets+=("$file"); done
    for file in "${sockets[@]}"; do [[ -r $file ]] || cr_die "Cannot inspect listening sockets: $file."; done
    awk 'FNR > 1 && $2 ~ /:01BB$/ && (FILENAME ~ /udp/ || $4 == "0A") {print $10}' "${sockets[@]}"
}
cr_pid_socket_inodes() {
    local pid=$1 fd target
    [[ -d /proc/$pid/fd && -r /proc/$pid/fd ]] || cr_die 'Cannot inspect the dedicated service socket ownership.'
    for fd in /proc/"$pid"/fd/*; do
        target=$(readlink -- "$fd" 2>/dev/null || true)
        if [[ $target =~ ^socket:\[([0-9]+)\]$ ]]; then printf '%s\n' "${BASH_REMATCH[1]}"; fi
    done
}
# The running dedicated unit may keep 443 during a long rebuild. Every occupied
# inode must belong to its actual MainPID; never stop or kill a different server.
cr_ports() {
    local occupied pid owned inode found item
    occupied=$(cr_port_inodes) || cr_die 'Cannot inspect listening sockets; port availability is unknown.'
    [[ -n $occupied ]] || return 0
    pid=$(systemctl show "$SERVICE" --property=MainPID --value) || cr_die 'Cannot inspect dedicated service MainPID.'
    [[ $pid =~ ^[0-9]+$ && $pid != 0 ]] || cr_die 'TCP or UDP 443 belongs to another process; no other service was stopped.'
    owned=$(cr_pid_socket_inodes "$pid") || cr_die 'Cannot establish service socket ownership.'
    while IFS= read -r inode; do
        [[ $inode =~ ^[0-9]+$ ]] || cr_die 'Invalid kernel socket record.'
        found=0
        while IFS= read -r item; do [[ $inode != "$item" ]] || found=1; done <<< "$owned"
        (( found )) || cr_die 'TCP or UDP 443 belongs to another process; no other service was stopped.'
    done <<< "$occupied"
}
# After stopping the dedicated unit, no listener is acceptable, including one
# still attributed to its old MainPID. This also closes the replacement race.
cr_ports_free() {
    local occupied
    occupied=$(cr_port_inodes) || cr_die 'Cannot inspect listening sockets after stopping the service.'
    [[ -z $occupied ]] || cr_die 'TCP or UDP 443 is still occupied; no files will be switched/start attempted while another listener remains.'
}
# Compatibility name retained for existing usage/tests; this is now a safe
# installation preflight, not an existence-based fresh-install gate.
cr_fresh() {
    local path dropin entry
    cr_check_account
    for path in "$ETC" "${PROFILE%/*}" "$TOOLS" "$TOOLS/backups" "$WWW"; do cr_check_leaf "$path" rootdir; done
    for path in "$DATA" "$RUNTIME"; do cr_check_leaf "$path" statedir; done
    for path in "$BIN" "$UNIT" "$CONFIG" "$SYSCTL"; do cr_check_leaf "$path" file; done
    for path in "$TOKEN_FILE" "$PROFILE" "$CLIENT_CONFIG"; do cr_check_leaf "$path" private; done
    for dropin in "$UNIT.d" "/run/systemd/system/$SERVICE.service.d" "/usr/lib/systemd/system/$SERVICE.service.d" "/lib/systemd/system/$SERVICE.service.d"; do
        cr_check_leaf "$dropin" rootdir
        [[ -d $dropin ]] || continue
        while IFS= read -r entry; do cr_check_leaf "$entry" file; done < <(find -P "$dropin" -mindepth 1 -maxdepth 1 -print)
    done
    cr_ports
}
# Downloads and redirects must remain HTTPS with normal certificate checking.
# Ignore .curlrc so local defaults cannot disable TLS verification or add requests.
# --disable must be curl's first argument, including for the readiness request.
# Retry transient failures, but bound connection setup and each transfer attempt.
cr_download() {
    curl --disable --proto '=https' --proto-redir '=https' --tlsv1.2 --fail --show-error --location \
        --retry 3 --connect-timeout 20 --max-time 900 --output "$2" "$1"
}
# Validate the metadata format before comparing the downloaded file's SHA-256.
# A checksum mismatch stops execution before extraction or use of the artifact.
cr_verify() {
    local actual
    [[ $2 =~ ^[a-f0-9]{64}$ ]] || cr_die 'Invalid checksum metadata.'
    actual=$(sha256sum -- "$1"); actual=${actual%% *}
    [[ $actual == "$2" ]] || cr_die 'Download checksum mismatch; refusing to use the artifact.'
}
# Consume file contents from stdin, create exclusively under a private umask,
# then grant only the requested access. Parent directories must already exist.
# Service-readable configuration uses its group; secret exports stay root-only.
cr_new_file() {
    local path=$1 mode=$2 group=${3:-root}
    [[ ! -e $path && ! -L $path ]] || cr_die "Refusing to replace $path."
    # noclobber also prevents following an existing symlink or truncating a file.
    (set -o noclobber; umask 077; cat > "$path")
    chmod "$mode" "$path"
    chown root:"$group" "$path"
}
# Restore only the dedicated files recorded before the switch. ACME state and
# website content never enter this transaction and are never removed/restored.
# Backups remain root-only outside scratch space after both success and failure.
cr_rollback() {
    local failed=0 index=0 path existed type prior
    if ! systemctl stop "$SERVICE" >/dev/null 2>&1; then
        # A missing/previously incomplete unit may legitimately have nothing to
        # stop. A still-active process is an actual rollback failure.
        if systemctl is-active --quiet "$SERVICE"; then failed=1; fi
    fi
    while IFS=$'\t' read -r index existed type path; do
        if [[ $type == dir ]]; then
            [[ ! -e $path ]] || rm -rf -- "$path" || failed=1
            if [[ $existed == 1 ]]; then cp -a -- "$backup_dir/files/$index" "$path" || failed=1; fi
        elif [[ $existed == 1 ]]; then
            prior=$(mktemp "${path%/*}/.${path##*/}.restore.XXXXXXXX") || { failed=1; continue; }
            if cp -a -- "$backup_dir/files/$index" "$prior" && mv -fT -- "$prior" "$path"; then :; else
                rm -f -- "$prior"; failed=1
            fi
        else
            rm -f -- "$path" || failed=1
        fi
    done < "$backup_dir/manifest"
    systemctl daemon-reload || failed=1
    # Remove candidate enablement first. In particular, restoring an originally
    # runtime-only enable must not leave the candidate's persistent wants link.
    if ! systemctl disable "$SERVICE" >/dev/null 2>&1; then
        if systemctl is-enabled --quiet "$SERVICE"; then failed=1; fi
    fi
    case $was_enabled in
        enabled) systemctl enable "$SERVICE" >/dev/null 2>&1 || failed=1 ;;
        enabled-runtime) systemctl enable --runtime "$SERVICE" >/dev/null 2>&1 || failed=1 ;;
    esac
    if (( was_active )); then
        if [[ -x $BIN && -f $CONFIG ]]; then
            systemctl start "$SERVICE" || failed=1
        else
            printf 'Warning: the previous deployment was already missing binary/config/unit files; its disk baseline was restored but it cannot be restarted.\n' >&2
            failed=1
        fi
    fi
    (( failed == 0 ))
}
cr_cleanup() {
    local status=$?
    trap - EXIT
    if (( transaction_started )); then
        if cr_rollback; then
            printf 'The candidate failed; dedicated files and prior active/enabled state were restored.\n' >&2
        else
            printf 'Rollback was incomplete; inspect private backup %s and journalctl -u %s.\n' "$backup_dir" "$SERVICE" >&2
        fi
        (( status != 0 )) || status=1
    fi
    if [[ -n $work ]] && ! rm -rf -- "$work"; then
        printf 'Warning: could not remove private scratch directory %s.\n' "$work" >&2
        (( status != 0 )) || status=1
    fi
    if (( status )); then printf 'Deployment incomplete (exit %s). Private backup: %s\n' "$status" "${backup_dir:-not needed before file replacement}" >&2; fi
    exit "$status"
}
# Copy into a same-filesystem temporary file, then rename. Replacing the pathname
# never truncates the executable inode still in use by the previous process.
cr_atomic_install() {
    local source=$1 destination=$2 mode=$3 group=${4:-root} temporary
    cr_check_parent_dirs "$destination"
    [[ ! -L $destination ]] || cr_die "Refusing installation symlink: $destination."
    temporary=$(mktemp "${destination%/*}/.${destination##*/}.install.XXXXXXXX")
    if install -o root -g "$group" -m "$mode" -- "$source" "$temporary" && mv -fT -- "$temporary" "$destination"; then :; else
        rm -f -- "$temporary"
        cr_die "Atomic installation failed: $destination."
    fi
}
cr_backup() {
    local path index=0 existed type canonical seen=$'\n'
    was_active=0
    if systemctl is-active --quiet "$SERVICE"; then was_active=1; fi
    was_enabled=$(systemctl is-enabled "$SERVICE" 2>/dev/null || true)
    was_enabled=${was_enabled:-disabled}
    cr_check_leaf "$TOOLS/backups" rootdir
    install -d -o root -g root -m 700 "$TOOLS/backups"
    backup_dir=$(mktemp -d "$TOOLS/backups/deployment-$(date -u +%Y%m%d-%H%M%S).XXXXXXXX")
    install -d -m 700 "$backup_dir/files"
    : > "$backup_dir/manifest"
    local paths=("$BIN" "$CONFIG" "$TOKEN_FILE" "$UNIT" "$PROFILE" "$CLIENT_CONFIG" "$SYSCTL"
        "$UNIT.d" "/run/systemd/system/$SERVICE.service.d" "/usr/lib/systemd/system/$SERVICE.service.d" "/lib/systemd/system/$SERVICE.service.d")
    for path in "${paths[@]}"; do
        canonical=$(readlink -m -- "$path")
        [[ $seen != *$'\n'"$canonical"$'\n'* ]] || continue
        seen+="$canonical"$'\n'
        type=file; [[ $path != *.service.d ]] || type=dir
        existed=0
        if [[ -e $path ]]; then existed=1; cp -a -- "$path" "$backup_dir/files/$index"; fi
        printf '%s\t%s\t%s\t%s\n' "$index" "$existed" "$type" "$path" >> "$backup_dir/manifest"
        index=$((index + 1))
    done
    printf 'active=%s\nenabled=%s\n' "$was_active" "$was_enabled" > "$backup_dir/service-state"
    printf 'Private deployment backup: %s\n' "$backup_dir"
    transaction_started=1
}
# Inspect adjacent module/replacement records in `go version -m` output. Merely
# finding a module name is insufficient: the binary must use its patched source.
cr_check_replacement() {
    local info=$1 module=$2 replacement=$3
    awk -F '\t' -v module="$module" -v replacement="$replacement" '
        ($2 == "dep" || $2 == "mod") && $3 == module { pending=1; next }
        pending { if ($2 == "=>" && $3 == replacement) found=1; pending=0 }
        END { exit !found }
    ' <<< "$info"
}
# Build in a disposable source snapshot. Never edit the checkout's module files
# or transport forks while adding the pinned Cloudflare provider to the build.
cr_build() {
    local jobs=$1 version expected modules info module
    mkdir "$work/source"
    tar -C "$REPO" --exclude=.git --exclude=target --exclude=__pycache__ --exclude=.venv \
        --exclude='relay-servers-*' -cf - . | tar -C "$work/source" -xf -
    # Use the repository's exact Go release and the official archive metadata.
    # Require one archive matching both the release and native Linux architecture.
    version=$(sed -n 's/^toolchain \(go[0-9][0-9.]*\)$/\1/p' "$work/source/go.mod")
    [[ $version =~ ^go[0-9]+[.][0-9]+[.][0-9]+$ ]] || cr_die 'go.mod must pin a release Go toolchain.'
    cr_download 'https://go.dev/dl/?mode=json&include=all' "$work/go-releases.json"
    expected=$(jq -er --arg version "$version" --arg arch "$arch" \
        '[.[] | select(.version == $version) | .files[] | select(.os == "linux" and .arch == $arch and .kind == "archive" and .filename == ($version + ".linux-" + $arch + ".tar.gz"))] | if length == 1 then .[0].sha256 else error("No unique Go archive") end' "$work/go-releases.json")
    cr_download "https://dl.google.com/go/$version.linux-$arch.tar.gz" "$work/go.tar.gz"
    cr_verify "$work/go.tar.gz" "$expected"
    tar --no-same-owner -C "$work" -xzf "$work/go.tar.gz"
    # Pin the same reviewed DNS plugin release and commit as the repository builder.
    # No inherited checkout hook or template may run before commit verification.
    GIT_TERMINAL_PROMPT=0 git -c core.hooksPath=/dev/null clone --template= --depth 1 --branch "$PLUGIN_TAG" --single-branch \
        https://github.com/caddy-dns/cloudflare.git "$work/cloudflare-src"
    [[ $(git -C "$work/cloudflare-src" rev-parse --verify HEAD) == "$PLUGIN_COMMIT" ]] || cr_die 'Cloudflare plugin commit does not match the reviewed release.'
    [[ -f $work/cloudflare-src/go.mod ]] || cr_die 'Incomplete Cloudflare plugin source.'
    # Ignore inherited Go configuration/workspaces and forbid automatic toolchain
    # switching. Disable CGO for a self-contained binary; choose baseline CPU
    # features so it does not accidentally require the build host's extensions.
    # These public modules need no inherited auth/cache executables or checksum
    # exemptions. Pin HTTPS module sources and keep checksum verification on.
    unset GOOS GOARCH GOFLAGS GOWORK GOROOT GOENV GOEXPERIMENT GOFIPS140
    unset GOCACHEPROG GOINSECURE GONOSUMDB GOPRIVATE GONOPROXY
    export GOTOOLCHAIN=local GOWORK=off GOENV=off GOFLAGS='' GOOS=linux GOARCH=$arch CGO_ENABLED=0
    export GO111MODULE=on GOAUTH=off GOPROXY=https://proxy.golang.org,direct GOSUMDB=sum.golang.org
    # Do not trust a partially removed installation's caches or an inherited
    # module-cache path. All compiled/downloaded material for this run is private.
    export GOAMD64=v1 GOARM64=v8.0 GOPATH=$work/gopath GOMODCACHE=$work/gopath/pkg/mod GOCACHE=$work/gocache
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
        # A local replacement binds the provider import to the verified checkout.
        # Alternate module files isolate dependency resolution from go.mod/go.sum.
        "$go" mod edit -modfile "$mod" -replace github.com/caddy-dns/cloudflare=../cloudflare-src
        "$go" get -modfile "$mod" github.com/caddy-dns/cloudflare@"$PLUGIN_TAG"
        # Preserve the project's patched HTTP/2 and QUIC transports. Upstream
        # substitutions could compile successfully while changing relay behavior.
        "$go" mod edit -modfile "$mod" -json | jq -e '
            any(.Replace[]; .Old.Path == "golang.org/x/net" and .New.Path == "./third_party/x-net") and
            any(.Replace[]; .Old.Path == "github.com/quic-go/quic-go" and .New.Path == "./third_party/quic-go") and
            any(.Replace[]; .Old.Path == "github.com/caddy-dns/cloudflare" and .New.Path == "../cloudflare-src")' >/dev/null
        # Dependency resolution is complete: building may no longer edit it.
        # Keep the repository's compatibility tag and limit build parallelism.
        "$go" build -modfile "$mod" -mod=readonly -tags http2legacy -trimpath -p "$jobs" -o "$work/$SERVICE" ./cmd/caddy
    )
    # Check the resulting executable, not just the requested build options:
    # required Caddy modules, source replacements, architecture and CGO status.
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
# Emit only configuration text; the caller supplies the validated domain/hash
# and writes it with service-readable, root-owned permissions. DNS-01 needs no
# port 80 listener, and disabling persistence avoids autosaved admin-API configs.
# The catch-all site is necessary because CONNECT's authority names the target,
# while the TLS SNI and certificate name identify this relay's domain.
#
# Escape the dollar sign in the heredoc: Caddy, not this shell, expands the
# CREDENTIALS_DIRECTORY environment placeholder. The provider then resolves the
# file placeholder to the systemd-delivered token. The token is not in this text.
cr_config_text() {
    cat <<EOF
# Managed by install-caddy-network-relay-native-build-cloudflare-dns.sh
{
    auto_https disable_redirects
    persist_config off
    admin $ADMIN_ADDRESS
}
# Catch-all :443 is required for CONNECT requests naming destination hosts.
$domain, :443 {
    tls {
        dns cloudflare {file.{\$CREDENTIALS_DIRECTORY}/CF_API_TOKEN}
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
# Generate a dedicated unit from the shared template without editing that file.
# Keep its notification type, descriptor limit and transport environment while
# replacing its generic Caddy paths/account and adding the following sandbox:
#
# - LoadCredential copies the root-only token for this service before applying
#   its filesystem restrictions. Hide the original source, not /run/credentials.
#   Remove any raw token inherited through the manager's environment as well.
# - StateDirectory and RuntimeDirectory provide private writable exceptions to
#   ProtectSystem=strict. Certificate/ACME state survives service restarts.
#   PrivateTmp also provides writable temporary storage inside the sandbox.
# - Run as the dedicated user with only CAP_NET_BIND_SERVICE for TCP/UDP 443.
#   NoNewPrivileges blocks privilege gains through later executable launches.
# - Isolate temporary files, devices and IPC; protect host/kernel control paths,
#   hide other users' processes and restrict namespace and identity changes.
# - Keep Internet/Unix sockets and AF_NETLINK for actual relay networking. Do not
#   hide /proc/meminfo: the application uses it for its memory-budget defaults.
# - Deny selected dangerous syscall groups without a broad allowlist that could
#   break Go networking. Native syscall architecture excludes alternate ABIs.
# - The CGO-disabled Go binary needs no JIT or external helpers. Restrict both
#   writable executable mappings and executable paths; hide build tools, client
#   exports and the raw token source from the runtime filesystem view.
# These limits reduce access after a compromise; the process still needs its
# delivered DNS credential and TLS keys to issue and renew certificates.
cr_unit_text() {
    # Adapt the repository's unit without changing the shared deployment template.
    # https://caddyserver.com/docs/running
    # https://caddyserver.com/docs/api
    # https://www.freedesktop.org/software/systemd/man/systemd.exec.html
    # Preserve networking and /proc/meminfo for relay traffic and memory budgets.
    # The CGO-disabled binary needs no external executables or writable code.
    awk -v service="$SERVICE" -v binary="$BIN" -v config="$CONFIG" \
        -v token="$TOKEN_FILE" -v data="$DATA" -v unit="$UNIT" -v admin="$ADMIN_ADDRESS" \
        -v private="${PROFILE%/*}" -v tools="$TOOLS" '
        /^# Installed by / {
            print "# Installed by install-caddy-network-relay-native-build-cloudflare-dns.sh as " unit "."
            next
        }
        /^(ProtectSystem|PrivateTmp|AmbientCapabilities|Restart|RestartSec|StartLimitIntervalSec)=/ { next }
        /^\[Unit\]$/ { print; print "StartLimitIntervalSec=0"; next }
        /^User=/ { print "User=" service; next }
        /^Group=/ { print "Group=" service; next }
        /^ExecStart=/ { print "ExecStart=" binary " run --config " config " --adapter caddyfile"; next }
        /^ExecReload=/ { print "ExecReload=" binary " reload --address " admin " --config " config " --adapter caddyfile --force"; next }
        { print }
        /^\[Service\]$/ {
            print "Restart=on-failure"
            print "RestartSec=5s"
            print "LoadCredential=CF_API_TOKEN:" token
            print "UnsetEnvironment=CF_API_TOKEN"
            print "Environment=HOME=" data
            print "Environment=XDG_DATA_HOME=" data "/.local/share"
            print "Environment=XDG_CONFIG_HOME=" data "/.config"
            print "RuntimeDirectory=" service
            print "RuntimeDirectoryMode=0700"
            print "StateDirectory=" service
            print "StateDirectoryMode=0700"
            print "UMask=0077"
            print "LimitCORE=0"
            print "NoNewPrivileges=yes"
            print "CapabilityBoundingSet=CAP_NET_BIND_SERVICE"
            print "AmbientCapabilities=CAP_NET_BIND_SERVICE"
            print "ProtectSystem=strict"
            print "ProtectHome=yes"
            print "PrivateTmp=yes"
            print "PrivateDevices=yes"
            print "PrivateIPC=yes"
            print "ProtectKernelTunables=yes"
            print "ProtectKernelModules=yes"
            print "ProtectKernelLogs=yes"
            print "ProtectControlGroups=yes"
            print "ProtectClock=yes"
            print "ProtectHostname=yes"
            print "ProtectProc=invisible"
            print "RestrictNamespaces=yes"
            print "RestrictRealtime=yes"
            print "RestrictSUIDSGID=yes"
            print "LockPersonality=yes"
            print "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK"
            print "SystemCallArchitectures=native"
            print "MemoryDenyWriteExecute=yes"
            print "SystemCallFilter=~@mount @reboot @swap @raw-io @debug @cpu-emulation @obsolete memfd_create"
            print "InaccessiblePaths=-" token " -" private " -" tools " -/dev/shm"
            print "NoExecPaths=/"
            print "ExecPaths=" binary
        }
    ' "$REPO/deploy/caddy.service"
}
# Build an argument array so bundled paths and domain values remain individual
# arguments. Exclude the relay's own domain to avoid routing it back to itself.
# The Apple profile uses bundled selected-domain rules, not a new user prompt.
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
# A previous dedicated identity is expected during upgrades and repairs. Empty
# orphaned dedicated groups may be reused; unrelated/shared identities are not.
cr_account() {
    cr_check_account
    if ! id -u "$SERVICE" >/dev/null 2>&1; then
        if getent group "$SERVICE" >/dev/null; then
            useradd --system --gid "$SERVICE" --no-create-home --home-dir "$DATA" --shell /usr/sbin/nologin "$SERVICE"
        else
            useradd --system --user-group --no-create-home --home-dir "$DATA" --shell /usr/sbin/nologin "$SERVICE"
        fi
    fi
    cr_check_account
}
# Export the same domain/user/password used by the server and Apple profile.
# This TOML supports the Rust GUI importer and headless client. SOCKS listens
# on loopback only, so importing it does not expose an unauthenticated LAN proxy.
# It does not import the Apple profile's selected-domain rules; applications
# choose which connections to send through this local SOCKS listener.
# The caller creates the file only after protocol checks pass, with mode 0600.
cr_client_config_text() {
    # Validated domain/user and the base64 password alphabet are TOML-safe.
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
# Generate exactly 22 ASCII characters using OpenSSL's cryptographic RNG. The
# alphabet is safe in Basic authentication, XML and a quoted TOML string, with
# no quotes, backslashes, whitespace or colon requiring separate escaping.
# Reject incomplete/malformed RNG output and propagate OpenSSL failures. Check
# character classes after truncation; a symbol in the discarded suffix does not
# count. Resampling avoids a predictable mandatory prefix or suffix.
cr_generate_password() {
    local candidate
    while :; do
        # 18 random bytes produce 24 base64 characters without padding. Take
        # 22 independent characters and resample until all four classes occur.
        candidate=$(openssl rand -base64 18) || return
        [[ $candidate =~ ^[A-Za-z0-9+/]{24}$ ]] || cr_die 'OpenSSL returned invalid password material.'
        candidate=${candidate:0:22}
        if [[ $candidate =~ [A-Z] && $candidate =~ [a-z] && $candidate =~ [0-9] && $candidate =~ [+/] ]]; then
            printf '%s\n' "$candidate"
            return
        fi
    done
}
# Recover only this installer's simple root-only TOML export, never by source
# or eval. The current script remains authoritative for every server/unit file;
# an old Caddyfile, missing file or stale password hash cannot block repair.
# Rehashing the same recovered password keeps existing clients working while
# deliberately regenerating the server configuration from the current template.
cr_recover_credentials() {
    local old_domain old_user old_password
    [[ -f $CLIENT_CONFIG ]] || return 1
    old_domain=$(sed -n 's|^uri_template = "https://\([^/]*\)/.well-known/masque/udp/{target_host}/{target_port}/"$|\1|p' "$CLIENT_CONFIG")
    old_user=$(sed -n 's/^username = "\([A-Za-z0-9_-][A-Za-z0-9_.-]*\)"$/\1/p' "$CLIENT_CONFIG")
    old_password=$(sed -n 's/^password = "\([A-Za-z0-9+/]*\)"$/\1/p' "$CLIENT_CONFIG")
    [[ $old_domain == "$domain" && $old_user == "$device_user" && ${#old_password} == 22 ]] || return 1
    [[ $old_password =~ [A-Z] && $old_password =~ [a-z] && $old_password =~ [0-9] && $old_password =~ [+/] ]] || return 1
    relay_password=$old_password
    credentials_reused=1
}
# Inspect CertMagic's normal storage layout before building or replacing files.
# A valid certificate is left exactly where Caddy expects it, with its existing
# JSON metadata and ACME account. No renew/revoke/delete command is issued here.
# Caddy loads this cache on startup and renews normally only when due. A corrupt,
# expired or wrong-name/key certificate is not declared reusable; Caddy handles
# issuance/renewal itself using DNS-01. External Certbot storage is not imported
# because guessing issuer metadata could disrupt Caddy's automatic renewals.
cr_certificate_valid() {
    local certificate=$1 key=$2 metadata=${1%.crt}.json certificate_key private_key
    [[ -f $certificate && -f $key && -f $metadata && ! -L $certificate && ! -L $key && ! -L $metadata ]] || return 1
    # CertMagic LoadCertResource also loads SiteMeta; crt/key alone are not a
    # reusable cache entry. Never invent or repair issuer metadata by guessing.
    jq -e 'type == "object"' "$metadata" >/dev/null 2>&1 || return 1
    openssl x509 -in "$certificate" -noout -checkend 0 >/dev/null 2>&1 || return 1
    openssl x509 -in "$certificate" -noout -checkhost "$domain" >/dev/null 2>&1 || return 1
    openssl verify -purpose sslserver -verify_hostname "$domain" -untrusted "$certificate" "$certificate" >/dev/null 2>&1 || return 1
    certificate_key=$(openssl x509 -in "$certificate" -noout -pubkey 2>/dev/null | openssl pkey -pubin -outform DER 2>/dev/null | sha256sum) || return 1
    # Never prompt for an encrypted key: Caddy's cached keys are unencrypted.
    private_key=$(openssl pkey -in "$key" -passin pass: -pubout -outform DER 2>/dev/null | sha256sum) || return 1
    [[ $certificate_key == "$private_key" ]]
}
cr_check_existing_certificate() {
    local store=$DATA/.local/share/caddy/certificates issuer certificate key resolved data_resolved
    certificate_available=0
    existing_certificate=
    [[ -d $store && ! -L $store ]] || { printf 'No reusable Caddy certificate cache found for %s; Caddy will manage DNS-01 issuance.\n' "$domain"; return 0; }
    data_resolved=$(readlink -f -- "$DATA") || cr_die 'Cannot resolve dedicated certificate state.'
    # With no email/CA override, Caddy 2.11's default issuer is Let's Encrypt.
    # A staging/custom issuer entry does not establish reusable state for this
    # script-generated automation policy (DefaultIssuers adds ZeroSSL only with
    # an email address). Keep certificate detection consistent with that policy.
    for issuer in acme-v02.api.letsencrypt.org-directory; do
        certificate=$store/$issuer/$domain/$domain.crt
        key=${certificate%.crt}.key
        [[ -f $certificate ]] || continue
        resolved=$(readlink -f -- "$certificate" 2>/dev/null || true)
        [[ $resolved == "$data_resolved/"* ]] || continue
        if cr_certificate_valid "$certificate" "$key"; then
            certificate_available=1
            existing_certificate=$certificate
            printf 'Valid retained certificate cache found for %s; Caddy can reuse it and renew normally when due.\n' "$domain"
            return 0
        fi
    done
    printf 'No complete, currently valid default-issuer cache found for %s; Caddy will manage DNS-01 issuance/renewal.\n' "$domain"
}
# Candidate validation happens before replacing any installed executable,
# Caddyfile, token or unit. A read-only namespace bind makes only the candidate
# binary/config reachable through root-only build parents; token and exports are
# not included. systemd copies the token with LoadCredential as it does at boot.
cr_prepare() {
    local candidate=$work/candidate validation_root=/run/$SERVICE-candidate
    install -d -o root -g "$SERVICE" -m 750 "$candidate"
    install -d -m 700 "$work/exports"
    install -o root -g root -m 755 "$work/$SERVICE" "$candidate/$SERVICE"
    printf '%s' "$cf_token" > "$work/token"
    chmod 600 "$work/token"
    unset cf_token
    credentials_reused=0
    if cr_recover_credentials; then
        printf 'Reusing the existing private client password; server files will follow the current script.\n'
    else
        relay_password=$(cr_generate_password)
        printf 'A new 22-character relay password was generated; update old clients using the refreshed exports.\n'
    fi
    account=$(printf '%s\n' "$relay_password" | "$work/$SERVICE" network-relay passwd --name "$device_user" --stdin)
    [[ $account =~ ^user[[:space:]]$device_user[[:space:]]\$[A-Za-z0-9\$=,+/._-]+$ ]] || cr_die 'Unexpected password hash output.'
    cr_config_text > "$candidate/Caddyfile"
    chmod 640 "$candidate/Caddyfile"
    chown root:"$SERVICE" "$candidate/Caddyfile"
    cr_unit_text > "$work/unit"
    chmod 644 "$work/unit"
    # Generate client files privately, without changing current exports. They are
    # published atomically only after the new service's real protocol checks pass.
    (
        local PROFILE=$work/exports/device.mobileconfig
        cr_profile_args
        printf '%s\n' "$relay_password" | "$work/$SERVICE" "${profile_args[@]}"
    )
    cr_client_config_text > "$work/exports/network-relay-rs-client.toml"
    chmod 600 "$work/exports/"*
    # systemd-run resolves its first executable in the host namespace, before
    # BindReadOnlyPaths exists. Start the host's env, which execs the candidate
    # inside the unit namespace; --wait still propagates validation failures.
    systemd-run --no-ask-password --unit="$SERVICE-validate" --collect --wait --pipe --service-type=exec \
        --property="User=$SERVICE" --property="Group=$SERVICE" \
        --property="LoadCredential=CF_API_TOKEN:$work/token" --property=UMask=0077 \
        --property="RuntimeDirectory=$SERVICE-validate" --property=RuntimeDirectoryMode=0700 \
        --property="BindReadOnlyPaths=$candidate:$validation_root" \
        --setenv="HOME=/run/$SERVICE-validate" --setenv="XDG_DATA_HOME=/run/$SERVICE-validate/share" \
        --setenv="XDG_CONFIG_HOME=/run/$SERVICE-validate/config" \
        /usr/bin/env -- "$validation_root/$SERVICE" validate --config "$validation_root/Caddyfile" --adapter caddyfile
}
# Upgrade and repair transaction. Existing Caddy runs throughout the build and
# candidate validation. Only after both succeed are dedicated files backed up,
# atomically switched, and the unit restarted. Any later failure restores the
# previous files plus active/enabled state. DATA and website content stay in place.
cr_deploy() {
    local relay_password account key current response ready=0 attempt path existed type index
    cr_fresh
    cr_account
    install -d -o root -g "$SERVICE" -m 750 "$ETC"
    install -d -o root -g root -m 700 "${PROFILE%/*}"
    if [[ ! -e $DATA ]]; then install -d -o "$SERVICE" -g "$SERVICE" -m 700 "$DATA"; fi
    [[ -d ${WWW%/*} ]] || install -d -m 755 "${WWW%/*}"
    if [[ ! -e $WWW ]]; then install -d -m 755 "$WWW"; fi
    # Only initialize an empty web directory. Existing files, including custom
    # index pages and non-index websites, are preserved exactly as supplied.
    if [[ -z $(find -P "$WWW" -mindepth 1 -maxdepth 1 -print -quit) ]]; then
        printf '<!doctype html>\n<title>Welcome</title>\n<h1>Welcome</h1>\n' | cr_new_file "$WWW/index.html" 644
    fi
    cr_prepare
    cr_ports
    # Record sysctl content before switching; preserve larger runtime ceilings.
    {
        printf '# UDP buffer limits for Caddy network relay.\n'
        for key in net.core.rmem_max net.core.wmem_max; do
            current=$(sysctl -n "$key")
            [[ $current =~ ^[0-9]+$ ]] || cr_die 'Cannot read UDP buffer limits.'
            (( current >= 8388608 )) || current=8388608
            printf '%s = %s\n' "$key" "$current"
        done
    } > "$work/sysctl"
    cr_backup
    # Stop with the previous unit's exact ExecStop semantics. Only after its
    # process releases 443 may its unit/drop-ins and executable be replaced.
    if ! systemctl stop "$SERVICE"; then
        # A genuinely new/missing unit has nothing to stop (systemctl returns
        # exit 5). Do not mistake that normal repair state for a failure.
        if systemctl is-active --quiet "$SERVICE"; then cr_die 'Could not stop the previous dedicated service.'; fi
    fi
    cr_ports_free
    # Remove only dedicated drop-ins, keeping their complete private copies.
    # Generic caddy.service and any of its settings are outside this transaction.
    while IFS=$'\t' read -r index existed type path; do
        if [[ $type == dir && -d $path ]]; then rm -rf -- "$path"; fi
    done < "$backup_dir/manifest"
    cr_atomic_install "$work/$SERVICE" "$BIN" 755
    cr_atomic_install "$work/candidate/Caddyfile" "$CONFIG" 640 "$SERVICE"
    cr_atomic_install "$work/token" "$TOKEN_FILE" 600
    cr_atomic_install "$work/unit" "$UNIT" 644
    cr_atomic_install "$work/sysctl" "$SYSCTL" 644
    systemctl daemon-reload
    # Recheck immediately before starting; never terminate an unrelated process
    # that happened to bind the newly released relay port during replacement.
    cr_ports_free
    systemctl enable "$SERVICE"
    systemctl start "$SERVICE"
    printf 'Waiting for DNS challenge and trusted HTTPS (up to about eight minutes)...\n'
    for ((attempt=0; attempt<60; attempt++)); do
        systemctl is-active --quiet "$SERVICE" || cr_die "$SERVICE stopped; restoring the previous deployment."
        # A custom website may return 404 or have no index. Successful trusted
        # TLS is the readiness condition, not a hard-coded page or HTTP status.
        if curl --disable --noproxy '*' --silent --show-error --output /dev/null --max-time 3 \
            --resolve "$domain:443:127.0.0.1" "https://$domain/" 2>/dev/null; then ready=1; break; fi
        sleep 5
    done
    (( ready )) || cr_die 'Certificate/HTTPS readiness failed; restoring the previous deployment.'
    if ! printf '%s\n' "$relay_password" | "$BIN" network-relay check --server "$domain" --address 127.0.0.1 \
        --user "$device_user" --password-stdin; then
        cr_die 'Protocol checks failed; restoring the previous deployment.'
    fi
    cr_atomic_install "$work/exports/device.mobileconfig" "$PROFILE" 600
    cr_atomic_install "$work/exports/network-relay-rs-client.toml" "$CLIENT_CONFIG" 600
    # A zero exit from enable is not enough: require the persistent "enabled"
    # state, not static, indirect or enabled-runtime, and a currently live unit.
    [[ $(systemctl is-enabled "$SERVICE") == enabled ]] || cr_die 'Persistent boot enablement was not established; restoring the previous deployment.'
    systemctl is-active --quiet "$SERVICE" || cr_die 'The new service is not active; restoring the previous deployment.'
    unset relay_password
    transaction_started=0
    sysctl -p "$SYSCTL" || printf 'Warning: UDP buffer tuning was denied; using system defaults.\n'
    printf 'All built-in TCP/UDP checks passed. Verify external access on a real device.\n'
    printf 'Apple profile: %s; Rust client TOML: %s (both root-only, mode 600).\n' "$PROFILE" "$CLIENT_CONFIG"
    printf 'Caddy renews certificates automatically. Keep %s and %s.\n' "$TOKEN_FILE" "$DATA"
    printf 'Private backup retained at %s. Reload: systemctl reload %s\n' "$backup_dir" "$SERVICE"
}
# Token syntax must match the pinned provider. Some provider errors include the
# rejected input, so reject malformed tokens here with a value-free diagnostic.
# Valid syntax does not prove that the token has access to the requested zone.
cr_token_valid() {
    # Match the pinned plugin before it can print rejected input in an error.
    [[ $1 =~ ^[A-Za-z0-9_-]{35,50}$ || $1 =~ ^cf(ut|at)_[A-Za-z0-9_-]{32,256}$ ]]
}
# These are the only interactive inputs. An inherited CF_API_TOKEN may supply
# the token without prompting; otherwise read it silently from the terminal.
# Normalize hostname case and a trailing DNS dot before validating it.
cr_inputs() {
    cr_ask 'Relay domain'; domain=${REPLY,,}; domain=${domain%.}
    cr_domain "$domain" || cr_die 'Invalid DNS hostname; omit scheme, port and wildcard.'
    printf 'Use a zone-scoped Cloudflare token with Zone:DNS:Edit and Zone:Zone:Read.\n'
    if [[ -z $cf_token ]]; then
        read -r -s -p 'CF_API_TOKEN (hidden): ' cf_token </dev/tty || cr_die 'Could not read token.'
        printf '\n'
    fi
    cr_token_valid "$cf_token" || cr_die 'Expected a Cloudflare API Token.'
}
# Prevent apt, Git or later helpers from adding questions after the two inputs.
cr_noninteractive() {
    # Only the domain/token prompts may read from the terminal. All subsequent
    # commands get EOF unless explicitly fed a generated secret through a pipe.
    exec </dev/null
    export GIT_TERMINAL_PROMPT=0 GIT_ASKPASS=/bin/false SSH_ASKPASS=/bin/false
    export DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a APT_LISTCHANGES_FRONTEND=none
}
# systemd 249 is the feature baseline for the selected credential/sandbox
# settings. Check the actual manager tool version rather than the OS label.
cr_require_systemd() {
    local version
    version=$(systemctl --version | awk 'NR == 1 { print $2 }')
    [[ $version =~ ^[0-9]+$ ]] && (( 10#$version >= 249 )) \
        || cr_die 'systemd 249+ is required for private credentials and service hardening.'
}
# Sequence matters: check dedicated path/account safety before input, then
# finish the build and candidate validation before switching the running unit.
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
    # Remove the exported token name before subsequent deployment commands. The
    # dynamically scoped shell-local copy is available to cr_inputs/cr_deploy,
    # not their environment.
    local cf_token=${CF_API_TOKEN:-} jobs path free_kib
    unset CF_API_TOKEN
    export -n cf_token
    cr_require_systemd
    umask 077
    command -v flock >/dev/null || cr_die 'flock from util-linux is required.'
    # Serialize installers before inspecting shared paths. The lock descriptor
    # remains open until process exit; its private directory persists harmlessly.
    install -d -m 700 "/run/$SERVICE-install"
    exec {install_lock}>"/run/$SERVICE-install/lock"
    flock -n "$install_lock" || cr_die 'Another installer is running.'
    cr_fresh
    cr_inputs
    cr_noninteractive
    # Fixed choices satisfy the two-input contract and bound build parallelism.
    device_user=iphone
    scope=selected
    jobs=1
    printf 'Defaults: user iphone, one build job, bundled selected-domain profile.\n'
    printf 'Set DNS-only A/AAAA records to this server; open TCP/UDP 443 in the provider firewall.\n'
    printf 'Installing Caddy with Cloudflare DNS-01 and automatic certificate renewal.\n'
    # The local patched transports, command entry point, unit and domain lists
    # are mandatory. This installer cannot work as a standalone downloaded file.
    local required=(go.mod go.sum cmd/caddy/main.go third_party/quic-go/go.mod third_party/x-net/go.mod
        deploy/caddy.service deploy/domains/google-ai-social.txt deploy/domains/global-services.txt)
    for path in "${required[@]}"; do [[ -f $REPO/$path ]] || cr_die "Complete checkout required; missing $path."; done
    free_kib=$(df -Pk /opt | awk 'NR==2 {print $4}')
    [[ $free_kib =~ ^[0-9]+$ ]] && (( free_kib >= 5*1024*1024 )) || cr_die 'At least 5 GiB free under /opt is required.'
    # Bound apt lock waits, retry downloads and retain existing local conffiles.
    # Install only build/deployment prerequisites; no firewall package is added.
    local apt=(apt-get -o DPkg::Lock::Timeout=1800 -o Acquire::Retries=3
        -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold)
    DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a APT_LISTCHANGES_FRONTEND=none "${apt[@]}" update
    DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a APT_LISTCHANGES_FRONTEND=none "${apt[@]}" install -y --no-install-recommends ca-certificates curl git jq openssl iproute2
    cr_check_existing_certificate
    install -d -m 700 "$TOOLS"
    work=$(mktemp -d "$TOOLS/build.XXXXXXXX")
    # Install traps only after this run owns a unique scratch directory. Signal
    # exits retain their conventional codes and pass through the same cleanup.
    trap cr_cleanup EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM
    cr_build "$jobs"
    cr_deploy
}

# Sourcing exposes helpers for isolated tests without installing anything.
# Executing directly enables strict error/undefined-variable/pipeline handling.
# Clear CDPATH for later directory changes; C locale stabilizes parsing and the
# ASCII character-class checks used for domains, passwords and metadata.
if [[ ${BASH_SOURCE[0]} == "$0" ]]; then
    set -Eeuo pipefail
    unset CDPATH
    export LC_ALL=C
    cr_main "$@"
fi
