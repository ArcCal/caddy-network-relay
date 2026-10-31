#!/usr/bin/env bash
# Interactive native Caddy relay build with the Cloudflare DNS plugin and ACME.
# Debian 12+ / Ubuntu 24.04+, amd64/arm64, Bash 4+, systemd; install/upgrade/repair.
# Direct client access uses TCP/UDP 443; DNS-01 has no A/AAAA target prerequisite.
# Token: Zone:DNS:Edit + Zone:Zone:Read, scoped to the relay's zone.
# No Certbot: Caddy obtains and renews certificates using its DNS plugin.
#
# Maintainer contract: requirements and deployment lessons
# ========================================================
# Keep these notes when maintaining this installer. They distinguish observed
# failures, required behavior and remaining verification limits.
#
# Required behavior
# -----------------
# - Keep a clearly named executable Bash installer in the repository root.
#   Modify this installer, not application code or shared source templates.
#   Read repository design/deployment documentation before making changes.
# - Support Debian 12+ and Ubuntu 24.04+ without an artificial upper version cap.
#   Detect native amd64/arm64 and build the corresponding pinned server.
# - Accept only the domain and hidden CF_API_TOKEN as terminal input. An inherited
#   token can skip its prompt; on reruns an empty answer reuses the checked
#   root-only token source. Do not ask for email, username, build jobs, profile
#   scope, password or confirmation. Keep apt/Git/helper commands noninteractive.
# - Use Cloudflare DNS-01. It validates TXT records and requires appropriate
#   zone-scoped token permissions, not an A/AAAA record pointing at this machine.
#   Do not add a public-IP lookup or DNS-to-host IP equality prerequisite.
# - Support install, upgrade and repair on every run. The current script governs
#   dedicated configuration/unit files; validate and automatically replace them.
#   Reuse a safe dedicated account and create it only when absent. Existing files,
#   directories or accounts are not errors by themselves. Keep genuine conflicts
#   (unsafe shared identities/parents, foreign listeners) distinct from existence.
# - Retain valid managed certificates, matching keys, issuer metadata and ACME
#   accounts. Do not force issuance just because the installer runs again.
#   Missing/invalid certificates need issuance; renewal when due stays enabled.
#   Never delete certificate state merely to make an installation look new.
# - Use a cryptographically random 22-character password with uppercase, lowercase,
#   digits and + or /. Reuse a compatible private client record when possible.
#   Keep server, Apple profile and Rust Network Relay RS TOML credentials aligned.
#   If plaintext credentials are unrecoverable, generate new ones and explain
#   that old clients need the refreshed configuration. Export both files privately.
# - Run the daemon as its dedicated non-root user with restricted groups and only
#   necessary capabilities. Protect DNS tokens, TLS keys, client exports and
#   backups; keep secrets out of argv/logs and outside the public web directory.
#   Preserve certificate renewal/reload and required TCP/UDP traffic.
# - Do not install UFW or another firewall, add firewall rules, or configure VPN
#   tunnel pools/NAT as a side effect of installing this application relay.
# - Persist binaries, configuration, credentials and certificate state. Reserve
#   /run for systemd-recreated transient data. Require active service state,
#   persistent enabled state and successful HTTPS/protocol checks before success.
#   Retain automatic restart and certificate renewal across host reboots.
# - Build and validate the candidate while the prior service remains running.
#   Back up dedicated files privately; stop only the old dedicated unit, verify
#   443 is free, and install atomically. On failure restore files and the prior
#   active/enabled state, including runtime-only enablement. Preserve ACME state
#   and unrelated services. Backups cannot recover files deleted before the run.
#
# Earlier failures and remedies
# -----------------------------
# 1. Fresh-only checks rejected each existing file, directory and account, forcing
#    manual deletion and risking certificate loss. Inspect/reuse safe resources
#    and replace managed files transactionally; support interrupted installs.
# 2. systemd-run tried to execute /run/<service>-candidate/<binary> before its
#    BindReadOnlyPaths namespace existed. It resolves the first executable in the
#    HOST namespace. Use the host's /usr/bin/env -- entry point to exec the mapped
#    candidate inside the unit, retaining --wait to propagate failures. Never
#    expose the root-only work tree to work around a namespace/permission error.
# 3. The old mock mapped paths before checking the host executable and hid that
#    real ARM deployment failure. Test host lookup, then namespace execution,
#    argument/credential preservation and nonzero exits; reproduce the real CLI
#    behavior where possible. A passing mock alone is not deployment evidence.
# 4. Stopping a missing old unit may return exit 5 during a first/partial install.
#    Continue only if it is inactive and 443 is free. Treat a live listener/failed
#    stop as a genuine problem. Stop with the OLD unit before replacing drop-ins
#    or unit content; never terminate another service to steal its port.
# 5. A long hexadecimal password did not meet the requested length/classes. It
#    was not insecure merely for being hexadecimal. The application fast-hash
#    mode requires 24+ characters, so the requested 22-character password uses the
#    supported Argon2id stdin mode. Never expose plaintext in command arguments.
# 6. Earlier firewall handling and generic paths did not match the deployment
#    requirements. Keep firewall management out, and use dedicated binary/config/
#    account/state names instead of altering a general-purpose installation.
# 7. Hardening must fit the actual process: check filesystem needs, credential
#    copy timing, dynamic libraries and reload helpers. Do not grant broad write
#    access or extra privileges simply to silence a sandbox failure.
#
# Lesson from an external installer's DNS gate
# --------------------------------------------
# An external script refused installation unless the DNS-only A record matched
# one detected public IPv4. That is inappropriate as a Cloudflare DNS-01 issuance
# prerequisite: the CA checks _acme-challenge TXT records, not that IP endpoint.
# A/AAAA may point elsewhere or be absent. IPv6-only DNS, multiple records, NAT,
# multiple NICs and VPN/proxy egress also make one IPv4 comparison unreliable.
# Its log alone does not prove the detected IP was wrong; DNS may truly point
# elsewhere. Do not reproduce that issuance gate. Cloudflare proxy/grey-cloud
# routing choices are also separate from TXT-based domain authorization.
#
# Verification limits and maintenance improvements
# ------------------------------------------------
# - A certificate proves domain authorization, not public routing or client
#   connectivity. Current HTTPS/relay checks connect to 127.0.0.1 with real
#   hostname/SNI and bypass public DNS. Report their local scope accurately;
#   do not turn this observation into a new A/AAAA installation prerequisite.
# - Current built-in test targets are example.com:80 and 1.1.1.1:53. Restricted
#   egress or no IPv4 route may fail them while other destinations work. Diagnose
#   target reachability before blaming DNS/certificates or changing server policy.
# - Distinguish config validation, active/enabled state, offline unit checks,
#   mocks and actual end-to-end/reboot tests. Never claim a real reboot, public
#   ACME flow or a deployment on every OS version without actually testing it.
#   Keep regressions for reruns, partial repair, certificate reuse, canonical
#   replacement, boot paths, secrets and failed-switch restoration.
# - journalctl -f waits for new entries; Ctrl+C exits the viewer. Missing old
#   units, skipped recent storage cleaning and renewal-information messages are
#   not by themselves deployment failures. Several available certificate chains
#   do not mean several separate certificate requests.
#
# Caddy-specific requirements
# ---------------------------
# Build with pinned caddy-dns/cloudflare and repository transport patches.
# Use /usr/local/bin/caddy-network-relay, /etc/caddy-network-relay and persistent
# /var/lib/caddy-network-relay ACME state. Load the token via systemd credentials;
# keep the Unix admin socket private under /run/caddy-network-relay.
# Managed certificate reuse needs the valid CRT/key and CertMagic JSON for the
# configured issuer. Do not fabricate metadata or silently treat arbitrary
# external PEMs as that cache. Preserve Caddy's normal automatic renewal.
# The permanent CGO-disabled unit permits only its own executable; the env
# wrapper belongs only to the separate transient validation unit.
# The plugin clone runs concurrently with the Go toolchain download. Caddy, not
# this script, performs ACME at startup, and the Caddyfile needs the built
# binary's password hash, so issuance/configuration cannot overlap the build.
# Takeover includes old dedicated-unit processes and manually started instances.
# Identify standalone servers by executable and run/config arguments, not by a
# truncated process name. Send TERM, then KILL after a bounded grace period,
# before replacing files. Do not signal general-purpose Caddy or other servers.
# If another program owns any TCP/UDP 443 socket, exit before takeover and report
# both protocols with listener addresses and available executable/PID details.
# Rollback restores the previous managed unit, not terminated standalone commands.
# Root-owned unit masks and stale runtime units are repairable entries, not
# arbitrary destination links. Keep their private backups and restore the exact
# old active/enabled state on failure. A matching executable basename alone is
# not proof that a standalone process belongs to this deployment.
#
# Run this file from a complete checkout on the target server. It performs:
#   1. Read-only platform, safe-path/account and port checks, then two inputs.
#   2. Noninteractive package installation and a verified native Go build.
#   3. Candidate preparation/validation while the previous service keeps running.
#   4. Root-only backup, atomic file replacement and service/protocol checks.
#   5. Export of the Rust client configuration with the same relay credentials.
# Client exports are staged before startup and published after checks pass.
# Rerunning also repairs missing dedicated files and upgrades
# an existing dedicated installation. General-purpose Caddy is never changed.
#
# Tracing must be disabled before reading secrets, including when invoked with
# bash -x or bash -v. Neither tokens nor generated passwords belong in logs.
set +x
set +v
set +a
# Bash can retain an exported outer value beneath a non-exported local. Remove
# inherited export attributes before introducing secret-bearing local scopes.
export -n cf_token relay_password account candidate old_password

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
clone_job=

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
self-checks. Client exports are staged privately and published after checks pass.
Requires Debian 12+ or Ubuntu 24.04+, systemd 249+ and 5 GiB of free disk.

Only two prompts: relay domain and hidden CF_API_TOKEN (Enter on a rerun keeps
the saved token; CF_API_TOKEN may also be inherited from the environment).
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
DNS-01 needs no A/AAAA records or IP match. Direct domain-based clients need
DNS-only records routing to this server. Open TCP/UDP 443 in the provider firewall.
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
# The final label may be an IDNA A-label TLD (xn--...); an all-letter-only
# rule wrongly rejected valid punycode TLDs. An all-numeric label stays invalid.
cr_domain() {
    local value=$1
    (( ${#value} <= 253 )) && [[ $value =~ ^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?[.])+([a-z]{2,63}|xn--[a-z0-9]([a-z0-9-]{0,57}[a-z0-9])?)$ ]]
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
    if [[ -L $path && ( $path == "$UNIT" || $path == "/run/systemd/system/$SERVICE.service" ) &&
        $(readlink -- "$path") == /dev/null && $(stat -c %u -- "$path") == 0 ]]; then
        return 0
    fi
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
cr_port_records() {
    local sockets=(/proc/net/tcp /proc/net/udp) file
    for file in /proc/net/tcp6 /proc/net/udp6; do [[ ! -r $file ]] || sockets+=("$file"); done
    for file in "${sockets[@]}"; do [[ -r $file ]] || cr_die "Cannot inspect listening sockets: $file."; done
    awk 'FNR > 1 && $2 ~ /:01BB$/ && (FILENAME ~ /udp/ || $4 == "0A") {
        printf "%s\t%s\t%s\n", (FILENAME ~ /udp/ ? "UDP" : "TCP"), $2, $10
    }' "${sockets[@]}"
}
cr_port_inodes() {
    cr_port_records | awk -F '\t' '{print $3}'
}
# Convert Linux's little-endian socket-table addresses for diagnostics when ss
# is unavailable. Supported amd64/arm64 hosts use this kernel representation.
cr_endpoint_text() {
    local address=${1%:*} reordered= part index result=
    if [[ $address =~ ^[a-fA-F0-9]{8}$ ]]; then
        printf '%d.%d.%d.%d:443' "0x${address:6:2}" "0x${address:4:2}" "0x${address:2:2}" "0x${address:0:2}"
    elif [[ $address =~ ^[a-fA-F0-9]{32}$ ]]; then
        for ((index=0; index<32; index+=8)); do
            part=${address:index:8}
            reordered+=${part:6:2}${part:4:2}${part:2:2}${part:0:2}
        done
        for ((index=0; index<32; index+=4)); do
            [[ -z $result ]] || result+=:
            result+=${reordered:index:4}
        done
        printf '[%s]:443' "$result"
    else
        printf '%s' "$1"
    fi
}
# Fallback ownership lookup is read-only. Report executable/PID rather than
# full command lines, which could contain secrets from an old manual launch.
cr_socket_owners() {
    local inode=$1 link pid executable name seen=$'\n' found=0
    [[ $inode =~ ^[0-9]+$ ]] || return 1
    while IFS= read -r link; do
        pid=${link#/proc/}; pid=${pid%%/*}
        [[ $pid =~ ^[0-9]+$ && $seen != *$'\n'"$pid"$'\n'* ]] || continue
        seen+="$pid"$'\n'
        executable=$(readlink -- "/proc/$pid/exe" 2>/dev/null || printf unavailable)
        name=$(cat "/proc/$pid/comm" 2>/dev/null || printf unavailable)
        printf '    PID=%s process=%q executable=%q\n' "$pid" "$name" "$executable" >&2
        found=1
    done < <(find -P /proc/[0-9]*/fd -maxdepth 1 -type l -lname "socket:\[$inode\]" -print 2>/dev/null)
    (( found )) || printf '    Owner unavailable in this PID namespace (socket inode %s).\n' "$inode" >&2
}
# Every conflict prints both protocols, even if only one is occupied. ss gives
# readable listener addresses and PID/process details; /proc remains a fallback
# on a minimal host before iproute2 is installed. Never install/stop anything
# merely to produce these diagnostics.
cr_report_ports() {
    local records protocol item address inode output reported
    records=$(cr_port_records) || return 1
    for protocol in TCP UDP; do
        printf '%s 443:\n' "$protocol" >&2
        reported=0
        if command -v ss >/dev/null 2>&1; then
            if [[ $protocol == TCP ]]; then
                output=$(ss -H -ltnp '( sport = :443 )' 2>/dev/null) || output=
            else
                output=$(ss -H -aunp '( sport = :443 )' 2>/dev/null) || output=
            fi
            # ss can print control bytes from a process's untrusted comm name.
            # Escape terminal controls without wrapping or exposing argv.
            if [[ -n $output ]]; then printf '%s\n' "$output" | LC_ALL=C sed -n 'l 0' >&2; reported=1; fi
        fi
        if (( !reported )); then
            while IFS=$'\t' read -r item address inode; do
                [[ $item == "$protocol" ]] || continue
                printf '  local=%s\n' "$(cr_endpoint_text "$address")" >&2
                cr_socket_owners "$inode"
                reported=1
            done <<< "$records"
            if (( !reported )); then printf '  Not occupied.\n' >&2; fi
        fi
    done
}
cr_pid_socket_inodes() {
    local pid=$1 fd target
    [[ -d /proc/$pid/fd && -r /proc/$pid/fd ]] || cr_die 'Cannot inspect the dedicated service socket ownership.'
    for fd in /proc/"$pid"/fd/*; do
        target=$(readlink -- "$fd" 2>/dev/null || true)
        if [[ $target =~ ^socket:\[([0-9]+)\]$ ]]; then printf '%s\n' "${BASH_REMATCH[1]}"; fi
    done
}
# Unit aliases can resolve a dedicated name to an unrelated active service.
# Return 0 only for the exact canonical unit, 1 for an absent/inactive alias
# that can be replaced safely, and 2 for a live or unidentified foreign unit.
cr_unit_identity() {
    local identity state
    identity=$(systemctl show "$SERVICE" --property=Id --value 2>/dev/null || true)
    [[ $identity != "$SERVICE.service" ]] || return 0
    state=$(systemctl show "$SERVICE" --property=ActiveState --value 2>/dev/null || true)
    if systemctl is-active --quiet "$SERVICE" ||
        [[ -n $identity && $state != inactive && $state != failed ]]; then
        printf 'Refusing takeover: %s resolves to foreign/unidentified unit %q (state %q).\n' "$SERVICE" "$identity" "$state" >&2
        return 2
    fi
    return 1
}
cr_unit_main_pid() {
    local pid identity_status=0
    cr_unit_identity || identity_status=$?
    (( identity_status != 2 )) || return 2
    (( identity_status == 0 )) || return 0
    pid=$(systemctl show "$SERVICE" --property=MainPID --value 2>/dev/null || true)
    if [[ $pid =~ ^[1-9][0-9]*$ && $pid != 1 && $pid != "$$" && $pid != "$BASHPID" ]]; then
        printf '%s\n' "$pid"
    fi
}
# A manually launched old server may have no unit or MainPID. Linux comm names
# are truncated, so pkill by process name is insufficient and risks unrelated
# processes. Inspect the actual executable (including unlinked old binaries)
# and NUL-delimited argv. A generic caddy binary qualifies only when its run
# command explicitly uses this deployment's exact configuration path.
cr_is_relay_pid() {
    local pid=$1 executable argument index configurations=0 selected=
    local -a arguments=()
    [[ $pid =~ ^[1-9][0-9]*$ && $pid != 1 && $pid != "$$" && $pid != "$BASHPID" ]] || return 1
    executable=$(readlink -- "/proc/$pid/exe" 2>/dev/null) || return 1
    executable=${executable% (deleted)}
    {
        while IFS= read -r -d '' argument; do arguments+=("$argument"); done < "/proc/$pid/cmdline"
    } 2>/dev/null || return 1
    [[ ${arguments[1]:-} == run ]] || return 1
    # A copied same-name executable can be an unrelated workload. Require the
    # installed path (or generic Caddy) AND the exact managed configuration.
    [[ $executable == "$BIN" || ${executable##*/} == caddy ]] || return 1
    for ((index=2; index<${#arguments[@]}; index++)); do
        # Cobra accepts repeated config flags (last value wins); --resume
        # ignores that file. Ambiguous or terminated option parsing is never
        # positive ownership evidence for signalling a standalone process.
        case ${arguments[index]} in
            --resume|--resume=*|--|-r|-r=*) return 1 ;;
            --config=*) configurations=$((configurations + 1)); selected=${arguments[index]#--config=} ;;
            --config|-c)
                index=$((index + 1))
                (( index < ${#arguments[@]} )) || return 1
                configurations=$((configurations + 1)); selected=${arguments[index]} ;;
            --adapter|--envfile|--pidfile|--pingback|-a)
                # Skip values as values, even when one resembles --config.
                index=$((index + 1)); (( index < ${#arguments[@]} )) || return 1 ;;
            --adapter=*|--envfile=*|--pidfile=*|--pingback=*|--environ|--environ=*|--watch|--watch=*|-e|-w) ;;
            *) return 1 ;;
        esac
    done
    [[ $configurations == 1 && $selected == "$CONFIG" ]]
}
cr_old_pids() {
    local unit_pid pid directory
    unit_pid=$(cr_unit_main_pid) || return
    if [[ -n $unit_pid && -d /proc/$unit_pid ]]; then printf '%s\n' "$unit_pid"; fi
    for directory in /proc/[0-9]*; do
        pid=${directory##*/}
        [[ $pid != "$unit_pid" ]] || continue
        if cr_is_relay_pid "$pid"; then printf '%s\n' "$pid"; fi
    done
}
# Existing dedicated-unit and standalone relay instances may retain 443 during
# compilation. Every occupied socket must belong to one of these old instances;
# an unrelated listener is a conflict and is never terminated by takeover.
cr_ports() {
    local occupied pids pid owned sockets inode found item foreign=0
    occupied=$(cr_port_inodes) || cr_die 'Cannot inspect listening sockets; port availability is unknown.'
    [[ -n $occupied ]] || return 0
    pids=$(cr_old_pids) || cr_die 'Cannot establish the old relay process identities.'
    owned=
    while IFS= read -r pid; do
        [[ -n $pid ]] || continue
        # A process may exit between the socket-table snapshot and this read.
        if sockets=$(cr_pid_socket_inodes "$pid" 2>/dev/null); then owned+="$sockets"$'\n'; fi
    done <<< "$pids"
    while IFS= read -r inode; do
        [[ $inode =~ ^[0-9]+$ ]] || cr_die 'Invalid kernel socket record.'
        found=0
        while IFS= read -r item; do [[ $inode != "$item" ]] || found=1; done <<< "$owned"
        (( found )) || foreign=1
    done <<< "$occupied"
    if (( foreign )); then
        cr_report_ports || true
        cr_die 'TCP or UDP 443 belongs to another program; takeover was cancelled without stopping it.'
    fi
}
# Recheck identity before every signal, especially after waiting, to reduce the
# risk of signalling another process that reused an exited server's numeric PID.
# Signal only the dedicated unit or positively identified standalone instances.
cr_signal_old() {
    local signal=$1 pids pid unit_pid
    pids=$(cr_old_pids) || return
    while IFS= read -r pid; do
        [[ -n $pid ]] || continue
        unit_pid=$(cr_unit_main_pid) || return
        if [[ $pid == "$unit_pid" ]] || cr_is_relay_pid "$pid"; then
            if kill -s "$signal" -- "$pid" 2>/dev/null; then
                printf 'Sent %s to previous %s process %s.\n' "$signal" "$SERVICE" "$pid"
            fi
        fi
    done <<< "$pids"
}
cr_wait_old_stopped() {
    local attempts=$1 attempt state remaining
    for ((attempt=0; attempt<attempts; attempt++)); do
        remaining=$(cr_old_pids) || return 1
        state=$(systemctl show "$SERVICE" --property=ActiveState --value 2>/dev/null || true)
        if [[ -z $remaining && ( -z $state || $state == inactive || $state == failed ) ]] \
            && ! systemctl is-active --quiet "$SERVICE"; then return 0; fi
        sleep 1
    done
    return 1
}
# Queue the stop without waiting indefinitely for an old unit's ExecStop or
# TimeoutStopSec. The stop job suppresses its Restart policy. Gracefully stop
# residual standalone servers too; force remaining unit members/processes only
# after ten seconds. This runs after candidate validation and private backup.
cr_stop_old() {
    local canonical=0 identity_status=0
    if cr_unit_identity; then canonical=1; else identity_status=$?; fi
    (( identity_status != 2 )) || return 1
    if (( canonical )); then systemctl stop --no-block "$SERVICE" >/dev/null 2>&1 || true; fi
    cr_signal_old TERM || return
    if ! cr_wait_old_stopped 10; then
        if (( canonical )); then
            cr_unit_identity || return 1
            systemctl kill --kill-who=all --signal=KILL "$SERVICE" >/dev/null 2>&1 || true
        fi
        cr_signal_old KILL || return
        if (( canonical )); then
            cr_unit_identity || return 1
            systemctl stop --no-block "$SERVICE" >/dev/null 2>&1 || true
        fi
        if ! cr_wait_old_stopped 5; then
            printf 'Could not stop all previous %s processes.\n' "$SERVICE" >&2
            return 1
        fi
    fi
}
# After stopping the dedicated unit, no listener is acceptable, including one
# still attributed to its old MainPID. Recheck before switching/starting; a later
# bind failure is handled by the deployment rollback.
cr_ports_free() {
    local occupied
    occupied=$(cr_port_inodes) || cr_die 'Cannot inspect listening sockets after stopping the service.'
    if [[ -n $occupied ]]; then
        cr_report_ports || true
        cr_die 'TCP or UDP 443 is still occupied; no files will be switched/start attempted while another listener remains.'
    fi
}
# Compatibility name retained for existing usage/tests; this is now a safe
# installation preflight, not an existence-based fresh-install gate.
cr_fresh() {
    local path dropin entry identity_status=0
    cr_unit_identity || identity_status=$?
    (( identity_status != 2 )) || cr_die 'An unrelated active service owns the dedicated unit alias; it was not stopped.'
    cr_check_account
    for path in "$ETC" "${PROFILE%/*}" "$TOOLS" "$TOOLS/backups" "$WWW"; do cr_check_leaf "$path" rootdir; done
    for path in "$DATA" "$RUNTIME"; do cr_check_leaf "$path" statedir; done
    for path in "$BIN" "$UNIT" "$CONFIG" "$SYSCTL"; do cr_check_leaf "$path" file; done
    cr_check_leaf "/run/systemd/system/$SERVICE.service" file
    for path in "/etc/systemd/system/multi-user.target.wants/$SERVICE.service" "/run/systemd/system/multi-user.target.wants/$SERVICE.service"; do
        cr_check_parent_dirs "$path"
        if [[ -L $path ]]; then
            [[ $(stat -c %u -- "$path") == 0 ]] || cr_die 'Dedicated enablement link is not root-owned.'
        else
            cr_check_leaf "$path" file
        fi
    done
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
    if ! cr_stop_old; then failed=1; fi
    # Disable the candidate BEFORE restoring saved masks/runtime links. Both
    # enablement namespaces must be cleared without following link targets.
    if cr_unit_identity; then
        systemctl disable "$SERVICE" >/dev/null 2>&1 || true
        systemctl disable --runtime "$SERVICE" >/dev/null 2>&1 || true
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
    # Restoring recorded entry paths retains runtime-only enablement and masks.
    # A successful systemctl command alone does not establish recovered state.
    prior=$(systemctl is-enabled "$SERVICE" 2>/dev/null || true)
    prior=${prior:-disabled}
    [[ $prior == "$was_enabled" ]] || failed=1
    if (( was_active )); then
        if [[ -x $BIN && -f $CONFIG ]]; then
            # An absent old unit file may expose a vendor alias after restore.
            # Never start that target merely because the old unit was active.
            if cr_unit_identity; then
                systemctl start "$SERVICE" || failed=1
                systemctl is-active --quiet "$SERVICE" || failed=1
            else
                failed=1
            fi
        else
            printf 'Warning: the previous deployment was already missing binary/config/unit files; its disk baseline was restored but it cannot be restarted.\n' >&2
            failed=1
        fi
    elif systemctl is-active --quiet "$SERVICE"; then
        failed=1
    fi
    (( failed == 0 ))
}
cr_cleanup() {
    local status=$?
    trap - EXIT
    # Do not delete scratch space under a still-running plugin clone.
    if [[ -n $clone_job ]]; then wait "$clone_job" 2>/dev/null || true; fi
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
        "/run/systemd/system/$SERVICE.service"
        "/etc/systemd/system/multi-user.target.wants/$SERVICE.service"
        "/run/systemd/system/multi-user.target.wants/$SERVICE.service"
        "$UNIT.d" "/run/systemd/system/$SERVICE.service.d" "/usr/lib/systemd/system/$SERVICE.service.d" "/lib/systemd/system/$SERVICE.service.d")
    for path in "${paths[@]}"; do
        # Deduplicate aliased parent directories (/lib -> /usr/lib), not leaf
        # links: two masks or enablement links must each be saved as entries.
        canonical=$(readlink -m -- "${path%/*}")/${path##*/}
        [[ $seen != *$'\n'"$canonical"$'\n'* ]] || continue
        seen+="$canonical"$'\n'
        type=file; [[ $path != *.service.d ]] || type=dir
        existed=0
        if [[ -e $path || -L $path ]]; then existed=1; cp -a -- "$path" "$backup_dir/files/$index"; fi
        printf '%s\t%s\t%s\t%s\n' "$index" "$existed" "$type" "$path" >> "$backup_dir/manifest"
        index=$((index + 1))
    done
    printf 'active=%s\nenabled=%s\n' "$was_active" "$was_enabled" > "$backup_dir/service-state"
    printf 'Private deployment backup: %s\n' "$backup_dir"
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
# Pin the same reviewed DNS plugin release and commit as the repository builder.
# No inherited checkout hook or template may run before commit verification.
# This runs as a background job whose exit status the build waits for.
cr_clone_plugin() {
    GIT_TERMINAL_PROMPT=0 git -c core.hooksPath=/dev/null clone --template= --depth 1 --branch "$PLUGIN_TAG" --single-branch \
        https://github.com/caddy-dns/cloudflare.git "$work/cloudflare-src" > "$work/plugin-clone.log" 2>&1 </dev/null
}
# Build in a disposable source snapshot. Never edit the checkout's module files
# or transport forks while adding the pinned Cloudflare provider to the build.
cr_build() {
    local jobs=$1 version expected modules info module
    local -a snapshot_excludes=(--exclude=.git --exclude=target --exclude=__pycache__ --exclude=.venv --exclude='relay-servers-*')
    # This also covers later authenticated protocol checks: x/net's inherited
    # http2debug logs header values, including the Basic proxy credential.
    unset GODEBUG
    # GOTMPDIR alone does not control Go's module-root test or Git/helper
    # scratch files. Ignore inherited locations and keep both private.
    mkdir -m 700 "$work/tmp"
    export TMPDIR=$work/tmp GOTMPDIR=$work/tmp
    mkdir "$work/source"
    # A complete checkout may itself be under TOOLS. Never copy this run's
    # growing source snapshot back into itself or exhaust the host's disk.
    if [[ $work == "${REPO%/}/"* ]]; then snapshot_excludes+=(--exclude="./${work#"${REPO%/}/"}"); fi
    tar -C "$REPO" "${snapshot_excludes[@]}" -cf - . | tar -C "$work/source" -xf -
    # The pinned plugin clone and the Go toolchain download are independent:
    # fetch both at once. Its commit is verified before anything uses it.
    cr_clone_plugin &
    clone_job=$!
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
    local clone_status=0
    wait "$clone_job" || clone_status=$?
    clone_job=
    cat -- "$work/plugin-clone.log"
    (( clone_status == 0 )) || cr_die 'Cloning the pinned Cloudflare DNS plugin failed.'
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
    # Caddy's writable HOME environment remains DATA for its certificate cache,
    # but SSH consults the NSS passwd home. nologin does not prevent SSH -N.
    # Move only this already-qualified identity to a root-controlled/absent
    # login home and lock passwords; no -m/-u or recursive ownership changes.
    cr_check_leaf /nonexistent rootdir
    if ! id -u "$SERVICE" >/dev/null 2>&1; then
        if getent group "$SERVICE" >/dev/null; then
            useradd --system --gid "$SERVICE" --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin "$SERVICE"
        else
            useradd --system --user-group --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin "$SERVICE"
        fi
    fi
    usermod --home /nonexistent --lock "$SERVICE"
    cr_check_account
    local entry home status
    entry=$(getent passwd "$SERVICE")
    home=${entry%:*}; home=${home##*:}
    [[ $home == /nonexistent ]] || cr_die 'Dedicated login home was not repaired.'
    status=$(passwd -S "$SERVICE")
    [[ $status == "$SERVICE L "* ]] || cr_die 'Dedicated login password is not locked.'
}
# Export the same domain/user/password used by the server and Apple profile.
# This TOML supports the Rust GUI importer and headless client. SOCKS listens
# on loopback only, so importing it does not expose an unauthenticated LAN proxy.
# It does not import the Apple profile's selected-domain rules; applications
# choose which connections to send through this local SOCKS listener.
# The caller publishes the installed file after protocol checks, with mode 0600.
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
    [[ $account =~ ^user[[:space:]]${device_user}[[:space:]]\$[A-Za-z0-9\$=,+/._-]+$ ]] || cr_die 'Unexpected password hash output.'
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
    local relay_password account key current response ready=0 attempt path existed type index identity_status=0
    # Also clear any export attribute inherited from a caller's same-name
    # environment variable; set +a prevents newly assigned secrets exporting.
    export -n relay_password account
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
    # Backup I/O can take time too. A snapshot alone is not a deployment
    # mutation: reject new conflicts without a rollback that stops the old unit.
    cr_ports
    cr_unit_identity || identity_status=$?
    (( identity_status != 2 )) || cr_die 'The unit alias changed during backup; no takeover was started.'
    transaction_started=1
    # Take over all old dedicated instances, including unmanaged/deleted binaries.
    # Do this only after the candidate is validated and the prior files saved.
    cr_stop_old || cr_die 'Previous relay processes could not be stopped; restoring the previous deployment.'
    cr_ports_free
    rm -f -- "/run/systemd/system/$SERVICE.service" \
        "/etc/systemd/system/multi-user.target.wants/$SERVICE.service" \
        "/run/systemd/system/multi-user.target.wants/$SERVICE.service"
    if [[ -L $UNIT ]]; then rm -f -- "$UNIT"; fi
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
# On reruns an empty answer keeps the retained root-only token source, which
# cr_fresh has already checked. Read it as data only; it is reinstalled as-is.
cr_saved_token() {
    [[ -f $TOKEN_FILE && ! -L $TOKEN_FILE ]] || return 1
    cr_check_leaf "$TOKEN_FILE" private
    # No helper variable: an inherited same-name export would reach children.
    # Accept only the single-line file this installer writes, as LoadCredential
    # would deliver any extra line to the DNS provider as part of the token.
    awk 'NR == 1 && /^[A-Za-z0-9_-]+$/ { token = $0 } END { if (NR == 1 && token != "") print token }' "$TOKEN_FILE"
}
cr_inputs() {
    cr_ask 'Relay domain'; domain=${REPLY,,}; domain=${domain%.}
    cr_domain "$domain" || cr_die 'Invalid DNS hostname; omit scheme, port and wildcard.'
    printf 'Use a zone-scoped Cloudflare token with Zone:DNS:Edit and Zone:Zone:Read.\n'
    if [[ -z $cf_token ]]; then
        if [[ -f $TOKEN_FILE && ! -L $TOKEN_FILE ]]; then
            read -r -s -p 'CF_API_TOKEN (hidden; Enter keeps the saved token): ' cf_token </dev/tty || cr_die 'Could not read token.'
        else
            read -r -s -p 'CF_API_TOKEN (hidden): ' cf_token </dev/tty || cr_die 'Could not read token.'
        fi
        printf '\n'
        if [[ -z $cf_token ]]; then
            cf_token=$(cr_saved_token) || cr_die 'No safe saved token exists; enter a Cloudflare API Token.'
        fi
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
# Do not follow a planted directory/lock symlink or truncate another hard link.
# This check happens before prompts and package/build subprocesses.
cr_acquire_lock() {
    local directory=/run/$SERVICE-install lock
    cr_check_parent_dirs "$directory"
    [[ ! -L $directory ]] || cr_die 'Installer lock directory must not be a symlink.'
    if [[ -e $directory ]]; then
        [[ -d $directory && $(stat -c '%u:%a' -- "$directory") == 0:700 ]] || cr_die 'Unsafe installer lock directory.'
    else
        mkdir -m 700 -- "$directory"
    fi
    lock=$directory/lock
    [[ ! -L $lock ]] || cr_die 'Installer lock must not be a symlink.'
    if [[ -e $lock ]]; then
        [[ -f $lock && $(stat -c '%u:%a:%h' -- "$lock") == 0:600:1 ]] || cr_die 'Unsafe installer lock file.'
    fi
    exec {install_lock}>>"$lock"
    flock -n "$install_lock" || cr_die 'Another installer is running.'
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
    cr_acquire_lock
    cr_fresh
    cr_inputs
    cr_noninteractive
    # Fixed choices satisfy the two-input contract and bound build parallelism.
    device_user=iphone
    scope=selected
    jobs=1
    printf 'Defaults: user iphone, one build job, bundled selected-domain profile.\n'
    printf 'DNS-01 needs no A/AAAA records. For direct domain-based clients, route DNS-only records here and allow TCP/UDP 443.\n'
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
