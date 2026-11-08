#!/usr/bin/env bash
# Build Network Relay servers for both Linux architectures from latest sources.
# Sourcing defines portable helper functions without inspecting or changing a host.

# BEGIN SHARED BUILD CHILD RUNNER

relay_build_group_active() {
    ps -A -o pgid= -o stat= | awk -v group="$1" '
        $1 == group && $2 !~ /^Z/ { active = 1 }
        END { exit !active }'
}

relay_build_terminal_group() {
    PYTHONDONTWRITEBYTECODE=1 python3 - "$1" <<'PY'
import os
import signal
import sys

signal.signal(signal.SIGTTOU, signal.SIG_IGN)
try:
    fd = os.open('/dev/tty', os.O_RDWR)
    try:
        if sys.argv[1] == 'get':
            print(os.tcgetpgrp(fd))
        else:
            os.tcsetpgrp(fd, int(sys.argv[1]))
    finally:
        os.close(fd)
except OSError:
    sys.exit(1)
PY
}

relay_stop_build_child() {
    local child=${1:-} group=${2:-} wait_cleanup=${3:-0} child_signal=${4-TERM} attempt
    [[ $child =~ ^[1-9][0-9]*$ ]] || return 0
    if [[ $group == "$child" ]]; then
        if [[ -n $child_signal ]]; then kill -"$child_signal" -- "-$group" 2>/dev/null || true; fi
        # A terminal reader can have stopped before foreground ownership moved.
        # Let it handle the pending signal and finish any installer rollback.
        kill -CONT -- "-$group" 2>/dev/null || true
        if (( wait_cleanup )); then
            # Installers may be restoring a live deployment. Do not kill their
            # rollback or delete their source while that cleanup is running.
            while relay_build_group_active "$group"; do sleep 0.1; done
            return 0
        fi
        for ((attempt = 0; attempt < 10; attempt++)); do
            relay_build_group_active "$group" || return 0
            sleep 0.1
        done
        kill -KILL -- "-$group" 2>/dev/null || true
    else
        if [[ -n $child_signal ]]; then kill -"$child_signal" "$child" 2>/dev/null || true; fi
        kill -CONT "$child" 2>/dev/null || true
    fi
}

relay_run_build_child() {
    local relay_child_pid='' relay_child_group='' relay_child_status=0 relay_child_interrupted=0
    local relay_child_monitor=0 relay_child_actual relay_child_int relay_child_term relay_child_hup relay_child_wait=0
    local relay_child_tty='' relay_child_parent_group relay_child_final_signal=TERM
    if [[ ${1:-} == --wait-for-cleanup ]]; then relay_child_wait=1; shift; fi
    [[ $# -gt 0 ]] || return 2
    if ! command -v ps >/dev/null || ! ps -A -o pgid= -o stat= >/dev/null 2>&1; then
        printf 'Build process cleanup requires ps (procps on Linux).\n' >&2
        return 125
    fi
    if { : </dev/tty; } 2>/dev/null; then
        if ! command -v python3 >/dev/null; then
            printf 'Interactive build process cleanup requires Python 3.\n' >&2
            return 125
        fi
        relay_child_tty=$(relay_build_terminal_group get) || return 125
        relay_child_parent_group=$(ps -o pgid= -p "$$") || return 125
        relay_child_parent_group=${relay_child_parent_group//[[:space:]]/}
        # A deliberately backgrounded build must not take the user's terminal.
        [[ $relay_child_tty == "$relay_child_parent_group" ]] || relay_child_tty=''
    fi
    relay_child_int=$(trap -p INT)
    relay_child_term=$(trap -p TERM)
    relay_child_hup=$(trap -p HUP)
    case $- in *m*) relay_child_monitor=1 ;; esac
    trap 'relay_child_interrupted=130; trap "" INT TERM HUP; relay_stop_build_child "$relay_child_pid" "$relay_child_group" "$relay_child_wait"' INT
    trap 'relay_child_interrupted=143; trap "" INT TERM HUP; relay_stop_build_child "$relay_child_pid" "$relay_child_group" "$relay_child_wait"' TERM
    trap 'relay_child_interrupted=129; trap "" INT TERM HUP; relay_stop_build_child "$relay_child_pid" "$relay_child_group" "$relay_child_wait"' HUP
    # Job control creates a group distinct from the caller. Disable it inside
    # the runner so cargo, rustc and their children stay in that owned group.
    set -m
    (
        set +m
        trap - EXIT INT TERM HUP
        "$@"
    ) &
    relay_child_pid=$! relay_child_group=$!
    (( relay_child_monitor )) || set +m
    relay_child_actual=$(ps -o pgid= -p "$relay_child_pid" 2>/dev/null) || relay_child_actual=''
    relay_child_actual=${relay_child_actual//[[:space:]]/}
    if [[ -n $relay_child_actual && $relay_child_actual != "$relay_child_pid" ]]; then
        # Never send a group signal unless this is the group we just created.
        relay_child_group=''
        relay_child_interrupted=125
        relay_stop_build_child "$relay_child_pid" ''
    fi
    if (( relay_child_interrupted )); then
        relay_stop_build_child "$relay_child_pid" "$relay_child_group" "$relay_child_wait"
    fi
    if [[ -n $relay_child_tty && -n $relay_child_group && $relay_child_interrupted == 0 ]]; then
        if ! relay_build_terminal_group "$relay_child_group" && relay_build_group_active "$relay_child_group"; then
            relay_child_interrupted=125
            relay_stop_build_child "$relay_child_pid" "$relay_child_group" "$relay_child_wait"
        fi
        kill -CONT -- "-$relay_child_group" 2>/dev/null || true
    fi
    if wait "$relay_child_pid"; then relay_child_status=0; else relay_child_status=$?; fi
    # A command can exit before a helper it spawned. Stop those helpers before
    # its caller removes sources/caches, and reap our direct child after signals.
    if (( relay_child_wait && !relay_child_interrupted )) &&
       [[ $relay_child_status == 129 || $relay_child_status == 130 || $relay_child_status == 143 ]]; then
        # A terminal signal already reached the foreground group. Do not send
        # a second signal while a surviving installer is restoring deployment.
        relay_child_final_signal=''
    fi
    relay_stop_build_child "$relay_child_pid" "$relay_child_group" "$relay_child_wait" "$relay_child_final_signal"
    wait "$relay_child_pid" 2>/dev/null || true
    [[ -z $relay_child_tty ]] || relay_build_terminal_group "$relay_child_tty" || true
    trap - INT TERM HUP
    [[ -z $relay_child_int ]] || eval "$relay_child_int"
    [[ -z $relay_child_term ]] || eval "$relay_child_term"
    [[ -z $relay_child_hup ]] || eval "$relay_child_hup"
    if (( relay_child_interrupted )); then return "$relay_child_interrupted"; fi
    return "$relay_child_status"
}
# END SHARED BUILD CHILD RUNNER

lr_usage() {
    cat <<'HELP'
Usage: bash build-linux-servers-on-linux.sh [--repo DIR] [--output DIR] [--jobs N]
                                   [--install-deps | --no-install-deps] [--check]

Build both servers for BOTH Linux amd64 (x64) and arm64 on every run:
  ArcCal/network-relay: network-relay
  ArcCal/caddy-network-relay: caddy-network-relay, including Cloudflare DNS

Supported hosts: Debian 13 or Ubuntu 26.04, on x64 or arm64.
Rust binaries use static musl via Zig; Go uses CGO_ENABLED=0.
All four files are named SOFTWARE-linux-ARCH and inspected for architecture
and static linking. Native executables also run version/module smoke checks.
Parallelism is reduced to available RAM plus cgroup-usable free swap; below
1 GiB the build stops with guidance before downloading sources or toolchains.

  --repo DIR       legacy option, accepted but no longer used as build input.
                   Complete latest main sources always use a new
                   /tmp/YYYYMMDD-HHMMSS.RANDOM directory.
  --output DIR     new or empty artifact directory (default: ./relay-servers-*)
  --jobs N         Cargo and Go parallelism (default: 2)
  Dependencies    install missing build prerequisites automatically (default).
                   Uses root or sudo only when system packages are missing.
  --install-deps   also refresh/install the apt prerequisite package set
  --no-install-deps
                   require existing build tools and Rust targets; install none
  --check          inspect host/tools without network access or filesystem changes

The newest committed script handles each build. Local checkout files and
CADDY_NETWORK_RELAY_SRC are never used as build inputs. The Caddy
snapshot pins the freshly downloaded main commit. The Rust server uses a fresh
network-relay main clone; caddy-dns/cloudflare uses its pinned v0.2.4 release.
Fetched commits are fixed for this
run and recorded in MANIFEST.txt. Credentials must allow both private repos.
Optional NETWORK_RELAY_TOKEN / CADDY_NETWORK_RELAY_TOKEN provide read tokens.
Rust defaults to 1.99.1; Go defaults to go1.27.3+auto (honors module requirements).

Any failed source, build, verification or checksum step fails the run.
Successful runs retain four binaries, logs, MANIFEST.txt and SHA256SUMS;
source checkouts and compiler work/caches are removed on success, failure
and normal signals. Existing installed tools are reused without deletion.
Afterwards every artifact folder is mode 777.
Network steps are retried. Debian 13 keeps /tmp in memory; when it is too small,
compiler temporary files go to ~/.cache instead; source stays in /tmp. Free disk space is checked first.
No server installation or service configuration is performed.
HELP
}
# The reviewed caddy-dns/cloudflare release built into Caddy, and its commit.
LR_CLOUDFLARE_DNS_TAG=v0.2.4
LR_CLOUDFLARE_DNS_COMMIT=a8737d095ad5a48ca031cea6ab704057dbc2d250
lr_die() { printf 'build-linux-servers-on-linux: %s\n' "$*" >&2; exit 1; }
# Leave the source and artifact folders, and every folder below them, open to all users.
lr_open_dirs() {
    local dir
    for dir in "$@"; do
        [[ -n $dir && -d $dir && ! -L $dir ]] || continue
        find "$dir" -type d -exec chmod 777 {} + 2>/dev/null || true
    done
}
lr_remove_work() {
    local directory result=0
    for directory in "$@"; do
        [[ -n $directory ]] || continue
        # Module caches contain read-only directories. Only this run's owned
        # workspaces are made writable, never an existing user cache/toolchain.
        if [[ -d $directory && ! -L $directory ]]; then
            find -P "$directory" -type d -exec chmod u+w -- {} + || result=1
        fi
        rm -rf -- "$directory" || result=1
    done
    return "$result"
}
lr_cleanup() {
    local status=$?
    if (( status )); then printf 'Build incomplete (exit %s). Artifacts/logs: %s\n' "$status" "$output" >&2; fi
    if (( output_owned )); then lr_open_dirs "$output"; rm -f -- "$output/.work"; fi
    lr_remove_work "${work:-}" "$stage" || status=1
    exit "$status"
}
lr_value() { [[ $# -ge 2 && -n $2 && $2 != --* ]] || lr_die "Pass a value to $1."; }
lr_physical_dir() { REPLY=$(cd -P -- "$1" && printf '%s/' "$PWD"); REPLY=${REPLY%/}; }
lr_empty_dir() {
    local entries
    [[ -r $1 && -x $1 ]] || return 1
    entries=$(ls -A -- "$1" && printf '.') || return 1
    [[ $entries == . ]]
}
lr_host() {
    [[ $(uname -s) == Linux && -r /etc/os-release ]] || lr_die 'A supported Linux VPS is required.'
    # This file is the operating system's trusted platform description.
    # shellcheck disable=SC1091
    source /etc/os-release
    case ${ID:-}:${VERSION_ID:-}:$(uname -m) in
        debian:13:x86_64) platform=debian-13-amd64; host_arch=amd64 ;;
        debian:13:aarch64|debian:13:arm64) platform=debian-13-arm64; host_arch=arm64 ;;
        ubuntu:26.04:x86_64) platform=ubuntu-26.04-amd64; host_arch=amd64 ;;
        ubuntu:26.04:aarch64|ubuntu:26.04:arm64) platform=ubuntu-26.04-arm64; host_arch=arm64 ;;
        *) lr_die 'Supported hosts: Debian 13 or Ubuntu 26.04, on x64 or arm64.' ;;
    esac
}
lr_check_tools() {
    local missing=0 tool targets triple
    for tool in ps git curl cc pkg-config file sha256sum rustup rustc cargo go zig cargo-zigbuild readelf; do
        if command -v "$tool" >/dev/null; then printf '  %s: available\n' "$tool";
        else printf '  %s: missing\n' "$tool" >&2; missing=1; fi
    done
    if [[ -z ${existing_toolchain_bin:-} ]] && command -v rustup >/dev/null; then
        if ! rustup which --toolchain "${RUSTUP_TOOLCHAIN:-1.99.1}" rustc >/dev/null 2>&1; then
            printf '  Rust toolchain %s: missing\n' "${RUSTUP_TOOLCHAIN:-1.99.1}" >&2
            missing=1
        else
            targets=$(rustup target list --installed --toolchain "${RUSTUP_TOOLCHAIN:-1.99.1}") || missing=1
            for triple in x86_64-unknown-linux-musl aarch64-unknown-linux-musl; do
                if ! grep -Fxq "$triple" <<< "${targets:-}"; then
                    printf '  Rust target %s: missing\n' "$triple" >&2; missing=1
                fi
            done
        fi
    fi
    return "$missing"
}
lr_install_system() {
    local apt_command=(apt-get)
    if (( EUID != 0 )); then
        command -v sudo >/dev/null || lr_die 'Installing missing system packages needs administrator rights. Run this script again with sudo, or ask an administrator to run it once.'
        apt_command=(sudo apt-get)
    fi
    # apt retries interrupted downloads itself.
    "${apt_command[@]}" -o Acquire::Retries=3 update
    "${apt_command[@]}" -o Acquire::Retries=3 install -y --no-install-recommends \
        build-essential pkg-config ca-certificates curl git file golang-go binutils python3-venv procps
}
lr_ensure_system() {
    local tool missing=0 needs_python=0
    for tool in ps git curl cc pkg-config file sha256sum go readelf; do
        if ! command -v "$tool" >/dev/null; then
            printf 'Missing system prerequisite: %s\n' "$tool"
            missing=1
        fi
    done
    [[ -s /etc/ssl/certs/ca-certificates.crt ]] || missing=1
    if ! command -v zig >/dev/null; then
        needs_python=1
        if ! command -v python3 >/dev/null || ! python3 -c 'import ensurepip, venv' >/dev/null 2>&1; then
            printf 'Missing Python venv support for the Zig installer.\n'
            missing=1
        fi
    fi
    (( missing )) || return 0
    (( install_deps )) || lr_die 'Missing system prerequisites and --no-install-deps was selected.'
    lr_install_system
    for tool in ps git curl cc pkg-config file sha256sum go readelf; do
        command -v "$tool" >/dev/null || lr_die "System package installation did not provide $tool."
    done
    [[ -s /etc/ssl/certs/ca-certificates.crt ]] || lr_die 'System CA certificates are unavailable.'
    if (( needs_python )); then
        python3 -c 'import ensurepip, venv' >/dev/null 2>&1 || lr_die 'Python venv support is unavailable after package installation.'
    fi
}
lr_install_rustup() {
    [[ -z ${existing_toolchain_bin:-} ]] || return 0
    local installer
    if ! command -v rustup >/dev/null; then
        (( install_deps )) || lr_die 'Missing rustup; use --install-deps.'
        installer=$(mktemp)
        curl --proto '=https' --tlsv1.2 -fsSL --retry 3 --retry-delay 5 https://sh.rustup.rs -o "$installer" || {
            rm -f -- "$installer"; lr_die 'Cannot download rustup.';
        }
        sh "$installer" -y --profile minimal --default-toolchain none --no-modify-path || {
            rm -f -- "$installer"; lr_die 'Cannot install rustup.';
        }
        rm -f -- "$installer"
    fi
}
lr_remote_git() {
    # A signed-in gh session can read private sources without global Git changes.
    # Existing credential helpers remain available before this fallback helper.
    if command -v gh >/dev/null; then
        GIT_TERMINAL_PROMPT=0 git -c protocol.file.allow=never -c 'credential.helper=!gh auth git-credential' "$@"
    else
        GIT_TERMINAL_PROMPT=0 git -c protocol.file.allow=never "$@"
    fi
}
lr_token_git() {
    local token=${CADDY_NETWORK_RELAY_TOKEN:-} header
    [[ -n $token ]] || { printf 'Configure Git credentials or CADDY_NETWORK_RELAY_TOKEN.\n' >&2; return 1; }
    header=$(printf 'x-access-token:%s' "$token" | base64 | tr -d '\n') || return
    GIT_TERMINAL_PROMPT=0 GIT_CONFIG_COUNT=2 \
        GIT_CONFIG_KEY_0=credential.helper GIT_CONFIG_VALUE_0='' \
        GIT_CONFIG_KEY_1=http.https://github.com/.extraheader \
        GIT_CONFIG_VALUE_1="Authorization: Basic $header" git -c protocol.file.allow=never "$@"
}
# Run a network command up to three times, 5 and then 15 seconds apart.
lr_retry() {
    local attempt
    for attempt in 1 2 3; do
        "$@" && return 0
        [[ $attempt == 3 ]] && break
        printf 'Network step failed (attempt %s of 3); retrying in %s seconds.\n' "$attempt" "$((attempt * 10 - 5))" >&2
        sleep "$((attempt * 10 - 5))"
    done
    return 1
}
# Explain a problem the user has to fix, one line per argument, then stop.
lr_explain() {
    printf '\n' >&2
    printf '%s\n' "$@" >&2
    printf '\n' >&2
    exit 1
}
# Plain-language help after GitHub could not be reached or read.
lr_access_help() {
    printf '\nCould not download %s from GitHub.\n' "$1" >&2
    printf 'Check that this computer is online. The repository is private, so Git must be signed in.\n' >&2
    if ! command -v gh >/dev/null; then
        printf 'Install the GitHub CLI (gh), run "gh auth login"%s, then run this script again.\n' "${2:+, or set $2 to a GitHub token}" >&2
    elif ! gh auth status >/dev/null 2>&1; then
        printf 'Sign in by running "gh auth login", then run this script again.\n' >&2
    else
        printf 'Your GitHub account may lack access to %s; check it, then run this script again.\n' "$1" >&2
    fi
}
# Run Git against GitHub with retries, then once with the optional token.
lr_github() {
    lr_retry lr_remote_git "$@" && return 0
    [[ -n ${CADDY_NETWORK_RELAY_TOKEN:-} ]] || return 1
    printf 'Trying once more with CADDY_NETWORK_RELAY_TOKEN.\n' >&2
    lr_token_git "$@"
}
# Always fetch a complete main checkout into this run's private source directory.
lr_update_checkout() {
    printf '==> Cloning latest complete ArcCal/caddy-network-relay main\n'
    if ! lr_github clone --branch main -- https://github.com/ArcCal/caddy-network-relay.git "$checkout"; then
        lr_access_help ArcCal/caddy-network-relay CADDY_NETWORK_RELAY_TOKEN
        lr_die 'Could not download latest source; no local checkout is used.'
    fi
    root_commit=$(git -C "$checkout" rev-parse --verify HEAD) || lr_die 'Cannot identify cloned commit.'
    [[ $root_commit == "$(git -C "$checkout" rev-parse --verify refs/remotes/origin/main)" ]] ||
        lr_die 'Cloned source is not GitHub main.'
}
lr_clone_repo() {
    local name=$1 destination=$2 token_name=$3 token header
    if lr_retry lr_remote_git -c protocol.file.allow=never clone --branch main -- "https://github.com/ArcCal/$name.git" "$destination"; then return 0; fi
    token=${!token_name:-}
    [[ -n $token ]] || { lr_access_help "ArcCal/$name" "$token_name"; return 1; }
    header=$(printf 'x-access-token:%s' "$token" | base64 | tr -d '\n')
    # The caller only supplies fresh paths in its owned private workspace.
    rm -rf -- "${destination:?}"
    GIT_TERMINAL_PROMPT=0 GIT_CONFIG_COUNT=2 \
        GIT_CONFIG_KEY_0=credential.helper GIT_CONFIG_VALUE_0='' \
        GIT_CONFIG_KEY_1=http.https://github.com/.extraheader \
        GIT_CONFIG_VALUE_1="Authorization: Basic $header" \
        git -c protocol.file.allow=never clone --branch main -- "https://github.com/ArcCal/$name.git" "$destination" ||
        { lr_access_help "ArcCal/$name" "$token_name"; return 1; }
}
# Rust comes from static.rust-lang.org; explain a download that keeps failing.
lr_rust_help() {
    printf '\nCould not download Rust %s from static.rust-lang.org.\n' "$RUSTUP_TOOLCHAIN" >&2
    printf 'This is a network problem on this computer, not a problem with the build.\n' >&2
    printf 'Check the internet connection. If a VPN, proxy or firewall is in use, make sure it\n' >&2
    printf 'allows static.rust-lang.org (or turn it off). Then run this script again.\n' >&2
    return 1
}
lr_prepare_rust() {
    if [[ -n ${existing_toolchain_bin:-} ]]; then rustc --version; return; fi
    lr_retry rustup toolchain install "$RUSTUP_TOOLCHAIN" --profile minimal || lr_rust_help
    lr_retry rustup target add --toolchain "$RUSTUP_TOOLCHAIN" x86_64-unknown-linux-musl aarch64-unknown-linux-musl || lr_rust_help
    rustc --version
}
lr_prepare_cross_tools() {
    if ! command -v zig >/dev/null; then
        (( install_deps )) || lr_die 'Install Zig or use --install-deps.'
        python3 -m venv "$work/zig-venv"
        "$work/zig-venv/bin/python" -m pip install --only-binary=:all: ziglang==0.14.1
        local zig_binary
        zig_binary=$("$work/zig-venv/bin/python" -c 'import pathlib, ziglang; print(pathlib.Path(ziglang.__file__).parent / "zig")')
        mkdir -p -- "$work/tools/bin"
        ln -s -- "$zig_binary" "$work/tools/bin/zig"
    fi
    if ! command -v cargo-zigbuild >/dev/null; then
        (( install_deps )) || lr_die 'Install cargo-zigbuild or use --install-deps.'
        cargo install --locked --version 0.24.0 --jobs "$jobs" --root "$work/tools" cargo-zigbuild
    fi
    zig version
    cargo-zigbuild --version
}
lr_step() { set -euo pipefail; "$@"; }
lr_run() {
    local name=$1 status
    shift
    printf '==> %s\n' "$name"
    set +e
    relay_run_build_child lr_step "$@" > "$output/logs/$name.log" 2>&1
    status=$?
    set -e
    if (( status >= 128 )); then exit "$status"; fi
    if (( status )); then
        printf '    FAILED (exit %s); log: %s/logs/%s.log\n' "$status" "$output" "$name" >&2
        tail -n 20 "$output/logs/$name.log" >&2
        failures=$((failures + 1))
    else printf '    ok\n'; fi
    return 0
}
lr_build_rust() {
    local manifest=$1 target_dir=$2 triple=$3
    shift 3
    cd -- "$(dirname -- "$manifest")"
    cargo zigbuild --locked --release --manifest-path "$manifest" \
        --target "$triple" --target-dir "$target_dir" --jobs "$jobs" "$@"
}
lr_prepare_caddy() {
    local build_mod="$caddy_src/build-plugins.mod" build_sum="$caddy_src/build-plugins.sum"
    local plugin_import="$caddy_src/cmd/caddy/cloudflare_dns_build.go" path go_version
    [[ -f $caddy_src/go.mod && -f $caddy_src/go.sum && -d $caddy_src/cmd/caddy &&
       -d $caddy_src/third_party/x-net && -d $caddy_src/third_party/quic-go ]] ||
        lr_die 'Complete caddy-network-relay source is required.'
    [[ -f $cloudflare_src/go.mod ]] || lr_die 'Cloudflare DNS plugin source is required.'
    grep -Eq 'ID:[[:space:]]*"network_relay"' "$caddy_src/app.go"
    grep -Eq 'ID:[[:space:]]*"http\.handlers\.network_relay"' "$caddy_src/handler.go"
    grep -Eq 'ID:[[:space:]]*"dns\.providers\.cloudflare"' "$cloudflare_src/cloudflare.go"
    cd -- "$caddy_src"
    export GOWORK=off GOFLAGS='' GOOS=linux GOARCH="$host_arch" GOAMD64=v1 GOARM64=v8.0 CGO_ENABLED=0
    # Alternate module files keep tracked source and the reviewed transport
    # replacements intact while adding the freshly fetched DNS plugin.
    for path in "$build_mod" "$build_sum" "$plugin_import"; do
        [[ ! -e $path && ! -L $path ]] || lr_die "Build overlay already exists: $path"
    done
    cp -- go.mod "$build_mod"
    cp -- go.sum "$build_sum"
    printf 'package main\n\nimport _ "github.com/caddy-dns/cloudflare"\n' > "$plugin_import"
    # The first go command may download the selected Go toolchain.
    lr_retry go version
    go_version=$(go env GOVERSION)
    # The manifest only states Go 1.26.0; the transport's reviewed toolchain
    # requirement is stricter and must also apply to an explicit override.
    if [[ $go_version =~ ^go1\.26\.([0-9]+)$ ]]; then
        (( 10#${BASH_REMATCH[1]} >= 9 )) || lr_die 'Caddy requires Go 1.26.9 or Go 1.27.2 or newer.'
    elif [[ $go_version =~ ^go1\.27\.([0-9]+)$ ]]; then
        (( 10#${BASH_REMATCH[1]} >= 2 )) || lr_die 'Caddy requires Go 1.26.9 or Go 1.27.2 or newer.'
    elif [[ $go_version =~ ^go1\.([0-9]+)(\.[0-9]+)?$ ]]; then
        (( 10#${BASH_REMATCH[1]} > 27 )) || lr_die 'Caddy requires Go 1.26.9 or Go 1.27.2 or newer.'
    else
        lr_die "Unrecognized release Go toolchain: $go_version"
    fi
    # A sibling path keeps the caller's username/output path out of Go build info.
    go mod edit -modfile "$build_mod" \
        -replace github.com/caddy-dns/cloudflare=../cloudflare-src
    lr_retry go get -modfile "$build_mod" github.com/caddy-dns/cloudflare@v0.0.0
}
lr_build_caddy() {
    local arch=$1
    cd -- "$caddy_src"
    export GOWORK=off GOFLAGS='' GOOS=linux GOARCH="$arch" GOAMD64=v1 GOARM64=v8.0 CGO_ENABLED=0
    go build -modfile "$caddy_src/build-plugins.mod" -mod=readonly -tags http2legacy -trimpath -p "$jobs" \
        -o "$work/caddy-network-relay-$arch" ./cmd/caddy
}
lr_check_replacement() {
    local info=$1 module=$2 replacement=$3
    awk -F '\t' -v module="$module" -v replacement="$replacement" '
        ($2 == "dep" || $2 == "mod") && $3 == module { pending=1; next }
        pending { if ($2 == "=>" && $3 == replacement) found=1; pending=0 }
        END { exit !found }
    ' <<< "$info"
}

lr_collect() {
    local source=$1 name=$2 arch=$3 description modules module info headers
    [[ -f $source && -s $source && -x $source ]] || lr_die "Missing executable: $source"
    description=$(LC_ALL=C file -b -- "$source")
    case $arch in
        amd64) [[ $description == *ELF* && $description == *x86-64* ]] ;;
        arm64) [[ $description == *ELF* && $description == *aarch64* ]] ;;
    esac || lr_die "Wrong architecture: $description"
    headers=$(LC_ALL=C readelf -l -d -- "$source")
    [[ $description == *static* && $headers != *INTERP* && $headers != *NEEDED* ]] ||
        lr_die "Artifact must be static: $source"
    if [[ $name == caddy-network-relay ]]; then
        info=$(go version -m "$source")
        grep -Eq '^[[:space:]]*path[[:space:]]+github\.com/arccal/caddy-network-relay/cmd/caddy$' <<< "$info"
        grep -Eq "^[[:space:]]*build[[:space:]]+GOARCH=$arch$" <<< "$info"
        grep -Eq '^[[:space:]]*build[[:space:]]+CGO_ENABLED=0$' <<< "$info"
        lr_check_replacement "$info" github.com/caddy-dns/cloudflare ../cloudflare-src
        lr_check_replacement "$info" golang.org/x/net ./third_party/x-net
        lr_check_replacement "$info" github.com/quic-go/quic-go ./third_party/quic-go
    fi
    # Foreign executables cannot run directly on the host. Their ELF headers
    # and Go build metadata are still mandatory checks.
    if [[ $arch == "$host_arch" ]]; then
        if [[ $name == caddy-network-relay ]]; then
            "$source" version
            modules=$("$source" list-modules)
            for module in network_relay http.handlers.network_relay dns.providers.cloudflare; do
                grep -Fxq -- "$module" <<< "$modules" || lr_die "Missing Caddy module: $module"
            done
        else
            "$source" --version
        fi
    fi
    install -m 755 -- "$source" "$output/$name-linux-$arch"
}
# Free space, in KiB, on the filesystem holding $1 or its nearest existing parent.
lr_free_kib() {
    local dir=$1
    while [[ ! -d $dir ]]; do dir=$(dirname -- "$dir"); done
    df -Pk -- "$dir" | awk 'NR == 2 { print $4 }'
}
# Mount point of the filesystem holding $1 or its nearest existing parent.
lr_mount_of() {
    local dir=$1
    while [[ ! -d $dir ]]; do dir=$(dirname -- "$dir"); done
    df -Pk -- "$dir" | awk 'NR == 2 { print $6 }'
}
lr_gib() { awk -v k="$1" 'BEGIN { printf "%.1f", k / 1048576 }'; }
# Compiler caches need disk space, not a RAM-backed /tmp on a small VPS.
lr_work_parent() {
    local candidate need=8
    if command -v rustup >/dev/null; then
        local compiler
        compiler=$(rustup which --toolchain "${RUSTUP_TOOLCHAIN:-1.99.1}" rustc 2>/dev/null) || compiler=
        if [[ -n $compiler && -d ${compiler%/*}/../lib/rustlib/x86_64-unknown-linux-musl/lib &&
              -d ${compiler%/*}/../lib/rustlib/aarch64-unknown-linux-musl/lib ]]; then need=4; fi
    fi
    for candidate in /tmp /var/tmp "$HOME/.cache" "$HOME"; do
        [[ -d $candidate ]] || continue
        case $(stat -f -c %T "$candidate") in tmpfs|ramfs) continue ;; esac
        if (( $(lr_free_kib "$candidate") >= need * 1048576 )); then
            REPLY=$candidate
            return 0
        fi
    done
    lr_explain "The build needs about $need GiB of free disk space for its private compiler workspace." \
        'Source stays in /tmp; compiler work on a small RAM-backed /tmp is avoided.' \
        'Free disk space or use a larger disk, then run this script again.'
}
lr_cgroup_headroom() {
    local cgroups=$1 mountinfo=$2 host_ram=$3 host_swap=$4
    local hierarchy controllers relative type root mount dir limit usage inactive ram swap used level smallest=''
    [[ -r $cgroups && -r $mountinfo ]] || return 1
    while IFS=: read -r hierarchy controllers relative; do
        if [[ $hierarchy == 0 && -z $controllers ]]; then type=cgroup2
        elif [[ ,$controllers, == *,memory,* ]]; then type=cgroup
        else continue
        fi
        while read -r root mount; do
            root=$(printf '%b' "$root"); mount=$(printf '%b' "$mount")
            if [[ $root == / || $relative == "$root" || $relative == "$root"/* ]]; then
                dir=$mount${relative#"${root%/}"}
            else
                # A cgroup namespace can report a relative process path while
                # mountinfo still exposes its host-side root (including /..).
                dir=$mount$relative
            fi
            dir=${dir%/}
            [[ -d $dir ]] || dir=${mount%/}
            while [[ -d $dir ]]; do
                ram=$host_ram; swap=$host_swap; inactive=0
                if [[ $type == cgroup2 && -r $dir/memory.max ]]; then
                    limit=$(< "$dir/memory.max")
                    if [[ $limit =~ ^[0-9]+$ ]] && (( ${#limit} < 19 )); then
                        usage=$(cat -- "$dir/memory.current") || return 1
                        [[ $usage =~ ^[0-9]+$ ]] || return 1
                        inactive=$(awk '$1 == "inactive_file" {print $2}' "$dir/memory.stat" 2>/dev/null)
                        ram=$(( (limit - usage + ${inactive:-0}) / 1024 ))
                    fi
                    limit=$(cat -- "$dir/memory.swap.max" 2>/dev/null || printf max)
                    if [[ $limit =~ ^[0-9]+$ ]] && (( ${#limit} < 19 )); then
                        used=$(cat -- "$dir/memory.swap.current") || return 1
                        [[ $used =~ ^[0-9]+$ ]] || return 1
                        swap=$(( (limit - used) / 1024 ))
                    fi
                elif [[ $type == cgroup && -r $dir/memory.limit_in_bytes ]]; then
                    limit=$(< "$dir/memory.limit_in_bytes")
                    inactive=$(awk '$1 == "total_inactive_file" {print $2}' "$dir/memory.stat" 2>/dev/null)
                    if [[ $limit =~ ^[0-9]+$ ]] && (( ${#limit} < 19 )); then
                        usage=$(cat -- "$dir/memory.usage_in_bytes") || return 1
                        [[ $usage =~ ^[0-9]+$ ]] || return 1
                        ram=$(( (limit - usage + ${inactive:-0}) / 1024 ))
                    fi
                fi
                (( ram >= 0 )) || ram=0
                (( swap >= 0 )) || swap=0
                (( ram <= host_ram )) || ram=$host_ram
                (( swap <= host_swap )) || swap=$host_swap
                level=$((ram + swap))
                if [[ $type == cgroup ]]; then
                    limit=$(cat -- "$dir/memory.memsw.limit_in_bytes" 2>/dev/null || true)
                    if [[ $limit =~ ^[0-9]+$ ]] && (( ${#limit} < 19 )); then
                        used=$(cat -- "$dir/memory.memsw.usage_in_bytes") || return 1
                        [[ $used =~ ^[0-9]+$ ]] || return 1
                        used=$(( (limit - used + ${inactive:-0}) / 1024 ))
                        (( used >= 0 )) || used=0
                        (( level <= used )) || level=$used
                    fi
                fi
                if [[ -z $smallest ]] || (( level < smallest )); then smallest=$level; fi
                [[ $dir != "${mount%/}" ]] || break
                dir=${dir%/*}
            done
        done < <(awk -v type="$type" '{
            for (i = 7; i <= NF; i++) if ($i == "-") {
                if ($(i + 1) == type && (type == "cgroup2" || $(i + 3) ~ /(^|,)memory(,|$)/)) print $4, $5
                break
            }
        }' "$mountinfo")
    done < "$cgroups"
    [[ -z $smallest ]] || printf '%s\n' "$smallest"
    return 0
}


lr_memory_jobs() {
    local available swap headroom allowed
    available=$(awk '/^(MemAvailable|SwapFree):/ {n += $2} END {print n+0}' "${1:-/proc/meminfo}") || lr_die 'Cannot inspect build memory.'
    swap=$(awk '/^SwapFree:/ {n = $2} END {print n+0}' "${1:-/proc/meminfo}")
    headroom=$(lr_cgroup_headroom "${2:-/proc/self/cgroup}" "${3:-/proc/self/mountinfo}" "$((available - swap))" "$swap") || lr_die 'Cannot inspect cgroup build memory limits.'
    if [[ $headroom =~ ^[0-9]+$ ]] && (( headroom < available )); then available=$headroom; fi
    if [[ ! $available =~ ^[0-9]+$ ]] || (( available < 1048576 )); then
        lr_die 'The Rust/Caddy build needs at least 1 GiB available RAM plus usable free swap within any cgroup limit. Add or increase swap on disk (not /tmp tmpfs), or raise the memory limit.'
    fi
    allowed=$((available / 1048576))
    if (( jobs > allowed )); then
        printf 'Reducing build parallelism from %s to %s for available RAM and usable swap.\n' "$jobs" "$allowed"
        jobs=$allowed
    fi
}
lr_main() {
    unset GIT_DIR GIT_WORK_TREE GIT_COMMON_DIR GIT_INDEX_FILE GIT_OBJECT_DIRECTORY GIT_ALTERNATE_OBJECT_DIRECTORIES
    checkout=
    # 2: install missing prerequisites; 1: additionally refresh apt; 0: opt out.
    output=; jobs=2; install_deps=2
    local check_only=0 interactive_python_missing=0
    while (( $# )); do
        case $1 in
            -h|--help) lr_usage; return ;;
            --repo) lr_value "$@"; printf '%s\n' '--repo is retained for compatibility; latest sources always use /tmp.' >&2; shift 2 ;;
            --output) lr_value "$@"; output=$2; shift 2 ;;
            --jobs) lr_value "$@"; jobs=$2; shift 2 ;;
            --install-deps) install_deps=1; shift ;;
            --no-install-deps) install_deps=0; shift ;;
            --check) check_only=1; shift ;;
            *) lr_usage >&2; lr_die "Unknown argument: $1" ;;
        esac
    done
    [[ $jobs =~ ^[1-9][0-9]*$ ]] || lr_die '--jobs must be a positive integer.'
    (( ! check_only || install_deps != 1 )) || lr_die '--check and --install-deps conflict.'
    lr_host
    export PATH="${CARGO_HOME:-$HOME/.cargo}/bin:$PATH"
    if (( check_only )); then
        printf 'Build host: %s; targets: linux-amd64, linux-arm64 (static)\n' "$platform"
        lr_check_tools
        return
    fi
    lr_memory_jobs /proc/meminfo /proc/self/cgroup /proc/self/mountinfo
    (( install_deps != 1 )) || lr_install_system
    if { : </dev/tty; } 2>/dev/null && ! command -v python3 >/dev/null; then
        interactive_python_missing=1
    fi
    if ! command -v git >/dev/null || ! command -v ps >/dev/null || (( interactive_python_missing )); then
        (( install_deps )) || lr_die 'Missing Git, ps, or interactive Python 3; --no-install-deps was selected.'
        lr_install_system
    fi
    lr_work_parent
    local build_parent=$REPLY
    stage=$(mktemp -d "/tmp/$(date +%Y%m%d-%H%M%S).XXXXXX") || lr_die 'Cannot create private source directory in /tmp.'
    checkout=$stage/caddy-network-relay-src
    trap 'status=$?; rm -rf -- "${stage:?}"; exit "$status"' EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM
    trap 'exit 129' HUP
    if relay_run_build_child lr_update_checkout; then :; else exit "$?"; fi
    root_commit=$(git -C "$checkout" rev-parse --verify HEAD) || lr_die 'Cannot identify cloned commit.'
    printf '%s\n' "$build_parent" > "$stage/.build-parent"
    printf '%s\n' "$root_commit" > "$stage/.owner"
    git -C "$checkout" show "$root_commit:build-linux-servers-on-linux.sh" > "$stage/driver.sh" || lr_die 'Cannot load newest committed script.'
    [[ -s $stage/driver.sh ]] || lr_die 'Newest build script is empty.'
    exec "$BASH" -c '
        relay_fresh_stage=$3
        relay_fresh_cleanup() {
            local status=$?
            find -P "$relay_fresh_stage" -type d -exec chmod u+w -- {} +
            rm -rf -- "$relay_fresh_stage"
            exit "$status"
        }
        trap relay_fresh_cleanup EXIT
        source "$0" "$@"
    ' "$stage/driver.sh" --build-updated "$checkout" "$stage" "$output" "$root_commit" "$jobs" "$install_deps" --deps-policy-v2
}

# Sourcing provides the portable build helpers without inspecting or changing a host.
[[ ${BASH_SOURCE[0]} == "$0" ]] || return 0
set +x
set -euo pipefail
unset CDPATH
# Parse the complete conditional before pull can replace the running input file.
if [[ ${1:-} != --build-updated ]]; then lr_main "$@"; exit; fi
[[ $# == 8 && ${8:-} == --deps-policy-v2 ]] || lr_die 'Invalid internal build invocation.'
checkout=$2; stage=$3; output=$4; root_commit=$5; jobs=$6; install_deps=$7
[[ $root_commit =~ ^[0-9a-f]{40}$ && $jobs =~ ^[1-9][0-9]*$ && ( $install_deps == 0 || $install_deps == 1 || $install_deps == 2 ) ]] || lr_die 'Invalid build options.'
[[ ${stage%/*} == /tmp && ${stage##*/} =~ ^[0-9]{8}-[0-9]{6}\.[[:alnum:]]+$ && -d $stage && ! -L $stage && -f $stage/.owner && ! -L $stage/.owner &&
   $(cat "$stage/.owner") == "$root_commit" ]] || lr_die 'Invalid private workspace.'
work=
output_owned=0
trap lr_cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP
lr_host
lr_memory_jobs /proc/meminfo /proc/self/cgroup /proc/self/mountinfo
printf 'Build host: %s; targets: linux-amd64, linux-arm64 (static)\n' "$platform"
export PATH="${CARGO_HOME:-$HOME/.cargo}/bin:$PATH"
while [[ $output == */ && $output != / ]]; do output=${output%/}; done
if [[ -z $output ]]; then
    stamp=$(date -u +%Y%m%d-%H%M%S)
    output=$(mktemp -d "$PWD/relay-servers-$platform-$stamp.XXXXXX") ||
        lr_explain "Cannot create the output folder in $PWD (this folder is not writable)." \
            'Run the script from your home folder (cd ~) or choose a folder with --output DIR.'
    # mktemp creates mode 700; artifacts get ordinary permissions for sharing and sync.
    chmod -- "$(printf '%o' $((0777 & ~$(umask))))" "$output"
elif [[ -e $output || -L $output ]]; then
    if [[ ! -d $output || -L $output ]] || ! lr_empty_dir "$output"; then
        lr_die '--output must be a new or empty directory.'
    fi
else
    mkdir -p -- "$output" || lr_explain "Cannot create the output folder $output." \
        'Choose a folder you can write to with --output DIR, for example one in your home folder.'
fi
lr_physical_dir "$output"; output=$REPLY
[[ $output/ != "$stage/"* && $stage/ != "$output/"* ]] || lr_die 'Output and work directories cannot overlap.'
work=$(mktemp -d "$(cat "$stage/.build-parent")/relay-servers.XXXXXX") || lr_die 'Cannot create compiler workspace.'
mkdir -- "$work/tmp"
export TMPDIR="$work/tmp" GOTMPDIR="$work/tmp"
if [[ ${work%/*} != /tmp ]]; then
    printf 'Compiler temporary files go to %s because /tmp is too small.\n' "$work"
fi
repo="$stage/network-relay-src"
caddy_src="$checkout"
cloudflare_src="$stage/cloudflare-src"
output_owned=1
mkdir -- "$output/logs"
ln -s -- "$work" "$output/.work"
printf 'Artifacts: %s\nFresh source checkout: %s\nWork directory: %s\n' "$output" "$checkout" "$work"
failures=0
export RUSTUP_TOOLCHAIN=${RUSTUP_TOOLCHAIN:-1.99.1}
existing_toolchain_bin=
if command -v rustup >/dev/null; then
    existing_rustc=$(rustup which --toolchain "$RUSTUP_TOOLCHAIN" rustc 2>/dev/null) || existing_rustc=
    if [[ -n $existing_rustc ]]; then
        existing_toolchain_bin=${existing_rustc%/*}
        for triple in x86_64-unknown-linux-musl aarch64-unknown-linux-musl; do
            [[ -d $existing_toolchain_bin/../lib/rustlib/$triple/lib ]] || existing_toolchain_bin=
        done
    fi
fi
export CARGO_HOME="$work/cargo" RUSTUP_HOME="$work/rustup"
export GOPATH="$work/gopath" GOMODCACHE="$work/gopath/pkg/mod" GOCACHE="$work/gocache"
export XDG_CACHE_HOME="$work/cache" PIP_CACHE_DIR="$work/pip-cache"
export ZIG_GLOBAL_CACHE_DIR="$work/zig-global-cache" ZIG_LOCAL_CACHE_DIR="$work/zig-local-cache"
export PATH="${existing_toolchain_bin:+$existing_toolchain_bin:}$CARGO_HOME/bin:$PATH"
export TEST_TELEMETRY_DIR="$work/go-telemetry"
export GOMAXPROCS="$jobs"
export RUSTC_WRAPPER='' RUSTC_WORKSPACE_WRAPPER=''
unset GOCACHEPROG GOROOT RUSTC RUSTDOC CARGO_BUILD_RUSTC CARGO_BUILD_RUSTDOC
export GOENV=off
if (( install_deps )); then
    export GOTOOLCHAIN=${GOTOOLCHAIN:-go1.27.3+auto}
else
    export GOTOOLCHAIN=${GOTOOLCHAIN:-local}
fi
lr_run system-prerequisites lr_ensure_system
(( failures == 0 )) || lr_die 'Cannot prepare system prerequisites.'
if (( install_deps )); then
    lr_run bootstrap-rustup lr_install_rustup
else
    lr_run installed-prerequisites lr_check_tools
fi
(( failures == 0 )) || lr_die 'Build prerequisites are unavailable.'
for tool in rustup rustc cargo; do command -v "$tool" >/dev/null || lr_die "Missing required tool after bootstrap: $tool"; done
lr_snapshot() {
    [[ $(git -C "$caddy_src" rev-parse --verify HEAD) == "$root_commit" ]]
}
lr_run source-caddy-network-relay lr_snapshot
lr_run source-network-relay lr_clone_repo network-relay "$repo" NETWORK_RELAY_TOKEN
lr_clone_cloudflare() {
    lr_retry env GIT_TERMINAL_PROMPT=0 git -c protocol.file.allow=never clone --branch "$LR_CLOUDFLARE_DNS_TAG" -- \
        https://github.com/caddy-dns/cloudflare.git "$cloudflare_src"
    [[ $(git -C "$cloudflare_src" rev-parse --verify HEAD) == "$LR_CLOUDFLARE_DNS_COMMIT" ]] ||
        lr_die "caddy-dns/cloudflare $LR_CLOUDFLARE_DNS_TAG is not the reviewed commit."
}
lr_run source-cloudflare lr_clone_cloudflare
export GOWORK=off GOFLAGS='' GOAMD64=v1 GOARM64=v8.0
unset GOOS GOARCH CARGO_TARGET_DIR CARGO_BUILD_TARGET RUSTFLAGS
export CARGO_ENCODED_RUSTFLAGS=''
export PATH="$work/tools/bin:$PATH"
if (( install_deps )); then
    lr_run toolchain-rust lr_prepare_rust
else
    lr_run toolchain-rust rustc --version
fi
lr_run toolchain-cross lr_prepare_cross_tools
(( failures == 0 )) || lr_die "$failures source/toolchain step(s) failed."
lr_run prepare-caddy lr_prepare_caddy
(( failures == 0 )) || lr_die 'Cannot prepare Caddy dependencies.'
for arch in amd64 arm64; do
    case $arch in
        amd64) triple=x86_64-unknown-linux-musl ;;
        arm64) triple=aarch64-unknown-linux-musl ;;
    esac
    lr_run "build-network-relay-$arch" lr_build_rust "$repo/Cargo.toml" "$work/rust-main" "$triple" --bin network-relay
    lr_run "build-caddy-network-relay-$arch" lr_build_caddy "$arch"
    lr_run "verify-network-relay-$arch" lr_collect "$work/rust-main/$triple/release/network-relay" network-relay "$arch"
    lr_run "verify-caddy-network-relay-$arch" lr_collect "$work/caddy-network-relay-$arch" caddy-network-relay "$arch"
done
(( failures == 0 )) || lr_die "$failures step(s) failed; see $output/logs."
lr_write_manifest() {
    local source commit branch fetched program arch description built rust_version
    built=$(date -u +%FT%TZ)
    rust_version=$(rustc --version)
    printf 'Build host: %s\nTargets: linux-amd64, linux-arm64 (static musl Rust, CGO-disabled Go)\nBuilt: %s\n' "$platform" "$built"
    printf 'Rust: %s\nGo selection: %s\n' "$rust_version" "$GOTOOLCHAIN"
    for source in "$repo" "$caddy_src" "$cloudflare_src"; do
        commit=$(git -C "$source" rev-parse --verify HEAD)
        if [[ $source == "$caddy_src" ]]; then branch=main; fetched=$root_commit;
        elif [[ $source == "$cloudflare_src" ]]; then branch=$LR_CLOUDFLARE_DNS_TAG; fetched=$LR_CLOUDFLARE_DNS_COMMIT;
        else branch=$(git -C "$source" symbolic-ref --short HEAD); fetched=$(git -C "$source" rev-parse --verify "refs/remotes/origin/$branch"); fi
        [[ $fetched == "$commit" ]] || lr_die "Source commit changed: $source"
        git -C "$source" diff --quiet HEAD -- || lr_die "Build changed tracked sources: $source"
        printf 'Source: %s\nBranch: %s\nCommit: %s\n' "${source##*/}" "$branch" "$commit"
    done
    for arch in amd64 arm64; do
        for program in network-relay caddy-network-relay; do
            description=$(LC_ALL=C file -b -- "$output/$program-linux-$arch")
            printf '%s: %s\n' "$program-linux-$arch" "$description"
        done
    done
}
lr_run manifest lr_write_manifest
(( failures == 0 )) || lr_die 'Manifest verification failed.'
# Run manifest generation in its own error-enabled step, then publish the log.
cp -- "$output/logs/manifest.log" "$output/MANIFEST.txt"
lr_checksums() (
    cd -- "$output" || exit
    artifact_files=()
    for arch in amd64 arm64; do
        for program in network-relay caddy-network-relay; do artifact_files+=("$program-linux-$arch"); done
    done
    sha256sum -- "${artifact_files[@]}" MANIFEST.txt > SHA256SUMS || exit
    sha256sum --check SHA256SUMS || exit
)
lr_run checksums lr_checksums
(( failures == 0 )) || lr_die 'Checksum generation or verification failed.'
rm -f -- "$output/.work"
lr_remove_work "$work"
printf '\nBoth servers built for amd64 and arm64.\nBoth architectures inspected; native executables also smoke-tested.\nArtifacts: %s\n' "$output"
