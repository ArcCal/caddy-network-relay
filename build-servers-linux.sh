#!/usr/bin/env bash
# Build all three Network Relay servers from fresh main snapshots on a VPS.
# Supported hosts: Debian 13 amd64; Ubuntu 26.04 amd64 and arm64.
# GNU binaries use the build host's glibc. Build on each deployment platform.
set -euo pipefail

usage() {
    cat <<'EOF'
Usage: bash build-servers-linux.sh [--output DIR] [--jobs N]
                                   [--install-deps] [--check]

Build these three servers from the latest main branches on GitHub:
  ArcCal/caddy-network-relay: caddy-network-relay
  ArcCal/network-relay: network-relay
  ArcCal/network-relay/network-relay-cf-masque: network-relay-cf-masque

Every run clones both server repositories and caddy-dns/cloudflare afresh.
Cloudflare DNS uses its latest master branch; server repositories use latest main.
Existing checkouts are never used
as build sources or modified. The two Rust servers share one fetched commit.
Branch tips are fixed when fetched; pushes during a build enter the next run.
All three source commit IDs are recorded in MANIFEST.txt.

Supported build/deployment hosts: Debian 13 x64, Ubuntu 26.04 x64 and
Ubuntu 26.04 arm64. Run on each deployment platform for native GNU binaries;
Ubuntu builds are not guaranteed to run on Debian's older glibc. Caddy is
built with CGO disabled. No clients or deployment steps are included.
Both http.handlers.network_relay and dns.providers.cloudflare are required.

  --output DIR      new or empty artifact directory (default: ./relay-servers-*)
  --jobs N          Cargo and Go build parallelism (default: 2)
  --install-deps    install apt build prerequisites and rustup if missing
                    (apt needs root or sudo; rustup runs as the calling user)
  --check           check host and installed tools without downloading,
                    installing packages, cloning sources or creating output

Configure git credentials for both private repositories, or set read tokens:
  NETWORK_RELAY_TOKEN        ArcCal/network-relay
  CADDY_NETWORK_RELAY_TOKEN  ArcCal/caddy-network-relay
  RUSTUP_TOOLCHAIN           Rust version (default: 1.99.0)
  GOTOOLCHAIN                Go selection (default: auto; honors go.mod)

All three servers are required; any failed step makes the run fail.
Successful runs keep three executables, logs, MANIFEST.txt and SHA256SUMS,
then delete downloaded source and intermediate build files. Failed runs
retain a private .work directory for diagnosis.

Example on a fresh VPS with git credentials configured:
  bash build-servers-linux.sh --install-deps
EOF
}

die() { printf 'build-servers-linux: %s\n' "$*" >&2; exit 1; }
value() { [[ $# -ge 2 && -n $2 && $2 != --* ]] || die "Pass a value to $1."; }
output=
install_deps=0
check_only=0
jobs=2
while (( $# )); do
    case $1 in
        -h|--help) usage; exit 0 ;;
        --output) value "$@"; output=$2; shift 2 ;;
        --jobs) value "$@"; jobs=$2; shift 2 ;;
        --install-deps) install_deps=1; shift ;;
        --check) check_only=1; shift ;;
        *) usage >&2; die "Unknown argument: $1" ;;
    esac
done
[[ $jobs =~ ^[1-9][0-9]*$ ]] || die '--jobs must be a positive integer.'
(( ! check_only || ! install_deps )) || die '--check and --install-deps conflict.'

[[ $(uname -s) == Linux && -r /etc/os-release ]] || die 'A supported Linux VPS is required.'
# /etc/os-release is the operating system's trusted platform description.
source /etc/os-release
case ${ID:-}:${VERSION_ID:-}:$(uname -m) in
    debian:13:x86_64) platform=debian-13-amd64; arch=amd64; triple=x86_64-unknown-linux-gnu ;;
    ubuntu:26.04:x86_64) platform=ubuntu-26.04-amd64; arch=amd64; triple=x86_64-unknown-linux-gnu ;;
    ubuntu:26.04:aarch64|ubuntu:26.04:arm64)
        platform=ubuntu-26.04-arm64; arch=arm64; triple=aarch64-unknown-linux-gnu ;;
    *) die 'Supported hosts: Debian 13 x64, Ubuntu 26.04 x64 or Ubuntu 26.04 arm64.' ;;
esac
printf 'Build platform: %s (%s)\n' "$platform" "$triple"

export PATH="${CARGO_HOME:-$HOME/.cargo}/bin:$PATH"
if (( check_only )); then
    missing=0
    for tool in git curl cc pkg-config file sha256sum rustup rustc cargo go; do
        if command -v "$tool" >/dev/null; then
            printf '  %s: available\n' "$tool"
        else
            printf '  %s: missing\n' "$tool" >&2
            missing=1
        fi
    done
    if command -v rustup >/dev/null &&
       ! rustup which --toolchain "${RUSTUP_TOOLCHAIN:-1.99.0}" rustc >/dev/null 2>&1; then
        printf '  Rust toolchain %s: not installed\n' "${RUSTUP_TOOLCHAIN:-1.99.0}" >&2
        missing=1
    fi
    printf 'Server repositories require fresh private clones; credentials are not checked in --check.\n'
    printf 'Required Rust: %s; Go: as specified in the latest Caddy go.mod (automatic download by default).\n' "${RUSTUP_TOOLCHAIN:-1.99.0}"
    exit "$missing"
fi

if (( install_deps )); then
    apt_command=(apt-get)
    if (( EUID != 0 )); then
        command -v sudo >/dev/null || die '--install-deps requires root or sudo.'
        apt_command=(sudo apt-get)
    fi
    "${apt_command[@]}" update
    "${apt_command[@]}" install -y --no-install-recommends \
        build-essential pkg-config ca-certificates curl git file golang-go
    if ! command -v rustup >/dev/null; then
        installer=$(mktemp)
        # Download before execution so an interrupted download cannot run.
        curl --proto '=https' --tlsv1.2 -fsSL https://sh.rustup.rs -o "$installer" || {
            rm -f -- "$installer"; die 'Cannot download rustup.';
        }
        sh "$installer" -y --profile minimal --default-toolchain none --no-modify-path || {
            rm -f -- "$installer"; die 'Cannot install rustup.';
        }
        rm -f -- "$installer"
    fi
fi
for tool in git curl cc pkg-config file sha256sum rustup rustc cargo go; do
    command -v "$tool" >/dev/null || die "Missing $tool; rerun with --install-deps, or install it first."
done

# Never overwrite artifacts from another run, including failed builds.
if [[ -z $output ]]; then
    output=$(mktemp -d "$PWD/relay-servers-$platform-$(date -u +%Y%m%d-%H%M%S).XXXXXX")
elif [[ -e $output || -L $output ]]; then
    [[ -d $output && ! -L $output && -z $(ls -A -- "$output") ]] || die '--output must be a new or empty directory.'
else
    mkdir -p -- "$output"
fi
output=$(cd -- "$output" && pwd -P)
work="$output/.work"
mkdir -p -- "$output/logs"
mkdir -m 700 -- "$work"
trap 'status=$?; if (( status )); then printf "Build incomplete (exit %s). Logs and work: %s\n" "$status" "$output" >&2; fi' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# Each step is an errexit-enabled subshell; do not call it in an if/|| context,
# which would disable errexit inside builder functions and mask intermediate errors.
failures=0
run() {
    local name=$1 status
    shift
    printf '==> %s\n' "$name"
    set +e
    ( set -e; "$@" ) >"$output/logs/$name.log" 2>&1
    status=$?
    set -e
    if (( status )); then
        printf 'FAILED: %s (exit %s)\n' "$name" "$status" >&2
        tail -n 20 "$output/logs/$name.log" >&2
        failures=$((failures + 1))
    else
        printf '    ok\n'
    fi
    return 0
}

# Token fallback uses per-process environment config, never a token-bearing URL
# or command-line argument, and never writes credentials to the checkout.
clone_repo() {
    local name=$1 destination=$2 token_name=$3 token header
    local options=(--depth 1 --branch main --single-branch)
    if GIT_TERMINAL_PROMPT=0 git clone "${options[@]}" "https://github.com/ArcCal/$name.git" "$destination"; then
        return 0
    fi
    token=${!token_name:-}
    [[ -n $token ]] || { printf 'Set git credentials or %s for ArcCal/%s.\n' "$token_name" "$name" >&2; return 1; }
    header=$(printf 'x-access-token:%s' "$token" | base64 | tr -d '\n')
    # destination is always owned by this run under its fresh .work directory.
    rm -rf -- "${destination:?}"
    GIT_TERMINAL_PROMPT=0 GIT_CONFIG_COUNT=2 \
        GIT_CONFIG_KEY_0=credential.helper GIT_CONFIG_VALUE_0='' \
        GIT_CONFIG_KEY_1=http.https://github.com/.extraheader \
        GIT_CONFIG_VALUE_1="Authorization: Basic $header" \
        git clone "${options[@]}" "https://github.com/ArcCal/$name.git" "$destination"
}

repo="$work/network-relay-src"
caddy_src="$work/caddy-network-relay-src"
run source-network-relay clone_repo network-relay "$repo" NETWORK_RELAY_TOKEN
run source-caddy-network-relay clone_repo caddy-network-relay "$caddy_src" CADDY_NETWORK_RELAY_TOKEN
cloudflare_src="$work/cloudflare-src"
run source-cloudflare env GIT_TERMINAL_PROMPT=0 git clone --depth 1 --branch master --single-branch \
    https://github.com/caddy-dns/cloudflare.git "$cloudflare_src"

export RUSTUP_TOOLCHAIN=${RUSTUP_TOOLCHAIN:-1.99.0}
export GOTOOLCHAIN=${GOTOOLCHAIN:-auto}
# Explicit native targets and directories isolate both Rust workspaces and keep
# caller-provided cross-build flags from producing mislabeled executables.
unset CARGO_BUILD_TARGET RUSTFLAGS CARGO_ENCODED_RUSTFLAGS
prepare_rust() {
    rustup toolchain install "$RUSTUP_TOOLCHAIN" --profile minimal
    rustup target add --toolchain "$RUSTUP_TOOLCHAIN" "$triple"
    rustc --version
}
run toolchain-rust prepare_rust

build_rust() {
    local manifest=$1 target_dir=$2
    shift 2
    cd -- "$(dirname -- "$manifest")"
    cargo build --locked --release --manifest-path "$manifest" \
        --target "$triple" --target-dir "$target_dir" --jobs "$jobs" "$@"
}
build_caddy() {
    local build_mod="$caddy_src/build-plugins.mod" build_sum="$caddy_src/build-plugins.sum"
    local plugin_import="$caddy_src/cmd/caddy/cloudflare_dns_build.go" path
    [[ -f $caddy_src/go.mod && -f $caddy_src/go.sum && -d $caddy_src/cmd/caddy &&
       -d $caddy_src/third_party/x-net && -d $caddy_src/third_party/quic-go ]] ||
        die 'Complete caddy-network-relay source is required.'
    [[ -f $cloudflare_src/go.mod ]] || die 'Cloudflare DNS plugin source is required.'
    cd -- "$caddy_src"
    export GOWORK=off GOFLAGS='' GOOS=linux GOARCH="$arch" GOAMD64=v1 GOARM64=v8.0 CGO_ENABLED=0
    # Alternate module files keep tracked source and the reviewed transport
    # replacements intact while adding the freshly fetched DNS plugin.
    for path in "$build_mod" "$build_sum" "$plugin_import"; do
        [[ ! -e $path && ! -L $path ]] || die "Build overlay already exists: $path"
    done
    cp -- go.mod "$build_mod"
    cp -- go.sum "$build_sum"
    printf 'package main\n\nimport _ "github.com/caddy-dns/cloudflare"\n' > "$plugin_import"
    go version
    go mod edit -modfile "$build_mod" \
        -replace "github.com/caddy-dns/cloudflare=$cloudflare_src"
    go get -modfile "$build_mod" github.com/caddy-dns/cloudflare@v0.0.0
    go build -modfile "$build_mod" -mod=readonly -tags http2legacy -trimpath -p "$jobs" -o "$work/caddy-network-relay-bin" ./cmd/caddy
}
run build-network-relay build_rust "$repo/Cargo.toml" "$work/rust-main" --bin network-relay
run build-cf-masque build_rust "$repo/network-relay-cf-masque/Cargo.toml" "$work/rust-cf" \
    --bin network-relay-cf-masque
run build-caddy-network-relay build_caddy

collect() {
    local source=$1 name=$2 description modules module
    [[ -f $source && -s $source && -x $source ]] || die "Missing executable: $source"
    description=$(file -b -- "$source")
    case $arch in
        amd64) [[ $description == *ELF* && $description == *x86-64* ]] ;;
        arm64) [[ $description == *ELF* && $description == *aarch64* ]] ;;
    esac || die "Wrong architecture: $description"
    # Exercise the native loader as well as checking the file header.
    if [[ $name == caddy-network-relay ]]; then
        "$source" version
        modules=$("$source" list-modules)
        for module in http.handlers.network_relay dns.providers.cloudflare; do
            grep -Fxq -- "$module" <<< "$modules" || die "Missing Caddy module: $module"
        done
    else
        "$source" --version
    fi
    install -m 755 -- "$source" "$output/$name-$platform"
}
run verify-network-relay collect "$work/rust-main/$triple/release/network-relay" network-relay
run verify-cf-masque collect "$work/rust-cf/$triple/release/network-relay-cf-masque" network-relay-cf-masque
run verify-caddy-network-relay collect "$work/caddy-network-relay-bin" caddy-network-relay
(( failures == 0 )) || die "$failures step(s) failed; see $output/logs."

{
    printf 'Platform: %s\nTarget: %s\nBuilt: %s\n' "$platform" "$triple" "$(date -u +%FT%TZ)"
    printf 'Rust: %s\n' "$(rustc --version)"
    for source in "$repo" "$caddy_src" "$cloudflare_src"; do
        commit=$(git -C "$source" rev-parse --verify HEAD)
        git -C "$source" diff --quiet HEAD -- || die "Build changed tracked sources: $source"
        printf 'Source: %s\nBranch: %s\nCommit: %s\n' "$source" \
            "$(git -C "$source" symbolic-ref --short HEAD)" "$commit"
    done
    printf '\nNative GNU builds require a compatible deployment glibc.\n'
    for program in network-relay network-relay-cf-masque caddy-network-relay; do
        printf '%s: %s\n' "$program-$platform" "$(file -b -- "$output/$program-$platform")"
    done
} > "$output/MANIFEST.txt"
(
    cd -- "$output"
    sha256sum -- *-"$platform" MANIFEST.txt > SHA256SUMS
    sha256sum --check SHA256SUMS
)
rm -rf -- "${work:?}"
printf '\nAll three servers built and verified.\nArtifacts: %s\n' "$output"
