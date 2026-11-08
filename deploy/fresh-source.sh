#!/usr/bin/env bash
# Source-only helpers: repository inputs are never taken from a saved checkout.
CADDY_SOURCE_WORK=
CADDY_BUILD_WORK=
CADDY_BUILD_JOBS=1
# shellcheck source=deploy/run-build-child.sh
source "${BASH_SOURCE[0]%/*}/run-build-child.sh"
caddy_run_build() {
    local status
    if relay_run_build_child "$@"; then return 0; else status=$?; fi
    if (( status > 128 )); then exit "$status"; fi
    return "$status"
}
caddy_build_in_source() {
    local source=$1
    shift
    cd -- "$source" || return
    "$@"
}
caddy_clone_latest() {
    local tracing=0 status
    case $- in *x*) tracing=1; set +x ;; esac
    if caddy_clone_latest_impl "$@"; then status=0; else status=$?; fi
    (( tracing == 0 )) || set -x
    return "$status"
}
caddy_clone_with_token() {
    GIT_TERMINAL_PROMPT=0 GIT_CONFIG_COUNT=2 \
        GIT_CONFIG_KEY_0=credential.helper GIT_CONFIG_VALUE_0='' \
        GIT_CONFIG_KEY_1=http.https://github.com/.extraheader \
        GIT_CONFIG_VALUE_1="Authorization: Basic $header" git "${args[@]}"
}
caddy_clone_latest_impl() {
    unset GIT_DIR GIT_WORK_TREE GIT_COMMON_DIR GIT_INDEX_FILE GIT_OBJECT_DIRECTORY GIT_ALTERNATE_OBJECT_DIRECTORIES
    local destination=$1 header
    local remote=https://github.com/ArcCal/caddy-network-relay.git
    local args=(-c protocol.file.allow=never -c core.hooksPath=/dev/null clone --template= --branch main -- "$remote" "$destination")
    if command -v gh >/dev/null; then
        caddy_run_build env GIT_TERMINAL_PROMPT=0 git -c 'credential.helper=!gh auth git-credential' "${args[@]}" && return 0
    elif caddy_run_build env GIT_TERMINAL_PROMPT=0 git "${args[@]}"; then
        return 0
    fi
    if [[ -n ${CADDY_NETWORK_RELAY_TOKEN:-} ]]; then
        # Only a fresh destination inside the caller's private workspace is used.
        rm -rf -- "${destination:?}"
        header=$(printf 'x-access-token:%s' "$CADDY_NETWORK_RELAY_TOKEN" | base64 | tr -d '\n') || return
        caddy_run_build caddy_clone_with_token && return 0
    fi
    printf 'Cannot download latest ArcCal/caddy-network-relay main; configure Git credentials or CADDY_NETWORK_RELAY_TOKEN. No saved source is used.\n' >&2
    return 1
}
caddy_latest_entry() {
    local entry=$1 commit interactive_python_missing=0
    local bootstrap_packages=(git ca-certificates procps)
    shift
    trap caddy_source_cleanup EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM
    trap 'exit 129' HUP
    if { : </dev/tty; } 2>/dev/null && ! command -v python3 >/dev/null; then
        interactive_python_missing=1
        bootstrap_packages+=(python3)
    fi
    if ! command -v git >/dev/null || ! command -v ps >/dev/null || (( interactive_python_missing )); then
        [[ $EUID == 0 ]] || { printf 'Git, ps, and Python 3 for interactive use are required to fetch and supervise current build source.\n' >&2; return 1; }
        DEBIAN_FRONTEND=noninteractive apt-get -o Acquire::Retries=3 update || return
        DEBIAN_FRONTEND=noninteractive apt-get -o Acquire::Retries=3 install -y --no-install-recommends "${bootstrap_packages[@]}" || return
    fi
    caddy_new_sources || return
    trap caddy_source_cleanup EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM
    trap 'exit 129' HUP
    commit=$(git -C "$REPLY" rev-parse --verify HEAD) || return
    printf '%s %s\n' "$$" "$commit" > "$CADDY_SOURCE_WORK/.fresh-owner" || return
    [[ -f $REPLY/$entry ]] || { printf 'Latest source has no %s.\n' "$entry" >&2; return 1; }
    # The native caller keeps its DNS credential shell-local while Git runs.
    # Only the fresh trusted installer receives it; it removes the export again.
    if [[ $entry == install-caddy-network-relay-native-build-cloudflare-dns.sh ]]; then
        export CF_API_TOKEN="${cf_token:-}"
    fi
    # Install fallback cleanup before parsing the freshly fetched entry point.
    # A valid script replaces it with its normal transactional cleanup.
    exec "$BASH" -c '
        relay_fresh_stage=$2
        relay_fresh_cleanup() {
            local status=$?
            find -P "$relay_fresh_stage" -type d -exec chmod u+w -- {} +
            rm -rf -- "$relay_fresh_stage"
            exit "$status"
        }
        trap relay_fresh_cleanup EXIT
        source "$0" "$@"
    ' "$REPLY/$entry" --fresh-source-run "$CADDY_SOURCE_WORK" "$commit" "$@"
}
caddy_accept_source() {
    local source=$1 directory=$2 commit=$3 owner
    [[ ${directory%/*} == /tmp && ${directory##*/} =~ ^[0-9]{8}-[0-9]{6}\.[[:alnum:]]+$ &&
       -d $directory && ! -L $directory && -f $directory/.fresh-owner && ! -L $directory/.fresh-owner &&
       $source == "$directory/source" && $commit =~ ^[0-9a-f]{40}$ ]] || return 1
    owner=$(cat "$directory/.fresh-owner") || return
    [[ $owner == "$$ $commit" ]] || return 1
    CADDY_SOURCE_WORK=$directory
    trap caddy_source_cleanup EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM
    trap 'exit 129' HUP
    [[ $(git -C "$source" rev-parse --verify HEAD) == "$commit" &&
       $(git -C "$source" rev-parse --verify refs/remotes/origin/main) == "$commit" ]] || return 1
    git -C "$source" diff --quiet HEAD -- || return
    caddy_memory_jobs /proc/meminfo /proc/self/cgroup /proc/self/mountinfo
}
caddy_new_sources() {
    caddy_memory_jobs /proc/meminfo /proc/self/cgroup /proc/self/mountinfo || return
    CADDY_SOURCE_WORK=$(mktemp -d "/tmp/$(date +%Y%m%d-%H%M%S).XXXXXX") || return
    if ! caddy_clone_latest "$CADDY_SOURCE_WORK/source"; then
        rm -rf -- "$CADDY_SOURCE_WORK"
        CADDY_SOURCE_WORK=
        return 1
    fi
    REPLY=$CADDY_SOURCE_WORK/source
    printf 'Latest source: %s (%s)\n' "$REPLY" "$(git -C "$REPLY" rev-parse --verify HEAD)"
}
caddy_build_parent() {
    local candidate need=${2:-3145728} free
    for candidate in "$1" /var/tmp "$HOME"; do
        [[ -d $candidate && -w $candidate ]] || continue
        case $(stat -f -c %T "$candidate") in tmpfs|ramfs) continue ;; esac
        free=$(df -Pk -- "$candidate" | awk 'NR == 2 {print $4}')
        if [[ $free =~ ^[0-9]+$ ]] && (( free >= need )); then REPLY=$candidate; return 0; fi
    done
    printf 'A disk-backed directory with enough free space is required for the private compiler workspace; /tmp tmpfs is not used for compiler caches.\n' >&2
    return 1
}
caddy_new_build_work() {
    caddy_build_parent "$1" || return
    CADDY_BUILD_WORK=$(mktemp -d "$REPLY/build.$(date +%Y%m%d-%H%M%S).XXXXXX") || return
    mkdir -m 700 "$CADDY_BUILD_WORK/tmp" || return
    export TMPDIR=$CADDY_BUILD_WORK/tmp GOTMPDIR=$CADDY_BUILD_WORK/tmp
    export TEST_TELEMETRY_DIR=$CADDY_BUILD_WORK/go-telemetry
    export GOPATH=$CADDY_BUILD_WORK/gopath GOMODCACHE=$CADDY_BUILD_WORK/gomod GOCACHE=$CADDY_BUILD_WORK/gocache
    export GOTOOLCHAIN=local GOWORK=off GOENV=off GOFLAGS=''
    unset GOCACHEPROG GOROOT
}
caddy_source_cleanup() {
    local result=0 directory
    for directory in "${CADDY_BUILD_WORK:-}" "${CADDY_SOURCE_WORK:-}"; do
        if [[ -n $directory ]]; then
            find -P "$directory" -type d -exec chmod u+w -- {} + || result=1
            rm -rf -- "$directory" || result=1
        fi
    done
    return "$result"
}

caddy_cgroup_headroom() {
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


caddy_memory_jobs() {
    local available swap headroom
    available=$(awk '/^(MemAvailable|SwapFree):/ {n += $2} END {print n+0}' "${1:-/proc/meminfo}") || return
    swap=$(awk '/^SwapFree:/ {n = $2} END {print n+0}' "${1:-/proc/meminfo}")
    headroom=$(caddy_cgroup_headroom "${2:-/proc/self/cgroup}" "${3:-/proc/self/mountinfo}" "$((available - swap))" "$swap") || return 1
    if [[ $headroom =~ ^[0-9]+$ ]] && (( headroom < available )); then available=$headroom; fi
    if [[ ! $available =~ ^[0-9]+$ ]] || (( available < 640 * 1024 )); then
        printf 'The Caddy build needs at least 640 MiB available RAM plus usable free swap within any cgroup limit. Add or increase swap on disk (not /tmp tmpfs), or raise the memory limit.\n' >&2
        return 1
    fi
    CADDY_BUILD_JOBS=$((available / 1048576))
    (( CADDY_BUILD_JOBS >= 1 )) || CADDY_BUILD_JOBS=1
    (( CADDY_BUILD_JOBS <= 2 )) || CADDY_BUILD_JOBS=2
}
