#!/usr/bin/env bash
# Installs or upgrades Caddy with the network_relay plugin on Debian 12/13
# or Ubuntu 22.04/24.04 (x86_64 or arm64), from the source directory this
# script is in.
#
# First install:
#     sudo bash deploy/install.sh --domain relay.example.com [--user iphone] [--email you@example.com]
# Upgrade (rebuild from this source; users, passwords and Caddyfile stay):
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
# Everything it writes is listed in docs/deploy.md. Messages are in Chinese.
set -Eeuo pipefail
export LANG=C.UTF-8 LC_ALL=C.UTF-8

GO_VERSION=1.26.8
# h1 hashes of golang.org/toolchain@v0.0.1-go$GO_VERSION.linux-* from
# sum.golang.org.
declare -A GO_SUMS=(
    [amd64]='h1:ZOmGe1OnfREDMIdb1Qi4G9JSuDPBLGExZMQ4nis1RXM='
    [arm64]='h1:sYL/O6MqS68ML0kjsQ36WoYIpJqkw60TxizWUYUKQMc='
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
die() { printf '错误：%s\n' "$*" >&2; exit 1; }
run_apt() { DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=1800 "$@"; }

SRC=$(cd "$(dirname "$0")/.." && pwd)
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
        *) die "不认识的参数 $1（--help 查看用法）" ;;
    esac
done

# ---- checks that change nothing ----
[[ $EUID == 0 || -n $ROOT ]] || die '请用 root 运行：先 sudo -i，再运行本脚本。'
grep -q '^module github.com/arccal/caddy-network-relay$' "$SRC/go.mod" 2>/dev/null \
    || die "找不到源码：请在解压后的 caddy-network-relay 目录里运行 bash deploy/install.sh。"
if [[ -z $ROOT ]]; then
    . /etc/os-release
    case "${ID:-} ${VERSION_ID:-}" in
        "debian 12"|"debian 13"|"ubuntu 22.04"|"ubuntu 24.04") ;;
        *) die "只支持 Debian 12/13 和 Ubuntu 22.04/24.04（这台是 ${PRETTY_NAME:-未知系统}）。" ;;
    esac
fi
case $(uname -m) in
    x86_64) GOARCH=amd64 ;;
    aarch64) GOARCH=arm64 ;;
    *) die "只支持 x86_64 和 arm64（这台是 $(uname -m)）。" ;;
esac

UPGRADE=0
if [[ -e $CADDYFILE ]]; then
    grep -qxF "$MARKER" "$CADDYFILE" || die "$CADDYFILE 已存在，但不是本脚本生成的。为免覆盖你的配置，脚本不处理这种情况；见 docs/deploy.md 的“手动升级”。"
    UPGRADE=1
    old_domain=$(sed -n 's/^# domain: //p' "$CADDYFILE")
    old_user=$(sed -n 's/^# user: //p' "$CADDYFILE")
    [[ -z $DOMAIN || $DOMAIN == "$old_domain" ]] || die "这台机器已经装好了 $old_domain；不能改成 $DOMAIN。要换域名，见 docs/deploy.md。"
    [[ -z $RELAY_USER || $RELAY_USER == "$old_user" ]] || die "已有用户 $old_user；加用户见 docs/deploy.md，不要用 --user 改。"
    DOMAIN=$old_domain RELAY_USER=$old_user
else
    [[ -n $DOMAIN ]] || die '第一次安装要写域名：bash deploy/install.sh --domain relay.example.com'
fi
DOMAIN=${DOMAIN,,}
DOMAIN=${DOMAIN%.}
RELAY_USER=${RELAY_USER:-iphone}
[[ $DOMAIN =~ ^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$ ]] || die "$DOMAIN 不是域名。"
[[ $RELAY_USER =~ ^[A-Za-z0-9_-][A-Za-z0-9._-]{0,63}$ ]] || die "用户名 $RELAY_USER 只能用字母、数字、- _ .，不能以 . 开头。"
[[ -z $EMAIL || $EMAIL =~ ^[^@[:space:]]+@[^@[:space:]]+\.[^@[:space:]]+$ ]] || die "$EMAIL 不是邮箱地址。"

if dpkg -s caddy >/dev/null 2>&1; then
    die '系统里装了 apt 的 caddy 软件包，会和本脚本装的 Caddy 抢端口和服务名。先 apt remove caddy（它的 /etc/caddy/Caddyfile 会保留），再运行。'
fi
if systemctl is-active --quiet network-relay 2>/dev/null; then
    ((REPLACE_OLD)) || die '旧的 network-relay（Rust 版）正在运行，占着 443 端口。确认要换成 Caddy 版就加上 --replace-network-relay 再运行（只停用旧服务，不删它的文件）。'
fi

# Who holds the ports, other than the Caddy this script manages.
port_users() {
    ss -Hlnptu 2>/dev/null | awk '($1=="tcp" && ($5 ~ /:(80|443)$/)) || ($1=="udp" && $5 ~ /:443$/) {print $1, $5, $7}' \
        | grep -v '"caddy"' | grep -v '"network-relay"' || true
}
busy=$(port_users)
[[ -z $busy ]] || die "端口被别的程序占用了（需要 TCP 80、443 和 UDP 443）：
$busy"

if ((DNS_CHECK)) && ((!UPGRADE)); then
    public_ip=$(curl -4 -fsS --max-time 10 https://api.ipify.org || curl -4 -fsS --max-time 10 https://ifconfig.me || true)
    dns_ips=$(getent ahostsv4 "$DOMAIN" | awk '{print $1}' | sort -u | tr '\n' ' ' || true)
    say "本机公网 IPv4：${public_ip:-查询失败}；$DOMAIN 解析到：${dns_ips:-无}"
    [[ -n $dns_ips ]] || die "$DOMAIN 还没有 DNS 记录：先加一条 A 记录指向 ${public_ip:-这台机器的公网 IP}（Cloudflare 要选“仅 DNS”，灰色云朵）。"
    if [[ -n $public_ip && " $dns_ips " != *" $public_ip "* ]]; then
        die "$DOMAIN 没有指向这台机器（$public_ip）。改好 DNS、等它生效后再运行。什么都没改。"
    fi
fi

# ---- install ----
say "==> 安装依赖软件包"
run_apt update -qq
run_apt install -y -qq ca-certificates curl python3 iproute2 >/dev/null

if ((REPLACE_OLD)) && systemctl is-active --quiet network-relay 2>/dev/null; then
    say "==> 停用旧的 network-relay 服务（文件保留在原处）"
    systemctl disable --now network-relay
fi

say "==> 准备 Go $GO_VERSION（只用于编译，装在 $OPT/go）"
GO=$OPT/go/bin/go
if [[ -n ${RELAY_TEST_GO:-} ]]; then
    GO=$RELAY_TEST_GO
elif [[ ! -x $GO || $("$GO" env GOVERSION 2>/dev/null) != "go$GO_VERSION" ]]; then
    # The official toolchain, from the Go module proxy (which the build
    # needs anyway), checked against the hash in Go's checksum database.
    module=golang.org/toolchain@v0.0.1-go$GO_VERSION.linux-$GOARCH
    mkdir -p "$CACHE" "$OPT"
    zip=$CACHE/go-toolchain.zip
    curl -fsSL --max-time 900 -o "$zip" "https://proxy.golang.org/golang.org/toolchain/@v/v0.0.1-go$GO_VERSION.linux-$GOARCH.zip" \
        || die '下载 Go 失败：这台机器要能访问 proxy.golang.org。'
    rm -rf "$OPT/go.new"
    python3 - "$zip" "$OPT/go.new" "$module" "${GO_SUMS[$GOARCH]}" <<'PY' || die 'Go 工具链校验失败：下载不完整或被篡改。'
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
    rm -rf "$OPT/go" "$zip"
    mv "$OPT/go.new" "$OPT/go"
fi

say "==> 编译 Caddy 和 network_relay 插件（小内存机器要几分钟）"
mkdir -p "$CACHE"
jobs=()
mem_kb=$(awk '/^MemTotal:/ {print $2}' /proc/meminfo 2>/dev/null || echo 0)
((mem_kb == 0 || mem_kb > 1800000)) || jobs=(-p 1)
(
    cd "$SRC"
    env GOTOOLCHAIN=local GOFLAGS=-mod=readonly CGO_ENABLED=0 \
        GOPATH="$CACHE/gopath" GOMODCACHE="$CACHE/gomod" GOCACHE="$CACHE/gocache" \
        "$GO" build "${jobs[@]}" -tags http2legacy -trimpath -ldflags '-s -w' -o "$CACHE/caddy.new" ./cmd/caddy
) || die '编译失败（上面是原因）。内存太小时先加 swap；网络不通时检查能否访问 proxy.golang.org。'
"$CACHE/caddy.new" list-modules 2>/dev/null | grep -qx 'http.handlers.network_relay' || die '编译出的 Caddy 里没有 network_relay 模块。'

if ! getent passwd caddy >/dev/null; then
    say "==> 创建系统用户 caddy"
    adduser --system --group --home /var/lib/caddy --shell /usr/sbin/nologin caddy >/dev/null
fi
mkdir -p "$ETC" "$SECRETS" "$WWW" "$DATA" "$(dirname "$BIN")" "$(dirname "$UNIT")" "$(dirname "$SYSCTL")"
chmod 700 "$SECRETS"
chown caddy:caddy "$DATA"
[[ -e $WWW/index.html ]] || printf '<!doctype html>\n<title>Welcome</title>\n<h1>Welcome</h1>\n' >"$WWW/index.html"

backup=$CACHE/backup.$(date +%Y%m%d-%H%M%S)
mkdir -p "$backup"
for f in "$BIN" "$CADDYFILE" "$UNIT"; do
    [[ -e $f ]] && cp -p "$f" "$backup/"
done
was_active=0
systemctl is-active --quiet caddy 2>/dev/null && was_active=1

password_file=$SECRETS/$RELAY_USER.password
# A first install that stops before the service starts leaves nothing
# behind, so the next run is a first install again.
started=0
undo_fresh() {
    if (($? != 0 && !UPGRADE && !started)); then
        rm -f "$CADDYFILE" "$password_file"
    fi
}
trap undo_fresh EXIT
if ((!UPGRADE)); then
    say "==> 生成用户 $RELAY_USER 的随机密码（不会显示，保存在 $password_file）"
    out=$("$CACHE/caddy.new" network-relay passwd --name "$RELAY_USER")
    password=$(sed -n 's/^password: //p' <<<"$out")
    user_line=$(grep '^user ' <<<"$out")
    [[ -n $password && -n $user_line ]] || die '生成密码失败。'
    (umask 077 && printf '%s\n' "$password" >"$password_file")
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

say "==> 检查配置"
if ! runuser -u caddy -- env HOME=/var/lib/caddy "$CACHE/caddy.new" validate --config "$CADDYFILE" --adapter caddyfile \
    >"$CACHE/validate.log" 2>&1; then
    tail -20 "$CACHE/validate.log" >&2
    die "配置检查没通过（上面是原因）。服务没有动，旧版本（如果有）照常运行。"
fi

# quic-go wants large UDP buffers; only raise the limits, never lower them.
want=7500000
{
    echo '# UDP buffers for HTTP/3 (quic-go); written by caddy-network-relay install.sh'
    for key in net.core.rmem_max net.core.wmem_max; do
        current=$(sysctl -n "$key" 2>/dev/null || echo 0)
        ((current >= want)) || echo "$key = $want"
    done
} >"$SYSCTL"
sysctl -p "$SYSCTL" >/dev/null 2>&1 || say "（这台机器不让改 UDP 缓冲区，继续用系统默认值。）"

if command -v ufw >/dev/null && ufw status 2>/dev/null | grep -q '^Status: active'; then
    say "==> 在 ufw 里放行 TCP 80、TCP 443、UDP 443"
    ufw allow 80/tcp >/dev/null
    ufw allow 443/tcp >/dev/null
    ufw allow 443/udp >/dev/null
fi

say "==> 安装并启动服务"
started=1
install -m 755 "$CACHE/caddy.new" "$BIN.new"
mv -f "$BIN.new" "$BIN"
install -m 644 "$SRC/deploy/caddy.service" "$UNIT"
systemctl daemon-reload
systemctl enable caddy >/dev/null 2>&1
systemctl restart caddy

rollback() {
    say "服务没能启动，正在恢复安装前的状态。日志："
    journalctl -u caddy -n 40 --no-pager 2>/dev/null || true
    for f in "$BIN" "$CADDYFILE" "$UNIT"; do
        if [[ -e $backup/$(basename "$f") ]]; then
            cp -p "$backup/$(basename "$f")" "$f"
        elif ((!UPGRADE)); then
            rm -f "$f"
        fi
    done
    systemctl daemon-reload
    if ((was_active)); then
        systemctl restart caddy || true
    else
        systemctl disable --now caddy >/dev/null 2>&1 || true
    fi
    die "安装失败，已恢复。$( ((UPGRADE)) && echo '旧版本继续运行。' || echo '可以修好原因后重新运行。')"
}
sleep "${RELAY_TEST_SLEEP:-2}"
systemctl is-active --quiet caddy || rollback

say "==> 等待证书并自检（第一次装要等 Let's Encrypt 签发，最多 3 分钟）"
check_ok=0
for _ in $(seq "${RELAY_TEST_TRIES:-36}"); do
    if "$BIN" network-relay check --server "$DOMAIN" --address 127.0.0.1 --user "$RELAY_USER" \
        --password-stdin --timeout 10s <"$password_file" >"$CACHE/check.log" 2>&1; then
        check_ok=1
        break
    fi
    systemctl is-active --quiet caddy || rollback
    sleep "${RELAY_TEST_SLEEP:-5}"
done
cat "$CACHE/check.log"

say "==> 生成描述文件"
lists=("$SRC/deploy/domains/google-ai-social.txt")
profile=$SECRETS/$DOMAIN-$RELAY_USER.mobileconfig
global=$SECRETS/$DOMAIN-$RELAY_USER-global.mobileconfig
if [[ ! -e $profile ]]; then
    "$BIN" network-relay profile --host "$DOMAIN" --user "$RELAY_USER" --password-stdin \
        --domains-file "${lists[0]}" -o "$profile" <"$password_file"
fi
if [[ ! -e $global ]]; then
    gfw=()
    ((GFWLIST)) && gfw=(--gfwlist)
    "$BIN" network-relay profile --host "$DOMAIN" --user "$RELAY_USER" --password-stdin \
        --domains-file "${lists[0]}" --domains-file "$SRC/deploy/domains/global-services.txt" "${gfw[@]}" \
        --ui-toggle-enabled false --name "$DOMAIN（全球服务）" -o "$global" <"$password_file" \
        || say "（global 描述文件没生成：多半是 gfwlist 下载失败。可以加 --no-gfwlist 重新运行。）"
fi

host_ip=$(tailscale ip -4 2>/dev/null | head -1 || true)
host_ip=${host_ip:-${public_ip:-这台机器的IP}}
cat <<MSG

完成。Caddy 和 network_relay 已经在运行，开机自动启动。
  配置：$CADDYFILE      日志：journalctl -u caddy -n 100 --no-pager
  描述文件（含密码，只有 root 能读）：
    $profile           Google/AI/X 等走中继
    $global    指定服务 + gfwlist 走中继，设置里不能手动关
  下载到 Mac（在 Mac 的终端里运行）：
    scp root@$host_ip:$global ~/Downloads/
  装到设备之前：先删掉设备上旧的中继描述文件。装好后删掉 Mac 上的副本。
MSG
if ((!check_ok)); then
    cat <<MSG

注意：本机自检没有全部通过（见上面的 FAIL 行）。服务保持运行，便于排查：
  - 证书还没签好：等一两分钟后运行
      $BIN network-relay check --server $DOMAIN --address 127.0.0.1 --user $RELAY_USER --password-stdin < $password_file
  - 云服务商的防火墙/安全组要放行 TCP 80、TCP 443、UDP 443。
MSG
    exit 1
fi
