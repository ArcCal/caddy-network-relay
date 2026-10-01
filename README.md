# caddy-network-relay

一个 [Caddy](https://caddyserver.com/) 插件：把你的服务器变成苹果「网络中继」（Network Relay）用的代理服务器。iPhone、iPad、Mac **只要装一个描述文件（.mobileconfig）**，不用装任何 App，就能让指定的网站（或全部流量）经过你的服务器。

- **Caddy 负责证书和接收流量**：Let's Encrypt 证书自动申请、自动续期；TCP 443 上的 HTTP/2、HTTP/1.1 由 Caddy 自己接收；UDP 443 上的 HTTP/3 由插件在 Caddy 进程里接收（原因见[下面](#为什么-http3-由插件接收)），用的也是 Caddy 的证书，请求同样交给 Caddy 处理。
- **标准协议**：TCP 走 HTTP CONNECT（RFC 9110/9113/9114），UDP 走 CONNECT-UDP（RFC 9298），UDP 包在 HTTP/3 上用 HTTP Datagram（RFC 9297），在 HTTP/2、HTTP/1.1 上用 Capsule。和苹果描述文件里 `HTTP3RelayURL`、`HTTP2RelayURL` 的要求一致。
- **看起来就是一个普通网站**：没有正确密码的请求，得到的是你网站的回答（默认是一个“Welcome”页面）。
- 这是 [network-relay](https://github.com/ArcCal/network-relay)（Rust 写的独立程序）的 Go 重写版，功能相同，作为 Caddy 插件运行。两个项目代码互不相干；旧版的密码哈希可以直接用在这里。

> 本项目还没有在真实的 iPhone/Mac 上验证过实际流量（自动化测试和协议互通测试见 [设计文档](docs/design.md#测试)）。

---

## 目录

- [准备](#准备)
- [一键安装（Debian 12/13）](#一键安装debian-1213)
- [把描述文件装到 iPhone / iPad / Mac](#把描述文件装到-iphone--ipad--mac)
- [从旧的 network-relay（Rust 版）换过来](#从旧的-network-relayrust-版换过来)
- [日常操作](#日常操作)：加用户、删用户、改密码、升级、看日志、重新生成描述文件、卸载
- [易错点（一定要看）](#易错点一定要看)
- [已经在用 Caddy：手动集成](#已经在用-caddy手动集成)
- [配置参考](#配置参考)
- [命令参考](#命令参考)
- [为什么 HTTP/3 由插件接收](#为什么-http3-由插件接收)

---

## 准备

| 需要 | 说明 |
|---|---|
| 一台 VPS | Debian 12 或 13，x86_64 或 arm64，**至少 1 GB 内存**（编译 Caddy 要用；512 MB 的机器先加 swap），3 GB 空闲磁盘 |
| 一个域名 | 比如 `relay.example.com`。下面所有命令里的 `relay.example.com` 都换成你的 |
| 防火墙 | 云服务商的安全组/防火墙放行 **TCP 80、TCP 443、UDP 443**（UDP 443 最容易忘） |
| 本机 | Mac（或任何能用 `scp` 的电脑），用来上传源码、下载描述文件 |

### 第 1 步：DNS

在域名服务商那里加一条 **A 记录**：`relay.example.com` → 服务器的公网 IPv4。

- 用 Cloudflare 的话，这条记录必须是 **“仅 DNS”（灰色云朵）**。橙色云朵（代理）会让一切失败。
- 等它生效：在 Mac 上运行 `dig +short relay.example.com`，看到服务器的 IP 再继续。

### 第 2 步：下载源码并上传

仓库是私有的：在电脑浏览器里登录 GitHub，打开本仓库，点绿色的 **Code → Download ZIP**，得到 `caddy-network-relay-main.zip`。在 Mac 的终端里上传（`服务器IP` 换成你的）：

```bash
scp ~/Downloads/caddy-network-relay-main.zip root@服务器IP:/root/
```

- Google Cloud 的网页 SSH 可以用右上角的“上传文件”，文件会到你登录用户的家目录（比如 `/home/你的用户名/`）。
- 只能用普通用户登录的机器（Google Cloud、AWS 常见），把上面的 `root@` 换成 `你的用户名@`，文件路径换成 `/home/你的用户名/`。

---

## 一键安装（Debian 12/13）

登录服务器，切到 root：

```bash
sudo -i
```

开一个 screen，断线也不会中断（`-U` 让中文正常显示）：

```bash
screen -U
```

解压（文件在别的目录时，把路径换掉）：

```bash
cd /root && apt-get install -y unzip && unzip -o caddy-network-relay-main.zip
```

运行（`relay.example.com` 换成你的域名；`iphone` 是用户名，可以不写）：

```bash
cd /root/caddy-network-relay-main && bash deploy/install.sh --domain relay.example.com --user iphone
```

脚本会：检查系统、DNS 和端口（不对就停下，什么都不改）→ 安装依赖 → 下载 Go 并校验 → 编译带插件的 Caddy → 生成随机密码（**不显示**）→ 写 Caddyfile → 启动服务 → 等 Let's Encrypt 签发证书 → 从本机自检三种 HTTP 版本的 TCP 和 UDP → 生成两个描述文件。最后打印下载命令。

- 编译要几分钟到十几分钟，看到 `go: downloading ...` 滚动是正常的。
- 最后看到 `all checks passed` 就是成功了。
- 可选参数：`--email 你的邮箱`（Let's Encrypt 用来通知证书问题）、`--no-gfwlist`（不下载 gfwlist）。全部参数：`bash deploy/install.sh --help`。

### 生成的两个描述文件

都在 `/etc/caddy/relay/` 里，只有 root 能读，**里面有明文密码**：

| 文件 | 走中继的内容 | 设置里能不能手动关 |
|---|---|---|
| `relay.example.com-iphone.mobileconfig` | Google/Gemini/YouTube、Claude、ChatGPT、X/Grok 等（[列表](deploy/domains/google-ai-social.txt)） | 能（系统默认） |
| `relay.example.com-iphone-global.mobileconfig` | 上面这些 + Spotify、Instagram、Meta AI、NYT、Wikipedia、Pandora 等（[列表](deploy/domains/global-services.txt)）+ [gfwlist](https://github.com/gfwlist/gfwlist) 里的所有域名 | **不能**（iOS/macOS 26 起生效） |

**一台设备只装其中一个。**

### 下载到 Mac

在 **Mac 的终端**里运行（不是在服务器上）。脚本最后打印的就是这条命令：

```bash
scp root@服务器IP:/etc/caddy/relay/relay.example.com-iphone-global.mobileconfig ~/Downloads/
```

只能用普通用户登录的机器，先在服务器上把文件复制给那个用户（`你的用户名` 换掉）：

```bash
install -m 600 -o 你的用户名 /etc/caddy/relay/relay.example.com-iphone-global.mobileconfig /home/你的用户名/
```

再在 Mac 上：

```bash
scp 你的用户名@服务器IP:relay.example.com-iphone-global.mobileconfig ~/Downloads/
```

之后记得在服务器上删掉 `/home/你的用户名/` 里的那份。

---

## 把描述文件装到 iPhone / iPad / Mac

**先删掉设备上旧的中继描述文件**（设置 → 通用 → VPN 与设备管理）。同一个域名和用户名的描述文件会自动替换，但不同的描述文件会同时生效、互相抢。

- **iPhone / iPad**：在 Mac 上用“隔空投送”把文件发给手机（或用 iCloud 云盘、存到“文件” App 里点开）→ 打开“设置”，顶部出现“已下载描述文件”→ 安装 → 输入锁屏密码。
- **Mac**：双击文件 →“系统设置 → 通用 → 设备管理”（或“隐私与安全性 → 描述文件”）→ 安装。

装好后在“设置 → 通用 → VPN 与设备管理”里能看到它。打开一个列表里的网站（比如 Gemini）试一试。

**装好后删掉 Mac 上 `~/Downloads/` 里的那份**：任何拿到它的人都能用你的中继。不要用微信、邮件之类发送这个文件。

---

## 从旧的 network-relay（Rust 版）换过来

在同一台机器上，旧服务占着 443 端口。加上 `--replace-network-relay`，脚本会停用旧服务（`systemctl disable --now network-relay`，**文件不删**）：

```bash
cd /root/caddy-network-relay-main && bash deploy/install.sh --domain relay.example.com --user iphone --replace-network-relay
```

- 新安装会生成**新的随机密码**，旧的描述文件全部失效。设备上先删掉旧描述文件，再装新的。
- 证书由 Caddy 重新申请（和 certbot 的那份互不相干）。同一个域名每周最多签 5 张，别反复重装。
- 想沿用旧密码：旧版的 `password_hash`（`$argon2id$...`）可以直接放进 Caddyfile 的 `user` 行，见[加用户](#加用户)；这时旧描述文件也能继续用（域名、用户名、端口不变的话）。
- 旧版的文件（`/etc/network-relay`、`/usr/local/bin/network-relay`、certbot 证书）都还在。确认新版好用后，可以按旧版文档删掉。

---

## 日常操作

下面的命令都在服务器上、以 root 运行。

### 加用户

每台设备一个用户，停用某台设备时只删它那一行。

```bash
caddy network-relay passwd --name ipad
```

它打印两行：`password: ...`（密码，只显示这一次）和 `user ipad $argon2id$...`。把 `user ...` 那一整行加到 `/etc/caddy/Caddyfile` 里 `network_relay { ... }` 的已有 `user` 行下面：

```bash
nano /etc/caddy/Caddyfile
```

然后生效（已有的连接不断）：

```bash
systemctl reload caddy
```

给新用户生成描述文件（运行后粘贴刚才的密码，回车；不会显示）：

```bash
caddy network-relay profile --host relay.example.com --user ipad --domains-file /root/caddy-network-relay-main/deploy/domains/google-ai-social.txt --domains-file /root/caddy-network-relay-main/deploy/domains/global-services.txt --gfwlist --ui-toggle-enabled false -o /etc/caddy/relay/relay.example.com-ipad-global.mobileconfig
```

### 删用户 / 改密码

删掉 Caddyfile 里那一行（改密码就换成新 `passwd` 打印的那一行），然后 `systemctl reload caddy`。这个用户正在用的连接**立刻断开**，其他用户不受影响。改密码后要重新生成并安装描述文件。

### 升级

下载新版源码 ZIP、上传、解压（同[第 2 步](#第-2-步下载源码并上传)），然后**不带任何参数**运行：

```bash
cd /root/caddy-network-relay-main && bash deploy/install.sh
```

用户、密码、Caddyfile、描述文件都保持不变，只重新编译、替换程序、重启。新版启动失败时自动换回旧版。

### 看状态和日志

```bash
systemctl status caddy --no-pager
```

```bash
journalctl -u caddy -n 100 --no-pager
```

自检（密码从文件读，不会显示）：

```bash
caddy network-relay check --server relay.example.com --address 127.0.0.1 --user iphone --password-stdin < /etc/caddy/relay/iphone.password
```

想看设备实际发了什么请求：在 `network_relay { ... }` 里加一行 `log_requests`，`systemctl reload caddy`，然后看日志。很吵，用完删掉。

### 重新生成描述文件

服务列表或 gfwlist 更新后，删掉旧文件再生成（同一域名、同一用户的新文件安装时会替换旧的）：

```bash
caddy network-relay profile --host relay.example.com --user iphone --password-stdin --domains-file /root/caddy-network-relay-main/deploy/domains/google-ai-social.txt --domains-file /root/caddy-network-relay-main/deploy/domains/global-services.txt --gfwlist --ui-toggle-enabled false -o /etc/caddy/relay/relay.example.com-iphone-global.mobileconfig < /etc/caddy/relay/iphone.password
```

### 卸载

```bash
systemctl disable --now caddy
```

```bash
rm -rf /usr/local/bin/caddy /etc/systemd/system/caddy.service /etc/caddy /var/lib/caddy /var/www/relay /opt/caddy-network-relay /var/cache/caddy-network-relay /etc/sysctl.d/60-caddy-network-relay.conf
```

```bash
systemctl daemon-reload && deluser --system caddy
```

`/var/lib/caddy` 里有 Caddy 申请的证书；删了以后重装会重新申请（注意每周 5 张的限额）。

---

## 易错点（一定要看）

| 现象 | 原因和办法 |
|---|---|
| 脚本说“没有指向这台机器” | DNS 还没生效，或 A 记录写错。`dig +short 域名` 要等于服务器公网 IP |
| 脚本卡在“等待证书”，最后自检失败 | ① 云防火墙没放行 TCP 80/443；② Cloudflare 开了橙色云朵；③ 同一域名一周内签了 5 次以上（`journalctl -u caddy` 里有 `rateLimited`） |
| 自检 TCP 都通过，UDP/HTTP/3 失败 | 云防火墙没放行 **UDP 443**。iPhone 这时会退回 HTTP/2，能用但慢一些 |
| 端口被占用 | 机器上有 nginx/apache/旧中继。本插件要独占 TCP 80、443 和 UDP 443；旧 Rust 版用 `--replace-network-relay` |
| “系统里装了 apt 的 caddy” | 先 `apt remove caddy`。本脚本装的 Caddy 在 `/usr/local/bin/caddy`，服务名也叫 `caddy` |
| 设备上什么都不走中继 | ① 装了两份描述文件互相抢：只留一份；② 打开的网站不在列表里（基本版只有 Google/AI/X 等）；③ 密码改过但描述文件没重装 |
| 中文显示成乱码 | `screen` 没加 `-U`。已经在 screen 里：按 `Ctrl+A`，输入 `:encoding UTF-8` 回车 |
| 网页 SSH 断线 | 脚本在 screen 里继续跑。重新登录后 `sudo -i`，再 `screen -r` 回到原来的画面 |
| 编译时被杀掉（`signal: killed`） | 内存不够。加 2 GB swap：`fallocate -l 2G /swapfile && chmod 600 /swapfile && mkswap /swapfile && swapon /swapfile`，再运行 |
| `scp` 说 No such file | `scp` 要在 **Mac** 上运行；路径要完整；普通用户登录的机器先复制到家目录（见上文） |
| 自己改了 Caddyfile 后 reload 失败 | `caddy validate --config /etc/caddy/Caddyfile` 看哪里错。失败的 reload 不影响正在运行的旧配置 |
| 把站点地址改成只有域名 | **不要**。必须是 `relay.example.com, :443`：设备的 CONNECT 请求以目标网站（比如 `www.google.com:443`）作主机名，只匹配域名的站点收不到它们 |
| 把密码或描述文件贴给别人（包括 AI 聊天） | 别人就能用你的中继。泄露了就[改密码](#删用户--改密码) |

---

## 已经在用 Caddy：手动集成

### 直接下载编译好的程序

每次推送到 `main`，GitHub Actions 都会测试并编译；打一个版本标签还会生成 Release。在仓库页面 **Releases** 里下载 `caddy-network-relay-<版本>-linux-amd64.tar.gz`（x86_64 服务器）或 `-linux-arm64.tar.gz`（ARM 服务器；`-darwin-arm64` 是给 Mac 上跑 `check` 用的），解压得到一个 `caddy`，放到 `/usr/local/bin/caddy` 即可，不需要在服务器上编译。仓库是私有的，所以要在浏览器里登录后下载，再上传到服务器。

发布一个版本：在本地 `git tag v1.0.0 && git push origin v1.0.0`，或者在 GitHub 的 **Actions → release → Run workflow** 里填一个已有的标签。

### 编译

需要 Go 1.26（`go.mod` 里写着具体版本，`GOTOOLCHAIN=auto` 时会自动下载）：

```bash
go build -tags http2legacy -o caddy ./cmd/caddy
```

`cmd/caddy` 是 Caddy 官方的标准模块加上本插件。用 xcaddy 也可以（仓库是私有的，用本地目录）：

```bash
XCADDY_GO_BUILD_FLAGS="-tags http2legacy" xcaddy build --with github.com/arccal/caddy-network-relay=./caddy-network-relay
```

- `-tags http2legacy`：用 Go 1.27 及以后编译时必须加，否则 HTTP/2 上的 UDP（扩展 CONNECT）只有在环境变量 `GODEBUG=http2xconnect=1` 下才打开（插件会在日志里警告）。用 Go 1.26 编译时加不加都一样。
- 在 systemd 单元里加 `Environment=GODEBUG=http2xconnect=1` 总是没有坏处（[deploy/caddy.service](deploy/caddy.service) 就是这样）。

### Caddyfile

见 [deploy/Caddyfile.example](deploy/Caddyfile.example)：

```caddyfile
relay.example.com, :443 {
	network_relay {
		user iphone $argon2id$v=19$m=19456,t=2,p=1$...
	}
	root * /var/www/relay
	file_server
}
```

要点：

1. **站点地址必须带上 `:443`**（或者只写 `:443`，再用 `tls` 指定证书）。原因见上面的易错点表。
2. `network_relay` 会自动排在站点里所有其他指令之前（不需要 `order`）。没有正确密码的请求交给后面的指令（你的网站）；没有密码的 CONNECT 请求得到 405（和普通的 Caddy 静态网站一样），不会交给后面的指令，以免某个指令回 2xx 被当成“隧道已建立”。
3. 插件**自动接管这个站点所在服务器的 HTTP/3**（Caddy 自带的 HTTP/3 对这个服务器关闭，改由插件在同一个 UDP 端口提供），不需要额外配置。如果你在 `servers { protocols ... }` 里去掉了 `h3`，插件也不提供 HTTP/3，这时描述文件要加 `--no-http3`。
4. 同一个 Caddy 上的其他网站照常工作。但如果设备经过中继访问**同一台 Caddy 上的其他域名**，CONNECT 会被那个域名的站点接收而失败：把这些域名加到描述文件的 `--exclude-domain`。
5. reload 时，用户和密码没变的设备连接不断；删除的用户、改了密码的用户立刻断开。

---

## 配置参考

`network_relay` 指令（JSON 里是 `"handler": "network_relay"`）：

| 选项 | 默认 | 说明 |
|---|---|---|
| `user <名字> <哈希>` | 无 | 一个用户；可以写多行。名字 1–64 个字母、数字、`-` `_` `.`，不以 `.` 开头。哈希是 `caddy network-relay passwd` 打印的 Argon2id 哈希（旧 Rust 版的也行），也接受 bcrypt 和 `caddy hash-password` 的输出 |
| `udp_template <路径>` | `/.well-known/masque/udp/{target_host}/{target_port}/` | CONNECT-UDP 的 URI 模板路径（RFC 9298）。改了的话描述文件要用 `--udp-template` 写同样的值。支持 `{var}` 和 `{?a,b}` / `{&a,b}` 形式 |
| `blocked_destinations [<CIDR>...]` | 本机、私有网络、链路本地（含云元数据 169.254.169.254）、组播、保留和文档地址等 | 设备不能访问的地址。域名解析出的每个地址都检查，IPv4 映射的 IPv6 地址按 IPv4 检查。写了就**替换**默认列表；只写选项名不写地址表示不封任何地址（**危险**：设备能访问服务器本机上只监听 127.0.0.1 的服务） |
| `blocked_ports [<端口>...]` | `25` | 设备不能访问的端口（TCP 和 UDP）。25 是发邮件的端口，封掉防止被用来发垃圾邮件 |
| `connect_timeout <时长>` | `10s` | 连接目标 TCP 的超时，1s–2m |
| `udp_idle_timeout <时长>` | `5m` | UDP 流两个方向都没有包多久后关闭，2m–1h |
| `max_tunnels <数量>` | `20000` | 所有用户加起来同时转发的 TCP 连接和 UDP 流上限，超过时回 503 |
| `log_requests` | 关 | 每个代理请求记一行日志（含请求头，密码只显示用户名） |

拒绝时的状态码和 `Proxy-Status`（RFC 9209）：

| 情况 | 状态 | `Proxy-Status` 的 `error=` |
|---|---|---|
| 目标格式不对；CONNECT-UDP 带了内容头或请求体；HTTP/1.1 的 CONNECT-UDP 不是 GET 或 `Connection` 里没有 `Upgrade` | 400 | `http_request_error` |
| CONNECT-UDP 的路径不是 `udp_template` | 404 | — |
| 端口被封；用户刚被删除 | 403 | `http_request_denied` |
| 地址被封 | 403 | `destination_ip_prohibited` |
| 域名解析失败 / 超时（5 秒） | 502 / 504 | `dns_error` / `dns_timeout` |
| 连接被拒绝 / 超时 / 不可达 | 502 / 504 / 502 | `connection_refused` / `connection_timeout` / `destination_unavailable` |
| 超过 `max_tunnels` | 503 | `connection_limit_reached` |

隧道建立后出了问题（目标断开、目标端口不可达、设备发来畸形数据），按 RFC 9114 / 9297 / 9298 复位流或关闭连接；每种情况用哪个错误码，见[设计文档](docs/design.md)。

只有通过了认证的请求才会看到这些；没有密码的请求只看到网站。

---

## 命令参考

都是 `caddy network-relay <命令>`，每个都有 `--help`。

### `passwd`

```bash
caddy network-relay passwd --name iphone
```

生成 144 位随机密码和它的哈希。`--stdin`：从标准输入读你自己的密码（至少 12 个字符），只打印 `user` 行。

### `profile`

```bash
caddy network-relay profile --host relay.example.com --user iphone
```

| 参数 | 说明 |
|---|---|
| `--host`、`--user` | 必填 |
| `--password` / `--password-stdin` | 不写时提示输入（不显示），推荐；`--password-stdin` 从标准输入读第一行 |
| `--port` | 不是 443 时写 |
| `--match-domain D` | 这个域名和子域名走中继，可重复。**所有 `--match-*`、`--domains-file`、`--gfwlist` 都不写时，全部流量走中继** |
| `--domains-file F` | 文件里每行一个域名，`#` 后面是注释，可重复 |
| `--gfwlist` / `--gfwlist-file F` | 加入 gfwlist 的域名（运行时下载 / 用已下载的文件）。正则、IP 和 `@@` 例外规则丢弃；只限某个路径的规则扩大到整个域名；运行结束时打印各类数量 |
| `--exclude-domain D` | 不走中继，可重复。用了列表时，中继自己的域名自动排除 |
| `--match-fqdn`、`--exclude-fqdn` | 精确匹配主机名，不含子域名（iOS 18.4、macOS 15.4 起） |
| `--ui-toggle-enabled true\|false` | 设置里能否手动关闭中继（iOS/macOS 26 起）；不写时系统默认 true |
| `--allow-dns-failover true\|false` | 能否回退到系统默认 DNS（iOS/macOS 26 起）；不写时系统默认 false |
| `--relay-uuid` | 托管 App 路由用（user enrollment 必填，macOS 不支持） |
| `--name` | 设置里显示的名字 |
| `--udp-template` | 服务器改过 `udp_template` 时写同样的值 |
| `--no-http3` / `--no-http2` | 只写一种中继 URL |
| `-o` | 输出文件，默认 `域名-用户.mobileconfig`；权限 600，原子写入，不覆盖符号链接 |

描述文件的标识符是 `com.github.arccal.network-relay.<域名>.<用户名>`（和旧 Rust 版相同），所以同一域名、同一用户的新描述文件安装时替换旧的。

### `check`

```bash
caddy network-relay check --server relay.example.com --user iphone
```

像设备一样测试：HTTP/3、HTTP/2、HTTP/1.1 上各测一次 TCP（经 CONNECT 向 `--tcp-target`，默认 `example.com:80`，发一个 HTTP 请求）和 UDP（经 CONNECT-UDP 向 `--udp-target`，默认 `1.1.1.1:53`，查一次 DNS），再确认没有密码的 CONNECT 打不开隧道。`--address IP` 直接连这个地址（比如 `127.0.0.1`，从服务器本机测）。全部通过时退出码为 0。在 Mac 上也能用（要先编译；先退出 Clash 之类的代理软件）。

---

## 为什么 HTTP/3 由插件接收

苹果设备经 HTTP/3 中继 UDP 时，UDP 包放在 QUIC DATAGRAM 里（RFC 9297 的 HTTP Datagram）。Caddy 自带的 HTTP/3 服务器没有打开这个功能，也没有提供打开它的配置，所以插件对含有 `network_relay` 的服务器关掉 Caddy 自带的 HTTP/3，在同一个 UDP 端口上用 quic-go（Caddy 自己用的同一个库）提供打开了 Datagram 的 HTTP/3：

- 证书来自 Caddy 的 TLS 设置（自动 HTTPS、续期都照常）；
- 收到的每个请求都交给同一个 Caddy 服务器处理，路由、日志、网站和 TCP 上完全一样；
- 配置 reload 时 UDP 端口不关闭，已有连接留在旧配置上，新连接用新配置。

HTTP/2 上的 UDP 要用扩展 CONNECT（RFC 8441），Go 的 HTTP/2 实现默认关闭它，插件在启动时打开（细节见[设计文档](docs/design.md)）。

更多：[设计文档](docs/design.md)（协议细节、规范对照、已知限制、测试）、[部署细节](docs/deploy.md)（脚本写了哪些文件、手动升级、换域名）、[域名列表说明](deploy/domains/README.md)。
