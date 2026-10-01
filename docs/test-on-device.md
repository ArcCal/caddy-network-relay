# 部署并在真机上测试

从零开始：一台 Ubuntu 22.04/24.04 或 Debian 12/13 的 x86_64 VPS，到 iPhone/Mac 实际走中继上网。每一步都写了“应该看到什么”和“不对怎么办”。全程大约 30 分钟，其中编译 5–15 分钟。

下文的 `relay.example.com` 换成你的域名，`服务器IP` 换成 VPS 的公网 IPv4。

## 0. 准备

| 需要 | 检查方法 |
|---|---|
| VPS：Ubuntu 22.04/24.04 或 Debian 12/13，x86_64，≥ 1 GB 内存，≥ 3 GB 空闲磁盘 | 登录后 `cat /etc/os-release \| head -2`、`free -m`、`df -h /` |
| 域名的 A 记录指向 VPS | 在 Mac 上 `dig +short relay.example.com`，输出等于服务器 IP。Cloudflare 必须是“仅 DNS”（灰色云朵） |
| 云防火墙放行 TCP 80、TCP 443、UDP 443 | 云服务商控制台的安全组/防火墙规则。**UDP 443 最容易漏** |
| 443 端口没被占用 | VPS 上 `sudo ss -lntup \| grep ':443\|:80'` 没有输出（有 nginx/apache 就先停掉） |
| 测试设备 | iPhone/iPad（iOS 17+）或 Mac（macOS 14+），和一个能把文件传到设备上的办法（隔空投送、iCloud 云盘、邮件给自己） |

内存只有 512 MB 的机器先加 swap，否则编译会被杀掉：

```bash
sudo fallocate -l 2G /swapfile && sudo chmod 600 /swapfile && sudo mkswap /swapfile && sudo swapon /swapfile
```

## 1. 把源码放到 VPS 上

在电脑浏览器里登录 GitHub，打开本仓库，**Code → Download ZIP**，得到 `caddy-network-relay-main.zip`。在 Mac 终端上传（Ubuntu 云主机通常用 `ubuntu` 用户登录；能直接用 root 的就写 `root@`）：

```bash
scp ~/Downloads/caddy-network-relay-main.zip ubuntu@服务器IP:~/
```

登录 VPS，切到 root，开一个 screen（断线也不中断；`-U` 让中文正常显示）：

```bash
ssh ubuntu@服务器IP
```

```bash
sudo -i
```

```bash
screen -U
```

解压（文件在 `ubuntu` 用户的家目录里）：

```bash
apt-get install -y unzip && cd /root && unzip -o /home/ubuntu/caddy-network-relay-main.zip && cd caddy-network-relay-main
```

应该看到：`ls` 里有 `deploy/`、`cmd/`、`go.mod`。

## 2. 安装

```bash
bash deploy/install.sh --domain relay.example.com --user iphone
```

可选：`--email 你的邮箱`（Let's Encrypt 用它通知证书问题）。

**应该看到的过程**（每一步前面有 `==>`）：

1. `本机公网 IPv4：x.x.x.x；relay.example.com 解析到：x.x.x.x` — 两个 IP 相同。不同就停下，什么都没改：去改 DNS，等 `dig` 显示新 IP 再运行。
2. `==> 安装依赖软件包`、`==> 准备 Go 1.26.8`（下载约 70 MB）。
3. `==> 编译 Caddy 和 network_relay 插件` — 滚动很多 `go: downloading ...`，然后安静几分钟。这是最慢的一步，1 GB 内存的机器约 10 分钟。
4. `==> 生成用户 iphone 的随机密码（不会显示，保存在 /etc/caddy/relay/iphone.password）`。
5. `==> 检查配置`、`==> 安装并启动服务`。
6. `==> 等待证书并自检` — 第一次要等 Let's Encrypt 签发，几十秒到 3 分钟。最后应该是：

```
ok   HTTP/3 TCP example.com:80    HTTP/1.1 200 OK
ok   HTTP/3 UDP 1.1.1.1:53        example.com: RCodeSuccess ... (datagrams)
ok   HTTP/2 TCP example.com:80    HTTP/1.1 200 OK
ok   HTTP/2 UDP 1.1.1.1:53        example.com: RCodeSuccess ...
ok   HTTP/1.1 TCP example.com:80  HTTP/1.1 200 OK
ok   HTTP/1.1 UDP 1.1.1.1:53      example.com: RCodeSuccess ...
ok   no password: refused         405 Method Not Allowed
all checks passed
```

7. `==> 生成描述文件`，然后 `完成。`，最后打印下载命令。

**自检有 FAIL 时**（服务会保持运行，便于排查）：

| 看到 | 原因 | 办法 |
|---|---|---|
| 所有行都 FAIL，`connection refused` 或证书错误 | 证书还没签好 | 等一两分钟，运行下面的“手动自检”再看 |
| 全部 FAIL，日志里有 `rateLimited` | 这个域名一周内签了 5 次以上证书 | 换一个子域名，或等一周 |
| 只有 `HTTP/3` 两行 FAIL（`timeout`） | 本机自检走的是 127.0.0.1，这种情况少见；多半是 `sysctl` 被拒绝 | 看 `journalctl -u caddy -n 50`，把报错发给我 |
| 全部 FAIL 且 `journalctl` 里有 `acme ... connection` 错误 | VPS 连不上 Let's Encrypt，或 TCP 80 被云防火墙挡住 | 放行 TCP 80 后 `systemctl restart caddy` |

手动自检（密码从文件读，不显示）：

```bash
caddy network-relay check --server relay.example.com --address 127.0.0.1 --user iphone --password-stdin < /etc/caddy/relay/iphone.password
```

## 3. 从外面检查端口

本机自检通过只说明服务没问题，不能证明云防火墙放行了。在 **Mac** 上：

```bash
curl -sI https://relay.example.com/ | head -3
```

应该看到 `HTTP/2 200` 和一行 `alt-svc: h3=":443"`。看不到 `alt-svc` 说明 HTTP/3 没开（看第 2 步的日志）；连不上说明 TCP 443 没放行或 DNS 没生效。

UDP 443 从外面测：在 Mac 上编译一份（只需要一次；要先装 Xcode 命令行工具和 Go），然后用 `check`：

```bash
xcode-select --install; brew install go
```

```bash
cd ~/Downloads && unzip -o caddy-network-relay-main.zip && cd caddy-network-relay-main && go build -tags http2legacy -o caddy ./cmd/caddy
```

```bash
./caddy network-relay check --server relay.example.com --user iphone
```

（提示时粘贴密码；密码在 VPS 的 `/etc/caddy/relay/iphone.password` 里，`cat` 一下。**先退出 Mac 上的 Clash/Stash 之类的代理软件**，否则测的是它们。）

- 7 行全 `ok`：云防火墙、DNS、证书都对了。
- 只有 `HTTP/3` 两行 FAIL：**云防火墙没放行 UDP 443**。iPhone 这时会退回 HTTP/2，能用但慢一些；放行后再测。

## 4. 下载描述文件

两个文件都在 VPS 的 `/etc/caddy/relay/`，只有 root 能读，**里面有明文密码**：

| 文件 | 走中继的 | 设置里能手动关 |
|---|---|---|
| `relay.example.com-iphone.mobileconfig` | Google/Gemini/YouTube、Claude、ChatGPT、X/Grok 等 | 能 |
| `relay.example.com-iphone-global.mobileconfig` | 上面 + Spotify、Instagram、Meta AI、NYT、Wikipedia 等 + gfwlist | 不能（iOS/macOS 26+） |

**第一次测试建议用第一个**（基础版）：出问题时能在设置里关掉，而且范围小，容易判断是不是中继在起作用。

Ubuntu 机器一般不能用 root 登录 scp，先在 VPS 上复制给登录用户：

```bash
install -m 600 -o ubuntu /etc/caddy/relay/relay.example.com-iphone.mobileconfig /home/ubuntu/
```

在 Mac 上：

```bash
scp ubuntu@服务器IP:relay.example.com-iphone.mobileconfig ~/Downloads/
```

下载完在 VPS 上删掉副本：`rm /home/ubuntu/relay.example.com-iphone.mobileconfig`。

## 5. 在 Mac 上测试（最容易看到细节，建议先做）

1. 双击 `~/Downloads/relay.example.com-iphone.mobileconfig`。
2. 系统设置 → 通用 → 设备管理（macOS 13 以前在“隐私与安全性 → 描述文件”）→ 双击它 → 安装 → 输入开机密码。
3. 看 VPS 的日志（另开一个终端）：

```bash
journalctl -u caddy -f
```

4. Mac 上打开 Safari，访问 https://gemini.google.com 或 https://www.youtube.com 。

**应该看到**：网页正常打开，VPS 日志里没有 `relay authentication failed`。默认日志级别下看不到每条隧道，所以“网页能开”本身证明不了走了中继（中继对应用是透明的，网页上的出口 IP 查询也看不出来）。要确认，按第 7 步临时打开请求日志：设备访问 Gemini 时，VPS 上应该滚动出现目标为 `gemini.google.com:443` 之类的 `relay request` 行。

5. “系统设置 → 通用 → 设备管理”里能看到这份描述文件；macOS 26 起网络设置里也会显示中继项。

## 6. 在 iPhone 上测试

1. 把文件隔空投送到 iPhone（或存到 iCloud 云盘后在“文件”App 里点开）。
2. iPhone 提示“已下载描述文件”→ 打开“设置”，顶部点“已下载描述文件”→ 安装 → 输入锁屏密码。
3. 打开 Safari 访问 https://gemini.google.com ，或打开 YouTube App。
4. 在“设置 → 通用 → VPN 与设备管理”里能看到这份描述文件；iOS 26 起“设置 → VPN”里也会出现中继。

**先用 Wi-Fi 测，再关掉 Wi-Fi 用蜂窝网络测一遍**：两种网络都应该能用。

## 7. 想看设备到底发了什么

在 VPS 上编辑 `/etc/caddy/Caddyfile`，在 `network_relay {` 里面加一行 `log_requests`：

```
	network_relay {
		user iphone $argon2id$...
		log_requests
	}
```

然后：

```bash
systemctl reload caddy && journalctl -u caddy -f
```

每个来自设备的请求会记一行 `relay request`：HTTP 版本（`proto`）、`CONNECT` 的目标、`udp` 是 true 还是 false、`authenticated` 是否通过。看完**记得删掉这一行再 reload**，它很吵。

从日志判断：

| 看到 | 含义 |
|---|---|
| `"proto":"HTTP/3.0"` 或 `"proto":"connect-udp"` 的请求 | 设备在用 HTTP/3；UDP 隧道正常 |
| 只有 `"proto":"HTTP/2.0"` | 设备退回了 HTTP/2，多半是 UDP 443 被挡（云防火墙或所在网络） |
| `relay authentication failed` | 描述文件里的密码和服务器不一致：改过密码没重新生成，或装了旧文件 |
| `"authenticated":false` 且没有 `Authorization` | 不是设备发的，是扫描器；正常 |
| 什么都没有，设备却能上网 | 描述文件没生效：域名不在列表里（基础版只有 Google/AI/X 等），或装了两份互相抢。只留一份 |

## 8. 常见问题

| 现象 | 办法 |
|---|---|
| 描述文件安装时提示“无法验证”或“未签名” | 正常，本项目的描述文件没有签名；点“仍要安装” |
| 安装后 Google 打不开，其他网站正常 | 多半是密码不一致，看第 7 步 |
| iPhone 能用，Mac 不能（或反过来） | 同一域名、同一用户的描述文件两台设备可以共用；检查另一台是否装了别的中继/VPN 在抢 |
| 一段时间后突然不能用 | `systemctl status caddy`；证书续期失败看 `journalctl -u caddy \| grep -i acme` |
| 想换回不走中继 | 设备上删除描述文件（设置 → VPN 与设备管理 → 这份文件 → 移除） |

## 9. 测完之后

- 删掉 Mac `~/Downloads/` 里的描述文件（含明文密码）。
- 基础版验证通过后，再装 global 版（先删基础版）。
- 把测试结果（哪些能用、哪些不能、第 7 步的日志片段）发给我；日志里 `Authorization` 只显示用户名，没有密码，可以放心贴。
