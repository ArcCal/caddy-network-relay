# 部署细节

## install.sh 写了哪些东西

| 路径 | 内容 |
|---|---|
| `/usr/local/bin/caddy` | 带插件的 Caddy（`go build -tags http2legacy -trimpath`） |
| `/etc/systemd/system/caddy.service` | 来自 [deploy/caddy.service](../deploy/caddy.service)：以 `caddy` 用户运行，只有绑定低端口和网络管理的能力，`GODEBUG=http2xconnect=1` |
| `/etc/caddy/Caddyfile` | 第一行是 `# Managed by caddy-network-relay deploy/install.sh`，接着记录域名和第一个用户。权限 640，属主 `root:caddy` |
| `/etc/caddy/relay/` | 权限 700，只有 root 能进：`<用户>.password`（第一个用户的密码，600）和描述文件（600） |
| `/var/lib/caddy/` | `caddy` 用户的家目录；Caddy 的证书、ACME 账户在 `.local/share/caddy/` |
| `/var/www/relay/index.html` | 默认网站（已存在时不覆盖）。可以换成任何静态网站 |
| `/etc/sysctl.d/60-caddy-network-relay.conf` | 把 UDP 收发缓冲上限提高到 7.5 MB（quic-go 的建议）；已经更大的不写 |
| `/opt/caddy-network-relay/go/` | 编译用的 Go，来自 proxy.golang.org，按 Go 校验和数据库（sum.golang.org）里的哈希校验，哈希写死在脚本里 |
| `/var/cache/caddy-network-relay/` | 编译缓存、依赖模块、每次运行前的备份（`backup.时间/`）、最近一次自检和配置检查的输出 |

还会：`apt-get install ca-certificates curl python3 iproute2`；创建系统用户 `caddy`；ufw 启用时放行 TCP 80、TCP 443、UDP 443；`--replace-network-relay` 时 `systemctl disable --now network-relay`。

## 脚本的检查和回滚

- 改动之前：系统版本和架构、源码目录、已有 Caddyfile 是不是本脚本生成的、是否装了 apt 的 caddy、旧 Rust 版是否在运行、TCP 80/443 和 UDP 443 是否被别的程序占用、（第一次安装时）域名的 A 记录是否指向本机公网 IP。任何一项不对就退出，什么都不改。
- 新程序先用 `caddy validate` 检查配置，不通过就不安装。
- 启动后服务没有运行：恢复安装前的程序、Caddyfile 和 systemd 单元；升级时旧版本重新启动，第一次安装时停用服务并删除生成的配置。第一次安装中途失败（服务启动之前），生成的 Caddyfile 和密码文件会删除，下次运行仍是第一次安装。
- 服务在运行但本机自检没通过（多半是证书还没签好或 UDP 被封）：不回滚，打印排查方法，退出码 1。

## 换域名

1. DNS 加好新域名的 A 记录。
2. 编辑 `/etc/caddy/Caddyfile`：把站点地址里的旧域名换成新的（`新域名, :443 {`），把开头的 `# domain: 旧域名` 也改掉（升级时脚本靠它识别）。
3. `systemctl reload caddy`，Caddy 自动申请新证书。
4. 用新域名重新生成描述文件（README 的“重新生成描述文件”，`--host` 写新域名），设备上删掉旧的、装新的。

## 手动升级（不是 install.sh 装的 Caddy）

在源码目录里编译，检查配置，替换：

```bash
go build -tags http2legacy -trimpath -o caddy.new ./cmd/caddy
```

```bash
./caddy.new validate --config /etc/caddy/Caddyfile
```

```bash
install -m 755 caddy.new /usr/local/bin/caddy && systemctl restart caddy
```

（路径按你的安装改。）

## 多个用户

每台设备一个用户：Caddyfile 的 `network_relay { }` 里每个用户一行 `user 名字 哈希`。安装脚本只管第一个用户的密码文件；其他用户的密码由你保存（或者只保存描述文件）。

## 端口不是 443

站点地址写 `relay.example.com:8443, :8443`，云防火墙放行这个端口的 TCP 和 UDP，生成描述文件和自检时加 `--port 8443`。用 443 最好：很多网络只放行 443，而且看起来就是一个普通网站。
