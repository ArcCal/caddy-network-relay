# 设计文档

## 1. 目标

苹果的「网络中继」（iOS/iPadOS 17、macOS 14 起）：描述文件里的 `com.apple.relay.managed` 负载告诉系统一个 HTTP 代理（中继）的地址，系统把匹配的连接交给它转发，不需要 VPN App。本插件让 Caddy 成为这样的中继：

- 只需要一个描述文件：`HTTP3RelayURL` / `HTTP2RelayURL` 是 RFC 9298 的 URI 模板，`AdditionalHTTPHeaderFields` 里是 Basic 认证头，设备每个请求都主动带上。
- Caddy 负责证书（自动 HTTPS）、接收 TCP 流量（HTTP/2、HTTP/1.1）、网站；HTTP/3 由插件在 Caddy 进程内接收（§3）。
- 与 Rust 版 [network-relay](https://github.com/ArcCal/network-relay) 的协议行为、默认值、描述文件格式和密码哈希兼容。

描述文件各个键的含义和设备行为的调研，见 Rust 版的设计文档 §1；本项目生成的描述文件与之相同（标识符 `com.github.arccal.network-relay.<域名>.<用户>` 也相同）。

## 2. 协议

### 2.1 请求分类

| HTTP 版本 | TCP 隧道 | UDP 隧道 |
|---|---|---|
| HTTP/3 | `CONNECT`，无 `:protocol`，`:authority = 主机:端口`（RFC 9114 §4.4） | 扩展 CONNECT，`:protocol = connect-udp`，`:path` 匹配模板（RFC 9298 §3.4、RFC 9220） |
| HTTP/2 | 同上（RFC 9113 §8.5） | 同上（RFC 8441） |
| HTTP/1.1 | `CONNECT 主机:端口`（RFC 9110 §9.3.6） | `GET 路径` + `Upgrade: connect-udp` + `Connection: Upgrade`（RFC 9298 §3.2），回 101 |

其他请求原样交给站点里后面的处理器，有两个例外：经典 CONNECT 总是由插件回答（§2.2 第 2 步）；`:protocol = connect-udp` 但路径不匹配模板的扩展 CONNECT 回 404（没有凭据时 405），因为网站对扩展 CONNECT 的任何 2xx 回答都会被理解为“隧道已建立”。其他 `:protocol`（比如 HTTP/2 上的 WebSocket）交给网站，`reverse_proxy` 可以处理它们。HTTP/1.1 上 `Upgrade` 含 `connect-udp` 但路径不匹配模板的请求是普通网页请求。

### 2.2 处理一个请求

1. **分类**（上表）。
2. **认证**：先看 `Proxy-Authorization`，没有再看 `Authorization`，按 Basic 解析。失败时：`CONNECT`（经典或扩展）回 405 和 `Allow: GET, HEAD`，和 Caddy 静态网站对 CONNECT 的回答一样（由 Caddy 的错误处理生成，`handle_errors` 也适用）；不交给后面的处理器，是因为某个处理器可能回 2xx，而 CONNECT 的 2xx 表示“隧道已建立”。`GET` + `Upgrade` 交给网站。带了凭据但错误时记一条警告日志（用户名由 zap 转义）。
3. **目标**：TCP 从 `:authority`（端口必填，IPv6 带方括号）；UDP 从模板变量（百分号解码，IPv6 不带方括号）。格式错 → 400。CONNECT-UDP 请求带 `Content-Length`、`Content-Type`、`Transfer-Encoding` 或请求体 → 400（RFC 9297 §3.2）。HTTP/1.1 的 CONNECT-UDP 请求方法不是 GET、或 `Connection` 里没有 `Upgrade` → 400（RFC 9298 §3.2：畸形请求必须回错误，建议 400）；`Connection`、`Upgrade` 按逗号分隔的令牌比较，不区分大小写。
4. **名额**：同时转发数达到 `max_tunnels` → 503。
5. **策略**：端口在 `blocked_ports` → 403；域名解析（5 秒）；每个地址检查 `blocked_destinations`，IPv4 映射地址按 IPv4 检查；一个都不剩 → 403（防 DNS 重绑定）。
6. **连接**：TCP 用 Happy Eyeballs（RFC 8305）：两种地址族交替，每 250 毫秒多试一个，失败的立刻试下一个，整体 `connect_timeout`。连接关闭 Nagle，开 keepalive（2 分钟起）。UDP 建一个 connect 过的套接字（只收目标发回的包），选第一个有路由的地址；Linux 上设置不分片（`IP_PMTUDISC_PROBE`），超过 MTU 的包丢弃而不是分片（RFC 9298 §3.1）。
7. **回应**：TCP 回 200；UDP 回 200（HTTP/1.1 是 101，带 `Connection: Upgrade` 和唯一一个 `Upgrade: connect-udp`）并带 `Capsule-Protocol: ?1`。成功回应里没有 `Content-Length`、`Content-Type`、`Transfer-Encoding`（RFC 9110 §9.3.6、RFC 9297 §3.2），失败回应里没有 `Capsule-Protocol`（RFC 9297 §3.4）；测试在三种版本的线路上逐字检查。失败时回 §2.2 中的状态码和 RFC 9209 `Proxy-Status: network-relay; error=...`（表见 README）。

### 2.3 TCP 转发

- 64 KiB 缓冲，双向复制。
- **半关闭**：设备发 FIN（HTTP/3 流结束、HTTP/2 END_STREAM、HTTP/1.1 的 TLS close_notify）→ 目标一侧 `shutdown(SHUT_WR)`，另一方向继续；目标发 FIN → HTTP/3 发 FIN（另一方向继续）、HTTP/1.1 发 close_notify、HTTP/2 结束响应（见 §5 限制）。
- **出错**：目标一侧出错（RST）→ HTTP/3 用 `H3_CONNECT_ERROR` 复位请求流（RFC 9114 §4.4）；设备一侧出错、用户被撤销、Caddy 退出 → HTTP/3 用 `H3_REQUEST_CANCELLED`，目标一侧发 TCP RST（`SO_LINGER=0`）。
- 设备消失：HTTP/2 由请求上下文（流被复位或连接关闭）发现，HTTP/3 由流的上下文（STOP_SENDING、复位、连接关闭）发现，HTTP/1.1 由读写错误发现。

### 2.4 UDP 转发

- 数据报格式（RFC 9298 §5）：上下文 ID（变长整数）+ UDP 负载；只处理上下文 ID 0，其他丢弃；空负载合法；超过 65527 字节中止。
- **HTTP/3**：设备的 SETTINGS 里有 `SETTINGS_H3_DATAGRAM`（quic-go 只在 QUIC DATAGRAM 也协商了时才接受）时用 HTTP Datagram，否则用请求流里的 DATAGRAM Capsule。用 Datagram 时仍然读请求流上的 Capsule（RFC 9297 §3.5 允许两种混用）。设备在收到回应前就发来的数据报（RFC 9298 §5 允许）由 quic-go 按流缓存（每流最多 32 个），认证完成后照常转发；比请求流本身还早到、quic-go 还不知道这个流时，数据报被丢弃（RFC 9297 §2.1、RFC 9298 §5 允许丢弃或缓存）。
- **HTTP/2、HTTP/1.1**：DATAGRAM Capsule。
- Capsule 解析是流式的：未知类型、其他上下文 ID 的 Capsule 按声明长度跳过，不受 UDP 大小限制；上下文 0 根据声明长度尽早检查上限；Capsule 中间断开、缺上下文 ID 等格式错误 → `H3_MESSAGE_ERROR`（HTTP/2 见 §5）。
- 目标发回的包太大、装不进一个 QUIC DATAGRAM 时丢弃，不改走可靠的流（RFC 9297 §3.5、RFC 9298 §6.1：QUIC 套 QUIC 时，两层拥塞控制会互相干扰，也会破坏 DPLPMTUD）。超过路径 MTU（EMSGSIZE）或发送缓冲满时只丢这个包。
- 操作系统报告套接字不可用时关闭隧道（HTTP/3 用 `H3_CONNECT_ERROR`）：RFC 9298 §3.1 要求这样做，例子正是 ICMP Destination Unreachable，Linux 在 connect 过的 UDP 套接字上把它报告为 ECONNREFUSED、EHOSTUNREACH、ENETUNREACH。
- 发往目标的包 ECN 为 Not-ECT（套接字默认），目标发回的包的 ECN 不转发（RFC 9298 §6.2）；外层 QUIC 连接保留拥塞控制。
- 两个方向都 `udp_idle_timeout` 没有包时正常关闭（RFC 4787 要求 NAT 映射至少 2 分钟，默认 5 分钟）。设备结束请求流时正常关闭。

### 2.5 URI 模板

支持 RFC 6570 的简单展开 `{var}` 和表单式查询 `{?a,b}`、`{&a,b}`，变量只有 `target_host`、`target_port`，两个都必须出现、各出现一次，两个 `{var}` 之间必须有分隔符。加载时把 `example.com:443`、`192.0.2.1:53`、`2001:db8::1:8443` 按模板展开再解析，结果必须一致，否则拒绝这个模板。匹配时宽容：未编码的 `:`（IPv6）也接受。

## 3. 在 Caddy 里的结构

### 3.1 模块

| 模块 | ID | 作用 |
|---|---|---|
| `Handler` | `http.handlers.network_relay` | 中间件：分类、认证、隧道；其他请求交给下一个处理器。Caddyfile 指令 `network_relay`，自动排在 `map` 之前（站点里最先） |
| `App` | `network_relay` | 由处理器自动创建，不用配置：为含有处理器的服务器提供 HTTP/3 |

### 3.2 HTTP/3

Caddy 2.11 的 HTTP/3 服务器（`http3.Server`）没有 `EnableDatagrams`，QUIC 配置也写死在 Caddy 内部，没有扩展点；而苹果设备经 HTTP/3 转发 UDP 依赖 HTTP Datagram。所以：

1. 处理器 provision 时从上下文取得它所在的 `caddyhttp.Server`（Caddy 在 provision 每个服务器的路由时把它放在上下文里），记下哪些监听地址原本要提供 HTTP/3，并从这个服务器的 `protocols`（以及 `listen_protocols`）里去掉 `h3`。这时 Caddy 还没启动这个服务器，所以 Caddy 不会再监听这些 UDP 端口。用户自己去掉了 `h3` 的服务器，插件也不提供 HTTP/3。
2. `App` 启动时，为每个这样的地址打开 UDP 套接字和 QUIC 监听（quic-go，和 Caddy 用的同一个库），`EnableDatagrams`、最多 1024 个并发流、单流窗口 4 MiB、连接窗口 32 MiB、空闲超时 5 分钟、初始包大小 1350（被转发的 QUIC 包至少 1200 字节，RFC 9000 §14.1，外层还要装 QUIC 头、DATAGRAM 帧和上下文 ID）、不允许 0-RTT。TLS 配置来自这个服务器的 `TLSConnPolicies`，即 Caddy 的证书。
3. 每个请求交给同一个 `caddyhttp.Server` 的 `ServeHTTP`：路由、匹配器、访问日志、网站、错误处理与 TCP 上完全相同。
4. TCP 上的回应由处理器加 `Alt-Svc: h3=":端口"; ma=2592000`（Caddy 自己的 HTTP/3 关闭后不再加）。
5. **reload**：UDP 端点是进程级的，按地址共享，记录使用它的各代配置，新连接交给最新的一代；旧代用 `Shutdown` 优雅结束（已有连接留在旧代）。新配置启动失败时只撤销它自己的登记，旧配置照常提供服务。最后一代释放时才关闭套接字。所以 reload 不会出现“旧配置还占着端口，新配置绑不上”的问题。

### 3.3 HTTP/3 CONNECT 流和 HTTP Datagram 的规则

插件对 HTTP/3 做了 quic-go 没有做的检查：

- **CONNECT 流上的帧**（RFC 9114 §4.4、§7.1、§9）：隧道建立后，设备一侧的帧由插件自己解析：只有 DATA 携带数据；HEADERS（quic-go 会当成 trailers 接受）、SETTINGS、GOAWAY、保留的 HTTP/2 帧类型、PRIORITY_UPDATE 等已知类型 → 连接错误 `H3_FRAME_UNEXPECTED`；未知类型（包括 greasing 用的保留值）跳过；流在帧中间结束 → 连接错误 `H3_FRAME_ERROR`。
- **不该有 Datagram 的请求**（RFC 9297 §2.1）：经典 CONNECT 和所有非 CONNECT 请求（网页）收到 HTTP Datagram 时，用 `H3_DATAGRAM_ERROR` 中止这个请求流；请求的接收方向已经结束（设备已发 FIN）后才到的数据报静默丢弃。扩展 CONNECT 不受此限（它们的协议可能定义了 Datagram）。quic-go 只有在接管请求流时才交出它（而接管会立刻发出回应头），所以插件按类型从 quic-go 的 `ResponseWriter` 里取出流；一个测试固定了这个做法，升级 quic-go 后它若失效，测试会失败。
- 数据报格式本身的错误（Quarter Stream ID 解析不了或超出范围 → 连接错误 `H3_DATAGRAM_ERROR`；对应的流还不存在 → 丢弃；接收方向已关闭 → 丢弃）由 quic-go 处理，符合 RFC 9297 §2.1。
- **保活**：QUIC 连接没有包超过空闲超时（5 分钟）就会关闭，不管里面有没有流；隧道可能空闲更久（比如中继里一个空闲的 TCP 连接）。插件每 30 秒发一次 QUIC PING；HTTP/2 连接上 Go 每 15 秒发 TCP keepalive，效果相同。没有请求流的 HTTP/3 连接仍在 Caddy 的 `idle_timeout`（默认 5 分钟）后关闭。

### 3.4 HTTP/2 扩展 CONNECT

CONNECT-UDP over HTTP/2 需要服务器发送 `SETTINGS_ENABLE_CONNECT_PROTOCOL`。Caddy 用 `golang.org/x/net/http2`；它支持扩展 CONNECT，但在 Go issue #71128 之后默认关闭，只认环境变量 `GODEBUG=http2xconnect=1`。

- Go 1.26 编译，或 Go 1.27+ 加 `-tags http2legacy`：`x/net/http2` 用自己的实现，插件在 `init` 里通过 `go:linkname` 打开开关（除非 `GODEBUG` 明确写了 `http2xconnect=0`）。
- Go 1.27+ 不加这个标签：`x/net/http2` 改用标准库内部的实现，链接器不允许 linkname 进标准库，只能靠环境变量。插件检测到没有打开时在日志里警告；`deploy/caddy.service` 总是设置这个环境变量。

扩展 CONNECT 打开后，浏览器也可能对这个服务器用 WebSocket over HTTP/2（这就是 Go 默认关闭它的原因）。Caddy 的 `reverse_proxy` 支持它；纯静态网站不受影响。

### 3.5 绕开 Caddy 为网站设计的超时

Caddy 2.11 默认给请求体读和响应写加 1 分钟的“空闲超时”（防 slowloris），每次读写前重设截止时间。对隧道而言，一分钟没有数据很正常。所以隧道建立后：

- 响应头通过 Caddy 的包装（访问日志能记录状态码）写出；之后的数据直接用最底层的 `ResponseWriter`（剥掉 `Unwrap` 链）和最底层的请求体（剥掉 `IdleTimeoutReader` 和访问日志的计数包装），并清除流或连接的读写截止时间。
- HTTP/1.1 劫持连接，HTTP/3 接管请求流（`HTTPStreamer`）。

### 3.6 隧道的生命周期

- 隧道属于建立它的那一代配置的处理器。reload 后旧处理器 cleanup 时，隧道交给新配置里**仍有同一用户、同一密码哈希**的处理器；没有的话（用户被删除或改了密码）立刻关闭。建立隧道的过程中旧配置已被替换的，同样检查。
- Caddy 退出时（`caddy stop`、SIGTERM），HTTP 服务器的关闭钩子关闭所有隧道；否则 Caddy 会一直等打开的 HTTP/2 请求结束。
- 隧道建立前，设备断开（请求上下文取消）会取消 DNS 解析和连接。建立后不再跟随请求上下文：Go 的 HTTP/1.1 服务器在被劫持的连接上设备半关闭时就取消它，quic-go 在中继半关闭时就取消它，两者都不表示设备走了；改用 §2.3 的方式发现设备消失。

## 4. 认证

- 只保存哈希。新哈希用 Argon2id（19 MiB、2 轮、1 线程，OWASP 建议，与 Rust 版相同，PHC 格式）；也验证 bcrypt 和 `caddy hash-password` 的 base64 输出。`passwd` 生成 144 位随机密码，在线猜不中，所以不封锁 IP 或账号。
- 验证结果按请求头缓存：成功 10 分钟、失败 1 分钟。键是请求头的 HMAC-SHA256（每次加载配置随机密钥），缓存里没有密码。同一个请求头的并发请求只算一次哈希；同时计算的哈希数不超过 CPU 核数的 2 倍。缓存最多 4096 条，满了先清过期的；失败结果不会挤掉成功结果。
- 用户名不存在时也对一个随机哈希算一次，响应时间不暴露哪些用户名存在。

## 5. 已知限制

| 限制 | 原因 | 影响 |
|---|---|---|
| HTTP/2 上目标先关闭时，中继结束整个流（END_STREAM，如设备仍在发送则随后 RST_STREAM(NO_ERROR)），不能只关一个方向 | Go 的 HTTP/2 服务器只在处理器返回时结束响应 | 极少见：目标半关闭后还要继续接收设备数据的协议。HTTP/3、HTTP/1.1 不受影响 |
| HTTP/2 隧道异常结束时的 RST_STREAM 码是 `INTERNAL_ERROR`；RFC 9113 §8.5 要求目标 TCP 出错时用 `CONNECT_ERROR`，RFC 9297 §3.3 / RFC 9113 §8.1.1 要求畸形 Capsule 用 `PROTOCOL_ERROR` | Go 的 HTTP/2 服务器（`x/net/http2`，Caddy 用的）不让处理器选择复位码，处理器中止时固定发 `INTERNAL_ERROR` | 设备照样看到流被复位、目标一侧照样收到 TCP RST，只是不知道原因细节。HTTP/3 上三种码都正确 |
| HTTP/2 CONNECT 流上的尾部 HEADERS 被当成流结束（等同 FIN），没有按 RFC 9113 §8.5 当作流错误 | 同上：`x/net/http2` 在处理器看到之前就把它当成 END_STREAM | 只有违反协议的客户端才会这样发。HTTP/3 上是 `H3_FRAME_UNEXPECTED` |
| 扩展 CONNECT 的 `:scheme` 没有检查是不是 `https`（RFC 9298 §3.4） | `x/net/http2` 和 quic-go 只检查它存在，不把值交给处理器 | 客户端都发 `https` |
| HTTP/2 的流控窗口和并发流数是 `x/net/http2` 的默认值（每流/每连接约 1 MiB，最多 250 个流） | Caddy 不提供这些设置 | HTTP/2 上的大流量上传吞吐受 RTT 限制；HTTP/3 不受影响 |
| 经中继访问同一台 Caddy 上其他站点的域名会失败 | CONNECT 以目标为主机名，被那个站点接收 | 把这些域名放进描述文件的 `--exclude-domain` |
| 撤销某个用户后，正在进行的认证可能已经放行了一个请求 | 认证和建立隧道之间的竞态 | 建立隧道时再次检查配置代际（§3.6），窗口只有几毫秒 |

## 6. 测试

`go test ./...`（CI 里加 `-race`，并在 Go 1.27 上分别以 `-tags http2legacy` 和 `GODEBUG=http2xconnect=1` 运行）：

- **单元**：URI 模板（展开、匹配、IPv6、查询形式、拒绝的写法）、目标解析、策略（映射地址、DNS 重绑定、DNS 超时）、Happy Eyeballs、密码哈希（含 Rust 版 `network-relay passwd` 生成的哈希、bcrypt、base64）、认证缓存、Capsule（大型未知 Capsule、其他上下文、空负载、65527 上限、截断）、描述文件、域名列表和 gfwlist 解析。
- **集成**（进程内启动真实 Caddy，真实 TLS/QUIC）：三种 HTTP 版本的 TCP 往返和半关闭、目标先关闭、UDP 往返（HTTP/3 Datagram、HTTP/3 Capsule、HTTP/2、HTTP/1.1；0、1、60、1200 字节，Capsule 还有 1400、9000 字节）、IPv6 目标、拒绝（403/400/502 和 `Proxy-Status`）、未认证请求看到网站、网站经 HTTP/3 和 `Alt-Svc`、Caddy 读写空闲超时不切断空闲隧道、`max_tunnels`、reload 撤销被删用户而保留其他用户、reload 失败时 HTTP/3 和隧道保持、Caddyfile 解析和指令顺序。
- **逐帧的协议一致性**（`compliance_test.go`，自己写的 HTTP/3 帧级客户端和 HTTP/2 帧级客户端，能发出正常客户端库不会发的东西）：服务器 SETTINGS（扩展 CONNECT、H3_DATAGRAM、QUIC DATAGRAM）；三种版本成功回应的头部（无 Content-Length/Content-Type/Transfer-Encoding，UDP 有且只有 `Capsule-Protocol: ?1`，HTTP/1.1 的 101 头部，拒绝时没有 `Capsule-Protocol`）；CONNECT 流上的未知帧被跳过、尾部 HEADERS/SETTINGS/GOAWAY/保留类型 → `H3_FRAME_UNEXPECTED`、截断的 DATA → `H3_FRAME_ERROR`；TCP 隧道和下载中的网页收到数据报 → `H3_DATAGRAM_ERROR`，FIN 之后的数据报被丢弃；回应前发出的数据报被转发；ICMP 不可达关闭三种版本的 UDP 隧道（HTTP/3 是 `H3_CONNECT_ERROR`）；HTTP/1.1 的畸形 Upgrade 请求 → 400、令牌列表形式的 `Connection`/`Upgrade` 被接受、重复 `Host` → 400；带内容头的 CONNECT-UDP → 400（HTTP/3、HTTP/2）；模板外的 connect-udp → 404/405，其他 `:protocol` 交给网站。
- **互通**：quic-go 的 [masque-go](https://github.com/quic-go/masque-go)（独立的 CONNECT-UDP 客户端和 RFC 6570 实现）经 HTTP/3 收发数据报；帧级 HTTP/2 客户端检查 `SETTINGS_ENABLE_CONNECT_PROTOCOL`、扩展 CONNECT、Capsule 往返、畸形 Capsule 引起的 RST_STREAM、正常结束（这个测试不依赖 Go 的 HTTP/2 客户端，所以在 Go 1.27 的标准库实现下也验证了服务端）；HTTP/3 的 `H3_MESSAGE_ERROR`、`H3_CONNECT_ERROR`。
- **安装脚本**：`python3 deploy/test_install.py`，系统命令换成记录调用的假命令，Caddy 用真实编译的程序：全新安装、升级保留一切、各种拒绝时什么都不写、不接管别人的 Caddyfile、替换 Rust 版、启动失败回滚（全新安装和升级）、配置检查失败、自检失败时保留服务。
- **手动端到端**：编译出的 `caddy` 加 Caddyfile 运行，`caddy network-relay check` 三种版本的 TCP 和 UDP（经真实互联网查询 1.1.1.1）全部通过；带打开的 HTTP/2 隧道时 SIGTERM，Caddy 约 1 秒内退出。

**还没做的**：真实 iPhone、Mac 的测试。
