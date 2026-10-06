# 天翼校园网 Linux 客户端 —— 门户登录（逆向复刻）

本目录是逆向 `ESurfingSvr` 后复刻出的**行为等价、可运行的登录程序**，实现：

```
配置探测 → 申请 ticket → 编码 POST → 解码解析 → 认证(auth) → 解码解析 → 登录状态
```

在原客户端上验证通过：`state=online`，且认证后外网可访问（`www.baidu.com` 返回 HTTP 200）。

---

## 1. 目录结构

```
final/
├── src/
│   └── portal_login.c     # 全部源码（单文件）
├── conf/
│   ├── conf.xml           # 运行依赖：客户端保存的配置（urls/clientId/schoolId/domain/area 等）
│   └── code.xml           # 运行依赖：服务端错误码中文表（失败时输出可读原因）
├── protect.so             # 运行依赖：编码模块（从原客户端捕获，Code/DeCode/FreeResult/...）
├── zxmAlogic.zxm          # 运行依赖：算法容器，程序从中读取 Algo-ID
├── build.sh               # 构建脚本
├── run_login.sh           # 登录（一次性）
├── dynamic.sh             # 动态取配置后登录（index.cgi）
├── logout.sh              # 注销（term.cgi）
├── state.sh               # 查询在线状态（state.cgi）
├── keep.sh                # 登录并保活（keep.cgi）
├── server.sh              # 命名管道服务端（IPC）
├── client.sh              # 命名管道客户端（IPC）
├── portal_login           # 构建产物（build.sh 生成）
└── README.md              # 本文件
```

> `protect.so`、`zxmAlogic.zxm`、`conf/conf.xml`、`conf/code.xml` 是运行期依赖，
> 必须与程序保持相对位置。
> 程序需从**本目录**运行（会读取 `conf/` 与 `zxmAlogic.zxm`）。
> 缺 `conf/code.xml` 时程序照常工作，只是错误信息只显示数字码。

> ARM 平台（树莓派 / 软路由等）请看 [`../arm/README.md`](../arm/README.md)。

---

## 2. 依赖

### 构建依赖（Linux）

| 依赖 | 用途 | 安装 |
|---|---|---|
| gcc | 编译 C 源码 | `sudo apt install -y build-essential` |
| pkg-config | 定位 libxml2 | `sudo apt install -y pkg-config` |
| libxml2 开发包 | 解析配置/响应 XML | `sudo apt install -y libxml2-dev` |

### 运行依赖

| 依赖 | 说明 |
|---|---|
| glibc | 标准 C 运行库（含 `dlopen`/`getifaddrs`） |
| `protect.so` | 随本目录提供，编码/解码模块 |
| `zxmAlogic.zxm` | 随本目录提供，提供 `Algo-ID` |
| `conf/conf.xml` | 随本目录提供，离线配置回退（网关地址、clientId 等） |

无需 OpenSSL 等第三方库（MD5 已内置于源码中）。

---

## 3. 使用说明

### 3.1 一次性准备：构建

```bash
cd final
sh build.sh          # 只需执行一次，产物为 ./portal_login
```

构建依赖：`build-essential`、`pkg-config`、`libxml2-dev`

```bash
sudo apt install -y build-essential pkg-config libxml2-dev
```

### 3.2 完整流程（①→⑦，按顺序执行）

| 步骤 | 命令 | 成功后应看到 |
|---|---|---|
| ① 构建 | `sh build.sh` | 生成 `./portal_login` |
| ② 登录 | `sh run_login.sh`，按提示输入账号、密码 | `state=online` |
| ③ 查状态 | `sh state.sh` | `state=online` |
| ④ 保活 | `sh keep.sh`（前台常驻，`Ctrl+C` 结束） | 周期性 `debug=keep-*`，不掉线 |
| ⑤ 再查状态 | **另开一个终端** `sh state.sh` | 仍为 `state=online` |
| ⑥ 注销 | `sh logout.sh` | `state=offline` |
| ⑦ 再查状态 | `sh state.sh` | `state=offline` |

```bash
cd final
sh build.sh                    # ① 构建
sh run_login.sh                # ② 按提示输入账号、密码
sh state.sh                    # ③ 应为 state=online
sh keep.sh                     # ④ 常驻保活（挡住这个终端）
# ⑤ 另开一个终端： sh state.sh   应为 state=online
sh logout.sh                   # ⑥ 注销
sh state.sh                    # ⑦ 应为 state=offline
```

> **登录和保活是两件事。** `sh run_login.sh` 只认证一次、成功即退出；
> 门户会话有存活时间，不续期就会被服务端踢下线。
> 想长时间在线请用 `sh keep.sh`（它=登录 + 周期性 keep 续期）。

### 3.3 账号密码怎么输入

三种方式，任选其一：

```bash
# 方式 1：交互式，账号和密码都按提示输入（密码不回显，最安全）
sh run_login.sh

# 方式 2：账号写在命令行，密码仍交互输入
./portal_login ./protect.so 19002036256

# 方式 3：保活模式（同样交互输入账号、密码）
sh keep.sh
```

- 密码**不回显**、**不写入任何文件**、**不打印到日志**。
- 关闭诊断输出：`GD_DEBUG=0 sh run_login.sh`。
- 诊断只输出**非敏感**信息：字节数、服务端 `Error-Code`、状态、IP。

运行示例：

```
Account: <输入你的账号>
Password: <输入密码，不回显>
debug=config ticket-url=http://14.146.227.141:7001/ticket.cgi?...
debug=ticket-http status=200 error=0 bytes=352
debug=ticket-ok length=32
debug=auth-http status=200 error=0 bytes=768
debug=finish result=ok local-ip=172.17.104.130
state=online
```

- 看到 **`state=online`** 即登录成功。
- 这个进程**登录成功后就会退出**，不会帮你保持在线（要常驻请用 `sh keep.sh`）。

### 3.4 也可直接手动运行

```bash
# 交互式（账号、密码都在终端输入）
GD_DEBUG=1 ./portal_login ./protect.so

# 账号作为参数，密码仍在终端输入
GD_DEBUG=1 ./portal_login ./protect.so <账号>
```

### 3.5 退出登录（注销）

```bash
sh logout.sh
```

成功输出 `state=offline`。注销通过向 `term.cgi` 发送编码请求
（`<reason>8</reason>`，字段：user-agent / client-id / ticket / local-time / reason）
实现，与原客户端的 `CPortalConn::TerminalTermRequest` 一致。

> 已注销后重复执行会返回 `term-server`（服务端 `Error-Code: 14`，ticket 已失效），属正常。

### 3.6 动态取配置（换校/换网更省心）

```bash
sh dynamic.sh
```

- 原理：GET `<redirect 主机>/index.cgi`，响应里 HTML 注释中内嵌 `<config>`：

  ```xml
  <config><ticket-url>..</ticket-url><auth-url>..</auth-url>
    <state-url>..</state-url><auth><type>..</type></auth>
    <ServerIPs>host:port,host:port</ServerIPs></config>
  ```

- 程序用 `ServerIPs` 选定服务器（优先与本机 `conf.xml` 主机一致的那个），
  替换 ticket / auth / term 的**服务器地址与端口**；查询参数等仍使用本地配置。
- 当前校区实测：由 `ServerIPs` 解析出 `http://14.146.227.141:7001/...`，取票 `Error-Code: 0`。
- 门户配置地址可用 `GD_CONFIG_URL` 覆盖。
- **会话参数**：把网络把你重定向到的**门户 URL** 传给程序，会自动提取
  `wlanacip / wlanuserip / wlanacname / clientmac / paip / vlan / iarmdst / portal_node`
  等参数填入请求：

  ```bash
  sh dynamic.sh 'http://125.88.59.131:10001/qs/index_gz.jsp?wlanacip=183.3.151.148&wlanuserip=172.17.104.132'
  # 或
  GD_PORTAL_URL='http://.../index_gz.jsp?wlanacip=..&wlanuserip=..' sh dynamic.sh
  ```

  - `wlanuserip/clientip` 会被**本机实际源 IP** 覆盖（服务端校验）；
  - `clientmac` 缺失时自动读本机网卡 MAC；
  - 未提供的参数沿用 `conf.xml`。

### 3.7 查询在线状态

```bash
sh state.sh
```

- 通过 `state.cgi` 判断当前是否在线：`state=online` 或 `state=offline`。
- 离线时会给出服务端错误码，例如 `detail=server-error=300`（140300 = 等待终端发起认证）。

### 3.8 保持在线（保活 keep）

```bash
sh keep.sh
```

登录成功后周期性向 `keep.cgi` 发送编码请求
（字段：user-agent / client-id / ticket / ipv4 / ipv6 / mac / local-time / shared），
间隔优先取服务端下发的 `<interval>`，否则用本地默认 **30 秒**
（`GD_KEEP_INTERVAL=<秒>` 可覆盖）；保活失败时输出 `state=offline` 并退出。
按 `Ctrl+C` 手动结束。

> `keep.sh` = 登录 + 保活，适合长时间挂机；只想验证登录用 `run_login.sh` 即可。

**掉线自动重登**：keep 失败（被别的终端踢下线、会话过期）后会按
5s → 10s → 20s …（上限 300s）自动重新认证，最多 3 次：

```
debug=relogin attempt=1 wait=5
state=online          ← 重登成功，继续保活
```

- 关闭：`GD_RELOGIN=0 sh keep.sh`
- 次数：`GD_RELOGIN_MAX=5`（默认 3，`0` = 不重登）
- 首次等待：`GD_RELOGIN_DELAY=10`（默认 5）
- 密码错、账号不存在这类“重登也没用”的错误会直接退出，不白费次数。

### 3.9 命名管道 IPC（server / client）

终端 1：
```bash
sh server.sh
```

终端 2：
```bash
sh client.sh connect <账号>    # 回车后提示输入密码
sh client.sh disconnect        # 注销
```

- FIFO：`run/clientpipe`、`run/serverpipe`（可用环境变量 `GD_PIPE_DIR` 更换目录）。
- 消息为 **NUL 结尾的 XML**，与原客户端一致：

  ```xml
  <M><OpS>client</OpS><OpT>Portal</OpT><OpC>PortalConnect</OpC>
     <P><user>..</user><password>..</password></P></M>
  ```

  操作码 `OpC`：`PortalConnect`（登录）、`PortalDisConnect`（注销）。
- 服务端应答：

  ```xml
  <M><OpS>ESurfingSvr</OpS><OpT>PortalState</OpT><OpC>PortalState</OpC>
     <P><state>online|offline|failed</state><detail>..</detail></P></M>
  ```

- 服务端登录成功后自动开始保活定时（空闲到点即发 keep）。

---

## 4. 常见问题（FAQ）

### 报 `Error-Code: 10`（无效客户端 IP）

`wlanuserip` / `clientip` 必须是**服务端看到的你的 IP**。程序会自动探测并替换。
机器有**多张网卡**时（例如同时有 NAT 有线 + 校园无线），探测到的是
「内核用来访问门户的那张网卡」的 IP，可能并不是校园网 IP。排查：

```bash
# 看内核实际用哪张网卡去门户
ip route get 14.146.227.141

# 临时指定本机 IP
GD_LOCAL_IP=172.17.104.130 sh run_login.sh

# 或让校园网卡成为去门户的主路由（需要 root，示例）
sudo ip route replace default via 172.17.107.254 dev wlx6c1ff73185c5 metric 50
```

> **已知限制**：当前版本 `GD_LOCAL_IP` 只在**路由探测失败**时才生效。
> 若探测成功但取错网卡，请临时调整路由 metric（如上）。
> 判断方法：对比 `debug=config ticket-url=...` 里的 `wlanuserip` 与
> `ip route get <门户IP>` 的 `src` 是否一致。

### `state=offline` 且 `detail=server-error=300`

`140300` = 服务端「正在等待终端发起认证」（该会话未认证）。两种可能：

1. 确实没登录 / 已被踢下线（因为没有保活）；
2. 查询时用了**错误的 IP**，服务端认不出你是谁（见上一条）。

### 保活多久发一次？

由服务端下发（auth / keep 响应里的 `<interval>`）决定；
本地默认 30 秒，可用 `GD_KEEP_INTERVAL=<秒>` 覆盖。

### 门户换了 IP / 参数怎么办？

见 [第 6 节](#6-更换学校--其他校区)。

### 失败时的 `detail` 怎么读

```
state=failed
detail=server-error=140102.13014000 | 您已在客户端登录了此账号，不能重复登录。（2）
```

- 格式：`server-error=<Error-Code>[.<子码>] | <中文含义>`；
  含义来自 `conf/code.xml`，缺表时只显示数字码。
- 常见：`140200` 密钥过期、`140300` 等待终端认证、`140100` 用户名/密码错、
  `140102.*` 认证被拒（含“已在别处登录”“终端数超出限制”）。
- 想看服务端原始错误体：`GD_DEBUG=2`。

### 环境变量速查

| 变量 | 作用 | 默认 |
|---|---|---|
| `GD_DEBUG` | `1` 诊断信息；`2` 额外打印服务端错误体 | 脚本内置 `1` |
| `GD_LOCAL_IP` | 指定本机 IP | 自动探测 |
| `GD_PORTAL_URL` | 提供门户 URL，提取会话参数 | 无 |
| `GD_CONFIG_URL` | 覆盖 `index.cgi` 地址 | 由 `redirect` 推导 |
| `GD_CLIENT_ID` | 覆盖客户端 ID | `conf.xml` |
| `GD_USER_AGENT` | 覆盖 User-Agent | `CCTP/Linux64/2.4.64` |
| `GD_ALGO_ID` | 覆盖 Algo-ID | 从 `zxmAlogic.zxm` 读取 |
| `GD_ZSM_PATH` | 覆盖算法容器路径 | `./zxmAlogic.zxm` |
| `GD_KEEP_INTERVAL` | 保活间隔（秒） | `30` |
| `GD_RELOGIN` | `0` 关闭掉线自动重登 | 开启 |
| `GD_RELOGIN_MAX` | 自动重登次数 | `3` |
| `GD_RELOGIN_DELAY` | 首次重登等待（秒，随后翻倍） | `5` |
| `GD_PIPE_DIR` | IPC FIFO 目录 | `run/` |

---

## 5. 工作原理（协议要点）

- **配置**：GET `detect.html`；若失败回退读取 `conf/conf.xml`。
- **ticket**：把下列 XML 用 `protect.so` 的 `Code()` 编码，再以 `POST` 发到 `ticket.cgi`：

  ```xml
  <request>
    <host-name>网关主机</host-name><user-agent>CCTP/Linux64/2.4.64</user-agent>
    <client-id>客户端ID</client-id><ipv4>本机IP</ipv4><ipv6></ipv6>
    <mac>本机MAC</mac><local-time>%Y-%m-%d %H:%M:%S</local-time><ostag></ostag>
  </request>
  ```

- **请求头**（关键）：

  ```
  User-Agent / Algo-ID / Client-ID / CDC-Checksum / CDC-SchoolId / CDC-Domain / CDC-Area
  ```

  其中 `CDC-Checksum` = 编码后 body 的 **MD5 小写十六进制**；`Algo-ID` 从 `zxmAlogic.zxm` 读取。

- **响应**：chunked 传输 → 去分块 → `DeCode()` 解码 → 解析 XML
  - ticket 响应：`<response><ticket>..</ticket><expire>..</expire></response>`
  - auth 响应：`<response><userid>..</userid><keep-retry>..</keep-retry>..</response>`

- **客户端 IP**：`wlanuserip` / `clientip` 必须是**服务端看到的源 IP**（程序自动探测并替换）。
  用错 IP 会被服务端以 `Error-Code: 10`（无效客户端 IP）拒绝，或查询返回 `300`。
  多网卡机器请确认 `ip route get <门户IP>` 走的是校园网卡（详见 [FAQ](#报-error-code-10无效客户端-ip)）。

- **成功判据**：服务端响应头 `Error-Code == 0` 且 `<response>` 可解析（与原客户端 `CPortalConn::Connect` 一致）。
  注意 `<keep-retry>` 是 keep-alive 重试参数，**不是**错误码。

### 常见服务端 `Error-Code`（对应 `conf/code.xml` 的 1400XX）

| Error-Code | 含义 |
|---|---|
| 0 | 成功 |
| 1 | 无效请求（例如对 ticket.cgi 用 GET） |
| 10 | 无效客户端 IP（本机 IP 与请求参数不一致） |
| 13 | 无效算法 ID（缺少/错误 `Algo-ID` 头） |
| 14 | 无效 ticket |

---

## 6. 更换学校 / 其他校区

已支持较完整的动态化（`--dynamic`）：

| 参数 | 来源 |
|---|---|
| ticket / auth / state / term 服务器与端口 | 门户 `index.cgi` 的 `ServerIPs` |
| `wlanacip` / `wlanacname` / `clientmac` / `paip` / `vlan` / `iarmdst` / `portal_node` | 门户 URL（`GD_PORTAL_URL`），`conf.xml` 兜底 |
| `wlanuserip` / `clientip` | 本机实际源 IP（自动探测；多网卡见 FAQ） |
| `clientmac` | 门户 URL，缺失时读本机网卡 MAC |
| `clientId` / `schoolId` / `domain` / `area` | 仍来自 `conf.xml` |

换校区用法：

```bash
sh dynamic.sh 'http://<新校区门户>/...?wlanacip=..&wlanuserip=..'
```

未提供的参数沿用 `conf.xml`；若新校区的 `clientId / schoolId / domain / area` 不同，
把它们更新到 `conf/conf.xml` 即可（这几项门户目前不动态下发）。

## 7. 注意事项

- 账号、密码只在本地终端输入，程序不保存、不回显、不打印。
- 必须使用**真实终端**运行（`getpass` 需要 TTY）。
- 必须在 `final/` 目录下运行（程序需从当前目录读取 `zxmAlogic.zxm`）。
- 完整环境变量清单见 [环境变量速查](#环境变量速查)。
- 本程序**不含**原客户端的共享检测（`CheckWiFiShare`）、网络状态机与自动探门户；
  只做门户认证 / 保活 / 状态查询 / 注销，够用且行为可控。
- ARM 平台请看 [`../arm/README.md`](../arm/README.md)：源码可直接构建，
  但还缺与目标架构匹配的 `protect.so`。
