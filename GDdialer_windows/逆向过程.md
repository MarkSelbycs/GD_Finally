# 天翼校园客户端 逆向全过程记录

> 从零开始，把一个 Windows 校园网客户端（`Chinatelecom_GDPortal` / `ESurfingClient`）
> 的登录协议完整逆向出来，并用纯 C 重写成独立拨号器的全过程。
>
> 记录时间线、每一步用的软件、关键突破点、以及 **Windows 与 Linux 的差异**。

---

## 0. 摘要（最终成果）

| 项目 | 结果 |
| --- | --- |
| 目标 | 天翼校园 Windows 客户端（`ESurfingClient.exe` 1068 版 / `ESurfingSvr.exe`） |
| 产出 | 纯 C 独立拨号器（登录 / 保活 / 登出，**不含共享检测**） |
| 核心难点 | 门户报文 body 的**动态加密算法** |
| 最终算法 | **6 重 DES 级联**（6 把静态密钥）+ XML 归一化 + 大写 hex |
| 验证 | 真实服务器联调：HTTP 200 / `Error-Code: 0` / 成功拿到 ticket |

最终算法一句话：

```
body = hex( E_k3( D_k2( E_k1( E_k6( D_k5( E_k4( normalise(xml) 补 NUL 到 8 字节, 最小 64 )))))) )
```

---

## 1. 目标与环境

```
C:\Program Files (x86)\Chinatelecom_GDPortal\
├── ESurfingClient.exe      主程序（GUI，稳定进程）
├── ESurfingSvr.exe         后台服务（真正拨号，短命进程）
├── log\20261006_svrinfo.log  拨号日志（关键线索来源）
└── ...
```

运行环境：Windows 10 19045，WLAN 网卡（Ugreen USB WiFi），
门户地址 `14.146.227.141:7001` / `121.8.177.212:7001`。

---

## 2. 用到的软件清单

| 软件 | 版本 | 用途 |
| --- | --- | --- |
| **pktmon** | Windows 10 内置 | 网络层抓包（不需要 attach 进程，最可靠） |
| **Frida** | 17.22.2 | 动态插桩：hook 函数、dump 内存、**直接调用模块函数** |
| **Python** | 3.12.14（DSH 自带） | 所有分析脚本 |
| **capstone** | 5.0.7 | x86 反汇编 |
| **pycryptodome** | 3.23.0 | DES / AES / RC4 等密码学验证 |
| **numpy** | 2.3.5 | 数据比对 |
| **TinyCC (tcc)** | 0.9.27 win64 | 编译 C 版拨号器（轻量，随附） |
| PowerShell 7 | — | 自动化：打补丁 / 断网 / 抓包 / 还原 一条龙 |
| AutoHotkey | 用户已有 | 用户自己写的自动物理登录脚本 |

> 说明：**没有用** IDA / Ghidra 这类重型反汇编器。全程用 capstone 写脚本按需反汇编，
> 因为目标是"找到某个函数并理解它"，脚本化比 GUI 更快、更可复现。

---

## 3. 逆向时间线（0 → 现在）

### 阶段 1：摸清通信（pktmon 抓包）

第一步不碰二进制，先看它**说了什么**。

```
pktmon filter remove
pktmon filter add -p 7001
pktmon start --capture --pkt-size 0 --file-name cap.etl
... 触发一次拨号 ...
pktmon stop
pktmon etl2pcap cap.etl -o cap.pcapng
```

然后用 Python 解析 pcapng（自己写，含 **TCP 重组**，因为 body 跨多个段）：

**得到的关键事实：**

```text
GET  /index.cgi?wlanacip=..&wlanuserip=..&clientip=..&wlanacname=SISE&clientmac=..&paip=..&vlan=..&iarmdst=..
POST /ticket.cgi    body = 大写 hex
POST /state.cgi     body = 大写 hex
POST /auth.cgi      body = 大写 hex
POST /keep.cgi      body = 大写 hex
POST /term.cgi      body = 大写 hex
GET  /detect.html   (共享检测)
POST /esurfing/esurfingclient/Wifisignal  (共享检测上报, JSON)

请求头：
  User-Agent: CCTP/WinSVR5/1068
  Algo-ID: <每拨号不同>
  Client-ID: 1009758f-89f4-413c-929b-c5e0e35b0d54
  CDC-Checksum: <body 的 MD5>
  CDC-SchoolId: 1099
  CDC-Domain: sise.cn
  CDC-Area: 020
```

**body 的特征**（最关键的线索）：
- 全部是大写 hex，解码后长度都是 8 的倍数（376 / 392 / 304 / 248 / 272 字节）
- 5 种请求共享**前 48 字节**（`C853A9968496B3E0...`）→ 说明开头明文相同
- keep 与 term 存在**偏移 120 字节**的整块共享 → 位置无关 → **分组密码**

### 阶段 2：容器格式（XXTEA + LZMA）

抓包时发现一个可疑响应：

```text
001@6ADD6889806FF9C9E0E6E95487A73F9064FEC817537CF22184303CEAA9B27EA8$E9747EF1-6849-4F87-957B-3B93E6A90393]...
```

这是"算法容器"：`001@<32字节hex密钥>$<Algo-ID>]<载荷>`。

用 capstone 在 `ESurfingSvr.exe` 里找到它的解析函数（调度器 `0x4156b0`），
逆出：

```
载荷 = 8 字节前缀 + XXTEA(逐8字节, 两把密钥) 密文
解出 = raw-LZMA 压缩的 PE
```

XXTEA 是**非标准变体**（`key[sum&3]` / `key[(sum>>11)&3]`，delta `0x9E3779B9`），
用 Frida hook 读到运行时真实密钥：

```
key1 = |iKFMm;FZjI6oItG
key2 = mvm536xR8MJ-5C89
```

**验证**：`24624 → XXTEA → 24616 → raw-LZMA → 46596 字节合法 PE (MZ)` ✅

### 阶段 3：走错的路（重要教训）

一开始以为 body 编码就在 `ESurfingSvr.exe` 里，逐个试探：

| 尝试 | 结果 |
| --- | --- |
| XXTEA / RC4 / AES / DES / Blowfish / TEA / XTEA + 各种已知密钥 | ✗ 全部失败 |
| 各种压缩（zlib/deflate/gzip/bz2/LZMA 全格式） | ✗ |
| 字节替换 / 流密码 | ✗（同位置 `m` 和空格都变成 `0x96`） |

**结论：body 不是这些。必须换思路。**

### 阶段 4：动态插桩定位（Frida）

**第一次突破**：注意到 body 的 `Algo-ID` 与容器里的 `Algo-ID` **完全一致**：

```text
容器:      001@6ADD6889...$E9747EF1-6849-4F87-957B-3B93E6A90393]
ticket:    Algo-ID: E9747EF1-6849-4F87-957B-3B93E6A90393
```

→ **编码器就是每次拨号动态下载的那个算法模块！**

于是：
1. 写 `fetch_module.py` 自己复现容器下载，把模块 PE 抠出来（46596 字节）
2. 用 Frida **内存特征扫描**找到模块加载基址（用模块入口 24 字节特征码 + `MZ` 头校验）
3. hook 模块入口 `0x8585` → 发现它只做编排
4. hook 到 `+0x6b65` → **抓到了编码器的输入输出！**

```text
[+0x6b65] 输入 = "<?xml version="1.0" encoding="UTF-8"?><request>..<reason>7</reason>..<lo"
[+0x6b65] 输出 = "C853A9968496B3E062B640DF7A9A022C..."
```

### 阶段 5：补丁闭环实验（排除法）

为了确认"body 到底走哪条路"，建立了一个**可重复的验证闭环**：

```powershell
# 一条龙脚本（do_rc4_test.ps1 / do_no_codec_test.ps1）
1. 杀掉所有 ESurfing 进程
2. 把 ESurfingSvr.exe 里某个函数首字节改成 ret  （打补丁）
3. 校验补丁确实写到盘上
4. pktmon 开始抓包
5. 禁用再启用 WLAN 网卡 → 强制触发一次真实拨号
6. 抓包 → 分析 body
7. 还原 EXE（从 .bak 复制）
8. 再断网重连，让网络恢复
```

**结果：**

| 被补丁的函数 | body 是否变化 |
| --- | --- |
| 自定义 SPN 流密码 `0x4331d0`（`xor esi,eax`→`mov esi,eax`） | **不变** |
| RC4 `0x425e80`（→ `ret 0x10`） | **不变** |
| XXTEA `0x4260b0`（→ `ret 0xc`） | **不变** |

→ **彻底排除 EXE 内置密码，坐实"编码在下载模块里"**。

> ⚠️ 这个实验有风险（断网），但用户有 AutoHotkey 自动物理登录兜底，且脚本自带还原步骤。

### 阶段 6：预言机（决定性的一步）

既然 `0x6b65(xml) → hex body`，那就**把它当函数直接调**：

```javascript
// Frida: 扫描模块基址后
const fn = new NativeFunction(base.add(0x6b65), 'pointer', ['pointer']);
rpc.exports.encode = function (xml) {
    return cstr(fn(Memory.allocUtf8String(xml)));   // 返回 hex 字符串
};
```

于是有了**无限对照组**！用构造的 XML 喂进去，观察输出规律：

```text
in=  57B -> out= 64B   C853A996...   ← 输出长度都是 16 的倍数！
in=  83B -> out= 80B   C853A996...
in= 121B -> out=128B   C853A996...
所有输出共享 40 字节前缀
字段每多 8 字节，输出多 8 字节
```

**推论：8 字节/16 字节分组密码 + 固定的 40 字节头。**

### 阶段 7：识别为 DES（静态反汇编）

用 capstone 反汇编编码器 `0x6b65`，看到主循环：

```asm
loop:
  memcpy(dest, src, max(len,8))
  call 0x10005c78(data, state+0x18)
  call 0x10005e5b(data, state+0x20)
  call 0x10005c78(data, state+0x28)
  call 0x10005c78(data, state+0)
  call 0x10005e5b(data, state+8)
  call 0x10005c78(data, state+0x10)
  len -= 8; dest += 8; src += 8
```

再反汇编 `0x5c78`，看到它**逐位展开**成 64 位数组，然后查表：

```asm
call 0x10005adb(bitarray, 0x1000c378, 0x40)   ; 64 项表
call 0x10005adb(bitarray, 0x1000c0d8, 0x38)   ; 56 项表
```

把两张表 dump 出来（注意是 **DWORD 数组**）：

```text
0x1000c378 = [58,50,42,34,26,18,10,2,60,52,44,36,28,20,12,4,...]   ← DES 初始置换 IP！
0x1000c0d8 = [57,49,41,33,25,17,9,1,58,50,42,34,26,18,...]         ← DES 密钥置换 PC-1！
```

**这就是 DES。**（之前"没有 256 字节表"的判断误导了我——DES 用的是 64/56/48 字节的表。）

### 阶段 8：抓密钥 + 穷举方向

`0x5a77` 从静态表 `0x1000c568 + 46`、长度 48 处取密钥：

```text
462b2b2a6c69237a 535373683f437e2b 7c2b216229407b3f
23594b7c747a513b 536e5f403a54432a 2525624a43275a53
```

（48 字节 = **6 把 DES 密钥**）

再用 Frida hook `0x5c78` 直接 dump 出实际使用的密钥字节 + 数据流，确认无误。

最后：6 把密钥、6 个操作位，一共 `2^6 = 64` 种加密/解密排列，
写个 Python 脚本**穷举**：

```
!!! HIT combo (1, 0, 1, 1, 0, 1)     # 顺序 [k4,k5,k6,k1,k2,k3]，操作 [E,D,E,E,D,E]
```

**瞬间对上！** `<?xml ve` → `C853A9968496B3E0` ✅

### 阶段 9：完整验证

| 验证 | 结果 |
| --- | --- |
| 预言机 27 组构造输入 | **26/27** 逐字节一致（唯一失败是非法 XML 的错误路径） |
| 5 个真实抓包 body 解码 | **5/5** 全部解出明文 XML |
| 解码→重编码往返 | **5/5** 完全还原 |

顺带解出了五种请求的完整明文结构：

```text
ticket: ostag, local-time, gwip, mac, ipv6, ipv4, client-id, user-agent, host-name
keep:   local-time, excheck-args(hello/conn), mac, ipv6, ipv4, ticket, client-id, user-agent
auth:   local-time, ticket, passwd, userid, client-id, user-agent
state:  local-time, ticket, client-id, user-agent
term:   reason, local-time, ticket, client-id, user-agent
```

### 阶段 10：C 重写 + 真实服务器联调

1. 下载 **TinyCC**（用户授权下载软件）
2. 写自包含 DES（标准表 + 位运算）
3. 写 `body_codec.c`（6DES 级联）、`md5.c`、`dialer.c`
4. TCC 缺少 Windows SDK 头 → 自己写 `winsock_min.h`（最小 Winsock + iphlpapi 声明）
5. 编译、自检（DES 已知答案 + 真实报文往返全部通过）
6. **真实服务器联调**：

```
[*] index.cgi ok, 26799 bytes
[*] Algo-ID = E9747EF1-6849-4F87-957B-3B93E6A90393
[+] decoded response: <response><ticket>4018fb05d5dad6108bf7430a4391756d</ticket>
    <expire>1791232158</expire></response>
[+] TICKET = 4018fb05d5dad6108bf7430a4391756d
```

服务器返回 **HTTP 200 + `Error-Code: 0` + 有效 ticket** → 全链路打通 ✅

---

## 4. 最终算法（完整版）

```
1) 归一化 XML
   - encoding="UTF-8"  →  encoding="utf-8"
   - 缺少声明时补上 <?xml version="1.0" encoding="utf-8"?>

2) 补位
   - 末尾补 NUL，长度向上取整到 8 的倍数
   - 最小 64 字节

3) 逐 8 字节块做 6 重 DES 级联
   E_k4 → D_k5 → E_k6 → E_k1 → D_k2 → E_k3

   密钥（静态）：
     k1 = 46 2b 2b 2a 6c 69 23 7a
     k2 = 53 53 73 68 3f 43 7e 2b
     k3 = 7c 2b 21 62 29 40 7b 3f
     k4 = 23 59 4b 7c 74 7a 51 3b
     k5 = 53 6e 5f 40 3a 54 43 2a
     k6 = 25 25 62 4a 43 27 5a 53

4) 转大写 hex
```

**解密**就是把 6 步反过来（顺序倒置 + 每个操作取反）。

**服务器响应**用同一套算法加密，并且用 HTTP `Transfer-Encoding: chunked` 传输
（注意：chunk 大小是十六进制，`110\r\n` = 272 字节）。

---

## 5. 是纯 Windows 吗？和 Linux 有什么不同？

### 5.1 分层看

| 层 | 是否 Windows 专属 | 说明 |
| --- | --- | --- |
| **门户协议**（HTTP 端点、参数、请求头、XML 结构） | ❌ 通用 | 这是中国电信标准门户协议，Win/Linux/Android 客户端都一样 |
| **body 编码算法**（6DES 级联） | ⚠️ 这个是 **Windows 客户端**的 | 见下 |
| **代码实现** `body_codec.c` / `md5.c` | ❌ **纯标准 C，零 Windows 依赖** | 可以直接在 Linux 编译 |
| **代码实现** `dialer.c` 的网络层 | ✅ Windows 专属 | WinSock + iphlpapi（探测本机 IP/MAC/网关） |

### 5.2 具体差异

**① 协议层（Win / Linux 相同）**

```
POST /ticket.cgi?wlanacip=...&wlanuserip=...&clientmac=...
User-Agent: CCTP/WinSVR5/1068     ← Windows 客户端标识
Algo-ID / Client-ID / CDC-Checksum / CDC-SchoolId / CDC-Domain / CDC-Area
```

Linux 客户端用相同的 URL 和字段，只是 `User-Agent` 和 `ostag`（系统标识）不同。

**② 编码层（这是 Windows 客户端特有的关键差异）**

Windows 客户端的 body 编码**不是写死在程序里的**，而是：

```
每次拨号 → 向服务器要一个"算法容器"
        → 容器里有 <32字节密钥> + <Algo-ID> + 加密压碎的算法模块(PE)
        → 客户端解密加载该模块
        → 调用模块的编码函数（实测每次 Algo-ID 会变：7F224CA8 / E9747EF1 ...）
```

**我们逆出来的结论是：不管 Algo-ID 怎么变，模块实现的算法都是一样的
——6 重 DES 级联 + 6 把固定密钥。**

所以最终 C 拨号器**不需要下载模块**，直接内置算法即可（只要在请求头里带上
服务器给的那个 Algo-ID 就行）。

> Linux 客户端（据早期资料）走的是另一套实现，报文编码方式与 Windows 不完全相同。
> **本次逆向只针对 Windows 客户端**，Linux 侧需要单独验证。

**③ 代码移植到 Linux 需要改什么**

`body_codec.c` / `body_codec.h` / `md5.c` / `md5.h` **一行都不用改**（纯标准 C）。

只有 `dialer.c` 需要替换：

| Windows 实现 | Linux 对应 |
| --- | --- |
| `<winsock2.h>` + `socket/connect/send/recv` | `<sys/socket.h>` 同名函数 |
| `GetAdaptersInfo()` 取 IP/MAC/网关 | `getifaddrs()` + `ioctl(SIOCGIFHWADDR)` |
| `GetComputerNameA()` | `gethostname()` |
| `Sleep(ms)` | `usleep(ms*1000)` |
| `_getch()`（隐藏输入） | `termios` 关掉 ECHO |

代码里已经用 `#ifdef _WIN32` 预留了这些分支，改起来就是几十行。

### 5.3 一句话回答

> **协议和加密算法是通用的；我写的 C 编解码器也是纯标准 C、可以直接搬到 Linux；
> 只有拨号器最外层的"取网卡信息 + 收发 HTTP"那部分目前是 Windows 专属，
> 但已经做好条件编译分支，移植量很小。**
>
> 需要注意：**Linux 客户端本身的加密实现可能与 Windows 版不同**，
> 如果要写 Linux 版拨号器，`body_codec.c` 里的密钥/级联顺序需要重新验证。

---

## 6. 交付物

### C 版拨号器（`windows\c\`）

| 文件 | 说明 | 行数 |
| --- | --- | --- |
| `body_codec.c/h` | 编解码器（自包含 DES + 6DES 级联） | ~300 |
| `md5.c/h` | MD5（CDC-Checksum 用） | ~110 |
| `dialer.c` | 拨号器（WinSock HTTP + 协议流程 + 自动探测） | ~800 |
| `portal_codec.c` | 报文 encode/decode 命令行工具 | ~150 |
| `test_body_codec.c` + `test_vectors.h` | 测试（DES KAT + 5 真实报文往返） | ~120 |
| `winsock_min.h` | 最小 Winsock/iphlpapi 声明（TCC 用） | ~110 |
| `dial.bat` / `logout.bat` | 一键启动器 | — |
| `README.md` | 使用说明 | — |

编译好的 `dialer.exe` / `portal_codec.exe` / `test_codec.exe` 已生成。

### 逆向过程脚本（`windows\`）

| 文件 | 用途 |
| --- | --- |
| `zxm_container.py` | 容器解码器（XXTEA + LZMA），已验证 |
| `fetch_module.py` | 复现算法模块下载 |
| `tcp_reassemble.py` | pcapng 解析 + TCP 重组 |
| `body_codec.py` | Python 版编解码器（逆向阶段用） |
| `frida_hook_encoder.py` | 定位并 hook 编码器 `0x6b65` |
| `frida_oracle.py` / `frida_oracle_battery.py` | **预言机**（直调模块函数） |
| `frida_hook_des_key.py` | dump DES 密钥与数据流 |
| `do_rc4_test.ps1` / `do_no_codec_test.ps1` | 补丁闭环实验脚本 |
| `RE_CINNERCODER.md` | 逆向笔记（中间结论） |

---

## 7. 复现步骤（简版）

```powershell
# 1. 抓一次真实拨号
pktmon filter add -p 7001
pktmon start --capture --pkt-size 0 --file-name cap.etl
# (触发拨号)
pktmon stop; pktmon etl2pcap cap.etl -o cap.pcapng
python tcp_reassemble.py cap.pcapng        # 看请求与 body

# 2. 拿到算法模块
python fetch_module.py                     # 下载容器
python zxm_container.py                    # 解出模块 PE

# 3. 挂预言机（需要目标程序正在运行）
python frida_oracle_battery.py             # 构造输入 → 收集输出

# 4. 编译拨号器
cd c
tcc -o dialer.exe dialer.c body_codec.c md5.c -lws2_32 -liphlpapi
dial.bat
```

---

## 8. 踩过的坑（给后来人）

1. **"没有查表"不等于"没有密码算法"**
   我一开始搜 256 字节置换表来判断是不是 AES/DES —— 结果 DES 根本不用 256 字节表。
   应该搜的是 **64/56/48 字节的置换表**。

2. **VA ↔ 文件偏移映射必须按节表算**
   早期用 `va - imagebase` 当文件偏移，差了 `0xC00`，导致反汇编出一堆乱码，
   还得出过"这个二进制被混淆了"的错误结论。

3. **不要只盯主程序**
   最关键的函数不在 `ESurfingSvr.exe` 里，而在**每次拨号动态下载的模块**里。
   线索是：`Algo-ID` 在请求头和容器里完全一致。

4. **短命进程 attach 不上时，改用网络层抓包**
   拨号服务进程生命周期极短，Frida 经常报 `0xc000010a`（进程正在退出）。
   这时 pktmon 这种网络层抓包反而稳。

5. **"禁用一个函数"比"猜算法"快得多**
   与其反复试 XXTEA/AES/RC4，不如把函数首字节改成 `ret`（注意 stdcall 要写成
   `C2 xx 00` 自清栈），然后看行为变不变。三轮就排除了全部内置密码。

6. **能"调用"就不要"猜测"**
   发现 `0x6b65` 之后，最高效的做法不是继续读汇编，而是用 Frida 把它当函数调，
   构造输入收集输出 —— 有了对照组，规律很快就看出来了。

7. **Windows 控制台是 GBK**
   程序里的 `—`（U+2014）在 GBK 控制台会显示成 `鈥?`。给 Windows 用的命令行程序
   **输出尽量只用 ASCII**。

8. **`_getch()` 不能从管道读**
   用 `_getch` 做隐藏密码输入时，程序必须运行在真实控制台窗口里，
   不能用管道/重定向测试（会一直阻塞等待输入）。

---

## 9. 免责声明

本文档仅用于**自己的设备、自己的账号**的网络接入研究与自动化，
目的是替代臃肿的官方客户端、并去掉其中的**共享设备检测**上报。
请遵守所在学校/运营商的网络使用规定。
