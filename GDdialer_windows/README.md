# 天翼校园网拨号器

独立实现的校园网拨号器，**只做三件事**：

- ✅ 登录
- ✅ 保活
- ✅ 登出

**不含**任何共享设备检测（不上报 `Wifisignal`、不探测 `detect.html`、不扫描 `CheckWifi`）。

---

## 选哪个版本？

| | C 版 | Python 版 |
| --- | --- | --- |
| 目录 | [`c/`](c/) | [`py/`](py/) |
| 运行依赖 | **无**（单个 exe，已编译好） | 需要装 Python 3 |
| 启动速度 | 瞬间 | 约 0.3 秒 |
| 适合 | 日常用、开机自启 | 想改代码 / 学习 |
| 编译 | 需要 tcc/gcc（已随附 tcc） | 不需要编译 |

**日常用选 C 版。**

---

## 快速开始

### C 版

```bat
cd c
dial.bat
```

提示 `account :` 输入账号，`password:` 输入密码（显示 `*`）。

### Python 版

```bat
cd py
dial.bat
```

同样交互提示账号和密码。

---

## 三个命令

| 操作 | C 版 | Python 版 |
| --- | --- | --- |
| **登录 + 保活** | `dial.bat` | `dial.bat` |
| **登出** | `logout.bat 账号` | `logout.bat 账号` |
| **只看报文（不联网）** | `dialer.exe -x` | `python dialer.py -x` |
| **只探测（不认证）** | `dialer.exe --probe` | `python dialer.py --probe` |

带上账号可以免去输入账号这一步：

```bat
dial.bat 12345678910
```

---

## ⚠️ 关于 Ctrl-C：不会自动登出

`dial.bat` 跑起来之后会**每 10 秒保活一次**。这时按 `Ctrl-C`：

```
[*] keepalive stopped (the session is STILL logged in)
[?] logout now? (y/N):
```

**程序会问你"要不要登出"**，不会直接退出：

- 输入 `y` → 立刻发 `term.cgi` 登出
- 输入 `n`（或直接回车）→ **保持登录状态**，只是不再保活了

### 为什么要这样

Ctrl-C 只是**停掉本地的保活程序**，它**不会**让服务器把你踢下线。
网络那边还是登录着的。

区别：

| 操作 | 网络是否还连着 |
| --- | --- |
| `Ctrl-C` 然后选 `n` | ✅ **还是连着的**（只是不再续期，可能过一阵被服务器超时踢掉） |
| `Ctrl-C` 然后选 `y` | ❌ 已登出 |
| `logout.bat 账号` | ❌ 已登出 |

所以：

- **想保持上网** → Ctrl-C 后选 `n`（或干脆别退出，让它一直挂着）
- **想主动断网** → Ctrl-C 后选 `y`，或者另开窗口跑 `logout.bat`

> 早期版本 Ctrl-C 是**直接杀掉程序、不登出**的，容易让人误会"我退出了所以断网了"。
> 现在改成了会询问。


---

## 它做了什么

```
1. GET  /index.cgi?<参数>              获取门户配置
2. POST /ticket.cgi  (38字节明文)      获取算法容器 → 解析出 Algo-ID
3. POST /ticket.cgi  (加密XML)         获取会话 ticket
4. POST /state.cgi   (加密XML)         上报状态
5. POST /auth.cgi    (加密XML)         认证（账号+密码+ticket）
6. POST /keep.cgi    (加密XML)         每 10 秒保活
7. POST /term.cgi    (加密XML)         登出
```

**它不发送的东西**（这些是原客户端用来做共享检测的）：

- `POST /esurfing/esurfingclient/Wifisignal` — 上报 Wi-Fi 信号/周围热点
- `GET  /detect.html` — 探测
- `CheckWifi` 本地扫描

---

## 报文编码算法（逆向结果）

门户请求 body 是：

```
body = hex( 6 重 DES 级联( 归一化XML ) )

级联顺序:  E_k4 → D_k5 → E_k6 → E_k1 → D_k2 → E_k3

6 把静态 DES 密钥:
  k1 = 46 2b 2b 2a 6c 69 23 7a     k4 = 23 59 4b 7c 74 7a 51 3b
  k2 = 53 53 73 68 3f 43 7e 2b     k5 = 53 6e 5f 40 3a 54 43 2a
  k3 = 7c 2b 21 62 29 40 7b 3f     k6 = 25 25 62 4a 43 27 5a 53

归一化: encoding="UTF-8" → "utf-8"，缺失声明时补上
补齐:   末尾补 NUL 到 8 字节边界，最少 64 字节
```

服务器响应也用同一套算法加密（外加 HTTP chunked 传输）。

想自己学怎么逆出来的，看 [`逆向教程_一步步.md`](逆向教程_一步步.md)；
完整过程记录见 [`逆向过程.md`](逆向过程.md)；密钥总表见 [`re/密钥与算法.md`](re/密钥与算法.md)。

---

## 验证状态

| 项 | 结果 |
| --- | --- |
| DES 已知答案向量 | ✅ OK |
| 5 个真实抓包报文解码→重编码往返 | ✅ 5/5 |
| 与真实客户端模块输出逐字节对照 | ✅ 26/27 |
| **真实服务器联调（index + ticket）** | ✅ **HTTP 200 / Error-Code 0 / 拿到 ticket** |
| C 版 / Python 版 | ✅ 两个版本都通过 |

---

## 目录结构

```
dialer/
├── README.md               <- 本文件
├── 逆向教程_一步步.md      <- ★ 从零教学：怎么自己逆向一个软件（12 步 + 附录）
├── 逆向过程.md             <- 本项目完整逆向过程记录
├── 逆向_REQUEST_怎么写.md  <- 以后怎么提逆向需求（避免被反问）
├── re/                     <- 逆向成果归档（密钥、算法、证据、脚本）
│   ├── README.md               成果索引
│   ├── 密钥与算法.md       ⭐ 所有密钥/算法总表
│   ├── keys.json           机器可读密钥表
│   ├── des_tables.txt      模块里的 DES 表
│   ├── 明文样本.txt        5 个真实报文的明文
│   ├── artifacts/          证据产物（算法模块 PE、容器样本、S-box…）
│   └── tools/              逆向脚本（容器解码、预言机、抓包解析…）
├── c/                 <- C 语言版（推荐）
│   ├── dial.bat           一键登录
│   ├── logout.bat         一键登出
│   ├── dialer.exe         已编译好的程序
│   ├── dialer.c           源码
│   ├── body_codec.c/.h    编解码器源码
│   ├── md5.c/.h            MD5 源码
│   ├── portal_codec.c     报文编解码工具
│   ├── test_body_codec.c  测试
│   ├── winsock_min.h      最小 Winsock 头（TCC 用）
│   └── README.md          C 版说明
└── py/                <- Python 版
    ├── dial.bat           一键登录
    ├── logout.bat         一键登出
    ├── dialer.py          拨号器
    ├── body_codec.py      编解码器（纯标准库）
    └── README.md          Python 版说明
```

---

## 换环境时可能要改的参数

这几个是**校园网环境参数**，换楼/换校区可能需要覆盖：

| 参数 | 默认值 | 说明 |
| --- | --- | --- |
| `wlanacname` | `SISE` | 无线控制器名称 |
| `wlanacip` | `183.3.151.148` | 无线控制器 IP |
| `paip` | `10.88.88.88` | 门户认证服务器 |
| `vlan` | `100.0` | VLAN |
| `iarmdst` | `www.189.cn/` | 认证后跳转地址 |
| `server` | `14.146.227.141:7001` | 门户服务器 |

本机 **IP / MAC / 网关 / 主机名是全自动探测的**，不用管。

---

## 免责声明

仅供**自己设备、自己账号**的网络接入使用，目的是替代臃肿的官方客户端。
请遵守所在学校/运营商的网络使用规定。
