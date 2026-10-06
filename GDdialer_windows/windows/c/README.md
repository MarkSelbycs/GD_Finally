# ESurfing 校园网拨号器 (C 语言实现)

只做三件事：**登录 / 保活 / 登出**。不含任何共享检测（不上报 Wifisignal、不探测 detect.html、不扫描 CheckWifi）。

## 编译

```powershell
# 已随附 TCC（tools\tcc\tcc.exe），或用自己的 gcc/mingw
tcc -o dialer.exe dialer.c body_codec.c md5.c -lws2_32 -liphlpapi
```

## 用法（纯命令行，无图形界面）

**最简单：直接双击 `dial.bat`，或运行**

```bat
dial.bat
```

程序会依次交互提示：

```
account : 12345678910        <- 输入账号（明文显示）
password: ********           <- 输入密码（显示 *，不回显）
```

然后自动登录并每 10 秒保活一次（Ctrl-C 退出）。

### 其它用法

```bat
dial.bat 12345678910             :: 账号写在参数里，只提示密码
dialer.exe 12345678910 -1        :: 登录一次就退出（不保活）
dialer.exe 12345678910 -p 密码    :: 密码写在命令行（会进命令历史，不推荐）
logout.bat 12345678910           :: 登出
dialer.exe -x                    :: 只看会发什么报文，不联网
dialer.exe --probe               :: 只探测（index+ticket，不做认证，安全）
```

`account` 直接放第一个位置即可；IP/MAC/网关/主机名**全自动探测**，无需手动填。

> 注意：账号/密码提示用的是控制台直接读键，必须在**真实命令行窗口**里运行
> （不能在管道/重定向下运行，否则会一直等待输入）。


## 全部选项

| 选项 | 说明 |
| --- | --- |
| `<account>` | 账号（位置参数，放第一个即可） |
| `-p <password>` | 密码（省略则隐藏输入提示） |
| `-1` | 登录一次后退出（默认登录后持续保活） |
| `-t` | 登出 |
| `-x` | dry-run：打印编码后的报文，不发包 |
| `--probe` | 只跑 index.cgi + ticket.cgi，不做认证 |
| `-s <ip:port>` | 门户服务器（默认 `14.146.227.141:7001`） |
| `-n <name>` | wlanacname（默认 `SISE`） |
| `-a <ip>` | wlanacip（默认 `183.3.151.148`） |
| `-i <ip>` | paip（默认 `10.88.88.88`） |
| `-v <vlan>` | vlan（默认 `100.0`） |
| `-d <dst>` | iarmdst（默认 `www.189.cn/`） |
| `-m <mac>` | 手动指定 MAC（默认自动探测） |

本机 IP / MAC / 网关 / 主机名都是**自动探测**的，通常无需手动指定。

## 输出示例

```
[*] local ip=172.17.104.130 mac=6C-1F-F7-31-85-C5 gw=172.17.107.254
[*] index.cgi ...
[*] fetching algorithm ...
[*] Algo-ID = E9747EF1-6849-4F87-957B-3B93E6A90393
[*] ticket.cgi ...
[+] ticket = 4018fb05d5dad6108bf7430a4391756d
[*] state.cgi ...
[*] auth.cgi ...
[+] login flow completed
[*] keepalive every 10s (Ctrl-C to stop)
[+] keepalive ok
[+] keepalive ok
```

## 文件说明

| 文件 | 说明 |
| --- | --- |
| `body_codec.c/h` | 门户报文编解码器（6 重 DES 级联 + 归一化 + hex），自包含 |
| `md5.c/h` | 自包含 MD5（`CDC-Checksum` 用） |
| `dialer.c` | 完整拨号器（WinSock HTTP + 协议流程） |
| `portal_codec.c` | 报文编解码命令行工具 |
| `test_body_codec.c` | 测试（DES 已知答案 + 真实报文往返） |
| `winsock_min.h` | 最小 Winsock 声明（TCC 无 SDK 头时用） |

## 报文编码算法

```
body = hex( E_k3( D_k2( E_k1( E_k6( D_k5( E_k4( 归一化XML 补NUL到8字节,最小64 )))))) )

6 把静态 DES 密钥:
  k1=462b2b2a6c69237a  k2=535373683f437e2b  k3=7c2b216229407b3f
  k4=23594b7c747a513b  k5=536e5f403a54432a  k6=2525624a43275a53

归一化: encoding="UTF-8" -> "utf-8"
```

服务器响应也是同样加密的（并采用 HTTP chunked 传输），拨号器会自动解块+解密。

## 验证

| 项 | 结果 |
| --- | --- |
| DES 已知答案向量 | OK |
| 5 个真实抓包 body 解码→重编码往返 | 5/5 |
| 与真实模块输出逐字节对照 | 26/27 |
| **真实服务器联调（index + ticket）** | **HTTP 200 / Error-Code 0 / 拿到 ticket** |
