# Python 版拨号器

纯 **Python 标准库**实现，**零第三方依赖**（DES 自己实现，不用 pycryptodome）。

## 环境要求

- Python 3.8+（实测 3.14.8 正常）
- 无需 pip install 任何东西

## 怎么用（命令行）

打开命令行窗口：

```bat
cd "C:\Program Files (x86)\Chinatelecom_GDPortal\dialer\py"
dial.bat
```

会依次提示：

```
account : 12345678910        <- 输入账号（明文）
password: ********           <- 输入密码（隐藏，不回显）
```

然后自动登录 + 每 10 秒保活。

### ⚠️ Ctrl-C 不会自动登出

保活过程中按 `Ctrl-C`：

```
[*] 保活已停止（会话仍然登录中）
[?] 现在登出吗? (y/N):
```

- 输入 `y` → 发 `term.cgi` **登出**
- 输入 `n` / 直接回车 → **保持登录**，只是不再保活

**Ctrl-C 只是停掉本地保活程序，不会让服务器把你踢下线。**
想主动断网请选 `y`，或另开窗口跑 `logout.bat 账号`。

### 其它用法

```bat
dial.bat 12345607891                :: 账号在参数里，只问密码
python dialer.py 12345607891  -1     :: 登录一次就退出（不保活）
python dialer.py 12345607891  -p 密码 :: 密码写在命令行（会进历史，不推荐）
logout.bat 12345607891               :: 登出
python dialer.py -x                 :: 只看报文，不联网
python dialer.py --probe            :: 只探测 index+ticket，不做认证（安全）
```

### 全部选项

| 选项 | 说明 |
| --- | --- |
| `账号` | 位置参数，放第一个即可（省略则提示输入） |
| `-p <密码>` | 密码（省略则隐藏输入） |
| `-1` | 登录一次后退出（默认持续保活） |
| `-t` | 登出 |
| `-x` | dry-run：打印编码后的报文，不发包 |
| `--probe` | 只跑 index.cgi + ticket.cgi，不认证 |
| `-s <ip:port>` | 门户服务器（默认 `14.146.227.141:7001`） |
| `-n <name>` | wlanacname（默认 `SISE`） |
| `-a <ip>` | wlanacip（默认 `183.3.151.148`） |
| `-i <ip>` | paip（默认 `10.88.88.88`） |
| `-v <vlan>` | vlan（默认 `100.0`） |
| `-d <dst>` | iarmdst（默认 `www.189.cn/`） |
| `-m <mac>` | 手动指定 MAC（默认自动探测） |

本机 IP / MAC / 网关 / 主机名**全自动探测**（用 ctypes 调 `GetAdaptersInfo`），无需手动填。

## 实测输出

```
[*] 本机 ip=172.17.104.130 mac=6C-1F-F7-31-85-C5 gw=172.17.107.254 host=DESKTOP-IC8UURD
[*] index.cgi ...
[*] 获取算法 ...
[*] Algo-ID = E9747EF1-6849-4F87-957B-3B93E6A90393
[*] ticket.cgi ...
[+] ticket = 4018fb05d5dad6108bf7430a4391756d
[*] state.cgi ...
[*] auth.cgi ...
[+] 登录流程完成
[*] 每 10 秒保活一次 (Ctrl-C 退出)
[+] 保活 ok 20:31:05
```

## 文件

| 文件 | 说明 |
| --- | --- |
| `body_codec.py` | 报文编解码器（纯 Python DES + 6 重级联） |
| `dialer.py` | 拨号器（协议流程 + 自动探测 + 交互输入） |
| `dial.bat` | 一键登录启动器 |
| `logout.bat` | 一键登出启动器 |

## 自检

```bat
python body_codec.py
```

输出：

```
  DES KAT   OK
  encode    OK
  decode    OK
SELFTEST PASS
```

## 报文编码算法

```
body = hex( E_k3( D_k2( E_k1( E_k6( D_k5( E_k4( 归一化XML 补NUL到8字节,最小64 )))))) )

6 把静态 DES 密钥:
  k1=462b2b2a6c69237a  k2=535373683f437e2b  k3=7c2b216229407b3f
  k4=23594b7c747a513b  k5=536e5f403a54432a  k6=2525624a43275a53

归一化: encoding="UTF-8" -> "utf-8"，缺失时补 <?xml version="1.0" encoding="utf-8"?>
```

服务器响应也是同样加密 + HTTP chunked 传输，程序会自动处理。

## 常见问题

**Q: 提示 `python not found in PATH`**
装一个 Python 3，安装时勾选 "Add Python to PATH"；或直接编辑 `dial.bat`，
把 `python` 改成完整路径，例如
`C:\Users\你的用户名\AppData\Local\Programs\Python\Python314\python.exe`。

**Q: 中文显示乱码**
`dial.bat` 已经设置 `chcp 65001` + `PYTHONUTF8=1`。如果还乱码，
可以在文件开头加 `chcp 936`。

**Q: 密码会留在历史里吗**
用 `-p` 会留在命令历史。**推荐不带 `-p`**，程序用 `getpass` 隐藏输入，不会留痕。

**Q: 在别的网络环境下连不上**
`wlanacip` / `paip` / `vlan` / `wlanacname` 这些是校园网环境参数，
换地点时可能需要用 `-a` / `-i` / `-v` / `-n` 覆盖。
