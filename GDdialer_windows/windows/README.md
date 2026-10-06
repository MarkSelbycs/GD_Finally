# Windows 拨号包

本目录提供三条可选路径。按可行性从高到低排列。

## 路径 A：直接使用你自带的 2024 版工具（推荐，已验证可运行）

`ESurfingDialer-onekey` 是你自己的项目，使用桌面门户协议，并通过 unidbg
（Dynarmic/Unicorn2）模拟 Android 环境运行客户端原生算法模块，因此**不需要**
逆向 zsm 编码即可正确加解密请求体。项目自带 JRE 21。

```powershell
cd "C:\Program Files (x86)\Chinatelecom_GDPortal\ESurfingDialer-onekey"
.\Start_ESurfingDialer.bat
```

等价命令：

```powershell
.\jre\bin\java.exe -jar ESurfingDialer-1.4.0-all.jar -u 账号 -p 密码
```

参数：`-u/--user`、`-p/--password`、`-d/--dynarmic`（使用 Dynarmic 后端）。

关键常量（从 jar 中提取）：

```text
BASE_URL   = http://14.146.227.141:7001
AUTH_URL   = http://14.146.227.141:7001/auth.cgi
ticket     = http://14.146.227.141:7001/ticket.cgi?wlanuserip=..&wlanacip=..&portal_node=http://61.140.12.23:10002
USER_AGENT = CCTP/android64_vpn/2085
PACKAGE_ID = com.cndatacom.campus.cdccportalgd
CAPTIVE    = http://www.gstatic.com/generate_204
原生接口   = load([B)J / enc(J,[B)[B / dec(J,[B)[B / getAlgoId
```

## 路径 B：手机协议 Python 拨号器（无需算法，最轻量）

按你 `LandLeg_Java-master` 的手机协议实现，纯 Python，**完全不涉及 zsm/XXTEA**。

```powershell
cd "C:\Program Files (x86)\Chinatelecom_GDPortal\windows"
.\run_enet.bat
```

或：

```powershell
py -3 enet_dialer.py --user 账号
py -3 enet_dialer.py --user 账号 --once          # 只测一次保活
py -3 enet_dialer.py --user 账号 --logout        # 只登出
```

协议：

```text
challenge : POST http://enet.10000.gd.cn:10001/client/challenge
login     : POST http://enet.10000.gd.cn:10001/client/login
keepalive : GET  http://enet.10000.gd.cn:8001/hbservice/client/active
logout    : POST http://enet.10000.gd.cn:10001/client/logout

secret    = "Eshore!@#"
iswifi    = "4060"
authenticator = MD5(clientip + nasip + mac + timestamp + secret)              # 大写
登录时再加 challenge = MD5(clientip + nasip + mac + timestamp + challenge + secret)
nasip     = 访问 http://www.baidu.com 重定向 Location 中的 wlanacip
```

已核对：签名与该 Java 参考实现逐字节一致。

实测连通性（2026-10-05）：

```text
enet.10000.gd.cn:10001 -> 61.140.12.23   可连接
enet.10000.gd.cn:8001  -> 超时           保活端口可能被封
14.146.227.141:7001    -> 可连接
```

如果 `--once` 报保活失败，说明 8001 不通，请改用路径 A。

## 路径 C：桌面门户协议 Python 实现（需要算法，未完成）

`portal_minimal.py` 实现了桌面协议的报文结构和登录/保活/登出流程，
但请求体编码需要 `zsm` 算法。当前状态：

- 桌面协议报文、端点、请求头、身份参数均已对齐真实抓包
- Windows 端的算法实例（Algo-ID `E9747EF1-…`）不在工作区内
- 根目录 `zxmAlogic.zxm` 是 **Linux 容器**，原生 Windows 服务加载时报
  `ERROR 193`（不是有效的 Win32 程序），见 `FINDINGS.md`
- 从 `ESurfingSvr.exe` 的 `CInnerCoder` 已恢复出算法族（RC4 + 自定义
  2 字 XXTEA + hex）与两套密钥数组，但尚未命中真实流量使用的模式组合，
  见 `RE_CINNERCODER.md`

```powershell
py -3 windows_dialer.py
```

## 注意

- 账号密码只在运行时读取，不保存到配置文件（路径 A 的 bat 会写入 `config.txt`）。
- 本目录的实现只做登录、保活、登出，不实现共享检测。
- 路径 C 需要能访问校园认证网关；`portal_config.json` 已按抓包真实值填写。
