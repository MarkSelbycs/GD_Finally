# 抓包结论（本机原生拨号器实测）

## 抓包方式

用 Windows 自带 `pktmon` 在本机被动抓取 7001 端口流量，未修改原始客户端：

```powershell
pktmon filter add -p 7001
pktmon start -c --pkt-size 0 --comp nics -f capture.etl
# 等待原生客户端发送保活请求
pktmon stop
pktmon etl2pcap capture.etl --out capture.pcapng
python parse_capture.py capture.pcapng
```

抓到的是原生拨号器自己的 `keep.cgi` 真实请求。

## 原生请求头（真实值）

```http
POST /keep.cgi HTTP/1.1
Connection: close
User-Agent: CCTP/WinSVR5/1068
Algo-ID: E9747EF1-6849-4F87-957B-3B93E6A90393
Client-ID: 1009758f-89f4-413c-929b-c5e0e35b0d54
CDC-Checksum: 176a420eef2f30ed71b264589be7a719
CDC-SchoolId: 1099
CDC-Domain: sise.cn
CDC-Area: 020
Content-Length: 784
Host: 14.146.227.142:7001
```

结论：

- `CDC-Checksum` 与请求体 MD5 **完全相同**，证明 `MD5(编码后 body)` 的校验算法正确。
- 请求**没有** `Content-Type` 头。
- `CDC-SchoolId` / `CDC-Domain` / `CDC-Area` 是必发头，值来自 `Config\ConnectSetting.ini`。
- 端点分主机：`ticket/auth/term/state` 在 `14.146.227.141:7001`，`keep` 在 `14.146.227.142:7001`。

## 编码格式与算法不匹配（关键结论）

请求体是**大写 ASCII 十六进制**，解码后：

| 数据 | ASCII hex 长度 | 二进制长度 | mod 16 | mod 8 |
| --- | --- | --- | --- | --- |
| keep 请求体 | 784 | 392 | 8 | 0 |
| keep 响应块 | 208 | 104 | 8 | 0 |

- 两者都**不是 16 的倍数**，所以不可能是 AES-128（16 字节分组）。
- 两者都是 **8 的倍数**，符合 8 字节分组密码。
- 用本地重建的 AES（两组 key、转置/非转置、多种 IV、8 字节头偏移）共 12 种组合尝试解密真实密文，**全部失败**。
- `ESurfingSvr.exe` 中检出 TEA/XXTEA 特征常量 `0x9E3779B9`，与 8 字节分组一致。

因此：根目录 `zxmAlogic.zxm` 里恢复出的是 **Linux 端 AES 算法**（Algo-ID `45433DCF-…`），而原生 Windows 端使用的是**另一套 8 字节分组算法**（Algo-ID `E9747EF1-…`）。两者不是同一算法实例。

## 为什么本地缺少 Windows 算法模块

`ESurfingSvr.log` 记录原生服务加载算法模块失败：

```text
LoadModExW ...\zxmAlogic.zxm Flags: 0
Load ...\zxmAlogic.zxm | ERROR: 193
Load ...\zxmAlogic.zxm | 0x0 => ERROR: 183
```

`ERROR 193` 表示“不是有效的 Win32 程序”。当前根目录的 `zxmAlogic.zxm` 是 Linux 容器格式（`001` 头 + 内部 ELF64），原生 Windows 客户端无法加载，于是退回内置编码器，因此 Algo-ID 变成 `E9747EF1-…`。

全盘搜索确认：`E9747EF1` 只存在于被排除的 `final` 目录中，工作区其余位置、`%APPDATA%`、`%TEMP%`、`C:\ProgramData` 均无该算法模块的落盘副本。

## 保留的证据样本

- `captured/req_14_146_227_142_7001_784.bin`：真实 keep 请求体（加密，不含明文）
- `captured/resp_172_17_104_130_50520_219.bin`：真实 keep 响应（含 chunked 框架）

抓包原始文件与含账号明文的另一条请求已删除，避免留存个人信息。

## 下一步需要什么

要让自建拨号器真正登录，必须拿到与 `E9747EF1-…` 对应的 **Windows 算法模块实现**，然后：

1. 恢复原始 Windows 版 `zxmAlogic.zxm`（不是 Linux 容器）；或
2. 从 `ESurfingSvr.exe` 内置编码器恢复 8 字节分组算法与密钥。

在此之前，即使请求头、端点、身份参数全部正确，服务端也无法解开请求体，会继续返回 `Error-Code: 2`。

## 已更新的配置

`portal_config.json` 已按抓包真实值更新：User-Agent、Algo-ID、Client-ID、CDC 校园域头、四个端点主机，以及 `clientmac` / `wlanuserip`。
