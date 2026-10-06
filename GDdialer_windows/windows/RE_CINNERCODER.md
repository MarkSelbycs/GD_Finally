# CInnerCoder 深挖结果

本文件记录对 `ESurfingSvr.exe` 中 `CInnerCoder` 的静态逆向结果，以及当前的验证状态。

## 1. RTTI / 虚表定位

`ESurfingSvr.exe`（PE32，imagebase `0x400000`）中相关类：

| 类 | RTTI TypeDescriptor | vtable |
| --- | --- | --- |
| `CInnerCoder` | `0x441680` | `0x43CAEC` |
| `CInnerMod` | `0x441548` | `0x43CB5C` |
| `CInnerLzma` | `0x441658` | `0x43CA90` |
| `CZsmMod` | `0x4414AC` | `0x43C4B8` |
| `CZxmMod` | `0x441440` | `0x43C320` |
| `CodeProtectItem` | `0x3FF80` | — |

同类族还有 `CInnerCommInfo`、`CInnerConcernedFunction`、`CInnerDSAssist`、`CMemImportProtect`。

`CInnerCoder` 构造函数在 `0x425C20`，把 vtable 写入对象后调用基类构造 `0x424B00`。

## 2. 内含的算法原语

| 函数 | 地址 | 说明 |
| --- | --- | --- |
| RC4 核心 | `0x425E80` | 标准 KSA + PRGA 就地异或，参数 `(key, keylen, data, datalen)` |
| 2 字 XXTEA 变体 | `0x4260B0` | `delta=0x9E3779B9`，`n>0` 加密 / `n<0` 解密，一次处理 8 字节 |
| 类封装编码 | `0x426200` | 用 key 构造对象后调用 `0x4331D0`（按 `len>>2` 处理），末尾析构 |
| 十六进制编码 | `0x4266E0` | 输出 `2*len+1`，字符表在 `0x43CAC4` |
| 十六进制解码 | `0x426770` | 对应解码 |
| 十六进制字符表 | `0x43CAC4` | `0123456789ABCDEF`（标准大写） |

### XXTEA 变体与标准 XXTEA 不同

反汇编 `0x4260B0` 得到的混合函数是**简化加法形式**，不是标准 XXTEA 的异或组合：

```
v0 += ((y<<4) ^ (y>>5)) + (y ^ sum) + k[sum & 3]
v1 += ((z<<4) ^ (z>>5)) + (z ^ sum) + k[(sum>>11) & 3]
```

其中 `y=v1`、`z=v0`，`sum` 每轮加一次 `delta`，循环 `|n|` 次（`n=-32` 即 32 轮）。

## 3. 调度器与密钥数组

调度器函数位于 `0x415E80` 附近，按 `[ebp-0x19]` 分派模式：

- 模式 2（`0x415EB2`）：用 `0x4260B0` 处理，密钥数组在 `[ebp-0x38]`（9 字）。
  每个 8 字节块连续用 **两把 key**：`key+0x00` 与 `key+0x10`，`n=-0x20`（32 轮）。
  循环后执行 `len -= data[len-1]`（去尾部填充字节）。
- 模式 3（`0x4161F5`）：用 `0x426200` 处理，密钥数组在 `[ebp-0x28]`（9 字），同样去尾部填充。

密钥数组由「立即数写入 + 逐项 XOR」两步构造。注意存放位置按**字节偏移**计算，偏移 `0,4,8,...` 对应字索引 `0,1,2,...`。

### 模式 2 密钥数组（KEY_A）

立即数：

```
idx0=0xEC4C6F3C idx1=0x5EC9BCD6 idx2=0x5D966189 idx3=0xC366F3C0 idx4=0xE94336D0
idx5=0x0006B81F idx6=0x93818B99 idx7=0xB173CFD0 idx8=0x93A97696
```

XOR 轮（按顺序）：`5^=0x527E8E2C`、`0^=0xAA070640`、`7^=0x884B8CE5`、`1^=0x18F2D19B`、
`8^=0xD2B0F996`、`3^=0x8412BAAF`、`6^=0xBECBC6A1`、`4^=0xDC2E40BD`、`2^=0x6BDF0BD3`

结果：

```
0x464B697C 0x463B6D4D 0x36496A5A 0x4774496F 0x356D766D 0x52783633 0x2D4A4D38 0x39384335 0x41198F00
```

字节 16..31 恰好是可打印 ASCII：`mvm536xR8MJ-5C89`。

### 模式 3 密钥数组（KEY_B）

立即数：

```
idx0=0xDC3261B5 idx1=0x41C8C32A idx2=0x85322235 idx3=0xC89E9EEA idx4=0x53E5CCD1
idx5=0x4AABBD7A idx6=0x0C49F529 idx7=0xC444CC80 idx8=0x2F3363DF
```

XOR 轮：`7^=0xBC60A8AB`、`4^=0x0BD39AB4`、`3^=0x9CEFCBB3`、`6^=0x2161D46A`、`0^=0xFA601DF8`、
`2^=0xA45B5C76`、`1^=0x2EB2B67D`、`5^=0x318FCD04`、`8^=0x2F3363DF`

结果：

```
0x26527C4D 0x6F7A7557 0x21697E43 0x54715559 0x58365665 0x7B24707E 0x2D282143 0x7824642B 0x00000000
```

这 8 个字全部是可打印 ASCII（32 字节）：

```
M|R&WuZoC~i!YUqTeV6X~p${C!(-+d$x
```

`idx8` 因为最后一次 XOR 等于初始值而变成 0，像是字符串终止符。这强烈提示 KEY_B 是一把 **32 字节 ASCII 密钥串**。

## 4. 当前验证状态

`cinncoder.py` 实现了该 XXTEA 变体与两套密钥。自洽性验证通过：

```
self roundtrip: PASS (A and B)
```

但用抓包得到的真实 keep 响应（104 字节）测试，全部组合都无法还原明文：

| 组合 | 可打印率 |
| --- | --- |
| KEY_A 偏移0 正序 | 0.38 |
| KEY_A 偏移0 逆序 | 0.41 |
| KEY_A 偏移8 正序 | 0.41 |
| KEY_A 偏移8 逆序 | 0.41 |
| KEY_B 偏移0 正序 | 0.32 |
| KEY_B 偏移0 逆序 | 0.44 |
| KEY_B 偏移8 正序 | 0.30 |
| KEY_B 偏移8 逆序 | 0.46 |

结论：**算法族已确认、密钥数组已提取，但尚未命中真实流量所用的具体模式/层组合。**

## 5. 剩余可能性（下一步）

1. 真实链路可能是 **RC4 与 XXTEA 叠加**，或先 RC4 再 XXTEA（模式 0/1 分支尚未反汇编，位于 `0x415E80` 之前）。
2. 可能存在 **LZMA** 层（`CInnerLzma` 类，vtable `0x43CA90`）。
3. 报文可能带有未识别的头部（长度均为 `8 + 8k`）。
4. `dump_key_memory.py` 可在运行时从进程内存读取真实密钥缓冲区；由于密钥经过 XOR 改写，需要改搜 XOR 后的值，或在 `0x415E99` / `0x4161B4` 下断点直接取参。

## 7. 运行时内存 dump（新进展）

原版服务的算法模块是通过 `CMemModImpl::LoadMod` 自行加载的，所以磁盘上取不到。
本次用 `dump_modules.py` 扫描运行中 `ESurfingSvr.exe`（PID 2480）的私有内存，
按 PE 头识别并 dump 出 5 个已加载映像：

| dump 文件 | 模块 | 关键内容 |
| --- | --- | --- |
| `image_01340000_30000.bin` | `Helper.DLL` | `EClient.Cryptography.1`、`CryptographyOper`、`CreateScanner` |
| `image_01470000_73000.bin` | `PortalServer.dll` | `AutoZSM`、`AutoModule`、`GetPortalServer` |
| `image_01500000_12000.bin` | `NetHelper.dll` | 网络工具（`Url2IP`、`AddNewRoute` 等 32 个导出） |
| `image_03020000_e000.bin` | 未知 | 4 个 RTTI，无导出 |
| `image_10000000_1f000.bin` | `DialServer.dll` | `ModLoadCompleted` |

注意：这些映像是**内存映像**，节头的 VirtualSize 被自定义加载器改写成了绝对地址，
且内部指针使用实际加载基址（如 `0x01470000`），不是节头里写的 `0x10000000`。
因此分析时要把 RVA 直接当文件偏移，并用实际基址计算指针。

### 关键地址

```text
原版当前 Algo-ID  E9747EF1-6849-4F87-957B-3B93E6A90393  @0x01462d38
zxmAlogic.zxm 路径串                                     @0x01462b5d
PortalServer.dll AutoZSM RTTI COL  0x014D4958  vtable 0x014D3734
  vt[0]=0x014BA580(析构) vt[1]=0x01491900 vt[2]=0x01485AC0
  vt[3]=0x01491930 vt[4]=0x01491970 vt[5]=0x014919A0 vt[6]=0x014919D0
zsm 接口名表（紧邻 vtable 之前，ASCII）：
  Code / DeCode / FreeResult / Inspect / GetExData
```

`AutoZSM` 的方法体都是轻量包装（`isValid`、getter/setter、`free`），
本身不含加密逻辑。

### 已排除

`Helper.DLL` 的 `EClient.Cryptography.1`（ATL/COM，方法 `Base64Decode`）
被 `CServicesStatusScanner` 用于**共享/虚拟机环境检测**，不是 zsm 编解码器。
该 ProgID 未在注册表注册（`HKLM/HKCU\SOFTWARE\Classes\EClient.Cryptography.1` 均不存在），
因此无法直接通过 COM 实例化调用。

### 结论与下一步

- 原版当前的算法模块**已经拿到**（内存 dump + 磁盘 `Mods\*.zxm`）。
- zsm 编码的真实实现仍在 `ESurfingSvr.exe` 的 `CInnerCoder`（RC4 + 2 字 XXTEA + hex），
  模块侧只提供包装与接口绑定。
- 下一步可选：
  1. 用 32 位宿主重新加载 dump 出的模块并调用 `Code/DeCode`（需要修复节头与导入表）；
  2. 在 `0x415E99`(RC4) / `0x4161B4`(XXTEA) 下断点，直接取运行时真实密钥；
  3. 用 `CreateRemoteThread` 在运行中的原版服务里调用 `Code`，把编码外包给原版进程。

## 8. 真实报文的编码层穷举结果（重要负结果）

抓到的两条真实报文（hex 解码后的二进制）：

```text
keep 请求体  392 字节   （784 个 ASCII hex 字符）
keep 响应体  104 字节   （208 个 ASCII hex 字符）
```

**两者前 24 字节完全相同**：

```text
req  : c8 53 a9 96 84 96 b3 e0 b6 40 df 7a 9a 02 2c a8 af 4b 51 f1 57 b4 8b
resp : c8 53 a9 96 84 96 b3 e0 b6 40 df 7a 9a 02 2c a8 af 4b 51 f1 57 b4 8b
```

24 字节恰好等于 XML 声明前缀 `<?xml version="1.0" enco` 的长度，说明：

- 加密是**确定性**的（无每报文随机 IV），或
- 报文前 24 字节使用的是固定密钥流 / 固定 IV 的同一分组。

用已恢复的两套密钥数组（`KEY_A`、`KEY_B`）及其各种组合尝试解密，**全部失败**：

| 组合 | 最高可打印率 |
| --- | --- |
| `rc4(KEY_A/B/切片)` | 0.41 |
| `xxtea2(KEY_A/B)` | 0.39 |
| `rc4 → xxtea2` | 0.44 |
| `xxtea2 → rc4` | 0.45 |

随机数据的可打印率约 0.4，因此这些结果等同随机，**说明静态还原的密钥不是真实链路使用的密钥**。

原因也清楚了：日志显示服务加载 `zxmAlogic.zxm` 失败后走的是 `AutoZSM`
（`load AutoZSM begin/end` + `update algoid success`），这条路径的密钥在运行时构造，
不是 `CInnerCoder` 里那两组静态立即数。

### 结论

要完成独立编解码，必须在**运行时**取真实密钥/密钥流。可选：

1. 在 `CInnerCoder` 的 RC4(`0x425E99` 调用点) / XXTEA(`0x4161B4`) 下断点取参；
2. 在 `AutoZSM` 实际使用的 enc 函数下断点，dump 明文与密文对；
3. 用 `CreateRemoteThread` 直接在原版进程里调用编码函数，把编码外包给原版。

## 10. 加密模式判定（重新拨号抓包，决定性）

触发原版重新拨号后，抓到完整流程的五条请求：

| 请求 | HTTP body | 二进制长度 | 8 字节块数 |
| --- | --- | --- | --- |
| ticket.cgi | 752 | 376 | 47 |
| keep.cgi | 784 | 392 | 49 |
| auth.cgi | 608 | 304 | 38 |
| state.cgi | 496 | 248 | 31 |
| term.cgi | 544 | 272 | 34 |

全部长度都是 8 的倍数。密文公共前缀：

```text
ticket / keep / auth / state / term 五条报文前 48 字节完全相同
48 字节 = <?xml version="1.0" encoding="UTF-8"?><request><  （明文前缀）
```

### 结论：ECB（逐块独立）

`keep` 与 `term` 的共享块出现在**不同偏移**：

```text
keep 块 33..48  ↔  term 块 18..33     （16 个块的位移共享后缀）
keep 与 auth 共享前 10 个块（80 字节）
其他两两之间共享前 6 个块（48 字节）
```

CBC（固定 IV）下，后缀共享要求链状态一致，而两条报文的分歧点之前数据不同，
因此**排除 CBC，判定为 ECB 或等价的逐块独立模式**（块长 8 字节）。

另外 `keep` 与 `term` 的**最后一块密文相同**（`2cb179c46853233f`），
说明两者尾部明文相同（同一秒内发送，`local-time` 一致）。

### 密钥验证（全部失败）

用已知的 48 字节明文前缀逐块验证 `CInnerCoder` 里恢复的两套密钥：

| 方案 | 匹配块数 |
| --- | --- |
| `enc(A[0:4])` / `enc(A[4:8])` / `enc(B[0:4])` / `enc(B[4:8])` | 0/6 |
| `enc(A[4:8])->enc(A[0:4])` 等双重应用 | 0/6 |

加上此前的 RC4、CBC、组合测试与 60+ 候选密钥，**静态还原的密钥与真实链路无关**。

### 该判定的实际价值

ECB 意味着「相同明文的 8 字节块 → 相同密文块，与位置无关」，因此可以：

1. 用抓到的密文块**拼接**任意明文块已知的报文；
2. 借助 HTTP 响应头里的 `Error-Code`（明文）作为预言机，做块重排分析；
3. 但**无法伪造新时间戳、新 ticket、以及 auth 里的密码块**——这些块的密文没有出现过。

所以仍然需要运行时密钥才能生成新请求。

## 12. 自动化密钥恢复（脚本）

按需求写了自动抓取脚本，直接从运行中的 `ESurfingSvr.exe` 内存里搜密钥：

| 脚本 | 作用 |
| --- | --- |
| `recover_key.py` | 扫描所有 16 字节窗口作候选密钥，用 XXTEA 变体加密已知明文块比对密文块 |
| `recover_key2.py` | 同上，但同时测试 5 种 8 字节分组密码 |
| `find_plaintext.py` | 在进程内存中搜索门户明文 XML |
| `dump_modules.py` | dump 进程内存中的 PE 模块 |
| `detect_mode.py` / `compare_bodies.py` | 由密文差异判定加密模式 |

原理：明文块已知（`<?xml ve`），密文块已知（`c853a9968496b3e0`），
分组 8 字节、ECB 模式，于是任何 16 字节窗口都可以当作候选密钥来验证。
用 numpy 向量化，每秒可测上百万候选。

### 结果：全部为负

```text
our_xxtea_variant    tested=18547209 hits=0
our_xxtea_swapped    tested=18547209 hits=0
standard_tea         tested=18437644 hits=0
standard_xtea        tested=18534927 hits=0
standard_xxtea       tested=18522636 hits=0
```

约 9200 万「密码 × 密钥」组合，零命中。`find_plaintext.py` 在内存里也只找到
系统 manifest，没有门户明文。

结论：**密钥不是内存中连续的 16 字节窗口**（可能每次调用派生），
或者**密码不是上述任何一种标准/已知 8 字节分组密码**。

## 13. 密码家族线索

在 dump 模块中搜索分组密码特征常量：

| 模块 | 命中 |
| --- | --- |
| `ESurfingSvr.exe` | TEA/XXTEA 常量 `0x9E3779B9`（2 处） |
| `image_01470000`（**PortalServer.dll**） | **标准 AES S-box** @0x52790 |
| 其他模块 | 无 |

`PortalServer.dll` 正是承载 `AutoZSM` 的模块。它同时含 AES S-box，
但报文长度全部是 8 的倍数、且 `ticket=376`/`keep=392`/`state=248` 都不是 16 的倍数，
**排除 AES-16**。因此该 S-box 很可能被用在某个**自定义 8 字节构造**里
（例如 Feistel 网络配 AES S-box）。

### 已排除的模式

- **流密码**：`keep` 与 `term` 的共享块出现在**位移**位置（`keep[33..48] ↔ term[18..33]`），
  流密码要求同偏移才相同，位移共享无法用密钥流解释。
- **CBC**：位移共享要求链状态相同，而 `keep[32] != term[17]`，排除。

因此确定是**位置无关的 8 字节分组密码（ECB 等价）**。

## 14. 下一步

需要在 `PortalServer.dll` / `AutoZSM` 里定位那个自定义 8 字节密码的实现：

1. 找 AES S-box（`0x52790`）的代码引用，看它属于哪个函数；
2. 在该函数里确认分组长度、轮结构和密钥调度；
3. 恢复密钥来源（常量表 / 运行时派生）。

## 16. 算法模块是拨号时下发的（关键发现）

放开端口过滤（只按电信服务器 IP + DNS 过滤）重新抓包后，找到了原版获取算法的机制。

### 触发方式：Algo-ID 全零 + 明文请求体

```http
POST /ticket.cgi?wlanacip=183.3.151.148&wlanuserip=172.17.104.130&clientip=172.17.104.130
     &wlanacname=SISE&clientmac=a4:fa:76:44:ba:e8&paip=10.88.88.88&vlan=100.0&iarmdst=www.189.cn/ HTTP/1.1
User-Agent: CCTP/WinSVR5/1068
Algo-ID: 00000000-0000-0000-0000-000000000000        ← 全零，表示本地没有算法
Client-ID: 1009758f-89f4-413c-929b-c5e0e35b0d54
CDC-Checksum: c4ba71a6fcb815e45ccc111ad118a48c
CDC-SchoolId: 1099
CDC-Domain: sise.cn
CDC-Area: 020
Content-Length: 38

tarce log algo auto compstr null value               ← 明文，不是密文
```

服务器返回 `Content-Type: application/octet-stream`，正文是模块容器。

### 响应容器格式

```text
001@47305F71CFD845438126563B6D1DB53FEFF7BADC217BBF61C24CC90335A5F839$7F224CA8-0DF5-47C6-9195-2D335E31D882]<负载>
│   └──────────────── 32 字节密钥（hex 文本）────────────────┘ └──────── Algo-ID ────────┘
└ 魔数
```

- 下载的模块：`001@` + 32 字节密钥 + `$` + Algo-ID + `]` + 负载
- 本地 `zxmAlogic.zxm`：`001\x80` + 64 字节密钥 + `$` + Algo-ID + 负载（同族，密钥更长）
- `Mods\*.zxm`：`ZXM\x00Z` 开头，另一种容器

### 验证：下发的模块就是当前流量使用的编码器

抓到的一次重新拨号中：

```text
1. POST /ticket.cgi   Algo-ID: 00000000-0000-0000-0000-000000000000  body=38 字节明文
   ← 响应 = 模块容器，Algo-ID 7F224CA8-0DF5-47C6-9195-2D335E31D882
2. 之后全部请求都改成 Algo-ID: 7F224CA8-...：
   /ticket.cgi (752)   /state.cgi (496)   /auth.cgi (608)   /term.cgi (544)
```

也就是说第 11 节里判定为 ECB-8、并作为已知明文分析对象的那批密文，
**正是由这个下发模块（密钥 `47305F71...`）编码的**。

### 自动抓取脚本

`fetch_module.py` 复刻了上面的请求，可随时重新拉取模块：

```powershell
py -3 fetch_module.py --ip 121.8.177.212
```

实测输出：

```text
HTTP 200 bytes 24730
Content-Type: application/octet-stream
Server-Tag: cdcportal/1.4.2/interface-1
Error-Code: 200
  key     : 47305F71CFD845438126563B6D1DB53FEFF7BADC217BBF61C24CC90335A5F839
  Algo-ID : 7F224CA8-0DF5-47C6-9195-2D335E31D882
  payload : 24624 bytes
```

注意：两次抓取的负载长度相差 331 字节（25061 vs 24730），
说明模块可能是**按请求动态生成/打包**的。

### 负载仍未解出

负载（`00 00 00 01 00 b6 00 20 ...`）是**压缩后又加密**的，已尝试且全部失败：

| 尝试 | 结果 |
| --- | --- |
| 直接 LZMA（ALONE/AUTO/XZ/RAW，多偏移多字典） | 全部失败 |
| 本地 `zxmAlogic.zxm` 负载（以 `5D 00 00` 开头，疑似 LZMA 属性） | 同样解不开 |
| AES-128/256、Blowfish、DES、3DES × ECB/CBC/CFB/OFB × 多种密钥/IV 派生 | 0 命中 |
| XOR（密钥重复） | 0 命中 |

### 下一步

1. 在 `ESurfingSvr.exe` / 下发模块加载路径里定位容器解析与解压函数
   （已知存在 `CInnerLzma`，vtable `0x43CA90`），弄清负载的加密与压缩；
2. 或直接调用进程中已加载的模块（`lsres.dll`）完成编解码，跳过算法还原。

## 18. 模块接口名（重要线索）

在运行进程的堆区（`0x00f50000`，偏移 `0x22700` 附近）找到一张**模块函数名表**：

```text
StrToWStr   HexCodeW   Uncompress  HexCodeA   HexDeCodeA
WStrToStr   Compress   FreeResult  HexDeCodeW Serialize
```

**全部是 `Compress`/`Uncompress`/`HexCode`/`HexDeCode`/`Serialize`，
没有任何 `Encrypt`/`Decrypt`** —— 强烈暗示门户报文是
**压缩 + hex 编码，而不是加密**。

表项形如 `<4 字节标识><ID><类型><名字或指针>`，其中 4 字节标识
（如 `0x7EB4AC55`）落在 `PAGE_NOACCESS` 区域，**不是有效地址**，只是标识。

### 但标准压缩全部失败

对五条报文二进制和模块负载尝试：

| 方式 | 结果 |
| --- | --- |
| zlib / gzip / deflate-raw / bz2 | 全部失败 |
| lzma（ALONE / XZ / AUTO） | 全部失败 |
| raw LZMA（多偏移 × 多字典 × 多 lc/lp/pb） | 全部失败 |

本地 `zxmAlogic.zxm` 负载以 `5D 00 00`（LZMA 属性字节）开头却也解不开，
说明是**自定义变体**，对应二进制里的 `CInnerLzma`（vtable `0x43CA90`）。

## 19. 模块没有被加载成 PE

`hunt_pe.py` 扫描全内存所有偏移处的 `MZ`+有效 PE 头，共 100 个映像，
只有 `Helper.DLL` / `PortalServer.dll` / `NetHelper.dll` / `DialServer.dll`
四个业务模块，**没有任何映像含 `Uncompress`/`Compress`/`HexCodeA`/`Serialize` 标记**。

接口名只出现在堆里的元数据区。结合日志 `LoadMod ... ERROR: 193`，
说明下载的 `lsres.dll` **没有作为 PE 成功加载**；服务很可能仍用内置
`CInnerCoder` 编码，只是把下载模块的 Algo-ID 当标签发出。

## 20. 内置编码器 × 容器密钥：穷尽失败

用容器密钥 `47305F71…` 配合内置编码器做了系统扫描（`sweep_coder.py`）：

- XXTEA 变体：加性密钥式 / `(sum>>2)&3` 式 × 16/32/64 轮 × 大小端字序 × 密钥反转 ×
  `raw32`/`hexascii`/`md5` 三种密钥材料 → 0 命中
- RC4（整钥/前 16/后 16 字节）→ 0 命中
- 单次/双重/三重应用、正反顺序 → 0 命中

加上此前的 9200 万「密码 × 内存密钥窗口」扫描，**静态与内存密钥两条路都已穷尽**。

## 21. 当前状态与下一步

**已完成**

- 协议、端点、请求头、身份参数：与真实抓包逐项对齐
- 算法模块**可自动抓取**（`fetch_module.py`），拿到密钥与 Algo-ID
- 报文编码特征确定：确定性、8 字节块、位置无关（ECB 等价）
- 已排除：标准分组/流密码、标准压缩、内置编码器配容器密钥、明文请求体方案

**阻塞点**

报文与模块负载用的是**自定义压缩/序列化变体**（`Compress`/`Uncompress`/`Serialize`），
不是标准算法。要复现必须逆出这几个例程。

**下一步（已缩小到具体目标）**

1. 在 `ESurfingSvr.exe` 里定位 `Uncompress`/`Compress`/`Serialize` 的实现
   （已知函数名，`CInnerLzma` vtable `0x43CA90`），逆出压缩格式；
2. 或调用进程中已加载的模块函数（需注入），跳过算法还原。

**今日可用方案**

用户自有的 `ESurfingDialer-onekey`（2024）已用 unidbg 跑通客户端原生库，
可完成登录/保活/登出，是当前唯一确定可用的拨号路径。

## 23. 模块加载器已定位

修正 RVA↔文件偏移映射后（`.rdata` 的 RVA 与文件偏移相差 0x636，之前的换算有误），
在 `ESurfingSvr.exe` 中找到 `CMemModImpl::LoadMod` 的实现位置：

```asm
0042e738  push 0x43b41c        ; "ESurfingSvr::CMemModImpl::LoadMod"
0042e73d  push 0x43b440        ; "<%s> LoadMod LOADING %S | 0x%x ..."
0042e742  call 0x40be60        ; 格式化日志
```

关键字符串地址（已按正确节映射换算）：

| 字符串 | VA |
| --- | --- |
| `ESurfingSvr::CMemModImpl::LoadMod` | `0x43b41c` |
| `<%s> LoadMod LOADING %S \| 0x%x ...` | `0x43b440` |
| `<%s> ABSOLUTE: %S` | `0x43b494` |
| `<%s> Load %S \| ERROR: %lu` | `0x43b4cc` |
| `<%s> Load %S \| 0x%x => ERROR: %lu` | `0x43b50c` |
| `<%s> LoadModExW %S Flags: %u` | `0x43b558` |

加载器函数体约从 `0x42e3a0` 开始，其调用图（部分）：

```text
0x4283c0  ← 包装：取缓冲 → 0x429290 → 赋值
0x429290  ← 内部调用 0x4297f0（取数据）、0x4298b0（取长度/校验）
0x4263f0 / 0x426290 / 0x42a230 / 0x42e200 / 0x427810 / 0x42fb10 ...
```

### 重要更正：二进制并未混淆

此前观察到 `mov eax,[edx]; xor eax,0x76f1ffff` 这类"乱码"，
并据此判断存在混淆——**这是错误的**。原因是 VA→文件偏移换算时漏了节内偏移差：

```text
.text   RVA 0x1000  文件偏移 0x400   → 相差 0xC00
.rdata  RVA 0x36000 文件偏移 0x35400 → 相差 0xC00
```

正确映射应为 `file = raw + (rva - va)`，而当时用的是 `file = va - imagebase`。
改正后所有函数都能正常反汇编，`CInnerLzma`/`CInnerMod`/`CInnerCoder`
的虚表项都是常规的构造/析构/取值函数。

## 24. 密钥是异或混淆存储的（关键发现）

编码器在运行时构造密钥数组，每个密钥字都以「真值 XOR 常量」写入，
使用时再异或还原：

```asm
00415b00  mov  eax, [ebp - 0x18]      ; 密钥对象
00415b06  mov  edx, [eax + 8]         ; 取缓冲区（虚调用）
00415b09  call edx
00415b10  imul edx, ecx, 0            ; word[0]
00415b13  add  eax, edx
00415b1b  mov  ecx, [eax]
00415b1d  xor  ecx, 0xa1fa8b42        ; ★ word[0] ^= 0xa1fa8b42
00415b26  mov  [edx], ecx
```

**这正是此前所有解密尝试失败的根因**：先前把立即数直接当作密钥，
用的是混淆后的值，而不是运行时还原后的真值。

在整个密钥构造区间（`0x4156b0`–`0x416800`）中共有 **30 次还原事件**，
分 **3 个批次**（对应 3 种模式），每批用一套不同的下标常量。
还原后得到 23 个字的候选密钥数组，其中含可读 ASCII 片段：

```text
C!(-   +d$x   D9dD   JSBN   14Gl   hQlm   zSZV   Nq7W   zP1:   KA3#   -#!h
```

与 `zxmAlogic.zxm` 容器里那种「ASCII 与二进制混合」的密钥串风格一致。

工具：`recover_real_key.py`（提取下标→常量对照）、`rebuild_keys.py`（重放所有批次并测试）。

## 25. 编码器调用点与流水线

分发函数起点 `0x4156b0`，RC4 调用点：

```asm
00415e48  mov  eax, [ebp - 0x18]
00415e4e  mov  edx, [eax + 8]
00415e51  call edx                    ; 取缓冲区
00415e58  imul edx, ecx, 0x16         ; word[22]
00415e69  mov  ecx, [eax]
00415e6b  xor  ecx, 0x3e0a94dd        ; word[22] 还原
00415e79  mov  eax, [ebp + 0xc]       ; 参数
00415e7c  push eax
00415e7d  mov  ecx, [ebp + 8]
00415e80  push ecx
00415e84  call 0x409240
00415e89  shl  eax, 2                 ; 长度 * 4
00415e8c  push eax
00415e93  mov  eax, [edx + 8]
00415e96  call eax                    ; 取密钥
00415e98  push eax
00415e99  call 0x425e80               ; RC4
```

三个原语已复核确认（正确偏移下）：

| 函数 | 证据 |
| --- | --- |
| `0x425e80` | `sub esp,0x118`（256 字节 S-box 栈缓冲）→ RC4 |
| `0x4260b0` | `imul eax,[ebp+0x10],0x9e3779b9` → XXTEA（delta） |
| `0x4266e0` | `lea ecx,[eax+eax+1]` 分配 2n+1 → hex 编码 |

**当前卡点**：密钥已能还原，但仍需确定
①三种模式的选取条件、②RC4/XXTEA/hex 的套用顺序、
③XXTEA 的轮数参数与块内字序。这些在 `0x4156b0` 的其余分支里。

## 26. ★ 动态插桩破解（Frida）——容器格式完全解开

静态分析了很久没突破，改用 **Frida 动态插桩**后一次解决。工具：`frida_watch.py`
`frida_watch2.py` `frida_watch3.py` `frida_dump_module.py`。

### 26.1 运行时真实密钥

hook `0x4260B0`（XXTEA）直接读到密钥缓冲区，两把 16 字节 **ASCII** 密钥：

```text
key1 = |iKFMm;FZjI6oItG   →  464B697C 463B6D4D 36496A5A 4774496F
key2 = mvm536xR8MJ-5C89   →  356D766D 52783633 2D4A4D38 39384335
```

**注意**：这两把正是早先静态重建的 `KEY_A` 前 8 个字。
第 24 节里那套「异或还原」得到的密钥数组反而是错的——
**动态 hook 才是唯一可信来源**。

hook 同时确认：`n = -32`（解密分支）、**逐 8 字节块**、两把密钥依次作用。

### 26.2 算法实现逐条核对通过

`0x4260B0` 解密分支的完整反汇编：

```asm
sum = 32 * delta
loop:
  v1 -= ((v0<<4)^(v0>>5)) + (v0 ^ sum) + key[(sum>>11)&3]
  sum -= delta                      ; add 0x61C88647
  v0 -= ((v1<<4)^(v1>>5)) + (v1 ^ sum) + key[sum & 3]
  until sum == 0
```

与 `cinncoder.py` 的实现逐条一致。

### 26.3 编码器入口与容器

hook `0x4156B0`（编码器入口）读到：

```text
ENTRY arg0 = "001@6ADD6889…$E9747EF1-6849-4F87-957B-3B93E6A90393]"   ← 容器
ENTRY arg1 = 0x609a = 24730                                           ← 长度
XXTEA #1  key=0xf54df0(|iKFMm;…)  data = 容器+114                     ← 头106 + 前缀8
XXTEA #2  key=0xf54e00(mvm536…)   data = 同一块（就地二次解密）
```

### 26.4 容器格式（已验证）

```text
容器 = "001@" + <64位hex=32字节密钥> + "$" + <Algo-ID> + "]" + <8字节前缀> + <密文>
密文 = XXTEA(LZMA(模块PE))        逐 8 字节块，key1 → key2
前缀 = 00 00 00 01 00 b6 00 20
```

解码步骤：

1. 跳过 ASCII 头（4 + 64 + 1 + 36 + 1 = 106 字节）
2. 跳过 8 字节前缀
3. 每 8 字节块：`XXTEA_decrypt(key1)` → `XXTEA_decrypt(key2)`
4. **raw LZMA 解压**（`lc=3, lp=0, pb=2`）→ 得到 PE

实测：

```text
payload=24624 → 解密 24616 → LZMA → 46596 字节，头 4D 5A 90 00（MZ）
machine=0x14c (x86)  sections=4
```

工具：`zxm_container.py`（解码已验证；编码长度略有差异，不保证逐字节还原）

### 26.5 交叉验证

`frida_dump_module.py` 在服务解密完成后**直接从进程内存 dump**出缓冲区，
其首块字节与我们离线计算的结果**逐字节一致**：

```text
进程内存 : 00 26 96 8e 70 00 17 f7 ec 05 bb ea f4 ff 94 01
离线计算 : 00 26 96 8e 70 00 17 f7 ec 05 bb ea f4 ff 94 01
```

这证明 **XXTEA 实现与密钥完全正确**。

### 26.6 已拿到的模块

解出的模块存于 `captured/module_inner.bin` / `captured/module_fetch_module.bin`：
**32 位 x86 PE DLL，46596 字节，4 个节，无导出**。

### 26.7 门户报文仍不是这条流水线

对五条抓包报文试过：

- 双密钥 XXTEA（key1→key2 / key2→key1，偏移 0/8）后接 raw LZMA → **无输出**
- 换成第二组密钥 `M|R&WuZoC~i!YUqT` / `eV6X~p${C!(-+d$x` → **无输出**

所以门户报文用的是**另一条编码路径**（很可能就是解出的模块里
`Compress`/`Uncompress`/`HexCode`/`Serialize` 那套）。
**下一步就是逆向这个刚拿到的 PE 模块。**

## 28. 解出的模块是什么（身份确认）

`captured/module_inner.bin`（46596 字节，x86 PE，4 节，无导出）内含：

```text
导入 : KERNEL32 / IPHLPAPI / WS2_32 / VCRUNTIME140 / CRT 系列
字符串: unexpected closing tag </%s>   standalone   <!ENTITY        ← XML 解析器
        GET /cgi-bin/luci HTTP/1.1                                  ← 探测 OpenWrt 路由器
        User-Agent: Mozilla/5.0 (Windows NT 6.1; rv:19.0) ...
        gswifi / guangsu team / www.guangsuwifi.com
        InnerDSAssist.dll / InnerConcernedFunction.dll / InnerCommInfo.dll
```

结论：**这个模块是"共享/路由器探测"用的**（WiFi 共享检测那一路），
**不是门户报文的编解码器** —— 正好是需求里要排除的部分。

## 29. 门户报文的发送路径

hook `ws2_32!WSASend` 抓到全部对外请求：

```text
WSASend ret=0x6be2b4d9 (webio.dll+0x1b4d9)    ← Windows HTTP 栈在发
  GET  /index.cgi?...&portal_node=http://125.88.59.131:10002
  POST /ticket.cgi?...                  (530 字节，含头)
  body "tarce log algo auto compstr null value"   (38 字节明文)
```

即门户流量经 **`webio.dll`** 发出；编码发生在更上层。

## 30. 明文 XML 不在内存中

`frida_scan_plaintext.py` 在 **发送那一刻** 扫描全部可读内存找
`<?xml version` / `<local-time>` / `<ticket>` / `<user-agent>`：

只找到系统 manifest（`requestedExecutionLevel` 那些），**没有任何门户请求 XML**。
说明请求 XML 在编码后立刻被释放/覆盖，或根本不以明文形式存在。

## 31. 当前状态总览

**已完成且经过验证**

| 项目 | 状态 |
| --- | --- |
| 登录/保活/登出协议、端点、请求头、身份参数 | ✅ 与真实抓包逐项对齐 |
| 模块容器格式 | ✅ 完全破解，`zxm_container.py` 解出合法 PE |
| 运行时密钥 | ✅ Frida 实读 `\|iKFMm;FZjI6oItG` / `mvm536xR8MJ-5C89` |
| XXTEA 变体实现 | ✅ 与进程内存输出逐字节一致 |
| 算法模块本体 | ✅ 已导出 `captured/module_inner.bin`（46596 字节 PE） |
| Frida 工具链 | ✅ 监视/跟随重启/内存 dump/WSASend hook/明文扫描 |

**唯一剩余**

门户报文体的编码：8 字节块、确定性、位置无关，但

- 双密钥 XXTEA（`asciiA` / `asciiB` / 容器密钥派生 / 交叉组合）× 两种顺序 × 偏移 0/8 → 全部无输出
- 其后接 raw LZMA 也无输出
- 发送时刻内存中没有明文 XML

**下一步建议**

1. 用 Frida **对发送缓冲区设置内存写断点**，回溯写入者（即编码器）；
2. 或在 `webio.dll` 调用点向上追栈，定位组装请求体的函数；
3. 拿到编码器后再判定它是否可逆（若为字节置换/替换，可用多组样本反推）。

## 33. ★ 找到门户报文的加密核心：自定义 SPN 分组密码

在 `ESurfingSvr.exe` 中发现**两个 256 字节置换表（自定义 S-box）**：

```text
S-box1 @ 文件 0x3b298  (VA 0x43be98)   已保存 captured/sbox1.bin
S-box2 @ 文件 0x3b398  (VA 0x43bf98)   已保存 captured/sbox2.bin
```

（两者都是 0–255 的完整置换；hex 表 `0123456789ABCDEF` 在 0x43cac4 不是置换。）

相关函数（`ESurfingSvr.exe`，VA = imagebase 0x400000 + RVA）：

| 函数 | 作用 |
| --- | --- |
| `0x432ba0` | 线性扩散：`(x<<2\|x>>30) ^ x ^ (x<<10\|x>>22) ^ (x<<18\|x>>14) ^ (x<<24\|x>>8)` |
| `0x432bf0` | 字节旋转 `(x<<8)\|(x>>24)` |
| `0x432c40` | 字节重组：`(b0<<24)\|(b1<<16)\|(b2<<8)\|b3` |
| `0x432c60` | 另一重组（带 `0x7fffffff` 掩码） |
| `0x432c90` | 状态字处理（`0x7fff8000` / `0xffff` 掩码，字偏移 `0x18+4N`） |
| `0x432d00` 起 | 轮函数：字混排 + `0x432ba0` 扩散 + S-box 替换 + `0x432c40` 重组 |

S-box 应用方式（反汇编确认）：

```asm
; 32 位字 x 的四个字节交替查两个 S-box：
;   byte0 -> S-box1[byte0]   byte1 -> S-box2[byte1]
;   byte2 -> S-box1[byte2]   byte3 -> S-box2[byte3]
; 再用 0x432c40 重组成字
```

即：**偶字节用 S-box1、奇字节用 S-box2**，配合旋转-XOR 线性层，构成自定义 SPN 结构。

状态区有 `0x18 + 4N`（N 到 15）共 16 个以上的字 —— 说明它可能是
**密钥调度 / 哈希式构造**，或作用于大于 8 字节的状态。

### 尚未确定的

- 分组长度（body 是 8 字节对齐，但状态区更大，需确认）
- 轮数、密钥来源（可能是 ASCII 密钥 `|iKFMm;…`/`mvm536…` 或容器密钥）
- 加解密方向与 hex 的衔接点

## 34. 工具

| 脚本 | 用途 |
| --- | --- |
| `dump_modules.py` | 从运行进程内存中 dump PE 模块 |
| `rtti_dump.py` | 解析内存 dump 的 RTTI/虚表（支持实际加载基址） |
| `rtti_vtable.py` | 解析磁盘 PE 的 RTTI/虚表 |
| `pe_exports.py` | 列出 PE 导出表 |
| `parse_capture.py` | 解析 pktmon 抓包，提取 7001 端口 HTTP 请求 |
| `dump_key_memory.py` | 在运行进程中搜索密钥常量 |
| `cinncoder.py` | XXTEA 变体 + 两套密钥的实现与验证 |

## 9. 参考项目（用户自有）

- `LandLeg_Java-master`：**手机协议**，无需算法。
  `challenge/login/logout` 在 `enet.10000.gd.cn:10001`，`active` 在 `:8001`；
  `secret=Eshore!@#`、`iswifi=4060`、`authenticator=MD5(clientip+nasip+mac+timestamp+[challenge+]secret)`（大写）。
  实测 `10001` 可连、`8001` 超时。
- `ESurfingDialer-onekey`（2024，`com.rsplwe.esurfing`）：**桌面协议**，
  用 unidbg（Dynarmic/Unicorn2）模拟 Android 运行客户端原生库，
  从 `DaMod` 取 `enc/dec/getAlgoId`。自带 JRE 21，`-u/-p/-d` 参数。

