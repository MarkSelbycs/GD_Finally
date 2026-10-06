# 逆向成果归档

这个目录放**逆向工程的全部成果**：密钥表、算法、证据产物、分析脚本。

> 完整过程叙述见 [`../逆向过程.md`](../逆向过程.md)
> 拨号器本体见 [`../c/`](../c/) 和 [`../py/`](../py/)

---

## 先看这个

| 文件 | 内容 |
| --- | --- |
| ⭐ [`密钥与算法.md`](密钥与算法.md) | **所有密钥、算法、常量、地址的总表（最核心）** |
| [`keys.json`](keys.json) | 同上，机器可读版（可直接被程序读） |
| [`des_tables.txt`](des_tables.txt) | 从模块里提取的 DES 置换表 + 6 把密钥 |
| [`明文样本.txt`](明文样本.txt) | 5 个真实报文解密后的明文 XML |

---

## 逆向出来的东西一览

### 需要实现的（就 1 个）

| 项目 | 内容 |
| --- | --- |
| 门户 body 加密 | **6 重 DES 级联**，6 把静态密钥，见 `密钥与算法.md` |

### 只是过程产物 / 已排除

| 项目 | 说明 |
| --- | --- |
| XXTEA 双密钥 + LZMA | 只用于解密**下载的算法模块**，拨号器不需要 |
| 自定义 SPN 流密码 | `ESurfingSvr.exe` 内置，**补丁实验证明不参与 body**，仅存档 |
| PortalServer.dll 内存镜像 | 用于提取 XML 模板 |

---

## 目录结构

```
re/
├── README.md              本文件
├── 密钥与算法.md           ⭐ 密钥/算法总表
├── keys.json               机器可读密钥表
├── des_tables.txt          模块里的 DES 表 + 密钥
├── 明文样本.txt            5 个真实报文的明文
│
├── artifacts/              证据产物（二进制）
│   ├── algo_module_46596.bin        每次拨号下载的算法模块（PE），编码器就在里面
│   ├── container_raw_24730.bin      容器原始响应（001@…$Algo-ID]…）
│   ├── container_payload_24624.bin  容器载荷（8字节前缀 + XXTEA 密文）
│   ├── after_xxtea_24616.bin        XXTEA 解密后（未解压，LZMA 流）
│   ├── portal_server_dll_dump.bin   PortalServer.dll 内存镜像（含 XML 模板）
│   ├── spn_sbox1.bin / spn_sbox2.bin  自定义 SPN 的两张 S-box
│   ├── oracle_samples.jsonl         预言机采集的 27 组对照样本
│   └── real_bodies/                 5 个真实抓包 body（也当测试向量）
│       ├── req_…_752.bin   ticket
│       ├── req_…_784.bin   keep
│       ├── req_…_608.bin   auth
│       ├── req_…_496.bin   state
│       └── req_…_544.bin   term
│
└── tools/                 逆向用的脚本（可复现）
    ├── body_codec.py            ⭐ 编解码器（Python 参考实现）
    ├── zxm_container.py         容器解码器（XXTEA + LZMA，已验证）
    ├── tcp_reassemble.py        pcapng 解析 + TCP 重组
    ├── fetch_module.py          复现算法模块下载
    ├── frida_hook_module_entry.py  内存扫描找模块基址 + hook 入口
    ├── frida_hook_encoder.py    hook 编码器 0x6b65（抓到输入输出）
    ├── frida_oracle.py          ⭐ 预言机（直接调用模块函数）
    ├── frida_oracle_battery.py  系统性对照实验
    ├── frida_hook_des_key.py    dump DES 密钥与数据流
    ├── frida_hook_xxtea_key.py  抓容器 XXTEA 密钥
    ├── do_rc4_test.ps1          补丁闭环实验（排除 RC4）
    ├── do_no_codec_test.ps1     补丁闭环实验（排除 XXTEA+RC4）
    ├── 逆向笔记_中间结论.md      过程中记录的笔记
    └── SPN密码反汇编.txt        自定义 SPN 的完整反汇编
```

---

## 复现路线（最短路径）

```powershell
cd re\tools

# 1) 看解密结果 —— 用现成的真实报文验证
python body_codec.py                       # 自检
python -c "import body_codec as B; print(B.decode_body_str(open('../artifacts/real_bodies/req_14_146_227_141_7001_496.bin').read()))"

# 2) 复现容器解密 —— 从原始响应到模块 PE
python zxm_container.py                    # 需要先有 container_raw 样本

# 3) 复现"预言机" —— 需要目标程序在运行
python frida_oracle_battery.py             # 构造输入 → 采集输出

# 4) 复现补丁闭环 —— 需要断网（用户有 AutoHotkey 兜底）
powershell -File do_rc4_test.ps1
```

---

## 关键结论（一句话版）

> 门户报文 = **6 重 DES 级联**加密后的 XML，密钥是 6 把固定的 8 字节值。
> 这个算法藏在**每次拨号动态下载的算法模块**里（`0x6b65`），
> 但**算法本体是固定的**，所以拨号器可以完全离线自己算，不需要下载模块。

---

## 涉及的工具

| 工具 | 版本 | 用途 |
| --- | --- | --- |
| pktmon | Win10 内置 | 网络层抓包 |
| Frida | 17.22.2 | 动态插桩 / 调用模块函数 |
| Python | 3.12 / 3.14 | 分析脚本 |
| capstone | 5.0.7 | x86 反汇编 |
| pycryptodome | 3.23.0 | 密码学验证 |
| TinyCC | 0.9.27 | 编译 C 版拨号器 |

---

## 免责声明

仅供**自己设备、自己账号**的网络接入研究使用。请遵守学校/运营商的规定。
