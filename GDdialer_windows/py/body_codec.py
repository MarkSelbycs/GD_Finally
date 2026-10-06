"""门户报文编解码器（纯 Python 标准库，无第三方依赖）。

body = hex( 6 重 DES 级联( 归一化XML 补 NUL 到 8 字节, 最小 64 ) )

级联顺序:  E_k4 -> D_k5 -> E_k6 -> E_k1 -> D_k2 -> E_k3

用法:
    import body_codec
    body = body_codec.encode_body('<?xml version="1.0" ...></request>')
    xml  = body_codec.decode_body_str(body)

自检:
    python body_codec.py
"""

from __future__ import annotations

# ---------------------------------------------------------------- DES 表 ----

_IP = [
    58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7,
]
_FP = [
    40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25,
]
_E = [
    32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11, 12, 13,
    12, 13, 14, 15, 16, 17, 16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1,
]
_P = [
    16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10,
    2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25,
]
_PC1 = [
    57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18,
    10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22,
    14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4,
]
_PC2 = [
    14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10,
    23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2,
    41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32,
]
_SHIFT = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]

_SBOX = [
    [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7,
     0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
     4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0,
     15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13],
    [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10,
     3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5,
     0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15,
     13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9],
    [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8,
     13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1,
     13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7,
     1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12],
    [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15,
     13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9,
     10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4,
     3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14],
    [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9,
     14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6,
     4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14,
     11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3],
    [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11,
     10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8,
     9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6,
     4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13],
    [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1,
     13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6,
     1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2,
     6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12],
    [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7,
     1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,
     7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8,
     2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11],
]


def _permute(value: int, table: list[int], inbits: int) -> int:
    out = 0
    for pos in table:
        out = (out << 1) | ((value >> (inbits - pos)) & 1)
    return out


def _key_schedule(key: bytes) -> list[int]:
    k = int.from_bytes(key, "big")
    cd = _permute(k, _PC1, 64)
    c = (cd >> 28) & 0x0FFFFFFF
    d = cd & 0x0FFFFFFF
    subkeys = []
    for shift in _SHIFT:
        c = ((c << shift) | (c >> (28 - shift))) & 0x0FFFFFFF
        d = ((d << shift) | (d >> (28 - shift))) & 0x0FFFFFFF
        subkeys.append(_permute((c << 28) | d, _PC2, 56))
    return subkeys


def _f(r: int, subkey: int) -> int:
    x = _permute(r, _E, 32) ^ subkey
    y = 0
    for i in range(8):
        six = (x >> (42 - 6 * i)) & 0x3F
        row = ((six & 0x20) >> 4) | (six & 1)
        col = (six >> 1) & 0x0F
        y = (y << 4) | _SBOX[i][row * 16 + col]
    return _permute(y, _P, 32)


def des_block(key: bytes, block: bytes, decrypt: bool = False) -> bytes:
    """单块 DES（ECB），8 字节密钥 + 8 字节数据。"""
    subkeys = _key_schedule(key)
    ip = _permute(int.from_bytes(block, "big"), _IP, 64)
    l = (ip >> 32) & 0xFFFFFFFF
    r = ip & 0xFFFFFFFF
    for i in range(16):
        rnd = (15 - i) if decrypt else i
        l, r = r, l ^ _f(r, subkeys[rnd])
    return _permute((r << 32) | l, _FP, 64).to_bytes(8, "big")


# ------------------------------------------------------------- 6DES 级联 ----

KEYS = [
    bytes.fromhex("462b2b2a6c69237a"),   # k1
    bytes.fromhex("535373683f437e2b"),   # k2
    bytes.fromhex("7c2b216229407b3f"),   # k3
    bytes.fromhex("23594b7c747a513b"),   # k4
    bytes.fromhex("536e5f403a54432a"),   # k5
    bytes.fromhex("2525624a43275a53"),   # k6
]

# (密钥下标, 是否加密)，顺序: E_k4 D_k5 E_k6 E_k1 D_k2 E_k3
CASCADE = [(3, True), (4, False), (5, True), (0, True), (1, False), (2, True)]

MIN_BLOCK = 64
DECLARATION = b'<?xml version="1.0" encoding="utf-8"?>'


def _cascade(block: bytes, inverse: bool = False) -> bytes:
    """CASCADE 中 True 表示加密。inverse=True 时倒序并翻转每个操作。"""
    steps = list(reversed(CASCADE)) if inverse else CASCADE
    d = block
    for idx, enc in steps:
        do_encrypt = enc if not inverse else (not enc)
        d = des_block(KEYS[idx], d, decrypt=not do_encrypt)
    return d


def normalise(xml: str | bytes) -> bytes:
    """与客户端一致：UTF-8 -> utf-8，缺声明时补上。"""
    x = xml.encode("utf-8") if isinstance(xml, str) else xml
    x = x.replace(b'encoding="UTF-8"', b'encoding="utf-8"')
    if not x.lstrip().startswith(b"<?xml"):
        x = DECLARATION + x
    return x


def encode_body(xml: str | bytes) -> str:
    """请求 XML -> 门户 body（大写 hex）。"""
    x = normalise(xml)
    n = max(MIN_BLOCK, (len(x) + 1 + 7) & ~7)
    pad = x + b"\x00" * (n - len(x))
    out = b"".join(_cascade(pad[i:i + 8]) for i in range(0, n, 8))
    return out.hex().upper()


def decode_body(body_hex: str) -> bytes:
    """门户 body（hex）-> 明文（末尾 NUL 补齐）。"""
    raw = bytes.fromhex("".join(c for c in body_hex if c in "0123456789abcdefABCDEF"))
    if len(raw) % 8:
        raise ValueError("body 长度不是 8 的倍数")
    return b"".join(_cascade(raw[i:i + 8], inverse=True) for i in range(0, len(raw), 8))


def decode_body_str(body_hex: str) -> str:
    """门户 body（hex）-> 明文 XML 字符串（去掉补齐的 NUL）。"""
    pt = decode_body(body_hex)
    return pt.split(b"\x00")[0].decode("utf-8", "replace")


# ----------------------------------------------------------------- 自检 ----

_REFERENCE = {
    '<?xml version="1.0" encoding="UTF-8"?><request></request>':
        "C853A9968496B3E062B640DF7A9A022CA8AF4B51F157B48B8F3CB474842312D4"
        "762D8EFF99C4A04680601181FA7CEBD2FA738361D094A7A52CB179C46853233F",
    '<?xml version="1.0" encoding="UTF-8"?><request><a></a></request>':
        "C853A9968496B3E062B640DF7A9A022CA8AF4B51F157B48B8F3CB474842312D4"
        "762D8EFF99C4A04680601181FA7CEBD26B8E2A6D7297DF8DD4ACA9A911958F9D"
        "2348D470D2980907",
}


def _selftest() -> int:
    bad = 0
    # DES 已知答案
    kat = des_block(bytes.fromhex("0123456789ABCDEF"),
                    bytes.fromhex("4E6F772069732074"))
    if kat.hex().upper() != "3FA40E8A984D4815":
        print("  DES KAT   FAIL", kat.hex().upper())
        bad += 1
    else:
        print("  DES KAT   OK")

    for xml, expect in _REFERENCE.items():
        got = encode_body(xml)
        ok = got == expect
        print(f"  encode    {'OK  ' if ok else 'FAIL'}  {xml[:48]}")
        if not ok:
            bad += 1
            print("      got ", got[:64])
            print("      want", expect[:64])
        back = decode_body_str(got)
        exp_norm = xml.replace("UTF-8", "utf-8")
        ok2 = back == exp_norm
        print(f"  decode    {'OK  ' if ok2 else 'FAIL'}")
        if not ok2:
            bad += 1
    print("SELFTEST", "PASS" if bad == 0 else f"FAILED ({bad})")
    return bad


if __name__ == "__main__":
    raise SystemExit(_selftest())
