"""Pure-Python implementation of the portal body codec (custom SPN stream cipher).

Reverse-engineered from ESurfingSvr.exe. The body is a stream cipher:

    body = hex( SPN_keystream(KEY) XOR plaintext_padded_to_4_bytes )

The SPN has a 22-word state, a 16-word working buffer, two custom S-boxes and a
31-bit modular-add mixing layer. The keystream depends ONLY on the key (two
16-byte ASCII halves), not on the plaintext, which is why every request shares
the same first 48 ciphertext bytes (same XML declaration + fixed keystream).

Function map (ESurfingSvr.exe VA, imagebase 0x400000):
    0x433100 init       0x4331d0 cipher     0x432c90 linear layer
    0x432d80 round      0x432f50 mix        0x432f00 shift-append
    0x432b70 mod31add   0x4330a0 bswap      0x432ba0 diffuse
    0x432c40 combine    0x432c60 combine2
    S-box1 @ 0x3b298   S-box2 @ 0x3b398   table @ 0x43c098
"""

from __future__ import annotations

import struct
from pathlib import Path

MASK = 0xFFFFFFFF

EXE = Path("../ESurfingSvr.exe")


def _load_exe_bytes(off: int, n: int) -> bytes:
    return EXE.read_bytes()[off:off + n]


# S-boxes are 256-byte permutations at file offsets 0x3b298 / 0x3b398
S1 = _load_exe_bytes(0x3B298, 256)
S2 = _load_exe_bytes(0x3B398, 256)

# key-mix table: 16 dwords at VA 0x43c098 -> file offset (in .rdata)
TABLE = [
    0x000044D7, 0x000026BC, 0x0000626B, 0x0000135E,
    0x00005789, 0x000035E2, 0x00007135, 0x000009AF,
    0x00004D78, 0x00002F13, 0x00006BC4, 0x00001AF1,
    0x00005E26, 0x00003C4D, 0x0000789A, 0x000047AC,
]


def rotl(x: int, n: int) -> int:
    return ((x << n) | (x >> (32 - n))) & MASK


def bswap(x: int) -> int:
    return ((x & 0xFF) << 24) | ((x & 0xFF00) << 8) | ((x >> 8) & 0xFF00) | ((x >> 24) & 0xFF)


def diffuse(x: int) -> int:
    # 0x432ba0
    return (rotl(x, 2) ^ x ^ rotl(x, 10) ^ rotl(x, 18) ^ rotl(x, 24)) & MASK


def rotl8(x: int) -> int:
    # 0x432bf0
    return ((x << 8) | (x >> 24)) & MASK


def combine(b0, b1, b2, b3) -> int:
    # 0x432c40
    return ((b0 & 0xFF) << 24) | ((b1 & 0xFF) << 16) | ((b2 & 0xFF) << 8) | (b3 & 0xFF)


def combine2(a, b, c) -> int:
    # 0x432c60
    return ((a << 23) & 0x7FFFFFFF) | ((b << 8) & 0x7FFFFFFF) | c


def mod31add(a: int, b: int) -> int:
    # 0x432b70
    s = (a + b) & MASK
    return ((s & 0x7FFFFFFF) + (s >> 31)) & MASK


def rotl31(x: int, n: int) -> int:
    return (((x << n) | (x >> (31 - n))) & 0x7FFFFFFF)


def sbox_word(x: int) -> int:
    return combine(S1[x & 0xFF], S2[(x >> 8) & 0xFF], S1[(x >> 16) & 0xFF], S2[(x >> 24) & 0xFF])


def linear_layer(s):
    # 0x432c90
    s[2] = ((s[21] & 0x7FFF8000) << 1) | (s[20] & 0xFFFF)
    s[3] = ((s[17] & 0xFFFF) << 16) | (s[15] >> 15)
    s[4] = ((s[13] & 0xFFFF) << 16) | (s[11] >> 15)
    s[5] = ((s[8] & 0xFFFF) << 16) | (s[6] >> 15)


def round_fn(s):
    # 0x432d80
    tmp0 = ((s[2] ^ s[0]) + s[0]) & MASK
    tmp1 = (s[0] + s[2]) & MASK
    tmp2 = (s[0] ^ s[3]) & MASK
    d0 = diffuse((((tmp1 & 0xFFFF) << 16) | (tmp2 >> 16)) & MASK)
    d1 = rotl8((((tmp2 & 0xFFFF) << 16) | (tmp1 >> 16)) & MASK)
    s[0] = sbox_word(d0)
    s[1] = sbox_word(d1)
    return tmp0


def mix(s):
    # 0x432f50
    w = s[6]
    w = mod31add(w, rotl31(w, 8))
    w = mod31add(w, rotl31(s[10], 20))
    w = mod31add(w, rotl31(s[16], 21))
    w = mod31add(w, rotl31(s[19], 17))
    w = mod31add(w, rotl31(s[21], 15))
    return w


def shift_append(s, x):
    # 0x432f00
    for i in range(15):
        s[6 + i] = s[7 + i]
    s[21] = x


def init(s, key1, key2):
    # 0x433100
    for i in range(22):
        s[i] = 0
    for i in range(16):
        s[6 + i] = combine2(key1[i], TABLE[i], key2[i])
    for _ in range(32):
        linear_layer(s)
        t = round_fn(s)
        w = mix(s)
        shift_append(s, mod31add(w, t >> 1))


def cipher(s, data_words, output_words):
    # 0x4331d0 (data_words = list of uint32, output in-place list)
    linear_layer(s)
    round_fn(s)
    for i in range(len(data_words)):
        w = mix(s)
        shift_append(s, w)
        linear_layer(s)
        x = bswap(data_words[i])
        r = round_fn(s)
        out = x ^ r ^ s[5]
        output_words[i] = bswap(out)
    w = mix(s)
    shift_append(s, w)


def code(key1: bytes, key2: bytes, data: bytes) -> bytes:
    """Apply the portal body stream cipher to data (in place, returns ciphertext)."""
    # data must be padded to a multiple of 4 bytes by the caller
    assert len(data) % 4 == 0, "data must be 4-byte aligned"
    words = list(struct.unpack("<%dI" % (len(data) // 4), data))
    s = [0] * 22
    init(s, key1, key2)
    out = [0] * len(words)
    cipher(s, words, out)
    return struct.pack("<%dI" % len(out), *out)


def main():
    plain = b'<?xml version="1.0" encoding="UTF-8"?><request><'
    plain = plain + b"\x00" * ((-len(plain)) % 4)
    target = ("C853A9968496B3E062B640DF7A9A022CA8AF4B51F157B48B"
              "8F3CB474842312D4762D8EFF99C4A046360E7DB7B1FC46F7")
    candidates = {
        "KEY_A": (b"|iKFMm;FZjI6oItG", b"mvm536xR8MJ-5C89"),
        "KEY_B": (b"M|R&WuZoC~i!YUqT", b"eV6X~p${C!(-+d$x"),
    }
    for name, (k1, k2) in candidates.items():
        ct = code(k1, k2, plain)
        print(f"{name}: {ct[:48].hex().upper()}")
        print(f"       match={ct[:48].hex().upper() == target}")
    print("expected:", target)


if __name__ == "__main__":
    main()
