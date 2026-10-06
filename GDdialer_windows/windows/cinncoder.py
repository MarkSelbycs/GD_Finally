"""Implementation of the CInnerCoder 2-word XXTEA variant in ESurfingSvr.exe.

Key arrays are reconstructed from the immediate stores plus the XOR rounds in
the dispatcher at 0x415e80:

  mode 2 (0x415eb2 branch) -> key array at [ebp-0x38], used with 0x4260b0
  mode 3 (0x4161f5 branch) -> key array at [ebp-0x28], used with 0x426200

Note: the dispatcher stores at BYTE offsets computed as 4*N, so offsets
0,4,8,... map to word indices 0,1,2,...
"""

from __future__ import annotations

import re
import struct
from pathlib import Path

DELTA = 0x9E3779B9
MASK = 0xFFFFFFFF


def _key_array(immediates: dict[int, int], xors: list[tuple[int, int]], size: int = 9) -> list[int]:
    words = [0] * size
    for index, value in immediates.items():
        words[index] = value & MASK
    for index, value in xors:
        words[index] = (words[index] ^ value) & MASK
    return words


KEY_A = _key_array(
    {
        0: 0xEC4C6F3C,
        1: 0x5EC9BCD6,
        2: 0x5D966189,
        3: 0xC366F3C0,
        4: 0xE94336D0,
        5: 0x0006B81F,
        6: 0x93818B99,
        7: 0xB173CFD0,
        8: 0x93A97696,
    },
    [
        (5, 0x527E8E2C),
        (0, 0xAA070640),
        (7, 0x884B8CE5),
        (1, 0x18F2D19B),
        (8, 0xD2B0F996),
        (3, 0x8412BAAF),
        (6, 0xBECBC6A1),
        (4, 0xDC2E40BD),
        (2, 0x6BDF0BD3),
    ],
)

KEY_B = _key_array(
    {
        0: 0xDC3261B5,
        1: 0x41C8C32A,
        2: 0x85322235,
        3: 0xC89E9EEA,
        4: 0x53E5CCD1,
        5: 0x4AABBD7A,
        6: 0x0C49F529,
        7: 0xC444CC80,
        8: 0x2F3363DF,
    },
    [
        (7, 0xBC60A8AB),
        (4, 0x0BD39AB4),
        (3, 0x9CEFCBB3),
        (6, 0x2161D46A),
        (0, 0xFA601DF8),
        (2, 0xA45B5C76),
        (1, 0x2EB2B67D),
        (5, 0x318FCD04),
        (8, 0x2F3363DF),
    ],
)


def xxtea2_decrypt(key: list[int], v0: int, v1: int, rounds: int = 32) -> tuple[int, int]:
    s = (rounds * DELTA) & MASK
    for _ in range(rounds):
        z = v0
        mx = ((((z << 4) & MASK) ^ (z >> 5)) + (z ^ s) + key[(s >> 11) & 3]) & MASK
        v1 = (v1 - mx) & MASK
        s = (s - DELTA) & MASK
        y = v1
        mx = ((((y << 4) & MASK) ^ (y >> 5)) + (y ^ s) + key[s & 3]) & MASK
        v0 = (v0 - mx) & MASK
    return v0, v1


def xxtea2_encrypt(key: list[int], v0: int, v1: int, rounds: int = 32) -> tuple[int, int]:
    s = 0
    limit = (rounds * DELTA) & MASK
    while s != limit:
        y = v1
        mx = ((((y << 4) & MASK) ^ (y >> 5)) + (y ^ s) + key[s & 3]) & MASK
        v0 = (v0 + mx) & MASK
        s = (s + DELTA) & MASK
        z = v0
        mx = ((((z << 4) & MASK) ^ (z >> 5)) + (z ^ s) + key[(s >> 11) & 3]) & MASK
        v1 = (v1 + mx) & MASK
    return v0, v1


def _apply(raw: bytes, keys: list[int], func, reverse: bool = False) -> bytearray:
    data = bytearray(raw)
    first, second = (keys[4:8], keys[0:4]) if reverse else (keys[0:4], keys[4:8])
    end = len(data) - 1
    p = 0
    while p < end:
        v0, v1 = struct.unpack_from("<II", data, p)
        v0, v1 = func(first, v0, v1)
        v0, v1 = func(second, v0, v1)
        struct.pack_into("<II", data, p, v0, v1)
        p += 8
    return data


def decode_mode2(raw: bytes, key_array: list[int]) -> bytes:
    data = _apply(raw, key_array, xxtea2_decrypt)
    pad = data[len(data) - 1]
    if not 1 <= pad <= 8:
        return bytes(data)
    return bytes(data[: len(data) - pad])


def encode_mode2(raw: bytes, key_array: list[int]) -> bytes:
    body = bytearray(raw)
    pad = 8 - (len(body) % 8)
    body.extend(bytes([pad]) * pad)
    return bytes(_apply(bytes(body), key_array, xxtea2_encrypt, reverse=True))


def main():
    print("KEY_A =", " ".join(f"0x{w:08X}" for w in KEY_A))
    print("KEY_B =", " ".join(f"0x{w:08X}" for w in KEY_B))
    probe = b"<request><probe>1</probe></request>"
    for name, key in (("A", KEY_A), ("B", KEY_B)):
        assert decode_mode2(encode_mode2(probe, key), key) == probe, name
    print("self roundtrip: PASS (A and B)")

    resp = Path("captured/resp_172_17_104_130_50520_219.bin").read_bytes()
    chunk = re.sub(rb"^[0-9a-fA-F]+\r\n", b"", resp).split(b"\r\n0\r\n")[0]
    raw = bytes.fromhex(chunk.decode("ascii"))
    print("ciphertext bytes", len(raw), "mod8", len(raw) % 8)

    for label, key in (("A", KEY_A), ("B", KEY_B)):
        swapped = key[4:8] + key[0:4]
        for offset in (0, 8):
            data = raw[offset:]
            if len(data) % 8 or len(data) < 16:
                continue
            for kl, kk in (("k1k2", key), ("k2k1", swapped)):
                out = decode_mode2(data, kk)
                printable = sum(1 for c in out if 32 <= c < 127 or c in (9, 10, 13))
                ratio = printable / max(len(out), 1)
                print(f"KEY_{label} off={offset} {kl}: len={len(out)} printable={ratio:.2f} head={out[:64]!r}")


if __name__ == "__main__":
    main()
