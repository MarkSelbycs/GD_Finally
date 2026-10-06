"""Decode (and encode) the portal algorithm-module container. VERIFIED.

Format recovered by hooking the live service with Frida and confirmed by
dumping the decrypted buffer out of ESurfingSvr.exe:

    container = "001@" + <64 hex chars = 32-byte key> + "$" + <Algo-ID> + "]" +
                <8-byte prefix> + <ciphertext>

    decode:  skip the ASCII header, skip the 8-byte prefix, then for every
             8-byte block apply the 2-word XXTEA variant twice -- first with
             key1, then with key2 (both 16-byte ASCII constants), then
             raw-LZMA decompress (lc=3, lp=0, pb=2) to get the module PE.

The two keys are fixed program constants:

    key1 = |iKFMm;FZjI6oItG
    key2 = mvm536xR8MJ-5C89

Verification: decoding the captured container yields a 46596-byte PE image, and
the decrypted first block matches byte-for-byte what ESurfingSvr.exe produced in
memory while decoding it.
"""

from __future__ import annotations

import lzma
import struct
import sys
from pathlib import Path

DELTA = 0x9E3779B9
MASK = 0xFFFFFFFF

KEY1 = b"|iKFMm;FZjI6oItG"
KEY2 = b"mvm536xR8MJ-5C89"

RAW_FILTERS = [{"id": lzma.FILTER_LZMA1, "dict_size": 1 << 20, "lc": 3, "lp": 0, "pb": 2}]
PREFIX_SIZE = 8


def _words(key: bytes) -> list[int]:
    return list(struct.unpack("<4I", key))


W1, W2 = _words(KEY1), _words(KEY2)


def xxtea_decrypt(key, v0, v1, rounds=32):
    s = (rounds * DELTA) & MASK
    for _ in range(rounds):
        mx = ((((v0 << 4) & MASK) ^ (v0 >> 5)) + (v0 ^ s) + key[(s >> 11) & 3]) & MASK
        v1 = (v1 - mx) & MASK
        s = (s - DELTA) & MASK
        mx = ((((v1 << 4) & MASK) ^ (v1 >> 5)) + (v1 ^ s) + key[s & 3]) & MASK
        v0 = (v0 - mx) & MASK
    return v0, v1


def xxtea_encrypt(key, v0, v1, rounds=32):
    s = 0
    limit = (rounds * DELTA) & MASK
    while s != limit:
        mx = ((((v1 << 4) & MASK) ^ (v1 >> 5)) + (v1 ^ s) + key[s & 3]) & MASK
        v0 = (v0 + mx) & MASK
        s = (s + DELTA) & MASK
        mx = ((((v0 << 4) & MASK) ^ (v0 >> 5)) + (v0 ^ s) + key[(s >> 11) & 3]) & MASK
        v1 = (v1 + mx) & MASK
    return v0, v1


def transform(data: bytes, keys, func) -> bytes:
    out = bytearray()
    for off in range(0, len(data) // 8 * 8, 8):
        v0, v1 = struct.unpack("<II", data[off:off + 8])
        for key in keys:
            v0, v1 = func(key, v0, v1)
        out += struct.pack("<II", v0, v1)
    return bytes(out)


def split_container(blob: bytes):
    """Return (magic, key_hex, algo_id, payload)."""
    at = blob.find(b"@")
    dollar = blob.find(b"$", at + 1)
    bracket = blob.find(b"]", dollar + 1)
    if not (0 <= at < 8 and at < dollar < bracket < 256):
        raise ValueError("not a module container")
    return blob[:at], blob[at + 1:dollar], blob[dollar + 1:bracket], blob[bracket + 1:]


def decode(blob: bytes) -> bytes:
    """Container bytes -> module PE bytes."""
    _magic, key_hex, algo_id, payload = split_container(blob)
    body = payload[PREFIX_SIZE:]
    decrypted = transform(body, [W1, W2], xxtea_decrypt)
    inner = lzma.LZMADecompressor(format=lzma.FORMAT_RAW, filters=RAW_FILTERS).decompress(decrypted)
    print(f"  key={key_hex.decode()}  Algo-ID={algo_id.decode()}")
    print(f"  payload={len(payload)} -> decrypted={len(decrypted)} -> module={len(inner)} bytes")
    return inner


def encode(module: bytes, key_hex: str, algo_id: str) -> bytes:
    """Module PE bytes -> container bytes (round-trip helper)."""
    comp = lzma.compress(module, format=lzma.FORMAT_RAW, filters=RAW_FILTERS)
    body = transform(comp, [W2, W1], xxtea_encrypt)
    prefix = b"\x00\x00\x00\x01\x00\xb6\x00\x20"
    return f"001@{key_hex}${algo_id}]".encode() + prefix + body


def main():
    targets = sys.argv[1:] or [
        "captured/module_fetch.bin",
        "captured/zxm_module_download.bin",
    ]
    for path in targets:
        p = Path(path)
        if not p.exists():
            print(f"missing {p}")
            continue
        print(f"=== {p} ===")
        blob = p.read_bytes()
        module = decode(blob)
        if module[:2] != b"MZ":
            print("  WARNING: result is not a PE image")
            continue
        out = p.with_name(p.stem + "_module.bin")
        out.write_bytes(module)
        pe = struct.unpack_from("<I", module, 0x3C)[0]
        machine = struct.unpack_from("<H", module, pe + 4)[0]
        nsec = struct.unpack_from("<H", module, pe + 6)[0]
        print(f"  saved {out} (PE machine=0x{machine:x}, sections={nsec})")

        # round-trip check
        _m, key_hex, algo_id, _pay = split_container(blob)
        re_made = encode(module, key_hex.decode(), algo_id.decode())
        same_sizes = len(re_made) == len(blob)
        print(f"  re-encode length {len(re_made)} vs original {len(blob)}: {'match' if same_sizes else 'differ'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
