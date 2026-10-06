"""Decode the module payload and the portal bodies with the hooked keys.

Frida showed the coder applying the 2-word XXTEA variant block by block
(arg1 advancing by 8) with two alternating 16-byte ASCII keys:

    key1 = |iKFMm;FZjI6oItG   -> 464B697C 463B6D4D 36496A5A 4774496F
    key2 = mvm536xR8MJ-5C89   -> 356D766D 52783633 2D4A4D38 39384335

These are exactly the first eight words of the earlier static reconstruction,
so the keys were right and only the layer order was wrong. This tries every
order on the module container payload and on the captured portal bodies.
"""

from __future__ import annotations

import struct
from pathlib import Path

from cinncoder import xxtea2_decrypt, xxtea2_encrypt

KEY1 = b"|iKFMm;FZjI6oItG"
KEY2 = b"mvm536xR8MJ-5C89"


def words(k: bytes):
    return list(struct.unpack("<4I", k))


W1, W2 = words(KEY1), words(KEY2)


def block_dec(block: bytes, keys) -> bytes:
    v0, v1 = struct.unpack("<II", block)
    for k in keys:
        v0, v1 = xxtea2_decrypt(k, v0, v1)
    return struct.pack("<II", v0, v1)


def block_enc(block: bytes, keys) -> bytes:
    v0, v1 = struct.unpack("<II", block)
    for k in keys:
        v0, v1 = xxtea2_encrypt(k, v0, v1)
    return struct.pack("<II", v0, v1)


SCHEMES = {
    "dec k1": [W1],
    "dec k2": [W2],
    "dec k1thenk2": [W1, W2],
    "dec k2thenk1": [W2, W1],
}


def looks(data: bytes) -> str:
    if data[:2] == b"MZ":
        return "PE"
    if data[:4] == b"\x7fELF":
        return "ELF"
    if data[:5] == b"ZXM\x00Z":
        return "ZXM"
    if b"<?xml" in data[:24] or data[:5] == b"<?xml":
        return "XML"
    if data[:3] == b"\x5d\x00\x00":
        return "LZMA"
    printable = sum(1 for c in data[:64] if 32 <= c < 127)
    return f"printable={printable}/64"


def main():
    print("key1 words:", [hex(x) for x in W1])
    print("key2 words:", [hex(x) for x in W2])

    payload = Path("captured/module_fetch_payload.bin").read_bytes()
    body_known = bytes.fromhex("c853a9968496b3e0")
    print("\n=== known portal block: plaintext '<?xml ve' ===")
    for name, keys in SCHEMES.items():
        out = block_dec(body_known, keys)
        print(f"  {name:14} -> {out!r}")

    print("\n=== module payload ===")
    for name, keys in SCHEMES.items():
        n = len(payload) // 8 * 8
        dec = bytearray()
        for off in range(0, n, 8):
            dec += block_dec(payload[off:off + 8], keys)
        print(f"  {name:14} head={bytes(dec[:16]).hex(' ')}  {looks(bytes(dec))}")

    print("\n=== portal bodies ===")
    for label, path in (
        ("ticket", "captured/req_14_146_227_141_7001_752.bin"),
        ("keep", "captured/req_14_146_227_142_7001_784.bin"),
        ("auth", "captured/req_14_146_227_141_7001_608.bin"),
    ):
        data = bytes.fromhex(Path(path).read_bytes().strip().decode())
        for name, keys in SCHEMES.items():
            dec = bytearray()
            for off in range(0, len(data) // 8 * 8, 8):
                dec += block_dec(data[off:off + 8], keys)
            print(f"  {label:7} {name:14} {bytes(dec)[:32]!r}  {looks(bytes(dec))}")


if __name__ == "__main__":
    main()
