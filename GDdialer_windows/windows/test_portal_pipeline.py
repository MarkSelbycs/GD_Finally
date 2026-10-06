"""Test whether the portal body uses the same pipeline as the module container.

The module container turned out to be

    XXTEA(key1) -> XXTEA(key2) per 8-byte block, then raw LZMA (lc=3, lp=0, pb=2)

If the portal body is the same scheme, then hex-decoding a captured body,
running the two XXTEA decryptions and raw-LZMA decompressing it must yield the
request XML.
"""

from __future__ import annotations

import lzma
import struct
from pathlib import Path

from cinncoder import xxtea2_decrypt, xxtea2_encrypt

KEY1 = b"|iKFMm;FZjI6oItG"
KEY2 = b"mvm536xR8MJ-5C89"
W1 = list(struct.unpack("<4I", KEY1))
W2 = list(struct.unpack("<4I", KEY2))

BODIES = {
    "ticket": "captured/req_14_146_227_141_7001_752.bin",
    "keep": "captured/req_14_146_227_142_7001_784.bin",
    "auth": "captured/req_14_146_227_141_7001_608.bin",
    "state": "captured/req_14_146_227_141_7001_496.bin",
    "term": "captured/req_14_146_227_141_7001_544.bin",
}


def blocks_decrypt(data: bytes, keys) -> bytes:
    out = bytearray()
    for off in range(0, len(data) // 8 * 8, 8):
        v0, v1 = struct.unpack("<II", data[off:off + 8])
        for k in keys:
            v0, v1 = xxtea2_decrypt(k, v0, v1)
        out += struct.pack("<II", v0, v1)
    return bytes(out)


def blocks_encrypt(data: bytes, keys) -> bytes:
    out = bytearray()
    for off in range(0, len(data) // 8 * 8, 8):
        v0, v1 = struct.unpack("<II", data[off:off + 8])
        for k in keys:
            v0, v1 = xxtea2_encrypt(k, v0, v1)
        out += struct.pack("<II", v0, v1)
    return bytes(out)


def raw_lzma(data: bytes, ds=1 << 20):
    filters = [{"id": lzma.FILTER_LZMA1, "dict_size": ds, "lc": 3, "lp": 0, "pb": 2}]
    return lzma.LZMADecompressor(format=lzma.FORMAT_RAW, filters=filters).decompress(data)


def main():
    # first: prove the module pipeline works end to end (sanity check)
    blob = Path("captured/module_fetch.bin").read_bytes()
    payload = blob[blob.find(b"]") + 1:]
    dec = blocks_decrypt(payload[8:], [W1, W2])
    inner = raw_lzma(dec)
    print(f"module check: {len(payload)} -> decrypt {len(dec)} -> lzma {len(inner)} head={inner[:2]!r}")

    print("\n=== portal bodies ===")
    for name, path in BODIES.items():
        raw = bytes.fromhex(Path(path).read_bytes().strip().decode())
        found = False
        for order_label, keys in (("k1k2", [W1, W2]), ("k2k1", [W2, W1])):
            dec = blocks_decrypt(raw, keys)
            for off in range(0, 17):
                for ds in (1 << 16, 1 << 20, 1 << 24):
                    try:
                        out = raw_lzma(dec[off:], ds)
                    except Exception:
                        continue
                    if len(out) > 16:
                        tag = "  <<< XML" if b"<" in out[:32] else ""
                        print(f"  {name:7} {order_label} off={off} ds={ds:#x} -> {len(out)} bytes "
                              f"head={out[:60]!r}{tag}")
                        found = True
                        if tag:
                            Path(f"captured/plain_{name}.xml").write_bytes(out)
                        break
                if found:
                    break
            if found:
                break
        if not found:
            dec = blocks_decrypt(raw, [W1, W2])
            print(f"  {name:7} no lzma; decrypted head={dec[:24].hex(' ')}")


if __name__ == "__main__":
    main()
