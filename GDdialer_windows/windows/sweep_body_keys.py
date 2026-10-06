"""Sweep key candidates for the portal body against the XXTEA block scheme.

The module container is decoded with two fixed ASCII keys, but the portal body
does not match them. A likely alternative is that the body key is derived from
the per-session container key that the server hands out with the module. This
tries every plausible key pairing and layer order, with an optional LZMA stage.
"""

from __future__ import annotations

import lzma
import struct
from pathlib import Path

from cinncoder import xxtea2_decrypt

BODIES = {
    "ticket": "captured/req_14_146_227_141_7001_752.bin",
    "keep": "captured/req_14_146_227_142_7001_784.bin",
    "auth": "captured/req_14_146_227_141_7001_608.bin",
    "state": "captured/req_14_146_227_141_7001_496.bin",
    "term": "captured/req_14_146_227_141_7001_544.bin",
}

A1, A2 = b"|iKFMm;FZjI6oItG", b"mvm536xR8MJ-5C89"
B1, B2 = b"M|R&WuZoC~i!YUqT", b"eV6X~p${C!(-+d$x"


def words(raw: bytes):
    return list(struct.unpack("<4I", raw[:16]))


def key_sets():
    sets = {}
    for path in ("captured/module_fetch.bin", "captured/zxm_module_download.bin"):
        p = Path(path)
        if not p.exists():
            continue
        blob = p.read_bytes()
        at, dl = blob.find(b"@"), blob.find(b"$")
        raw = bytes.fromhex(blob[at + 1:dl].decode())
        if len(raw) >= 32:
            sets[f"container:{raw[:8].hex()}"] = (words(raw[:16]), words(raw[16:32]))
    sets["asciiA"] = (words(A1), words(A2))
    sets["asciiB"] = (words(B1), words(B2))
    sets["mixedA1B2"] = (words(A1), words(B2))
    sets["mixedB1A2"] = (words(B1), words(A2))
    return sets


def decrypt(data: bytes, kx, ky) -> bytes:
    out = bytearray()
    for off in range(0, len(data) // 8 * 8, 8):
        v0, v1 = struct.unpack("<II", data[off:off + 8])
        v0, v1 = xxtea2_decrypt(kx, v0, v1)
        v0, v1 = xxtea2_decrypt(ky, v0, v1)
        out += struct.pack("<II", v0, v1)
    return bytes(out)


def try_lzma(data: bytes):
    for off in range(0, 17):
        for ds in (1 << 16, 1 << 20, 1 << 24):
            try:
                filters = [{"id": lzma.FILTER_LZMA1, "dict_size": ds, "lc": 3, "lp": 0, "pb": 2}]
                return off, lzma.LZMADecompressor(format=lzma.FORMAT_RAW, filters=filters).decompress(data[off:])
            except Exception:
                continue
    return None, None


def main():
    sets = key_sets()
    print("key sets:", list(sets))
    for name, path in BODIES.items():
        raw = bytes.fromhex(Path(path).read_bytes().strip().decode())
        for label, (kx, ky) in sets.items():
            for order in ("xy", "yx"):
                a, b = (kx, ky) if order == "xy" else (ky, kx)
                dec = decrypt(raw, a, b)
                printable = sum(1 for c in dec if 32 <= c < 127 or c in (9, 10, 13)) / len(dec)
                off, out = try_lzma(dec)
                if out:
                    print(f"  {name:7} {label:26} {order} LZMA off={off} -> {len(out)} {out[:40]!r}")
                elif printable > 0.9:
                    print(f"  {name:7} {label:26} {order} printable={printable:.2f} {dec[:48]!r}")
    print("sweep done")


if __name__ == "__main__":
    main()
