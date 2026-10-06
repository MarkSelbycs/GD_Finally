"""Decompress the XXTEA-decrypted module buffer.

The dumped buffer (24 KB) is still high entropy, so an Uncompress stage must
follow. This sweeps the standard decompressors at several offsets, and also
checks the custom container header bytes for a length/dictionary field.
"""

from __future__ import annotations

import bz2
import lzma
import struct
import zlib
from pathlib import Path

SRC = Path("captured/decrypted_module_1.bin")


def report(label, out: bytes):
    if not out or len(out) < 64:
        return False
    head = out[:24]
    tag = ""
    if head[:2] == b"MZ":
        tag = "  <<< PE"
    elif head[:4] == b"\x7fELF":
        tag = "  <<< ELF"
    elif b"<" in head and b">" in head:
        tag = "  <<< text"
    print(f"  {label:34} -> {len(out):7} bytes  head={head.hex(' ')}{tag}")
    if tag:
        Path("captured/module_inner.bin").write_bytes(out)
    return True


def main():
    data = SRC.read_bytes()
    print("buffer size", len(data))
    print("first 32 bytes:", data[:32].hex(" "))
    print("as dwords     :", [hex(x) for x in struct.unpack_from("<8I", data, 0)])

    hits = 0
    for offset in range(0, 33):
        chunk = data[offset:]
        for label, fn in (
            ("zlib", lambda c: zlib.decompress(c)),
            ("gzip", lambda c: zlib.decompress(c, 16 + zlib.MAX_WBITS)),
            ("deflate", lambda c: zlib.decompress(c, -zlib.MAX_WBITS)),
            ("bz2", lambda c: bz2.decompress(c)),
            ("lzma-alone", lambda c: lzma.decompress(c, format=lzma.FORMAT_ALONE)),
            ("xz", lambda c: lzma.decompress(c, format=lzma.FORMAT_XZ)),
            ("auto", lambda c: lzma.decompress(c, format=lzma.FORMAT_AUTO)),
        ):
            try:
                out = fn(chunk)
                if report(f"{label} off={offset}", out):
                    hits += 1
            except Exception:
                pass
        for ds in (1 << 16, 1 << 20, 1 << 23, 0x01000000):
            for props in ((3, 0, 2), (3, 0, 0), (0, 0, 0)):
                try:
                    filters = [{"id": lzma.FILTER_LZMA1, "dict_size": ds,
                                "lc": props[0], "lp": props[1], "pb": props[2]}]
                    dec = lzma.LZMADecompressor(format=lzma.FORMAT_RAW, filters=filters)
                    out = dec.decompress(chunk)
                    if report(f"raw-lzma off={offset} ds={ds:#x} {props}", out):
                        hits += 1
                except Exception:
                    pass
    print("decompression hits:", hits)


if __name__ == "__main__":
    main()
