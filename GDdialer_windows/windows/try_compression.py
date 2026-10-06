"""Try treating portal bodies as compressed (not encrypted) data.

The algorithm module loaded by the service exposes only
    Compress / Uncompress / HexCodeA / HexDeCodeA / HexCodeW / HexDeCodeW
    StrToWStr / WStrToStr / Serialize / FreeResult
with no encrypt/decrypt names. So a portal body may simply be
    hex(compress(xml))
rather than an encrypted blob. This tries the standard decompressors.
"""

from __future__ import annotations

import bz2
import lzma
import zlib
from pathlib import Path

FILES = {
    "ticket": "captured/req_14_146_227_141_7001_752.bin",
    "keep": "captured/req_14_146_227_142_7001_784.bin",
    "auth": "captured/req_14_146_227_141_7001_608.bin",
    "state": "captured/req_14_146_227_141_7001_496.bin",
    "term": "captured/req_14_146_227_141_7001_544.bin",
    "dlmod": "captured/module_fetch_payload.bin",
}


def looks_like_xml(data: bytes) -> bool:
    head = data[:64]
    return b"<" in head and b">" in head


def raw_lzma(data: bytes, dict_size: int, lc=3, lp=0, pb=2):
    filters = [{"id": lzma.FILTER_LZMA1, "dict_size": dict_size, "lc": lc, "lp": lp, "pb": pb}]
    dec = lzma.LZMADecompressor(format=lzma.FORMAT_RAW, filters=filters)
    return dec.decompress(data)


def main():
    for name, path in FILES.items():
        blob = Path(path).read_bytes()
        if name == "dlmod":
            data = blob
        else:
            data = bytes.fromhex(blob.strip().decode("ascii"))
        print(f"\n=== {name}: {len(data)} bytes, head={data[:12].hex(' ')} ===")

        attempts = []
        for offset in range(0, 9):
            chunk = data[offset:]
            for label, fn in (
                ("zlib", lambda c: zlib.decompress(c)),
                ("gzip", lambda c: zlib.decompress(c, 16 + zlib.MAX_WBITS)),
                ("deflate-raw", lambda c: zlib.decompress(c, -zlib.MAX_WBITS)),
                ("bz2", lambda c: bz2.decompress(c)),
                ("lzma-alone", lambda c: lzma.decompress(c, format=lzma.FORMAT_ALONE)),
                ("xz", lambda c: lzma.decompress(c, format=lzma.FORMAT_XZ)),
            ):
                try:
                    out = fn(chunk)
                    if len(out) > 32:
                        attempts.append((label, offset, out))
                except Exception:
                    pass
            for ds in (1 << 16, 1 << 20, 1 << 23, 0x01000000):
                for props in ((3, 0, 2), (3, 0, 0), (0, 0, 0), (2, 0, 2)):
                    try:
                        out = raw_lzma(chunk, ds, *props)
                        if len(out) > 32:
                            attempts.append((f"raw-lzma ds={ds:#x} {props}", offset, out))
                    except Exception:
                        pass

        if not attempts:
            print("  no decompressor succeeded")
            continue
        for label, offset, out in attempts:
            tag = "  <<< XML" if looks_like_xml(out) else ""
            print(f"  {label:28} off={offset} -> {len(out)} bytes")
            print(f"      head: {out[:110]!r}{tag}")
            if looks_like_xml(out):
                save = Path("decompressed")
                save.mkdir(exist_ok=True)
                (save / f"{name}_{label.split()[0]}_{offset}.bin").write_bytes(out)


if __name__ == "__main__":
    main()
