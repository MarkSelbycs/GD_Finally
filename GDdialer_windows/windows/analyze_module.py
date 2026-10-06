"""Structural analysis of the recovered algorithm module (module_inner.bin).

The module is a 32-bit PE with four sections and no export table, so the coder
interface must be registered some other way. This maps RVAs correctly, lists
imports, strings and the entry point to identify what the module implements.
"""

from __future__ import annotations

import re
import struct
from pathlib import Path

SRC = Path("captured/module_inner.bin")


class PE:
    def __init__(self, data: bytes):
        self.data = data
        self.pe = struct.unpack_from("<I", data, 0x3C)[0]
        self.nsec = struct.unpack_from("<H", data, self.pe + 6)[0]
        self.optsize = struct.unpack_from("<H", data, self.pe + 20)[0]
        self.opt = self.pe + 24
        self.magic = struct.unpack_from("<H", data, self.opt)[0]
        self.entry = struct.unpack_from("<I", data, self.opt + 16)[0]
        self.imagebase = struct.unpack_from("<I", data, self.opt + 28)[0]
        self.sections = []
        sec = self.opt + self.optsize
        for i in range(self.nsec):
            o = sec + i * 40
            name = data[o:o + 8].rstrip(b"\0").decode("latin1")
            vs, va, rs, ra = struct.unpack_from("<IIII", data, o + 8)
            self.sections.append((name, va, vs, ra, rs))
        self.dd = self.opt + (96 if self.magic == 0x10B else 112)

    def rva2off(self, rva: int):
        for _n, va, vs, ra, rs in self.sections:
            if va <= rva < va + max(vs, rs):
                return ra + (rva - va)
        return None

    def cstr(self, rva: int, limit: int = 256) -> str:
        off = self.rva2off(rva)
        if off is None:
            return ""
        end = self.data.find(b"\0", off, off + limit)
        if end < 0:
            end = off + limit
        return self.data[off:end].decode("latin1", "replace")

    def directory(self, index: int):
        return struct.unpack_from("<II", self.data, self.dd + index * 8)


def main():
    data = SRC.read_bytes()
    pe = PE(data)
    print(f"image size {len(data)}  imagebase 0x{pe.imagebase:x}  entry RVA 0x{pe.entry:x}")
    for name, va, vs, ra, rs in pe.sections:
        print(f"  {name:8} va=0x{va:06x} vs=0x{vs:06x} ra=0x{ra:06x} rs=0x{rs:06x}")

    print("\n--- directories ---")
    names = ["export", "import", "resource", "exception", "security", "reloc",
             "debug", "arch", "globalptr", "tls", "loadcfg", "bound", "iat", "delay", "clr"]
    for i, nm in enumerate(names):
        rva, size = pe.directory(i)
        if rva or size:
            print(f"  {nm:10} rva=0x{rva:06x} size=0x{size:x}")

    print("\n--- imports ---")
    rva, size = pe.directory(1)
    off = pe.rva2off(rva)
    if off:
        i = 0
        while True:
            ent = data[off + i * 20: off + i * 20 + 20]
            if len(ent) < 20 or ent == b"\0" * 20:
                break
            name_rva = struct.unpack_from("<I", ent, 12)[0]
            if name_rva:
                print("  ", pe.cstr(name_rva))
            i += 1

    print("\n--- strings ---")
    strings = []
    for m in re.finditer(rb"[\x20-\x7e]{5,}", data):
        s = m.group().decode("latin1")
        if not re.fullmatch(r"[0-9A-Fa-f]+", s):
            strings.append(s)
    print(f"  total {len(strings)}")
    for s in strings[:80]:
        print("   ", s)


if __name__ == "__main__":
    main()
