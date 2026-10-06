"""Analyse a memory-dumped module: locate RTTI vtables (RVA == file offset)."""

from __future__ import annotations

import struct
import sys
from pathlib import Path

from capstone import Cs, CS_ARCH_X86, CS_MODE_32


def load(path: Path):
    b = path.read_bytes()
    pe = struct.unpack_from("<I", b, 0x3C)[0]
    nsec = struct.unpack_from("<H", b, pe + 6)[0]
    optsize = struct.unpack_from("<H", b, pe + 20)[0]
    opt = pe + 24
    imagebase = struct.unpack_from("<I", b, opt + 28)[0]
    return b, imagebase, nsec


def find_rtti(b: bytes, imagebase: int, class_name: bytes):
    """RVA == file offset for a memory dump."""
    pos = b.find(class_name)
    if pos < 0:
        return None
    td_va = imagebase + (pos - 8)
    needle = struct.pack("<I", td_va)
    results = []
    start = 0
    while True:
        i = b.find(needle, start)
        if i < 0:
            break
        start = i + 1
        sig = struct.unpack_from("<I", b, i - 0xC)[0]
        if sig != 0:
            continue
        col_va = imagebase + (i - 0xC)
        vt_needle = struct.pack("<I", col_va)
        s2 = 0
        while True:
            j = b.find(vt_needle, s2)
            if j < 0:
                break
            s2 = j + 1
            vt_off = j + 4
            results.append((col_va, imagebase + vt_off, vt_off))
    return results


def main():
    path = Path(sys.argv[1])
    args = sys.argv[2:]
    load_base = None
    if args and args[0].startswith("0x"):
        load_base = int(args[0], 16)
        args = args[1:]
    names = [a.encode() for a in args] or [b".?AVAutoZSM@ESurfingSvr@@"]
    b, imagebase, nsec = load(path)
    if load_base is None:
        load_base = imagebase
    print(f"{path.name}: header_imagebase=0x{imagebase:x} load_base=0x{load_base:x} dump={len(b)} bytes")
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    for name in names:
        print(f"\n=== {name.decode()} ===")
        hits = find_rtti(b, load_base, name)
        if not hits:
            print("  no vtable found")
            continue
        for col_va, vt_va, vt_off in hits:
            print(f"  COL=0x{col_va:x} vtable=0x{vt_va:x} (file 0x{vt_off:x})")
            for k in range(10):
                fn = struct.unpack_from("<I", b, vt_off + k * 4)[0]
                if fn == 0:
                    break
                fo = fn - load_base
                print(f"    [{k}] VA=0x{fn:08x} file=0x{fo:x}")
                if 0 <= fo < len(b) - 8:
                    for ins in md.disasm(b[fo:fo + 32], fn):
                        print(f"         {ins.address:08x}  {ins.mnemonic:7} {ins.op_str}")
                    print("         ...")


if __name__ == "__main__":
    main()
