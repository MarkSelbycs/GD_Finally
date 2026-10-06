"""Locate MSVC RTTI vtables for coding-related classes in ESurfingSvr.exe."""

import struct
import sys
from pathlib import Path

from capstone import Cs, CS_ARCH_X86, CS_MODE_32


def load_pe(path: Path):
    b = path.read_bytes()
    pe = b.find(b"PE\x00\x00")
    coff = pe + 4
    nsec = struct.unpack_from("<H", b, coff + 2)[0]
    optsize = struct.unpack_from("<H", b, coff + 16)[0]
    opt = coff + 20
    imagebase = struct.unpack_from("<I", b, opt + 28)[0]
    sec_off = opt + optsize
    secs = []
    for i in range(nsec):
        o = sec_off + i * 40
        name = b[o:o + 8].rstrip(b"\0").decode("latin1")
        vsize, vaddr, rsize, raddr = struct.unpack_from("<IIII", b, o + 8)
        secs.append((name, vaddr, vsize, raddr, rsize))
    return b, imagebase, secs


def off2va(off, imagebase, secs):
    for name, vaddr, vsize, raddr, rsize in secs:
        if raddr <= off < raddr + max(rsize, 1):
            return imagebase + vaddr + (off - raddr)
    return None


def va2off(va, imagebase, secs):
    for name, vaddr, vsize, raddr, rsize in secs:
        base = imagebase + vaddr
        if base <= va < base + max(vsize, rsize):
            delta = va - base
            if delta < rsize:
                return raddr + delta
    return None


def main():
    path = Path(sys.argv[1] if len(sys.argv) > 1 else "ESurfingSvr.exe")
    b, imagebase, secs = load_pe(path)
    targets = [
        b".?AVCInnerCoder@ESurfingSvr@@",
        b".?AVCInnerMod@ESurfingSvr@@",
        b".?AVCInnerLzma@ESurfingSvr@@",
        b".?AVCZsmMod@ESurfingSvr@@",
        b".?AVCZxmMod@ESurfingSvr@@",
    ]
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    for name in targets:
        pos = b.find(name)
        if pos < 0:
            print("missing", name)
            continue
        td_va = off2va(pos - 8, imagebase, secs)  # TypeDescriptor starts 8 bytes before the name
        print(f"\n=== {name.decode()} TypeDescriptor name VA=0x{td_va:x}")
        # COL contains a pointer to the TypeDescriptor at +0xC
        needle = struct.pack("<I", td_va)
        col_hits = []
        start = 0
        while True:
            i = b.find(needle, start)
            if i < 0:
                break
            col_hits.append(i)
            start = i + 1
        for i in col_hits:
            col_va = off2va(i - 0xC, imagebase, secs)
            if col_va is None:
                continue
            # sanity: signature should be 0
            sig = struct.unpack_from("<I", b, i - 0xC)[0]
            if sig not in (0, 1):
                continue
            print(f"  COL candidate VA=0x{col_va:x} file={hex(i - 0xC)}")
            vt_needle = struct.pack("<I", col_va)
            s2 = 0
            while True:
                j = b.find(vt_needle, s2)
                if j < 0:
                    break
                s2 = j + 1
                vt_va = off2va(j + 4, imagebase, secs)
                print(f"    vtable VA=0x{vt_va:x} file={hex(j + 4)}")
                for k in range(8):
                    fo = j + 4 + k * 4
                    fn_va = struct.unpack_from("<I", b, fo)[0]
                    fn_off = va2off(fn_va, imagebase, secs)
                    print(f"      [{k}] 0x{fn_va:08x} file={hex(fn_off) if fn_off else None}")


if __name__ == "__main__":
    main()
