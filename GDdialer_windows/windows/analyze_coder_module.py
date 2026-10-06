"""Analyse the memory-loaded codec module (region_02410000_11000.bin).

This rwx region starts with an MZ header and contains the string "Code", so it is
the PE image that actually assembles and encodes portal bodies. It is loaded in
memory, so section RVAs map directly to offsets within the dump.
"""

from __future__ import annotations

import re
import struct
from pathlib import Path

SRC = Path("captured/coder_region/region_02410000_11000.bin")


def main():
    data = SRC.read_bytes()
    print("size", len(data))
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    print("e_lfanew", hex(pe), "sig", data[pe:pe + 4])
    nsec = struct.unpack_from("<H", data, pe + 6)[0]
    optsize = struct.unpack_from("<H", data, pe + 20)[0]
    opt = pe + 24
    magic = struct.unpack_from("<H", data, opt)[0]
    entry = struct.unpack_from("<I", data, opt + 16)[0]
    ib = struct.unpack_from("<I", data, opt + 28)[0]
    sizeimg = struct.unpack_from("<I", data, opt + 56)[0]
    print(f"machine={struct.unpack_from('<H',data,pe+4)[0]:#x} optmagic={magic:#x} entry=0x{entry:x} imagebase=0x{ib:x} sizeimage=0x{sizeimg:x}")
    sec = opt + optsize
    for i in range(nsec):
        o = sec + i * 40
        name = data[o:o + 8].rstrip(b"\0").decode("latin1")
        vs, va, rs, ra = struct.unpack_from("<IIII", data, o + 8)
        print(f"  {name:8} va=0x{va:06x} vs=0x{vs:06x} ra=0x{ra:06x} rs=0x{rs:06x}")

    # 导出表
    exp_rva, exp_size = struct.unpack_from("<II", data, opt + 96)
    print("export rva", hex(exp_rva), "size", exp_size)
    if exp_size:
        o = exp_rva
        try:
            nr = struct.unpack_from("<I", data, o + 12)[0]
            dll = data[nr:data.find(b"\0", nr)].decode("latin1")
            nfunc, nname = struct.unpack_from("<II", data, o + 20)
            af, an, ao = struct.unpack_from("<III", data, o + 28)
            print(f"  dll={dll} nfunc={nfunc} nnames={nname}")
            for i in range(min(nname, 60)):
                r = struct.unpack_from("<I", data, an + i * 4)[0]
                fn = data[r:data.find(b"\0", r)].decode("latin1")
                idx = struct.unpack_from("<H", data, ao + i * 2)[0]
                frva = struct.unpack_from("<I", data, af + idx * 4)[0]
                print(f"    {fn:24} rva=0x{frva:x}")
        except Exception as e:
            print("  export parse err", e)

    # 字符串
    print("\nstrings (meaningful):")
    seen = set()
    for m in re.finditer(rb"[\x20-\x7e]{5,}", data):
        s = m.group().decode("latin1")
        if s not in seen and sum(1 for c in s if c.isalpha()) >= 3:
            seen.add(s)
            print(f"  0x{m.start():05x}  {s}")


if __name__ == "__main__":
    main()
