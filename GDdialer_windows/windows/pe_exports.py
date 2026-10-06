"""List exported names of a PE file."""

import struct
import sys
from pathlib import Path


def main():
    p = Path(sys.argv[1])
    b = p.read_bytes()
    pe = b.find(b"PE\x00\x00")
    coff = pe + 4
    nsec = struct.unpack_from("<H", b, coff + 2)[0]
    optsize = struct.unpack_from("<H", b, coff + 16)[0]
    opt = coff + 20
    magic = struct.unpack_from("<H", b, opt)[0]
    imagebase = struct.unpack_from("<I", b, opt + 28)[0]
    # data directory 0 = export
    dd = opt + (96 if magic == 0x10B else 112)
    exp_rva, exp_size = struct.unpack_from("<II", b, dd)
    sec_off = opt + optsize
    secs = []
    for i in range(nsec):
        o = sec_off + i * 40
        name = b[o:o + 8].rstrip(b"\0").decode("latin1")
        vsize, vaddr, rsize, raddr = struct.unpack_from("<IIII", b, o + 8)
        secs.append((name, vaddr, vsize, raddr, rsize))

    def rva2off(rva):
        for name, vaddr, vsize, rsize_, raddr in ((n, v, vs, rs, ra) for n, v, vs, ra, rs in secs):
            if vaddr <= rva < vaddr + max(vsize, rsize_):
                return raddr + (rva - vaddr)
        return None

    print(f"{p.name}: imagebase=0x{imagebase:x} export_rva=0x{exp_rva:x} size={exp_size}")
    if not exp_rva:
        print("no exports")
        return 0
    off = rva2off(exp_rva)
    nfunc, nname = struct.unpack_from("<II", b, off + 20)
    addr_names, addr_funcs = struct.unpack_from("<II", b, off + 32)
    no = rva2off(addr_names)
    of = rva2off(addr_funcs)
    print(f"functions={nfunc} names={nname}")
    for i in range(nname):
        nrva = struct.unpack_from("<I", b, no + i * 4)[0]
        so = rva2off(nrva)
        nm = b[so:b.find(b"\0", so)].decode("latin1")
        frva = struct.unpack_from("<I", b, of + struct.unpack_from("<H", b, rva2off(addr_names + 0) + 0)[0] * 0)[0] if False else None
        print(f"  [{i}] {nm}  rva=0x{struct.unpack_from('<I', b, of + i * 4)[0]:x}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
