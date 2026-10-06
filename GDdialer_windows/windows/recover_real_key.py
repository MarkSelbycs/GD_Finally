"""Recover the real coder key from the XOR-obfuscated immediates.

The coder builds its key array in a buffer and stores each word obfuscated:

    call edx                     ; get key buffer
    imul edx, ecx, 0x14          ; word index 20
    mov  ecx, [eax]
    xor  ecx, 0xdd6fe84a         ; <-- per-index de-obfuscation constant
    mov  [edx], ecx

so the real key word is (stored immediate) XOR (per-index constant). Earlier
reconstructions used the stored immediates directly, which is why every
decryption attempt failed.
"""

from __future__ import annotations

import re
import struct
from pathlib import Path

from capstone import Cs, CS_ARCH_X86, CS_MODE_32

EXE = Path("../ESurfingSvr.exe")
IB = 0x400000


def sections(data: bytes):
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    nsec = struct.unpack_from("<H", data, pe + 6)[0]
    optsize = struct.unpack_from("<H", data, pe + 20)[0]
    opt = pe + 24
    sec = opt + optsize
    out = []
    for i in range(nsec):
        o = sec + i * 40
        name = data[o:o + 8].rstrip(b"\0").decode("latin1")
        vs, va, rs, ra = struct.unpack_from("<IIII", data, o + 8)
        out.append((name, va, vs, ra, rs))
    return out


def main():
    data = EXE.read_bytes()
    secs = sections(data)

    def va2f(v):
        for _n, va, vs, ra, rs in secs:
            if IB + va <= v < IB + va + max(vs, rs):
                return ra + (v - (IB + va))
        return None

    md = Cs(CS_ARCH_X86, CS_MODE_32)
    lo, hi = 0x4156b0, 0x416500
    insns = list(md.disasm(data[va2f(lo):va2f(hi)], lo))

    store = {}
    xors = []
    idx = None
    for ins in insns:
        t = ins.op_str
        # mov ecx, 4 / imul edx, ecx, K  -> index K
        m = re.match(r"edx, ecx, (0x[0-9a-f]+|\d+)$", t)
        if ins.mnemonic == "imul" and m:
            idx = int(m.group(1), 0)
            continue
        m = re.match(r"ecx, ecx, (0x[0-9a-f]+|\d+)$", t)
        if ins.mnemonic == "shl" and m:
            idx = 1 << int(m.group(1), 0)
            continue
        # mov dword ptr [eax + ...], IMM  -> obfuscated stored word
        m = re.match(r"dword ptr \[eax \+ [^\]]+\], (0x[0-9a-f]+)$", t)
        if ins.mnemonic == "mov" and m:
            store[idx] = int(m.group(1), 16)
            continue
        # xor ecx, IMM  -> de-obfuscation constant
        m = re.match(r"ecx, (0x[0-9a-f]+)$", t)
        if ins.mnemonic == "xor" and m:
            xors.append((ins.address, idx, int(m.group(1), 16)))

    print("stores: index -> obfuscated word")
    for k in sorted(k for k in store if k is not None):
        print(f"  word[{k:2}] = 0x{store[k]:08x}")
    print(f"\nxor sites: {len(xors)}")
    seen = {}
    for addr, k, c in xors:
        if k is None:
            continue
        seen.setdefault(k, []).append((addr, c))
    for k in sorted(seen):
        for addr, c in seen[k]:
            real = (store.get(k, 0) ^ c) & 0xFFFFFFFF
            print(f"  word[{k:2}] ^= 0x{c:08x}   @0x{addr:08x}   stored={store.get(k) and hex(store[k])}  real=0x{real:08x}")
    print("\nreal key words (stored ^ const):")
    out = []
    for k in sorted(seen):
        addr, c = seen[k][0]
        if k in store:
            real = (store[k] ^ c) & 0xFFFFFFFF
            out.append((k, real))
    for k, v in out:
        print(f"  k[{k:2}] = 0x{v:08x}  ({struct.pack('<I', v)!r})")


if __name__ == "__main__":
    main()
