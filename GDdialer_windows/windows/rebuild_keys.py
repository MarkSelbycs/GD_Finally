"""Rebuild every candidate key array (one per de-obfuscation pass) and test it.

The coder re-stores obfuscated key immediates and then XORs selected words with
per-mode constants. Each pass therefore yields a complete key array. This
replays the passes symbolically and tests each resulting key against the known
plaintext/ciphertext block pair of the captured portal body.
"""

from __future__ import annotations

import re
import struct
from pathlib import Path

from capstone import Cs, CS_ARCH_X86, CS_MODE_32

EXE = Path("../ESurfingSvr.exe")
IB = 0x400000
PLAIN_PREFIX = b'<?xml version="1.0" encoding="UTF-8"?><request><'
TARGET = bytes.fromhex("c853a9968496b3e0")
DELTA = 0x9E3779B9


def sections(data):
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    nsec = struct.unpack_from("<H", data, pe + 6)[0]
    optsize = struct.unpack_from("<H", data, pe + 20)[0]
    sec = pe + 24 + optsize
    out = []
    for i in range(nsec):
        o = sec + i * 40
        name = data[o:o + 8].rstrip(b"\0").decode("latin1")
        vs, va, rs, ra = struct.unpack_from("<IIII", data, o + 8)
        out.append((name, va, vs, ra, rs))
    return out


def xxtea_var(key, v0, v1, rounds=32):
    s = 0
    for _ in range(rounds):
        y = v1
        v0 = (v0 + ((((y << 4) & 0xFFFFFFFF) ^ (y >> 5)) + (y ^ s) + key[s & 3])) & 0xFFFFFFFF
        s = (s + DELTA) & 0xFFFFFFFF
        z = v0
        v1 = (v1 + ((((z << 4) & 0xFFFFFFFF) ^ (z >> 5)) + (z ^ s) + key[(s >> 11) & 3])) & 0xFFFFFFFF
    return v0, v1


def rc4(key, data):
    s = list(range(256))
    j = 0
    for i in range(256):
        j = (j + s[i] + key[i % len(key)]) & 0xFF
        s[i], s[j] = s[j], s[i]
    out = bytearray()
    i = j = 0
    for b in data:
        i = (i + 1) & 0xFF
        j = (j + s[i]) & 0xFF
        s[i], s[j] = s[j], s[i]
        out.append(b ^ s[(s[i] + s[j]) & 0xFF])
    return bytes(out)


def main():
    data = EXE.read_bytes()
    secs = sections(data)

    def va2f(v):
        for _n, va, vs, ra, rs in secs:
            if IB + va <= v < IB + va + max(vs, rs):
                return ra + (v - (IB + va))
        return None

    md = Cs(CS_ARCH_X86, CS_MODE_32)
    lo, hi = 0x4156b0, 0x416800
    insns = list(md.disasm(data[va2f(lo):va2f(hi)], lo))

    arr: dict[int, int] = {}
    idx = None
    passes = []
    for ins in insns:
        t = ins.op_str
        m = re.match(r"edx, ecx, (0x[0-9a-fA-F]+|\d+)$", t)
        if ins.mnemonic == "imul" and m:
            idx = int(m.group(1), 0)
            continue
        m = re.match(r"ecx, ecx, (0x[0-9a-fA-F]+|\d+)$", t)
        if ins.mnemonic == "shl" and m:
            idx = 1 << int(m.group(1), 0)
            continue
        m = re.match(r"dword ptr \[eax \+ [^\]]+\], (0x[0-9a-fA-F]+)$", t)
        if ins.mnemonic == "mov" and m:
            if idx is not None:
                arr[idx] = int(m.group(1), 16)
            continue
        m = re.match(r"ecx, (0x[0-9a-fA-F]+)$", t)
        if ins.mnemonic == "xor" and m:
            if idx is not None and idx in arr:
                arr[idx] ^= int(m.group(1), 16)
                passes.append((ins.address, idx, arr[idx], dict(arr)))
            continue

    print(f"de-obfuscation events: {len(passes)}")
    p = struct.unpack("<II", PLAIN_PREFIX[:8])
    t0, t1 = struct.unpack("<II", TARGET)

    tested = 0
    for addr, k, val, snapshot in passes:
        words = [snapshot.get(i, 0) for i in range(max(snapshot) + 1)]
        kb = b"".join(struct.pack("<I", w) for w in words)
        # candidate key material slices
        for start in (0, 4, 8, 16, 32):
            for nwords in (4, 8):
                chunk = words[start // 4:start // 4 + nwords]
                if len(chunk) < 4:
                    continue
                key = chunk[:4]
                tested += 1
                o0, o1 = xxtea_var(key, p[0], p[1])
                if struct.pack("<II", o0, o1) == TARGET:
                    print(f"  !!! XXTEA HIT @0x{addr:08x} idx={k} start={start} n={nwords} key={[hex(x) for x in key]}")
                out = rc4(kb[:16] or b"\0", PLAIN_PREFIX[:8])
                if out == TARGET:
                    print(f"  !!! RC4 HIT @0x{addr:08x} key={kb[:16].hex()}")

    print(f"tested {tested} key/scheme combinations")
    # 最后一批快照（ASCII 可读的那个）单独打印
    if passes:
        snapshot = passes[-1][3]
        words = [snapshot.get(i, 0) for i in range(max(snapshot) + 1)]
        kb = b"".join(struct.pack("<I", w) for w in words)
        print("\nlast pass key bytes:", kb.hex())
        print("as ascii:", "".join(chr(c) if 32 <= c < 127 else "." for c in kb))


if __name__ == "__main__":
    main()
