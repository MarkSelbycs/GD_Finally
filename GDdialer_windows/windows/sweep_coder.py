"""Systematic sweep of the built-in CInnerCoder against the known plaintext block.

Findings so far:
  * portal bodies are a deterministic, position-independent 8-byte block transform
  * the module downloaded at dial time is not loaded as a PE, so the service most
    likely encodes with its built-in CInnerCoder using the container key
This tries that hypothesis across byte orders, round counts and layer orders.
"""

from __future__ import annotations

import itertools
import struct
from pathlib import Path

PLAIN = b'<?xml version="1.0" encoding="UTF-8"?><request><'
TARGET = bytes.fromhex("c853a9968496b3e0")
DELTA = 0x9E3779B9


def rc4(key: bytes, data: bytes) -> bytes:
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


def xxtea_var(key, v0, v1, rounds, shift_a=4, shift_b=5, delta=DELTA):
    """CInnerCoder 2-word XXTEA variant, parameterised."""
    s = 0
    limit = (delta * rounds) & 0xFFFFFFFF
    while s != limit:
        s = (s + delta) & 0xFFFFFFFF
        y = v1
        mx = (((y << shift_a) & 0xFFFFFFFF) ^ (y >> shift_b)) + (y ^ s) + key[(s >> 2) & 3]
        v0 = (v0 + mx) & 0xFFFFFFFF
        z = v0
        mx = (((z << shift_a) & 0xFFFFFFFF) ^ (z >> shift_b)) + (z ^ s) + key[(s >> 2) & 3]
        v1 = (v1 + mx) & 0xFFFFFFFF
    return v0, v1


def xxtea_additive(key, v0, v1, rounds=32):
    """Additive-key variant: k[sum & 3] / k[(sum >> 11) & 3]."""
    s = 0
    for _ in range(rounds):
        y = v1
        mx = (((y << 4) & 0xFFFFFFFF) ^ (y >> 5)) + (y ^ s) + key[s & 3]
        v0 = (v0 + mx) & 0xFFFFFFFF
        s = (s + DELTA) & 0xFFFFFFFF
        z = v0
        mx = (((z << 4) & 0xFFFFFFFF) ^ (z >> 5)) + (z ^ s) + key[(s >> 11) & 3]
        v1 = (v1 + mx) & 0xFFFFFFFF
    return v0, v1


def keys_from(material: bytes):
    """Candidate 4-word keys from key material."""
    out = {}
    if len(material) >= 16:
        out["le0"] = list(struct.unpack("<4I", material[:16]))
        out["be0"] = list(struct.unpack(">4I", material[:16]))
        out["rev"] = list(struct.unpack("<4I", material[:16]))[::-1]
    if len(material) >= 32:
        out["le16"] = list(struct.unpack("<4I", material[16:32]))
    return out


def main():
    blob = Path("captured/module_fetch.bin").read_bytes()
    key_hex = blob[blob.find(b"@") + 1:blob.find(b"$")]
    key_raw = bytes.fromhex(key_hex.decode())
    print("container key:", key_hex.decode())

    materials = {
        "raw32": key_raw,
        "hexascii": key_hex,
        "md5raw": __import__("hashlib").md5(key_raw).digest(),
    }
    p0, p1 = struct.unpack("<II", PLAIN[:8])
    p0b, p1b = struct.unpack(">II", PLAIN[:8])
    t0, t1 = struct.unpack("<II", TARGET)
    t0b, t1b = struct.unpack(">II", TARGET)

    hits = []
    for mname, material in materials.items():
        for kname, key in keys_from(material).items():
            for rname, fn in (("additive", xxtea_additive),
                              ("var32", lambda k, a, b: xxtea_var(k, a, b, 32)),
                              ("var16", lambda k, a, b: xxtea_var(k, a, b, 16)),
                              ("var64", lambda k, a, b: xxtea_var(k, a, b, 64))):
                for iname, (a0, b0) in (("le", (p0, p1)), ("be", (p0b, p1b))):
                    for rev in (False, True):
                        k = key[::-1] if rev else key
                        try:
                            o0, o1 = fn(k, a0, b0)
                        except Exception:
                            continue
                        got = struct.pack("<II", o0, o1)
                        got_be = struct.pack(">II", o0, o1)
                        if got == TARGET or got_be == TARGET:
                            hits.append((mname, kname, rname, iname, rev, got.hex()))
                            print("  !!! HIT", mname, kname, rname, iname, rev, got.hex())
    print("xxtea sweep hits:", len(hits))

    # RC4 / layer orders
    for mname, material in materials.items():
        for kname, key in (("full", material), ("first16", material[:16]), ("last16", material[-16:])):
            for label, out in (
                ("rc4", rc4(key, PLAIN[:8])),
                ("xxteaThenRc4", rc4(key, struct.pack("<II", *xxtea_additive(list(struct.unpack("<4I", material[:16])), p0, p1)))),
            ):
                if out == TARGET:
                    print("  !!! HIT", mname, kname, label, out.hex())
    print("done")


if __name__ == "__main__":
    main()
