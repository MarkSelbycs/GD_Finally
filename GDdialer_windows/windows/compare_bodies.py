"""Compare two captured portal bodies to determine the cipher mode.

If the cipher is a fixed-keystream stream cipher, XOR of two ciphertexts equals
XOR of the two plaintexts, so the difference is confined to the bytes where the
plaintexts differ (e.g. the local-time digits). For a block cipher in CBC the
difference starts at a block boundary and smears across the following block.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path


def load_hex(path: Path) -> bytes:
    raw = path.read_bytes()
    if raw.lstrip()[:1] == b"d":  # chunked response
        raw = re.sub(rb"^[0-9a-fA-F]+\r\n", b"", raw)
        raw = raw.split(b"\r\n0\r\n")[0]
    text = raw.strip()
    return bytes.fromhex(text.decode("ascii"))


def main():
    args = sys.argv[1:]
    if len(args) < 2:
        print("usage: compare_bodies.py body1.bin body2.bin [body3.bin ...]")
        return 2
    bodies = [load_hex(Path(a)) for a in args]
    for i, b in enumerate(bodies):
        print(f"[{i}] {args[i]}  len={len(b)}  head={b[:32].hex()}")
    base = bodies[0]
    for i, other in enumerate(bodies[1:], start=1):
        n = min(len(base), len(other))
        diff = [k for k in range(n) if base[k] != other[k]]
        print(f"\n--- [0] vs [{i}] : common={n} differing={len(diff)} ---")
        if diff:
            print(f"    first diff at {diff[0]}, last at {diff[-1]}")
            runs = []
            start = prev = diff[0]
            for k in diff[1:]:
                if k == prev + 1:
                    prev = k
                else:
                    runs.append((start, prev))
                    start = prev = k
            runs.append((start, prev))
            print(f"    diff runs: {runs[:12]}")
            if len(base) == len(other):
                x = bytes(a ^ b for a, b in zip(base, other))
                print(f"    xor nonzero bytes: {sum(1 for c in x if c)}")
                print(f"    xor[0:64] = {x[:64].hex()}")
        same_prefix = 0
        while same_prefix < n and base[same_prefix] == other[same_prefix]:
            same_prefix += 1
        print(f"    identical leading bytes = {same_prefix}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
