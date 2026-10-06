"""Detect the cipher mode from repeated 8-byte blocks across captured bodies.

ECB with a fixed key maps equal plaintext blocks to equal ciphertext blocks, so
shared plaintext fragments (the fixed XML prefix, common tags, identical
padding) show up as repeated ciphertext blocks at any offset. CBC with a fixed
IV only keeps them aligned and prefix-contiguous.
"""

from __future__ import annotations

from collections import Counter
from pathlib import Path

FILES = {
    "ticket": "captured/req_14_146_227_141_7001_752.bin",
    "keep": "captured/req_14_146_227_142_7001_784.bin",
    "auth": "captured/req_14_146_227_141_7001_608.bin",
    "state": "captured/req_14_146_227_141_7001_496.bin",
    "term": "captured/req_14_146_227_141_7001_544.bin",
}


def blocks(data: bytes, size: int = 8):
    for off in range(0, len(data) - size + 1, size):
        yield off, data[off:off + size]


def main():
    bodies = {k: bytes.fromhex(Path(v).read_bytes().strip().decode()) for k, v in FILES.items()}
    for k, v in bodies.items():
        print(f"{k:7} len={len(v)} blocks={len(v)//8} tail_block={v[-8:].hex()}")

    print("\n--- tail block equality (identical padding under ECB would match) ---")
    tails = {k: v[-8:] for k, v in bodies.items()}
    counts = Counter(tails.values())
    for k, t in tails.items():
        print(f"  {k:7} {t.hex()}  occurrences={counts[t]}")

    print("\n--- shared 8-byte blocks across messages ---")
    table = {k: Counter(b for _, b in blocks(v)) for k, v in bodies.items()}
    names = list(bodies)
    for i in range(len(names)):
        for j in range(i + 1, len(names)):
            a, b = names[i], names[j]
            common = set(table[a]) & set(table[b])
            total = sum(min(table[a][x], table[b][x]) for x in common)
            print(f"  {a:7} vs {b:7}: shared distinct blocks={len(common):3} total_pairs={total}")
            for x in list(common)[:4]:
                print(f"        {x.hex()}  ({table[a][x]}x vs {table[b][x]}x)")

    print("\n--- block positions of the common 48-byte prefix ---")
    base = bodies["ticket"]
    for k, v in bodies.items():
        same = 0
        while same < min(len(base), len(v)) and base[same] == v[same]:
            same += 1
        print(f"  {k:7} identical prefix bytes={same} (blocks={same//8}, remainder={same%8})")


if __name__ == "__main__":
    main()
