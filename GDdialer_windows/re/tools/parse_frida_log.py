"""Parse the Frida hook log into an ordered list of codec calls.

The hook captured the real runtime arguments of RC4 / XXTEA / hex inside
ESurfingSvr.exe. This extracts, for each call, the function, the key pointer,
the data pointer and the first bytes of both, so the exact layer order, the two
XXTEA keys and the RC4 key become explicit.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

LOG = Path("frida_watch_log.txt")


def parse_hexdump(lines, start):
    """Read a hexdump block, returning the bytes."""
    out = bytearray()
    i = start
    while i < len(lines):
        line = lines[i].rstrip("\n")
        m = re.match(r"^([0-9a-f]{8,})\s+((?:[0-9a-f]{2} ){1,16})", line)
        if not m:
            break
        out.extend(bytes.fromhex(m.group(2).replace(" ", "")))
        i += 1
    return bytes(out), i


def main():
    text = LOG.read_text(encoding="utf-8", errors="replace")
    lines = text.splitlines()

    calls = []
    i = 0
    while i < len(lines):
        line = lines[i]
        m = re.match(r"##### (RC4|XXTEA|HEX) 0x([0-9a-f]+) #####", line.strip())
        if not m:
            i += 1
            continue
        func = m.group(1)
        args = {}
        j = i + 1
        mem = {}
        while j < len(lines) and not lines[j].startswith("#####"):
            am = re.match(r"\s+arg(\d+) = (0x[0-9a-f]+)", lines[j])
            if am:
                args[int(am.group(1))] = am.group(2)
                j += 1
                continue
            mm = re.match(r"\s+-- mem arg(\d+) --", lines[j])
            if mm:
                idx = int(mm.group(1))
                data, j = parse_hexdump(lines, j + 1)
                mem[idx] = data
                continue
            nm = re.match(r"\s+n = (-?\d+)", lines[j])
            if nm:
                args["n"] = nm.group(1)
            j += 1
        calls.append((func, args, mem))
        i = j

    print(f"parsed {len(calls)} codec calls")
    from collections import Counter
    print(Counter(c[0] for c in calls))

    print("\nfirst 24 calls:")
    for func, args, mem in calls[:24]:
        key = args.get("0", "?")
        data = args.get("1", "?")
        extra = f" n={args.get('n')}" if "n" in args else ""
        head = mem.get(0, b"")[:16]
        dhead = mem.get(1, b"")[:16]
        print(f"  {func:6} key={key:>10} data={data:>10}{extra}")
        if head:
            print(f"         key bytes : {head.hex(' ')}  {head!r}")
        if dhead:
            print(f"         data bytes: {dhead.hex(' ')}")

    # distinct key pointers and their bytes
    print("\ndistinct arg0 pointers (keys):")
    seen = {}
    for func, args, mem in calls:
        p = args.get("0")
        if p and p not in seen and mem.get(0):
            seen[p] = (func, mem[0][:32])
    for p, (func, data) in sorted(seen.items()):
        print(f"  {p} ({func}): {data.hex(' ')}  {data!r}")


if __name__ == "__main__":
    sys.exit(main())
