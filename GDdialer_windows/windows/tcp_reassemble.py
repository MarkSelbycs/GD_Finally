"""Reassemble TCP streams from a pktmon pcapng and extract port-7001 HTTP bodies.

Each POST/GET body is recovered from the full stream (not just the first
segment), so portal bodies that span segments are visible in full.
"""

from __future__ import annotations

import struct
import sys
from pathlib import Path


def iter_blocks(data):
    off = 0
    endian = "<"
    while off + 12 <= len(data):
        bt = struct.unpack_from(endian + "I", data, off)[0]
        if bt == 0x0A0D0D0A:
            bo = struct.unpack_from("<I", data, off + 8)[0]
            endian = "<" if bo == 0x1A2B3C4D else ">"
        ln = struct.unpack_from(endian + "I", data, off + 4)[0]
        if ln < 12 or off + ln > len(data):
            break
        yield bt, data[off:off + ln], endian
        off += ln


def packets(path):
    for bt, body, endian in iter_blocks(Path(path).read_bytes()):
        if bt != 6:
            continue
        caplen = struct.unpack_from(endian + "I", body, 20)[0]
        yield body[28:28 + caplen]


def find_ipv4(f):
    for o in range(min(len(f) - 20, 64) + 1):
        if f[o] >> 4 != 4:
            continue
        ihl = (f[o] & 0x0F) * 4
        if ihl < 20 or o + ihl > len(f):
            continue
        total = struct.unpack_from(">H", f, o + 2)[0]
        if total < ihl or o + total > len(f):
            continue
        return o, ihl, total
    return None


def main():
    path = Path(sys.argv[1] if len(sys.argv) > 1 else "cap.pcapng")
    streams: dict[tuple, list[tuple[int, bytes]]] = {}
    for f in packets(str(path)):
        ip = find_ipv4(f)
        if not ip:
            continue
        o, ihl, total = ip
        if f[o + 9] != 6:
            continue
        src = f[o + 12:o + 16]
        dst = f[o + 16:o + 20]
        tcp = o + ihl
        doff = (f[tcp + 12] >> 4) * 4
        sport, dport = struct.unpack_from(">HH", f, tcp)
        seq = struct.unpack_from(">I", f, tcp + 4)[0]
        payload = f[tcp + doff:o + total]
        if not payload:
            continue
        streams.setdefault((src, sport, dst, dport), []).append((seq, payload))

    seen = set()
    out = []
    for key, segs in streams.items():
        segs.sort(key=lambda x: x[0])
        data = b"".join(s[1] for s in segs)
        pos = 0
        while True:
            i = data.find(b"POST ", pos)
            j = data.find(b"GET ", pos)
            if i < 0 and j < 0:
                break
            start = min(x for x in (i, j) if x >= 0)
            he = data.find(b"\r\n\r\n", start)
            if he < 0:
                break
            head = data[start:he].decode("latin1", "replace")
            line = head.split("\r\n")[0]
            # Content-Length
            clen = 0
            for h in head.split("\r\n"):
                if h.lower().startswith("content-length:"):
                    try:
                        clen = int(h.split(":", 1)[1].strip())
                    except ValueError:
                        pass
            body = data[he + 4:he + 4 + clen] if clen else b""
            pos = he + 4 + clen
            sig = body[:24]
            if len(body) > 60 and sig in seen:
                continue
            seen.add(sig)
            out.append((line, len(body), body))
    print(f"reassembled request bodies: {len(out)}")
    for line, n, body in out:
        try:
            t = body.decode("ascii")
            hexlike = all(c in "0123456789abcdefABCDEF" for c in t.strip()) and len(t) > 60
        except UnicodeDecodeError:
            t, hexlike = "", False
        if hexlike:
            print(f"  {line[:58]:58} len={n} head={t[:64]}")
    # 保存所有 hex body
    Path("cap_bodies.txt").write_text(
        "\n".join(f"{line}\t{body.decode('ascii', 'replace')}" for line, n, body in out
                  if n > 60 and all(c in "0123456789abcdefABCDEF"
                                    for c in body.decode("ascii", "replace").strip())),
        encoding="utf-8")
    print("saved cap_bodies.txt")


if __name__ == "__main__":
    main()
