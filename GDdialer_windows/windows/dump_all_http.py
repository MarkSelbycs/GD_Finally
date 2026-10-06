"""Dump all HTTP bodies and DNS queries from a pktmon pcapng capture.

Unlike parse_capture.py this does not assume a port, so it also catches traffic
that could carry a downloaded algorithm module (the service logs
"update algoid success" when it dials).
"""

from __future__ import annotations

import argparse
import hashlib
import struct
from pathlib import Path


def iter_blocks(data: bytes):
    offset = 0
    endian = "<"
    while offset + 12 <= len(data):
        btype = struct.unpack_from(endian + "I", data, offset)[0]
        if btype == 0x0A0D0D0A:
            byte_order = struct.unpack_from("<I", data, offset + 8)[0]
            endian = "<" if byte_order == 0x1A2B3C4D else ">"
        length = struct.unpack_from(endian + "I", data, offset + 4)[0]
        if length < 12 or offset + length > len(data):
            break
        yield btype, data[offset:offset + length], endian
        offset += length


def packets(path: Path):
    data = path.read_bytes()
    for btype, body, endian in iter_blocks(data):
        if btype != 0x00000006:
            continue
        caplen = struct.unpack_from(endian + "I", body, 20)[0]
        yield body[28:28 + caplen]


def find_ipv4(frame: bytes):
    limit = min(len(frame) - 20, 64)
    for offset in range(max(limit, 0) + 1):
        if frame[offset] >> 4 != 4:
            continue
        ihl = (frame[offset] & 0x0F) * 4
        if ihl < 20 or offset + ihl > len(frame):
            continue
        total = struct.unpack_from(">H", frame, offset + 2)[0]
        if total < ihl or offset + total > len(frame):
            continue
        return offset, ihl, total, frame[offset + 9]
    return None


def parse_dns(payload: bytes) -> str:
    if len(payload) < 12:
        return ""
    labels = []
    pos = 12
    while pos < len(payload) and payload[pos]:
        length = payload[pos]
        labels.append(payload[pos + 1:pos + 1 + length].decode("latin1", "replace"))
        pos += 1 + length
        if len(labels) > 8:
            break
    return ".".join(labels)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("pcapng")
    ap.add_argument("--out", default="all_http")
    ap.add_argument("--min-bin", type=int, default=256, help="flag non-text bodies at least this big")
    args = ap.parse_args()

    out_dir = Path(args.out)
    out_dir.mkdir(exist_ok=True)

    streams: dict[tuple, bytearray] = {}
    order: list[tuple] = []
    dns_names: set[str] = set()

    for frame in packets(Path(args.pcapng)):
        located = find_ipv4(frame)
        if not located:
            continue
        offset, ihl, total, proto = located
        src = ".".join(str(b) for b in frame[offset + 12:offset + 16])
        dst = ".".join(str(b) for b in frame[offset + 16:offset + 20])
        l4 = offset + ihl
        if proto == 17:
            sport, dport = struct.unpack_from(">HH", frame, l4)
            if 53 in (sport, dport):
                name = parse_dns(frame[l4 + 8:offset + total])
                if name:
                    dns_names.add(name)
            continue
        if proto != 6:
            continue
        sport, dport = struct.unpack_from(">HH", frame, l4)
        data_off = (frame[l4 + 12] >> 4) * 4
        payload = frame[l4 + data_off:offset + total]
        if not payload:
            continue
        key = (src, sport, dst, dport)
        if key not in streams:
            streams[key] = bytearray()
            order.append(key)
        streams[key].extend(payload)
        if len(streams[key]) > 8_000_000:
            streams[key] = streams[key][-4_000_000:]

    print("=== DNS names ===")
    for name in sorted(dns_names):
        print("  ", name)

    print("\n=== HTTP messages ===")
    for key in order:
        blob = bytes(streams[key])
        if b"HTTP/1." not in blob[:256]:
            continue
        head, _, body = blob.partition(b"\r\n\r\n")
        first = head.split(b"\r\n", 1)[0].decode("latin1", "replace")
        direction = "req" if first.startswith(("GET", "POST", "HEAD", "PUT")) else "resp"
        if not body:
            continue
        printable = sum(1 for c in body[:512] if 32 <= c < 127 or c in (9, 10, 13))
        ratio = printable / max(min(len(body), 512), 1)
        interesting = ratio < 0.9 and len(body) >= args.min_bin
        tag = "  <<< BINARY/LARGE" if interesting else ""
        print(f"\n{key[0]}:{key[1]} -> {key[2]}:{key[3]}  [{direction}] {first}")
        print(f"   body len={len(body)} printable={ratio:.2f} md5={hashlib.md5(body).hexdigest()}{tag}")
        name = out_dir / f"{direction}_{key[2].replace('.', '_')}_{key[3]}_{len(body)}.bin"
        name.write_bytes(body)
        if interesting:
            print(f"   saved -> {name.name}")

    # hex-looking ASCII bodies are also candidates for encoded payloads
    print("\n=== ASCII-hex bodies (likely encoded portal bodies) ===")
    import re
    for key in order:
        blob = bytes(streams[key])
        head, _, body = blob.partition(b"\r\n\r\n")
        text = body.strip()
        if len(text) >= 64 and re.fullmatch(rb"[0-9A-Fa-f]+", text):
            print(f"  {key[0]}:{key[1]} -> {key[2]}:{key[3]} hex_len={len(text)} (binary {len(text)//2})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
