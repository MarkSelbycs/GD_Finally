"""Parse a pktmon pcapng capture and show portal HTTP requests on port 7001.

Usage:
    python parse_capture.py capture.pcapng

Only local debugging of this project's own client traffic. Credentials and
tickets are masked in the output; request/response bodies are shown as length,
MD5 and a short hex prefix so they can be compared with a local encoder.
"""

from __future__ import annotations

import hashlib
import struct
import sys
from pathlib import Path


def iter_blocks(data: bytes):
    offset = 0
    endian = "<"
    while offset + 12 <= len(data):
        block_type = struct.unpack_from(endian + "I", data, offset)[0]
        if block_type == 0x0A0D0D0A:
            byte_order = struct.unpack_from("<I", data, offset + 8)[0]
            endian = "<" if byte_order == 0x1A2B3C4D else ">"
            block_type = 0x0A0D0D0A
        length = struct.unpack_from(endian + "I", data, offset + 4)[0]
        if length < 12 or offset + length > len(data):
            break
        yield block_type, data[offset:offset + length], endian
        offset += length


def parse_pcapng(path: Path):
    packets = []
    data = path.read_bytes()
    for block_type, body, endian in iter_blocks(data):
        if block_type != 0x00000006:
            continue
        caplen = struct.unpack_from(endian + "I", body, 20)[0]
        frame = body[28:28 + caplen]
        packets.append(frame)
    return packets


def find_ipv4(frame: bytes):
    """Locate an IPv4 header inside a captured frame.

    pktmon frames may carry metadata and LLC/SNAP headers before the IP
    header, so scan for a plausible IPv4 header instead of a fixed offset.
    """
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
        if frame[offset + 9] != 6:
            continue
        return offset, ihl, total
    return None


def tcp_payload(frame: bytes):
    located = find_ipv4(frame)
    if not located:
        return None
    offset, ihl, total = located
    src = ".".join(str(b) for b in frame[offset + 12:offset + 16])
    dst = ".".join(str(b) for b in frame[offset + 16:offset + 20])
    tcp = offset + ihl
    if len(frame) < tcp + 20:
        return None
    sport, dport = struct.unpack_from(">HH", frame, tcp)
    data_offset = (frame[tcp + 12] >> 4) * 4
    if data_offset < 20:
        return None
    payload = frame[tcp + data_offset:offset + total]
    return src, dst, sport, dport, payload


MASK = ("authorization", "cookie", "password", "passwd", "ticket")


def mask_header(line: str) -> str:
    lowered = line.lower()
    for key in MASK:
        if lowered.startswith(key):
            return line.split(":", 1)[0] + ": <masked>"
    return line


def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__)
        return 2
    out_dir = Path(sys.argv[1]).with_suffix("").parent / "captured"
    out_dir.mkdir(exist_ok=True)
    packets = parse_pcapng(Path(sys.argv[1]))
    streams: dict[tuple, bytearray] = {}
    order: list[tuple] = []
    for frame in packets:
        parsed = tcp_payload(frame)
        if not parsed:
            continue
        src, dst, sport, dport, payload = parsed
        if 7001 not in (sport, dport) or not payload:
            continue
        key = (src, sport, dst, dport)
        if key not in streams:
            streams[key] = bytearray()
            order.append(key)
        streams[key].extend(payload)
    for key in order:
        blob = bytes(streams[key])
        if b"POST " not in blob and b"HTTP/1." not in blob[:16]:
            continue
        head, _, body = blob.partition(b"\r\n\r\n")
        lines = head.split(b"\r\n")
        print("=" * 70)
        print(f"{key[0]}:{key[1]} -> {key[2]}:{key[3]}")
        try:
            print(mask_header(lines[0].decode("latin1")))
            for line in lines[1:]:
                print(mask_header(line.decode("latin1")))
        except Exception:
            print(head[:200])
        if body:
            preview = body[:48].hex()
            print(f"BODY len={len(body)} md5={hashlib.md5(body).hexdigest()}")
            print(f"BODY hex[:48]={preview}")
            direction = "req" if key[1] != 7001 else "resp"
            target = out_dir / f"{direction}_{key[2].replace('.', '_')}_{key[3]}_{len(body)}.bin"
            target.write_bytes(body)
            print(f"BODY saved={target.name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
