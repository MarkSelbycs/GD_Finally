"""Locate the freshly downloaded algorithm module inside ESurfingSvr.exe.

The portal served a container
    001@<32-byte key hex>$<Algo-ID>]<payload>
during the dial, and the service logs "update algoid success". The decrypted
module must therefore live in the process. This searches for the new Algo-ID and
the key string, then dumps the surrounding region.
"""

from __future__ import annotations

import ctypes
import re
import struct
import subprocess
import sys
from ctypes import wintypes
from pathlib import Path

PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010
MEM_COMMIT = 0x1000
PAGE_READABLE = (0x02, 0x04, 0x20, 0x40)
PAGE_GUARD = 0x100

DOWNLOAD = Path("captured/zxm_module_download.bin")


class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_void_p),
        ("AllocationBase", ctypes.c_void_p),
        ("AllocationProtect", wintypes.DWORD),
        ("RegionSize", ctypes.c_size_t),
        ("State", wintypes.DWORD),
        ("Protect", wintypes.DWORD),
        ("Type", wintypes.DWORD),
    ]


def find_pid(name):
    out = subprocess.check_output(
        ["tasklist", "/fi", f"imagename eq {name}", "/fo", "csv", "/nh"],
        text=True, errors="replace",
    )
    for line in out.splitlines():
        parts = [p.strip().strip('"') for p in line.split(",")]
        if len(parts) > 1 and parts[0].lower() == name.lower():
            return int(parts[1])
    return None


def pe_size(data: bytes):
    if len(data) < 0x100 or data[:2] != b"MZ":
        return None
    try:
        e = struct.unpack_from("<I", data, 0x3C)[0]
    except struct.error:
        return None
    if not 0 < e < len(data) - 0x40 or data[e:e + 4] != b"PE\x00\x00":
        return None
    return struct.unpack_from("<I", data, e + 24 + 56)[0]


def main():
    target = sys.argv[1] if len(sys.argv) > 1 else "ESurfingSvr.exe"
    blob = DOWNLOAD.read_bytes()
    uuid = blob[blob.find(b"$") + 1:blob.find(b"]")].decode()
    key_hex = blob[blob.find(b"@") + 1:blob.find(b"$")].decode()

    needles = {
        "algo_id_ascii": uuid.encode(),
        "algo_id_utf16": uuid.encode("utf-16-le"),
        "key_hex": key_hex.encode(),
        "container_sig": b"001@",
        "mods_sig": b"ZXM\x00Z",
    }
    print("algo id:", uuid)
    print("key hex:", key_hex)

    pid = find_pid(target)
    if not pid:
        print(target, "not running")
        return 1
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    handle = k32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
    if not handle:
        print("OpenProcess failed", ctypes.get_last_error())
        return 1

    out_dir = Path("module_memory")
    out_dir.mkdir(exist_ok=True)

    mbi = MEMORY_BASIC_INFORMATION()
    addr = 0
    hits = 0
    images = 0
    while addr < 0x80000000:
        if not k32.VirtualQueryEx(handle, ctypes.c_void_p(addr), ctypes.byref(mbi), ctypes.sizeof(mbi)):
            break
        base = mbi.BaseAddress or 0
        size = mbi.RegionSize
        if (mbi.State == MEM_COMMIT and mbi.Protect in PAGE_READABLE
                and not (mbi.Protect & PAGE_GUARD) and 0 < size <= 64 * 1024 * 1024):
            buf = ctypes.create_string_buffer(size)
            read = ctypes.c_size_t(0)
            if k32.ReadProcessMemory(handle, ctypes.c_void_p(base), buf, size, ctypes.byref(read)):
                data = buf.raw[:read.value]
                for name, needle in needles.items():
                    pos = data.find(needle)
                    if pos >= 0:
                        hits += 1
                        ctx = data[max(0, pos - 32):pos + 160]
                        print(f"\nHIT {name} @0x{base + pos:08x}  (region 0x{base:08x}+0x{size:x})")
                        print("   ", repr(ctx[:150]))
                        if name in ("algo_id_ascii", "key_hex"):
                            name_out = out_dir / f"{name}_{base + pos:08x}.bin"
                            name_out.write_bytes(data[:min(size, 2_000_000)])
                            print(f"    dumped region head -> {name_out.name} ({min(size, 2_000_000)} bytes)")
                img = pe_size(data)
                if img:
                    images += 1
                    path = out_dir / f"img_{base:08x}_{img:x}.bin"
                    path.write_bytes(data[:min(img, len(data))])
                    print(f"PE image @0x{base:08x} size=0x{img:x} -> {path.name}")
        addr = base + size

    print(f"\ntotal string hits={hits} pe_images={images}")
    k32.CloseHandle(handle)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
