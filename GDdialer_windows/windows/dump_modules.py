"""Dump PE images and interesting strings out of the running ESurfingSvr.exe.

The original service loads its coding module through a custom in-memory loader
(CMemModImpl::LoadMod), so a failed zxmAlogic.zxm load still leaves an
executable image in private memory. This scans for those images.
"""

from __future__ import annotations

import ctypes
import struct
import subprocess
import sys
from ctypes import wintypes
from pathlib import Path

PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010
MEM_COMMIT = 0x1000
MEM_PRIVATE = 0x20000
PAGE_READABLE = (0x02, 0x04, 0x20, 0x40)
PAGE_GUARD = 0x100


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


def find_pid(name: str) -> int | None:
    out = subprocess.check_output(
        ["tasklist", "/fi", f"imagename eq {name}", "/fo", "csv", "/nh"],
        text=True,
        errors="replace",
    )
    for line in out.splitlines():
        parts = [p.strip().strip('"') for p in line.split(",")]
        if len(parts) > 1 and parts[0].lower() == name.lower():
            return int(parts[1])
    return None


def pe_size(data: bytes) -> int | None:
    """Return the image size if data starts with a plausible PE image."""
    if len(data) < 0x100 or data[:2] != b"MZ":
        return None
    try:
        e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    except struct.error:
        return None
    if not 0 < e_lfanew < len(data) - 0x40:
        return None
    if data[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
        return None
    opt = e_lfanew + 24
    magic = struct.unpack_from("<H", data, opt)[0]
    if magic not in (0x10B, 0x20B):
        return None
    size_of_image = struct.unpack_from("<I", data, opt + 56)[0]
    if not 0x1000 <= size_of_image <= 64 * 1024 * 1024:
        return None
    return size_of_image


def main():
    target = sys.argv[1] if len(sys.argv) > 1 else "ESurfingSvr.exe"
    out_dir = Path("dumped_modules")
    out_dir.mkdir(exist_ok=True)

    pid = find_pid(target)
    if not pid:
        print(f"{target} not running")
        return 1
    print("pid", pid)

    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    handle = k32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
    if not handle:
        print("OpenProcess failed", ctypes.get_last_error())
        return 1

    strings = [b"AutoZSM", b"zxmAlogic", b"Algo-ID", b"DaMod", b"cdccportalgd", b"E9747EF1"]
    mbi = MEMORY_BASIC_INFORMATION()
    addr = 0
    images = 0
    hits = 0
    scanned = 0
    while addr < 0x80000000:
        if not k32.VirtualQueryEx(handle, ctypes.c_void_p(addr), ctypes.byref(mbi), ctypes.sizeof(mbi)):
            break
        base = mbi.BaseAddress or 0
        size = mbi.RegionSize
        if (
            mbi.State == MEM_COMMIT
            and mbi.Type == MEM_PRIVATE
            and mbi.Protect in PAGE_READABLE
            and not (mbi.Protect & PAGE_GUARD)
            and 0 < size <= 32 * 1024 * 1024
        ):
            buf = ctypes.create_string_buffer(size)
            read = ctypes.c_size_t(0)
            if k32.ReadProcessMemory(handle, ctypes.c_void_p(base), buf, size, ctypes.byref(read)):
                data = buf.raw[:read.value]
                scanned += len(data)
                image_size = pe_size(data)
                if image_size:
                    name = out_dir / f"image_{base:08x}_{image_size:x}.bin"
                    name.write_bytes(data[:min(image_size, len(data))])
                    print(f"IMAGE at 0x{base:08x} size 0x{image_size:x} -> {name.name}")
                    images += 1
                for needle in strings:
                    pos = data.find(needle)
                    if pos >= 0:
                        ctx = data[max(0, pos - 40):pos + 80]
                        print(f"  str {needle.decode()} @0x{base + pos:08x} ctx={ctx[:60]!r}")
                        hits += 1
        addr = base + size
    print(f"\nscanned {scanned} bytes, images={images}, string hits={hits}")
    k32.CloseHandle(handle)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
