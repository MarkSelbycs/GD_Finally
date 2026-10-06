"""Find every PE image anywhere in the service's memory, not just at region starts.

The downloaded module (lsres.dll) exposes Uncompress/Compress/HexCodeA and is
loaded through CMemModImpl, so its MZ header may not sit at a region boundary.
This scans all readable memory for MZ + valid PE header and reports images,
highlighting any that contain the algorithm module's function names.
"""

from __future__ import annotations

import ctypes
import struct
import subprocess
from ctypes import wintypes
from pathlib import Path

PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010
MEM_COMMIT = 0x1000
PAGE_READABLE = (0x02, 0x04, 0x20, 0x40)
PAGE_GUARD = 0x100
MARKERS = [b"Uncompress", b"HexDeCodeA", b"HexCodeA", b"Serialize", b"lsres.dll"]


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


def pe_at(data: bytes, off: int):
    """Return (image_size, dll_name) if a valid PE image starts at off."""
    if data[off:off + 2] != b"MZ" or off + 0x40 > len(data):
        return None
    try:
        e = struct.unpack_from("<I", data, off + 0x3C)[0]
    except struct.error:
        return None
    if not 0 < e < 0x1000 or off + e + 0x40 > len(data) or data[off + e:off + e + 4] != b"PE\x00\x00":
        return None
    opt = off + e + 24
    if struct.unpack_from("<H", data, opt)[0] not in (0x10B, 0x20B):
        return None
    size = struct.unpack_from("<I", data, opt + 56)[0]
    if not 0x1000 <= size <= 64 * 1024 * 1024:
        return None
    name = ""
    exp_rva, exp_size = struct.unpack_from("<II", data, opt + 96)
    if exp_size and exp_rva < len(data) - off - 40:
        nr = struct.unpack_from("<I", data, off + exp_rva + 12)[0]
        if 0 < nr < len(data) - off:
            end = data.find(b"\0", off + nr)
            name = data[off + nr:end].decode("latin1", "replace")
    return size, name


def main():
    target = "ESurfingSvr.exe"
    pid = find_pid(target)
    if not pid:
        print(target, "not running")
        return 1
    print("pid", pid)

    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    handle = k32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
    if not handle:
        print("OpenProcess failed", ctypes.get_last_error())
        return 1

    out_dir = Path("pe_hunt")
    out_dir.mkdir(exist_ok=True)

    mbi = MEMORY_BASIC_INFORMATION()
    addr = 0
    images = 0
    interesting = 0
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
                markers = [m.decode() for m in MARKERS if m in data]
                pos = 0
                while True:
                    pos = data.find(b"MZ", pos)
                    if pos < 0:
                        break
                    info = pe_at(data, pos)
                    pos += 1
                    if not info:
                        continue
                    img_size, name = info
                    images += 1
                    if markers:
                        interesting += 1
                        print(f"PE @0x{base + pos - 1:08x} va=0x{base + pos - 1:08x} size=0x{img_size:x} "
                              f"dll={name!r} markers={markers}")
                        path = out_dir / f"pe_{base + pos - 1:08x}_{img_size:x}.bin"
                        path.write_bytes(data[pos - 1:pos - 1 + min(img_size, len(data) - pos + 1)])
                        print(f"   saved {path.name}")
                    elif name:
                        print(f"PE @0x{base + pos - 1:08x} size=0x{img_size:x} dll={name!r} type={mbi.Type:#x}")
        addr = base + size

    print(f"\nPE images found: {images}, with module markers: {interesting}")
    k32.CloseHandle(handle)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
