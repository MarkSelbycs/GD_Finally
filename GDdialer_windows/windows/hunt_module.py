"""Hunt for the downloaded algorithm module inside the live service process.

The client fetches lsres.dll (Algo-ID 7F224CA8-...) at dial time and loads it
through CMemModImpl, so the decrypted module must be reachable in memory. This
looks for the module's characteristic export names and for any PE image that
contains them, then dumps the region.
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
PAGE_READABLE = (0x02, 0x04, 0x20, 0x40)
PAGE_GUARD = 0x100

NAMES = [b"GetExData", b"FreeResult", b"Inspect", b"DeCode", b"lsres", b"lsres.dll"]


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


def pe_image(data: bytes):
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

    out_dir = Path("module_hunt")
    out_dir.mkdir(exist_ok=True)

    mbi = MEMORY_BASIC_INFORMATION()
    addr = 0
    total_regions = 0
    with_names = []
    while addr < 0x80000000:
        if not k32.VirtualQueryEx(handle, ctypes.c_void_p(addr), ctypes.byref(mbi), ctypes.sizeof(mbi)):
            break
        base = mbi.BaseAddress or 0
        size = mbi.RegionSize
        if (mbi.State == MEM_COMMIT and mbi.Protect in PAGE_READABLE
                and not (mbi.Protect & PAGE_GUARD) and 0 < size <= 64 * 1024 * 1024):
            total_regions += 1
            buf = ctypes.create_string_buffer(size)
            read = ctypes.c_size_t(0)
            if k32.ReadProcessMemory(handle, ctypes.c_void_p(base), buf, size, ctypes.byref(read)):
                data = buf.raw[:read.value]
                found = [n for n in NAMES if n in data]
                if found:
                    img = pe_image(data)
                    with_names.append((base, size, found, img))
                    tag = f" PE_image=0x{img:x}" if img else ""
                    print(f"region 0x{base:08x} size=0x{size:x} names={[n.decode() for n in found]}{tag} type={mbi.Type:#x}")
                    dump = out_dir / f"region_{base:08x}_{size:x}.bin"
                    dump.write_bytes(data[:min(size, 4_000_000)])
        addr = base + size

    print(f"\nregions with module names: {len(with_names)} (scanned {total_regions})")
    for base, size, found, img in with_names:
        if img:
            print(f"  candidate module image @0x{base:08x} size=0x{img:x} names={[n.decode() for n in found]}")
    k32.CloseHandle(handle)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
