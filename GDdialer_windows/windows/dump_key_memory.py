"""Read the CInnerCoder key buffer out of the live ESurfingSvr.exe process.

Searches committed, readable memory for the immediate constants that the
coder writes into its key array, then dumps the surrounding bytes so the
full key schedule can be recovered.
"""

from __future__ import annotations

import ctypes
import struct
import sys
from ctypes import wintypes

PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010
MEM_COMMIT = 0x1000
PAGE_READABLE = (0x02, 0x04, 0x20, 0x40)  # RO, RW, EX_R, EX_RW


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
    import subprocess

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


def main():
    name = sys.argv[1] if len(sys.argv) > 1 else "ESurfingSvr.exe"
    needles = [0x93A97696, 0xC366F3C0, 0x93818B99, 0xE94336D0, 0x5D966189,
               0xEC4C6F3C, 0x5EC9BCD6, 0xB173CFD0, 0x0006B81F, 0x2F3363DF,
               0xDC3261B5, 0x41C8C32A, 0x4AABBD7A, 0x0C49F529, 0xC89E9EEA,
               0x85322235, 0x53E5CCD1, 0xC444CC80]
    patterns = {n: struct.pack("<I", n) for n in needles}

    pid = find_pid(name)
    if not pid:
        print(f"{name} not running")
        return 1
    print("pid", pid)

    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    handle = k32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
    if not handle:
        print("OpenProcess failed", ctypes.get_last_error())
        return 1

    mbi = MEMORY_BASIC_INFORMATION()
    addr = 0
    found = 0
    while k32.VirtualQueryEx(handle, ctypes.c_void_p(addr), ctypes.byref(mbi), ctypes.sizeof(mbi)):
        base = mbi.BaseAddress or 0
        size = mbi.RegionSize
        if mbi.State == MEM_COMMIT and mbi.Protect in PAGE_READABLE and size < 64 * 1024 * 1024:
            buf = ctypes.create_string_buffer(size)
            read = ctypes.c_size_t(0)
            if k32.ReadProcessMemory(handle, ctypes.c_void_p(base), buf, size, ctypes.byref(read)):
                data = buf.raw[:read.value]
                for value, pat in patterns.items():
                    pos = data.find(pat)
                    while pos >= 0 and found < 60:
                        start = max(0, pos - 32)
                        chunk = data[start:pos + 68]
                        print(f"\n--- hit 0x{value:08x} at 0x{base + pos:08x} ---")
                        for off in range(0, len(chunk) - 3, 4):
                            word = struct.unpack_from("<I", chunk, off)[0]
                            mark = "  <== needle" if word == value else ""
                            print(f"  0x{base + start + off:08x}: 0x{word:08x}{mark}")
                        found += 1
                        pos = data.find(pat, pos + 1)
        addr = base + size
        if addr > 0x7FFFFFFF:
            break
    print("\ntotal hits", found)
    k32.CloseHandle(handle)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
