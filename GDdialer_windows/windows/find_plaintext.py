"""Search the live ESurfingSvr.exe memory for portal plaintext XML.

CInnerCoder's RC4 runs in place, so the request buffer may still hold either the
plaintext XML or the encoded bytes. Finding a plaintext lets us pair it with a
captured ciphertext and recover the keystream.
"""

from __future__ import annotations

import ctypes
import re
import subprocess
import sys
from ctypes import wintypes
from pathlib import Path

PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010
MEM_COMMIT = 0x1000
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

    needles = [
        b"<?xml version=",
        b"<request>",
        b"<user-agent>",
        b"<client-id>",
        b"<ticket>",
        b"<local-time>",
        b"<passwd>",
    ]
    mbi = MEMORY_BASIC_INFORMATION()
    addr = 0
    hits = 0
    out_dir = Path("plaintext_dump")
    out_dir.mkdir(exist_ok=True)
    while addr < 0x80000000:
        if not k32.VirtualQueryEx(handle, ctypes.c_void_p(addr), ctypes.byref(mbi), ctypes.sizeof(mbi)):
            break
        base = mbi.BaseAddress or 0
        size = mbi.RegionSize
        if (
            mbi.State == MEM_COMMIT
            and mbi.Protect in PAGE_READABLE
            and not (mbi.Protect & PAGE_GUARD)
            and 0 < size <= 64 * 1024 * 1024
        ):
            buf = ctypes.create_string_buffer(size)
            read = ctypes.c_size_t(0)
            if k32.ReadProcessMemory(handle, ctypes.c_void_p(base), buf, size, ctypes.byref(read)):
                data = buf.raw[:read.value]
                for needle in needles:
                    for m in re.finditer(re.escape(needle), data):
                        pos = m.start()
                        snippet = data[pos:pos + 420]
                        printable = sum(1 for c in snippet if 32 <= c < 127 or c in (9, 10, 13))
                        ratio = printable / max(len(snippet), 1)
                        print(f"\nHIT {needle.decode()} @0x{base + pos:08x} ratio={ratio:.2f}")
                        text = "".join(chr(c) if 32 <= c < 127 else "." for c in snippet[:240])
                        print("   ", text)
                        if ratio > 0.8:
                            name = out_dir / f"plain_{base + pos:08x}.bin"
                            name.write_bytes(snippet)
                            print(f"    saved {name.name}")
                        hits += 1
                        if hits > 25:
                            break
                    if hits > 25:
                        break
        addr = base + size
    print("\ntotal hits", hits)
    k32.CloseHandle(handle)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
