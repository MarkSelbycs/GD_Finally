"""Multi-cipher key recovery from the live ESurfingSvr.exe memory.

Block size is 8 bytes (all captured bodies are multiples of 8, several are not
multiples of 16). This scans every 16-byte window of process memory as a
candidate key and tests several 8-byte-block ciphers against the known
plaintext/ciphertext block pair:

    plaintext  "<?xml ve"
    ciphertext c853a9968496b3e0

Ciphers are evaluated vectorised with numpy so millions of candidates per
second are possible.
"""

from __future__ import annotations

import argparse
import ctypes
import struct
import subprocess
from ctypes import wintypes

import numpy as np

PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010
MEM_COMMIT = 0x1000
PAGE_READABLE = (0x02, 0x04, 0x20, 0x40)
PAGE_GUARD = 0x100

D = 0x9E3779B9
PLAIN_BLOCK = b"<?xml ve"
CIPHER_BLOCK = bytes.fromhex("c853a9968496b3e0")
KEY_BYTES = 16


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


U = np.uint32


def _mk(n, v):
    return np.full(n, v, dtype=np.uint32)


def our_xxtea_variant(keys, v0, v1, rounds=32):
    a, b = _mk(keys.shape[0], v0), _mk(keys.shape[0], v1)
    s = U(0)
    with np.errstate(over="ignore"):
        for _ in range(rounds):
            y = b
            a = a + (((y << U(4)) ^ (y >> U(5))) + (y ^ s) + keys[:, int(s) & 3])
            s = U((int(s) + D) & 0xFFFFFFFF)
            z = a
            b = b + (((z << U(4)) ^ (z >> U(5))) + (z ^ s) + keys[:, (int(s) >> 11) & 3])
    return a, b


def our_xxtea_variant_swapped(keys, v0, v1, rounds=32):
    return our_xxtea_variant(keys[:, ::-1].copy(), v0, v1, rounds)


def standard_tea(keys, v0, v1, rounds=64):
    n = keys.shape[0]
    a, b = _mk(n, v0), _mk(n, v1)
    s = U(0)
    with np.errstate(over="ignore"):
        for _ in range(rounds // 2):
            s = U((int(s) + D) & 0xFFFFFFFF)
            a = a + (((b << U(4)) + keys[:, 0]) ^ (b + s) ^ ((b >> U(5)) + keys[:, 1]))
            b = b + (((a << U(4)) + keys[:, 2]) ^ (a + s) ^ ((a >> U(5)) + keys[:, 3]))
    return a, b


def standard_xtea(keys, v0, v1, rounds=64):
    n = keys.shape[0]
    a, b = _mk(n, v0), _mk(n, v1)
    s = U(0)
    with np.errstate(over="ignore"):
        for _ in range(rounds // 2):
            a = a + ((((b << U(4)) ^ (b >> U(5))) + b) ^ (s + keys[:, int(s) & 3]))
            s = U((int(s) + D) & 0xFFFFFFFF)
            b = b + ((((a << U(4)) ^ (a >> U(5))) + a) ^ (s + keys[:, (int(s) >> 11) & 3]))
    return a, b


def standard_xxtea(keys, v0, v1):
    """Standard XXTEA with n=2 (32 rounds over the 2-word block)."""
    n = keys.shape[0]
    a, b = _mk(n, v0), _mk(n, v1)
    s = U(0)
    with np.errstate(over="ignore"):
        for _ in range(32):
            s = U((int(s) + D) & 0xFFFFFFFF)
            e = (int(s) >> 2) & 3
            mx = (((b >> U(5)) ^ (a << U(2))) + ((b >> U(3)) ^ (a << U(4)))) ^ ((s ^ b) + (keys[:, (0 & 3) ^ e] ^ a))
            a = a + mx
            mx = (((a >> U(5)) ^ (b << U(2))) + ((a >> U(3)) ^ (b << U(4)))) ^ ((s ^ a) + (keys[:, (1 & 3) ^ e] ^ b))
            b = b + mx
    return a, b


CIPHERS = {
    "our_xxtea_variant": our_xxtea_variant,
    "our_xxtea_swapped": our_xxtea_variant_swapped,
    "standard_tea": standard_tea,
    "standard_xtea": standard_xtea,
    "standard_xxtea": standard_xxtea,
}


def iter_regions(handle, k32):
    mbi = MEMORY_BASIC_INFORMATION()
    addr = 0
    while addr < 0x80000000:
        if not k32.VirtualQueryEx(handle, ctypes.c_void_p(addr), ctypes.byref(mbi), ctypes.sizeof(mbi)):
            break
        base = mbi.BaseAddress or 0
        size = mbi.RegionSize
        if (mbi.State == MEM_COMMIT and mbi.Protect in PAGE_READABLE
                and not (mbi.Protect & PAGE_GUARD) and 0 < size <= 64 * 1024 * 1024):
            yield base, size
        addr = base + size


def batches(handle, k32, stride, batch):
    """Yield (base_address, start_offsets, keys(N,4)) batches of candidate keys."""
    for base, size in iter_regions(handle, k32):
        buf = ctypes.create_string_buffer(size)
        read = ctypes.c_size_t(0)
        if not k32.ReadProcessMemory(handle, ctypes.c_void_p(base), buf, size, ctypes.byref(read)):
            continue
        data = buf.raw[:read.value]
        raw = np.frombuffer(data, dtype=np.uint8)
        windows = np.lib.stride_tricks.sliding_window_view(raw, KEY_BYTES)
        total = windows.shape[0]
        if total <= 0:
            continue
        step = batch * stride
        for start in range(0, total, step):
            starts = np.arange(start, min(total, start + step), stride, dtype=np.int64)
            if starts.size == 0:
                continue
            chunk = np.ascontiguousarray(windows[starts])
            yield base, starts, chunk.view("<u4")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("process", nargs="?", default="ESurfingSvr.exe")
    ap.add_argument("--stride", type=int, default=4)
    ap.add_argument("--batch", type=int, default=2_000_000)
    args = ap.parse_args()

    pid = find_pid(args.process)
    if not pid:
        print(args.process, "not running")
        return 1
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    handle = k32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
    if not handle:
        print("OpenProcess failed", ctypes.get_last_error())
        return 1

    pv0, pv1 = struct.unpack("<II", PLAIN_BLOCK)
    tv0, tv1 = struct.unpack("<II", CIPHER_BLOCK)
    print(f"pid={pid} plain={PLAIN_BLOCK!r} -> cipher={CIPHER_BLOCK.hex()}")

    for name, fn in CIPHERS.items():
        hits = 0
        tested = 0
        for base, starts, keys in batches(handle, k32, args.stride, args.batch):
            try:
                o0, o1 = fn(keys, pv0, pv1)
            except Exception as exc:  # noqa: BLE001
                print(f"  {name}: error {exc}")
                break
            tested += int(keys.shape[0])
            mask = (o0 == U(tv0)) & (o1 == U(tv1))
            for idx in np.nonzero(mask)[0]:
                off = int(starts[idx])
                print(f"  HIT {name} @0x{base + off:08x} key={keys[idx].tobytes().hex()}")
                hits += 1
                if hits >= 4:
                    break
            if hits >= 4:
                break
        print(f"{name:20} tested={tested} hits={hits}")

    k32.CloseHandle(handle)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
