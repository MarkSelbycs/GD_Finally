"""Dump the algorithm module from memory right after ESurfingSvr decrypts it.

Frida showed the coder entry receiving the downloaded container

    001@<32-byte hex key>$<Algo-ID>]<payload>

and then running thousands of in-place XXTEA block decryptions over the payload.
Because the buffer is decrypted in place, the module is sitting in memory when
the burst finishes. This watches for that burst and exfiltrates the buffer.

Usage:
    python frida_dump_module.py --seconds 600
"""

from __future__ import annotations

import argparse
import subprocess
import time
from pathlib import Path

import frida

MODULE = "ESurfingSvr.exe"
IMAGE_BASE = 0x400000

JS = r"""
const MODULE = 'ESurfingSvr.exe';
const IMAGE_BASE = 0x400000;
let base = null;
try { base = Process.getModuleByName(MODULE).base; } catch (e) { send({t:'log', m:'[!] ' + e}); }
function va(v) { return base.add(v - IMAGE_BASE); }

let pending = null;   // {ptr, len, skip}
let timer = null;
let bursts = 0;

function scheduleDump() {
    if (timer !== null) { clearTimeout(timer); }
    timer = setTimeout(doDump, 400);
}

function doDump() {
    timer = null;
    if (pending === null) return;
    bursts++;
    const { ptr, len, skip } = pending;
    try {
        const buf = ptr.add(skip).readByteArray(len - skip);
        send({ t: 'dump', bursts: bursts, ptr: ptr.toString(), len: len, skip: skip }, buf);
        send({ t: 'log', m: '[dump] bursts=' + bursts + ' ptr=' + ptr + ' len=' + len + ' skip=' + skip });
    } catch (e) {
        send({ t: 'log', m: '[dump failed] ' + e });
    }
    pending = null;
}

if (base !== null) {
    Interceptor.attach(va(0x4156b0), {
        onEnter(args) {
            try {
                const p = args[0];
                const n = args[1].toInt32();
                const head = new Uint8Array(p.readByteArray(8));
                const txt = String.fromCharCode.apply(null, head);
                send({ t: 'log', m: '[ENTRY] ptr=' + p + ' len=' + n + ' head=' + JSON.stringify(txt) });
                pending = { ptr: p, len: n, skip: 0 };
                // the container header length varies; locate the ']' to find the payload
                try {
                    const whole = new Uint8Array(p.readByteArray(Math.min(n, 256)));
                    for (let i = 0; i < whole.length; i++) {
                        if (whole[i] === 0x5d) { pending.skip = i + 1 + 8; break; }
                    }
                } catch (e) {}
                scheduleDump();
            } catch (e) {}
        }
    });
    Interceptor.attach(va(0x4260b0), {
        onEnter(args) {
            try {
                if (pending === null) return;
                const d = args[1];
                const container = pending.ptr;
                const delta = d.sub(container).toInt32();
                if (delta >= 0 && delta < pending.len) scheduleDump();
            } catch (e) {}
        }
    });
    send({ t: 'log', m: '[*] hooks installed base=' + base });
}
"""


def pids_of(name: str):
    out = subprocess.check_output(
        ["tasklist", "/fi", f"imagename eq {name}", "/fo", "csv", "/nh"],
        text=True, errors="replace",
    )
    pids = []
    for line in out.splitlines():
        parts = [p.strip().strip('"') for p in line.split(",")]
        if len(parts) > 1 and parts[0].lower() == name.lower():
            try:
                pids.append(int(parts[1]))
            except ValueError:
                pass
    return pids


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--seconds", type=float, default=600.0)
    ap.add_argument("--out", default="captured")
    args = ap.parse_args()
    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    hooked = {}
    saved = 0
    deadline = time.time() + args.seconds
    print(f"watching {MODULE} for {args.seconds:g}s", flush=True)
    while time.time() < deadline:
        current = set(pids_of(MODULE))
        for pid in current - set(hooked):
            try:
                session = frida.attach(pid)
                script = session.create_script(JS)

                def on_message(message, data, pid=pid):
                    nonlocal saved
                    if message.get("type") != "send":
                        if message.get("type") == "error":
                            print(f"[{pid}] err {message.get('description')}", flush=True)
                        return
                    payload = message.get("payload") or {}
                    if payload.get("t") == "log":
                        print(f"[{pid}] {payload.get('m')}", flush=True)
                    elif payload.get("t") == "dump" and data:
                        saved += 1
                        name = out_dir / f"decrypted_module_{saved}.bin"
                        name.write_bytes(data)
                        head = bytes(data[:16])
                        tag = "PE" if head[:2] == b"MZ" else "ELF" if head[:4] == b"\x7fELF" else ""
                        print(f"[{pid}] saved {name.name} {len(data)} bytes head={head.hex(' ')} {tag}", flush=True)

                script.on("message", on_message)
                script.load()
                hooked[pid] = session
                print(f"[+] attached pid {pid}", flush=True)
            except Exception as exc:  # noqa: BLE001
                print(f"[!] attach {pid} failed: {exc}", flush=True)
        for pid in list(hooked):
            if pid not in current:
                print(f"[-] pid {pid} exited", flush=True)
                try:
                    hooked[pid].detach()
                except Exception:
                    pass
                del hooked[pid]
        time.sleep(1.0)
    for session in hooked.values():
        try:
            session.detach()
        except Exception:
            pass
    print(f"done, saved {saved}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
