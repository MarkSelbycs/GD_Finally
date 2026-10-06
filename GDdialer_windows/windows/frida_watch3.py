"""Compact, high-volume hook of the coder so the whole pipeline is visible.

The previous run capped logging at 24 calls and only saw the module container
being decrypted. This logs one compact line per call (function, key pointer,
data pointer, first 8 bytes, round parameter) with a much higher cap, so the
portal-body stage order and its buffers become visible.
"""

from __future__ import annotations

import argparse
import subprocess
import time

import frida

MODULE = "ESurfingSvr.exe"
IMAGE_BASE = 0x400000
CAP = 20000

JS = r"""
const MODULE = 'ESurfingSvr.exe';
const IMAGE_BASE = 0x400000;
const CAP = %d;
let base = null;
try { base = Process.getModuleByName(MODULE).base; } catch (e) { send('[!] ' + e); }
function va(v) { return base.add(v - IMAGE_BASE); }

const seen = {};
let n = 0;
function line(tag, args, nargs) {
    if (n >= CAP) return;
    n++;
    let s = tag;
    for (let i = 0; i < nargs; i++) {
        let v; try { v = args[i]; } catch (e) { break; }
        s += ' a' + i + '=' + v;
        if (i === 1) {
            try {
                const b = new Uint8Array(v.readByteArray(8));
                s += ' [' + Array.from(b).map(x => x.toString(16).padStart(2, '0')).join(' ') + ']';
            } catch (e) { s += ' [?]'; }
        }
    }
    send(s);
}
function hook(addr, name, nargs) {
    Interceptor.attach(va(addr), { onEnter(a) { line(name, a, nargs); } });
    send('[*] hooked ' + name);
}
if (base !== null) {
    hook(0x4156b0, 'ENTRY', 3);
    hook(0x425e80, 'RC4  ', 4);
    hook(0x4260b0, 'XXTEA', 4);
    hook(0x4266e0, 'HEX  ', 3);
    hook(0x426200, 'CODER', 4);
    hook(0x426770, 'HEX2 ', 3);
    send('[*] base=' + base);
}
""" % CAP


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
    ap.add_argument("--seconds", type=float, default=900.0)
    args = ap.parse_args()
    hooked = {}
    deadline = time.time() + args.seconds
    print(f"watching {MODULE} for {args.seconds:g}s", flush=True)
    while time.time() < deadline:
        current = set(pids_of(MODULE))
        for pid in current - set(hooked):
            try:
                session = frida.attach(pid)
                script = session.create_script(JS)

                def on_message(message, data, pid=pid):
                    kind = message.get("type")
                    if kind in ("send", "log"):
                        print(f"[{pid}] " + str(message.get("payload")), flush=True)
                    elif kind == "error":
                        print(f"[{pid}] err " + str(message.get("description")), flush=True)

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
    print("done", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
