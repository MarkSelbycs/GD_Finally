"""Hook the DialServer.dll send-chain functions and dump their arguments.

DialServer.dll loads at its preferred base 0x10000000 (no ASLR), and the WinHttp
backtrace showed the send chain entering it at 0x1000c1fc / 0x1000d881. These
functions sit between ESurfingSvr.exe (which owns the XXTEA + hex codec) and
PortalServer.dll (which talks to WinHTTP), so their arguments should reveal the
encoded body and possibly the plaintext XML.
"""

from __future__ import annotations

import argparse
import subprocess
import time

import frida

BASE = 0x10000000
HOOKS = [0xBF00, 0xD6D0, 0xD4E0, 0xE300, 0xD450, 0xF1B8]

JS = r"""
const BASE = 0x10000000;
const HOOKS = [0xBF00, 0xD6D0, 0xD4E0, 0xE300, 0xD450, 0xF1B8];
function ascii(p, n) {
    try { const b = new Uint8Array(p.readByteArray(n)); let s=''; for (let i=0;i<b.length;i++) s += (b[i]>=32&&b[i]<127)?String.fromCharCode(b[i]):'.'; return s; } catch(e){return '(na)';}
}
function hd(p, n) { try { return hexdump(p, {length:n, ansi:false}); } catch(e){return '(na)';} }
let n = 0;
for (const off of HOOKS) {
    Interceptor.attach(ptr(BASE + off), {
        onEnter(args) {
            n++;
            if (n > 50) return;
            let out = '==== 0x' + off.toString(16) + ' #' + n + ' ret=' + this.returnAddress;
            for (let i = 0; i < 4; i++) {
                let v; try { v = args[i]; } catch (e) { break; }
                let s = '  arg' + i + ' = ' + v;
                try { if (!v.isNull() && v.compare(0x10000) > 0 && v.compare(0x80000000) < 0) s += '  [' + ascii(v, 96) + ']'; } catch (e) {}
                out += '\n' + s;
            }
            for (let i = 0; i < 2; i++) {
                try {
                    const v = args[i];
                    if (!v.isNull() && v.compare(0x10000) > 0 && v.compare(0x80000000) < 0) {
                        out += '\n  --mem arg' + i + '--\n' + hd(v, 128);
                    }
                } catch (e) {}
            }
            send(out);
        }
    });
    send('[*] hooked 0x' + off.toString(16));
}
"""


def pids_of(name):
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
    ap.add_argument("--seconds", type=float, default=400.0)
    args = ap.parse_args()
    hooked = set()
    deadline = time.time() + args.seconds
    print(f"watching ESurfingSvr.exe for {args.seconds:g}s", flush=True)
    while time.time() < deadline:
        current = set(pids_of("ESurfingSvr.exe"))
        for pid in current - hooked:
            try:
                session = frida.attach(pid)
                script = session.create_script(JS)

                def on_message(m, d, pid=pid):
                    if m.get("type") in ("send", "log"):
                        print(f"[{pid}] " + str(m.get("payload")), flush=True)

                script.on("message", on_message)
                script.load()
                hooked.add(pid)
                print(f"[+] attached {pid}", flush=True)
            except Exception as exc:  # noqa: BLE001
                print(f"[!] attach {pid} failed: {exc}", flush=True)
        for pid in list(hooked):
            if pid not in current:
                print(f"[-] {pid} exited", flush=True)
                hooked.discard(pid)
        time.sleep(1.0)
    print("done", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
