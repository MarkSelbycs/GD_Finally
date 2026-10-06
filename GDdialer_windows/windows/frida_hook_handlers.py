"""Hook the request-handler entry functions in PortalServer.dll and dump args.

The WinHttp backtrace located the assembly chain in PortalServer.dll (offsets
0x3f6f0, 0x371b0, 0x30b30, then the sender at ~0x11bf1). PortalServer.dll is a
memory-loaded module (not in the module list), so this finds its base by
scanning for the AES s-box pattern, then hooks the entry functions and dumps
their arguments and the memory they point at -- revealing the plaintext XML and
the encoded body.
"""

from __future__ import annotations

import argparse
import subprocess
import time

import frida

SBOX = "63 7c 77 7b f2 6b 6f c5 30 01 67 2b fe d7 ab 76"
HOOKS = [0x3F6F0, 0x371B0, 0x30B30, 0x36240]

JS = r"""
const SBOX = [0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76];
const HOOKS = [0x3F6F0, 0x371B0, 0x30B30, 0x36240];
const ranges = Process.enumerateRanges('r--');
let base = null;
for (const r of ranges) {
    if (r.size < 0x20000 || r.size > 0x200000) continue;
    try {
        const u8 = new Uint8Array(r.base.readByteArray(Math.min(r.size, 0x80000)));
        for (let i = 0; i + 16 <= u8.length; i++) {
            let ok = true;
            for (let j = 0; j < 16; j++) if (u8[i + j] !== SBOX[j]) { ok = false; break; }
            if (ok) { base = r.base; break; }
        }
        if (base !== null) break;
    } catch (e) {}
}
if (base === null) { send('[!] sbox not found'); } else {
    send('[*] PortalServer base=' + base);
    function ascii(p, n) {
        try { const b = new Uint8Array(p.readByteArray(n)); let s=''; for (let i=0;i<b.length;i++) s += (b[i]>=32&&b[i]<127)?String.fromCharCode(b[i]):'.'; return s; } catch(e){return '(na)';}
    }
    function hd(p, n) { try { return hexdump(p, {length:n, ansi:false}); } catch(e){return '(na)';} }
    let n = 0;
    for (const off of HOOKS) {
        Interceptor.attach(base.add(off), {
            onEnter(args) {
                n++;
                if (n > 40) return;
                let out = '==== ' + '0x' + off.toString(16) + ' #' + n + ' ret=' + this.returnAddress;
                for (let i = 0; i < 4; i++) {
                    let v; try { v = args[i]; } catch (e) { break; }
                    let s = '  arg' + i + ' = ' + v;
                    try { if (!v.isNull() && v.compare(0x10000) > 0 && v.compare(0x80000000) < 0) s += '  [' + ascii(v, 72) + ']'; } catch (e) {}
                    out += '\n' + s;
                }
                for (let i = 0; i < 2; i++) {
                    try {
                        const v = args[i];
                        if (!v.isNull() && v.compare(0x10000) > 0 && v.compare(0x80000000) < 0) {
                            out += '\n  --mem arg' + i + '--\n' + hd(v, 96);
                        }
                    } catch (e) {}
                }
                send(out);
            }
        });
        send('[*] hooked 0x' + off.toString(16));
    }
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
