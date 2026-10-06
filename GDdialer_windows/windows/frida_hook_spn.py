"""Hook the custom SPN cipher (0x433100) and dump its key and data.

The cipher at ESurfingSvr.exe+0x33100 has signature (state, key, data), mixes a
16-byte key and 16-byte data over 16+32 rounds. Hooking it during a dial reveals
the real key material and whether it processes portal body data.
"""

from __future__ import annotations

import argparse
import subprocess
import time

import frida

JS = r"""
function ascii(p, n) {
    try { const b = new Uint8Array(p.readByteArray(n)); let s=''; for (let i=0;i<b.length;i++) s += (b[i]>=32&&b[i]<127)?String.fromCharCode(b[i]):'.'; return s; }
    catch (e) { return '(na)'; }
}
function hd(p, n) { try { return hexdump(p, {length:n, ansi:false}); } catch(e){return '(na)';} }
let base = null;
try { base = Process.getModuleByName('ESurfingSvr.exe').base; } catch (e) {}
if (base === null) { send('[!] no module'); } else {
    send('[*] base=' + base);
    let n = 0;
    for (const off of [0x33100, 0x330e0, 0x432d80, 0x432c90]) {
        Interceptor.attach(base.add(off), {
            onEnter(args) {
                n++;
                if (n > 30) return;
                let out = '==== +0x' + off.toString(16) + ' #' + n + ' ret=' + this.returnAddress;
                for (let i = 0; i < 3; i++) {
                    let v; try { v = args[i]; } catch (e) { break; }
                    let s = '  arg' + i + ' = ' + v;
                    try { if (!v.isNull() && v.compare(0x10000) > 0 && v.compare(0x80000000) < 0) s += '  [' + ascii(v, 64) + ']'; } catch (e) {}
                    out += '\n' + s;
                }
                for (let i = 0; i < 3; i++) {
                    try {
                        const v = args[i];
                        if (!v.isNull() && v.compare(0x10000) > 0 && v.compare(0x80000000) < 0) {
                            out += '\n  --mem arg' + i + '--\n' + hd(v, 64);
                        }
                    } catch (e) {}
                }
                send(out);
            }
        });
        send('[*] hooked +0x33100 / +0x330e0 / +0x432d80 / +0x432c90');
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
