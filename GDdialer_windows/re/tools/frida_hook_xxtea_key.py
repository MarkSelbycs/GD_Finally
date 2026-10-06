"""Capture the XXTEA key for BOTH directions during a dial.

The body is an 8-byte-block XXTEA (matching 0x4260b0), but the body-encryption
(n=+32) calls were missed before. This hooks 0x4260b0 and records every call's
n and key bytes, so the body key (used with n=+32) becomes visible.
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
let base = null;
try { base = Process.getModuleByName('ESurfingSvr.exe').base; } catch (e) {}
if (base === null) { send('[!] no module'); } else {
    send('[*] base=' + base);
    let seen = {};
    let total = 0;
    Interceptor.attach(base.add(0x4260b0 - 0x400000), {
        onEnter(args) {
            total++;
            if (total > 60) return;
            const n = args[2].toInt32();
            const keyPtr = args[0];
            let keyHex = '';
            try {
                const kb = new Uint8Array(keyPtr.readByteArray(32));
                keyHex = Array.from(kb).map(x => x.toString(16).padStart(2,'0')).join(' ');
            } catch (e) {}
            const keySig = keyHex.slice(0, 47); // first 16 bytes
            if (!seen[keySig]) {
                seen[keySig] = 1;
                send('XXTEA n=' + n + ' key=' + keyPtr + '  ' + keyHex);
            }
            // 也记录数据指针范围
            if (total <= 3) send('  data=' + args[1] + '  n=' + n);
        }
    });
    send('[*] hooked 0x4260b0');
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
