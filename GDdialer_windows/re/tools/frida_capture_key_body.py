"""Capture container key and portal bodies from the SAME dial session.

The container key changes every dial and the body ciphertext changes with it,
so the key and the bodies must be paired from one session. This hooks both the
coder entry (0x4156b0, which receives the "001@<key>$<AlgoID>]" container) and
WinHttpSendRequest (which receives the encoded bodies) and prints them together.
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
let containerKey = null;
let containerAlgo = null;
let bodyCount = 0;

let svrBase = null;
try { svrBase = Process.getModuleByName('ESurfingSvr.exe').base; } catch (e) {}
if (svrBase !== null) {
    // coder entry 0x4156b0: arg0 = "001@<64 hex>$<algo-id>]..."
    Interceptor.attach(svrBase.add(0x4156b0 - 0x400000), {
        onEnter(args) {
            try {
                const head = ascii(args[0], 160);
                const at = head.indexOf('@');
                const dl = head.indexOf('$');
                if (at > 0 && dl > at) {
                    containerKey = head.slice(at + 1, dl);
                    containerAlgo = head.slice(dl + 1, head.indexOf(']'));
                    send('KEY ' + containerKey + '  ALGO ' + containerAlgo);
                }
            } catch (e) {}
        }
    });
    send('[*] hooked coder entry @' + svrBase.add(0x156b0));
} else {
    send('[!] ESurfingSvr.exe base not found');
}

let winhttp = null;
try { winhttp = Process.getModuleByName('winhttp.dll'); } catch (e) {}
if (winhttp !== null) {
    const target = winhttp.getExportByName('WinHttpSendRequest');
    Interceptor.attach(target, {
        onEnter(args) {
            const len = args[4].toInt32();
            if (len <= 0 || bodyCount > 20) return;
            bodyCount++;
            const body = ascii(args[3], Math.min(len, 800));
            send('BODY len=' + len + ' key=' + (containerKey || '?') + ' :: ' + body);
        }
    });
    send('[*] hooks installed');
} else {
    send('[!] winhttp not loaded');
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
