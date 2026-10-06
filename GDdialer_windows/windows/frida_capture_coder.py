"""Capture the codec module the instant a portal body is sent.

The WinHttp backtrace showed the body-assembly frames in a memory range that
Frida could not resolve to a module (0x2231bf1, 0x225727a, ...), which is the
transiently loaded algorithm module. This hooks WinHttpSendRequest and, on the
first request carrying a body, dumps the distinct memory ranges that own each
backtrace frame, plus the module containing the immediate caller.
"""

from __future__ import annotations

import argparse
import subprocess
import time
from pathlib import Path

import frida

JS = r"""
function modOf(addr) {
    try { const m = Process.findModuleByAddress(addr); return m ? m.name : 'unknown'; }
    catch (e) { return 'err'; }
}
let fired = 0;
(function () {
    let winhttp = null;
    try { winhttp = Process.getModuleByName('winhttp.dll'); } catch (e) {}
    if (winhttp === null) { send('[!] winhttp not loaded'); return; }
    const target = winhttp.getExportByName('WinHttpSendRequest');
    Interceptor.attach(target, {
        onEnter(args) {
            if (fired > 0) return;
            const len = args[4].toInt32();
            if (len <= 0) return;   // only requests with a body
            fired = 1;
            const seen = {};
            let frames = [];
            try {
                const bt = Thread.backtrace(this.context, Backtracer.ACCURATE);
                frames = bt;
                for (const a of bt) {
                    try {
                        const r = Process.findRangeByAddress(a);
                        if (r !== null && !seen[r.base.toString()]) {
                            seen[r.base.toString()] = r;
                        }
                    } catch (e) {}
                }
            } catch (e) {}
            send({ t: 'log', m: 'frames=' + frames.length + ' ranges=' + Object.keys(seen).length
                        + ' caller=' + this.returnAddress + ' (' + modOf(this.returnAddress) + ')' });
            for (const k in seen) {
                const r = seen[k];
                if (r.size > 2 * 1024 * 1024) continue;
                try {
                    const data = r.base.readByteArray(r.size);
                    send({ t: 'region', base: r.base.toString(), size: r.size, prot: r.protection }, data);
                } catch (e) {
                    send({ t: 'log', m: 'dump failed ' + r.base + ' ' + e });
                }
            }
        }
    });
    send('[*] WinHttpSendRequest body-dump hook installed');
})();
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
    ap.add_argument("--seconds", type=float, default=420.0)
    ap.add_argument("--out", default="captured/coder_module")
    args = ap.parse_args()
    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

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
                    if m.get("type") != "send":
                        return
                    payload = m.get("payload") or {}
                    if payload.get("t") == "log":
                        print(f"[{pid}] {payload['m']}", flush=True)
                    elif payload.get("t") == "region" and d:
                        base = int(payload["base"], 16)
                        name = out_dir / f"mod_{base:08x}_{payload['size']:x}.bin"
                        name.write_bytes(d)
                        head = bytes(d[:16])
                        tag = "PE" if head[:2] == b"MZ" else ""
                        print(f"[{pid}] saved {name.name} {payload['size']} bytes prot={payload['prot']} {tag}", flush=True)

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
