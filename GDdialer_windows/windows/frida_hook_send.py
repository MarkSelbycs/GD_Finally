"""Find the code that actually sends portal requests, via ws2_32!send.

The coder entry at 0x4156b0 only handled the module container, so the portal
body must be encoded (and sent) somewhere else. Hooking send/WSASend in the
service records, for every outbound buffer, the caller address and the first
bytes -- enough to identify the HTTP requests and then walk back to the encoder.
"""

from __future__ import annotations

import argparse
import subprocess
import time

import frida

TARGETS = ["ESurfingSvr.exe", "ESurfingClient.exe"]

JS = r"""
function ascii(p, n) {
    try {
        const b = new Uint8Array(p.readByteArray(n));
        let s = '';
        for (let i = 0; i < b.length; i++) s += (b[i] >= 32 && b[i] < 127) ? String.fromCharCode(b[i]) : '.';
        return s;
    } catch (e) { return '(na)'; }
}
let count = {};
let total = 0;
function report(tag, ret, buf, len) {
    total++;
    if (total > 400) return;
    const key = tag + ':' + ret;
    count[key] = (count[key] || 0) + 1;
    if (count[key] > 6) return;
    send(tag + ' len=' + len + ' ret=' + ret + '  ' + JSON.stringify(ascii(buf, Math.min(len, 200))));
}
(function () {
    const ws2 = Process.getModuleByName('ws2_32.dll');
    for (const name of ['send', 'WSASend', 'sendto']) {
        let addr = null;
        try { addr = ws2.getExportByName(name); } catch (e) { continue; }
        if (addr === null) continue;
        Interceptor.attach(addr, {
            onEnter(args) {
                try {
                    if (name === 'WSASend') {
                        const len = args[2].toInt32();
                        send('WSASend count=' + len + ' ret=' + this.returnAddress);
                    } else {
                        report(name, this.returnAddress, args[1], args[2].toInt32());
                    }
                } catch (e) {}
            }
        });
        send('[*] hooked ' + name + ' @' + addr);
    }
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
    ap.add_argument("--seconds", type=float, default=600.0)
    args = ap.parse_args()
    hooked = set()
    deadline = time.time() + args.seconds
    print(f"watching {TARGETS} for {args.seconds:g}s", flush=True)
    while time.time() < deadline:
        current = set()
        for t in TARGETS:
            current |= set(pids_of(t))
        for pid in current - hooked:
            try:
                session = frida.attach(pid)
                script = session.create_script(JS)
                script.on("message", lambda m, d, pid=pid: print(
                    f"[{pid}] " + str(m.get("payload")), flush=True) if m.get("type") in ("send", "log") else None)
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
