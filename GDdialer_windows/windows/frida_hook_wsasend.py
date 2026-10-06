"""Dump WSASend buffers and resolve which module sends the portal requests.

send() was easy to read, but the service transmits portal traffic through
WSASend, whose payload lives in a WSABUF array. This reads that array, prints
the buffer contents, and names the module that owns the return address so the
encoder can be located in the right image.
"""

from __future__ import annotations

import argparse
import subprocess
import time

import frida

TARGETS = ["ESurfingSvr.exe", "ESurfingClient.exe"]

JS = r"""
function modOf(addr) {
    try {
        const m = Process.findModuleByAddress(addr);
        if (m === null) return 'unknown';
        return m.name + '+0x' + addr.sub(m.base).toString(16);
    } catch (e) { return 'err'; }
}
function ascii(p, n) {
    try {
        const b = new Uint8Array(p.readByteArray(n));
        let s = '';
        for (let i = 0; i < b.length; i++) s += (b[i] >= 32 && b[i] < 127) ? String.fromCharCode(b[i]) : '.';
        return s;
    } catch (e) { return '(na)'; }
}
function raw(p, n) {
    try {
        const b = new Uint8Array(p.readByteArray(n));
        return Array.from(b).map(x => x.toString(16).padStart(2, '0')).join(' ');
    } catch (e) { return '(na)'; }
}
let total = 0;
(function () {
    const ws2 = Process.getModuleByName('ws2_32.dll');
    const target = ws2.getExportByName('WSASend');
    Interceptor.attach(target, {
        onEnter(args) {
            total++;
            if (total > 120) return;
            try {
                const count = args[2].toInt32();
                const ret = this.returnAddress;
                const mod = modOf(ret);
                let out = 'WSASend ret=' + ret + ' (' + mod + ') bufs=' + count;
                for (let i = 0; i < count && i < 4; i++) {
                    const len = args[1].add(i * 8).readU32();
                    const ptr = args[1].add(i * 8 + 4).readPointer();
                    out += '\n   buf' + i + ' len=' + len + '  ' + JSON.stringify(ascii(ptr, Math.min(len, 260)));
                    if (len > 0 && len < 400) out += '\n      hex=' + raw(ptr, Math.min(len, 96));
                }
                send(out);
            } catch (e) { send('WSASend err ' + e); }
        }
    });
    send('[*] WSASend hooked');
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
