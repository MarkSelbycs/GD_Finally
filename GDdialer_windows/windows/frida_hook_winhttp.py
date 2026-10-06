"""Hook WinHttpSendRequest/WriteData to find the request-assembly code.

WSASend is buried inside webio.dll; the application actually hands the encoded
body to WinHTTP. WinHttpSendRequest(hRequest, headers, headersLen, lpOptional,
optionalLen, totalLen, ctx) receives the body as lpOptional (args[3]). Hooking
it gives the body pointer and, crucially, the *caller* in ESurfingSvr.exe plus a
full backtrace that shows the encoder frames.
"""

from __future__ import annotations

import argparse
import subprocess
import time

import frida

TARGETS = ["ESurfingSvr.exe"]

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
let shots = 0;
function backtrace() {
    const lines = [];
    try {
        const bt = Thread.backtrace(this.context, Backtracer.ACCURATE);
        for (const a of bt) {
            lines.push('    ' + a + '  (' + modOf(a) + ')');
        }
    } catch (e) { lines.push('    backtrace err ' + e); }
    return lines.join('\n');
}
(function () {
    let winhttp = null;
    try { winhttp = Process.getModuleByName('winhttp.dll'); } catch (e) {}
    if (winhttp === null) { send('[!] winhttp.dll not loaded'); return; }
    for (const name of ['WinHttpSendRequest', 'WinHttpWriteData']) {
        let addr = null;
        try { addr = winhttp.getExportByName(name); } catch (e) { continue; }
        if (addr === null) continue;
        Interceptor.attach(addr, {
            onEnter(args) {
                shots++;
                if (shots > 8) return;
                send('==== ' + name + ' #' + shots + ' ====');
                send('  ret=' + this.returnAddress + ' (' + modOf(this.returnAddress) + ')');
                if (name === 'WinHttpSendRequest') {
                    const opt = args[3];
                    const len = args[4].toInt32();
                    send('  lpOptional=' + opt + ' optionalLen=' + len);
                    if (len > 0 && len < 2000) {
                        send('  body: ' + JSON.stringify(ascii(opt, Math.min(len, 400))));
                    }
                } else {
                    const buf = args[1];
                    const len = args[2].toInt32();
                    send('  buf=' + buf + ' len=' + len);
                    if (len > 0 && len < 2000) send('  body: ' + JSON.stringify(ascii(buf, Math.min(len, 400))));
                }
                if (shots <= 2) send(backtrace.call(this));
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
