"""Scan process memory for the downloaded AutoZSM module, then hook its entry.

The algorithm module is memory-mapped at a random base on every dial and has no
exports, so locate it by its entry signature and hook 0x8585 (the module entry)
to capture the (input, mode, arg) triple and the produced output.
"""

from __future__ import annotations

import argparse
import subprocess
import time

import frida

TARGETS = ["ESurfingSvr.exe", "ESurfingClient.exe"]

JS = r"""
// 20-byte signature of the module entry (RVA 0x8585)
const SIG = [0x55,0x8b,0xec,0x83,0x7d,0x0c,0x01,0x75,0x05,0xe8,0x33,0x04,0x00,0x00,0xff,0x75,0x10,0xff,0x75,0x0c,0xff,0x75,0x08,0xe8];
function hx(p, n) {
    try { const b = new Uint8Array(p.readByteArray(n)); return Array.from(b).map(x=>x.toString(16).padStart(2,'0')).join(' '); }
    catch (e) { return '(na)'; }
}
function ascii(p, n) {
    try { const b = new Uint8Array(p.readByteArray(n)); let s=''; for (let i=0;i<b.length;i++) s += (b[i]>=32&&b[i]<127)?String.fromCharCode(b[i]):'.'; return s; }
    catch (e) { return '(na)'; }
}
let found = null;
function scan() {
    if (found !== null) return true;
    const ranges = Process.enumerateRanges('r-x');
    for (const r of ranges) {
        if (r.size > 0x4000000) continue;
        let data;
        try { data = r.base.readByteArray(Math.min(r.size, 0x4000000)); } catch (e) { continue; }
        if (data === null) continue;
        const m = new Uint8Array(data);
        outer:
        for (let i = 0; i + SIG.length < m.length; i++) {
            if (m[i] !== SIG[0]) continue;
            for (let k = 1; k < SIG.length; k++) { if (m[i+k] !== SIG[k]) continue outer; }
            const base = r.base.add(i - 0x8585);
            // verify the PE header sits at this base
            let ok = false;
            try { ok = base.readU16() === 0x5A4D; } catch (e) { ok = false; }
            if (!ok) continue;
            found = base;
            send('[*] module base = ' + base + '  (entry ' + r.base.add(i) + ', MZ ok)');
            const OFFS = [0x8585, 0x844f, 0x8245, 0x7a43, 0x6f9e, 0x6b65, 0x6f49,
                          0x7808, 0x6d87, 0x6f1b, 0x8298, 0x839f];
            for (const off of OFFS) {
                try {
                    Interceptor.attach(base.add(off), {
                        onEnter(args) {
                            let s = '=== +0x' + off.toString(16) + '  a0=' + args[0] +
                                    ' a1=' + args[1] + ' a2=' + args[2];
                            for (let k = 0; k < 3; k++) {
                                try {
                                    const v = args[k];
                                    if (!v.isNull() && v.compare(0x10000) > 0 && v.compare(0x7f000000) < 0) {
                                        s += '\n   a' + k + ' [' + ascii(v, 72) + ']';
                                    }
                                } catch (e) {}
                            }
                            send(s);
                        }
                    });
                } catch (e) { send('[!] hook +0x' + off.toString(16) + ' failed ' + e); }
            }
            send('[*] hooked ' + OFFS.length + ' module offsets');
            return true;
        }
    }
    return false;
}
if (!scan()) {
    const iv = setInterval(function () { if (scan()) clearInterval(iv); }, 60);
}
"""


def pids_of(name):
    try:
        out = subprocess.check_output(
            ["tasklist", "/fi", f"imagename eq {name}", "/fo", "csv", "/nh"],
            text=True, errors="replace",
        )
    except Exception:
        return []
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
    ap.add_argument("--seconds", type=float, default=240.0)
    args = ap.parse_args()
    hooked = set()
    deadline = time.time() + args.seconds
    print(f"watching {TARGETS} for {args.seconds:g}s", flush=True)
    while time.time() < deadline:
        current = set()
        for name in TARGETS:
            current.update(pids_of(name))
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
        time.sleep(0.1)
    print("done", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
