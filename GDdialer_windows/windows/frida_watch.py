"""Watch for ESurfingSvr.exe and attach Frida every time it (re)starts.

The service restarts whenever the client reconnects, which detaches any hook.
This polls for the process, attaches as soon as it appears, installs the coder
hooks, and re-attaches after each restart, so a reconnect cannot escape capture.

Usage:
    python frida_watch.py --seconds 600
"""

from __future__ import annotations

import argparse
import subprocess
import sys
import time

import frida

IMAGE_BASE = 0x400000
MODULE = "ESurfingSvr.exe"

JS = r"""
const MODULE = 'ESurfingSvr.exe';
const IMAGE_BASE = 0x400000;
let base = null;
try { base = Process.getModuleByName(MODULE).base; } catch (e) { send('[!] module missing: ' + e); }
function va(v) { return base.add(v - IMAGE_BASE); }

function ascii(p, n) {
    try {
        if (p.isNull()) return '';
        const b = new Uint8Array(p.readByteArray(n));
        let s = '';
        for (let i = 0; i < b.length; i++) s += (b[i] >= 32 && b[i] < 127) ? String.fromCharCode(b[i]) : '.';
        return s;
    } catch (e) { return '(na)'; }
}
function hd(p, n) {
    try { if (p.isNull()) return '(null)'; return hexdump(p, { length: n, ansi: false }); }
    catch (e) { return '(na)'; }
}
function report(tag, args, n) {
    const lines = ['##### ' + tag + ' #####'];
    for (let i = 0; i < n; i++) {
        let v; try { v = args[i]; } catch (e) { continue; }
        let s = '  arg' + i + ' = ' + v;
        try { if (!v.isNull() && v.compare(0x10000) > 0 && v.compare(0x80000000) < 0) s += '  [' + ascii(v, 64) + ']'; } catch (e) {}
        lines.push(s);
    }
    for (let i = 0; i < Math.min(n, 3); i++) {
        try {
            const v = args[i];
            if (!v.isNull() && v.compare(0x10000) > 0 && v.compare(0x80000000) < 0) {
                lines.push('  -- mem arg' + i + ' --');
                lines.push(hd(v, 128));
            }
        } catch (e) {}
    }
    send(lines.join('\n'));
}

if (base !== null) {
    Interceptor.attach(va(0x425e80), { onEnter(a) { report('RC4 0x425e80', a, 4); } });
    Interceptor.attach(va(0x4260b0), { onEnter(a) {
        report('XXTEA 0x4260b0', a, 4);
        try { send('  n = ' + a[2].toInt32()); } catch (e) {}
    } });
    Interceptor.attach(va(0x4266e0), { onEnter(a) { report('HEX 0x4266e0', a, 3); } });
    send('[*] hooks installed, base=' + base);
}
"""


def pids_of(name: str):
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


def on_message(message, data):
    kind = message.get("type")
    if kind in ("send", "log"):
        payload = message.get("payload")
        print(payload, flush=True)
    elif kind == "error":
        print("[script error]", message.get("description"), flush=True)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--seconds", type=float, default=600.0)
    args = ap.parse_args()

    hooked: dict[int, object] = {}
    deadline = time.time() + args.seconds
    print(f"watching {MODULE} for {args.seconds:g}s ...", flush=True)
    while time.time() < deadline:
        current = set(pids_of(MODULE))
        for pid in current - set(hooked):
            try:
                session = frida.attach(pid)
                script = session.create_script(JS)
                script.on("message", on_message)
                script.load()
                hooked[pid] = (session, script)
                print(f"[+] attached pid {pid}", flush=True)
            except Exception as exc:  # noqa: BLE001
                print(f"[!] attach {pid} failed: {exc}", flush=True)
        for pid in list(hooked):
            if pid not in current:
                print(f"[-] pid {pid} exited", flush=True)
                try:
                    hooked[pid][0].detach()
                except Exception:
                    pass
                del hooked[pid]
        time.sleep(1.0)
    for pid, (session, _s) in hooked.items():
        try:
            session.detach()
        except Exception:
            pass
    print("done", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
