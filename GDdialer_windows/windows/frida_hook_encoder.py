"""Hook the AutoZSM module encoder (module+0x6b65) and capture full XML->output.

0x6b65 receives the plaintext XML and returns the encoded body. Capturing both
sides of this call gives exact (plaintext, ciphertext) pairs for reversing the
portal body transform.
"""

from __future__ import annotations

import argparse
import subprocess
import time

import frida

TARGETS = ["ESurfingSvr.exe", "ESurfingClient.exe"]

JS = r"""
const SIG = [0x55,0x8b,0xec,0x83,0x7d,0x0c,0x01,0x75,0x05,0xe8,0x33,0x04,0x00,0x00,0xff,0x75,0x10,0xff,0x75,0x0c,0xff,0x75,0x08,0xe8];
function hx(p, n) {
    try { const b = new Uint8Array(p.readByteArray(n)); return Array.from(b).map(x=>x.toString(16).padStart(2,'0')).join(' '); }
    catch (e) { return '(na)'; }
}
function ascii(p, n) {
    try { const b = new Uint8Array(p.readByteArray(n)); let s=''; for (let i=0;i<b.length;i++) s += (b[i]>=32&&b[i]<127)?String.fromCharCode(b[i]):'.'; return s; }
    catch (e) { return '(na)'; }
}
function cstr(p, max) {
    try {
        const b = new Uint8Array(p.readByteArray(max));
        let s = '';
        for (let i = 0; i < b.length; i++) { if (b[i] === 0) break; s += String.fromCharCode(b[i]); }
        return s;
    } catch (e) { return '(na)'; }
}
let found = null, n = 0;
function scan() {
    if (found !== null) return true;
    for (const r of Process.enumerateRanges('r-x')) {
        if (r.size > 0x4000000) continue;
        let data; try { data = r.base.readByteArray(Math.min(r.size, 0x4000000)); } catch (e) { continue; }
        if (data === null) continue;
        const m = new Uint8Array(data);
        outer:
        for (let i = 0; i + SIG.length < m.length; i++) {
            if (m[i] !== SIG[0]) continue;
            for (let k = 1; k < SIG.length; k++) { if (m[i+k] !== SIG[k]) continue outer; }
            let base = r.base.add(i - 0x8585);
            try { if (base.readU16() !== 0x5A4D) continue; } catch (e) { continue; }
            found = base;
            send('[*] module base = ' + base);
            // 0x6b65 = encoder(xml) -> encoded
            Interceptor.attach(base.add(0x6b65), {
                onEnter(args) {
                    this.xml = args[0];
                    n++;
                    if (n > 6) return;
                    send('=== ENCODE #' + n + ' xml@' + args[0]);
                    send('  XML: ' + cstr(args[0], 1400));
                },
                onLeave(ret) {
                    if (n > 6) return;
                    try {
                        send('  OUT@' + ret + ': ' + hx(ret, 96));
                        send('  OUTascii: ' + ascii(ret, 96));
                    } catch (e) { send('  out err ' + e); }
                }
            });
            send('[*] hooked encoder +0x6b65');
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
    ap.add_argument("--seconds", type=float, default=150.0)
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
            except Exception:
                pass
        for pid in list(hooked):
            if pid not in current:
                hooked.discard(pid)
        time.sleep(0.1)
    print("done", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
