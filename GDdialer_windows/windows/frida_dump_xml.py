"""Dump the complete XML node structures built by DialServer's 0xf1b8.

The function at DialServer+0xf1b8 receives node structures containing UTF-16
strings (XML element names/values). This dumps arg0 (and pointers it references)
fully so the portal request XML can be reconstructed offline.
"""

from __future__ import annotations

import argparse
import subprocess
import time
from pathlib import Path

import frida

JS = r"""
function utf16le(p, n) {
    try {
        const b = new Uint8Array(p.readByteArray(n));
        let s = '';
        for (let i = 0; i + 1 < b.length; i += 2) {
            const c = b[i] | (b[i+1] << 8);
            s += (c >= 32 && c < 127) ? String.fromCharCode(c) : '.';
        }
        return s;
    } catch (e) { return '(na)'; }
}
function ascii(p, n) {
    try { const b = new Uint8Array(p.readByteArray(n)); let s=''; for (let i=0;i<b.length;i++) s += (b[i]>=32&&b[i]<127)?String.fromCharCode(b[i]):'.'; return s; }
    catch (e) { return '(na)'; }
}
let n = 0;
Interceptor.attach(ptr(0x1000f1b8), {
    onEnter(args) {
        n++;
        if (n > 8) return;
        send('=== call #' + n + ' arg0=' + args[0] + ' arg1=' + args[1] + ' arg2=' + args[2]);
        // dump arg0 raw (768 bytes) as binary so we can reconstruct
        try {
            const data = args[0].readByteArray(768);
            send({ t: 'dump', id: n, base: args[0].toString() }, data);
        } catch (e) { send('dump err ' + e); }
        send('  utf16 arg0: ' + utf16le(args[0], 512));
        send('  ascii arg0: ' + ascii(args[0], 512));
    }
});
send('[*] hooked DialServer+0xf1b8');
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
    ap.add_argument("--out", default="captured/xml_nodes")
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
                    if payload.get("t") == "dump" and d:
                        name = out_dir / f"node_{payload['id']}_{payload['base'].replace('0x','')}.bin"
                        name.write_bytes(d)
                        print(f"[{pid}] saved {name.name} ({len(d)} bytes)", flush=True)
                    else:
                        print(f"[{pid}] {payload.get('payload') if isinstance(payload, dict) and 'payload' in payload else payload}", flush=True)

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
