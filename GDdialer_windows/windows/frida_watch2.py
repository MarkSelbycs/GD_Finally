"""Hook the coder entry point and capture a full plaintext -> body pair.

Previous run showed only XXTEA firing (13698 block calls), which looks like the
module container being decrypted rather than a portal body being encoded. This
hooks the coder dispatch function at 0x4156b0 (whose input should be the request
XML) plus RC4/XXTEA/hex, and logs only the first few calls of each so the actual
portal-encoding stage order becomes visible.
"""

from __future__ import annotations

import argparse
import subprocess
import time

import frida

MODULE = "ESurfingSvr.exe"
IMAGE_BASE = 0x400000
LIMIT = 24  # log at most this many calls per hook

JS = r"""
const MODULE = 'ESurfingSvr.exe';
const IMAGE_BASE = 0x400000;
const LIMIT = %d;
let base = null;
try { base = Process.getModuleByName(MODULE).base; } catch (e) { send('[!] ' + e); }
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

const counts = {};
function hook(addr, name, argc, wantDump) {
    counts[name] = 0;
    Interceptor.attach(va(addr), {
        onEnter(args) {
            if (counts[name] >= LIMIT) return;
            counts[name]++;
            const out = ['##### ' + name + ' #' + counts[name] + ' #####'];
            for (let i = 0; i < argc; i++) {
                let v; try { v = args[i]; } catch (e) { continue; }
                let s = '  arg' + i + ' = ' + v;
                try { if (!v.isNull() && v.compare(0x10000) > 0 && v.compare(0x80000000) < 0) s += '  [' + ascii(v, 72) + ']'; } catch (e) {}
                out.push(s);
            }
            for (const i of wantDump) {
                try {
                    const v = args[i];
                    if (!v.isNull() && v.compare(0x10000) > 0 && v.compare(0x80000000) < 0) {
                        out.push('  -- mem arg' + i + ' --');
                        out.push(hd(v, 160));
                    }
                } catch (e) {}
            }
            send(out.join('\n'));
        }
    });
    send('[*] hooked ' + name + ' @0x' + addr.toString(16));
}

if (base !== null) {
    hook(0x4156b0, 'CODER-ENTRY', 6, [0, 1, 2]);
    hook(0x425e80, 'RC4', 4, [0, 1]);
    hook(0x4260b0, 'XXTEA', 4, [0, 1]);
    hook(0x4266e0, 'HEX', 3, [0, 1]);
    send('[*] base=' + base);
}
""" % LIMIT


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


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--seconds", type=float, default=600.0)
    args = ap.parse_args()

    hooked = {}
    deadline = time.time() + args.seconds
    print(f"watching {MODULE} for {args.seconds:g}s", flush=True)
    while time.time() < deadline:
        current = set(pids_of(MODULE))
        for pid in current - set(hooked):
            try:
                session = frida.attach(pid)
                script = session.create_script(JS)

                def on_message(message, data, pid=pid):
                    kind = message.get("type")
                    if kind in ("send", "log"):
                        print(f"[pid {pid}] " + str(message.get("payload")), flush=True)
                    elif kind == "error":
                        print(f"[pid {pid}] script error: " + str(message.get("description")), flush=True)

                script.on("message", on_message)
                script.load()
                hooked[pid] = session
                print(f"[+] attached pid {pid}", flush=True)
            except Exception as exc:  # noqa: BLE001
                print(f"[!] attach {pid} failed: {exc}", flush=True)
        for pid in list(hooked):
            if pid not in current:
                print(f"[-] pid {pid} exited", flush=True)
                try:
                    hooked[pid].detach()
                except Exception:
                    pass
                del hooked[pid]
        time.sleep(1.0)
    for pid, session in hooked.items():
        try:
            session.detach()
        except Exception:
            pass
    print("done", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
