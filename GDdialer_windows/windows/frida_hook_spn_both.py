"""Hook the SPN codec (0x426200) in BOTH ESurfingSvr.exe and ESurfingClient.exe.

The body-encoding process kept failing to attach as ESurfingSvr.exe, so watch the
GUI process too: whichever process actually runs the portal encoder will print
the real key1/key2 and the plaintext/ciphertext pair.
"""

from __future__ import annotations

import argparse
import subprocess
import time

import frida

TARGETS = ["ESurfingSvr.exe", "ESurfingClient.exe"]

JS = r"""
function hx(p, n) {
    try { const b = new Uint8Array(p.readByteArray(n)); return Array.from(b).map(x => x.toString(16).padStart(2,'0')).join(' '); }
    catch (e) { return '(na)'; }
}
function ascii(p, n) {
    try { const b = new Uint8Array(p.readByteArray(n)); let s=''; for (let i=0;i<b.length;i++) s += (b[i]>=32&&b[i]<127)?String.fromCharCode(b[i]):'.'; return s; }
    catch (e) { return '(na)'; }
}
const mod = Process.enumerateModules().find(m => /ESurfing/i.test(m.name));
if (!mod) { send('[!] module not found'); } else {
    send('[*] module=' + mod.name + ' base=' + mod.base);
    let n = 0;
    Interceptor.attach(mod.base.add(0x26200), {
        onEnter(args) {
            n++;
            if (n > 8) return;
            const k1 = args[0], k2 = args[1], data = args[2], len = args[3].toInt32();
            send('=== SPN #' + n + ' len=' + len);
            send('  key1: ' + hx(k1, 16) + '  [' + ascii(k1, 16) + ']');
            send('  key2: ' + hx(k2, 16) + '  [' + ascii(k2, 16) + ']');
            if (len > 0 && len < 0x10000) send('  in : ' + hx(data, Math.min(len, 48)));
            this.dataPtr = data; this.len = len;
        },
        onLeave(ret) {
            try { if (this.len > 0 && this.len < 0x10000) send('  out: ' + hx(this.dataPtr, Math.min(this.len, 48))); } catch (e) {}
        }
    });
    send('[*] hooked +0x26200');
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
    ap.add_argument("--seconds", type=float, default=300.0)
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
