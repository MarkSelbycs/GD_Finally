"""At portal-send time, scan the process memory for the plaintext XML.

The body is produced somewhere between the request builder and webio.dll, and
the coder entry we hooked only handled the module container. Rather than guess
further, this hooks WSASend and, the moment a portal POST goes out, searches
readable memory for the request XML ("<?xml", "<ticket>", "<local-time>").

Finding the plaintext pairs it with the ciphertext we already captured, which
settles the cipher.
"""

from __future__ import annotations

import argparse
import subprocess
import time

import frida

TARGETS = ["ESurfingSvr.exe", "ESurfingClient.exe"]

JS = r"""
const NEEDLES = ['<?xml version', '<local-time>', '<ticket>', '<user-agent>'];
function scanOnce(tag) {
    let hits = 0;
    const ranges = Process.enumerateRanges('r--');
    for (const r of ranges) {
        if (r.size > 8 * 1024 * 1024) continue;
        let base = r.base;
        try {
            const size = r.size;
            const buf = base.readByteArray(size);
            if (buf === null) continue;
            const u8 = new Uint8Array(buf);
            for (const needle of NEEDLES) {
                const nb = [];
                for (let i = 0; i < needle.length; i++) nb.push(needle.charCodeAt(i));
                outer:
                for (let i = 0; i + nb.length <= u8.length; i++) {
                    for (let j = 0; j < nb.length; j++) if (u8[i + j] !== nb[j]) continue outer;
                    hits++;
                    if (hits > 6) return hits;
                    const start = Math.max(0, i - 32);
                    const end = Math.min(u8.length, i + 400);
                    let s = '';
                    for (let k = start; k < end; k++) s += (u8[k] >= 32 && u8[k] < 127) ? String.fromCharCode(u8[k]) : '.';
                    send(tag + ' ' + needle + ' @' + base.add(i) + ' :: ' + s);
                    i += 64;
                }
            }
        } catch (e) {}
    }
    return hits;
}

let armed = false;
(function () {
    const ws2 = Process.getModuleByName('ws2_32.dll');
    const target = ws2.getExportByName('WSASend');
    Interceptor.attach(target, {
        onEnter(args) {
            if (armed) return;
            try {
                const count = args[2].toInt32();
                for (let i = 0; i < count && i < 2; i++) {
                    const len = args[1].add(i * 8).readU32();
                    const ptr = args[1].add(i * 8 + 4).readPointer();
                    if (len < 8 || len > 100000) continue;
                    const head = new Uint8Array(ptr.readByteArray(Math.min(len, 40)));
                    let s = '';
                    for (let k = 0; k < head.length; k++) s += String.fromCharCode(head[k]);
                    if (s.indexOf('cgi') >= 0 && (s.indexOf('POST') >= 0 || s.indexOf('ticket') >= 0)) {
                        armed = true;
                        send('[send] ' + s.replace(/[^\x20-\x7e]/g, '.'));
                        setTimeout(() => { const h = scanOnce('[scan]'); send('[scan] hits=' + h); armed = false; }, 30);
                    }
                }
            } catch (e) {}
        }
    });
    send('[*] scanning hook installed');
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
