"""Capture WinHttpSendRequest bodies from every ESurfing process.

Used together with the ESurfingSvr.exe patch that turns the SPN cipher into a
raw keystream generator: the captured body then IS the keystream.
"""

from __future__ import annotations

import argparse
import subprocess
import time

import frida

TARGETS = ["ESurfingSvr.exe", "ESurfingClient.exe"]

JS = r"""
function tryHook() {
    let wh = null;
    try { wh = Process.getModuleByName('winhttp.dll'); } catch (e) { return false; }
    if (wh === null) return false;
    let fn = null;
    try { fn = wh.getExportByName('WinHttpSendRequest'); } catch (e) { return false; }
    Interceptor.attach(fn, {
        onEnter(args) {
            const len = args[4].toInt32();
            if (len <= 0 || len > 0x100000) return;
            try {
                const b = new Uint8Array(args[3].readByteArray(Math.min(len, 2048)));
                let s = '';
                for (let i = 0; i < b.length; i++) s += String.fromCharCode(b[i]);
                send('BODY len=' + len + ' :: ' + s);
            } catch (e) { send('body read err ' + e); }
        }
    });
    send('[*] winhttp hooked');
    return true;
}
if (!tryHook()) {
    const iv = setInterval(function () { if (tryHook()) clearInterval(iv); }, 30);
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
    ap.add_argument("--seconds", type=float, default=120.0)
    args = ap.parse_args()
    hooked = set()
    deadline = time.time() + args.seconds
    print(f"capturing for {args.seconds:g}s", flush=True)
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
