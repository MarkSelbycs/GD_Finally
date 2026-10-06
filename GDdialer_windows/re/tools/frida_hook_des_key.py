"""Hook the module's DES primitive (module+0x5c78) and dump the key bytes.

0x5c78 applies IP to the data (ecx) and PC-1 to the key material held at edx.
Reading the 8 bytes at edx for each call reveals the DES key schedule inputs.
"""

from __future__ import annotations

import argparse
import subprocess
import time

import frida

TARGETS = ["ESurfingSvr.exe", "ESurfingClient.exe"]

JS = r"""
const SIG = [0x55,0x8b,0xec,0x83,0x7d,0x0c,0x01,0x75,0x05,0xe8,0x33,0x04,0x00,0x00,0xff,0x75,0x10,0xff,0x75,0x0c,0xff,0x75,0x08,0xe8];
function findBase() {
    for (const r of Process.enumerateRanges('r-x')) {
        if (r.size > 0x4000000) continue;
        let data; try { data = r.base.readByteArray(Math.min(r.size, 0x4000000)); } catch (e) { continue; }
        if (data === null) continue;
        const m = new Uint8Array(data);
        outer:
        for (let i = 0; i + SIG.length < m.length; i++) {
            if (m[i] !== SIG[0]) continue;
            for (let k = 1; k < SIG.length; k++) { if (m[i+k] !== SIG[k]) continue outer; }
            const base = r.base.add(i - 0x8585);
            try { if (base.readU16() === 0x5A4D) return base; } catch (e) {}
        }
    }
    return null;
}
function hx(p, n) { try { const b=new Uint8Array(p.readByteArray(n)); return Array.from(b).map(x=>x.toString(16).padStart(2,'0')).join(' '); } catch(e){ return '(na)'; } }
let base = null, seen = {};
function install() {
    if (base !== null) return true;
    base = findBase();
    if (base === null) return false;
    send('[*] base=' + base);
    // 0x5c78: ecx = data, edx = key material pointer
    Interceptor.attach(base.add(0x5c78), {
        onEnter(args) {
            const ctx = this.context;
            const keyp = ctx.edx, datap = ctx.ecx;
            let k = '';
            try { k = hx(keyp, 8); } catch (e) { k = '(na)'; }
            let sig = String(keyp) + '|' + k;
            if (!seen[sig]) {
                seen[sig] = 1;
                send('KEY@' + keyp + ' = ' + k + '\n     data@' + datap + ' = ' + hx(datap, 8));
            }
        }
    });
    // 0x5e5b: the big DES round function
    Interceptor.attach(base.add(0x5e5b), {
        onEnter(args) {
            const ctx = this.context;
            let sig = 'r' + String(ctx.edx);
            if (!seen[sig]) {
                seen[sig] = 1;
                send('ROUND data@' + ctx.ecx + ' = ' + hx(ctx.ecx, 8) + '   state@' + ctx.edx + ' = ' + hx(ctx.edx, 16));
            }
        }
    });
    // 0x6b65 encoder entry: also dump the state it will use
    send('[*] hooked 0x5c78 / 0x5e5b');
    return true;
}
if (!install()) { const iv = setInterval(function(){ if (install()) clearInterval(iv); }, 60); }
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
    while time.time() < deadline:
        current = set()
        for name in TARGETS:
            current.update(pids_of(name))
        for pid in current - hooked:
            try:
                session = frida.attach(pid)
                sc = session.create_script(JS)
                sc.on("message", lambda m, d, pid=pid: print(f"[{pid}] " + str(m.get("payload")), flush=True))
                sc.load()
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
