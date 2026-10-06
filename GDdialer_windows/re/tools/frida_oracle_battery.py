"""Run a systematic battery against the AutoZSM encoder oracle.

Feeds crafted XML requests and records (plaintext, body) pairs so the encoder's
structure (field serialization + block/stream transform) can be derived.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import time
from pathlib import Path

import frida

TARGETS = ["ESurfingSvr.exe", "ESurfingClient.exe"]
OUT = Path("oracle_battery.jsonl")

JS = Path("oracle_js.js").read_text(encoding="utf-8") if Path("oracle_js.js").exists() else r"""
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
function cstr(p) {
    try { const b = new Uint8Array(p.readByteArray(8192)); let s=''; for (let i=0;i<b.length;i++){ if(b[i]===0) break; s+=String.fromCharCode(b[i]); } return s; }
    catch (e) { return '(na)'; }
}
let base = null;
function install() {
    if (base !== null) return true;
    base = findBase();
    if (base === null) return false;
    send('[*] module base = ' + base);
    const fn = new NativeFunction(base.add(0x6b65), 'pointer', ['pointer']);
    rpc.exports.encode = function (xml) {
        const p = Memory.allocUtf8String(xml);
        return cstr(fn(p));
    };
    send('[*] oracle ready');
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


DECL = '<?xml version="1.0" encoding="UTF-8"?><request>'


def battery():
    cases = []
    # 1. single field with varying value length
    for n in range(0, 9):
        cases.append((f"field_A_{n}", f"{DECL}<a>{'A' * n}</a></request>"))
    # 2. varying value length on a numeric field
    for n in (0, 1, 2, 3, 4, 8, 16, 32, 64):
        cases.append((f"reason_len_{n}", f"{DECL}<reason>{'9' * n}</reason></request>"))
    # 3. two fields
    cases.append(("two_fields", f"{DECL}<reason>7</reason><ticket>X</ticket></request>"))
    cases.append(("two_fields_b", f"{DECL}<reason>7</reason><ticket>Y</ticket></request>"))
    # 4. empty request and bare
    cases.append(("empty", f"{DECL}</request>"))
    cases.append(("bare_no_decl", "<request></request>"))
    # 5. same field, different single char
    for ch in "ABCZ":
        cases.append((f"one_char_{ch}", f"{DECL}<a>{ch}</a></request>"))
    # 6. non-xml text
    cases.append(("plain_text", "HELLO"))
    cases.append(("empty_str", ""))
    return cases


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--seconds", type=float, default=120.0)
    args = ap.parse_args()
    deadline = time.time() + args.seconds
    scripts = {}
    ready = None
    while time.time() < deadline and ready is None:
        current = set()
        for name in TARGETS:
            current.update(pids_of(name))
        for pid in current - set(scripts):
            try:
                session = frida.attach(pid)
                sc = session.create_script(JS)
                sc.on("message", lambda m, d: None)
                sc.load()
                scripts[pid] = sc
            except Exception:
                pass
        for pid, sc in scripts.items():
            try:
                probe = f"{DECL}</request>"
                out = sc.exports_sync.encode(probe)
                if out.startswith("C853A996"):
                    ready = (pid, sc)
                    break
            except Exception:
                pass
        if ready is None:
            time.sleep(0.3)
    if ready is None:
        print("oracle not ready", flush=True)
        return 1
    pid, sc = ready
    print(f"oracle on pid {pid}", flush=True)
    rows = []
    for label, xml in battery():
        try:
            out = sc.exports_sync.encode(xml)
        except Exception as exc:  # noqa: BLE001
            print(f"  {label:20} ERR {exc}", flush=True)
            continue
        rows.append({"label": label, "xml": xml, "out": out})
        print(f"  {label:22} in={len(xml):4} out={len(out)//2:4}B  {out[:48]}", flush=True)
    OUT.write_text("\n".join(json.dumps(r) for r in rows), encoding="utf-8")
    print(f"saved {len(rows)} rows -> {OUT}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
