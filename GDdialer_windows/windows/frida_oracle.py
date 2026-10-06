"""Call the AutoZSM module encoder (module+0x6b65) as an oracle.

The encoder takes a null-terminated XML string and returns a pointer to an
ASCII hex string (the portal body). Invoking it directly with crafted inputs
produces an unlimited set of controlled (plaintext, ciphertext) pairs.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import time
from pathlib import Path

import frida

TARGETS = ["ESurfingSvr.exe", "ESurfingClient.exe"]
OUT = Path("oracle_pairs.jsonl")

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
function cstr(p) {
    try {
        const b = new Uint8Array(p.readByteArray(4096));
        let s = '';
        for (let i = 0; i < b.length; i++) { if (b[i] === 0) break; s += String.fromCharCode(b[i]); }
        return s;
    } catch (e) { return '(na)'; }
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
        const out = fn(p);
        return cstr(out);
    };
    send('[*] encoder oracle ready');
    return true;
}
if (!install()) {
    const iv = setInterval(function () { if (install()) clearInterval(iv); }, 60);
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


def build_xml(fields: list[tuple[str, str]]) -> str:
    parts = ['<?xml version="1.0" encoding="UTF-8"?><request>\r\n']
    for k, v in fields:
        parts.append(f"\r\n<{k}>{v}</{k}>\r\n")
    parts.append("\r\n</request>")
    return "".join(parts)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--seconds", type=float, default=120.0)
    args = ap.parse_args()
    scripts = {}

    deadline = time.time() + args.seconds
    print(f"watching {TARGETS} for {args.seconds:g}s", flush=True)
    ready = None
    while time.time() < deadline:
        current = set()
        for name in TARGETS:
            current.update(pids_of(name))
        for pid in current - set(scripts):
            try:
                session = frida.attach(pid)
                script = session.create_script(JS)
                script.on("message", lambda m, d: print("[js] " + str(m.get("payload")), flush=True))
                script.load()
                scripts[pid] = script
                print(f"[+] attached {pid}", flush=True)
            except Exception:
                pass
        for pid in list(scripts):
            if pid not in current:
                scripts.pop(pid, None)
        if ready is None:
            for pid, sc in scripts.items():
                try:
                    # probe the oracle with the known request
                    xml = build_xml([
                        ("reason", "7"),
                        ("local-time", "2026-10-06 03:20:30"),
                        ("ticket", "8e51f4ce78867e69a2c77d950b97ec63"),
                        ("client-id", "1009758f-89f4-413c-929b-c5e0e35b0d54"),
                        ("user-agent", "CCTP/WinSVR5/1068"),
                    ])
                    out = sc.exports_sync.encode(xml)
                    print(f"[{pid}] PROBE xml={len(xml)}B -> {out[:80]}", flush=True)
                    if out.startswith("C853A996"):
                        ready = (pid, sc)
                        print("*** ORACLE VERIFIED ***", flush=True)
                        break
                except Exception as exc:  # noqa: BLE001
                    pass
        if ready:
            break
        time.sleep(0.2)

    if ready is None:
        print("oracle not ready", flush=True)
        return 1

    pid, sc = ready
    pairs = []

    def emit(label, xml):
        try:
            out = sc.exports_sync.encode(xml)
        except Exception as exc:  # noqa: BLE001
            print(f"  {label}: ERR {exc}", flush=True)
            return
        pairs.append({"label": label, "xml": xml, "out": out})
        print(f"  {label:34} in={len(xml):4}B out={len(out)//2:4}B  {out[:56]}", flush=True)

    print("\n=== oracle samples ===", flush=True)
    emit("baseline", build_xml([
        ("reason", "7"), ("local-time", "2026-10-06 03:20:30"),
        ("ticket", "8e51f4ce78867e69a2c77d950b97ec63"),
        ("client-id", "1009758f-89f4-413c-929b-c5e0e35b0d54"),
        ("user-agent", "CCTP/WinSVR5/1068")]))
    emit("ticket_changed", build_xml([
        ("reason", "7"), ("local-time", "2026-10-06 03:20:30"),
        ("ticket", "00000000000000000000000000000000"),
        ("client-id", "1009758f-89f4-413c-929b-c5e0e35b0d54"),
        ("user-agent", "CCTP/WinSVR5/1068")]))
    emit("time_changed", build_xml([
        ("reason", "7"), ("local-time", "2026-10-06 03:20:31"),
        ("ticket", "8e51f4ce78867e69a2c77d950b97ec63"),
        ("client-id", "1009758f-89f4-413c-929b-c5e0e35b0d54"),
        ("user-agent", "CCTP/WinSVR5/1068")]))
    emit("reason_changed", build_xml([
        ("reason", "8"), ("local-time", "2026-10-06 03:20:30"),
        ("ticket", "8e51f4ce78867e69a2c77d950b97ec63"),
        ("client-id", "1009758f-89f4-413c-929b-c5e0e35b0d54"),
        ("user-agent", "CCTP/WinSVR5/1068")]))
    emit("one_field", build_xml([("reason", "7")]))
    emit("empty_request", '<?xml version="1.0" encoding="UTF-8"?><request></request>')
    emit("short_a", '<?xml version="1.0" encoding="UTF-8"?><request>A</request>')
    emit("short_aa", '<?xml version="1.0" encoding="UTF-8"?><request>AA</request>')
    emit("short_aab", '<?xml version="1.0" encoding="UTF-8"?><request>AAB</request>')
    emit("short_aabc", '<?xml version="1.0" encoding="UTF-8"?><request>AABC</request>')
    emit("long_aaa", '<?xml version="1.0" encoding="UTF-8"?><request>' + "A" * 64 + '</request>')

    with OUT.open("w", encoding="utf-8") as fh:
        for p in pairs:
            fh.write(json.dumps(p) + "\n")
    print(f"\nsaved {len(pairs)} pairs -> {OUT}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
