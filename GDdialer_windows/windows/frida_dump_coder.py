"""Dump the memory-loaded module (around 0x22xxxxx) that assembles portal bodies.

The WinHttp backtrace showed the request-assembly/encoding frames living in a
memory region Frida could not resolve to a module (addresses 0x2231bf1,
0x225727a, ...). That is the downloaded algorithm module loaded via the custom
loader. This enumerates executable/readable ranges in that span and exfiltrates
them so the module can be analysed offline.
"""

from __future__ import annotations

import argparse
import subprocess
import time
from pathlib import Path

import frida

JS = r"""
(function () {
    const ranges = Process.enumerateRanges('r--');
    const out = [];
    for (const r of ranges) {
        const b = r.base;
        const n = b.toUInt32 ? b.toUInt32() : 0;
        if (n >= 0x2000000 && n < 0x3000000) {
            out.push({ base: b.toString(), size: r.size, prot: r.protection });
        }
    }
    send({ t: 'ranges', ranges: out });
    for (const r of ranges) {
        const base = ptr(r.base);
        try {
            const data = base.readByteArray(r.size);
            send({ t: 'region', base: r.base, size: r.size, prot: r.protection }, data);
        } catch (e) {
            send({ t: 'gap', base: r.base, size: r.size, msg: '' + e });
        }
    }
    send({ t: 'done' });
})();
"""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="captured/coder_region")
    args = ap.parse_args()
    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    out = subprocess.check_output(
        ["tasklist", "/fi", "imagename eq ESurfingSvr.exe", "/fo", "csv", "/nh"],
        text=True, errors="replace",
    )
    pids = [int(l.split(",")[1].strip('"')) for l in out.splitlines() if "ESurfingSvr" in l]
    if not pids:
        print("ESurfingSvr.exe not running")
        return 1
    pid = pids[0]
    print("attaching pid", pid)

    session = frida.attach(pid)
    regions = {}

    def on_message(message, data):
        if message.get("type") != "send":
            return
        payload = message.get("payload") or {}
        if payload.get("t") == "ranges":
            for r in payload["ranges"]:
                print(f"  range base={r['base']} size=0x{r['size']:x} prot={r['prot']}")
        elif payload.get("t") == "region" and data:
            regions[payload["base"]] = (payload["size"], payload["prot"], data)
        elif payload.get("t") == "gap":
            print(f"  gap @ {payload['base']} size=0x{payload['size']:x}: {payload['msg']}")
        elif payload.get("t") == "done":
            print(f"received {len(regions)} regions")

    script = session.create_script(JS)
    script.on("message", on_message)
    script.load()
    time.sleep(6)

    for base in sorted(regions):
        size, prot, data = regions[base]
        b = int(base, 16)
        name = out_dir / f"region_{b:08x}_{size:x}.bin"
        name.write_bytes(data)
        print(f"saved {name} ({size} bytes, prot={prot})")

    session.detach()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
