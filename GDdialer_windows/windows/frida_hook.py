"""Attach Frida to ESurfingSvr.exe and dump the coder arguments at runtime.

Static analysis established the three primitives inside ESurfingSvr.exe:

    0x425E80  RC4          (256-byte S-box on the stack)
    0x4260B0  XXTEA        (delta 0x9E3779B9)
    0x4266E0  hex encode   (allocates 2n+1)

The key array is stored XOR-obfuscated and restored at runtime, so the real key
and the exact layer order can only be read while the service is dialing. This
hooks all three and dumps their arguments (and the memory they point at), which
reveals the real key, the plaintext and the ciphertext in one go.

Usage:
    python frida_hook.py                 # hook until Ctrl+C
    python frida_hook.py --seconds 180
"""

from __future__ import annotations

import argparse
import sys
import time

import frida

IMAGE_BASE = 0x400000

JS = r"""
const MODULE = 'ESurfingSvr.exe';
const IMAGE_BASE = 0x400000;

let base = null;
try {
    base = Process.getModuleByName(MODULE).base;
} catch (e) {
    console.log('[!] module not found: ' + e);
}

function va(v) { return base.add(v - IMAGE_BASE); }

function safeHexdump(p, n) {
    try {
        if (p.isNull()) return '(null)';
        return hexdump(p, { length: n, ansi: false });
    } catch (e) {
        return '(unreadable: ' + e + ')';
    }
}

function ascii(p, n) {
    try {
        if (p.isNull()) return '';
        const b = new Uint8Array(p.readByteArray(n));
        let s = '';
        for (let i = 0; i < b.length; i++) {
            s += (b[i] >= 32 && b[i] < 127) ? String.fromCharCode(b[i]) : '.';
        }
        return s;
    } catch (e) {
        return '(unreadable)';
    }
}

function dumpArgs(tag, args, count) {
    console.log('\n===== ' + tag + ' @ ' + new Date().toISOString() + ' =====');
    for (let i = 0; i < count; i++) {
        let v = null;
        try { v = args[i]; } catch (e) { continue; }
        let line = '  arg' + i + ' = ' + v;
        try {
            if (!v.isNull() && v.compare(0x10000) > 0 && v.compare(0x80000000) < 0) {
                line += '   [' + ascii(v, 48) + ']';
            }
        } catch (e) {}
        console.log(line);
    }
    for (let i = 0; i < Math.min(count, 3); i++) {
        try {
            const v = args[i];
            if (!v.isNull() && v.compare(0x10000) > 0 && v.compare(0x80000000) < 0) {
                console.log('  --- mem @ arg' + i + ' ---');
                console.log(safeHexdump(v, 96));
            }
        } catch (e) {}
    }
}

function hookRC4() {
    Interceptor.attach(va(0x425e80), {
        onEnter(args) {
            console.log('\n##### RC4 #####');
            dumpArgs('RC4', args, 4);
        }
    });
    console.log('[*] hooked RC4   0x425e80');
}

function hookXXTEA() {
    Interceptor.attach(va(0x4260b0), {
        onEnter(args) {
            console.log('\n##### XXTEA #####');
            dumpArgs('XXTEA', args, 4);
            try {
                const n = args[2].toInt32();
                console.log('  n (rounds param) = ' + n);
            } catch (e) {}
        }
    });
    console.log('[*] hooked XXTEA 0x4260b0');
}

function hookHex() {
    Interceptor.attach(va(0x4266e0), {
        onEnter(args) {
            console.log('\n##### HEX #####');
            dumpArgs('HEX', args, 3);
        }
    });
    console.log('[*] hooked HEX    0x4266e0');
}

if (base !== null) {
    hookRC4();
    hookXXTEA();
    hookHex();
    console.log('[*] module base = ' + base);
} else {
    console.log('[!] cannot hook without module base');
}
"""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--seconds", type=float, default=300.0)
    ap.add_argument("--process", default="ESurfingSvr.exe")
    args = ap.parse_args()

    try:
        session = frida.attach(args.process)
    except Exception as exc:  # noqa: BLE001
        print("attach failed:", exc)
        return 1
    print("attached to", args.process)

    script = session.create_script(JS)

    def on_message(message, data):
        kind = message.get("type")
        if kind in ("send", "log"):
            print(message.get("payload"))
        elif kind == "error":
            print("[script error]", message.get("description"))
            print(message.get("stack", ""))

    script.on("message", on_message)
    script.load()
    print(f"hooks installed; running for {args.seconds:g}s (Ctrl+C to stop)")
    deadline = time.time() + args.seconds
    try:
        while time.time() < deadline:
            time.sleep(0.5)
    except KeyboardInterrupt:
        print("\nstopping")
    try:
        session.detach()
    except Exception:
        pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
