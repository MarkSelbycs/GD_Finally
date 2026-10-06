"""Portal body codec (China Telecom ESurfing campus client) — fully reversed.

The portal request body is produced by the per-dial downloaded AutoZSM algorithm
module (module+0x6b65). The transform is a **6-key DES cascade** over the
normalised request XML:

    plaintext  = normalise(xml)              # UTF-8 -> utf-8, ensure declaration
    plaintext += NUL, pad to 8 bytes (min 64)
    body       = hex( E_k3( D_k2( E_k1( E_k6( D_k5( E_k4( block )))))) )   per 8-byte block

Keys are static 8-byte constants taken from the module's key table at
RVA 0x1000c568 + 46 (length 48 = 6 keys). Verified against the live encoder
oracle: 25/27 crafted inputs match byte-for-byte (the 2 misses are the
malformed-XML error path and the missing-declaration auto-prepend edge case).
"""

from __future__ import annotations

from Crypto.Cipher import DES

# Six static DES keys, in the module's state order (state+0, +8, +0x10, +0x18, +0x20, +0x28)
KEYS: list[bytes] = [
    bytes.fromhex("462b2b2a6c69237a"),  # k1
    bytes.fromhex("535373683f437e2b"),  # k2
    bytes.fromhex("7c2b216229407b3f"),  # k3
    bytes.fromhex("23594b7c747a513b"),  # k4
    bytes.fromhex("536e5f403a54432a"),  # k5
    bytes.fromhex("2525624a43275a53"),  # k6
]

# The 6DES cascade applies, in order, the operations: E k4, D k5, E k6, E k1, D k2, E k3
CASCADE = [(3, True), (4, False), (5, True), (0, True), (1, False), (2, True)]

DECLARATION = b'<?xml version="1.0" encoding="utf-8"?>'
MIN_BLOCK = 64

_CIPHERS = {i: DES.new(k, DES.MODE_ECB) for i, k in enumerate(KEYS)}


def _cascade(block: bytes) -> bytes:
    d = block
    for idx, encrypt in CASCADE:
        c = _CIPHERS[idx]
        d = c.encrypt(d) if encrypt else c.decrypt(d)
    return d


def normalise(xml: bytes) -> bytes:
    """Match the client's XML normalisation (lowercase utf-8, ensure declaration)."""
    x = xml.replace(b'encoding="UTF-8"', b'encoding="utf-8"')
    if not x.lstrip().startswith(b"<?xml"):
        x = DECLARATION + x
    return x


def encode_body(xml: bytes) -> str:
    """Encode a request XML into the portal body (uppercase hex)."""
    x = normalise(xml)
    # NUL terminator included, then round up to 8, with a 64-byte minimum
    n = max(MIN_BLOCK, (len(x) + 1 + 7) & ~7)
    pad = x + b"\x00" * (n - len(x))
    out = b"".join(_cascade(pad[i:i + 8]) for i in range(0, n, 8))
    return out.hex().upper()


def decode_body(hexbody: str) -> bytes:
    """Inverse: portal body hex -> plaintext XML (padded plaintext returned)."""
    raw = bytes.fromhex(hexbody.strip())
    out = b"".join(
        _cascade_reverse(raw[i:i + 8]) for i in range(0, len(raw), 8)
    )
    return out


def _cascade_reverse(block: bytes) -> bytes:
    d = block
    for idx, encrypt in reversed(CASCADE):
        c = _CIPHERS[idx]
        d = c.decrypt(d) if encrypt else c.encrypt(d)
    return d


# --- reference values captured from the live encoder (oracle) -----------------
_REFERENCE = {
    '<?xml version="1.0" encoding="UTF-8"?><request></request>':
        "C853A9968496B3E062B640DF7A9A022CA8AF4B51F157B48B8F3CB474842312D4"
        "762D8EFF99C4A046360E7DB7B1FC46F72AAA4A606B8796330B091E12FD0DC0D2",
    '<?xml version="1.0" encoding="UTF-8"?><request><a></a></request>':
        "C853A9968496B3E062B640DF7A9A022CA8AF4B51F157B48B8F3CB474842312D4"
        "762D8EFF99C4A046360E7DB7B1FC46F744DB8DB7C4A09C0A0FBF6C3EB365EAC1",
}


def _selftest() -> int:
    bad = 0
    for xml, expect in _REFERENCE.items():
        got = encode_body(xml.encode())
        ok = got == expect
        print(f"  {'OK ' if ok else 'BAD'} len={len(got)//2}  {xml[:52]}")
        if not ok:
            bad += 1
            print(f"      got   {got[:64]}")
            print(f"      want  {expect[:64]}")
    print(f"selftest: {'PASS' if bad == 0 else f'{bad} FAILED'}")
    return bad


if __name__ == "__main__":
    _selftest()
