"""Fetch the portal algorithm module the same way the original client does.

Discovery
---------
During a dial the client sends a *plaintext* request with an all-zero Algo-ID:

    POST /ticket.cgi?wlanacip=..&wlanuserip=..&... HTTP/1.1
    User-Agent: CCTP/WinSVR5/1068
    Algo-ID: 00000000-0000-0000-0000-000000000000
    Client-ID: <client id>
    CDC-Checksum: <md5 of body>
    CDC-SchoolId / CDC-Domain / CDC-Area: ...
    Content-Length: 38

    tarce log algo auto compstr null value

The server answers with a container:

    001@<64 hex chars = 32-byte key>$<Algo-ID>]<compressed+encrypted payload>

Every later request then carries that Algo-ID, so this module is exactly the
encoder used for the portal bodies.

Usage
-----
    python fetch_module.py --ip 121.8.177.212
    python fetch_module.py --ip 121.8.177.212 --out captured/module.bin
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import urllib.error
import urllib.request
from pathlib import Path

BODY = b"tarce log algo auto compstr null value"
ZERO_ALGO = "00000000-0000-0000-0000-000000000000"
UA = "CCTP/WinSVR5/1068"

DEFAULT_PARAMS = {
    "wlanacip": "183.3.151.148",
    "wlanuserip": "172.17.104.130",
    "clientip": "172.17.104.130",
    "wlanacname": "SISE",
    "clientmac": "a4:fa:76:44:ba:e8",
    "paip": "10.88.88.88",
    "vlan": "100.0",
    "iarmdst": "www.189.cn/",
}


def load_defaults():
    """Take wlan parameters from portal_config.json when present."""
    path = Path("portal_config.json")
    if not path.exists():
        return dict(DEFAULT_PARAMS)
    try:
        cfg = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return dict(DEFAULT_PARAMS)
    params = dict(DEFAULT_PARAMS)
    for key in params:
        value = cfg.get("ticket_params", {}).get(key)
        if value:
            params[key] = str(value)
    return params


def parse_container(blob: bytes):
    at = blob.find(b"@")
    dl = blob.find(b"$", at + 1)
    rb = blob.find(b"]", dl + 1)
    if not (0 <= at < 8 and at < dl < rb < 200):
        return None
    return {
        "magic": blob[:at].decode("latin1"),
        "key_hex": blob[at + 1:dl].decode("latin1"),
        "algo_id": blob[dl + 1:rb].decode("latin1"),
        "payload": blob[rb + 1:],
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ip", default="121.8.177.212", help="portal server ip")
    ap.add_argument("--out", default="captured/module_fetch.bin")
    ap.add_argument("--client-id", default="1009758f-89f4-413c-929b-c5e0e35b0d54")
    ap.add_argument("--school-id", default="1099")
    ap.add_argument("--domain", default="sise.cn")
    ap.add_argument("--area", default="020")
    ap.add_argument("--timeout", type=float, default=15.0)
    args = ap.parse_args()

    params = load_defaults()
    query = "&".join(f"{k}={v}" for k, v in params.items())
    url = f"http://{args.ip}:7001/ticket.cgi?{query}"

    headers = {
        "User-Agent": UA,
        "Algo-ID": ZERO_ALGO,
        "Client-ID": args.client_id,
        "CDC-Checksum": hashlib.md5(BODY).hexdigest(),
        "CDC-SchoolId": args.school_id,
        "CDC-Domain": args.domain,
        "CDC-Area": args.area,
        "Content-Length": str(len(BODY)),
        "Connection": "close",
        "Host": f"{args.ip}:7001",
    }
    print(f"POST {url}")
    print(f"Algo-ID: {ZERO_ALGO}")
    print(f"body: {BODY!r}")

    request = urllib.request.Request(url, data=BODY, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(request, timeout=args.timeout) as response:
            blob = response.read()
            print("HTTP", response.status, "bytes", len(blob))
            for name, value in response.headers.items():
                if name.lower().startswith(("error", "server", "content-type")):
                    print(f"  {name}: {value}")
    except urllib.error.HTTPError as exc:
        blob = exc.read()
        print("HTTP", exc.code, "bytes", len(blob))
    except urllib.error.URLError as exc:
        print("network error:", exc.reason)
        return 1

    container = parse_container(blob)
    if not container:
        print("response is not a module container; head:", blob[:120])
        out = Path(args.out)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_bytes(blob)
        print("saved raw response to", out)
        return 1

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(blob)
    payload = container["payload"]
    payload_path = out.with_name(out.stem + "_payload.bin")
    payload_path.write_bytes(payload)
    print("\ncontainer parsed:")
    print("  magic   :", container["magic"])
    print("  key     :", container["key_hex"], f"({len(container['key_hex'])//2} bytes)")
    print("  Algo-ID :", container["algo_id"])
    print("  payload :", len(payload), "bytes ->", payload_path)
    print(f"  saved container -> {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
