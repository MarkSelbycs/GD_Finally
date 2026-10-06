"""Tianyi campus dialer using the Enet phone protocol.

This is a Python reimplementation of the flow used by the user's own
LandLeg Java client (phone protocol, no zsm/XXTEA encoding):

    challenge : POST http://enet.10000.gd.cn:10001/client/challenge
    login     : POST http://enet.10000.gd.cn:10001/client/login
    keepalive : GET  http://enet.10000.gd.cn:8001/hbservice/client/active
    logout    : POST http://enet.10000.gd.cn:10001/client/logout

Signature (uppercase MD5):

    authenticator = MD5(clientip + nasip + mac + timestamp + secret)
    login adds the challenge: MD5(clientip + nasip + mac + timestamp + challenge + secret)

Usage:
    python enet_dialer.py --user <account> [--password <pwd>] [--interval 15]
    python enet_dialer.py --logout --user <account>
"""

from __future__ import annotations

import argparse
import getpass
import hashlib
import json
import re
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Optional

CHALLENGE_URL = "http://enet.10000.gd.cn:10001/client/challenge"
LOGIN_URL = "http://enet.10000.gd.cn:10001/client/login"
ACTIVE_URL = "http://enet.10000.gd.cn:8001/hbservice/client/active"
LOGOUT_URL = "http://enet.10000.gd.cn:10001/client/logout"
REDIRECT_PROBE = "http://www.baidu.com"

SECRET = "Eshore!@#"
ISWIFI = "4060"


class EnetError(RuntimeError):
    pass


def md5_upper(text: str) -> str:
    return hashlib.md5(text.encode("utf-8")).hexdigest().upper()


def local_ipv4() -> str:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect(("223.5.5.5", 80))
        return sock.getsockname()[0]
    except OSError:
        try:
            return socket.gethostbyname(socket.gethostname())
        except OSError:
            return ""
    finally:
        sock.close()


def local_mac() -> str:
    try:
        output = subprocess.check_output(
            ["getmac", "/fo", "csv", "/nh"],
            text=True,
            stderr=subprocess.DEVNULL,
        )
    except (OSError, subprocess.SubprocessError):
        return ""
    for line in output.splitlines():
        value = line.split(",", 1)[0].strip().strip('"')
        if value and value.upper() != "N/A" and value != "00-00-00-00-00-00":
            return value.replace(":", "-").upper()
    return ""


def discover_nasip(timeout: float = 8.0) -> str:
    """Read wlanacip from the captive-portal redirect of a plain HTTP request."""
    request = urllib.request.Request(REDIRECT_PROBE, method="GET")
    opener = urllib.request.build_opener(NoRedirect)
    try:
        opener.open(request, timeout=timeout)
    except urllib.error.HTTPError as exc:
        location = exc.headers.get("Location", "")
        found = _wlanacip_from(location)
        if found:
            return found
    except (urllib.error.URLError, OSError):
        pass
    return ""


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _wlanacip_from(location: str) -> str:
    if not location:
        return ""
    query = urllib.parse.urlsplit(location).query
    for key, value in urllib.parse.parse_qsl(query):
        if key.lower() == "wlanacip":
            return value
    match = re.search(r"wlanacip=([^&]+)", location)
    return match.group(1) if match else ""


class EnetDialer:
    def __init__(
        self,
        username: str,
        password: str = "",
        clientip: str = "",
        mac: str = "",
        nasip: str = "",
        iswifi: str = ISWIFI,
        secret: str = SECRET,
        timeout: float = 10.0,
        content_type: str = "application/json",
    ):
        self.username = username
        self.password = password
        self.clientip = clientip or local_ipv4()
        self.mac = mac or local_mac()
        self.nasip = nasip
        self.iswifi = iswifi
        self.secret = secret
        self.timeout = timeout
        self.content_type = content_type
        self.timestamp = ""

    def _fresh_timestamp(self) -> str:
        self.timestamp = str(int(time.time() * 1000))
        return self.timestamp

    def _authenticator(self, extra: str = "") -> str:
        return md5_upper(self.clientip + self.nasip + self.mac + self.timestamp + extra + self.secret)

    def _post(self, url: str, payload: dict) -> dict:
        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        request = urllib.request.Request(
            url,
            data=body,
            headers={"Content-Type": self.content_type, "Connection": "close"},
            method="POST",
        )
        return self._read(request)

    def _get(self, url: str, params: dict) -> dict:
        full = url + "?" + urllib.parse.urlencode(params)
        request = urllib.request.Request(full, method="GET", headers={"Connection": "close"})
        return self._read(request)

    def _read(self, request: urllib.request.Request) -> dict:
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                raw = response.read()
        except urllib.error.HTTPError as exc:
            raw = exc.read()
            if not raw:
                raise EnetError(f"HTTP {exc.code} with empty body") from exc
        except urllib.error.URLError as exc:
            raise EnetError(f"network error: {exc.reason}") from exc
        text = raw.decode("utf-8", errors="replace").strip()
        try:
            return json.loads(text)
        except ValueError as exc:
            raise EnetError(f"server returned non-JSON: {text[:160]!r}") from exc

    def challenge(self) -> str:
        self._fresh_timestamp()
        payload = {
            "username": self.username,
            "clientip": self.clientip,
            "nasip": self.nasip,
            "mac": self.mac,
            "iswifi": self.iswifi,
            "timestamp": self.timestamp,
            "authenticator": self._authenticator(),
        }
        result = self._post(CHALLENGE_URL, payload)
        if str(result.get("rescode")) != "0":
            raise EnetError(f"challenge failed: {result}")
        code = result.get("challenge", "")
        if not code:
            raise EnetError(f"challenge response lacks challenge: {result}")
        return code

    def login(self) -> dict:
        verify_code = self.challenge()
        self._fresh_timestamp()
        payload = {
            "username": self.username,
            "password": self.password,
            "verificationcode": "",
            "clientip": self.clientip,
            "nasip": self.nasip,
            "mac": self.mac,
            "iswifi": self.iswifi,
            "timestamp": self.timestamp,
            "authenticator": self._authenticator(verify_code),
        }
        result = self._post(LOGIN_URL, payload)
        return result

    def keepalive(self) -> dict:
        self._fresh_timestamp()
        params = {
            "username": self.username,
            "clientip": self.clientip,
            "nasip": self.nasip,
            "mac": self.mac,
            "timestamp": self.timestamp,
            "authenticator": self._authenticator(),
        }
        return self._get(ACTIVE_URL, params)

    def logout(self) -> dict:
        self._fresh_timestamp()
        payload = {
            "clientip": self.clientip,
            "nasip": self.nasip,
            "mac": self.mac,
            "timestamp": self.timestamp,
            "authenticator": self._authenticator(),
        }
        return self._post(LOGOUT_URL, payload)


def _ok(result: dict) -> bool:
    return str(result.get("rescode")) == "0"


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Enet phone-protocol campus dialer")
    parser.add_argument("--user", required=True, help="broadband account")
    parser.add_argument("--password", help="broadband password (prompted if omitted)")
    parser.add_argument("--nasip", default="", help="wlanacip / AC address (auto-detected if omitted)")
    parser.add_argument("--clientip", default="", help="local IPv4 (auto-detected if omitted)")
    parser.add_argument("--mac", default="", help="local MAC (auto-detected if omitted)")
    parser.add_argument("--iswifi", default=ISWIFI)
    parser.add_argument("--interval", type=float, default=15.0, help="keepalive interval in minutes")
    parser.add_argument("--logout", action="store_true", help="only log out")
    parser.add_argument("--once", action="store_true", help="do one keepalive then exit")
    args = parser.parse_args(argv)

    password = args.password
    if not args.logout and password is None:
        password = getpass.getpass("Password: ")

    nasip = args.nasip or discover_nasip()
    if not nasip:
        print("warning: could not detect wlanacip; pass --nasip explicitly", file=sys.stderr)

    dialer = EnetDialer(
        username=args.user,
        password=password or "",
        clientip=args.clientip,
        mac=args.mac,
        nasip=nasip,
    )
    print(f"Client IP: {dialer.clientip}")
    print(f"MAC:       {dialer.mac}")
    print(f"NASIP:     {dialer.nasip or '(unknown)'}")

    try:
        if args.logout:
            result = dialer.logout()
            print(f"logout -> {result}")
            return 0 if _ok(result) else 1

        result = dialer.login()
        print(f"login -> {result}")
        if not _ok(result):
            print("login rejected by server", file=sys.stderr)
            return 1
        print("connected")

        if args.once:
            print(f"keepalive -> {dialer.keepalive()}")
            return 0

        interval = max(args.interval, 1.0) * 60.0
        print(f"press Ctrl+C to log out; keepalive every {args.interval:g} min")
        while True:
            time.sleep(interval)
            try:
                keep = dialer.keepalive()
                print(f"keepalive -> {keep}")
                if not _ok(keep):
                    print("keepalive rejected; retrying login")
                    again = dialer.login()
                    print(f"relogin -> {again}")
            except EnetError as exc:
                print(f"keepalive error: {exc}", file=sys.stderr)
    except KeyboardInterrupt:
        print("\nlogging out...")
    except EnetError as exc:
        print(f"failed: {exc}", file=sys.stderr)
        return 1
    finally:
        try:
            print(f"logout -> {dialer.logout()}")
        except EnetError as exc:
            print(f"logout warning: {exc}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
