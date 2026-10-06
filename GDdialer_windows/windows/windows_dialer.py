from __future__ import annotations

import getpass
import json
import socket
import subprocess
import threading
import uuid
from pathlib import Path

from portal_minimal import PortalClient, PortalError, PortalIdentity, PortalEndpoints
from zsm_codec import PythonZsmCodec


ROOT = Path(__file__).resolve().parent
CONFIG_PATH = ROOT / "portal_config.json"


def load_config() -> tuple[PortalEndpoints, PortalIdentity]:
    with CONFIG_PATH.open("r", encoding="utf-8") as stream:
        config = json.load(stream)
    return PortalEndpoints(**config["endpoints"]), PortalIdentity(**config["identity"])


def _local_identity(identity: PortalIdentity) -> PortalIdentity:
    identity.host_name = identity.host_name or socket.gethostname()
    if not identity.ipv4:
        try:
            identity.ipv4 = socket.gethostbyname(identity.host_name)
        except OSError:
            identity.ipv4 = ""
    if not identity.mac:
        try:
            output = subprocess.check_output(
                ["getmac", "/fo", "csv", "/nh"],
                text=True,
                stderr=subprocess.DEVNULL,
            )
            for line in output.splitlines():
                value = line.split(",", 1)[0].strip().strip('"')
                if value and value != "N/A":
                    identity.mac = value.replace("-", ":").lower()
                    break
        except (OSError, subprocess.SubprocessError):
            pass
    if not identity.client_id:
        identity.client_id = str(uuid.uuid4()).upper()
        try:
            config = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
            config.setdefault("identity", {})["client_id"] = identity.client_id
            CONFIG_PATH.write_text(
                json.dumps(config, ensure_ascii=False, indent=2) + "\n",
                encoding="utf-8",
            )
        except (OSError, ValueError):
            pass
    return identity


def main() -> int:
    try:
        endpoints, identity = load_config()
        identity = _local_identity(identity)
    except Exception as exc:
        print(f"Configuration error: {exc}")
        return 1

    print("China Telecom portal dialer")
    print("Only login, keep-alive, and logout are enabled.")
    print(f"Host: {identity.host_name}")
    print(f"IPv4: {identity.ipv4 or 'unknown'}")
    print(f"MAC: {identity.mac or 'unknown'}")
    print(f"Client-ID: {identity.client_id}")
    username = input("Username: ").strip()
    password = getpass.getpass("Password: ")
    if not username or not password:
        print("Username and password are required.")
        return 2

    client = PortalClient(endpoints, identity, PythonZsmCodec(), timeout=12)
    stop = threading.Event()
    try:
        session = client.login(username, password)
        print("Login succeeded.")
        print(f"Keep-alive interval: {session.interval}s")
        print("Press Ctrl+C to logout and exit.")
        client.keepalive_loop(stop)
    except KeyboardInterrupt:
        print("\nLogging out...")
    except PortalError as exc:
        print(f"Dial failed: {exc}")
        return 1
    finally:
        stop.set()
        try:
            client.logout()
        except PortalError as exc:
            print(f"Logout warning: {exc}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
