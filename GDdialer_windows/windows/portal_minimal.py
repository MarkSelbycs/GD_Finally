"""Minimal client for the campus portal login lifecycle.

The original client sends XML request documents through a pluggable codec.
This module keeps only ticket acquisition, authentication, keep-alive, and
termination. Shared-device inspection is intentionally not part of the API.
"""

from __future__ import annotations

import argparse
import dataclasses
import hashlib
import html
import json
import re
import subprocess
import threading
from datetime import datetime
from typing import Dict, Mapping, Optional, Protocol, Sequence
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qsl, quote, urlencode, urlsplit, urlunsplit
from urllib.request import Request, urlopen
import xml.etree.ElementTree as ET

from zsm_codec import PythonZsmCodec


class PortalError(RuntimeError):
    """Raised when a portal request or portal response fails."""


class BodyCodec(Protocol):
    """Encode request XML and decode the matching portal response."""

    def encode(self, xml_body: str) -> bytes:
        ...

    def decode(self, body: bytes) -> str:
        ...


class PlainXmlCodec:
    """Codec useful for local protocol tests and plain XML deployments."""

    def encode(self, xml_body: str) -> bytes:
        return xml_body.encode("utf-8")

    def decode(self, body: bytes) -> str:
        return body.decode("utf-8-sig", errors="replace")


class CommandCodec:
    """Adapter for the original zsm encoder/decoder supplied externally.

    The command receives the operation name as argv[1]. Request XML is sent on
    stdin. It must write the encoded request or decoded response to stdout.
    """

    def __init__(self, command: Sequence[str]):
        if not command:
            raise ValueError("codec command must not be empty")
        self._command = list(command)

    def _run(self, operation: str, data: bytes) -> bytes:
        try:
            proc = subprocess.run(
                [*self._command, operation],
                input=data,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
        except OSError as exc:
            raise PortalError(f"cannot start codec command: {exc}") from exc
        if proc.returncode != 0:
            detail = proc.stderr.decode("utf-8", errors="replace").strip()
            raise PortalError(f"codec {operation} failed: {detail or proc.returncode}")
        return proc.stdout

    def encode(self, xml_body: str) -> bytes:
        return self._run("encode", xml_body.encode("utf-8"))

    def decode(self, body: bytes) -> str:
        return self._run("decode", body).decode("utf-8-sig", errors="replace")


@dataclasses.dataclass
class PortalEndpoints:
    """URLs returned by the portal configuration service."""

    ticket_url: str
    auth_url: str
    keep_url: str = ""
    term_url: str = ""
    state_url: str = ""
    query_url: str = ""
    ticket_params: Dict[str, str] = dataclasses.field(default_factory=dict)


@dataclasses.dataclass
class PortalIdentity:
    """Client identity values included in portal request XML."""

    user_agent: str = "CCTP/Linux32/2.2"
    client_id: str = ""
    host_name: str = ""
    ipv4: str = ""
    ipv6: str = ""
    mac: str = ""
    ostag: str = "linux32"
    algo_id: str = ""
    cdc_checksum: str = ""
    cdc_school_id: str = ""
    cdc_domain: str = ""
    cdc_area: str = ""

    def local_time(self) -> str:
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


@dataclasses.dataclass
class LoginSession:
    """State retained between login, keep-alive, and logout."""

    ticket: str
    endpoints: PortalEndpoints
    interval: int = 60
    expires: Optional[str] = None


class PortalClient:
    """Small stateful implementation of the three required operations."""

    def __init__(
        self,
        endpoints: PortalEndpoints,
        identity: PortalIdentity,
        codec: BodyCodec,
        *,
        timeout: float = 10.0,
        extra_headers: Optional[Mapping[str, str]] = None,
    ):
        self.endpoints = endpoints
        self.identity = identity
        self.codec = codec
        self.timeout = timeout
        self.extra_headers = dict(extra_headers or {})
        self.session: Optional[LoginSession] = None

    @staticmethod
    def _xml_escape(value: object) -> str:
        return html.escape(str(value), quote=True)

    def _request_xml(self, endpoint: str, xml_body: str) -> str:
        if not endpoint:
            raise PortalError("portal endpoint is empty")
        payload = self.codec.encode(xml_body)
        headers = {
            "Accept": "*/*",
            "Connection": "close",
            "User-Agent": self.identity.user_agent,
            "Client-ID": self.identity.client_id,
        }
        optional_headers = {
            "Algo-ID": self.identity.algo_id,
            "CDC-Checksum": self.identity.cdc_checksum or hashlib.md5(payload).hexdigest(),
            "CDC-SchoolId": self.identity.cdc_school_id,
            "CDC-Domain": self.identity.cdc_domain,
            "CDC-Area": self.identity.cdc_area,
        }
        headers.update({key: value for key, value in optional_headers.items() if value})
        headers.update(self.extra_headers)
        request = Request(endpoint, data=payload, headers=headers, method="POST")
        response_headers = {}
        try:
            with urlopen(request, timeout=self.timeout) as response:
                response_headers = dict(response.headers.items())
                body = response.read()
        except HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")
            error_code = exc.headers.get("Error-Code", "")
            raise PortalError(
                f"portal HTTP {exc.code} error-code={error_code}: {detail[:200]}"
            ) from exc
        except URLError as exc:
            raise PortalError(f"portal network error: {exc.reason}") from exc
        if not body:
            error_code = response_headers.get("Error-Code", "unknown")
            server_tag = response_headers.get("Server-Tag", "unknown")
            raise PortalError(
                f"portal returned an empty response: error-code={error_code}, server={server_tag}"
            )
        try:
            return self.codec.decode(body)
        except (ValueError, UnicodeError) as exc:
            content_type = response_headers.get("Content-Type", "unknown")
            preview = body[:160].decode("utf-8", errors="replace").replace("\r", " ").replace("\n", " ")
            raise PortalError(
                f"portal returned non-zsm data: content-type={content_type}, preview={preview!r}"
            ) from exc

    @staticmethod
    def _root(xml_body: str) -> ET.Element:
        try:
            return ET.fromstring(xml_body)
        except ET.ParseError as exc:
            raise PortalError(f"invalid portal XML response: {exc}") from exc

    @staticmethod
    def _find(root: ET.Element, *names: str) -> str:
        wanted = {name.lower() for name in names}
        for node in root.iter():
            if node.tag.rsplit("}", 1)[-1].lower() in wanted:
                return (node.text or "").strip()
        return ""

    @classmethod
    def _check_response(cls, xml_body: str) -> ET.Element:
        root = cls._root(xml_body)
        code = cls._find(root, "code", "error-code", "errorcode")
        if code and code not in {"0", "140000", "200"}:
            subcode = cls._find(root, "sub-error", "suberrcode", "sub-error-code")
            raise PortalError(f"portal rejected request: code={code} subcode={subcode}")
        return root

    def discover_endpoints(self, redirect_url: str) -> PortalEndpoints:
        """Discover portal URLs from the original config XML endpoint.

        The production gateway may return an HTML protection page first; in
        that case the XML parser raises a clear error and no credentials are
        sent. This method performs only the unauthenticated config request.
        """
        if not redirect_url:
            raise PortalError("portal redirect URL is empty")
        candidates = [redirect_url]
        if redirect_url.lower().endswith("/detect.html"):
            candidates.insert(0, redirect_url[:-len("detect.html")] + "index.cgi")
        body = b""
        last_error: Optional[BaseException] = None
        for candidate in candidates:
            request = Request(
                candidate,
                data=b"",
                headers={
                    "Accept": "*/*",
                    "Connection": "close",
                    "User-Agent": self.identity.user_agent,
                    "Client-ID": self.identity.client_id,
                },
                method="POST",
            )
            try:
                with urlopen(request, timeout=self.timeout) as response:
                    body = response.read()
                break
            except (HTTPError, URLError) as exc:
                last_error = exc
        else:
            if isinstance(last_error, HTTPError):
                raise PortalError(f"portal config HTTP {last_error.code}") from last_error
            raise PortalError(f"portal config network error: {last_error}") from last_error
        text = body.decode("utf-8-sig", errors="replace")
        config_match = re.search(r"<config\b.*?</config>", text, flags=re.IGNORECASE | re.DOTALL)
        if config_match:
            text = config_match.group(0)
        try:
            root = ET.fromstring(text)
        except ET.ParseError as exc:
            raise PortalError("portal config response is not config XML") from exc
        config = next(
            (node for node in root.iter() if node.tag.rsplit("}", 1)[-1].lower() == "config"),
            root,
        )
        values = {}
        for node in config.iter():
            name = node.tag.rsplit("}", 1)[-1].lower()
            if name in {"ticket-url", "query-url", "auth-url", "state-url", "state-interval"}:
                values[name] = (node.text or "").strip()
        if not values.get("ticket-url") or not values.get("auth-url"):
            raise PortalError("portal config XML lacks ticket-url or auth-url")
        self.endpoints = PortalEndpoints(
            ticket_url=values["ticket-url"],
            query_url=values.get("query-url", ""),
            auth_url=values["auth-url"],
            state_url=values.get("state-url", ""),
        )
        return self.endpoints

    def _ticket_endpoint(self) -> str:
        params = dict(self.endpoints.ticket_params)
        if not params:
            return self.endpoints.ticket_url
        if not params.get("wlanuserip"):
            params["wlanuserip"] = self.identity.ipv4
        if not params.get("clientip"):
            params["clientip"] = self.identity.ipv4
        if not params.get("clientmac"):
            params["clientmac"] = self.identity.mac
        parts = urlsplit(self.endpoints.ticket_url)
        query = dict(parse_qsl(parts.query, keep_blank_values=True))
        query.update({key: value for key, value in params.items() if value})
        encoded_query = []
        for key, value in query.items():
            if value:
                safe = ":/" if key in {"clientmac", "iarmdst", "portal_node"} else ""
                encoded_query.append(f"{quote(str(key), safe='')}={quote(str(value), safe=safe)}")
        return urlunsplit((parts.scheme, parts.netloc, parts.path, "&".join(encoded_query), parts.fragment))

    def request_ticket(self) -> str:
        """Obtain a ticket before authentication."""
        i = self.identity
        body = (
            '<?xml version="1.0" encoding="UTF-8"?>'
            "<request>"
            f"<host-name>{self._xml_escape(i.host_name)}</host-name>"
            f"<user-agent>{self._xml_escape(i.user_agent)}</user-agent>"
            f"<client-id>{self._xml_escape(i.client_id)}</client-id>"
            f"<ipv4>{self._xml_escape(i.ipv4)}</ipv4>"
            f"<ipv6>{self._xml_escape(i.ipv6)}</ipv6>"
            f"<mac>{self._xml_escape(i.mac)}</mac>"
            f"<local-time>{self._xml_escape(i.local_time())}</local-time>"
            f"<ostag>{self._xml_escape(i.ostag)}</ostag>"
            "</request>"
        )
        root = self._check_response(self._request_xml(self._ticket_endpoint(), body))
        ticket = self._find(root, "ticket")
        if not ticket:
            raise PortalError("ticket response did not contain <ticket>")
        return ticket

    def login(self, username: str, password: str) -> LoginSession:
        """Request a ticket and authenticate the supplied account."""
        i = self.identity
        ticket = self.request_ticket()
        body = (
            '<?xml version="1.0" encoding="UTF-8"?>'
            "<request>"
            f"<user-agent>{self._xml_escape(i.user_agent)}</user-agent>"
            f"<client-id>{self._xml_escape(i.client_id)}</client-id>"
            f"<userid>{self._xml_escape(username)}</userid>"
            f"<passwd>{self._xml_escape(password)}</passwd>"
            f"<ticket>{self._xml_escape(ticket)}</ticket>"
            f"<local-time>{self._xml_escape(i.local_time())}</local-time>"
            "</request>"
        )
        root = self._check_response(self._request_xml(self.endpoints.auth_url, body))
        response_ticket = self._find(root, "ticket") or ticket
        keep_url = self.session.endpoints.keep_url if self.session else self.endpoints.keep_url
        term_url = self.session.endpoints.term_url if self.session else self.endpoints.term_url
        keep_url = keep_url or self._find(root, "keep-url", "keepurl")
        term_url = term_url or self._find(root, "term-url", "termurl")
        session_endpoints = dataclasses.replace(
            self.endpoints,
            keep_url=keep_url,
            term_url=term_url,
        )
        interval_text = self._find(root, "interval", "keep-interval")
        try:
            interval = max(5, int(interval_text)) if interval_text else 60
        except ValueError:
            interval = 60
        session = LoginSession(
            ticket=response_ticket,
            endpoints=session_endpoints,
            interval=interval,
            expires=self._find(root, "expire", "expires") or None,
        )
        self.session = session
        return session

    def keepalive_once(self) -> bool:
        """Send one keep-alive request; no shared-device field is sent."""
        if self.session is None:
            raise PortalError("keepalive requires an active login session")
        i = self.identity
        body = (
            '<?xml version="1.0" encoding="UTF-8"?>'
            "<request>"
            f"<user-agent>{self._xml_escape(i.user_agent)}</user-agent>"
            f"<client-id>{self._xml_escape(i.client_id)}</client-id>"
            f"<ticket>{self._xml_escape(self.session.ticket)}</ticket>"
            f"<ipv4>{self._xml_escape(i.ipv4)}</ipv4>"
            f"<ipv6>{self._xml_escape(i.ipv6)}</ipv6>"
            f"<mac>{self._xml_escape(i.mac)}</mac>"
            f"<local-time>{self._xml_escape(i.local_time())}</local-time>"
            "</request>"
        )
        self._check_response(self._request_xml(self.session.endpoints.keep_url, body))
        return True

    def keepalive_loop(self, stop: threading.Event) -> None:
        """Keep the session alive until stop is set."""
        if self.session is None:
            raise PortalError("keepalive requires an active login session")
        while not stop.wait(self.session.interval):
            self.keepalive_once()

    def logout(self, reason: str = "client logout") -> bool:
        """Terminate the active portal session."""
        if self.session is None:
            return True
        i = self.identity
        body = (
            '<?xml version="1.0" encoding="UTF-8"?>'
            "<request>"
            f"<user-agent>{self._xml_escape(i.user_agent)}</user-agent>"
            f"<client-id>{self._xml_escape(i.client_id)}</client-id>"
            f"<ticket>{self._xml_escape(self.session.ticket)}</ticket>"
            f"<local-time>{self._xml_escape(i.local_time())}</local-time>"
            f"<reason>{self._xml_escape(reason)}</reason>"
            "</request>"
        )
        self._check_response(self._request_xml(self.session.endpoints.term_url, body))
        self.session = None
        return True


def _load_json(path: str) -> Dict[str, object]:
    with open(path, "r", encoding="utf-8") as stream:
        value = json.load(stream)
    if not isinstance(value, dict):
        raise ValueError("configuration must be a JSON object")
    return value


def _client_from_json(path: str, codec: BodyCodec) -> PortalClient:
    cfg = _load_json(path)
    endpoint_data = cfg.get("endpoints", {})
    identity_data = cfg.get("identity", {})
    if not isinstance(endpoint_data, dict) or not isinstance(identity_data, dict):
        raise ValueError("endpoints and identity must be JSON objects")
    endpoints = PortalEndpoints(**endpoint_data)
    identity = PortalIdentity(**identity_data)
    return PortalClient(endpoints, identity, codec)


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="minimal campus portal client")
    parser.add_argument("config", help="JSON file containing endpoints and identity")
    parser.add_argument("operation", choices=("login", "keepalive", "logout"))
    parser.add_argument("--username")
    parser.add_argument("--password")
    parser.add_argument("--ticket", help="ticket for keepalive/logout")
    parser.add_argument("--interval", type=int, default=60)
    parser.add_argument("--codec", choices=("zsm", "plain", "command"), default="zsm")
    parser.add_argument("--codec-command", nargs="+", help="external zsm codec command")
    args = parser.parse_args(argv)
    if args.codec == "zsm":
        codec: BodyCodec = PythonZsmCodec()
    elif args.codec == "plain":
        codec = PlainXmlCodec()
    else:
        if not args.codec_command:
            parser.error("--codec command requires --codec-command")
        codec = CommandCodec(args.codec_command)
    client = _client_from_json(args.config, codec)
    if args.operation == "login":
        if args.username is None or args.password is None:
            parser.error("login requires --username and --password")
        session = client.login(args.username, args.password)
        print(json.dumps(dataclasses.asdict(session), ensure_ascii=True))
    else:
        if not args.ticket:
            parser.error(f"{args.operation} requires --ticket")
        client.session = LoginSession(args.ticket, client.endpoints, interval=max(5, args.interval))
        if args.operation == "keepalive":
            client.keepalive_once()
        else:
            client.logout()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
