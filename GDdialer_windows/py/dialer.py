"""天翼校园网拨号器（Python 版，纯标准库，零依赖）。

只做三件事：登录 / 保活 / 登出。不含任何共享检测。

用法:
    python dialer.py                     # 交互提示账号+密码
    python dialer.py 12345607891          # 交互提示密码
    python dialer.py 12345607891  -p 密码
    python dialer.py 12345607891  -1      # 登录一次就退出
    python dialer.py 12345607891  -t      # 登出
    python dialer.py -x                  # 只打印报文，不联网
    python dialer.py --probe             # 只探测(不认证)

依赖: 无（只用 Python 标准库）
"""

from __future__ import annotations

import getpass
import hashlib
import socket
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

import body_codec as B

# --------------------------------------------------------------- 默认参数 ---

DEFAULTS = {
    "server": "14.146.227.141:7001",
    "wlanacip": "183.3.151.148",
    "wlanacname": "SISE",
    "paip": "10.88.88.88",
    "vlan": "100.0",
    "iarmdst": "www.189.cn/",
    "clientid": "1009758f-89f4-413c-929b-c5e0e35b0d54",
    "alogoid": "E9747EF1-6849-4F87-957B-3B93E6A90393",
    "zeroalgoid": "00000000-0000-0000-0000-000000000000",
    "trigger": "tarce log algo auto compstr null value",
}

UA = "CCTP/WinSVR5/1068"


# ----------------------------------------------------------- 本机信息探测 ---

def detect_local() -> tuple[str, str, str, str]:
    """返回 (ip, mac, gateway, hostname)。"""
    ip = mac = gw = ""
    host = socket.gethostname()

    try:
        import ctypes
        from ctypes import wintypes

        class IP_ADDR_STRING(ctypes.Structure):
            pass

        IP_ADDR_STRING._fields_ = [
            ("Next", ctypes.POINTER(IP_ADDR_STRING)),
            ("IpAddress", ctypes.c_char * 16),
            ("IpMask", ctypes.c_char * 16),
            ("Context", wintypes.DWORD),
        ]

        class IP_ADAPTER_INFO(ctypes.Structure):
            pass

        IP_ADAPTER_INFO._fields_ = [
            ("Next", ctypes.POINTER(IP_ADAPTER_INFO)),
            ("ComboIndex", wintypes.DWORD),
            ("AdapterName", ctypes.c_char * 260),
            ("Description", ctypes.c_char * 132),
            ("AddressLength", wintypes.UINT),
            ("Address", ctypes.c_ubyte * 8),
            ("Index", wintypes.DWORD),
            ("Type", wintypes.UINT),
            ("DhcpEnabled", wintypes.UINT),
            ("CurrentIpAddress", ctypes.POINTER(IP_ADDR_STRING)),
            ("IpAddressList", IP_ADDR_STRING),
            ("GatewayList", IP_ADDR_STRING),
            ("DhcpServer", IP_ADDR_STRING),
            ("HaveWins", wintypes.BOOL),
            ("PrimaryWinsServer", IP_ADDR_STRING),
            ("SecondaryWinsServer", IP_ADDR_STRING),
            ("LeaseObtained", wintypes.DWORD),
            ("LeaseExpires", wintypes.DWORD),
        ]

        size = wintypes.ULONG(0)
        ctypes.windll.iphlpapi.GetAdaptersInfo(None, ctypes.byref(size))
        buf = ctypes.create_string_buffer(size.value)
        if ctypes.windll.iphlpapi.GetAdaptersInfo(
                ctypes.cast(buf, ctypes.POINTER(IP_ADAPTER_INFO)),
                ctypes.byref(size)) == 0:
            node = ctypes.cast(buf, ctypes.POINTER(IP_ADAPTER_INFO))
            while node:
                a = node.contents
                if a.Type in (6, 71) and a.IpAddressList.IpAddress not in (b"", b"0.0.0.0"):
                    ip = a.IpAddressList.IpAddress.decode()
                    mac = "-".join("%02X" % a.Address[i] for i in range(6))
                    if a.GatewayList.IpAddress:
                        gw = a.GatewayList.IpAddress.decode()
                    break
                node = a.Next
    except Exception:
        pass

    if not ip:
        try:  # 退路：UDP connect 拿本机出接口 IP
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect((DEFAULTS["server"].split(":")[0], 7001))
            ip = s.getsockname()[0]
            s.close()
        except Exception:
            pass
    if not mac:
        try:
            n = __import__("uuid").getnode()
            mac = "-".join("%02X" % ((n >> (8 * i)) & 0xFF) for i in range(6))
        except Exception:
            pass
    return ip, mac, gw, host


# ------------------------------------------------------------------ HTTP ----

class Cfg:
    def __init__(self) -> None:
        self.__dict__.update(DEFAULTS)
        self.account = ""
        self.password = ""
        self.ip = self.mac = self.gw = self.host = ""


def params(c: Cfg) -> str:
    def e(s: str) -> str:
        return urllib.parse.quote(s, safe=":")
    return ("wlanacip=%s&wlanuserip=%s&clientip=%s&wlanacname=%s&clientmac=%s"
            "&paip=%s&vlan=%s&iarmdst=%s" % (
                c.wlanacip, e(c.ip), e(c.ip), e(c.wlanacname), e(c.mac),
                c.paip, c.vlan, urllib.parse.quote(c.iarmdst, safe="")))


def http(c: Cfg, method: str, path: str, headers: dict, body: bytes = b"") -> bytes:
    url = "http://%s%s" % (c.server, path)
    req = urllib.request.Request(url, data=body if body else None, method=method)
    for k, v in headers.items():
        req.add_header(k, v)
    if body:
        req.add_header("Content-Length", str(len(body)))
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return r.read()
    except urllib.error.HTTPError as e:
        return e.read()
    except Exception as e:
        print("[!] 请求失败:", e)
        return b""


def post_xml(c: Cfg, script: str, xml: str, use_algo: bool = True) -> str:
    hexbody = B.encode_body(xml)
    headers = {
        "Connection": "close",
        "User-Agent": UA,
        "Algo-ID": c.alogoid if use_algo else c.zeroalgoid,
        "Client-ID": c.clientid,
        "CDC-Checksum": hashlib.md5(hexbody.encode()).hexdigest(),
        "CDC-SchoolId": "1099",
        "CDC-Domain": "sise.cn",
        "CDC-Area": "020",
        "Content-Type": "text/xml",
    }
    raw = http(c, "POST", "/%s?%s" % (script, params(c)), headers, hexbody.encode())
    if not raw:
        return ""
    try:
        return B.decode_body_str(raw.decode("latin1").strip())
    except Exception:
        return raw.decode("latin1", "replace")


def get_script(c: Cfg, script: str) -> str:
    headers = {"Connection": "close", "User-Agent": UA, "CDC-SchoolId": "1099",
               "Accept": "text/html,text/xml,application/xhtml+xml,*/*"}
    raw = http(c, "GET", "/%s?%s" % (script, params(c)), headers)
    return raw.decode("utf-8", "replace")


def tag(text: str, name: str) -> str:
    a = text.find("<%s>" % name)
    if a < 0:
        return ""
    a += len(name) + 2
    b = text.find("</%s>" % name, a)
    return text[a:b] if b >= 0 else ""


# ------------------------------------------------------------- XML 模板 ----

def _now() -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S")


def xml_ticket(c: Cfg) -> str:
    return ('<?xml version="1.0" encoding="UTF-8"?><request>\n'
            '<ostag>Windows 10(19045),64 bit </ostag>\n'
            f'<local-time>{_now()}</local-time>\n'
            f'<gwip>{c.gw}</gwip>\n'
            f'<mac>{c.mac}</mac>\n'
            '<ipv6></ipv6>\n'
            f'<ipv4>{c.ip}</ipv4>\n'
            f'<client-id>{c.clientid}</client-id>\n'
            f'<user-agent>{UA}</user-agent>\n'
            f'<host-name>{c.host}</host-name>\n'
            '</request>')


def xml_state(c: Cfg, ticket: str) -> str:
    return ('<?xml version="1.0" encoding="UTF-8"?><request>\n'
            f'<local-time>{_now()}</local-time>\n'
            f'<ticket>{ticket}</ticket>\n'
            f'<client-id>{c.clientid}</client-id>\n'
            f'<user-agent>{UA}</user-agent>\n'
            '</request>')


def xml_auth(c: Cfg, ticket: str) -> str:
    return ('<?xml version="1.0" encoding="UTF-8"?><request>\n'
            f'<local-time>{_now()}</local-time>\n'
            f'<ticket>{ticket}</ticket>\n'
            f'<passwd>{c.password}</passwd>\n'
            f'<userid>{c.account}</userid>\n'
            f'<client-id>{c.clientid}</client-id>\n'
            f'<user-agent>{UA}</user-agent>\n'
            '</request>')


def xml_keep(c: Cfg, ticket: str, hello: str = "63635", conn: str = "50225") -> str:
    return ('<?xml version="1.0" encoding="UTF-8"?><request>\n'
            f'<local-time>{_now()}</local-time>\n'
            f'<excheck-args><hello>{hello}</hello><conn>{conn}</conn></excheck-args>\n'
            f'<mac>{c.mac}</mac>\n'
            '<ipv6></ipv6>\n'
            f'<ipv4>{c.ip}</ipv4>\n'
            f'<ticket>{ticket}</ticket>\n'
            f'<client-id>{c.clientid}</client-id>\n'
            f'<user-agent>{UA}</user-agent>\n'
            '</request>')


def xml_term(c: Cfg, ticket: str, reason: int = 1) -> str:
    return ('<?xml version="1.0" encoding="UTF-8"?><request>\n'
            f'<reason>{reason}</reason>\n'
            f'<local-time>{_now()}</local-time>\n'
            f'<ticket>{ticket}</ticket>\n'
            f'<client-id>{c.clientid}</client-id>\n'
            f'<user-agent>{UA}</user-agent>\n'
            '</request>')


# --------------------------------------------------------------- 主流程 ----

def fetch_algorithm(c: Cfg) -> None:
    headers = {
        "Connection": "close",
        "User-Agent": UA,
        "Algo-ID": c.zeroalgoid,
        "Client-ID": c.clientid,
        "CDC-Checksum": hashlib.md5(c.trigger.encode()).hexdigest(),
        "CDC-SchoolId": "1099",
        "CDC-Domain": "sise.cn",
        "CDC-Area": "020",
    }
    raw = http(c, "POST", "/ticket.cgi?%s" % params(c), headers, c.trigger.encode())
    text = raw.decode("latin1", "replace")
    i = text.find("001@")
    if i >= 0:
        j = text.find("$", i)
        k = text.find("]", j)
        if 0 <= j < k:
            c.alogoid = text[j + 1:k]
    print("[*] Algo-ID =", c.alogoid)


def do_login(c: Cfg) -> str:
    print("[*] index.cgi ...")
    get_script(c, "index.cgi")

    print("[*] 获取算法 ...")
    fetch_algorithm(c)

    print("[*] ticket.cgi ...")
    resp = post_xml(c, "ticket.cgi", xml_ticket(c))
    ticket = tag(resp, "ticket")
    if not ticket:
        print("[!] 没拿到 ticket，响应:", resp[:200])
        return ""
    print("[+] ticket =", ticket)

    print("[*] state.cgi ...")
    post_xml(c, "state.cgi", xml_state(c, ticket))
    print("[*] auth.cgi ...")
    r = post_xml(c, "auth.cgi", xml_auth(c, ticket))
    print("[*] auth 响应:", r[:160])
    return ticket


def do_keep(c: Cfg, ticket: str) -> bool:
    r = post_xml(c, "keep.cgi", xml_keep(c, ticket))
    return "errorCode=0" in r or "<response" in r or "result" in r or bool(r)


def do_logout(c: Cfg, ticket: str = "") -> None:
    if not ticket:
        fetch_algorithm(c)
        resp = post_xml(c, "ticket.cgi", xml_ticket(c))
        ticket = tag(resp, "ticket")
        if ticket:
            print("[+] ticket =", ticket)
    post_xml(c, "term.cgi", xml_term(c, ticket))
    print("[+] 登出已发送")


def show_usage(prog: str) -> None:
    print(f"""天翼校园网拨号器 (Python 版) -- 仅登录/保活/登出, 无共享检测

用法: python {prog} [账号] [-p 密码] [选项]

  账号              学号/账号, 例如 12345607891  (省略则交互提示)
  -p <密码>         密码 (省略则隐藏输入)
  -1                登录一次后退出 (默认登录后持续保活)
  -t                登出
  -x                仅打印报文, 不联网
  --probe           只探测 index/ticket, 不做认证

  -s <ip:port>      门户服务器 (默认 {DEFAULTS['server']})
  -n <name>         wlanacname (默认 {DEFAULTS['wlanacname']})
  -a <ip>           wlanacip   (默认 {DEFAULTS['wlanacip']})
  -i <ip>           paip       (默认 {DEFAULTS['paip']})
  -v <vlan>         vlan       (默认 {DEFAULTS['vlan']})
  -d <dst>          iarmdst    (默认 {DEFAULTS['iarmdst']})
  -m <mac>          手动指定 MAC (默认自动探测)

示例:
  python {prog}                     # 提示输入账号和密码
  python {prog} 12345607891          # 提示输入密码
  python {prog} 12345607891  -1      # 登录一次就退出
  python {prog} 12345607891  -t      # 登出
  python {prog} -x                  # 只看报文
""")


def main(argv: list[str]) -> int:
    c = Cfg()
    dryrun = once = probe = logout = False
    i = 1
    while i < len(argv):
        a = argv[i]
        v = argv[i + 1] if i + 1 < len(argv) else None
        if a == "-p" and v:
            c.password = v; i += 2; continue
        if a == "-s" and v:
            c.server = v; i += 2; continue
        if a == "-n" and v:
            c.wlanacname = v; i += 2; continue
        if a == "-a" and v:
            c.wlanacip = v; i += 2; continue
        if a == "-i" and v:
            c.paip = v; i += 2; continue
        if a == "-v" and v:
            c.vlan = v; i += 2; continue
        if a == "-d" and v:
            c.iarmdst = v; i += 2; continue
        if a == "-m" and v:
            c.mac = v; i += 2; continue
        if a == "-1":
            once = True; i += 1; continue
        if a == "-t":
            logout = True; i += 1; continue
        if a == "-x":
            dryrun = True; i += 1; continue
        if a == "--probe":
            probe = True; i += 1; continue
        if a in ("-h", "--help"):
            show_usage(argv[0]); return 0
        if not a.startswith("-"):
            c.account = a; i += 1; continue
        show_usage(argv[0])
        return 2

    ip, mac, gw, host = detect_local()
    if not c.mac:
        c.mac = mac
    c.ip, c.gw, c.host = ip, gw, host
    print(f"[*] 本机 ip={c.ip} mac={c.mac} gw={c.gw} host={c.host}")

    if dryrun:
        print("\n=== 仅打印报文（不联网）===\n")
        for name, xml in (("ticket.cgi", xml_ticket(c)),
                          ("state.cgi", xml_state(c, "0" * 32)),
                          ("keep.cgi", xml_keep(c, "0" * 32)),
                          ("term.cgi", xml_term(c, "0" * 32))):
            body = B.encode_body(xml)
            print(f"-- {name}  ({len(xml)} B xml -> {len(body)//2} B body)")
            print(body, "\n")
        return 0

    if probe:
        print("[*] probe: index.cgi + ticket.cgi (不认证)")
        get_script(c, "index.cgi")
        print("[+] index.cgi ok")
        fetch_algorithm(c)
        resp = post_xml(c, "ticket.cgi", xml_ticket(c))
        t = tag(resp, "ticket")
        print("[+] 响应:", resp[:200])
        if t:
            print("[+] TICKET =", t)
        return 0

    if not c.account:
        c.account = input("account : ").strip()
    if not c.password and not logout:
        c.password = getpass.getpass("password: ")
    if not c.account:
        show_usage(argv[0])
        return 2

    if logout:
        do_logout(c)
        return 0

    ticket = do_login(c)
    if not ticket:
        print("[!] 登录失败")
        return 1
    print("[+] 登录流程完成")
    if once:
        return 0

    print("[*] 每 10 秒保活一次 —— 按 Ctrl-C 停止")
    try:
        while True:
            ok = do_keep(c, ticket)
            print("[+] 保活", "ok" if ok else "失败", time.strftime("%H:%M:%S"))
            time.sleep(10)
    except KeyboardInterrupt:
        # Ctrl-C 只是停掉保活程序，网络那边【还是登录状态】
        print("\n[*] 保活已停止（会话仍然登录中）")
        try:
            ans = input("[?] 现在登出吗? (y/N): ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            ans = ""
        if ans == "y":
            print("[*] term.cgi ...")
            do_logout(c, ticket)
            print("[+] 已登出")
        else:
            print(f"[!] 保持登录。以后要登出请运行:  logout.bat {c.account}")


if __name__ == "__main__":
    try:
        raise SystemExit(main(sys.argv))
    except KeyboardInterrupt:
        print("\n[!] 已中断")
