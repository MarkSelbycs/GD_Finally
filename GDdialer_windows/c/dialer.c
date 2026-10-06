/*
 * dialer.c — standalone ESurfing campus portal dialer (login / keepalive / logout)
 *
 * Only implements the three things asked for: login, keepalive, logout.
 * It deliberately does NOT implement any of the vendor's shared-device
 * detection (Wifisignal uploads, detect.html probing, CheckWifi scanning).
 *
 * Protocol (reversed from the client):
 *   GET  /index.cgi?<params>                    -> portal config
 *   POST /ticket.cgi?<params>   (38B plaintext) -> algorithm container (Algo-ID + key)
 *   POST /ticket.cgi?<params>   (encoded XML)   -> session ticket
 *   POST /state.cgi             (encoded XML)   -> portal state
 *   POST /auth.cgi              (encoded XML)   -> authenticate
 *   POST /keep.cgi              (encoded XML)   -> keepalive (periodic)
 *   POST /term.cgi              (encoded XML)   -> logout
 *
 * Body encoding: 6-key DES cascade over the XML (see body_codec.c).
 *
 * Build (MinGW/TCC):  tcc -o dialer.exe dialer.c body_codec.c md5.c -lws2_32
 *                or:  gcc -O2 -o dialer dialer.c body_codec.c md5.c -lws2_32
 *
 * Usage:
 *   dialer -u <account> -p <password> [-s <server:port>] [-n <wlanacname>]
 *          [-a <wlanacip>] [-i <paip>] [-v <vlan>] [-d <iarmdst>]
 *          [-m <clientmac>] [-t]        # -t = logout instead of login
 *          [-k]                         # keepalive loop only
 */
#include "body_codec.h"
#include "md5.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
#if defined(__TINYC__) || defined(USE_WINSOCK_MIN)
#include "winsock_min.h"
#include <conio.h>
#else
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <conio.h>
#endif
typedef int socklen_t;
#define CLOSESOCK closesocket
#else
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#define CLOSESOCK close
typedef int SOCKET;
#ifndef INVALID_SOCKET
#define INVALID_SOCKET (-1)
#endif
#endif

#define BUFSZ 65536

/* ---------------------------------------------------------------- 信号 ---- */

/* Ctrl-C / 关闭窗口：不立即杀进程，先让主循环优雅收尾（询问是否登出） */
static volatile int g_stop = 0;

#ifdef _WIN32
static BOOL WINAPI console_ctrl_handler(DWORD type)
{
    (void)type;
    g_stop = 1;
    return TRUE;          /* 已处理，不要直接终止进程 */
}
#endif

/* 可中断等待：共 ms 毫秒，每 100ms 检查一次 g_stop */
static void sleep_interruptible(int ms)
{
    int i;
    for (i = 0; i < ms / 100 && !g_stop; i++) {
#ifdef _WIN32
        Sleep(100);
#else
        usleep(100 * 1000);
#endif
    }
}

/* 读一行（可见输入），用于 y/N 询问 */
static int ask_yes(const char *prompt)
{
    char buf[16];
    printf("%s", prompt);
    fflush(stdout);
    if (!fgets(buf, sizeof(buf), stdin)) return 0;
    return (buf[0] == 'y' || buf[0] == 'Y');
}

/* ------------------------------------------------------------- runtime cfg */

typedef struct {
    char account[64];
    char password[128];
    char server[64];      /* ip:port */
    char wlanacip[32];
    char wlanuserip[32];
    char wlanacname[64];
    char clientmac[32];
    char paip[32];
    char vlan[32];
    char iarmdst[64];
    char gwip[32];
    char hostname[64];
    char clientid[64];
    char alogoid[64];
    int  do_logout;
    int  keepalive_only;
    int  dryrun;
    int  once;
    int  probe;
} cfg_t;

static cfg_t g;

/* ------------------------------------------------------------------ utils */

static void now_str(char *out, size_t n)
{
    time_t t = time(NULL);
    struct tm *tm = localtime(&t);
    strftime(out, n, "%Y-%m-%d %H:%M:%S", tm);
}

static char *url_encode(const char *s, char *out, size_t outsz)
{
    static const char *hex = "0123456789ABCDEF";
    size_t w = 0;
    for (; *s && w + 4 < outsz; s++) {
        unsigned char c = (unsigned char)*s;
        if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
            (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' || c == '~' || c == ':') {
            out[w++] = (char)c;
        } else {
            out[w++] = '%';
            out[w++] = hex[c >> 4];
            out[w++] = hex[c & 15];
        }
    }
    out[w] = '\0';
    return out;
}

/* Detect the local IPv4 + MAC of the interface holding the default route. */
static int detect_local(char *ip, size_t ipsz, char *mac, size_t macsz)
{
#ifdef _WIN32
    IP_ADAPTER_INFO *ai, *p;
    ULONG len = 0;
    if (GetAdaptersInfo(NULL, &len) != ERROR_BUFFER_OVERFLOW || len == 0) return -1;
    ai = (IP_ADAPTER_INFO *)malloc(len);
    if (!ai) return -1;
    if (GetAdaptersInfo(ai, &len) != ERROR_SUCCESS) { free(ai); return -1; }
    for (p = ai; p; p = p->Next) {
        if (p->Type == MIB_IF_TYPE_ETHERNET || p->Type == MIB_IF_TYPE_IEEE80211) {
            if (strcmp(p->IpAddressList.IpAddress.String, "0.0.0.0") == 0) continue;
            snprintf(ip, ipsz, "%s", p->IpAddressList.IpAddress.String);
            snprintf(mac, macsz, "%02X-%02X-%02X-%02X-%02X-%02X",
                     p->Address[0], p->Address[1], p->Address[2],
                     p->Address[3], p->Address[4], p->Address[5]);
            if (g.gwip[0] == '\0' && p->GatewayList.IpAddress.String[0])
                snprintf(g.gwip, sizeof(g.gwip), "%s", p->GatewayList.IpAddress.String);
            free(ai);
            return 0;
        }
    }
    free(ai);
#endif
    return -1;
}

/* --------------------------------------------------------------- HTTP ---- */

static int http_request(const char *hostport, const char *method, const char *path,
                        const char *headers, const char *body, size_t bodylen,
                        char *resp, size_t respsz, size_t *resplen)
{
    char host[64];
    int port = 7001;
    char *colon;
    SOCKET s;
    struct sockaddr_in sa;
    struct hostent *he;
    char *req;
    size_t reqcap, w = 0;
    size_t got = 0;

    snprintf(host, sizeof(host), "%s", hostport);
    colon = strchr(host, ':');
    if (colon) { *colon = '\0'; port = atoi(colon + 1); }

    s = socket(AF_INET, SOCK_STREAM, 0);
    if (s == INVALID_SOCKET) return -1;

    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons((unsigned short)port);
    if ((he = gethostbyname(host)) != NULL) {
        memcpy(&sa.sin_addr, he->h_addr, he->h_length);
    } else {
        sa.sin_addr.s_addr = inet_addr(host);
    }

    if (connect(s, (struct sockaddr *)&sa, sizeof(sa)) != 0) {
        CLOSESOCK(s);
        return -1;
    }

    reqcap = strlen(path) + strlen(host) + (headers ? strlen(headers) : 0) + bodylen + 512;
    req = (char *)malloc(reqcap);
    if (!req) { CLOSESOCK(s); return -1; }

    w += (size_t)snprintf(req + w, reqcap - w, "%s %s HTTP/1.1\r\n", method, path);
    w += (size_t)snprintf(req + w, reqcap - w, "Host: %s:%d\r\n", host, port);
    if (headers && *headers) w += (size_t)snprintf(req + w, reqcap - w, "%s", headers);
    if (body && bodylen) w += (size_t)snprintf(req + w, reqcap - w,
                                               "Content-Length: %u\r\n", (unsigned)bodylen);
    w += (size_t)snprintf(req + w, reqcap - w, "\r\n");
    if (body && bodylen) {
        memcpy(req + w, body, bodylen);
        w += bodylen;
    }

    if (send(s, req, (int)w, 0) != (int)w) { free(req); CLOSESOCK(s); return -1; }
    free(req);

    for (;;) {
        int n = recv(s, resp + got, (int)(respsz - 1 - got), 0);
        if (n <= 0) break;
        got += (size_t)n;
        if (got >= respsz - 1) break;
    }
    CLOSESOCK(s);
    resp[got] = '\0';
    if (resplen) *resplen = got;
    return 0;
}

/* Return pointer to the response body, handling Transfer-Encoding: chunked and
   de-chunking into `out`. Returns the body length. */
static size_t http_body(const char *resp, size_t resplen, char *out, size_t outsz)
{
    const char *p = strstr(resp, "\r\n\r\n");
    size_t blen, pos = 0, w = 0;
    if (!p) { out[0] = '\0'; return 0; }
    p += 4;
    blen = resplen - (size_t)(p - resp);
    if (strstr(resp, "Transfer-Encoding: chunked") || strstr(resp, "transfer-encoding: chunked")) {
        while (pos < blen) {
            const char *nl = memchr(p + pos, '\n', blen - pos);
            long sz;
            if (!nl) break;
            sz = strtol(p + pos, NULL, 16);
            pos = (size_t)(nl - p) + 1;
            if (sz <= 0) break;
            if (w + (size_t)sz + 1 > outsz) break;
            memcpy(out + w, p + pos, (size_t)sz);
            w += (size_t)sz;
            pos += (size_t)sz;
            while (pos < blen && (p[pos] == '\r' || p[pos] == '\n')) pos++;
        }
        out[w] = '\0';
        return w;
    }
    if (blen >= outsz) blen = outsz - 1;
    memcpy(out, p, blen);
    out[blen] = '\0';
    return blen;
}

/* Decrypt a portal response body (server replies are encoded too). */
static void decode_portal_body(char *body, size_t *blen)
{
    char clean[65536];
    size_t i, w = 0, n;
    for (i = 0; body[i]; i++)
        if ((body[i] >= '0' && body[i] <= '9') ||
            (body[i] >= 'a' && body[i] <= 'f') ||
            (body[i] >= 'A' && body[i] <= 'F'))
            clean[w++] = body[i];
    clean[w] = '\0';
    if (w == 0 || w % 2 != 0) return;
    n = w / 2;
    if (n % 8 != 0) return;
    if (portal_decode_body_str(clean, body, *blen > 8192 ? *blen : 8192, blen) == 0) {
        /* body now holds the plaintext XML */
    }
}

/* Return pointer to the response body (after the header terminator). */
static const char *resp_body(const char *resp, size_t *len)
{
    const char *p = strstr(resp, "\r\n\r\n");
    if (!p) { if (len) *len = 0; return resp + strlen(resp); }
    p += 4;
    if (len) *len = strlen(p);
    return p;
}

/* ------------------------------------------------------- protocol requests */

static void build_params(char *out, size_t outsz)
{
    char e_user[128], e_mac[64], e_name[128], e_dst[256];
    url_encode(g.wlanuserip, e_user, sizeof(e_user));
    url_encode(g.clientmac, e_mac, sizeof(e_mac));
    url_encode(g.wlanacname, e_name, sizeof(e_name));
    url_encode(g.iarmdst, e_dst, sizeof(e_dst));
    snprintf(out, outsz,
             "wlanacip=%s&wlanuserip=%s&clientip=%s&wlanacname=%s&clientmac=%s"
             "&paip=%s&vlan=%s&iarmdst=%s",
             g.wlanacip, e_user, e_user, e_name, e_mac, g.paip, g.vlan, e_dst);
}

static void build_headers(char *out, size_t outsz, const char *bodyhex, int use_algo)
{
    char sum[33];
    md5_hex(bodyhex ? bodyhex : "", bodyhex ? strlen(bodyhex) : 0, sum);
    snprintf(out, outsz,
             "Connection: close\r\n"
             "Accept: text/html,text/xml,application/xhtml+xml,application/x-javascript,*/*\r\n"
             "User-Agent: CCTP/WinSVR5/1068\r\n"
             "Algo-ID: %s\r\n"
             "Client-ID: %s\r\n"
             "CDC-Checksum: %s\r\n"
             "CDC-SchoolId: 1099\r\n"
             "CDC-Domain: sise.cn\r\n"
             "CDC-Area: 020\r\n",
             use_algo ? g.alogoid : "00000000-0000-0000-0000-000000000000",
             g.clientid, sum);
}

/* POST an XML request, returning the DECODED response body (caller frees). */
static char *post_xml(const char *script, const char *xml, int use_algo, size_t *rlen)
{
    char path[2048], params[1024], headers[1024];
    char hex[65536];
    char *body;
    static char resp[BUFSZ];
    size_t n, blen;

    portal_encode_body(xml, hex, sizeof(hex));
    build_params(params, sizeof(params));
    snprintf(path, sizeof(path), "/%s?%s", script, params);
    build_headers(headers, sizeof(headers), hex, use_algo);

    if (http_request(g.server, "POST", path, headers, hex, strlen(hex),
                     resp, sizeof(resp), &n) != 0)
        return NULL;

    body = (char *)malloc(BUFSZ);
    if (!body) return NULL;
    blen = http_body(resp, n, body, BUFSZ);
    decode_portal_body(body, &blen);
    if (rlen) *rlen = blen;
    return body;
}

/* GET a plain script, returning the DECODED response body (caller frees). */
static char *get_script(const char *script, const char *extra_params, size_t *rlen)
{
    char path[2048], params[1200], headers[512];
    char *body;
    static char resp[BUFSZ];
    size_t n, blen;
    build_params(params, sizeof(params));
    snprintf(path, sizeof(path), "/%s?%s%s", script, params, extra_params ? extra_params : "");
    snprintf(headers, sizeof(headers),
             "Connection: close\r\n"
             "Accept: text/html,text/xml,application/xhtml+xml,application/x-javascript,*/*\r\n"
             "User-Agent: CCTP/WinSVR5/1068\r\n"
             "CDC-SchoolId: 1099\r\n");
    if (http_request(g.server, "GET", path, headers, NULL, 0, resp, sizeof(resp), &n) != 0)
        return NULL;
    body = (char *)malloc(BUFSZ);
    if (!body) return NULL;
    blen = http_body(resp, n, body, BUFSZ);
    decode_portal_body(body, &blen);
    if (rlen) *rlen = blen;
    return body;
}

/* ------------------------------------------------------------- XML bodies */

static void xml_ticket(char *out, size_t n)
{
    char t[64];
    now_str(t, sizeof(t));
    snprintf(out, n,
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?><request>\n"
        "<ostag>Windows 10(19045),64 bit </ostag>\n"
        "<local-time>%s</local-time>\n"
        "<gwip>%s</gwip>\n"
        "<mac>%s</mac>\n"
        "<ipv6></ipv6>\n"
        "<ipv4>%s</ipv4>\n"
        "<client-id>%s</client-id>\n"
        "<user-agent>CCTP/WinSVR5/1068</user-agent>\n"
        "<host-name>%s</host-name>\n"
        "</request>", t, g.gwip, g.clientmac, g.wlanuserip, g.clientid, g.hostname);
}

static void xml_state(char *out, size_t n, const char *ticket)
{
    char t[64];
    now_str(t, sizeof(t));
    snprintf(out, n,
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?><request>\n"
        "<local-time>%s</local-time>\n"
        "<ticket>%s</ticket>\n"
        "<client-id>%s</client-id>\n"
        "<user-agent>CCTP/WinSVR5/1068</user-agent>\n"
        "</request>", t, ticket, g.clientid);
}

static void xml_auth(char *out, size_t n, const char *ticket)
{
    char t[64];
    now_str(t, sizeof(t));
    snprintf(out, n,
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?><request>\n"
        "<local-time>%s</local-time>\n"
        "<ticket>%s</ticket>\n"
        "<passwd>%s</passwd>\n"
        "<userid>%s</userid>\n"
        "<client-id>%s</client-id>\n"
        "<user-agent>CCTP/WinSVR5/1068</user-agent>\n"
        "</request>", t, ticket, g.password, g.account, g.clientid);
}

static void xml_keep(char *out, size_t n, const char *ticket, const char *hello, const char *conn)
{
    char t[64];
    now_str(t, sizeof(t));
    snprintf(out, n,
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?><request>\n"
        "<local-time>%s</local-time>\n"
        "<excheck-args><hello>%s</hello><conn>%s</conn></excheck-args>\n"
        "<mac>%s</mac>\n"
        "<ipv6></ipv6>\n"
        "<ipv4>%s</ipv4>\n"
        "<ticket>%s</ticket>\n"
        "<client-id>%s</client-id>\n"
        "<user-agent>CCTP/WinSVR5/1068</user-agent>\n"
        "</request>", t, hello, conn, g.clientmac, g.wlanuserip, ticket, g.clientid);
}

static void xml_term(char *out, size_t n, const char *ticket, int reason)
{
    char t[64];
    now_str(t, sizeof(t));
    snprintf(out, n,
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?><request>\n"
        "<reason>%d</reason>\n"
        "<local-time>%s</local-time>\n"
        "<ticket>%s</ticket>\n"
        "<client-id>%s</client-id>\n"
        "<user-agent>CCTP/WinSVR5/1068</user-agent>\n"
        "</request>", reason, t, ticket, g.clientid);
}

/* Extract <ticket>...</ticket> or a tag value from a response. */
static int extract_tag(const char *buf, const char *tag, char *out, size_t outsz)
{
    char open[64], close[64];
    const char *p, *q;
    snprintf(open, sizeof(open), "<%s>", tag);
    snprintf(close, sizeof(close), "</%s>", tag);
    p = strstr(buf, open);
    if (!p) return -1;
    p += strlen(open);
    q = strstr(p, close);
    if (!q) return -1;
    if ((size_t)(q - p) >= outsz) return -1;
    memcpy(out, p, (size_t)(q - p));
    out[q - p] = '\0';
    return 0;
}

/* --------------------------------------------------------------- actions */

/* Step 1+2: fetch the algorithm container to obtain the Algo-ID. */
static int fetch_algorithm(void)
{
    static char resp[BUFSZ];
    char headers[1024], params[1024], path[2048];
    const char *trigger = "tarce log algo auto compstr null value";
    char sum[33];
    size_t n;

    md5_hex(trigger, strlen(trigger), sum);
    build_params(params, sizeof(params));
    snprintf(path, sizeof(path), "/ticket.cgi?%s", params);
    snprintf(headers, sizeof(headers),
        "Connection: close\r\n"
        "User-Agent: CCTP/WinSVR5/1068\r\n"
        "Algo-ID: 00000000-0000-0000-0000-000000000000\r\n"
        "Client-ID: %s\r\n"
        "CDC-Checksum: %s\r\n"
        "CDC-SchoolId: 1099\r\n"
        "CDC-Domain: sise.cn\r\n"
        "CDC-Area: 020\r\n", g.clientid, sum);

    if (http_request(g.server, "POST", path, headers, trigger, strlen(trigger),
                     resp, sizeof(resp), &n) != 0)
        return -1;

    /* the container looks like: 001@<64 hex>$<Algo-ID>]... */
    {
        const char *p = strstr(resp, "001@");
        if (p) {
            const char *dollar = strchr(p, '$');
            const char *close;
            if (dollar) {
                close = strchr(dollar, ']');
                if (close && (size_t)(close - dollar - 1) < sizeof(g.alogoid)) {
                    memcpy(g.alogoid, dollar + 1, (size_t)(close - dollar - 1));
                    g.alogoid[close - dollar - 1] = '\0';
                    printf("[*] Algo-ID = %s\n", g.alogoid);
                    return 0;
                }
            }
        }
    }
    /* fall back: reuse the well-known id */
    snprintf(g.alogoid, sizeof(g.alogoid), "E9747EF1-6849-4F87-957B-3B93E6A90393");
    printf("[!] fell back to default Algo-ID\n");
    return 0;
}

static int do_login(char *ticket_out, size_t tsz)
{
    char xml[4096], *rb;
    size_t rl;

    printf("[*] index.cgi ...\n");
    rb = get_script("index.cgi", NULL, &rl);
    free(rb);

    printf("[*] fetching algorithm ...\n");
    if (fetch_algorithm() != 0) { printf("[!] algorithm fetch failed\n"); return -1; }

    printf("[*] ticket.cgi ...\n");
    xml_ticket(xml, sizeof(xml));
    rb = post_xml("ticket.cgi", xml, 1, &rl);
    if (!rb) { printf("[!] ticket request failed\n"); return -1; }
    if (extract_tag(rb, "ticket", ticket_out, tsz) != 0) {
        printf("[!] no <ticket> in response\n%.200s\n", rb);
        free(rb);
        return -1;
    }
    printf("[+] ticket = %s\n", ticket_out);
    free(rb);

    printf("[*] state.cgi ...\n");
    xml_state(xml, sizeof(xml), ticket_out);
    rb = post_xml("state.cgi", xml, 1, &rl);
    free(rb);

    printf("[*] auth.cgi ...\n");
    xml_auth(xml, sizeof(xml), ticket_out);
    rb = post_xml("auth.cgi", xml, 1, &rl);
    if (!rb) { printf("[!] auth request failed\n"); return -1; }
    printf("[*] auth response: %.160s\n", rb);
    free(rb);
    return 0;
}

static int do_keepalive(const char *ticket)
{
    char xml[4096], *rb;
    size_t rl;
    xml_keep(xml, sizeof(xml), ticket, "63635", "50225");
    rb = post_xml("keep.cgi", xml, 1, &rl);
    if (!rb) return -1;
    free(rb);
    return 0;
}

static int do_logout(const char *ticket)
{
    char xml[4096], *rb;
    size_t rl;
    xml_term(xml, sizeof(xml), ticket, 1);
    rb = post_xml("term.cgi", xml, 1, &rl);
    free(rb);
    return 0;
}

/* ----------------------------------------------------------------- main */

/* Read a line from the console. hidden=1 echoes '*' and supports backspace. */
static void read_line(const char *prompt, char *out, size_t outsz, int hidden)
{
    size_t w = 0;
    int k;
    printf("%s", prompt);
    fflush(stdout);
    out[0] = '\0';
    for (;;) {
        k = _getch();
        if (k == '\r' || k == '\n') break;
        if (k == 3) { printf("\n"); exit(130); }        /* Ctrl-C */
        if (k == 8 || k == 127) {
            if (w > 0) { w--; printf("\b \b"); }
            continue;
        }
        if (k >= 32 && k < 127 && w + 1 < outsz) {
            out[w++] = (char)k;
            putchar(hidden ? '*' : (char)k);
        }
    }
    out[w] = '\0';
    printf("\n");
}

static void usage(const char *argv0)
{
    fprintf(stderr,
        "ESurfing campus portal dialer -- login / keepalive / logout only\n"
        "(no shared-device detection)\n"
        "\n"
        "usage: %s [account] [-p password] [options]\n"
        "\n"
        "  account            your campus account, e.g. 12345678910\n"
        "                     (omit to be prompted)\n"
        "  -p <password>      password (omit to be prompted, hidden input)\n"
        "  -1                 login once, then exit (default: keep alive)\n"
        "  -t                 logout instead of login\n"
        "  -x                 dry run: print the encoded bodies, send nothing\n"
        "\n"
        "  -s <server:port>   portal server (default 14.146.227.141:7001)\n"
        "  -n <wlanacname>    default SISE\n"
        "  -a <wlanacip>      default 183.3.151.148\n"
        "  -i <paip>          default 10.88.88.88\n"
        "  -v <vlan>          default 100.0\n"
        "  -d <iarmdst>       default www.189.cn/\n"
        "  -m <clientmac>     override MAC (default: auto-detect)\n"
        "\n"
        "examples:\n"
        "  %s                       # ask for account and password\n"
        "  %s 12345678910           # ask for password, login + keepalive\n"
        "  %s 12345678910 -1        # login once and exit\n"
        "  %s 12345678910 -t        # logout\n"
        "  %s -x                    # show the encoded bodies only\n",
        argv0, argv0, argv0, argv0, argv0, argv0);
}

int main(int argc, char **argv)
{
    int i;
    char ticket[128] = "";
    char localip[64] = "", localmac[64] = "";

    memset(&g, 0, sizeof(g));
    snprintf(g.server, sizeof(g.server), "14.146.227.141:7001");
    snprintf(g.wlanacname, sizeof(g.wlanacname), "SISE");
    snprintf(g.wlanacip, sizeof(g.wlanacip), "183.3.151.148");
    snprintf(g.paip, sizeof(g.paip), "10.88.88.88");
    snprintf(g.vlan, sizeof(g.vlan), "100.0");
    snprintf(g.iarmdst, sizeof(g.iarmdst), "www.189.cn/");
    snprintf(g.clientid, sizeof(g.clientid),
             "1009758f-89f4-413c-929b-c5e0e35b0d54");

    if (detect_local(localip, sizeof(localip), localmac, sizeof(localmac)) == 0) {
        snprintf(g.wlanuserip, sizeof(g.wlanuserip), "%s", localip);
        snprintf(g.clientmac, sizeof(g.clientmac), "%s", localmac);
        printf("[*] local ip=%s mac=%s gw=%s\n", localip, localmac, g.gwip);
    } else {
        printf("[!] could not auto-detect local ip/mac; use -m and set wlanuserip\n");
    }
#ifdef _WIN32
    {
        char hn[128];
        DWORD hnlen = sizeof(hn);
        if (GetComputerNameA(hn, &hnlen))
            snprintf(g.hostname, sizeof(g.hostname), "%s", hn);
    }
#endif
    if (!g.hostname[0]) snprintf(g.hostname, sizeof(g.hostname), "PC");

    for (i = 1; i < argc; i++) {
        const char *a = argv[i];
        const char *v = (i + 1 < argc) ? argv[i + 1] : NULL;
        if (!strcmp(a, "-u") && v) { snprintf(g.account, sizeof(g.account), "%s", v); i++; }
        else if (!strcmp(a, "-p") && v) { snprintf(g.password, sizeof(g.password), "%s", v); i++; }
        else if (!strcmp(a, "-s") && v) { snprintf(g.server, sizeof(g.server), "%s", v); i++; }
        else if (!strcmp(a, "-n") && v) { snprintf(g.wlanacname, sizeof(g.wlanacname), "%s", v); i++; }
        else if (!strcmp(a, "-a") && v) { snprintf(g.wlanacip, sizeof(g.wlanacip), "%s", v); i++; }
        else if (!strcmp(a, "-i") && v) { snprintf(g.paip, sizeof(g.paip), "%s", v); i++; }
        else if (!strcmp(a, "-v") && v) { snprintf(g.vlan, sizeof(g.vlan), "%s", v); i++; }
        else if (!strcmp(a, "-d") && v) { snprintf(g.iarmdst, sizeof(g.iarmdst), "%s", v); i++; }
        else if (!strcmp(a, "-m") && v) { snprintf(g.clientmac, sizeof(g.clientmac), "%s", v); i++; }
        else if (!strcmp(a, "-t")) { g.do_logout = 1; }
        else if (!strcmp(a, "-k")) { g.keepalive_only = 1; }
        else if (!strcmp(a, "-x") || !strcmp(a, "--dryrun")) { g.dryrun = 1; }
        else if (!strcmp(a, "-1") || !strcmp(a, "--once")) { g.once = 1; }
        else if (!strcmp(a, "--probe")) { g.probe = 1; }
        else if (a[0] != '-') { snprintf(g.account, sizeof(g.account), "%s", a); }
        else { usage(argv[0]); return 2; }
    }

    /* interactive prompts: account first (echoed), then password (hidden) */
    if (!g.dryrun && !g.probe) {
        if (!g.account[0])
            read_line("account : ", g.account, sizeof(g.account), 0);
        if (!g.password[0] && !g.do_logout)
            read_line("password: ", g.password, sizeof(g.password), 1);
    }

#ifdef _WIN32
    {
        WSADATA wsa;
        WSAStartup(MAKEWORD(2, 2), &wsa);
    }
#endif

    if (g.dryrun) {
        char xml[4096], hex[65536], back[8192];
        size_t xl;
        printf("=== dry run: encoded request bodies ===\n\n");
        xml_ticket(xml, sizeof(xml));
        portal_encode_body(xml, hex, sizeof(hex));
        printf("-- ticket.cgi  (%u B xml -> %u B body)\n%s\n\n",
               (unsigned)strlen(xml), (unsigned)(strlen(hex) / 2), hex);
        portal_decode_body_str(hex, back, sizeof(back), &xl);
        printf("   decoded: %s\n\n", back);

        xml_state(xml, sizeof(xml), "0123456789abcdef0123456789abcdef");
        portal_encode_body(xml, hex, sizeof(hex));
        printf("-- state.cgi   (%u B xml -> %u B body)\n%s\n\n",
               (unsigned)strlen(xml), (unsigned)(strlen(hex) / 2), hex);

        xml_keep(xml, sizeof(xml), "0123456789abcdef0123456789abcdef", "63635", "50225");
        portal_encode_body(xml, hex, sizeof(hex));
        printf("-- keep.cgi    (%u B xml -> %u B body)\n%s\n\n",
               (unsigned)strlen(xml), (unsigned)(strlen(hex) / 2), hex);

        xml_term(xml, sizeof(xml), "0123456789abcdef0123456789abcdef", 1);
        portal_encode_body(xml, hex, sizeof(hex));
        printf("-- term.cgi    (%u B xml -> %u B body)\n%s\n\n",
               (unsigned)strlen(xml), (unsigned)(strlen(hex) / 2), hex);
        return 0;
    }

    if (!g.account[0] && !g.dryrun && !g.probe) { usage(argv[0]); return 2; }

    if (g.probe) {
        char *rb;
        size_t rl, n;
        char headers[1024], params[1024], path[2048];
        static char resp[BUFSZ];
        printf("[*] probe: index.cgi + ticket.cgi (no authentication)\n");

        build_params(params, sizeof(params));
        snprintf(path, sizeof(path), "/index.cgi?%s", params);
        snprintf(headers, sizeof(headers),
            "Connection: close\r\nAccept: text/html,text/xml,application/xhtml+xml,"
            "application/x-javascript,*/*\r\nUser-Agent: CCTP/WinSVR5/1068\r\n"
            "CDC-SchoolId: 1099\r\n");
        if (http_request(g.server, "GET", path, headers, NULL, 0, resp, sizeof(resp), &n) == 0) {
            printf("[+] index.cgi ok, %u bytes\n", (unsigned)n);
            {
                const char *body = resp_body(resp, &rl);
                char tmp[256];
                if (extract_tag(body, "tickUrl", tmp, sizeof(tmp)) == 0)
                    printf("    tickUrl     = %s\n", tmp);
                if (extract_tag(body, "schoolId", tmp, sizeof(tmp)) == 0)
                    printf("    schoolId    = %s\n", tmp);
                if (extract_tag(body, "authDefautType", tmp, sizeof(tmp)) == 0)
                    printf("    authType    = %s\n", tmp);
            }
        } else {
            printf("[!] index.cgi failed\n");
        }

        printf("[*] fetching algorithm ...\n");
        fetch_algorithm();

        printf("[*] ticket.cgi ...\n");
        {
            char xml[4096], tk[128];
            xml_ticket(xml, sizeof(xml));
            rb = post_xml("ticket.cgi", xml, 1, &rl);
            if (rb) {
                printf("[+] decoded response: %.400s\n", rb);
                if (extract_tag(rb, "ticket", tk, sizeof(tk)) == 0)
                    printf("[+] TICKET = %s\n", tk);
                free(rb);
            } else {
                printf("[!] ticket request failed\n");
            }
        }
        printf("[+] probe complete (no auth performed)\n");
        return 0;
    }

    if (g.do_logout) {
        char tk[128] = "";
        char *rb;
        size_t rl;
        printf("[*] obtaining a session ticket ...\n");
        fetch_algorithm();
        {
            static char xml[4096];
            xml_ticket(xml, sizeof(xml));
            rb = post_xml("ticket.cgi", xml, 1, &rl);
            if (rb) {
                extract_tag(rb, "ticket", tk, sizeof(tk));
                free(rb);
            }
        }
        if (tk[0]) printf("[+] ticket = %s\n", tk);
        else printf("[!] no ticket; sending term anyway\n");
        printf("[*] term.cgi ...\n");
        do_logout(tk);
        printf("[+] logout sent\n");
    } else {
        if (do_login(ticket, sizeof(ticket)) != 0) {
            printf("[!] login failed\n");
            return 1;
        }
        printf("[+] login flow completed\n");
        if (g.once) {
            printf("[+] done (-1: no keepalive)\n");
            return 0;
        }

#ifdef _WIN32
        SetConsoleCtrlHandler(console_ctrl_handler, TRUE);
#endif
        printf("[*] keepalive every 10s -- press Ctrl-C to stop\n");
        while (!g_stop) {
            char ts[32];
            now_str(ts, sizeof(ts));
            if (do_keepalive(ticket) == 0) printf("[+] keepalive ok  %s\n", ts);
            else printf("[!] keepalive failed  %s\n", ts);
            sleep_interruptible(10000);
        }

        /* Ctrl-C 之后：保活已停，但网络那边还是登录状态 —— 询问是否登出 */
        printf("\n[*] keepalive stopped (the session is STILL logged in)\n");
        if (ask_yes("[?] logout now? (y/N): ")) {
            printf("[*] term.cgi ...\n");
            do_logout(ticket);
            printf("[+] logged out\n");
        } else {
            printf("[!] kept the session. run  logout.bat <account>  to log out later.\n");
        }
    }
    return 0;
}
