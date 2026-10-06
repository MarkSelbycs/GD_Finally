/*
 * winsock_min.h — minimal Winsock2 + iphlpapi declarations using the STANDARD
 * type names, for toolchains that ship windows.h but not winsock2.h (TinyCC).
 * Include this INSTEAD of <winsock2.h>.
 */
#ifndef WINSOCK_MIN_H
#define WINSOCK_MIN_H

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef UINT_PTR SOCKET;
#ifndef INVALID_SOCKET
#define INVALID_SOCKET ((SOCKET)(~0))
#endif
#ifndef SOCKET_ERROR
#define SOCKET_ERROR (-1)
#endif
#ifndef AF_INET
#define AF_INET 2
#endif
#ifndef SOCK_STREAM
#define SOCK_STREAM 1
#endif
#ifndef SOCK_DGRAM
#define SOCK_DGRAM 2
#endif
#ifndef IPPROTO_TCP
#define IPPROTO_TCP 6
#endif

struct in_addr { unsigned long s_addr; };
struct sockaddr { unsigned short sa_family; char sa_data[14]; };
struct sockaddr_in {
    short sin_family;
    unsigned short sin_port;
    struct in_addr sin_addr;
    char sin_zero[8];
};
struct hostent {
    char *h_name;
    char **h_aliases;
    short h_addrtype;
    short h_length;
    char **h_addr_list;
};
#define h_addr h_addr_list[0]

typedef struct { WORD wVersion, wHighVersion; char szDescription[257];
                 char szSystemStatus[129]; unsigned short iMaxSockets, iMaxUdpDg;
                 char *lpVendorInfo; } WSADATA;

int __stdcall WSAStartup(WORD wVersionRequested, WSADATA *lpWSAData);
int __stdcall WSACleanup(void);
SOCKET __stdcall socket(int af, int type, int protocol);
int __stdcall connect(SOCKET s, const struct sockaddr *name, int namelen);
int __stdcall send(SOCKET s, const char *buf, int len, int flags);
int __stdcall recv(SOCKET s, char *buf, int len, int flags);
int __stdcall closesocket(SOCKET s);
int __stdcall getsockname(SOCKET s, struct sockaddr *name, int *namelen);
struct hostent *__stdcall gethostbyname(const char *name);
unsigned long __stdcall inet_addr(const char *cp);
char *__stdcall inet_ntoa(struct in_addr in);
unsigned short __stdcall htons(unsigned short hostshort);

/* --- iphlpapi --- */
typedef struct { char String[16]; } IP_ADDRESS_STRING;
typedef struct { char String[16]; } IP_MASK_STRING;

typedef struct _IP_ADDR_STRING {
    struct _IP_ADDR_STRING *Next;
    IP_ADDRESS_STRING IpAddress;
    IP_MASK_STRING IpMask;
    DWORD Context;
} IP_ADDR_STRING;

typedef struct _IP_ADAPTER_INFO {
    struct _IP_ADAPTER_INFO *Next;
    DWORD ComboIndex;
    char AdapterName[260];
    char Description[132];
    UINT AddressLength;
    BYTE Address[8];
    DWORD Index;
    UINT Type;
    UINT DhcpEnabled;
    IP_ADDR_STRING *CurrentIpAddress;
    IP_ADDR_STRING IpAddressList;
    IP_ADDR_STRING GatewayList;
    IP_ADDR_STRING DhcpServer;
    BOOL HaveWins;
    IP_ADDR_STRING PrimaryWinsServer;
    IP_ADDR_STRING SecondaryWinsServer;
    long LeaseObtained;
    long LeaseExpires;
} IP_ADAPTER_INFO;

#define MIB_IF_TYPE_ETHERNET 6
#define MIB_IF_TYPE_IEEE80211 71

DWORD __stdcall GetAdaptersInfo(IP_ADAPTER_INFO *pAdapterInfo, PULONG pOutBufLen);

#ifdef __cplusplus
}
#endif

#endif
