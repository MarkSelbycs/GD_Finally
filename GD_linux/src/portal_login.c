#define _POSIX_C_SOURCE 200809L
#define _GNU_SOURCE

#include <arpa/inet.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <libxml/parser.h>
#include <libxml/tree.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <unistd.h>

typedef char *(*codec_function)(const char *);
typedef void (*free_function)(const char *);

struct buffer {
    char *data;
    size_t length;
};

struct portal_config {
    char *ticket_url;
    char *auth_url;
    char *term_url;
    char *state_url;
    char *redirect_url;
    char *client_id;
    char *user_agent;
    char *wlan_user_ip;
    char *wlan_user_mac;
    char *wlan_ac_ip;
    char *school_id;
    char *domain;
    char *area;
};

struct codec {
    void *module;
    codec_function code;
    codec_function decode;
    free_function release;
};

static const char *default_config_url =
    "http://14.146.227.141:7001/detect.html";
static const char *default_portal_url =
    "http://125.88.59.131:10001/qs/index_gz.jsp?"
    "wlanacip=183.3.151.148&wlanuserip=172.17.104.132";

static void buffer_free(struct buffer *buffer)
{
    free(buffer->data);
    buffer->data = NULL;
    buffer->length = 0;
}

static int append_bytes(struct buffer *buffer, const char *data, size_t bytes)
{
    char *grown = realloc(buffer->data, buffer->length + bytes + 1);

    if (grown == NULL) {
        return 0;
    }
    memcpy(grown + buffer->length, data, bytes);
    buffer->data = grown;
    buffer->length += bytes;
    buffer->data[buffer->length] = '\0';
    return 1;
}

static int decode_chunked_body(struct buffer *buffer)
{
    char *decoded = malloc(buffer->length + 1);
    size_t input = 0;
    size_t output = 0;

    if (decoded == NULL) {
        return 0;
    }
    while (input < buffer->length) {
        char *line_end = strstr(buffer->data + input, "\r\n");
        unsigned long chunk_size;
        char *end;

        if (line_end == NULL) {
            free(decoded);
            return 0;
        }
        *line_end = '\0';
        chunk_size = strtoul(buffer->data + input, &end, 16);
        if (end == buffer->data + input || *end != '\0') {
            free(decoded);
            return 0;
        }
        input = (size_t)(line_end - buffer->data) + 2;
        if (chunk_size == 0) {
            break;
        }
        if (chunk_size > buffer->length - input ||
            buffer->length - input - chunk_size < 2) {
            free(decoded);
            return 0;
        }
        memcpy(decoded + output, buffer->data + input, (size_t)chunk_size);
        output += (size_t)chunk_size;
        input += (size_t)chunk_size + 2;
    }
    decoded[output] = '\0';
    free(buffer->data);
    buffer->data = decoded;
    buffer->length = output;
    return 1;
}

static int parse_http_url(const char *url, char **host, char **port,
                          char **path)
{
    const char *start;
    const char *slash;
    const char *colon;
    size_t host_length;
    size_t port_length;

    if (strncmp(url, "http://", 7) != 0) {
        return 0;
    }
    start = url + 7;
    slash = strchr(start, '/');
    if (slash == NULL) {
        slash = start + strlen(start);
    }
    colon = memchr(start, ':', (size_t)(slash - start));
    host_length = (size_t)((colon == NULL ? slash : colon) - start);
    if (host_length == 0) {
        return 0;
    }
    *host = strndup(start, host_length);
    if (colon == NULL) {
        *port = strdup("80");
    } else {
        port_length = (size_t)(slash - colon - 1);
        *port = strndup(colon + 1, port_length);
    }
    *path = strdup(*slash == '\0' ? "/" : slash);
    if (*host == NULL || *port == NULL || *path == NULL) {
        free(*host);
        free(*port);
        free(*path);
        return 0;
    }
    return 1;
}

static int send_all(int descriptor, const char *data, size_t length)
{
    while (length != 0) {
        ssize_t written = send(descriptor, data, length, 0);
        if (written <= 0) {
            return 0;
        }
        data += written;
        length -= (size_t)written;
    }
    return 1;
}

static int http_request(const char *url, const char *post_data,
                        const char *extra_headers, const char *user_agent,
                        struct buffer *response, long *status,
                        long *portal_error, const char *cookie,
                        char **new_cookie)
{
    struct addrinfo hints = {0};
    struct addrinfo *addresses = NULL;
    struct addrinfo *address;
    char *host = NULL;
    char *port = NULL;
    char *path = NULL;
    char *request = NULL;
    char *separator;
    int descriptor = -1;
    int connected = 0;
    char receive_buffer[8192];
    ssize_t received;
    size_t header_length;
    int chunked;
    const char *cookie_prefix = cookie == NULL ? "" : "Cookie: ";
    const char *cookie_value = cookie == NULL ? "" : cookie;
    const char *cookie_suffix = cookie == NULL ? "" : "\r\n";

    if (!parse_http_url(url, &host, &port, &path)) {
        return 0;
    }
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host, port, &hints, &addresses) != 0) {
        goto cleanup;
    }
    for (address = addresses; address != NULL; address = address->ai_next) {
        descriptor = socket(address->ai_family, address->ai_socktype,
                            address->ai_protocol);
        if (descriptor >= 0 && connect(descriptor, address->ai_addr,
                                       address->ai_addrlen) == 0) {
            connected = 1;
            break;
        }
        close(descriptor);
        descriptor = -1;
    }
    if (!connected) {
        goto cleanup;
    }
    if (post_data == NULL) {
        if (asprintf(&request, "GET %s HTTP/1.1\r\nHost: %s\r\n%s"
                     "User-Agent: %s\r\n"
                     "Accept: text/html,text/xml,application/xhtml+xml,application/xml,*/*\r\n"
                     "Connection: close\r\n%s%s%s\r\n", path, host,
                     extra_headers != NULL ? extra_headers : "", user_agent,
                     cookie_prefix, cookie_value, cookie_suffix) < 0) {
            goto cleanup;
        }
    } else if (asprintf(&request, "POST %s HTTP/1.1\r\nHost: %s\r\n%s"
                        "Connection: close\r\n"
                        "Content-Type: text/xml; charset=UTF-8\r\n"
                        "Content-Length: %zu\r\n%s%s%s\r\n%s", path, host,
                        extra_headers != NULL ? extra_headers : "", strlen(post_data),
                        cookie_prefix, cookie_value, cookie_suffix,
                        post_data) < 0) {
        goto cleanup;
    }
    if (!send_all(descriptor, request, strlen(request))) {
        goto cleanup;
    }
    while ((received = recv(descriptor, receive_buffer,
                            sizeof(receive_buffer), 0)) > 0) {
        if (!append_bytes(response, receive_buffer, (size_t)received)) {
            goto cleanup;
        }
    }
    separator = strstr(response->data == NULL ? "" : response->data,
                       "\r\n\r\n");
    if (separator == NULL || sscanf(response->data, "HTTP/%*s %ld", status) != 1) {
        goto cleanup;
    }
    if (portal_error != NULL) {
        char *error_header = strcasestr(response->data, "Error-Code:");

        *portal_error = -1;
        if (error_header != NULL) {
            *portal_error = strtol(error_header + strlen("Error-Code:"), NULL, 10);
        }
    }
    if (new_cookie != NULL) {
        char *cookie_start = strcasestr(response->data, "Set-Cookie:");
        if (cookie_start != NULL) {
            char *cookie_end;

            cookie_start += strlen("Set-Cookie:");
            while (*cookie_start == ' ') {
                ++cookie_start;
            }
            cookie_end = strpbrk(cookie_start, ";\r\n");
            if (cookie_end != NULL) {
                free(*new_cookie);
                *new_cookie = strndup(cookie_start,
                                      (size_t)(cookie_end - cookie_start));
            }
        }
    }
    chunked = strcasestr(response->data, "Transfer-Encoding: chunked") != NULL;
    header_length = (size_t)(separator + 4 - response->data);
    memmove(response->data, response->data + header_length,
            response->length - header_length + 1);
    response->length -= header_length;
    if (chunked && !decode_chunked_body(response)) {
        goto cleanup;
    }
    connected = *status >= 200 && *status < 400;

cleanup:
    if (descriptor >= 0) {
        close(descriptor);
    }
    freeaddrinfo(addresses);
    free(host);
    free(port);
    free(path);
    free(request);
    return connected;
}

static char *node_text(xmlNodePtr root, const char *name)
{
    xmlNodePtr node;
    xmlChar *content;

    if (root == NULL) {
        return NULL;
    }
    if (root->type == XML_ELEMENT_NODE &&
        xmlStrcasecmp(root->name, (const xmlChar *)name) == 0) {
        content = xmlNodeGetContent(root);
        if (content != NULL && content[0] != '\0') {
            return (char *)content;
        }
        xmlFree(content);
        return NULL;
    }
    for (node = root->children; node != NULL; node = node->next) {
        xmlChar *content;

        if (node->type != XML_ELEMENT_NODE ||
            xmlStrcasecmp(node->name, (const xmlChar *)name) != 0) {
            continue;
        }
        content = xmlNodeGetContent(node);
        if (content == NULL || content[0] == '\0') {
            xmlFree(content);
            return NULL;
        }
        return (char *)content;
    }
    return NULL;
}

static char *find_text(xmlNodePtr root, const char *first, const char *second)
{
    char *value = node_text(root, first);
    return value != NULL ? value : node_text(root, second);
}

static int set_value(char **destination, char *value)
{
    free(*destination);
    *destination = value;
    return value != NULL;
}

static int parse_config(const char *data, struct portal_config *config)
{
    xmlDocPtr document = xmlReadMemory(data, (int)strlen(data), NULL, NULL,
                                       XML_PARSE_NONET | XML_PARSE_NOERROR);
    xmlNodePtr root;

    if (document == NULL) {
        return 0;
    }
    root = xmlDocGetRootElement(document);
    if (root == NULL) {
        xmlFreeDoc(document);
        return 0;
    }
    set_value(&config->ticket_url, find_text(root, "tickUrl", "ticket-url"));
    set_value(&config->auth_url, find_text(root, "authUrl", "auth-url"));
    set_value(&config->term_url, find_text(root, "termUrl", "term-url"));
    set_value(&config->state_url, find_text(root, "stateUrl", "state-url"));
    set_value(&config->redirect_url, node_text(root, "redirect"));
    set_value(&config->client_id, find_text(root, "clientId", "client-id"));
    set_value(&config->wlan_user_ip, node_text(root, "wlanuserip"));
    set_value(&config->wlan_user_mac, node_text(root, "wlanusermac"));
    set_value(&config->wlan_ac_ip, node_text(root, "wlanacip"));
    set_value(&config->school_id, node_text(root, "schoolId"));
    set_value(&config->domain, node_text(root, "domain"));
    set_value(&config->area, node_text(root, "area"));
    if (config->auth_url == NULL && config->ticket_url != NULL) {
        const char *path = strstr(config->ticket_url, "/ticket.cgi");
        size_t prefix_length = path == NULL ? 0 : (size_t)(path - config->ticket_url);

        if (prefix_length != 0) {
            if (asprintf(&config->auth_url, "%.*s/auth.cgi",
                         (int)prefix_length, config->ticket_url) < 0) {
                config->auth_url = NULL;
            }
        }
    }
    if (config->term_url == NULL && config->ticket_url != NULL) {
        const char *path = strstr(config->ticket_url, "/ticket.cgi");
        size_t prefix_length = path == NULL ? 0 : (size_t)(path - config->ticket_url);

        if (prefix_length != 0) {
            if (asprintf(&config->term_url, "%.*s/term.cgi",
                         (int)prefix_length, config->ticket_url) < 0) {
                config->term_url = NULL;
            }
        }
    }
    xmlFreeDoc(document);
    return config->ticket_url != NULL && config->auth_url != NULL;
}

static char *read_file(const char *path)
{
    FILE *file = fopen(path, "rb");
    long length;
    char *data;

    if (file == NULL || fseek(file, 0, SEEK_END) != 0) {
        if (file != NULL) {
            fclose(file);
        }
        return NULL;
    }
    length = ftell(file);
    if (length < 0 || fseek(file, 0, SEEK_SET) != 0) {
        fclose(file);
        return NULL;
    }
    data = malloc((size_t)length + 1);
    if (data == NULL || fread(data, 1, (size_t)length, file) != (size_t)length) {
        free(data);
        fclose(file);
        return NULL;
    }
    data[length] = '\0';
    fclose(file);
    return data;
}

static char *query_value(const char *url, const char *name)
{
    char *marker;
    char *end;
    size_t length;

    marker = strstr(url, name);
    if (marker == NULL || (marker != url && marker[-1] != '?' && marker[-1] != '&') ||
        marker[strlen(name)] != '=') {
        return NULL;
    }
    marker += strlen(name) + 1;
    end = strpbrk(marker, "&#");
    length = end == NULL ? strlen(marker) : (size_t)(end - marker);
    return strndup(marker, length);
}

static char *replace_query_value(const char *url, const char *name,
                                 const char *value)
{
    char *marker = strstr(url, name);
    const char *value_start;
    const char *value_end;
    size_t prefix_length;
    size_t suffix_length;
    char *result;

    if (marker == NULL || (marker != url && marker[-1] != '?' && marker[-1] != '&') ||
        marker[strlen(name)] != '=') {
        return strdup(url);
    }
    value_start = marker + strlen(name) + 1;
    value_end = strpbrk(value_start, "&#");
    if (value_end == NULL) {
        value_end = url + strlen(url);
    }
    prefix_length = (size_t)(value_start - url);
    suffix_length = strlen(value_end);
    result = malloc(prefix_length + strlen(value) + suffix_length + 1);
    if (result == NULL) {
        return NULL;
    }
    memcpy(result, url, prefix_length);
    memcpy(result + prefix_length, value, strlen(value));
    memcpy(result + prefix_length + strlen(value), value_end, suffix_length);
    result[prefix_length + strlen(value) + suffix_length] = '\0';
    return result;
}

static void config_free(struct portal_config *config)
{
    free(config->ticket_url);
    free(config->auth_url);
    free(config->term_url);
    free(config->state_url);
    free(config->redirect_url);
    free(config->client_id);
    free(config->user_agent);
    free(config->wlan_user_ip);
    free(config->wlan_user_mac);
    free(config->wlan_ac_ip);
    free(config->school_id);
    free(config->domain);
    free(config->area);
}

static int load_codec(const char *path, struct codec *codec)
{
    void *symbol;

    codec->module = dlopen(path, RTLD_NOW | RTLD_LOCAL);
    if (codec->module == NULL) {
        return 0;
    }
    symbol = dlsym(codec->module, "Code");
    memcpy(&codec->code, &symbol, sizeof(codec->code));
    symbol = dlsym(codec->module, "DeCode");
    memcpy(&codec->decode, &symbol, sizeof(codec->decode));
    symbol = dlsym(codec->module, "FreeResult");
    memcpy(&codec->release, &symbol, sizeof(codec->release));
    if (codec->code == NULL || codec->decode == NULL || codec->release == NULL) {
        dlclose(codec->module);
        memset(codec, 0, sizeof(*codec));
        return 0;
    }
    return 1;
}

static void unload_codec(struct codec *codec)
{
    if (codec->module != NULL) {
        dlclose(codec->module);
    }
}

/* --- MD5 (RFC 1321) ----------------------------------------------------- */

struct md5_state {
    unsigned int digest[4];
    unsigned long long length;
    unsigned char block[64];
    size_t used;
};

static unsigned int md5_rotate(unsigned int value, unsigned int bits)
{
    return (value << bits) | (value >> (32 - bits));
}

static void md5_transform(struct md5_state *state, const unsigned char *data)
{
    static const unsigned int shifts[64] = {
        7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
        5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
        4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
        6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21
    };
    static const unsigned int constants[64] = {
        0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf,
        0x4787c62a, 0xa8304613, 0xfd469501, 0x698098d8, 0x8b44f7af,
        0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e,
        0x49b40821, 0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
        0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8, 0x21e1cde6,
        0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8,
        0x676f02d9, 0x8d2a4c8a, 0xfffa3942, 0x8771f681, 0x6d9d6122,
        0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
        0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039,
        0xe6db99e5, 0x1fa27cf8, 0xc4ac5665, 0xf4292244, 0x432aff97,
        0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d,
        0x85845dd1, 0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
        0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
    };
    unsigned int a = state->digest[0];
    unsigned int b = state->digest[1];
    unsigned int c = state->digest[2];
    unsigned int d = state->digest[3];
    unsigned int message[16];
    int index;

    for (index = 0; index < 16; ++index) {
        message[index] = (unsigned int)data[index * 4] |
                         ((unsigned int)data[index * 4 + 1] << 8) |
                         ((unsigned int)data[index * 4 + 2] << 16) |
                         ((unsigned int)data[index * 4 + 3] << 24);
    }
    for (index = 0; index < 64; ++index) {
        unsigned int mix;
        unsigned int slot;
        unsigned int temp;

        if (index < 16) {
            mix = (b & c) | (~b & d);
            slot = (unsigned int)index;
        } else if (index < 32) {
            mix = (d & b) | (~d & c);
            slot = (unsigned int)(5 * index + 1) % 16;
        } else if (index < 48) {
            mix = b ^ c ^ d;
            slot = (unsigned int)(3 * index + 5) % 16;
        } else {
            mix = c ^ (b | ~d);
            slot = (unsigned int)(7 * index) % 16;
        }
        temp = d;
        d = c;
        c = b;
        b += md5_rotate(a + mix + constants[index] + message[slot],
                        shifts[index]);
        a = temp;
    }
    state->digest[0] += a;
    state->digest[1] += b;
    state->digest[2] += c;
    state->digest[3] += d;
}

static void md5_init(struct md5_state *state)
{
    state->digest[0] = 0x67452301;
    state->digest[1] = 0xefcdab89;
    state->digest[2] = 0x98badcfe;
    state->digest[3] = 0x10325476;
    state->length = 0;
    state->used = 0;
}

static void md5_update(struct md5_state *state, const unsigned char *data,
                       size_t length)
{
    state->length += (unsigned long long)length;
    while (length != 0) {
        size_t space = 64 - state->used;
        size_t take = length < space ? length : space;

        memcpy(state->block + state->used, data, take);
        state->used += take;
        data += take;
        length -= take;
        if (state->used == 64) {
            md5_transform(state, state->block);
            state->used = 0;
        }
    }
}

static void md5_finish(struct md5_state *state, unsigned char digest[16])
{
    unsigned long long bits = state->length * 8;
    unsigned char padding[64] = {0x80};
    unsigned char tail[8];
    size_t pad_length = state->used < 56 ? 56 - state->used
                                         : 120 - state->used;
    int index;

    for (index = 0; index < 8; ++index) {
        tail[index] = (unsigned char)(bits >> (index * 8));
    }
    md5_update(state, padding, pad_length);
    md5_update(state, tail, 8);
    for (index = 0; index < 4; ++index) {
        digest[index * 4] = (unsigned char)state->digest[index];
        digest[index * 4 + 1] = (unsigned char)(state->digest[index] >> 8);
        digest[index * 4 + 2] = (unsigned char)(state->digest[index] >> 16);
        digest[index * 4 + 3] = (unsigned char)(state->digest[index] >> 24);
    }
}

static int md5_hex_lower(const char *data, char output[33])
{
    static const char hex[] = "0123456789abcdef";
    struct md5_state state;
    unsigned char digest[16];
    int index;

    md5_init(&state);
    md5_update(&state, (const unsigned char *)data, strlen(data));
    md5_finish(&state, digest);
    for (index = 0; index < 16; ++index) {
        output[index * 2] = hex[digest[index] >> 4];
        output[index * 2 + 1] = hex[digest[index] & 0x0f];
    }
    output[32] = '\0';
    return 1;
}

/* --- Runtime helpers ---------------------------------------------------- */

static int local_ipv4(char *output, size_t size)
{
    struct ifaddrs *addresses = NULL;
    struct ifaddrs *address;
    const char *override = getenv("GD_LOCAL_IP");
    int best_score = -1;
    char best_address[64] = {0};

    if (override != NULL && override[0] != '\0') {
        snprintf(output, size, "%s", override);
        return 1;
    }
    if (getifaddrs(&addresses) != 0) {
        return 0;
    }
    for (address = addresses; address != NULL; address = address->ifa_next) {
        struct sockaddr_in *socket_address;
        int score;

        if (address->ifa_addr == NULL ||
            address->ifa_addr->sa_family != AF_INET ||
            address->ifa_name == NULL ||
            strcmp(address->ifa_name, "lo") == 0) {
            continue;
        }
        socket_address = (struct sockaddr_in *)address->ifa_addr;
        if (socket_address->sin_addr.s_addr == htonl(INADDR_LOOPBACK)) {
            continue;
        }
        if (strncmp(address->ifa_name, "wl", 2) == 0) {
            score = 3;
        } else if (strncmp(address->ifa_name, "en", 2) == 0 ||
                   strncmp(address->ifa_name, "eth", 3) == 0 ||
                   strncmp(address->ifa_name, "br", 2) == 0) {
            score = 2;
        } else {
            score = 1;
        }
        if (score > best_score &&
            inet_ntop(AF_INET, &socket_address->sin_addr, best_address,
                      (socklen_t)sizeof(best_address)) != NULL) {
            best_score = score;
        }
    }
    freeifaddrs(addresses);
    if (best_score < 0) {
        return 0;
    }
    snprintf(output, size, "%s", best_address);
    return 1;
}

/* Pick the source address the kernel would use to reach host:port. */
static int local_ipv4_route(const char *host, const char *port, char *output,
                            size_t size)
{
    struct addrinfo hints = {0};
    struct addrinfo *addresses = NULL;
    struct addrinfo *address;
    int found = 0;

    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;
    if (getaddrinfo(host, port, &hints, &addresses) != 0) {
        return 0;
    }
    for (address = addresses; address != NULL; address = address->ai_next) {
        struct sockaddr_in local;
        socklen_t length = sizeof(local);
        int descriptor = socket(address->ai_family, address->ai_socktype,
                                address->ai_protocol);

        if (descriptor < 0) {
            continue;
        }
        if (connect(descriptor, address->ai_addr, address->ai_addrlen) == 0 &&
            getsockname(descriptor, (struct sockaddr *)&local, &length) == 0 &&
            local.sin_family == AF_INET &&
            inet_ntop(AF_INET, &local.sin_addr, output,
                      (socklen_t)size) != NULL) {
            found = 1;
        }
        close(descriptor);
        if (found) {
            break;
        }
    }
    freeaddrinfo(addresses);
    return found;
}

static int local_ipv4_for_url(const char *url, char *output, size_t size)
{
    char *host = NULL;
    char *port = NULL;
    char *path = NULL;
    int found = 0;

    if (parse_http_url(url, &host, &port, &path)) {
        found = local_ipv4_route(host, port, output, size);
    }
    free(host);
    free(port);
    free(path);
    return found;
}

static void local_time_now(char *output, size_t size)
{
    time_t current = time(NULL);
    struct tm broken;

    localtime_r(&current, &broken);
    strftime(output, size, "%Y-%m-%d %H:%M:%S", &broken);
}

static int skip_byte(FILE *file, int *value)
{
    int byte = fgetc(file);

    if (byte == EOF) {
        return 0;
    }
    *value = byte;
    return 1;
}

static char *read_container_string(FILE *file, size_t length)
{
    char *value = malloc(length + 1);

    if (value == NULL) {
        return NULL;
    }
    if (length != 0 && fread(value, 1, length, file) != length) {
        free(value);
        return NULL;
    }
    value[length] = '\0';
    return value;
}

/* The zsm container stores "3-byte tag, length-prefixed string, algo id". */
static char *container_algo_id(const char *path)
{
    FILE *file = fopen(path, "rb");
    char *discarded;
    char *algo_id;
    int length;
    int index;

    if (file == NULL) {
        return NULL;
    }
    for (index = 0; index < 3; ++index) {
        if (!skip_byte(file, &length)) {
            fclose(file);
            return NULL;
        }
    }
    if (!skip_byte(file, &length)) {
        fclose(file);
        return NULL;
    }
    discarded = read_container_string(file, (size_t)length);
    if (discarded == NULL) {
        fclose(file);
        return NULL;
    }
    free(discarded);
    if (!skip_byte(file, &length) || length == 0) {
        fclose(file);
        return NULL;
    }
    algo_id = read_container_string(file, (size_t)length);
    fclose(file);
    return algo_id;
}

static char *resolve_algo_id(const char *module_path)
{
    const char *configured = getenv("GD_ALGO_ID");
    const char *container = getenv("GD_ZSM_PATH");
    char *candidate = NULL;
    char *value;

    if (configured != NULL && configured[0] != '\0') {
        return strdup(configured);
    }
    if (container != NULL && container[0] != '\0') {
        value = container_algo_id(container);
        if (value != NULL) {
            return value;
        }
    }
    value = container_algo_id("zxmAlogic.zxm");
    if (value != NULL) {
        return value;
    }
    if (module_path != NULL) {
        char *slash = strrchr(module_path, '/');

        if (slash != NULL) {
            size_t directory = (size_t)(slash - module_path);

            if (asprintf(&candidate, "%.*s/zxmAlogic.zxm", (int)directory,
                         module_path) >= 0) {
                value = container_algo_id(candidate);
                free(candidate);
                if (value != NULL) {
                    return value;
                }
            }
        }
    }
    return NULL;
}

/* --- Request construction ----------------------------------------------- */

static char *make_ticket_request(const char *host_name, const char *user_agent,
                                 const char *client_id, const char *ipv4,
                                 const char *ipv6, const char *mac,
                                 const char *local_time, const char *ostag)
{
    char *request = NULL;

    if (asprintf(&request,
                 "<?xml version=\"1.0\" encoding=\"UTF-8\"?><request>"
                 "<host-name>%s</host-name><user-agent>%s</user-agent>"
                 "<client-id>%s</client-id><ipv4>%s</ipv4><ipv6>%s</ipv6>"
                 "<mac>%s</mac><local-time>%s</local-time>"
                 "<ostag>%s</ostag></request>",
                 host_name, user_agent, client_id, ipv4, ipv6, mac, local_time,
                 ostag) < 0) {
        return NULL;
    }
    return request;
}

static char *make_term_request(const char *user_agent, const char *client_id,
                               const char *ticket, const char *local_time,
                               const char *reason)
{
    char *request = NULL;

    if (asprintf(&request,
                 "<?xml version=\"1.0\" encoding=\"UTF-8\"?><request>"
                 "<user-agent>%s</user-agent><client-id>%s</client-id>"
                 "<ticket>%s</ticket><local-time>%s</local-time>"
                 "<reason>%s</reason></request>",
                 user_agent, client_id, ticket, local_time, reason) < 0) {
        return NULL;
    }
    return request;
}

static char *make_request_headers(const char *user_agent, const char *algo_id,
                                  const char *client_id, const char *body,
                                  const struct portal_config *config)
{
    char digest[33];
    char *headers = NULL;

    if (!md5_hex_lower(body, digest)) {
        return NULL;
    }
    if (asprintf(&headers,
                 "User-Agent:%s\r\nAlgo-ID:%s\r\nClient-ID:%s\r\n"
                 "CDC-Checksum:%s\r\nCDC-SchoolId:%s\r\nCDC-Domain:%s\r\n"
                 "CDC-Area:%s\r\n",
                 user_agent, algo_id, client_id, digest,
                 config->school_id != NULL ? config->school_id : "",
                 config->domain != NULL ? config->domain : "",
                 config->area != NULL ? config->area : "") < 0) {
        return NULL;
    }
    return headers;
}

/* --- Dynamic config (index.cgi) ----------------------------------------- */

/* Keep the query string from "existing" but use the server base from "base". */
static char *merge_config_url(const char *base, const char *existing)
{
    const char *query = strchr(existing, '?');
    size_t base_length = strlen(base);
    char *result = NULL;

    if (query == NULL) {
        return strdup(base);
    }
    if (base_length != 0 && base[base_length - 1] == '?') {
        if (asprintf(&result, "%s%s", base, query + 1) < 0) {
            return NULL;
        }
    } else {
        if (asprintf(&result, "%s%s", base, query) < 0) {
            return NULL;
        }
    }
    return result;
}

/* Pick a server from "host:port,host:port", preferring the current one. */
static char *choose_server(const char *servers, const char *existing_url)
{
    char *copy = strdup(servers);
    char *token;
    char *save = NULL;
    char *first = NULL;
    char *match = NULL;
    char authority[160] = "";
    char *host = NULL;
    char *port = NULL;
    char *path = NULL;

    if (existing_url != NULL &&
        parse_http_url(existing_url, &host, &port, &path)) {
        snprintf(authority, sizeof(authority), "%s:%s", host, port);
    }
    free(host);
    free(port);
    free(path);
    if (copy == NULL) {
        return NULL;
    }
    for (token = strtok_r(copy, ",", &save); token != NULL;
         token = strtok_r(NULL, ",", &save)) {
        while (*token == ' ') {
            ++token;
        }
        if (first == NULL) {
            first = strdup(token);
        }
        if (authority[0] != '\0' && strcmp(token, authority) == 0) {
            match = strdup(token);
            break;
        }
    }
    free(copy);
    if (match != NULL) {
        free(first);
        return match;
    }
    return first;
}

static char *build_dynamic_url(const char *server, const char *base,
                               const char *existing)
{
    const char *path;
    const char *query;
    char *path_only = NULL;
    char *result = NULL;
    size_t path_length;

    path = strstr(base, "://");
    path = path != NULL ? path + 3 : base;
    path = strchr(path, '/');
    if (path == NULL) {
        path = "/";
    }
    query = strchr(path, '?');
    path_length = query != NULL ? (size_t)(query - path) : strlen(path);
    path_only = strndup(path, path_length);
    if (path_only == NULL) {
        return NULL;
    }
    query = strchr(existing, '?');
    if (query != NULL) {
        if (asprintf(&result, "http://%s%s%s", server, path_only, query) < 0) {
            result = NULL;
        }
    } else if (asprintf(&result, "http://%s%s", server, path_only) < 0) {
        result = NULL;
    }
    free(path_only);
    return result;
}

/* Set (replace or append) a query parameter. */
static char *set_query_param(const char *url, const char *name, const char *value)
{
    size_t length = strlen(url);
    const char *separator;

    if (query_value(url, name) != NULL) {
        return replace_query_value(url, name, value);
    }
    if (length != 0 && url[length - 1] == '?') {
        separator = "";
    } else {
        separator = strchr(url, '?') != NULL ? "&" : "?";
    }
    {
        char *result = NULL;

        if (asprintf(&result, "%s%s%s=%s", url, separator, name, value) < 0) {
            return NULL;
        }
        return result;
    }
}

static int local_mac_for_ip(const char *ip, char *output, size_t size)
{
    struct ifaddrs *addresses = NULL;
    struct ifaddrs *address;
    int found = 0;

    if (getifaddrs(&addresses) != 0) {
        return 0;
    }
    for (address = addresses; address != NULL; address = address->ifa_next) {
        struct sockaddr_in *socket_address;
        char text[64];

        if (address->ifa_addr == NULL ||
            address->ifa_addr->sa_family != AF_INET ||
            address->ifa_name == NULL) {
            continue;
        }
        socket_address = (struct sockaddr_in *)address->ifa_addr;
        if (inet_ntop(AF_INET, &socket_address->sin_addr, text,
                      sizeof(text)) == NULL ||
            strcmp(text, ip) != 0) {
            continue;
        }
        {
            char path[256];
            FILE *file;

            snprintf(path, sizeof(path), "/sys/class/net/%s/address",
                     address->ifa_name);
            file = fopen(path, "r");
            if (file != NULL) {
                if (fgets(output, (int)size, file) != NULL) {
                    output[strcspn(output, "\r\n")] = '\0';
                    found = 1;
                }
                fclose(file);
            }
        }
        break;
    }
    freeifaddrs(addresses);
    return found;
}

/* Copy session parameters from a portal URL into the ticket URL query. */
static void rederive_term_url(struct portal_config *config);

static void apply_portal_params(struct portal_config *config,
                                const char *portal_url)
{
    static const char *keys[] = {
        "wlanacip", "wlanuserip", "wlanacname", "wlanusermac", "clientmac",
        "clientip", "paip", "vlan", "iarmdst", "portal_node"
    };
    size_t index;

    for (index = 0; index < sizeof(keys) / sizeof(keys[0]); ++index) {
        char *value = query_value(portal_url, keys[index]);

        if (value == NULL) {
            continue;
        }
        {
            char *updated = set_query_param(config->ticket_url, keys[index],
                                            value);

            if (updated != NULL) {
                free(config->ticket_url);
                config->ticket_url = updated;
            }
        }
        free(value);
    }
    {
        char *ip = query_value(config->ticket_url, "wlanuserip");

        if (ip != NULL) {
            char *updated = set_query_param(config->ticket_url, "clientip", ip);

            if (updated != NULL) {
                free(config->ticket_url);
                config->ticket_url = updated;
            }
            free(ip);
        }
    }
    rederive_term_url(config);
}

static void rederive_term_url(struct portal_config *config)
{
    const char *marker = strstr(config->ticket_url, "ticket.cgi");

    if (marker != NULL) {
        size_t prefix = (size_t)(marker - config->ticket_url);
        char *joined = NULL;

        if (asprintf(&joined, "%.*sterm.cgi%s", (int)prefix, config->ticket_url,
                     marker + strlen("ticket.cgi")) >= 0) {
            free(config->term_url);
            config->term_url = joined;
        }
    }
}

static char *derive_index_url(const char *redirect)
{
    char *host = NULL;
    char *port = NULL;
    char *path = NULL;
    char *result = NULL;

    if (redirect == NULL || !parse_http_url(redirect, &host, &port, &path)) {
        return NULL;
    }
    if (asprintf(&result, "http://%s:%s/index.cgi", host, port) < 0) {
        result = NULL;
    }
    free(host);
    free(port);
    free(path);
    return result;
}

static int fetch_dynamic_config(const char *config_url,
                                struct portal_config *config, int verbose)
{
    struct buffer response = {0};
    long status = 0;
    char *start;
    char *end;
    xmlDocPtr document;
    xmlNodePtr root;
    char *ticket = NULL;
    char *auth = NULL;
    char *state_url = NULL;
    char *servers = NULL;
    int ok = 0;

    if (!http_request(config_url, NULL, NULL, "CCTP/Linux64/2.4.64", &response,
                      &status, NULL, NULL, NULL)) {
        buffer_free(&response);
        return 0;
    }
    start = strstr(response.data, "<config>");
    end = start != NULL ? strstr(start, "</config>") : NULL;
    if (start == NULL || end == NULL) {
        buffer_free(&response);
        return 0;
    }
    end += strlen("</config>");
    document = xmlReadMemory(start, (int)(end - start), NULL, NULL,
                             XML_PARSE_NONET | XML_PARSE_NOERROR);
    buffer_free(&response);
    if (document == NULL) {
        return 0;
    }
    root = xmlDocGetRootElement(document);
    if (root != NULL &&
        xmlStrcasecmp(root->name, (const xmlChar *)"config") == 0) {
        ticket = node_text(root, "ticket-url");
        auth = node_text(root, "auth-url");
        state_url = node_text(root, "state-url");
        servers = node_text(root, "ServerIPs");
        {
            char *chosen = servers != NULL
                               ? choose_server(servers, config->ticket_url)
                               : NULL;

            if (ticket != NULL) {
                char *updated = chosen != NULL
                                    ? build_dynamic_url(chosen, ticket,
                                                        config->ticket_url)
                                    : merge_config_url(ticket,
                                                       config->ticket_url);

                if (updated != NULL) {
                    free(config->ticket_url);
                    config->ticket_url = updated;
                }
            }
            if (auth != NULL) {
                char *updated = chosen != NULL
                                    ? build_dynamic_url(chosen, auth,
                                                        config->ticket_url)
                                    : merge_config_url(auth,
                                                       config->ticket_url);

                if (updated != NULL) {
                    free(config->auth_url);
                    config->auth_url = updated;
                }
            }
            if (state_url != NULL) {
                char *updated = chosen != NULL
                                    ? build_dynamic_url(chosen, state_url,
                                                        config->ticket_url)
                                    : merge_config_url(state_url,
                                                       config->ticket_url);

                if (updated != NULL) {
                    free(config->state_url);
                    config->state_url = updated;
                }
            }
            free(chosen);
        }
        if (config->ticket_url != NULL) {
            rederive_term_url(config);
        }
        if (verbose) {
            fprintf(stderr, "debug=dynamic ticket=%s auth=%s servers=%s\n",
                    config->ticket_url != NULL ? config->ticket_url : "",
                    config->auth_url != NULL ? config->auth_url : "",
                    servers != NULL ? servers : "");
        }
        ok = 1;
    }
    xmlFree(ticket);
    xmlFree(auth);
    xmlFree(state_url);
    xmlFree(servers);
    xmlFreeDoc(document);
    return ok;
}

static char *parse_ticket(const char *data)
{
    xmlDocPtr document = xmlReadMemory(data, (int)strlen(data), NULL, NULL,
                                       XML_PARSE_NONET | XML_PARSE_NOERROR);
    xmlNodePtr root;
    char *ticket;

    if (document == NULL) {
        return NULL;
    }
    root = xmlDocGetRootElement(document);
    ticket = find_text(root, "ticket", "Ticket");
    xmlFreeDoc(document);
    return ticket;
}

static char *make_auth_request(const char *user_agent, const char *client_id,
                               const char *user_id, const char *password,
                               const char *ticket, const char *local_time)
{
    const char *names[] = {"user-agent", "client-id", "userid", "passwd",
                           "ticket", "local-time"};
    const char *values[] = {user_agent, client_id, user_id, password, ticket,
                            local_time};
    xmlDocPtr document = xmlNewDoc((const xmlChar *)"1.0");
    xmlNodePtr root;
    xmlChar *data = NULL;
    int length = 0;
    char *result;
    size_t index;

    if (document == NULL || (root = xmlNewNode(NULL, (const xmlChar *)"request")) == NULL) {
        xmlFreeDoc(document);
        return NULL;
    }
    xmlDocSetRootElement(document, root);
    for (index = 0; index < sizeof(names) / sizeof(names[0]); ++index) {
        if (xmlNewChild(root, NULL, (const xmlChar *)names[index],
                        (const xmlChar *)values[index]) == NULL) {
            xmlFreeDoc(document);
            return NULL;
        }
    }
    xmlDocDumpMemoryEnc(document, &data, &length, "UTF-8");
    if (data == NULL || length <= 0) {
        xmlFree(data);
        xmlFreeDoc(document);
        return NULL;
    }
    result = strndup((const char *)data, (size_t)length);
    xmlFree(data);
    xmlFreeDoc(document);
    return result;
}

static int auth_succeeded(const char *data, char **message)
{
    xmlDocPtr document = xmlReadMemory(data, (int)strlen(data), NULL, NULL,
                                       XML_PARSE_NONET | XML_PARSE_NOERROR);
    xmlNodePtr root;
    char *user_id = NULL;
    char *keep_retry = NULL;
    char *error = NULL;
    int success = 0;

    if (document == NULL) {
        return 0;
    }
    root = xmlDocGetRootElement(document);
    if (root != NULL &&
        xmlStrcasecmp(root->name, (const xmlChar *)"response") == 0) {
        user_id = find_text(root, "userid", "user-id");
        keep_retry = find_text(root, "keep-retry", "keepRetry");
        error = find_text(root, "message", "error");
        success = user_id != NULL && user_id[0] != '\0';
        if (!success) {
            if (error != NULL) {
                set_value(message, error);
                error = NULL;
            } else if (keep_retry != NULL) {
                char *detail = NULL;

                if (asprintf(&detail, "result=%s", keep_retry) >= 0) {
                    set_value(message, detail);
                }
            } else {
                set_value(message, strdup("auth-response"));
            }
        }
    }
    xmlFree(user_id);
    xmlFree(keep_retry);
    xmlFree(error);
    xmlFreeDoc(document);
    return success;
}

/* --- Server error text (conf/code.xml) ---------------------------------- */

/* The client ships conf/code.xml with "<err id="140102.13014000" value=..."/>"
   entries; the original looks them up as "<Error-Code>.<sub code>" (CGuard
   uses the format "%ld.%s"). We do the same so failures are readable. */

struct error_entry {
    char *id;
    char *text;
};

static struct error_entry *error_entries = NULL;
static size_t error_entries_count = 0;
static int error_table_loaded = 0;

static void append_error_entry(char *id, char *text)
{
    struct error_entry *grown;

    if (id == NULL || text == NULL) {
        free(id);
        free(text);
        return;
    }
    grown = realloc(error_entries,
                    (error_entries_count + 1) * sizeof(*error_entries));
    if (grown == NULL) {
        free(id);
        free(text);
        return;
    }
    error_entries = grown;
    error_entries[error_entries_count].id = id;
    error_entries[error_entries_count].text = text;
    error_entries_count += 1;
}

static void load_error_table(void)
{
    xmlDocPtr document;
    xmlNodePtr root;
    xmlNodePtr node;

    if (error_table_loaded) {
        return;
    }
    error_table_loaded = 1;
    /* The shipped conf/code.xml is not strictly well formed (some values
       contain a bare '<', e.g. "(>_<)"), so recover instead of giving up. */
    document = xmlReadFile("conf/code.xml", NULL,
                           XML_PARSE_RECOVER | XML_PARSE_NONET |
                           XML_PARSE_NOERROR | XML_PARSE_NOWARNING);
    if (document == NULL) {
        return;
    }
    root = xmlDocGetRootElement(document);
    for (node = root != NULL ? root->children : NULL; node != NULL;
         node = node->next) {
        xmlChar *id;
        xmlChar *value;

        if (node->type != XML_ELEMENT_NODE) {
            continue;
        }
        id = xmlGetProp(node, (const xmlChar *)"id");
        if (id == NULL) {
            id = xmlGetProp(node, (const xmlChar *)"code");
        }
        value = xmlGetProp(node, (const xmlChar *)"value");
        if (id == NULL || value == NULL) {
            xmlFree(id);
            xmlFree(value);
            continue;
        }
        append_error_entry(strdup((const char *)id),
                           strdup((const char *)value));
        xmlFree(id);
        xmlFree(value);
    }
    xmlFreeDoc(document);
}

static const char *lookup_error_text(const char *key)
{
    size_t index;

    if (key == NULL) {
        return NULL;
    }
    load_error_table();
    for (index = 0; index < error_entries_count; ++index) {
        if (error_entries[index].id != NULL &&
            strcmp(error_entries[index].id, key) == 0) {
            return error_entries[index].text;
        }
    }
    return NULL;
}

static int is_code_token(const char *text)
{
    size_t length;
    size_t index;

    if (text == NULL) {
        return 0;
    }
    length = strlen(text);
    if (length == 0 || length > 24) {
        return 0;
    }
    for (index = 0; index < length; ++index) {
        if (text[index] < '0' || text[index] > '9') {
            return 0;
        }
    }
    return 1;
}

/* Sub code reported inside the response body (e.g. 140102 + 13014000). */
static char *response_subcode(const char *decoded)
{
    static const char *tags[] = {"error-code", "errcode", "sub-code",
                                 "subcode", "reason"};
    xmlDocPtr document;
    xmlNodePtr root;
    char *found = NULL;
    size_t index;

    if (decoded == NULL || decoded[0] == '\0') {
        return NULL;
    }
    document = xmlReadMemory(decoded, (int)strlen(decoded), NULL, NULL,
                             XML_PARSE_NONET | XML_PARSE_NOERROR |
                             XML_PARSE_NOWARNING);
    if (document == NULL) {
        return NULL;
    }
    root = xmlDocGetRootElement(document);
    for (index = 0; index < sizeof(tags) / sizeof(tags[0]) && found == NULL;
         ++index) {
        char *text = node_text(root, tags[index]);

        if (text != NULL && is_code_token(text)) {
            found = text;
        } else {
            free(text);
        }
    }
    xmlFreeDoc(document);
    return found;
}

static void set_server_error(char **message, long code, const char *decoded)
{
    char *sub = response_subcode(decoded);
    char key[64];
    const char *text = NULL;
    char *full = NULL;
    int used_sub = 0;

    if (message == NULL) {
        free(sub);
        return;
    }
    /* conf/code.xml keys are "140" + three digit code (e.g. 200 -> 140200),
       optionally followed by ".<sub code>" (e.g. 140102.13014000). */
    if (sub != NULL) {
        snprintf(key, sizeof(key), "140%03ld.%s", code, sub);
        text = lookup_error_text(key);
        if (text == NULL) {
            snprintf(key, sizeof(key), "%ld.%s", code, sub);
            text = lookup_error_text(key);
        }
        used_sub = text != NULL;
    }
    if (text == NULL) {
        snprintf(key, sizeof(key), "140%03ld", code);
        text = lookup_error_text(key);
    }
    if (text == NULL) {
        snprintf(key, sizeof(key), "%ld", code);
        text = lookup_error_text(key);
    }
    if (text != NULL) {
        if (used_sub) {
            if (asprintf(&full, "server-error=%ld.%s | %s", code, sub,
                         text) < 0) {
                full = NULL;
            }
        } else if (asprintf(&full, "server-error=%ld | %s", code, text) < 0) {
            full = NULL;
        }
    }
    if (full == NULL && asprintf(&full, "server-error=%ld", code) < 0) {
        full = NULL;
    }
    free(sub);
    if (full != NULL) {
        free(*message);
        *message = full;
    }
}

/* Decode the (still encoded) error body so the sub code can be looked up. */
static void set_error_from_response(struct codec *codec, char **message,
                                    long code, struct buffer *response)
{
    char *body = NULL;

    if (response != NULL && response->data != NULL && response->length > 0 &&
        response->length < 8192) {
        body = codec->decode(response->data);
    }
    if (getenv("GD_DEBUG") != NULL && atoi(getenv("GD_DEBUG")) >= 2) {
        fprintf(stderr, "debug=error-body=%s\n",
                body != NULL ? body : response != NULL && response->data != NULL
                                   ? "(undecodable)"
                                   : "(empty)");
    }
    set_server_error(message, code, body);
    if (body != NULL) {
        codec->release(body);
    }
}

static void print_state(const char *state, const char *detail)
{
    printf("state=%s\n", state);
    if (detail != NULL) {
        printf("detail=%s\n", detail);
    }
}

/* --- Keep-alive / IPC (named pipes) ------------------------------------- */

#define PIPE_MESSAGE_LIMIT 65536

struct session_info {
    char *ticket;
    char *keep_url;
    long keep_interval;
};

static char *make_keep_request(const char *user_agent, const char *client_id,
                               const char *ticket, const char *ipv4,
                               const char *ipv6, const char *mac,
                               const char *local_time, int shared)
{
    char *request = NULL;

    if (asprintf(&request,
                 "<?xml version=\"1.0\" encoding=\"UTF-8\"?><request>"
                 "<user-agent>%s</user-agent><client-id>%s</client-id>"
                 "<ticket>%s</ticket><ipv4>%s</ipv4><ipv6>%s</ipv6>"
                 "<mac>%s</mac><local-time>%s</local-time>"
                 "<shared>%d</shared></request>",
                 user_agent, client_id, ticket, ipv4, ipv6, mac, local_time,
                 shared) < 0) {
        return NULL;
    }
    return request;
}

static void parse_keep_info(const char *data, char **keep_url, long *interval)
{
    xmlDocPtr document = xmlReadMemory(data, (int)strlen(data), NULL, NULL,
                                       XML_PARSE_NONET | XML_PARSE_NOERROR);
    xmlNodePtr root;

    (void)interval;
    if (document == NULL) {
        return;
    }
    root = xmlDocGetRootElement(document);
    if (root != NULL &&
        xmlStrcasecmp(root->name, (const xmlChar *)"response") == 0) {
        char *url = node_text(root, "keep-url");
        char *retry = node_text(root, "keep-retry");

        if (url != NULL && url[0] != '\0' && *keep_url == NULL) {
            *keep_url = strdup(url);
        }
        xmlFree(url);
        xmlFree(retry);
    }
    xmlFreeDoc(document);
}

/* keep-retry is a counter, not the interval; use a safe default (env override). */
static long keep_default_interval(void)
{
    const char *configured = getenv("GD_KEEP_INTERVAL");
    long value = configured != NULL ? strtol(configured, NULL, 10) : 30;

    if (value < 5) {
        value = 30;
    }
    return value;
}

static char *make_state_request(const char *user_agent, const char *client_id,
                                const char *ticket, const char *local_time)
{
    char *request = NULL;

    if (asprintf(&request,
                 "<?xml version=\"1.0\" encoding=\"UTF-8\"?><request>"
                 "<user-agent>%s</user-agent><client-id>%s</client-id>"
                 "<ticket>%s</ticket><local-time>%s</local-time></request>",
                 user_agent, client_id, ticket, local_time) < 0) {
        return NULL;
    }
    return request;
}

static int perform_state(struct codec *codec,
                         const struct portal_config *config,
                         const char *user_agent, const char *algo_id,
                         const char *client_id, const char *ticket,
                         int verbose, long *error_out, char **message)
{
    struct buffer response = {0};
    char local_time[32];
    char *request = NULL;
    char *encoded = NULL;
    char *headers = NULL;
    long status = 0;
    long error = -1;
    int online = 0;

    if (config->state_url == NULL) {
        if (message != NULL) {
            *message = strdup("no-state-url");
        }
        return 0;
    }
    local_time_now(local_time, sizeof(local_time));
    request = make_state_request(user_agent, client_id, ticket, local_time);
    if (request == NULL) {
        goto done;
    }
    encoded = codec->code(request);
    if (encoded == NULL) {
        goto done;
    }
    headers = make_request_headers(user_agent, algo_id, client_id, encoded,
                                   config);
    if (headers == NULL) {
        goto done;
    }
    if (!http_request(config->state_url, encoded, headers, user_agent,
                      &response, &status, &error, NULL, NULL)) {
        goto done;
    }
    if (verbose) {
        fprintf(stderr, "debug=state-http status=%ld error=%ld\n", status,
                error);
    }
    if (error == 0) {
        online = 1;
    } else {
        set_error_from_response(codec, message, error, &response);
    }
done:
    if (error_out != NULL) {
        *error_out = error;
    }
    free(request);
    if (encoded != NULL) {
        codec->release(encoded);
    }
    free(headers);
    buffer_free(&response);
    return online;
}

static int perform_logout(struct codec *codec,
                          const struct portal_config *config,
                          const char *user_agent, const char *algo_id,
                          const char *client_id, const char *ticket,
                          int verbose, char **message)
{
    struct buffer response = {0};
    char local_time[32];
    char *request = NULL;
    char *encoded = NULL;
    char *headers = NULL;
    long status = 0;
    long error = -1;
    int ok = 0;

    local_time_now(local_time, sizeof(local_time));
    request = make_term_request(user_agent, client_id, ticket, local_time, "8");
    if (request == NULL) {
        goto done;
    }
    encoded = codec->code(request);
    if (encoded == NULL) {
        goto done;
    }
    headers = make_request_headers(user_agent, algo_id, client_id, encoded,
                                   config);
    if (headers == NULL) {
        goto done;
    }
    if (!http_request(config->term_url, encoded, headers, user_agent, &response,
                      &status, &error, NULL, NULL)) {
        goto done;
    }
    if (verbose) {
        fprintf(stderr, "debug=term-http status=%ld error=%ld\n", status, error);
    }
    if (error != 0) {
        set_error_from_response(codec, message, error, &response);
        goto done;
    }
    ok = 1;
done:
    free(request);
    if (encoded != NULL) {
        codec->release(encoded);
    }
    free(headers);
    buffer_free(&response);
    return ok;
}

static int keep_pulse(struct codec *codec,
                      const struct portal_config *config,
                      const char *user_agent, const char *algo_id,
                      const char *client_id, const char *ipv4,
                      const char *mac, const char *ticket,
                      const char *keep_url, int verbose, long *interval,
                      char **message)
{
    struct buffer response = {0};
    char local_time[32];
    char *request = NULL;
    char *encoded = NULL;
    char *headers = NULL;
    char *decoded = NULL;
    long status = 0;
    long error = -1;
    int ok = 0;

    if (keep_url == NULL) {
        if (message != NULL) {
            *message = strdup("no-keep-url");
        }
        return 0;
    }
    local_time_now(local_time, sizeof(local_time));
    request = make_keep_request(user_agent, client_id, ticket, ipv4, "", mac,
                                local_time, 0);
    if (request == NULL) {
        goto done;
    }
    encoded = codec->code(request);
    if (encoded == NULL) {
        goto done;
    }
    headers = make_request_headers(user_agent, algo_id, client_id, encoded,
                                   config);
    if (headers == NULL) {
        goto done;
    }
    if (!http_request(keep_url, encoded, headers, user_agent, &response, &status,
                      &error, NULL, NULL)) {
        goto done;
    }
    if (error != 0) {
        set_error_from_response(codec, message, error, &response);
        goto done;
    }
    decoded = codec->decode(response.data);
    if (decoded == NULL) {
        if (message != NULL) {
            *message = strdup("keep-decode");
        }
        goto done;
    }
    {
        xmlDocPtr document = xmlReadMemory(decoded, (int)strlen(decoded), NULL,
                                           NULL, XML_PARSE_NONET |
                                           XML_PARSE_NOERROR);
        xmlNodePtr root = document != NULL ? xmlDocGetRootElement(document)
                                           : NULL;

        if (root != NULL &&
            xmlStrcasecmp(root->name, (const xmlChar *)"response") == 0) {
            char *interval_text = node_text(root, "interval");
            char *level_text = node_text(root, "level");
            long value = 0;
            long level = 0;

            if (interval_text != NULL) {
                value = strtol(interval_text, NULL, 10);
            }
            if (level_text != NULL) {
                level = strtol(level_text, NULL, 10);
            }
            if (value > 0 && interval != NULL) {
                *interval = value;
            }
            if (level != 0) {
                if (message != NULL) {
                    if (asprintf(message, "keep-level=%ld", level) < 0) {
                        *message = NULL;
                    }
                }
                xmlFree(interval_text);
                xmlFree(level_text);
                if (document != NULL) {
                    xmlFreeDoc(document);
                }
                goto done;
            }
            xmlFree(interval_text);
            xmlFree(level_text);
        }
        if (document != NULL) {
            xmlFreeDoc(document);
        }
        ok = 1;
    }
done:
    if (verbose) {
        fprintf(stderr, "debug=keep-http status=%ld error=%ld ok=%d\n", status,
                error, ok);
    }
    free(request);
    if (encoded != NULL) {
        codec->release(encoded);
    }
    free(headers);
    if (decoded != NULL) {
        codec->release(decoded);
    }
    buffer_free(&response);
    return ok;
}

static int perform_login(struct codec *codec, struct portal_config *config,
                         const char *user_agent, const char *algo_id,
                         const char *client_id, const char *local_ip,
                         const char *mac, const char *user_id,
                         const char *password, int verbose,
                         struct session_info *session, const char **failure,
                         char **message)
{
    struct buffer response = {0};
    char local_time[32];
    char *ticket_request = NULL;
    char *auth_request = NULL;
    char *encoded = NULL;
    char *headers = NULL;
    char *decoded = NULL;
    char *ticket = NULL;
    long status = 0;
    long error = -1;
    int ok = 0;

    session->ticket = NULL;
    session->keep_url = NULL;
    session->keep_interval = keep_default_interval();

    local_time_now(local_time, sizeof(local_time));
    *failure = "ticket-request";
    ticket_request = make_ticket_request("", user_agent, client_id, local_ip,
                                         "", mac != NULL ? mac : "", local_time,
                                         "");
    if (ticket_request == NULL) {
        *failure = "ticket-xml";
        goto done;
    }
    *failure = "ticket-code";
    encoded = codec->code(ticket_request);
    if (encoded == NULL) {
        goto done;
    }
    *failure = "ticket-headers";
    headers = make_request_headers(user_agent, algo_id, client_id, encoded,
                                   config);
    if (headers == NULL) {
        goto done;
    }
    *failure = "ticket-http";
    if (!http_request(config->ticket_url, encoded, headers, user_agent,
                      &response, &status, &error, NULL, NULL)) {
        goto done;
    }
    codec->release(encoded);
    encoded = NULL;
    free(headers);
    headers = NULL;
    if (error != 0) {
        *failure = "ticket-server";
        set_error_from_response(codec, message, error, &response);
        goto done;
    }
    *failure = "ticket-decode";
    decoded = codec->decode(response.data);
    buffer_free(&response);
    if (decoded == NULL) {
        goto done;
    }
    *failure = "ticket-parse";
    ticket = parse_ticket(decoded);
    codec->release(decoded);
    decoded = NULL;
    if (ticket == NULL) {
        goto done;
    }

    local_time_now(local_time, sizeof(local_time));
    *failure = "auth-request";
    auth_request = make_auth_request(user_agent, client_id, user_id, password,
                                     ticket, local_time);
    if (auth_request == NULL) {
        *failure = "auth-xml";
        goto done;
    }
    *failure = "auth-code";
    encoded = codec->code(auth_request);
    if (encoded == NULL) {
        goto done;
    }
    *failure = "auth-headers";
    headers = make_request_headers(user_agent, algo_id, client_id, encoded,
                                   config);
    if (headers == NULL) {
        goto done;
    }
    *failure = "auth-http";
    if (!http_request(config->auth_url, encoded, headers, user_agent, &response,
                      &status, &error, NULL, NULL)) {
        goto done;
    }
    codec->release(encoded);
    encoded = NULL;
    free(headers);
    headers = NULL;
    if (error != 0) {
        *failure = "auth-server";
        set_error_from_response(codec, message, error, &response);
        goto done;
    }
    *failure = "auth-decode";
    decoded = codec->decode(response.data);
    buffer_free(&response);
    if (decoded == NULL) {
        goto done;
    }
    *failure = "auth-response";
    ok = auth_succeeded(decoded, message);
    if (ok) {
        parse_keep_info(decoded, &session->keep_url, &session->keep_interval);
    }
    codec->release(decoded);
    decoded = NULL;
    if (verbose) {
        fprintf(stderr, "debug=login ok=%d\n", ok);
    }

done:
    if (ok) {
        session->ticket = ticket;
        ticket = NULL;
    }
    free(ticket);
    free(ticket_request);
    free(auth_request);
    if (encoded != NULL) {
        codec->release(encoded);
    }
    free(headers);
    if (decoded != NULL) {
        codec->release(decoded);
    }
    buffer_free(&response);
    return ok;
}

static int read_pipe_message(int descriptor, char *buffer, size_t size,
                             size_t *length)
{
    size_t used = 0;

    while (used + 1 < size) {
        ssize_t received = read(descriptor, buffer + used, 1);

        if (received <= 0) {
            return 0;
        }
        if (buffer[used] == '\0') {
            *length = used;
            return 1;
        }
        ++used;
    }
    return 0;
}

static int write_pipe_message(int descriptor, const char *message)
{
    size_t length = strlen(message) + 1;
    size_t written = 0;

    while (written < length) {
        ssize_t count = write(descriptor, message + written, length - written);

        if (count <= 0) {
            return 0;
        }
        written += (size_t)count;
    }
    return 1;
}

static char *build_state_message(const char *state, const char *detail)
{
    char *message = NULL;

    if (asprintf(&message,
                 "<M><OpS>ESurfingSvr</OpS><OpT>PortalState</OpT>"
                 "<OpC>PortalState</OpC><P><state>%s</state>"
                 "<detail>%s</detail></P></M>",
                 state, detail != NULL ? detail : "") < 0) {
        return NULL;
    }
    return message;
}

static char *message_value(xmlNodePtr node, const char *name)
{
    xmlNodePtr child;

    for (child = node->children; child != NULL; child = child->next) {
        if (child->type == XML_ELEMENT_NODE &&
            xmlStrcasecmp(child->name, (const xmlChar *)name) == 0) {
            xmlChar *content = xmlNodeGetContent(child);

            if (content != NULL && content[0] != '\0') {
                char *value = strdup((char *)content);

                xmlFree(content);
                return value;
            }
            xmlFree(content);
        }
    }
    return NULL;
}

static int parse_pipe_message(const char *data, char **opcode, char **user,
                              char **password)
{
    xmlDocPtr document = xmlReadMemory(data, (int)strlen(data), NULL, NULL,
                                       XML_PARSE_NONET | XML_PARSE_NOERROR);
    xmlNodePtr root;

    if (document == NULL) {
        return 0;
    }
    root = xmlDocGetRootElement(document);
    if (root == NULL || xmlStrcmp(root->name, (const xmlChar *)"M") != 0) {
        xmlFreeDoc(document);
        return 0;
    }
    *opcode = message_value(root, "OpC");
    {
        xmlNodePtr node;

        for (node = root->children; node != NULL; node = node->next) {
            if (node->type == XML_ELEMENT_NODE &&
                xmlStrcasecmp(node->name, (const xmlChar *)"P") == 0) {
                *user = message_value(node, "user");
                *password = message_value(node, "password");
                break;
            }
        }
    }
    xmlFreeDoc(document);
    return 1;
}

static int relogin_enabled(void)
{
    const char *value = getenv("GD_RELOGIN");

    return value == NULL || value[0] != '0';
}

static long relogin_attempts(void)
{
    const char *value = getenv("GD_RELOGIN_MAX");
    long parsed;

    if (value == NULL || value[0] == '\0') {
        return 3;
    }
    parsed = strtol(value, NULL, 10);
    return parsed > 0 ? parsed : 0;
}

static long relogin_delay(void)
{
    const char *value = getenv("GD_RELOGIN_DELAY");
    long parsed;

    if (value == NULL || value[0] == '\0') {
        return 5;
    }
    parsed = strtol(value, NULL, 10);
    return parsed > 0 ? parsed : 5;
}

/* Errors that re-authenticating cannot fix (bad credentials/identity). */
static int relogin_is_fatal(const char *detail)
{
    static const char *fatal[] = {"server-error=140100", "server-error=140101",
                                  "server-error=140104", "server-error=140105",
                                  "server-error=140012", "server-error=140013",
                                  "server-error=140102.13012000",
                                  "server-error=140102.13016000",
                                  "server-error=140102.13017000",
                                  "server-error=140102.13015000"};
    size_t index;

    if (detail == NULL) {
        return 0;
    }
    for (index = 0; index < sizeof(fatal) / sizeof(fatal[0]); ++index) {
        if (strstr(detail, fatal[index]) != NULL) {
            return 1;
        }
    }
    return 0;
}

/* Keep the session alive, and re-authenticate when the server drops us
   (the original recovers via CPortalConn::DisasterRecovery). */
static int run_keep_loop(struct codec *codec, struct portal_config *config,
                         const char *user_agent, const char *algo_id,
                         const char *client_id, const char *local_ip,
                         const char *mac, const char *user_id,
                         const char *password, struct session_info *session,
                         int verbose)
{
    long interval = session->keep_interval > 0 ? session->keep_interval : 30;
    long attempts = relogin_enabled() ? relogin_attempts() : 0;
    long delay = relogin_delay();

    if (verbose) {
        fprintf(stderr, "debug=keep-start interval=%ld url=%s relogin=%ld\n",
                interval,
                session->keep_url != NULL ? session->keep_url : "(none)",
                attempts);
    }
    for (;;) {
        char *message = NULL;
        long attempt;

        sleep((unsigned)interval);
        if (keep_pulse(codec, config, user_agent, algo_id, client_id, local_ip,
                       mac, session->ticket, session->keep_url, verbose,
                       &interval, &message)) {
            continue;
        }
        print_state("offline", message != NULL ? message : "keep");
        free(message);
        if (attempts == 0) {
            return 0;
        }
        for (attempt = 1; attempt <= attempts; ++attempt) {
            const char *failure = "relogin";
            char *detail = NULL;

            if (verbose) {
                fprintf(stderr, "debug=relogin attempt=%ld wait=%ld\n",
                        attempt, delay);
            }
            sleep((unsigned)delay);
            free(session->ticket);
            free(session->keep_url);
            session->ticket = NULL;
            session->keep_url = NULL;
            session->keep_interval = 0;
            if (perform_login(codec, config, user_agent, algo_id, client_id,
                              local_ip, mac, user_id, password, verbose,
                              session, &failure, &detail)) {
                interval = session->keep_interval > 0 ? session->keep_interval
                                                     : 30;
                free(detail);
                print_state("online", NULL);
                break;
            }
            print_state("failed", detail != NULL ? detail : failure);
            if (relogin_is_fatal(detail)) {
                free(detail);
                return 0;
            }
            free(detail);
            delay *= 2;
            if (delay > 300) {
                delay = 300;
            }
        }
        if (attempt > attempts) {
            return 0;
        }
    }
}

static int run_server(struct codec *codec, struct portal_config *config,
                      const char *user_agent, const char *algo_id,
                      const char *client_id, const char *local_ip,
                      const char *mac, const char *client_pipe,
                      const char *server_pipe, int verbose)
{
    int input;
    int output;
    char buffer[PIPE_MESSAGE_LIMIT];
    struct session_info session = {0};
    long keep_interval = keep_default_interval();
    int online = 0;

    if (mkfifo(client_pipe, 0600) != 0 && errno != EEXIST) {
        perror(client_pipe);
        return 0;
    }
    if (mkfifo(server_pipe, 0600) != 0 && errno != EEXIST) {
        perror(server_pipe);
        return 0;
    }
    input = open(client_pipe, O_RDWR);
    if (input < 0) {
        perror(client_pipe);
        return 0;
    }
    output = open(server_pipe, O_RDWR);
    if (output < 0) {
        perror(server_pipe);
        close(input);
        return 0;
    }
    printf("state=serving\n");
    fflush(stdout);
    for (;;) {
        fd_set set;
        struct timeval timeout;
        int ready;

        FD_ZERO(&set);
        FD_SET(input, &set);
        timeout.tv_sec = online ? (keep_interval > 0 ? keep_interval : 30)
                                : 3600;
        timeout.tv_usec = 0;
        ready = select(input + 1, &set, NULL, NULL, &timeout);
        if (ready < 0) {
            if (errno == EINTR) {
                continue;
            }
            break;
        }
        if (ready == 0) {
            if (online) {
                char *message = NULL;

                if (!keep_pulse(codec, config, user_agent, algo_id, client_id,
                                local_ip, mac, session.ticket,
                                session.keep_url, verbose, &keep_interval,
                                &message)) {
                    char *reply = build_state_message(
                        "offline", message != NULL ? message : "keep");

                    if (reply != NULL) {
                        write_pipe_message(output, reply);
                        free(reply);
                    }
                    online = 0;
                }
                free(message);
            }
            continue;
        }
        {
            size_t length = 0;
            char *opcode = NULL;
            char *user = NULL;
            char *password = NULL;
            char *reply = NULL;

            if (!read_pipe_message(input, buffer, sizeof(buffer), &length)) {
                continue;
            }
            if (!parse_pipe_message(buffer, &opcode, &user, &password)) {
                free(opcode);
                free(user);
                free(password);
                continue;
            }
            if (verbose) {
                fprintf(stderr, "debug=server-recv opcode=%s\n",
                        opcode != NULL ? opcode : "(null)");
            }
            if (opcode != NULL && strcmp(opcode, "PortalConnect") == 0) {
                const char *failure = "config";
                char *detail = NULL;

                free(session.ticket);
                free(session.keep_url);
                session.ticket = NULL;
                session.keep_url = NULL;
                if (perform_login(codec, config, user_agent, algo_id, client_id,
                                  local_ip, mac, user != NULL ? user : "",
                                  password != NULL ? password : "", verbose,
                                  &session, &failure, &detail)) {
                    online = 1;
                    keep_interval = session.keep_interval;
                    reply = build_state_message("online", "");
                } else {
                    online = 0;
                    reply = build_state_message(
                        "failed", detail != NULL ? detail : failure);
                }
                free(detail);
            } else if (opcode != NULL &&
                       strcmp(opcode, "PortalDisConnect") == 0) {
                char *message = NULL;
                int ok = 0;

                if (online && session.ticket != NULL) {
                    ok = perform_logout(codec, config, user_agent, algo_id,
                                        client_id, session.ticket, verbose,
                                        &message);
                }
                online = 0;
                free(session.ticket);
                free(session.keep_url);
                session.ticket = NULL;
                session.keep_url = NULL;
                reply = build_state_message(ok ? "offline" : "failed",
                                            ok ? "" : (message != NULL
                                                       ? message : "term"));
                free(message);
            } else {
                reply = build_state_message("failed", "unknown-opcode");
            }
            if (reply != NULL) {
                write_pipe_message(output, reply);
                free(reply);
            }
            free(opcode);
            free(user);
            free(password);
        }
    }
    free(session.ticket);
    free(session.keep_url);
    close(input);
    close(output);
    return 1;
}

static int run_client(const char *client_pipe, const char *server_pipe,
                      const char *opcode, const char *user,
                      const char *password, int verbose)
{
    int output;
    int input;
    char buffer[PIPE_MESSAGE_LIMIT];
    char *message = NULL;
    size_t length = 0;

    output = open(client_pipe, O_WRONLY);
    if (output < 0) {
        perror(client_pipe);
        return 0;
    }
    if (asprintf(&message,
                 "<M><OpS>client</OpS><OpT>Portal</OpT><OpC>%s</OpC>"
                 "<P><user>%s</user><password>%s</password></P></M>",
                 opcode, user != NULL ? user : "",
                 password != NULL ? password : "") < 0) {
        close(output);
        return 0;
    }
    write_pipe_message(output, message);
    free(message);
    close(output);
    input = open(server_pipe, O_RDONLY);
    if (input < 0) {
        perror(server_pipe);
        return 0;
    }
    if (!read_pipe_message(input, buffer, sizeof(buffer), &length)) {
        close(input);
        return 0;
    }
    close(input);
    if (verbose) {
        fprintf(stderr, "debug=client-reply\n");
    }
    printf("%s\n", buffer);
    return 1;
}

int main(int argc, char **argv)
{
    struct portal_config config = {0};
    struct codec codec = {0};
    struct buffer response = {0};
    char *password;
    char *ticket = NULL;
    char *encoded = NULL;
    char *headers = NULL;
    char *decoded = NULL;
    char *message = NULL;
    const char *client_id;
    const char *user_agent;
    const char *config_url;
    const char *module_path;
    const char *user_id;
    char *algo_id = NULL;
    char *host_name = NULL;
    char *mac = NULL;
    char *ticket_request = NULL;
    char *auth_request = NULL;
    char *term_request = NULL;
    char local_ip[64] = {0};
    char local_time[32] = {0};
    char account[128] = {0};
    char *cookie = NULL;
    const char *failure = "config-http";
    int verbose = getenv("GD_DEBUG") != NULL;
    int logout = 0;
    int keep_mode = 0;
    int server_mode = 0;
    int client_mode = 0;
    int dynamic_mode = 0;
    int state_mode = 0;
    int state_printed = 0;
    const char *client_command = NULL;
    char *keep_url = NULL;
    long keep_interval = keep_default_interval();
    long status = 0;
    long ticket_error = -1;
    long auth_error = -1;
    int success = 0;
    const char *program_name = argv[0];

    for (;;) {
        if (argc >= 2 && (strcmp(argv[1], "--logout") == 0 ||
                          strcmp(argv[1], "-l") == 0)) {
            logout = 1;
        } else if (argc >= 2 && strcmp(argv[1], "--keep") == 0) {
            keep_mode = 1;
        } else if (argc >= 2 && strcmp(argv[1], "--dynamic") == 0) {
            dynamic_mode = 1;
        } else if (argc >= 2 && strcmp(argv[1], "--state") == 0) {
            state_mode = 1;
        } else if (argc >= 2 && strcmp(argv[1], "--server") == 0) {
            server_mode = 1;
        } else if (argc >= 2 && strcmp(argv[1], "--client") == 0) {
            client_mode = 1;
        } else {
            break;
        }
        ++argv;
        --argc;
    }

    if (client_mode) {
        const char *pipe_dir = getenv("GD_PIPE_DIR");
        char *client_pipe = NULL;
        char *server_pipe = NULL;
        char *client_password = NULL;
        int rc = 0;

        if (argc < 2) {
            fprintf(stderr, "用法: %s --client <connect|disconnect> [userid]\n",
                    program_name);
            return EXIT_FAILURE;
        }
        client_command = argv[1];
        user_id = argc >= 3 ? argv[2] : "";
        if (pipe_dir == NULL) {
            pipe_dir = ".";
        }
        if (asprintf(&client_pipe, "%s/clientpipe", pipe_dir) < 0 ||
            asprintf(&server_pipe, "%s/serverpipe", pipe_dir) < 0) {
            return EXIT_FAILURE;
        }
        if (strcmp(client_command, "connect") == 0) {
            client_password = getpass("Password: ");
            if (client_password == NULL) {
                free(client_pipe);
                free(server_pipe);
                return EXIT_FAILURE;
            }
            rc = run_client(client_pipe, server_pipe, "PortalConnect",
                            user_id, client_password, 0);
        } else {
            rc = run_client(client_pipe, server_pipe, "PortalDisConnect",
                            "", "", 0);
        }
        free(client_pipe);
        free(server_pipe);
        return rc ? EXIT_SUCCESS : EXIT_FAILURE;
    }

    if (argc < 2 || argc > 4) {
        fprintf(stderr,
                "用法: %s [--logout|--keep|--dynamic|--server] [config-url] <protect.so> [userid]\n"
                "       %s --client <connect|disconnect> [userid]\n"
                "  --logout   注销下线（term.cgi）\n"
                "  --keep     登录后保持保活（keep.cgi）\n"
                "  --dynamic  从门户 index.cgi 动态获取配置\n"
                "  --state    查询当前在线状态（state.cgi）\n"
                "  --server   以命名管道服务方式运行\n"
                "  省略 userid 时会提示在终端输入账号。\n",
                program_name, program_name);
        return EXIT_FAILURE;
    }
    if (argc == 2) {
        config_url = default_config_url;
        module_path = argv[1];
        if (logout || server_mode || state_mode) {
            user_id = "";
        } else {
            fputs("Account: ", stdout);
            fflush(stdout);
            if (fgets(account, sizeof(account), stdin) == NULL) {
                return EXIT_FAILURE;
            }
            account[strcspn(account, "\r\n")] = '\0';
            user_id = account;
        }
    } else {
        config_url = argc == 3 ? default_config_url : argv[1];
        module_path = argc == 3 ? argv[1] : argv[2];
        user_id = argc == 3 ? argv[2] : argv[3];
    }
    if (logout || server_mode || state_mode) {
        password = (char *)"";
    } else {
        password = getpass("Password: ");
        if (password == NULL) {
            return EXIT_FAILURE;
        }
    }
    client_id = getenv("GD_CLIENT_ID");
    user_agent = getenv("GD_USER_AGENT");
    if (user_agent == NULL) {
        user_agent = "CCTP/Linux64/2.4.64";
    }

    if (http_request(config_url, NULL, NULL, user_agent, &response, &status,
                     NULL, NULL, &cookie) &&
        parse_config(response.data, &config)) {
        buffer_free(&response);
    } else {
        char *saved_config = read_file("conf/conf.xml");

        failure = "config-fallback";
        buffer_free(&response);
        if (saved_config == NULL || !parse_config(saved_config, &config)) {
            free(saved_config);
            goto finish;
        }
        free(saved_config);
    }
    if (client_id == NULL) {
        client_id = config.client_id != NULL ? config.client_id : "";
    }
    if (dynamic_mode) {
        const char *config_override = getenv("GD_CONFIG_URL");
        char *index_url = config_override != NULL && config_override[0] != '\0'
                              ? strdup(config_override)
                              : derive_index_url(config.redirect_url);

        if (index_url == NULL ||
            !fetch_dynamic_config(index_url, &config, verbose)) {
            if (verbose) {
                fprintf(stderr, "debug=dynamic failed, using saved config\n");
            }
        }
        free(index_url);
    }
    {
        const char *portal_url = getenv("GD_PORTAL_URL");

        if (portal_url != NULL && portal_url[0] != '\0') {
            apply_portal_params(&config, portal_url);
            if (verbose) {
                fprintf(stderr, "debug=portal-params ticket-url=%s\n",
                        config.ticket_url);
            }
        }
    }
    if (!load_codec(module_path, &codec)) {
        failure = "codec-load";
        goto finish;
    }
    algo_id = resolve_algo_id(module_path);
    if (algo_id == NULL) {
        failure = "algo-id";
        goto finish;
    }
    if (verbose) {
        fprintf(stderr, "debug=config ticket-url=%s\n", config.ticket_url);
    }

    if (!local_ipv4_for_url(config.ticket_url, local_ip, sizeof(local_ip)) &&
        !local_ipv4(local_ip, sizeof(local_ip))) {
        char *portal_ip = query_value(config_url, "wlanuserip");

        if (portal_ip == NULL) {
            portal_ip = query_value(default_portal_url, "wlanuserip");
        }
        if (portal_ip != NULL) {
            snprintf(local_ip, sizeof(local_ip), "%s", portal_ip);
            free(portal_ip);
        }
    }
    if (local_ip[0] != '\0') {
        char *updated;

        updated = replace_query_value(config.ticket_url, "wlanuserip", local_ip);
        if (updated != NULL) {
            free(config.ticket_url);
            config.ticket_url = updated;
        }
        updated = replace_query_value(config.ticket_url, "clientip", local_ip);
        if (updated != NULL) {
            free(config.ticket_url);
            config.ticket_url = updated;
        }
    }
    if (logout) {
        const char *marker = strstr(config.ticket_url, "ticket.cgi");

        if (marker != NULL) {
            size_t prefix = (size_t)(marker - config.ticket_url);
            char *joined = NULL;

            if (asprintf(&joined, "%.*sterm.cgi%s", (int)prefix,
                         config.ticket_url,
                         marker + strlen("ticket.cgi")) >= 0) {
                free(config.term_url);
                config.term_url = joined;
            }
        }
    }
    {
        char *ticket_host = NULL;
        char *ticket_port = NULL;
        char *ticket_path = NULL;

        if (parse_http_url(config.ticket_url, &ticket_host, &ticket_port,
                           &ticket_path)) {
            host_name = ticket_host;
            free(ticket_port);
            free(ticket_path);
        }
    }
    if (query_value(config.ticket_url, "clientmac") == NULL) {
        char local_mac[32] = {0};

        if (local_mac_for_ip(local_ip, local_mac, sizeof(local_mac))) {
            char *updated = set_query_param(config.ticket_url, "clientmac",
                                            local_mac);

            if (updated != NULL) {
                free(config.ticket_url);
                config.ticket_url = updated;
            }
        }
    }
    mac = query_value(config.ticket_url, "clientmac");
    if (mac == NULL && config.wlan_user_mac != NULL &&
        config.wlan_user_mac[0] != '\0') {
        mac = strdup(config.wlan_user_mac);
    }

    if (server_mode) {
        const char *pipe_dir = getenv("GD_PIPE_DIR");
        char *client_pipe = NULL;
        char *server_pipe = NULL;
        int rc;

        if (pipe_dir == NULL) {
            pipe_dir = ".";
        }
        if (asprintf(&client_pipe, "%s/clientpipe", pipe_dir) < 0 ||
            asprintf(&server_pipe, "%s/serverpipe", pipe_dir) < 0) {
            failure = "server-pipe";
            goto finish;
        }
        failure = "server";
        rc = run_server(&codec, &config, user_agent, algo_id, client_id,
                        local_ip[0] != '\0' ? local_ip : "127.0.0.1",
                        mac != NULL ? mac : "", client_pipe, server_pipe,
                        verbose);
        free(client_pipe);
        free(server_pipe);
        success = rc;
        state_printed = 1;
        goto finish;
    }

    local_time_now(local_time, sizeof(local_time));

    failure = "ticket-request";
    ticket_request = make_ticket_request(host_name != NULL ? host_name : "",
                                         user_agent, client_id, local_ip, "",
                                         mac != NULL ? mac : "", local_time,
                                         "");
    if (ticket_request == NULL) {
        failure = "ticket-xml";
        goto finish;
    }
    failure = "ticket-code";
    encoded = codec.code(ticket_request);
    if (encoded == NULL) {
        goto finish;
    }
    failure = "ticket-headers";
    headers = make_request_headers(user_agent, algo_id, client_id, encoded,
                                   &config);
    if (headers == NULL) {
        goto finish;
    }
    failure = "ticket-http";
    if (!http_request(config.ticket_url, encoded, headers, user_agent,
                      &response, &status, &ticket_error, cookie, &cookie)) {
        goto finish;
    }
    codec.release(encoded);
    encoded = NULL;
    free(headers);
    headers = NULL;
    if (verbose) {
        fprintf(stderr, "debug=ticket-http status=%ld error=%ld bytes=%zu\n",
                status, ticket_error, response.length);
    }
    if (ticket_error != 0) {
        failure = "ticket-server";
        set_error_from_response(&codec, &message, ticket_error, &response);
        goto finish;
    }
    failure = "ticket-decode";
    decoded = codec.decode(response.data);
    buffer_free(&response);
    if (decoded == NULL) {
        goto finish;
    }
    failure = "ticket-parse";
    ticket = parse_ticket(decoded);
    codec.release(decoded);
    decoded = NULL;
    if (ticket == NULL) {
        goto finish;
    }
    if (verbose) {
        fprintf(stderr, "debug=ticket-ok length=%zu\n", strlen(ticket));
    }

    if (state_mode) {
        long state_error = -1;
        char *detail = NULL;
        int online = perform_state(&codec, &config, user_agent, algo_id,
                                   client_id, ticket, verbose, &state_error,
                                   &detail);

        printf("state=%s\n", online ? "online" : "offline");
        if (!online) {
            printf("detail=%s\n", detail != NULL ? detail : "state");
        }
        free(detail);
        success = online;
        state_printed = 1;
        goto finish;
    }

    if (logout) {
        local_time_now(local_time, sizeof(local_time));
        failure = "term-request";
        term_request = make_term_request(user_agent, client_id, ticket,
                                         local_time, "8");
        if (term_request == NULL) {
            failure = "term-xml";
            goto finish;
        }
        failure = "term-code";
        encoded = codec.code(term_request);
        if (encoded == NULL) {
            goto finish;
        }
        failure = "term-headers";
        headers = make_request_headers(user_agent, algo_id, client_id, encoded,
                                       &config);
        if (headers == NULL) {
            goto finish;
        }
        failure = "term-http";
        if (!http_request(config.term_url, encoded, headers, user_agent,
                          &response, &status, &auth_error, cookie, &cookie)) {
            goto finish;
        }
        codec.release(encoded);
        encoded = NULL;
        free(headers);
        headers = NULL;
        if (verbose) {
            fprintf(stderr, "debug=term-http status=%ld error=%ld bytes=%zu\n",
                    status, auth_error, response.length);
        }
        if (auth_error != 0) {
            failure = "term-server";
            set_error_from_response(&codec, &message, auth_error, &response);
            goto finish;
        }
        success = 1;
        goto finish;
    }

    local_time_now(local_time, sizeof(local_time));
    failure = "auth-request";
    auth_request = make_auth_request(user_agent, client_id, user_id, password,
                                     ticket, local_time);
    if (auth_request == NULL) {
        failure = "auth-xml";
        goto finish;
    }
    failure = "auth-code";
    encoded = codec.code(auth_request);
    if (encoded == NULL) {
        goto finish;
    }
    failure = "auth-headers";
    headers = make_request_headers(user_agent, algo_id, client_id, encoded,
                                   &config);
    if (headers == NULL) {
        goto finish;
    }
    failure = "auth-http";
    if (!http_request(config.auth_url, encoded, headers, user_agent,
                      &response, &status, &auth_error, cookie, &cookie)) {
        goto finish;
    }
    codec.release(encoded);
    encoded = NULL;
    free(headers);
    headers = NULL;
    if (verbose) {
        fprintf(stderr, "debug=auth-http status=%ld error=%ld bytes=%zu\n",
                status, auth_error, response.length);
    }
    if (auth_error != 0) {
        failure = "auth-server";
        set_error_from_response(&codec, &message, auth_error, &response);
        goto finish;
    }
    failure = "auth-decode";
    decoded = codec.decode(response.data);
    buffer_free(&response);
    if (decoded == NULL) {
        goto finish;
    }
    failure = "auth-response";
    success = auth_succeeded(decoded, &message) && auth_error == 0;
    if (success) {
        parse_keep_info(decoded, &keep_url, &keep_interval);
    }
    codec.release(decoded);
    decoded = NULL;

    if (success && keep_mode) {
        struct session_info session = {0};

        session.ticket = ticket;
        session.keep_url = keep_url;
        session.keep_interval = keep_interval;
        printf("state=online\n");
        fflush(stdout);
        state_printed = 1;
        run_keep_loop(&codec, &config, user_agent, algo_id, client_id,
                      local_ip[0] != '\0' ? local_ip : "",
                      mac != NULL ? mac : "", user_id, password, &session,
                      verbose);
        ticket = NULL;
        goto finish;
    }

finish:
    if (verbose) {
        fprintf(stderr, "debug=finish result=%s local-ip=%s\n",
                success ? "ok" : failure,
                local_ip[0] != '\0' ? local_ip : "(none)");
    }
    if (!state_printed) {
        if (logout) {
            print_state(success ? "offline" : "failed",
                        success ? NULL : (message != NULL ? message : failure));
        } else if (success) {
            print_state("online", NULL);
        } else {
            print_state("failed", message != NULL ? message : failure);
        }
    }
    free(message);
    free(ticket);
    free(ticket_request);
    free(auth_request);
    free(term_request);
    free(keep_url);
    if (encoded != NULL && codec.release != NULL) {
        codec.release(encoded);
    }
    if (decoded != NULL && codec.release != NULL) {
        codec.release(decoded);
    }
    free(headers);
    free(algo_id);
    free(host_name);
    free(mac);
    free(cookie);
    buffer_free(&response);
    unload_codec(&codec);
    config_free(&config);
    return success ? EXIT_SUCCESS : EXIT_FAILURE;
}