/*
 * test_body_codec.c — verify the C body codec.
 *
 * 1. Standard DES known-answer vector.
 * 2. Real portal bodies captured from the client (decode -> re-encode round-trip).
 * 3. Oracle samples (encode must match the live module byte-for-byte).
 */
#include "body_codec.h"
#include "test_vectors.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int fails = 0;

static void hex2bin(const char *h, uint8_t *out, int n)
{
    int i;
    for (i = 0; i < n; i++) {
        unsigned v;
        sscanf(h + 2 * i, "%2x", &v);
        out[i] = (uint8_t)v;
    }
}

static void check_des(void)
{
    const char *key = "0123456789ABCDEF";
    const char *pt = "4E6F772069732074"; /* "Now is t" */
    const char *ct = "3FA40E8A984D4815";
    uint8_t k[8], p[8], c[8], o[8];
    int i;
    hex2bin(key, k, 8);
    hex2bin(pt, p, 8);
    hex2bin(ct, c, 8);

    des_encrypt_block(k, p, o);
    printf("  DES KAT encrypt: ");
    for (i = 0; i < 8; i++) printf("%02X", o[i]);
    if (memcmp(o, c, 8) == 0) printf("  OK\n");
    else { printf("  FAIL (want %s)\n", ct); fails++; }

    des_decrypt_block(k, c, o);
    printf("  DES KAT decrypt: ");
    for (i = 0; i < 8; i++) printf("%02X", o[i]);
    if (memcmp(o, p, 8) == 0) printf("  OK\n");
    else { printf("  FAIL (want %s)\n", pt); fails++; }
}

static void check_roundtrip(const char *name, const char *hexbody)
{
    char xml[8192];
    char *re;
    size_t xl, rl, hn = strlen(hexbody), j;
    int bad = 0;

    if (portal_decode_body_str(hexbody, xml, sizeof(xml), &xl) != 0) {
        printf("  %-8s decode FAIL\n", name);
        fails++;
        return;
    }
    re = (char *)malloc(hn * 2 + 16);
    rl = portal_encode_body(xml, re, hn * 2 + 16);
    if (rl != hn) bad = 1;
    else for (j = 0; j < hn; j++) if (re[j] != hexbody[j]) { bad = 1; break; }

    if (!bad)
        printf("  %-8s round-trip OK   (%u B body -> %u B xml)\n",
               name, (unsigned)(hn / 2), (unsigned)xl);
    else {
        printf("  %-8s round-trip FAIL (re=%u want=%u)\n",
               name, (unsigned)rl, (unsigned)hn);
        fails++;
    }
    free(re);
}

static void check_oracle(const char *label, const char *xml, const char *expect)
{
    static char got[65536];
    size_t n = portal_encode_body(xml, got, sizeof(got));
    if (n && strcmp(got, expect) == 0) {
        printf("  %-14s OK\n", label);
    } else {
        printf("  %-14s FAIL\n      got  %.64s\n      want %.64s\n", label, got, expect);
        fails++;
    }
}

int main(void)
{
    unsigned i;

    puts("== DES known-answer ==");
    check_des();

    puts("\n== real captured bodies (decode -> re-encode) ==");
    for (i = 0; i < sizeof(VECTORS) / sizeof(VECTORS[0]); i++)
        check_roundtrip(VECTORS[i].name, VECTORS[i].hex);

    puts("\n== oracle samples (encode) ==");
    check_oracle("empty",
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?><request></request>",
        "C853A9968496B3E062B640DF7A9A022CA8AF4B51F157B48B8F3CB474842312D4"
        "762D8EFF99C4A04680601181FA7CEBD2FA738361D094A7A52CB179C46853233F");
    check_oracle("field_a",
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?><request><a></a></request>",
        "C853A9968496B3E062B640DF7A9A022CA8AF4B51F157B48B8F3CB474842312D4"
        "762D8EFF99C4A04680601181FA7CEBD26B8E2A6D7297DF8DD4ACA9A911958F9D"
        "2348D470D2980907");

    printf("\n%s (%d failure%s)\n", fails ? "FAILED" : "ALL PASS", fails,
           fails == 1 ? "" : "s");
    return fails ? 1 : 0;
}
