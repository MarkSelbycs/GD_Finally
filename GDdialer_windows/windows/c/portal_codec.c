/*
 * portal_codec.c — command-line tool for the ESurfing portal body codec.
 *
 *   portal_codec encode <xml-file>     -> prints the body hex
 *   portal_codec decode <hex-file>     -> prints the plaintext XML
 *   portal_codec selftest              -> runs built-in vectors
 *
 * Build:  tcc -o portal_codec.exe portal_codec.c body_codec.c
 *     or: gcc -O2 -o portal_codec portal_codec.c body_codec.c
 */
#include "body_codec.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static char *read_file(const char *path, size_t *len)
{
    FILE *f = fopen(path, "rb");
    long n;
    char *buf;
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    n = ftell(f);
    fseek(f, 0, SEEK_SET);
    buf = (char *)malloc((size_t)n + 1);
    if (!buf) { fclose(f); return NULL; }
    if (fread(buf, 1, (size_t)n, f) != (size_t)n) { free(buf); fclose(f); return NULL; }
    buf[n] = '\0';
    fclose(f);
    if (len) *len = (size_t)n;
    return buf;
}

static void strip_ws(char *s)
{
    size_t n = strlen(s), i = 0, w = 0;
    for (; i < n; i++) {
        char c = s[i];
        if (c == '\r' || c == '\n' || c == ' ' || c == '\t') continue;
        s[w++] = c;
    }
    s[w] = '\0';
}

static const struct { const char *name; const char *xml; const char *hex; } VEC[] = {
    { "empty",
      "<?xml version=\"1.0\" encoding=\"UTF-8\"?><request></request>",
      "C853A9968496B3E062B640DF7A9A022CA8AF4B51F157B48B8F3CB474842312D4"
      "762D8EFF99C4A04680601181FA7CEBD2FA738361D094A7A52CB179C46853233F" },
    { "field_a",
      "<?xml version=\"1.0\" encoding=\"UTF-8\"?><request><a></a></request>",
      "C853A9968496B3E062B640DF7A9A022CA8AF4B51F157B48B8F3CB474842312D4"
      "762D8EFF99C4A04680601181FA7CEBD26B8E2A6D7297DF8DD4ACA9A911958F9D"
      "2348D470D2980907" },
};

static int selftest(void)
{
    size_t i;
    int bad = 0;
    char *got = (char *)malloc(1 << 20);
    char *back = (char *)malloc(1 << 20);
    for (i = 0; i < sizeof(VEC) / sizeof(VEC[0]); i++) {
        size_t xl;
        /* the codec normalises encoding="UTF-8" to lowercase, so the decoded
           plaintext legitimately differs from the raw input in that token */
        char expect[4096];
        const char *p;
        size_t w = 0;
        for (p = VEC[i].xml; *p; p++) {
            if (strncmp(p, "UTF-8", 5) == 0) { memcpy(expect + w, "utf-8", 5); w += 5; p += 4; }
            else expect[w++] = *p;
        }
        expect[w] = '\0';

        portal_encode_body(VEC[i].xml, got, 1 << 20);
        printf("  %-10s encode %s\n", VEC[i].name,
               strcmp(got, VEC[i].hex) == 0 ? "OK" : "FAIL");
        if (strcmp(got, VEC[i].hex) != 0) bad++;
        portal_decode_body_str(VEC[i].hex, back, 1 << 20, &xl);
        printf("  %-10s decode %s\n", VEC[i].name,
               strcmp(back, expect) == 0 ? "OK" : "FAIL");
        if (strcmp(back, expect) != 0) bad++;
    }
    free(got); free(back);
    printf("%s\n", bad ? "SELFTEST FAILED" : "SELFTEST PASS");
    return bad ? 1 : 0;
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr,
            "usage:\n"
            "  portal_codec encode <xml-file>   # XML -> body hex\n"
            "  portal_codec decode <hex-file>   # body hex -> XML\n"
            "  portal_codec selftest\n");
        return 2;
    }
    if (strcmp(argv[1], "selftest") == 0) return selftest();

    if (strcmp(argv[1], "encode") == 0 && argc >= 3) {
        size_t n;
        char *xml = read_file(argv[2], &n);
        char *out;
        size_t r;
        if (!xml) { fprintf(stderr, "cannot read %s\n", argv[2]); return 1; }
        out = (char *)malloc(portal_encoded_len(n) * 2 + 16);
        r = portal_encode_body(xml, out, portal_encoded_len(n) * 2 + 16);
        if (r == 0) { fprintf(stderr, "encode failed\n"); free(xml); free(out); return 1; }
        printf("%s\n", out);
        free(xml); free(out);
        return 0;
    }

    if (strcmp(argv[1], "decode") == 0 && argc >= 3) {
        size_t n;
        char *hx = read_file(argv[2], &n);
        char *out = (char *)malloc(n + 16);
        size_t xl;
        if (!hx) { fprintf(stderr, "cannot read %s\n", argv[2]); return 1; }
        strip_ws(hx);
        if (portal_decode_body_str(hx, out, n + 16, &xl) != 0) {
            fprintf(stderr, "decode failed\n"); free(hx); free(out); return 1;
        }
        fwrite(out, 1, xl, stdout);   /* write exactly, no added newline */
        free(hx); free(out);
        return 0;
    }

    fprintf(stderr, "unknown command\n");
    return 2;
}
