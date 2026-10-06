/*
 * body_codec.c — self-contained DES + the ESurfing portal 6DES body codec.
 */
#include "body_codec.h"

#include <string.h>

/* ------------------------------------------------------------------ DES ---- */

static const uint8_t IP[64] = {
    58,50,42,34,26,18,10,2, 60,52,44,36,28,20,12,4,
    62,54,46,38,30,22,14,6, 64,56,48,40,32,24,16,8,
    57,49,41,33,25,17,9,1,  59,51,43,35,27,19,11,3,
    61,53,45,37,29,21,13,5, 63,55,47,39,31,23,15,7
};
static const uint8_t FP[64] = {
    40,8,48,16,56,24,64,32, 39,7,47,15,55,23,63,31,
    38,6,46,14,54,22,62,30, 37,5,45,13,53,21,61,29,
    36,4,44,12,52,20,60,28, 35,3,43,11,51,19,59,27,
    34,2,42,10,50,18,58,26, 33,1,41,9,49,17,57,25
};
static const uint8_t E[48] = {
    32,1,2,3,4,5, 4,5,6,7,8,9, 8,9,10,11,12,13, 12,13,14,15,16,17,
    16,17,18,19,20,21, 20,21,22,23,24,25, 24,25,26,27,28,29, 28,29,30,31,32,1
};
static const uint8_t P[32] = {
    16,7,20,21,29,12,28,17, 1,15,23,26,5,18,31,10,
    2,8,24,14,32,27,3,9, 19,13,30,6,22,11,4,25
};
static const uint8_t PC1[56] = {
    57,49,41,33,25,17,9, 1,58,50,42,34,26,18,
    10,2,59,51,43,35,27, 19,11,3,60,52,44,36,
    63,55,47,39,31,23,15, 7,62,54,46,38,30,22,
    14,6,61,53,45,37,29, 21,13,5,28,20,12,4
};
static const uint8_t PC2[48] = {
    14,17,11,24,1,5, 3,28,15,6,21,10,
    23,19,12,4,26,8, 16,7,27,20,13,2,
    41,52,31,37,47,55, 30,40,51,45,33,48,
    44,49,39,56,34,53, 46,42,50,36,29,32
};
static const uint8_t SHIFT[16] = {1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1};

static const uint8_t SBOX[8][64] = {
 { 14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7,
    0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8,
    4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0,
   15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13 },
 { 15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10,
    3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5,
    0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15,
   13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9 },
 { 10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8,
   13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1,
   13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7,
    1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12 },
 {  7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15,
   13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9,
   10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4,
    3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14 },
 {  2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9,
   14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6,
    4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14,
   11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3 },
 { 12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11,
   10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8,
    9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6,
    4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13 },
 {  4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1,
   13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6,
    1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2,
    6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12 },
 { 13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7,
    1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2,
    7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8,
    2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11 }
};

/* Permute `inbits`-wide value `in` through a 1-based table of `n` entries. */
static uint64_t permute(uint64_t in, const uint8_t *tbl, int n, int inbits)
{
    uint64_t out = 0;
    int i;
    for (i = 0; i < n; i++) {
        uint64_t bit = (in >> (inbits - tbl[i])) & 1ULL;
        out |= bit << (n - 1 - i);
    }
    return out;
}

static uint32_t f_func(uint32_t r, uint64_t subkey)
{
    uint64_t x = permute(r, E, 48, 32) ^ subkey;
    uint32_t y = 0;
    int i;
    for (i = 0; i < 8; i++) {
        int row, col, v;
        uint8_t six = (uint8_t)((x >> (42 - 6 * i)) & 0x3F);
        row = ((six & 0x20) >> 4) | (six & 1);
        col = (six >> 1) & 0x0F;
        v = SBOX[i][row * 16 + col];
        y = (y << 4) | (uint32_t)v;
    }
    return (uint32_t)permute(y, P, 32, 32);
}

static void key_schedule(const uint8_t key[8], uint64_t subkeys[16])
{
    uint64_t k = 0, cd;
    uint32_t c, d;
    int i, shift;
    for (i = 0; i < 8; i++) k = (k << 8) | key[i];
    cd = permute(k, PC1, 56, 64);
    c = (uint32_t)(cd >> 28) & 0x0FFFFFFF;
    d = (uint32_t)cd & 0x0FFFFFFF;
    for (i = 0; i < 16; i++) {
        shift = SHIFT[i];
        c = ((c << shift) | (c >> (28 - shift))) & 0x0FFFFFFF;
        d = ((d << shift) | (d >> (28 - shift))) & 0x0FFFFFFF;
        subkeys[i] = permute(((uint64_t)c << 28) | d, PC2, 48, 56);
    }
}

static void des_crypt(const uint8_t key[8], const uint8_t in[8], uint8_t out[8], int decrypt)
{
    uint64_t subkeys[16], blk = 0, ip;
    uint32_t l, r;
    int i, round;
    key_schedule(key, subkeys);
    for (i = 0; i < 8; i++) blk = (blk << 8) | in[i];
    ip = permute(blk, IP, 64, 64);
    l = (uint32_t)(ip >> 32);
    r = (uint32_t)ip;
    for (i = 0; i < 16; i++) {
        uint32_t t;
        round = decrypt ? (15 - i) : i;
        t = r;
        r = l ^ f_func(r, subkeys[round]);
        l = t;
    }
    {
        uint64_t pre = ((uint64_t)r << 32) | l;
        uint64_t fp = permute(pre, FP, 64, 64);
        for (i = 0; i < 8; i++) out[i] = (uint8_t)(fp >> (56 - 8 * i));
    }
}

void des_encrypt_block(const uint8_t key[8], const uint8_t in[8], uint8_t out[8])
{
    des_crypt(key, in, out, 0);
}

void des_decrypt_block(const uint8_t key[8], const uint8_t in[8], uint8_t out[8])
{
    des_crypt(key, in, out, 1);
}

/* --------------------------------------------------------------- codec ---- */

/* Static 6-key cascade (from the algorithm module, RVA 0x1000c568 + 46). */
static const uint8_t KEYS[6][8] = {
    { 0x46,0x2b,0x2b,0x2a,0x6c,0x69,0x23,0x7a },  /* k1 */
    { 0x53,0x53,0x73,0x68,0x3f,0x43,0x7e,0x2b },  /* k2 */
    { 0x7c,0x2b,0x21,0x62,0x29,0x40,0x7b,0x3f },  /* k3 */
    { 0x23,0x59,0x4b,0x7c,0x74,0x7a,0x51,0x3b },  /* k4 */
    { 0x53,0x6e,0x5f,0x40,0x3a,0x54,0x43,0x2a },  /* k5 */
    { 0x25,0x25,0x62,0x4a,0x43,0x27,0x5a,0x53 }   /* k6 */
};

/* (key index, is_encrypt) applied in order: E k4, D k5, E k6, E k1, D k2, E k3 */
static const struct { int key; int enc; } CASCADE[6] = {
    { 3, 1 }, { 4, 0 }, { 5, 1 }, { 0, 1 }, { 1, 0 }, { 2, 1 }
};

#define MIN_BLOCK 64

static void cascade_block(const uint8_t in[8], uint8_t out[8], int inverse)
{
    uint8_t a[8], b[8];
    int i, step;
    memcpy(a, in, 8);
    for (i = 0; i < 6; i++) {
        step = inverse ? (5 - i) : i;
        if (CASCADE[step].enc != inverse)
            des_encrypt_block(KEYS[CASCADE[step].key], a, b);
        else
            des_decrypt_block(KEYS[CASCADE[step].key], a, b);
        memcpy(a, b, 8);
    }
    memcpy(out, a, 8);
}

size_t portal_encoded_len(size_t xml_len)
{
    size_t n = xml_len + 1;
    n = (n + 7) & ~(size_t)7;
    if (n < MIN_BLOCK) n = MIN_BLOCK;
    return n;
}

/* Build the normalised plaintext (UTF-8 -> utf-8, ensure declaration). */
static size_t normalise(const char *xml, uint8_t *out, size_t outsz)
{
    static const char DECL[] = "<?xml version=\"1.0\" encoding=\"utf-8\"?>";
    size_t n = strlen(xml), i, w = 0;
    int has_decl = 0;

    for (i = 0; i + 5 <= n; i++)
        if (xml[i] == '<' && xml[i + 1] == '?' &&
            xml[i + 2] == 'x' && xml[i + 3] == 'm' && xml[i + 4] == 'l') {
            has_decl = 1;
            break;
        }

    if (!has_decl) {
        size_t dl = sizeof(DECL) - 1;
        if (w + dl >= outsz) return 0;
        memcpy(out + w, DECL, dl);
        w += dl;
    }
    if (w + n >= outsz) return 0;
    for (i = 0; i < n; i++) out[w + i] = (uint8_t)xml[i];
    w += n;

    /* lowercase the encoding="UTF-8" token */
    {
        static const char UP[] = "UTF-8";
        size_t j;
        for (j = 0; j + 5 < w; j++) {
            if (out[j] == 'U' && out[j + 1] == 'T' &&
                out[j + 2] == 'F' && out[j + 3] == '-' && out[j + 4] == '8')
                memcpy(out + j, UP, 5), out[j] = 'u', out[j + 1] = 't', out[j + 2] = 'f';
        }
    }
    return w;
}

size_t portal_encode_body(const char *xml, char *out, size_t outsz)
{
    uint8_t plain[8192], block[8], ct[8];
    size_t n, padded, i, k;
    static const char HEX[] = "0123456789ABCDEF";

    n = normalise(xml, plain, sizeof(plain));
    if (n == 0) return 0;
    padded = portal_encoded_len(n);
    if (padded > sizeof(plain)) return 0;
    memset(plain + n, 0, padded - n);

    if (outsz < padded * 2 + 1) return 0;

    k = 0;
    for (i = 0; i < padded; i += 8) {
        memcpy(block, plain + i, 8);
        cascade_block(block, ct, 0);
        out[k++] = HEX[ct[0] >> 4]; out[k++] = HEX[ct[0] & 15];
        out[k++] = HEX[ct[1] >> 4]; out[k++] = HEX[ct[1] & 15];
        out[k++] = HEX[ct[2] >> 4]; out[k++] = HEX[ct[2] & 15];
        out[k++] = HEX[ct[3] >> 4]; out[k++] = HEX[ct[3] & 15];
        out[k++] = HEX[ct[4] >> 4]; out[k++] = HEX[ct[4] & 15];
        out[k++] = HEX[ct[5] >> 4]; out[k++] = HEX[ct[5] & 15];
        out[k++] = HEX[ct[6] >> 4]; out[k++] = HEX[ct[6] & 15];
        out[k++] = HEX[ct[7] >> 4]; out[k++] = HEX[ct[7] & 15];
    }
    out[k] = '\0';
    return k;
}

static int hexval(int c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

int portal_decode_body(const char *hexbody, uint8_t *out, size_t outsz, size_t *outlen)
{
    size_t n = strlen(hexbody), i;
    uint8_t block[8], pt[8];
    if (n % 16 != 0) return -1;
    if (n / 2 > outsz) return -1;
    for (i = 0; i < n; i += 16) {
        int j;
        for (j = 0; j < 8; j++) {
            int hi = hexval(hexbody[i + 2 * j]);
            int lo = hexval(hexbody[i + 2 * j + 1]);
            if (hi < 0 || lo < 0) return -1;
            block[j] = (uint8_t)((hi << 4) | lo);
        }
        cascade_block(block, pt, 1);
        memcpy(out + i / 2, pt, 8);
    }
    if (outlen) *outlen = n / 2;
    return 0;
}

int portal_decode_body_str(const char *hexbody, char *out, size_t outsz, size_t *outlen)
{
    size_t n;
    if (portal_decode_body(hexbody, (uint8_t *)out, outsz - 1, &n) != 0) return -1;
    /* strip at the first NUL (padding) */
    {
        size_t i;
        for (i = 0; i < n; i++) if (out[i] == '\0') break;
        out[i] = '\0';
        if (outlen) *outlen = i;
    }
    return 0;
}
