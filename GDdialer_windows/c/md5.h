/*
 * md5.h / md5.c (header part) — minimal self-contained MD5 for CDC-Checksum.
 */
#ifndef MD5_H
#define MD5_H

#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint32_t state[4];
    uint64_t count;
    uint8_t buffer[64];
} md5_ctx;

void md5_init(md5_ctx *c);
void md5_update(md5_ctx *c, const void *data, size_t len);
void md5_final(md5_ctx *c, uint8_t digest[16]);
void md5_hex(const void *data, size_t len, char out[33]);

#endif
