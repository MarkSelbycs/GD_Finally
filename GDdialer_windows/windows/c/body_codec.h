/*
 * body_codec.h — China Telecom ESurfing campus portal body codec (C port)
 *
 * The portal request body is a 6-key DES cascade over the normalised request
 * XML, hex-encoded. Reversed from the per-dial downloaded AutoZSM module.
 *
 *   plaintext = normalise(xml)          // UTF-8 -> utf-8, ensure declaration
 *   plaintext += NUL, pad to 8 bytes (minimum 64)
 *   body      = hex( E_k3( D_k2( E_k1( E_k6( D_k5( E_k4( block )))))) )
 *
 * No external crypto library is required (self-contained DES).
 */
#ifndef BODY_CODEC_H
#define BODY_CODEC_H

#include <stddef.h>
#include <stdint.h>

/* Single-block DES (ECB), 8-byte block, 8-byte key. */
void des_encrypt_block(const uint8_t key[8], const uint8_t in[8], uint8_t out[8]);
void des_decrypt_block(const uint8_t key[8], const uint8_t in[8], uint8_t out[8]);

/*
 * Encode a NUL-terminated request XML string into the portal body.
 *   out     : destination buffer (ASCII hex, NUL terminated)
 *   outsz   : size of out; must be >= 2 * portal_encoded_len(xml) + 1
 * Returns the number of hex characters written, or 0 on failure.
 */
size_t portal_encode_body(const char *xml, char *out, size_t outsz);

/*
 * Length in bytes (not hex chars) of the encoded body for a given XML length.
 */
size_t portal_encoded_len(size_t xml_len);

/*
 * Decode a portal body (ASCII hex, NUL terminated) back to plaintext.
 *   out/outsz : destination for the padded plaintext
 *   outlen    : receives the plaintext length in bytes
 * Returns 0 on success, -1 on failure.
 */
int portal_decode_body(const char *hexbody, uint8_t *out, size_t outsz, size_t *outlen);

/* Convenience: decode and return a NUL-terminated XML string (strips padding). */
int portal_decode_body_str(const char *hexbody, char *out, size_t outsz, size_t *outlen);

#endif /* BODY_CODEC_H */
