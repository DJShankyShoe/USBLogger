/*
 * SHA-256, HMAC-SHA256 and PBKDF2-HMAC-SHA256 in portable C, with no SDK or hardware accelerator,
 * so the host tools and tests compute the same hashes as the firmware.
 */
#ifndef SHA256_H
#define SHA256_H

/* size_t and the fixed-width integers. */
#include <stddef.h>
#include <stdint.h>

/* Size of a SHA-256 digest in bytes. */
#define SHA256_DIGEST_SIZE 32

/* A hash in progress: the state, the bits taken so far, and a partial block. */
typedef struct {
    uint32_t state[8];
    uint64_t bitlen;
    uint32_t buflen;
    uint8_t  buf[64];
} sha256_ctx_t;

/* Starts a new hash. */
void sha256_init(sha256_ctx_t *ctx);
/* Adds `len` bytes to the hash. */
void sha256_update(sha256_ctx_t *ctx, const void *data, size_t len);
/* Finishes the hash and writes its 32-byte digest. */
void sha256_final(sha256_ctx_t *ctx, uint8_t out[SHA256_DIGEST_SIZE]);

/* Hashes one buffer in a single call. */
void sha256(const void *data, size_t len, uint8_t out[SHA256_DIGEST_SIZE]);

/* An HMAC-SHA256 key (RFC 2104): its inner and outer hash states, computed once. */
typedef struct {
    sha256_ctx_t inner;   /* SHA-256 after (key XOR 0x36...) */
    sha256_ctx_t outer;   /* SHA-256 after (key XOR 0x5c...) */
} hmac_sha256_key_t;

/* Prepares a key: its inner and outer hash states, computed once. */
void hmac_sha256_key(hmac_sha256_key_t *k, const uint8_t *key, size_t len);
/* Starts a message: `ctx` takes it with sha256_update, then finish. */
void hmac_sha256_start(const hmac_sha256_key_t *k, sha256_ctx_t *ctx);
/* Finishes a message started with hmac_sha256_start and writes its HMAC. */
void hmac_sha256_finish(const hmac_sha256_key_t *k, sha256_ctx_t *ctx, uint8_t out[SHA256_DIGEST_SIZE]);
/* The HMAC of one message in a single call. */
void hmac_sha256(const hmac_sha256_key_t *k, const void *data, size_t len, uint8_t out[SHA256_DIGEST_SIZE]);

/* PBKDF2-HMAC-SHA256 (RFC 8018): a password hashed `iterations` times with a salt, one 32-byte
 * block. */
void pbkdf2_hmac_sha256(const uint8_t *password, size_t len, const uint8_t *salt, size_t salt_len,
                        uint32_t iterations, uint8_t out[SHA256_DIGEST_SIZE]);

#endif /* SHA256_H */
