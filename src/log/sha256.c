/*
 * SHA-256 (FIPS 180-4), HMAC-SHA256 (RFC 2104) and PBKDF2-HMAC-SHA256 (RFC 8018), with no SDK.
 */

/* memcpy, memset. */
#include <string.h>

/* What this file defines. */
#include "sha256.h"

/* The 64 round constants (the first 32 bits of the cube roots of the first 64 primes). */
static const uint32_t K[64] = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u,
    0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
    0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u,
    0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
    0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu,
    0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
    0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u,
    0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
    0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u,
    0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
    0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u,
    0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
    0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u,
    0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
    0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
    0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u,
};

/* The standard's bit functions on 32-bit words; ROR rotates right by n. */
#define ROR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
#define CH(x, y, z)  (((x) & (y)) ^ (~(x) & (z)))                /* "choose": y where x is 1, z where 0 */
#define MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))   /* majority of the three bits */
#define BSIG0(x) (ROR(x, 2) ^ ROR(x, 13) ^ ROR(x, 22))           /* on a, in each round */
#define BSIG1(x) (ROR(x, 6) ^ ROR(x, 11) ^ ROR(x, 25))           /* on e, in each round */
#define SSIG0(x) (ROR(x, 7) ^ ROR(x, 18) ^ ((x) >> 3))           /* in the message schedule */
#define SSIG1(x) (ROR(x, 17) ^ ROR(x, 19) ^ ((x) >> 10))         /* in the message schedule */

/* Mixes one 64-byte block into the hash state: the schedule, then 64 rounds. */
static void sha256_block(sha256_ctx_t *ctx, const uint8_t *p)
{
    uint32_t w[64];

    for (int i = 0; i < 16; i++) {
        w[i] = ((uint32_t)p[i * 4] << 24) | ((uint32_t)p[i * 4 + 1] << 16) |
               ((uint32_t)p[i * 4 + 2] << 8) | (uint32_t)p[i * 4 + 3];
    }
    for (int i = 16; i < 64; i++) {
        w[i] = SSIG1(w[i - 2]) + w[i - 7] + SSIG0(w[i - 15]) + w[i - 16];
    }

    uint32_t a = ctx->state[0], b = ctx->state[1];
    uint32_t c = ctx->state[2], d = ctx->state[3];
    uint32_t e = ctx->state[4], f = ctx->state[5];
    uint32_t g = ctx->state[6], h = ctx->state[7];

    for (int i = 0; i < 64; i++) {
        uint32_t t1 = h + BSIG1(e) + CH(e, f, g) + K[i] + w[i];
        uint32_t t2 = BSIG0(a) + MAJ(a, b, c);
        h = g; g = f; f = e;
        e = d + t1;
        d = c; c = b; b = a;
        a = t1 + t2;
    }

    ctx->state[0] += a; ctx->state[1] += b;
    ctx->state[2] += c; ctx->state[3] += d;
    ctx->state[4] += e; ctx->state[5] += f;
    ctx->state[6] += g; ctx->state[7] += h;
}

/* Starts a hash at the standard's initial state, with nothing hashed yet. */
void sha256_init(sha256_ctx_t *ctx)
{
    ctx->state[0] = 0x6a09e667u; ctx->state[1] = 0xbb67ae85u;
    ctx->state[2] = 0x3c6ef372u; ctx->state[3] = 0xa54ff53au;
    ctx->state[4] = 0x510e527fu; ctx->state[5] = 0x9b05688cu;
    ctx->state[6] = 0x1f83d9abu; ctx->state[7] = 0x5be0cd19u;
    ctx->bitlen = 0;
    ctx->buflen = 0;
}

/* Adds bytes to the hash, a block at a time; a partial block waits in ctx->buf. */
void sha256_update(sha256_ctx_t *ctx, const void *data, size_t len)
{
    const uint8_t *p = (const uint8_t *)data;

    while (len > 0) {
        uint32_t space = 64u - ctx->buflen;
        uint32_t take = (len < space) ? (uint32_t)len : space;
        memcpy(&ctx->buf[ctx->buflen], p, take);
        ctx->buflen += take;
        p += take;
        len -= take;

        if (ctx->buflen == 64u) {
            sha256_block(ctx, ctx->buf);
            ctx->bitlen += 512u;
            ctx->buflen = 0;
        }
    }
}

/* Pads the message with its length in bits and writes the 32-byte digest. */
void sha256_final(sha256_ctx_t *ctx, uint8_t out[SHA256_DIGEST_SIZE])
{
    uint64_t total_bits = ctx->bitlen + (uint64_t)ctx->buflen * 8u;
    uint32_t i = ctx->buflen;

    ctx->buf[i++] = 0x80u;
    if (i > 56u) {
        while (i < 64u) {
            ctx->buf[i++] = 0;
        }
        sha256_block(ctx, ctx->buf);
        i = 0;
    }
    while (i < 56u) {
        ctx->buf[i++] = 0;
    }
    for (int b = 7; b >= 0; b--) {
        ctx->buf[i++] = (uint8_t)(total_bits >> (b * 8));
    }
    sha256_block(ctx, ctx->buf);

    for (int j = 0; j < 8; j++) {
        out[j * 4]     = (uint8_t)(ctx->state[j] >> 24);
        out[j * 4 + 1] = (uint8_t)(ctx->state[j] >> 16);
        out[j * 4 + 2] = (uint8_t)(ctx->state[j] >> 8);
        out[j * 4 + 3] = (uint8_t)(ctx->state[j]);
    }
}

/* Hashes one buffer in a single call. */
void sha256(const void *data, size_t len, uint8_t out[SHA256_DIGEST_SIZE])
{
    sha256_ctx_t ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, data, len);
    sha256_final(&ctx, out);
}

/* Prepares a key: the inner and outer padded keys, already hashed in. */
void hmac_sha256_key(hmac_sha256_key_t *k, const uint8_t *key, size_t len)
{
    uint8_t block[64];
    memset(block, 0, sizeof(block));
    if (len > sizeof(block)) {
        sha256(key, len, block);   /* a key longer than a block is hashed first */
    } else {
        memcpy(block, key, len);
    }
    /* Each padded key is exactly one block: hashed straight in. */
    uint8_t pad[64];
    for (size_t i = 0; i < sizeof(pad); i++) {
        pad[i] = block[i] ^ 0x36u;
    }
    sha256_init(&k->inner);
    sha256_block(&k->inner, pad);
    k->inner.bitlen = 512u;
    for (size_t i = 0; i < sizeof(pad); i++) {
        pad[i] = block[i] ^ 0x5cu;
    }
    sha256_init(&k->outer);
    sha256_block(&k->outer, pad);
    k->outer.bitlen = 512u;
    memset(block, 0, sizeof(block));
    memset(pad, 0, sizeof(pad));
}

/* Starts an HMAC: a hash that already holds the inner padded key. */
void hmac_sha256_start(const hmac_sha256_key_t *k, sha256_ctx_t *ctx)
{
    *ctx = k->inner;
}

/* Finishes an HMAC: the inner digest hashed again after the outer padded key. */
void hmac_sha256_finish(const hmac_sha256_key_t *k, sha256_ctx_t *ctx, uint8_t out[SHA256_DIGEST_SIZE])
{
    uint8_t inner[SHA256_DIGEST_SIZE];
    sha256_final(ctx, inner);
    *ctx = k->outer;
    sha256_update(ctx, inner, sizeof(inner));
    sha256_final(ctx, out);
}

/* Gives the HMAC of one buffer in a single call. */
void hmac_sha256(const hmac_sha256_key_t *k, const void *data, size_t len, uint8_t out[SHA256_DIGEST_SIZE])
{
    sha256_ctx_t ctx;
    hmac_sha256_start(k, &ctx);
    sha256_update(&ctx, data, len);
    hmac_sha256_finish(k, &ctx, out);
}

/* PBKDF2's one block: U1 = HMAC(password, salt | 00 00 00 01), U(n) = HMAC(password, U(n-1)), all
 * XORed. */
void pbkdf2_hmac_sha256(const uint8_t *password, size_t len, const uint8_t *salt, size_t salt_len,
                        uint32_t iterations, uint8_t out[SHA256_DIGEST_SIZE])
{
    static const uint8_t block_one[4] = { 0u, 0u, 0u, 1u };
    hmac_sha256_key_t k;
    sha256_ctx_t ctx;
    uint8_t u[SHA256_DIGEST_SIZE];
    hmac_sha256_key(&k, password, len);
    hmac_sha256_start(&k, &ctx);
    sha256_update(&ctx, salt, salt_len);
    sha256_update(&ctx, block_one, sizeof(block_one));
    hmac_sha256_finish(&k, &ctx, u);
    memcpy(out, u, SHA256_DIGEST_SIZE);
    for (uint32_t i = 1; i < iterations; i++) {
        hmac_sha256(&k, u, sizeof(u), u);   /* the message is read before the result is written */
        for (uint32_t b = 0; b < SHA256_DIGEST_SIZE; b++) {
            out[b] ^= u[b];
        }
    }
    memset(&k, 0, sizeof(k));
    memset(&ctx, 0, sizeof(ctx));
    memset(u, 0, sizeof(u));
}
