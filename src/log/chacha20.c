/*
 * The ChaCha20 stream cipher (RFC 8439), used to encrypt the card's blocks.
 */

/* The two functions this file defines. */
#include "chacha20.h"

/* Reads four bytes as a little-endian 32-bit word. */
static uint32_t load32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

/* Rotates a 32-bit word left by n bits (n is 7, 8, 12 or 16). */
static uint32_t rotl(uint32_t v, unsigned n)
{
    return (v << n) | (v >> (32u - n));
}

/* The quarter round: four additions, XORs and rotations on four words. */
#define QR(a, b, c, d)                       \
    a += b; d ^= a; d = rotl(d, 16);         \
    c += d; b ^= c; b = rotl(b, 12);         \
    a += b; d ^= a; d = rotl(d, 8);          \
    c += d; b ^= c; b = rotl(b, 7)

/* Makes one 64-byte block of keystream for (key, nonce, counter). */
void chacha20_block(const uint8_t key[32], const uint8_t nonce[12], uint32_t counter, uint8_t out[64])
{
    /* The state: four constants ("expand 32-byte k"), the key, the counter and the nonce. */
    uint32_t s[16];
    s[0] = 0x61707865u;
    s[1] = 0x3320646eu;
    s[2] = 0x79622d32u;
    s[3] = 0x6b206574u;
    for (int i = 0; i < 8; i++) {
        s[4 + i] = load32(key + 4 * i);
    }
    s[12] = counter;
    s[13] = load32(nonce);
    s[14] = load32(nonce + 4);
    s[15] = load32(nonce + 8);

    uint32_t x[16];
    for (int i = 0; i < 16; i++) {
        x[i] = s[i];
    }
    for (int round = 0; round < 10; round++) {   /* 20 rounds: column then diagonal */
        QR(x[0], x[4], x[8], x[12]);
        QR(x[1], x[5], x[9], x[13]);
        QR(x[2], x[6], x[10], x[14]);
        QR(x[3], x[7], x[11], x[15]);
        QR(x[0], x[5], x[10], x[15]);
        QR(x[1], x[6], x[11], x[12]);
        QR(x[2], x[7], x[8], x[13]);
        QR(x[3], x[4], x[9], x[14]);
    }
    for (int i = 0; i < 16; i++) {
        const uint32_t v = x[i] + s[i];
        out[4 * i]     = (uint8_t)v;
        out[4 * i + 1] = (uint8_t)(v >> 8);
        out[4 * i + 2] = (uint8_t)(v >> 16);
        out[4 * i + 3] = (uint8_t)(v >> 24);
    }
}

/* Encrypts or decrypts data in place: XORs it with keystream from block `counter` on. */
void chacha20_xor(const uint8_t key[32], const uint8_t nonce[12], uint32_t counter, uint8_t *data, size_t len)
{
    uint8_t ks[64];
    while (len > 0) {
        chacha20_block(key, nonce, counter++, ks);
        const size_t n = len < sizeof(ks) ? len : sizeof(ks);
        for (size_t i = 0; i < n; i++) {
            data[i] ^= ks[i];
        }
        data += n;
        len -= n;
    }
}
