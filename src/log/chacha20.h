/*
 * The ChaCha20 stream cipher (RFC 8439), used to encrypt the card's blocks.
 * A 256-bit key, a 96-bit nonce and a 32-bit counter give 64-byte keystream blocks; a key and nonce
 * must never be used twice for different data.
 */
#ifndef CHACHA20_H
#define CHACHA20_H

/* size_t and the fixed-width integers. */
#include <stddef.h>
#include <stdint.h>

/* XORs `len` bytes of `data` in place with the keystream from block `counter` of (key, nonce). */
void chacha20_xor(const uint8_t key[32], const uint8_t nonce[12], uint32_t counter, uint8_t *data, size_t len);

/* One 64-byte keystream block (RFC 8439 section 2.3), for the test vectors. */
void chacha20_block(const uint8_t key[32], const uint8_t nonce[12], uint32_t counter, uint8_t out[64]);

#endif /* CHACHA20_H */
