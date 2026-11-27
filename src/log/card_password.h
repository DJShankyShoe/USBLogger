/*
 * The card password: a new card's card_password.txt checked against the PBKDF2 hash in the firmware.
 * The firmware holds only the salt, the iteration count and the hash (tools/make_secret.py card-password).
 */
#ifndef CARD_PASSWORD_H
#define CARD_PASSWORD_H

/* bool and the fixed-width integers. */
#include <stdbool.h>
#include <stdint.h>

/* The password's longest length, its salt and its hash, in bytes. */
#define CARD_PASSWORD_MAX_BYTES  64u   /* the longest password, once trimmed */
#define CARD_PASSWORD_SALT_BYTES 16u
#define CARD_PASSWORD_HASH_BYTES 32u

/* Where the password starts in card_password.txt's bytes, and its length: a BOM and white space at
 * either end dropped. */
void card_password_trim(const uint8_t *text, uint32_t len, uint32_t *start, uint32_t *n);

/* True if `text` is the password `hash` was made from: trimmed, 1 to 64 bytes, compared in constant
 * time. */
bool card_password_ok(const uint8_t *text, uint32_t len, const uint8_t salt[CARD_PASSWORD_SALT_BYTES],
                    uint32_t iterations, const uint8_t hash[CARD_PASSWORD_HASH_BYTES]);

#endif /* CARD_PASSWORD_H */
