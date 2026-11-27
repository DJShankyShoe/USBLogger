/*
 * A card_password.txt's text checked against the card password's hash.
 */

/* memset. */
#include <string.h>

/* What this file defines, and PBKDF2-HMAC-SHA256. */
#include "card_password.h"
#include "sha256.h"

/* True for the white space a text editor puts around a line. */
static bool is_space(uint8_t c)
{
    return c == ' ' || c == '\t' || c == '\r' || c == '\n';
}

/* Skips a byte-order mark and the white space at either end. */
void card_password_trim(const uint8_t *text, uint32_t len, uint32_t *start, uint32_t *n)
{
    uint32_t a = 0, b = len;
    if (len >= 3u && text[0] == 0xEFu && text[1] == 0xBBu && text[2] == 0xBFu) {
        a = 3u;
    }
    while (a < b && is_space(text[a])) {
        a++;
    }
    while (b > a && is_space(text[b - 1u])) {
        b--;
    }
    *start = a;
    *n = b - a;
}

/* Hashes the trimmed text as the firmware's hash was made, and compares every byte. */
bool card_password_ok(const uint8_t *text, uint32_t len, const uint8_t salt[CARD_PASSWORD_SALT_BYTES],
                    uint32_t iterations, const uint8_t hash[CARD_PASSWORD_HASH_BYTES])
{
    uint32_t start, n;
    card_password_trim(text, len, &start, &n);
    if (n == 0u || n > CARD_PASSWORD_MAX_BYTES || iterations == 0u) {
        return false;
    }
    uint8_t got[CARD_PASSWORD_HASH_BYTES];
    pbkdf2_hmac_sha256(&text[start], n, salt, CARD_PASSWORD_SALT_BYTES, iterations, got);
    uint8_t diff = 0;   /* every byte compared, so the time says nothing about where they differ */
    for (uint32_t i = 0; i < CARD_PASSWORD_HASH_BYTES; i++) {
        diff |= (uint8_t)(got[i] ^ hash[i]);
    }
    memset(got, 0, sizeof(got));
    return diff == 0u;
}
