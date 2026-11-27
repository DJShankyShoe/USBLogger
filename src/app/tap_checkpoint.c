/*
 * The checkpoint in the Pico's flash: the card's file id and its last record's session, seq and hash,
 * sealed with the chain key. The next boot's check must meet it, so a log cut short or an older card is
 * refused. Two 4 KB slots written in turn. Part of USBLogger.c (#included).
 */

/* Where the checkpoint lives: the top two 4 KB sectors of flash, used in turn; and its flags. */
#define CKPT_SECTORS 2u
#define CKPT_OFFSET  (PICO_FLASH_SIZE_BYTES - CKPT_SECTORS * FLASH_SECTOR_SIZE)
#define CKPT_ACCEPTED 1u   /* set by an operator's accept, not by a session's end */
#define CKPT_EMPTY    2u   /* the card held no records: any content of that file passes */
#define CKPT_PASSWORD 4u   /* the accept came from the card's card_password.txt file */
/* The first eight bytes of a checkpoint slot. */
static const char CKPT_MAGIC[8] = { 'T', 'A', 'P', 'C', 'K', 'P', 'T', '1' };

/* One checkpoint, as stored in a flash slot. */
typedef struct __attribute__((packed)) {
    char     magic[8];
    uint32_t generation;   /* +1 each save: the higher valid slot is the current one */
    uint32_t flags;        /* CKPT_* */
    uint64_t file_id;      /* AUDIT.BIN's id (sd_log.h) */
    uint64_t session_id;
    uint64_t seq;
    uint8_t  head[SHA256_DIGEST_SIZE];
    uint8_t  mac[SHA256_DIGEST_SIZE];   /* HMAC(chain key, every field above) */
} checkpoint_t;

static checkpoint_t g_ckpt;          /* the current one, read at boot */
static bool         g_ckpt_found;    /* a valid one was read at boot */
static uint32_t     g_ckpt_slot;     /* the slot it was read from */
static bool         g_ckpt_accept;   /* key c: keep the card as it is as the new reference */
static const char  *g_ckpt_why;      /* why the card did not match it */

/* Gives a slot's address in the flash, read through XIP. */
static const checkpoint_t *ckpt_in_flash(uint32_t slot)
{
    return (const checkpoint_t *)(XIP_BASE + CKPT_OFFSET + slot * FLASH_SECTOR_SIZE);
}

/* Computes a checkpoint's seal: HMAC with the chain key over every field before the seal. */
static void ckpt_mac(const checkpoint_t *c, uint8_t out[SHA256_DIGEST_SIZE])
{
    hmac_sha256(&g_chain_key, c, offsetof(checkpoint_t, mac), out);
}

/* Reads both slots and keeps the valid one with the higher generation. */
static bool checkpoint_load(void)
{
    g_ckpt_found = false;
    for (uint32_t slot = 0; slot < CKPT_SECTORS; slot++) {
        checkpoint_t c;
        memcpy(&c, ckpt_in_flash(slot), sizeof(c));
        uint8_t mac[SHA256_DIGEST_SIZE];
        ckpt_mac(&c, mac);
        if (memcmp(c.magic, CKPT_MAGIC, sizeof(CKPT_MAGIC)) != 0 || memcmp(mac, c.mac, sizeof(mac)) != 0) {
            continue;
        }
        if (!g_ckpt_found || c.generation > g_ckpt.generation) {
            g_ckpt = c;
            g_ckpt_slot = slot;
            g_ckpt_found = true;
        }
    }
    return g_ckpt_found;
}

/* Erases and programs one slot from SRAM, putting the tap's flash timing back after each step (the
 * SDK restores the ROM's). */
static void __no_inline_not_in_flash_func(ckpt_flash_write)(uint32_t offs, const uint8_t *page)
{
    const uint32_t timing = qmi_hw->m[0].timing;
    flash_range_erase(offs, FLASH_SECTOR_SIZE);
    qmi_hw->m[0].timing = timing;
    flash_range_program(offs, page, FLASH_PAGE_SIZE);
    qmi_hw->m[0].timing = timing;
}

/* Writes a new checkpoint to the other slot (core1 is held in reset from here on); true if it reads
 * back. */
static bool checkpoint_save(uint64_t file_id, uint64_t session_id, uint64_t seq,
                            const uint8_t head[SHA256_DIGEST_SIZE], uint32_t flags)
{
    checkpoint_t n;
    memset(&n, 0, sizeof(n));
    memcpy(n.magic, CKPT_MAGIC, sizeof(CKPT_MAGIC));
    n.generation = g_ckpt_found ? g_ckpt.generation + 1u : 1u;
    n.flags      = flags;
    n.file_id    = file_id;
    n.session_id = session_id;
    n.seq        = seq;
    memcpy(n.head, head, SHA256_DIGEST_SIZE);
    ckpt_mac(&n, n.mac);

    const uint32_t slot = g_ckpt_found ? 1u - g_ckpt_slot : 0u;
    static uint8_t page[FLASH_PAGE_SIZE];
    memset(page, 0xFF, sizeof(page));
    memcpy(page, &n, sizeof(n));

    multicore_reset_core1();
    const uint32_t irq = save_and_disable_interrupts();
    ckpt_flash_write(CKPT_OFFSET + slot * FLASH_SECTOR_SIZE, page);
    restore_interrupts(irq);

    if (memcmp(ckpt_in_flash(slot), &n, sizeof(n)) != 0) {
        return false;
    }
    g_ckpt = n;
    g_ckpt_slot = slot;
    g_ckpt_found = true;
    return true;
}

/* Keeps the card as the check found it as the new reference: key c then q, or a right
 * card_password.txt. */
static bool checkpoint_save_accepted(uint32_t flags)
{
    const bool empty = g_card_check.records == 0u;
    return checkpoint_save(g_sd_log.file_id, g_card_check.session_id,
                           empty ? 0u : g_card_check.next_seq - 1u, g_card_check.prev,
                           CKPT_ACCEPTED | (empty ? CKPT_EMPTY : 0u) | flags);
}

/* Why a card_password.txt was not used, for the banner. */
static const char *g_accept_why;

/* Accepts a new card by its card_password.txt (already wiped and deleted): only if its chains are sound,
 * the checkpoint names another card, it holds no record and the password is right. Then saves the
 * checkpoint and reboots (flash needs core1 stopped); otherwise the card stays refused. */
static void accept_by_password(void)
{
    if (!g_sd_info.password_found) {
        return;
    }
    const bool eligible = g_card_check_ran && g_card_check_walked && !g_card_check.broken &&
                          (g_card_check_aux & AUDIT_CHECKPOINT_LOST);
    if (!eligible) {
        g_accept_why = g_card_check_ok ? "card_password.txt not needed: the card passed its check"
                                       : "card_password.txt not used: the card's log does not verify";
    } else if (g_card_check.records != 0u) {
        g_accept_why = "card_password.txt refused: the card holds a log (only a new or freshly formatted card is accepted)";
    } else if (!g_sd_info.password_removed) {
        g_accept_why = "card_password.txt refused: it could not be wiped and deleted (read-only?)";
    } else if (!card_password_ok(g_sd_info.password, g_sd_info.password_len, CARD_PASSWORD_SALT,
                                 CARD_PASSWORD_ITERATIONS, CARD_PASSWORD_HASH)) {
        g_accept_why = "card_password.txt refused: wrong password";
    } else {
        memset(g_sd_info.password, 0, sizeof(g_sd_info.password));
        tap_printf("[check] card_password.txt: right password, and the card is new: it becomes the reference; rebooting\n");
        if (!checkpoint_save_accepted(CKPT_PASSWORD)) {
            g_accept_why = "card_password.txt right, but the checkpoint was NOT kept (flash did not read back)";
            return;
        }
        watchdog_reboot(0, 0, 0);
        for (;;) {
            tight_loop_contents();
        }
    }
    memset(g_sd_info.password, 0, sizeof(g_sd_info.password));
}

/* At boot, after the walk: does the card still hold the checkpoint? Gives AUDIT_CHECKPOINT_* for
 * CARD_CHECK. */
static uint8_t checkpoint_compare(const audit_chain_check_t *c, uint64_t file_id)
{
    if (!g_ckpt_found) {
        return AUDIT_CHECKPOINT_NONE;
    }
    const uint8_t accepted = ((g_ckpt.flags & CKPT_ACCEPTED) ? AUDIT_CHECKPOINT_ACCEPTED : 0u) |
                             ((g_ckpt.flags & CKPT_PASSWORD) ? AUDIT_CHECKPOINT_PASSWORD : 0u);
    if (g_ckpt.file_id != file_id) {
        g_ckpt_why = "this is not the AUDIT.BIN this tap last wrote (another card, or the card was reformatted)";
        return AUDIT_CHECKPOINT_LOST | accepted;
    }
    if ((g_ckpt.flags & CKPT_EMPTY) || (c->watch_seen && c->watch_ok)) {
        return AUDIT_CHECKPOINT_OK | accepted;
    }
    g_ckpt_why = "the card no longer holds the last record this tap wrote to it (its log was cut short, or "
                 "an older copy of it was put back)";
    return AUDIT_CHECKPOINT_LOST | accepted;
}

/* The first session on a card accepted by password: its CARD_CHECK is an ACCEPT, so the accept is
 * in the chain. */
static bool checkpoint_first_after_password(const audit_chain_check_t *c, uint8_t aux)
{
    return (aux & AUDIT_CHECKPOINT_OK) && (g_ckpt.flags & CKPT_PASSWORD) && (g_ckpt.flags & CKPT_EMPTY) &&
           c->records == 0u;
}
