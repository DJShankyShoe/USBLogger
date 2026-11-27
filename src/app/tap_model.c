/*
 * The exFAT name model kept on the SD card, one snapshot per volume, so names carry across power-downs.
 * Saved when the drive goes away and at the session's end (a MODEL SAVED record vouches for it); the
 * latest is loaded at boot and trusted only once the drive's boot sector confirms it. Part of USBLogger.c.
 */

#define MODEL_INDEX 8u   /* volumes whose last snapshot the boot check keeps track of */
/* One volume in the index: the serial, where its latest snapshot starts, and its digest. */
typedef struct {
    bool     used;
    bool     stale;        /* a later VOLUME record for it, with no snapshot saved since */
    uint32_t serial;
    uint32_t block;        /* the snapshot's first block in the log file */
    uint8_t  digest[16];   /* what its MODEL SAVED record vouches for */
    uint64_t order;        /* records walked when it was found: the largest is the latest */
} model_index_t;
/* The index the boot check's walk builds, and how many records it walked. */
static model_index_t g_model_index[MODEL_INDEX];
static uint64_t      g_model_walked;

static bool     g_model_save_due;        /* the drive went away: save once the link is empty */
static bool     g_model_from_card;       /* the model was loaded and awaits its boot sector */
static uint32_t g_model_from_card_serial;   /* the loaded model's volume */
/* Counters and timings for the [model] line. */
static uint64_t g_model_saves, g_model_save_fails, g_model_loads, g_model_refusals;
static uint32_t g_model_last_bytes, g_model_last_blocks;
static uint64_t g_model_save_us_max, g_model_load_us_max;
/* What happened to the model at boot, printed in the banner. */
static char     g_model_boot_note[160] = "no usable card: no model loaded";
/* A save and a load never overlap: they share their block buffer. */
static union {
    sd_blob_writer_t w;
    sd_blob_reader_t r;
} g_model_io;

/* Reads a little-endian 32-bit field. */
static uint32_t rd_le32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

/* Finds a volume in the index; NULL if it has no snapshot on the card. */
static model_index_t *model_index_find(uint32_t serial)
{
    for (uint32_t i = 0; i < MODEL_INDEX; i++) {
        if (g_model_index[i].used && g_model_index[i].serial == serial) {
            return &g_model_index[i];
        }
    }
    return NULL;
}

/* Notes a volume's latest snapshot: from the boot check's walk, and from every save this session. */
static void model_index_note(uint32_t serial, uint32_t block, const uint8_t digest[16])
{
    model_index_t *e = model_index_find(serial);
    for (uint32_t i = 0; e == NULL && i < MODEL_INDEX; i++) {
        e = !g_model_index[i].used ? &g_model_index[i] : NULL;
    }
    if (e == NULL) {   /* full: the volume saved longest ago gives way */
        e = &g_model_index[0];
        for (uint32_t i = 1; i < MODEL_INDEX; i++) {
            e = g_model_index[i].order < e->order ? &g_model_index[i] : e;
        }
    }
    e->used   = true;
    e->stale  = false;
    e->serial = serial;
    e->block  = block;
    e->order  = ++g_model_walked;
    memcpy(e->digest, digest, 16u);
}

/* The volume was seen (a VOLUME record): its snapshot is stale until the next save. */
static void model_index_seen(uint32_t serial)
{
    model_index_t *const e = model_index_find(serial);
    if (e != NULL) {
        e->stale = true;
    }
}

/* The boot check's visitor: the chain check, then the records that place or date a snapshot. */
static bool model_index_visit(void *vctx, const uint8_t *data, uint32_t len)
{
    const bool more = audit_chain_check_visit(vctx, data, len);
    led_tick();   /* the slow blink goes on through the walk */
    if (len != sizeof(audit_record_t)) {
        return more;
    }
    g_model_walked++;
    const uint8_t type = data[offsetof(audit_body_t, type)];
    const uint8_t op   = data[offsetof(audit_body_t, op)];
    if (type == AUDIT_REC_MODEL && op == AUDIT_MODEL_SAVED) {
        model_index_note(rd_le32(&data[offsetof(audit_body_t, dev_addr)]),
                         rd_le32(&data[offsetof(audit_body_t, lba)]), &data[offsetof(audit_body_t, block_count)]);
    } else if (type == AUDIT_REC_FILE_EVENT && op == AUDIT_FILE_VOLUME) {
        model_index_seen(rd_le32(&data[offsetof(audit_body_t, block_count)]));
    }
    return more;
}

/* Writes a 16-byte digest as 32 lowercase hex digits. */
static void hex16(const uint8_t *d, char out[33])
{
    static const char digits[] = "0123456789abcdef";
    for (int i = 0; i < 16; i++) {
        out[2 * i]     = digits[d[i] >> 4];
        out[2 * i + 1] = digits[d[i] & 0x0Fu];
    }
    out[32] = '\0';
}

/* Loads a volume's last snapshot and checks it against its record; a MODEL record either way, fresh
 * on refusal. */
static bool model_load(const model_index_t *e, bool at_insertion)
{
    sd_blob_reader_t *const r = &g_model_io.r;
    uint8_t digest[SHA256_DIGEST_SIZE];
    const uint64_t t0 = time_us_64();
    bool ok = sd_blob_open(r, &g_sd_log, e->block) &&
              exfat_model_snapshot_read(&g_exfat, sd_blob_get, r, digest);
    uint8_t why = ok ? 0u : 1u;
    if (ok && (memcmp(digest, e->digest, 16u) != 0 || g_exfat.serial != e->serial)) {
        ok  = false;
        why = 2u;
        exfat_model_init(&g_exfat, g_exfat.cb, g_exfat.ctx);
    }
    const uint64_t us = time_us_64() - t0;
    g_model_load_us_max = us > g_model_load_us_max ? us : g_model_load_us_max;
    const uint8_t aux = (uint8_t)((e->stale ? AUDIT_MODEL_STALE : 0u) | (at_insertion ? AUDIT_MODEL_INSERTION : 0u));
    audit_log_model(&g_log, (time_us_64() - g_capture.start_us) * 1000u,
                    ok ? AUDIT_MODEL_LOADED : AUDIT_MODEL_REFUSED, aux, why, e->block, e->serial,
                    ok ? digest : e->digest);
    char dhex[33];
    hex16(e->digest, dhex);
    if (ok) {
        g_model_loads++;
        g_model_from_card = true;
        g_model_from_card_serial = e->serial;
        snprintf(g_model_boot_note, sizeof(g_model_boot_note),
                 "volume %08lx loaded from block %lu (%lu blocks, %.0f ms), digest %s... as its record says%s",
                 (unsigned long)e->serial, (unsigned long)e->block, (unsigned long)r->blocks_read,
                 (double)us / 1000.0, dhex, e->stale ? "; STALE: a later session saw the volume and saved none" : "");
    } else {
        g_model_refusals++;
        g_model_from_card = false;
        snprintf(g_model_boot_note, sizeof(g_model_boot_note),
                 "volume %08lx NOT loaded: its snapshot at block %lu %s -- names start afresh",
                 (unsigned long)e->serial, (unsigned long)e->block,
                 why == 1u ? "could not be read or is not a snapshot"
                           : "is not what the chain vouches for (changed on the card)");
    }
    if (at_insertion || g_banner_done) {
        tap_printf("[model] %s\n", g_model_boot_note);
    }
    return ok;
}

/* At boot, after the card check passed: the volume saved last. */
static void model_preload(void)
{
    const model_index_t *latest = NULL;
    uint32_t n = 0;
    for (uint32_t i = 0; i < MODEL_INDEX; i++) {
        if (g_model_index[i].used) {
            n++;
            latest = latest == NULL || g_model_index[i].order > latest->order ? &g_model_index[i] : latest;
        }
    }
    if (latest == NULL) {
        snprintf(g_model_boot_note, sizeof(g_model_boot_note), "no model on the card yet");
        return;
    }
    (void)model_load(latest, false);
    const size_t at = strlen(g_model_boot_note);
    snprintf(&g_model_boot_note[at], sizeof(g_model_boot_note) - at, " (the card has %lu volume(s))",
             (unsigned long)n);
}

/* Before a transfer reaches the model: another volume's boot sector brings that volume's model from
 * the card. */
static void model_before_feed(uint64_t lba, const uint8_t *data, uint32_t blocks)
{
    for (uint32_t s = 0; s < blocks; s++) {
        uint32_t serial;
        if (!exfat_boot_sector_serial(&g_exfat, lba + s, &data[s * META_SECTOR_BYTES], &serial)) {
            continue;
        }
        if (g_exfat.have_volume && g_exfat.serial == serial) {
            return;
        }
        const model_index_t *const e = model_index_find(serial);
        if (e != NULL && (g_sd_log.state == SD_LOG_OPEN || g_sd_log.state == SD_LOG_FULL)) {
            (void)model_load(e, true);
        }
        return;
    }
}

/* After a VOLUME event: says whether the model from the card was confirmed or dropped. */
static void model_on_volume(uint32_t serial)
{
    model_index_seen(serial);
    if (!g_model_from_card) {
        return;
    }
    g_model_from_card = false;
    if (serial == g_model_from_card_serial && g_exfat.ndirs != 0u) {
        uint32_t cached = 0;
        for (uint32_t i = 0; i < EXFAT_CACHE_SECTORS; i++) {
            cached += g_exfat.cache[i].valid ? 1u : 0u;
        }
        tap_printf("[model] volume %08lx confirmed by its boot sector: the model from the card carries on (%lu"
               " directories, %lu directory sectors remembered); a directory read that differs from them is"
               " a change made where the tap did not see it\n",
               (unsigned long)serial, (unsigned long)g_exfat.ndirs, (unsigned long)cached);
    } else {
        tap_printf("[model] the drive is volume %08lx, or its layout changed: the model loaded for %08lx was"
               " dropped, names start afresh\n", (unsigned long)serial, (unsigned long)g_model_from_card_serial);
    }
}

/* Writes the model to the card if this insertion's boot sector confirmed it; called when the bus is
 * quiet. */
static void model_save(const char *when)
{
    if (!g_exfat.have_volume || !g_exfat.volume_confirmed) {
        return;
    }
    if (g_sd_log.state != SD_LOG_OPEN) {
        g_model_save_fails++;
        tap_printf("[model] volume %08lx: model NOT saved (%s): the card is %s\n", (unsigned long)g_exfat.serial,
               when, sd_state_name(g_sd_log.state));
        return;
    }
    sd_blob_writer_t *const w = &g_model_io.w;
    uint8_t digest[SHA256_DIGEST_SIZE];
    const uint64_t t0 = time_us_64();
    (void)sd_blob_begin(w, &g_sd_log);
    const uint32_t n = exfat_model_snapshot_write(&g_exfat, sd_blob_put, w, digest);
    const bool ok = sd_blob_end(w) && w->bytes == n;
    const uint64_t us = time_us_64() - t0;
    g_model_save_us_max = us > g_model_save_us_max ? us : g_model_save_us_max;
    if (!ok) {
        g_model_save_fails++;
        tap_printf("[model] volume %08lx: model NOT saved (%s): the card failed after %lu of its blocks\n",
               (unsigned long)g_exfat.serial, when, (unsigned long)w->number);
        return;
    }
    audit_log_model(&g_log, (time_us_64() - g_capture.start_us) * 1000u, AUDIT_MODEL_SAVED, 0u, 0u, w->first,
                    g_exfat.serial, digest);
    model_index_note(g_exfat.serial, w->first, digest);   /* the newest, if the drive comes back this session */
    sd_make_room();
    g_model_saves++;
    g_model_last_bytes  = n;
    g_model_last_blocks = w->number;
    char dhex[33];
    hex16(digest, dhex);
    tap_printf("[model] volume %08lx: model saved (%s), %lu bytes in blocks %lu..%lu, %.0f ms; digest %s...\n",
           (unsigned long)g_exfat.serial, when, (unsigned long)n, (unsigned long)w->first,
           (unsigned long)(w->first + w->number - 1u), (double)us / 1000.0, dhex);
}

/* Saves the model once the drive has gone and the link is empty, then waits for the next boot
 * sector. */
static void model_tick(void)
{
    if (!g_model_save_due || meta_link_used(&g_meta_link) != 0u) {
        return;
    }
    g_model_save_due = false;
    model_save("the drive went away");
    exfat_model_unconfirm(&g_exfat);
    meta_clear_interest(&g_meta_link);
    g_exfat_interest_sent = false;
}

/* Prints the [model] line: volumes known, saves, loads and refusals. */
static void print_model_stats(void)
{
    uint32_t n = 0;
    for (uint32_t i = 0; i < MODEL_INDEX; i++) {
        n += g_model_index[i].used ? 1u : 0u;
    }
    tap_printf("[model] %s; volumes with a model on the card at boot %lu; saved %llu (last %lu bytes, %lu blocks;"
           " longest %.0f ms), not saved %llu; loaded %llu (longest %.0f ms), refused %llu (must be 0)\n",
           !g_exfat.have_volume ? "no volume" : g_exfat.volume_confirmed ? "volume confirmed by its boot sector"
                                                                         : "volume remembered, awaiting its boot sector",
           (unsigned long)n, (unsigned long long)g_model_saves, (unsigned long)g_model_last_bytes,
           (unsigned long)g_model_last_blocks, (double)g_model_save_us_max / 1000.0,
           (unsigned long long)g_model_save_fails, (unsigned long long)g_model_loads,
           (double)g_model_load_us_max / 1000.0, (unsigned long long)g_model_refusals);
}
