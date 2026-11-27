/*
 * The SD card glue: sectors routed to the card, decoding held back for it, the [sd] stats, and the
 * read-back at a session's end. Part of USBLogger.c (#included; parts in order: sd, names, stats).
 */

/* Gives the card log's state as the [sd] line prints it. */
static const char *sd_state_name(sd_log_state_t st)
{
    switch (st) {
    case SD_LOG_WAITING: return "WAITING (not opened yet)";
    case SD_LOG_OPEN:    return "OPEN";
    case SD_LOG_FULL:    return "FULL";
    case SD_LOG_OFF:     return "OFF";
    default:             return "?";
    }
}

/* Sectors' worth of SD FIFO room below which decoding waits, the copies held in the link (only
 * while it is under half full). */
#define DECODE_WAIT_SECTORS 16u
/* Says whether core0's decoding waits for the card now, and counts and times the waits. */
static bool decode_waits_for_card(void)
{
    const bool wait = g_sd_log.state == SD_LOG_OPEN &&
                      SD_FIFO_BYTES - store_fifo_held(&g_sd_fifo) <
                          SD_SECTOR_RESERVE + DECODE_WAIT_SECTORS * (STORE_RAM_HEADER_BYTES + 8u + META_SECTOR_BYTES) &&
                      meta_link_used(&g_meta_link) < META_LINK_WORDS / 2u;
    const uint64_t now = time_us_64();
    if (wait && g_decode_wait_since_us == 0u) {
        g_decode_waits++;
        g_decode_wait_since_us = now;
    } else if (!wait && g_decode_wait_since_us != 0u) {
        g_decode_wait_us += now - g_decode_wait_since_us;
        g_decode_wait_since_us = 0u;
    }
    return wait;
}

/* FNV-1a over a sector item (its length, then its bytes), chained from `h`; the read-back
 * recomputes it. */
static uint64_t sector_item_hash(uint64_t h, const uint8_t *data, uint32_t len)
{
    h = (h ^ len) * 0x100000001B3ull;
    for (uint32_t i = 0; i < len; i++) {
        h = (h ^ data[i]) * 0x100000001B3ull;
    }
    return h;
}

/* Passes a metadata sector to the SD FIFO unless that would eat the room kept for records; counts and hashes what it gives. */
static bool sd_sector_write(void *ctx, store_item_t kind, const uint8_t *data, uint32_t len)
{
    (void)ctx;
    if (SD_FIFO_BYTES - store_fifo_held(&g_sd_fifo) < SD_SECTOR_RESERVE + STORE_RAM_HEADER_BYTES + len ||
        !g_sd_fifo_b.write(g_sd_fifo_b.ctx, kind, data, len)) {
        g_sd_sectors_refused++;
        return false;
    }
    g_sd_sectors_given++;
    g_sd_sectors_hash = sector_item_hash(g_sd_sectors_hash, data, len);
    return true;
}

/* Prints the [sd] lines: blocks, write timings, records lost, and the metadata sectors. */
static void print_sd_stats(void)
{
    const sd_log_t *const l = &g_sd_log;
    tap_printf("[sd]    %s: blocks written %llu (%llu partly filled), next block %lu of %lu (%lu part(s)), %lu free;"
           " write errors %llu;"
           " records lost %llu (must be 0); core0 per block write max %.2f ms, mean %.2f ms; card busy:"
           " longest seen %.2f ms, %llu probes found it busy; sd-fifo high-water %lu of %u bytes, pumped"
           " during a decode to make room %llu\n"
           "[sd]    metadata sectors: given %llu, written %llu (%llu all zero), lost %llu (must be 0), refused"
           " to keep room for records %llu (must be 0); decoding waited for the card %llu times, %.1f ms\n",
           sd_state_name(l->state), (unsigned long long)l->blocks_written,
           (unsigned long long)l->partial_blocks, (unsigned long)l->next, (unsigned long)(l->parts * l->blocks),
           (unsigned long)l->parts, (unsigned long)sd_log_blocks_free(l),
           (unsigned long long)l->write_errors, (unsigned long long)l->records_lost,
           (double)g_sd_info.write_us_max / 1000.0,
           l->blocks_written ? (double)g_sd_info.write_us_total / 1000.0 / (double)l->blocks_written : 0.0,
           (double)g_sd_info.busy_us_max / 1000.0, (unsigned long long)g_sd_info.busy_probes,
           (unsigned long)g_sd_fifo.high_water, (unsigned)SD_FIFO_BYTES,
           (unsigned long long)g_sd_pumped_in_decode,
           (unsigned long long)g_sd_sectors_given, (unsigned long long)l->sectors_written,
           (unsigned long long)l->sectors_zero, (unsigned long long)l->sectors_lost,
           (unsigned long long)g_sd_sectors_refused, (unsigned long long)g_decode_waits,
           (double)g_decode_wait_us / 1000.0);
}

/* The read-back of this session's records: the chain re-derived from the card must reach the
 * console's head. */
typedef struct {
    uint8_t  prev[SHA256_DIGEST_SIZE];
    uint64_t n;           /* records of this session, in an unbroken chain */
    uint64_t other;       /* records of another session (must be 0: one session per boot) */
    bool     broken;
    uint64_t broken_seq;
} sd_check_t;

/* Re-derives this session's chain from one record read back off the card. */
static bool sd_check_visit(void *vctx, const uint8_t *data, uint32_t len)
{
    sd_check_t *const c = vctx;
    static audit_record_t rec;
    static uint8_t h[SHA256_DIGEST_SIZE];
    if (len != sizeof(rec)) {
        c->broken = true;
        return false;
    }
    memcpy(&rec, data, sizeof(rec));
    if (rec.body.session_id != g_log.session_id) {
        c->other++;
        return true;
    }
    if (c->broken) {
        return true;
    }
    audit_record_hash(g_log.key, c->prev, &rec.body, h);
    if (rec.body.seq != c->n || memcmp(h, rec.hash, SHA256_DIGEST_SIZE) != 0) {
        c->broken = true;
        c->broken_seq = rec.body.seq;
        return true;
    }
    memcpy(c->prev, h, SHA256_DIGEST_SIZE);
    c->n++;
    return true;
}

/* The sectors read back, counted and hashed as they were given. */
typedef struct {
    uint64_t n;
    uint64_t hash;
} sd_sector_check_t;

/* Counts and hashes one sector read back off the card. */
static bool sd_sector_visit(void *vctx, const uint8_t *data, uint32_t len)
{
    sd_sector_check_t *const c = vctx;
    c->n++;
    c->hash = sector_item_hash(c->hash, data, len);
    return true;
}

/* True when this session's records on the card re-derive to the console's head: the card holds them
 * all. */
static bool sd_read_back(void)
{
    print_sd_stats();
    if (g_sd_log.state != SD_LOG_OPEN && g_sd_log.state != SD_LOG_FULL) {
        tap_printf("[sd]    no read-back: the card was not in use (%s)\n", g_sd_info.why);
        return false;
    }
    static sd_check_t c;
    memset(&c, 0, sizeof(c));
    memcpy(c.prev, g_log.genesis, SHA256_DIGEST_SIZE);   /* this session's first record follows it */
    const uint64_t t0 = time_us_64();
    const bool walked = g_sd_b.for_each(g_sd_b.ctx, STORE_ITEM_AUDIT_RECORD, sd_check_visit, &c);
    const bool same = walked && !c.broken && c.other == 0u && c.n == g_log.records &&
                      memcmp(c.prev, g_log.prev_hash, SHA256_DIGEST_SIZE) == 0;
    tap_printf("[sd]    read back from the card (blocks %lu..%lu, %.0f ms): %llu of %llu records of this session"
           " in an unbroken chain%s; head %s -- %s\n",
           (unsigned long)g_sd_log.boot_first, (unsigned long)(g_sd_log.next - 1u),
           (double)(time_us_64() - t0) / 1000.0, (unsigned long long)c.n,
           (unsigned long long)g_log.records, c.other ? " (and records of ANOTHER session)" : "",
           same ? "the same as the console's" : "DIFFERENT from the console's",
           same ? "CARD LOG COMPLETE" : (!walked ? "a block could not be read back or was invalid"
                                                 : c.broken ? "chain broken on the card" : "records missing"));
    if (c.broken) {
        tap_printf("[sd]    the chain breaks at seq %llu\n", (unsigned long long)c.broken_seq);
    }

    static sd_sector_check_t sc;
    memset(&sc, 0, sizeof(sc));
    const uint64_t t1 = time_us_64();
    const bool swalked = g_sd_b.for_each(g_sd_b.ctx, STORE_ITEM_METADATA_SECTOR, sd_sector_visit, &sc);
    const bool ssame = swalked && sc.n == g_sd_sectors_given && sc.hash == g_sd_sectors_hash;
    tap_printf("[sd]    sectors read back (%.0f ms): %llu of %llu given, contents %s -- %s\n",
           (double)(time_us_64() - t1) / 1000.0, (unsigned long long)sc.n,
           (unsigned long long)g_sd_sectors_given,
           sc.hash == g_sd_sectors_hash ? "identical" : "DIFFERENT",
           ssame ? "CARD SECTORS COMPLETE" : (!swalked ? "a block could not be read back or was invalid"
                                                       : "sectors missing or changed"));
    return same;
}


/* Feeds records to the SD card, and writes a partly filled block after 1 s. */
static void sd_pump(void)
{
    store_fifo_pump(&g_sd_fifo, SD_PUMP_ITEMS);
    sd_log_tick(&g_sd_log, time_us_64());
}

/* How long the drive must go without a READ or WRITE before a full card turns it off. */
#define CARD_FULL_QUIET_US 2000000u

/* Turns the drive off once the log is in its reserve: when no READ or WRITE has come for a while (not
 * mid-copy), or at once with half the reserve used. */
static void card_full_tick(uint64_t now_us)
{
    if (!g_drive_power || (g_sd_log.state != SD_LOG_OPEN && g_sd_log.state != SD_LOG_FULL)) {
        return;
    }
    const uint32_t left = sd_log_blocks_free(&g_sd_log);
    if (left > SD_LOG_RESERVE_BLOCKS ||
        (left > SD_LOG_RESERVE_BLOCKS / 2u && now_us - g_last_io_us < CARD_FULL_QUIET_US)) {
        return;
    }
    g_card_full = true;
    drive_power(false, AUDIT_POWER_CARD_FULL);
    led_set(LED_FAULT);
    tap_printf("[relay] drive power OFF: the card's log is full (%lu blocks left, kept to close the session);"
               " copy the log off the card, delete it and give the card a card_password.txt\n", (unsigned long)left);
}

/* Pumps the SD FIFO inside the metadata decode once it is over half full; below that, nothing. */
static void sd_make_room(void)
{
    if (store_fifo_held(&g_sd_fifo) > SD_FIFO_BYTES / 2u) {
        g_sd_pumped_in_decode++;
        sd_log_tick(&g_sd_log, time_us_64());   /* a staged sector holds the FIFO */
        store_fifo_pump(&g_sd_fifo, SD_PUMP_ITEMS);
    }
}

/* Routes a metadata sector to the card (its FIFO keeps it while the card opens), or to the console
 * without one. */
static bool sector_route_write(void *ctx, store_item_t kind, const uint8_t *data, uint32_t len)
{
    (void)ctx;
    if (g_sd_log.state != SD_LOG_OFF) {
        return sd_sector_write(NULL, kind, data, len);
    }
#if !TAP_DEBUG
    g_sectors_console_refused++;   /* no card and no console: nowhere to keep it */
    return false;
#endif
    if (!g_console_fifo_b.write(g_console_fifo_b.ctx, kind, data, len)) {
        g_sectors_console_refused++;
        return false;
    }
    g_sectors_to_console++;
    return true;
}

/* The console FIFO's target: records print as AUD lines, sectors (without a card) as SEC lines. */
static bool console_any_write(void *ctx, store_item_t kind, const uint8_t *data, uint32_t len)
{
    (void)ctx;
    if (kind == STORE_ITEM_METADATA_SECTOR) {
        return sector_console_write(NULL, kind, data, len);
    }
    return g_console.write(g_console.ctx, kind, data, len);
}
