/*
 * Metadata sectors and file names: sectors fed to the exFAT model, its events as FILE records, the
 * directory check, and reads and writes summed per file. Part of USBLogger.c (#included).
 */

/* ---- metadata sectors (core0) ---------------------------------------- */

/* Prints a sector item as a SEC line (without a card): its LBA, then its bytes less the trailing
 * zeros. */
static bool sector_console_write(void *ctx, store_item_t kind, const uint8_t *data, uint32_t len)
{
    (void)ctx;
    if (kind != STORE_ITEM_METADATA_SECTOR || len < 8u || len > 8u + META_SECTOR_BYTES) {
        return false;
    }
    uint64_t lba = 0;
    for (int i = 7; i >= 0; i--) {
        lba = (lba << 8) | data[i];
    }
    if (len == 8u) {
        tap_printf("SEC|%llu|zero\n", (unsigned long long)lba);
        return true;
    }
    static const char digits[] = "0123456789abcdef";
    static char hex[2u * META_SECTOR_BYTES + 1u];
    for (uint32_t i = 0; i < META_SECTOR_BYTES; i++) {
        const uint8_t v = 8u + i < len ? data[8u + i] : 0u;   /* trailing zeros left off */
        hex[2u * i]      = digits[v >> 4];
        hex[2u * i + 1u] = digits[v & 0x0Fu];
    }
    hex[2u * META_SECTOR_BYTES] = '\0';
    tap_printf("SEC|%llu|%s\n", (unsigned long long)lba, hex);
    return true;
}

/* Sectors already printed, so each distinct content is printed once (the directory is rewritten
 * often). */
#define SEEN_SECTORS 256u   /* a repeat beyond it is only printed again */
/* One sector already printed: where, and a hash of what it held. */
typedef struct {
    uint64_t lba;
    uint64_t hash;   /* 64-bit multiply-xorshift hash of the sector */
} seen_sector_t;
/* The sectors printed, a ring of SEEN_SECTORS, and where the next goes. */
static seen_sector_t g_seen_sectors[SEEN_SECTORS];
static uint32_t      g_seen_used, g_seen_next;

/* Checks whether this sector was printed with this content; if not, remembers it. */
static bool sector_seen_before(uint64_t lba, uint64_t hash)
{
    for (uint32_t i = 0; i < g_seen_used; i++) {
        if (g_seen_sectors[i].lba == lba && g_seen_sectors[i].hash == hash) {
            return true;
        }
    }
    g_seen_sectors[g_seen_next].lba  = lba;
    g_seen_sectors[g_seen_next].hash = hash;
    g_seen_next = (g_seen_next + 1u) % SEEN_SECTORS;
    if (g_seen_used < SEEN_SECTORS) {
        g_seen_used++;
    }
    return false;
}

/* Forgets a sector remembered by sector_seen_before. */
static void sector_seen_forget(uint64_t lba, uint64_t hash)
{
    for (uint32_t i = 0; i < g_seen_used; i++) {
        if (g_seen_sectors[i].lba == lba && g_seen_sectors[i].hash == hash) {
            g_seen_sectors[i].lba = UINT64_MAX;   /* no sector has this LBA */
        }
    }
}

/* The command whose sectors feed the model: FILE records carry its CBW time and tag, linking them
 * to its SCSI record. */
static uint64_t g_names_ts;
static uint32_t g_names_tag;   /* its CBW tag */

/* The model's event numbers are the FILE_EVENT record's ops. */
_Static_assert(AUDIT_FILE_UNRELIABLE > EXFAT_EV_CREATE_FILLED,
               "AUDIT_FILE_UNRELIABLE is not an exFAT model event number");
_Static_assert(EXFAT_EV_VOLUME == AUDIT_FILE_VOLUME && EXFAT_EV_EXISTING == AUDIT_FILE_EXISTING &&
               EXFAT_EV_CREATE == AUDIT_FILE_CREATE && EXFAT_EV_DELETE == AUDIT_FILE_DELETE &&
               EXFAT_EV_RENAME == AUDIT_FILE_RENAME && EXFAT_EV_MODIFY == AUDIT_FILE_MODIFY &&
               EXFAT_EV_CREATE_FILLED == AUDIT_FILE_CREATED,
               "audit FILE_EVENT op numbers follow exfat_event_type_t");

/* Puts the event into the hash-chained audit log. */
static void names_audit(const exfat_event_t *e)
{
    audit_file_event_t a;
    memset(&a, 0, sizeof(a));
    a.event      = (uint8_t)e->type;
    a.from_write = e->from_write;
    if (e->type == EXFAT_EV_VOLUME) {
        a.lba           = e->boot_lba;
        a.serial        = e->serial;
        a.heap_offset   = (uint32_t)(e->heap_lba - e->boot_lba);
        a.root_cluster  = e->root_cluster;
        a.cluster_shift = (uint8_t)__builtin_ctz(e->sectors_per_cluster);
        a.boot_checked  = e->boot_checksum_checked;
        a.boot_ok       = e->boot_checksum_ok;
    } else {
        a.directory     = e->directory;
        a.lba           = e->lba;
        a.index         = (uint8_t)e->index;
        a.first_cluster = e->first_cluster;
        a.size          = e->size;
        a.have_before   = e->type == EXFAT_EV_DELETE || e->type == EXFAT_EV_RENAME ||
                          e->type == EXFAT_EV_MODIFY || e->type == EXFAT_EV_CREATE_FILLED;
        a.old_first_cluster = e->old_first_cluster;
        a.old_size      = e->old_size;
        a.name          = e->name;
        a.old_name      = e->type == EXFAT_EV_RENAME ? e->old_name : NULL;
    }
    audit_log_file_event(&g_log, g_names_ts, g_names_tag, &a);
    sd_make_room();
}

/* Logs and prints one model event (defined below). */
static void on_names_event_body(const exfat_event_t *e);

/* Timed, to split the model's cycles from its events' (printing and a hashed record each). */
static void on_names_event(const exfat_event_t *e, void *ctx)
{
    (void)ctx;
    const uint32_t t0 = usb_cycles();
    on_names_event_body(e);
    g_names_cyc += (uint32_t)(usb_cycles() - t0);
}

/* Logs one model event as FILE records and prints it as a [names] line. */
static void on_names_event_body(const exfat_event_t *e)
{
    names_audit(e);
    const char *const kind = e->directory ? "directory" : "file";
    const char *const seen = e->from_write ? "" : " -- seen in a READ: changed where the tap did not see it";
    switch (e->type) {
    case EXFAT_EV_VOLUME:
        tap_printf("[names] VOLUME exFAT serial %08lx, boot LBA %llu, cluster heap LBA %llu, %lu sectors per"
               " cluster, root directory cluster %lu; boot checksum %s\n",
               (unsigned long)e->serial, (unsigned long long)e->boot_lba,
               (unsigned long long)e->heap_lba, (unsigned long)e->sectors_per_cluster,
               (unsigned long)e->root_cluster,
               e->boot_checksum_checked ? (e->boot_checksum_ok ? "ok" : "WRONG")
                                        : "not checked (boot region not read in one transfer)");
        model_on_volume(e->serial);
        break;
    case EXFAT_EV_EXISTING:
        tap_printf("[names] EXISTING %s \"%s\" cluster %lu size %llu (LBA %llu entry %lu)\n", kind, e->name,
               (unsigned long)e->first_cluster, (unsigned long long)e->size,
               (unsigned long long)e->lba, (unsigned long)e->index);
        break;
    case EXFAT_EV_CREATE:
        tap_printf("[names] CREATE %s \"%s\" cluster %lu size %llu (LBA %llu entry %lu)%s\n", kind, e->name,
               (unsigned long)e->first_cluster, (unsigned long long)e->size,
               (unsigned long long)e->lba, (unsigned long)e->index, seen);
        break;
    case EXFAT_EV_DELETE:
        tap_printf("[names] DELETE %s \"%s\" (was cluster %lu size %llu, LBA %llu entry %lu)%s\n", kind,
               e->name, (unsigned long)e->old_first_cluster, (unsigned long long)e->old_size,
               (unsigned long long)e->lba, (unsigned long)e->index, seen);
        break;
    case EXFAT_EV_RENAME:
        tap_printf("[names] RENAME %s \"%s\" -> \"%s\" cluster %lu size %llu (LBA %llu entry %lu)%s\n", kind,
               e->old_name, e->name, (unsigned long)e->first_cluster, (unsigned long long)e->size,
               (unsigned long long)e->lba, (unsigned long)e->index, seen);
        break;
    case EXFAT_EV_CREATE_FILLED:
        tap_printf("[names] CREATE %s \"%s\" completed: data written, cluster %lu size %llu"
               " (LBA %llu entry %lu)%s\n", kind, e->name, (unsigned long)e->first_cluster,
               (unsigned long long)e->size, (unsigned long long)e->lba, (unsigned long)e->index, seen);
        break;
    case EXFAT_EV_MODIFY:
        tap_printf("[names] MODIFY %s \"%s\" size %llu -> %llu, cluster %lu -> %lu (LBA %llu entry %lu)%s\n",
               kind, e->name, (unsigned long long)e->old_size, (unsigned long long)e->size,
               (unsigned long)e->old_first_cluster, (unsigned long)e->first_cluster,
               (unsigned long long)e->lba, (unsigned long)e->index, seen);
        break;
    }
}

/* A directory command whose sectors the model did not get whole: a WRITE warns and is sealed in the
 * chain; a READ is counted. */
static void on_expect(meta_expect_outcome_t outcome, const meta_expect_item_t *c,
                      const meta_expect_item_t *r, void *ctx)
{
    (void)ctx;
    if (!c->write) {
        g_dir_reads_missed++;
        return;
    }
    g_dir_writes_unreliable++;
    static char path[EXFAT_PATH_UTF8];
    if (!exfat_model_directory_path(&g_exfat, c->lba, path, sizeof(path))) {
        snprintf(path, sizeof(path), "?");
    } else if (path[0] == '\0') {
        snprintf(path, sizeof(path), "\\");
    }
    if (outcome == META_EXPECT_MISSING) {
        tap_printf("[names] WARNING: directory \"%s\" WRITE LBA %llu-%llu (tag %08lx) was not decoded at all"
               " (its copy was dropped or never made): a change there may be missing from the names\n",
               path, (unsigned long long)c->lba, (unsigned long long)(c->lba + c->blocks - 1u),
               (unsigned long)c->tag);
    } else if (r && r->bytes == c->blocks * META_SECTOR_BYTES) {
        /* Every byte, but no status: the drive's CSW fell in a gap, so the WRITE's success is
         * unknown. */
        tap_printf("[names] WARNING: directory \"%s\" WRITE LBA %llu-%llu (tag %08lx): all %lu bytes decoded"
               " but its status (CSW) was not: a change there may be missing from the names\n",
               path, (unsigned long long)c->lba, (unsigned long long)(c->lba + c->blocks - 1u),
               (unsigned long)c->tag, (unsigned long)r->bytes);
    } else {
        tap_printf("[names] WARNING: directory \"%s\" WRITE LBA %llu-%llu (tag %08lx) was decoded only in part"
               " (%lu of %lu bytes): a change there may be missing from the names\n",
               path, (unsigned long long)c->lba, (unsigned long long)(c->lba + c->blocks - 1u),
               (unsigned long)c->tag, (unsigned long)(r ? r->bytes : 0u),
               (unsigned long)(c->blocks * META_SECTOR_BYTES));
    }
    audit_file_event_t a;
    memset(&a, 0, sizeof(a));
    a.event      = AUDIT_FILE_UNRELIABLE;
    a.from_write = true;
    a.directory  = true;
    a.lba        = c->lba;
    a.blocks     = c->blocks;
    a.bytes      = r ? r->bytes : 0u;
    a.missing    = outcome == META_EXPECT_MISSING;
    a.name       = path;
    audit_log_file_event(&g_log, c->ts_ns, c->tag, &a);
    sd_make_room();
}

/* Once the volume is confirmed, and when its directories change, core1 copies only transfers
 * overlapping a directory extent. */
static void update_interest(void)
{
    if (!g_exfat.have_volume || !g_exfat.volume_confirmed ||
        (g_exfat_interest_sent && g_exfat.dirs_version == g_exfat_dirs_sent &&
         g_exfat.heap_lba == g_exfat_heap_sent && g_exfat.serial == g_exfat_serial_sent)) {
        return;
    }
    static uint64_t lba[META_MAX_RANGES];
    static uint32_t sectors[META_MAX_RANGES];
    const uint32_t n = exfat_model_directory_ranges(&g_exfat, lba, sectors, META_MAX_RANGES);
    meta_set_interest(&g_meta_link, lba, sectors, n);
    g_exfat_dirs_sent     = g_exfat.dirs_version;
    g_exfat_heap_sent     = g_exfat.heap_lba;
    g_exfat_serial_sent   = g_exfat.serial;
    g_exfat_interest_sent = true;
    tap_printf("[names] core1 now copies only transfers in %lu directory extent(s)\n", (unsigned long)n);
}

/* Takes one decoded transfer: checks it off for the directory check and feeds it to the model if whole. */
static void on_meta_result(const meta_result_t *r, void *ctx)
{
    (void)ctx;
    /* Complete transfers print no line each (hundreds of lines in the decode call); only incomplete
     * ones do. */
    if (!(r->flags & META_COMPLETE))
    tap_printf("[meta]  %s lba=%llu blocks=%lu bytes=%lu of %lu packets=%lu dup=%lu bad=%lu csw=%d%s%s%s%s%s tag=%08lx\n",
           r->write ? "WRITE" : "READ", (unsigned long long)r->lba, (unsigned long)r->blocks,
           (unsigned long)r->bytes, (unsigned long)r->data_len, (unsigned long)r->packets,
           (unsigned long)r->dup_packets, (unsigned long)r->bad_packets, (int)r->status,
           (r->flags & META_COMPLETE) ? " complete" : "",
           (r->flags & META_NO_CSW)   ? " no-csw" : "",
           (r->flags & META_SHORT)    ? " short" : "",
           (r->flags & META_FAILED)   ? " failed" : "",
           (r->flags & META_OVERLONG) ? " overlong" : "", (unsigned long)r->tag);
    const uint32_t expect_t0 = usb_cycles();
    meta_expect_result(&g_expect, r->ts_ns, r->tag, r->write, r->lba, r->blocks,
                       (r->flags & META_COMPLETE) != 0u, r->bytes);
    g_expect_cyc += (uint32_t)(usb_cycles() - expect_t0);
    if (!(r->flags & META_COMPLETE)) {
        return;
    }
    g_names_ts  = r->ts_ns;
    g_names_tag = r->tag;
    model_before_feed(r->lba, r->data, r->blocks);   /* another volume's boot sector: its model from the card */
    const uint64_t changes_full_before = g_exfat.changes_full;   /* after it: a load resets the counters */
    const uint32_t model_t0 = usb_cycles();
    exfat_model_feed(&g_exfat, r->lba, r->data, r->blocks, r->write);
    g_model_cyc += (uint32_t)(usb_cycles() - model_t0);
    if (g_exfat.changes_full != changes_full_before) {
        /* More changes in one transfer than the model pairs (EXFAT_MAX_CHANGES): the rest were not
         * reported, so it is said. */
        const uint64_t lost = g_exfat.changes_full - changes_full_before;
        g_names_changes_lost += lost;
        static char path[EXFAT_PATH_UTF8];
        if (!exfat_model_directory_path(&g_exfat, r->lba, path, sizeof(path))) {
            snprintf(path, sizeof(path), "?");
        } else if (path[0] == '\0') {
            snprintf(path, sizeof(path), "\\");
        }
        tap_printf("[names] WARNING: directory \"%s\" %s LBA %llu-%llu (tag %08lx) holds more than %u creations or"
               " deletions: %llu of them not reported\n",
               path, r->write ? "WRITE" : "READ", (unsigned long long)r->lba,
               (unsigned long long)(r->lba + r->blocks - 1u), (unsigned long)r->tag,
               (unsigned)EXFAT_MAX_CHANGES, (unsigned long long)lost);
        audit_file_event_t a;
        memset(&a, 0, sizeof(a));
        a.event      = AUDIT_FILE_UNRELIABLE;
        a.from_write = r->write;
        a.directory  = true;
        a.lba        = r->lba;
        a.blocks     = r->blocks;
        a.bytes      = r->bytes;
        a.name       = path;
        audit_log_file_event(&g_log, r->ts_ns, r->tag, &a);
        sd_make_room();
    }
    update_interest();
    const uint32_t sector_t0 = usb_cycles();
    /* One SECTOR record per transfer vouches for the sectors it stores (one per sector cost too
     * many records). */
    static sha256_ctx_t vouch;
    uint64_t vouch_lba = 0;
    uint8_t  vouch_n = 0;
    uint8_t  refused = 0;   /* new sectors the card had no room for: not vouched for */
    audit_sectors_start(&vouch);
    for (uint32_t s = 0; s < r->blocks; s++) {
        const uint8_t *const sec = &r->data[s * META_SECTOR_BYTES];
        const uint64_t lba = r->lba + s;
        /* A 64-bit multiply-xorshift hash, not SHA-256: it only decides whether a sector is stored
         * again. */
        /* 32 bits at a time when the sectors are word-aligned, as they are in practice. */
        uint64_t hash = 0x9E3779B97F4A7C15ull ^ lba;
        if (((uintptr_t)sec & 3u) == 0u) {
            const uint32_t *const w32 = (const uint32_t *)(const void *)sec;
            for (uint32_t i = 0; i < META_SECTOR_BYTES / 4u; i += 2u) {
                hash ^= (uint64_t)w32[i] | ((uint64_t)w32[i + 1u] << 32);
                hash *= 0xBF58476D1CE4E5B9ull;
                hash ^= hash >> 31;
            }
        } else {
            for (uint32_t i = 0; i < META_SECTOR_BYTES; i += 8u) {
                uint64_t w = 0;
                for (uint32_t k = 0; k < 8u; k++) {
                    w |= (uint64_t)sec[i + k] << (8u * k);
                }
                hash ^= w;
                hash *= 0xBF58476D1CE4E5B9ull;
                hash ^= hash >> 31;
            }
        }
        if (sector_seen_before(lba, hash)) {
            g_sectors_repeated++;
            continue;
        }
        g_sectors_new++;

        /* Static, as `vouch` is: 776 bytes off core0's deepest call chain (never re-entered). */
        static uint8_t item[8u + META_SECTOR_BYTES];
        for (int i = 0; i < 8; i++) {
            item[i] = (uint8_t)(lba >> (8 * i));
        }
        /* The sector without its trailing zero bytes (an all-zero one is the LBA alone). */
        uint32_t used = META_SECTOR_BYTES;
        while (used != 0u && sec[used - 1u] == 0u) {
            used--;
        }
        memcpy(&item[8], sec, used);
        const uint32_t item_len = 8u + used;
        if (!store_write(&g_sector_store, STORE_ITEM_METADATA_SECTOR, item, item_len)) {
            sector_seen_forget(lba, hash);   /* so a later read of it is stored */
            refused++;
            continue;
        }
        if (vouch_n++ == 0u) {
            vouch_lba = lba;
        }
        audit_sectors_add(&vouch, lba, sec);
        sd_make_room();
    }
    if (vouch_n != 0u || refused != 0u) {
        uint8_t digest[16];
        audit_sectors_end(&vouch, digest);
        audit_log_sectors(&g_log, r->ts_ns, vouch_lba, vouch_n, digest, r->write, refused);
    }
    g_sector_cyc += (uint32_t)(usb_cycles() - sector_t0);
}

/* on_meta_result, timed, to separate handling results from decoding in the [meta] line. */
static void on_meta_result_timed(const meta_result_t *r, void *ctx)
{
    const uint64_t t0 = time_us_64();
    on_meta_result(r, ctx);
    g_meta_result_us += time_us_64() - t0;
}

/* ---- which file a READ or WRITE touched (core0) ---------------------- */

/* Consecutive READs or WRITEs form runs, named a few seconds after they end (a new file's entry
 * comes after its data). */
#define IO_RUNS         32u
#define IO_RUN_IDLE_US  1000000u    /* a run with no new command for 1 s is closed */
#define IO_RUN_NAME_US  3000000u    /* and named 3 s after its last command */

/* One run of consecutive READs or WRITEs: its LBA range, commands and when it was last extended. */
typedef struct {
    bool     write;
    uint64_t first;
    uint64_t end;
    uint32_t commands;
    uint64_t last_us;
} io_run_t;

/* The run being extended, and the closed runs waiting to be named. */
static io_run_t g_open_run;
static bool     g_open_run_valid;
static io_run_t g_runs[IO_RUNS];
static uint32_t g_runs_n;

/* Named runs are gathered per file (or area) and printed once that file has gone quiet for
 * IO_GROUP_IDLE_US. */
#define IO_GROUPS        8u
#define IO_GROUP_IDLE_US 5000000u
#define GROUP_FILE       0u
#define GROUP_DIRECTORY  1u
#define GROUP_UNKNOWN    255u      /* else GROUP_AREA + exfat_area_t */
#define GROUP_AREA       2u

/* The runs of one file (or area) gathered for one [names] line. */
typedef struct {
    bool     used;
    bool     write;
    uint8_t  kind;
    char     name[256];
    uint64_t first;
    uint64_t end;
    uint64_t blocks;
    uint32_t commands;
    uint32_t runs;
    uint64_t last_us;
} io_group_t;

/* The files with runs gathered and not yet printed. */
static io_group_t g_groups[IO_GROUPS];

/* Prints one [names] line: the file or area, READ or WRITE, blocks, commands and LBA range. */
static void print_group(const io_group_t *g)
{
    const char *const op = g->write ? "WRITE" : "READ";
    char label[300];
    if (g->kind == GROUP_FILE || g->kind == GROUP_DIRECTORY) {
        snprintf(label, sizeof(label), "%s \"%s\"", g->kind == GROUP_FILE ? "file" : "directory", g->name);
    } else if (g->kind == GROUP_UNKNOWN) {
        snprintf(label, sizeof(label), "(no file known there)");
    } else {
        snprintf(label, sizeof(label), "exFAT %s", exfat_model_area_name((exfat_area_t)(g->kind - GROUP_AREA)));
    }
    tap_printf("[names] %s %s: %llu blocks in %lu commands, LBA %llu-%llu (%lu run%s)\n", op, label,
           (unsigned long long)g->blocks, (unsigned long)g->commands, (unsigned long long)g->first,
           (unsigned long long)(g->end - 1u), (unsigned long)g->runs, g->runs == 1u ? "" : "s");
}

/* Names the queued runs old enough (or all) into groups, and prints the groups gone quiet (or all). */
static void resolve_runs(uint64_t now, bool all)
{
    static char name[256];
    uint32_t done = 0;
    while (done < g_runs_n && (all || now - g_runs[done].last_us >= IO_RUN_NAME_US)) {
        const io_run_t *const r = &g_runs[done++];
        uint64_t size = 0;
        bool dir = false;
        uint8_t kind;
        if (exfat_model_file_at(&g_exfat, r->first, name, sizeof(name), &size, &dir)) {
            kind = dir ? GROUP_DIRECTORY : GROUP_FILE;
        } else {
            name[0] = '\0';
            const exfat_area_t area = exfat_model_area_at(&g_exfat, r->first);
            if (area == EXFAT_AREA_DIRECTORY) {
                continue;                 /* the [names] events say what changed there */
            }
            if (area == EXFAT_AREA_NONE) {
                if (r->end - r->first <= META_MAX_BLOCKS) {
                    continue;             /* small and unplaced: the SCSI records have it */
                }
                kind = GROUP_UNKNOWN;
            } else {
                kind = (uint8_t)(GROUP_AREA + area);
            }
        }
        io_group_t *g = NULL, *free_slot = NULL, *oldest = NULL;
        for (uint32_t i = 0; i < IO_GROUPS; i++) {
            io_group_t *const c = &g_groups[i];
            if (!c->used) {
                if (free_slot == NULL) {
                    free_slot = c;
                }
                continue;
            }
            if (c->write == r->write && c->kind == kind && strcmp(c->name, name) == 0) {
                g = c;
                break;
            }
            if (oldest == NULL || c->last_us < oldest->last_us) {
                oldest = c;
            }
        }
        if (g == NULL) {
            g = free_slot;
            if (g == NULL) {
                print_group(oldest);      /* table full: the quietest group goes out now */
                g = oldest;
            }
            memset(g, 0, sizeof(*g));
            g->used  = true;
            g->write = r->write;
            g->kind  = kind;
            memcpy(g->name, name, sizeof(g->name));
            g->first = r->first;
            g->end   = r->end;
        }
        if (r->first < g->first) {
            g->first = r->first;
        }
        if (r->end > g->end) {
            g->end = r->end;
        }
        g->blocks   += r->end - r->first;
        g->commands += r->commands;
        g->runs++;
        if (r->last_us > g->last_us) {
            g->last_us = r->last_us;
        }
    }
    if (done != 0u) {
        memmove(g_runs, &g_runs[done], (g_runs_n - done) * sizeof(g_runs[0]));
        g_runs_n -= done;
    }
    for (uint32_t i = 0; i < IO_GROUPS; i++) {
        if (g_groups[i].used &&
            (all || now - g_groups[i].last_us >= IO_RUN_NAME_US + IO_GROUP_IDLE_US)) {
            print_group(&g_groups[i]);
            g_groups[i].used = false;
        }
    }
}

/* Closes the open run and queues it to be named (naming the queue first if it is full). */
static void close_open_run(void)
{
    if (!g_open_run_valid) {
        return;
    }
    g_open_run_valid = false;
    if (g_runs_n == IO_RUNS) {
        resolve_runs(time_us_64(), true);   /* full: name what is queued now */
    }
    g_runs[g_runs_n++] = g_open_run;
}

/* Extends the open run with a READ or WRITE that follows it, or starts a new run. */
static void note_io(const msc_command_t *c)
{
    if ((c->op != MSC_OP_READ && c->op != MSC_OP_WRITE) || !c->lba_valid || c->block_count == 0u) {
        return;
    }
    const bool write = c->op == MSC_OP_WRITE;
    const uint64_t now = time_us_64();
    if (g_open_run_valid && g_open_run.write == write && c->lba == g_open_run.end) {
        g_open_run.end += c->block_count;
        g_open_run.commands++;
        g_open_run.last_us = now;
        return;
    }
    close_open_run();
    g_open_run.write    = write;
    g_open_run.first    = c->lba;
    g_open_run.end      = c->lba + c->block_count;
    g_open_run.commands = 1u;
    g_open_run.last_us  = now;
    g_open_run_valid    = true;
}

/* Closes an idle run and names the runs that are due (`all`: every one, at the end). */
static void names_runs_tick(bool all)
{
    const uint64_t now = time_us_64();
    if (g_open_run_valid && (all || now - g_open_run.last_us >= IO_RUN_IDLE_US)) {
        close_open_run();
    }
    resolve_runs(now, all);
}

/* Notes a READ/WRITE of up to 16 sectors in a tracked directory for the directory check (a failed
 * one changed nothing). */
static void names_expect(const msc_command_t *c)
{
    if ((c->op != MSC_OP_READ && c->op != MSC_OP_WRITE) || !c->lba_valid || c->block_count == 0u ||
        c->block_count > META_MAX_BLOCKS || c->data_len > META_MAX_BYTES ||
        (c->completed && c->status != 0u) ||
        !exfat_model_overlaps_directory(&g_exfat, c->lba, c->block_count)) {
        return;
    }
    meta_expect_command(&g_expect, c->ts_cbw_ns, c->tag, c->op == MSC_OP_WRITE, c->lba, c->block_count,
                        time_us_64());
}
