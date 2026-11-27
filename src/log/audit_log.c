/*
 * The hash-chained audit records: builds each record type, seals it and hands it to the store; also the
 * chain check of the card's records, and the console backend that prints AUD| lines.
 */

/* offsetof, printf for the AUD| lines, memset and memcpy. */
#include <stddef.h>
#include <stdio.h>
#include <string.h>

/* What this file defines, and the bus event codes. */
#include "audit_log.h"
#include "usb_decode.h"

/* Gives a record type's name as the AUD| line prints it ("SCSI", "FILE", ...). */
static const char *rec_type_name(uint8_t type)
{
    switch (type) {
    case AUDIT_REC_SESSION_START: return "SESSION_START";
    case AUDIT_REC_SCSI_COMMAND:  return "SCSI";
    case AUDIT_REC_BUS_EVENT:     return "BUS_EVENT";
    case AUDIT_REC_GAP:           return "GAP";
    case AUDIT_REC_SESSION_END:   return "SESSION_END";
    case AUDIT_REC_FILE_EVENT:    return "FILE";
    case AUDIT_REC_FILE_BEFORE:   return "FILE_BEFORE";
    case AUDIT_REC_FILE_NAME:     return "FILE_NAME";
    case AUDIT_REC_DRIVE_POWER:   return "DRIVE_POWER";
    case AUDIT_REC_CARD_CHECK:    return "CARD_CHECK";
    case AUDIT_REC_SECTOR:        return "SECTOR";
    case AUDIT_REC_MODEL:         return "MODEL";
    case AUDIT_REC_HOST_POWER:    return "HOST_POWER";
    default:                      return "?";
    }
}

/* Gives a file event's name as the AUD| line prints it ("CREATE", "DELETE", ...). */
static const char *file_event_name(uint8_t event)
{
    switch (event) {
    case AUDIT_FILE_VOLUME:   return "VOLUME";
    case AUDIT_FILE_EXISTING: return "EXISTING";
    case AUDIT_FILE_CREATE:   return "CREATE";
    case AUDIT_FILE_DELETE:   return "DELETE";
    case AUDIT_FILE_RENAME:   return "RENAME";
    case AUDIT_FILE_MODIFY:   return "MODIFY";
    case AUDIT_FILE_CREATED:  return "CREATED";
    case AUDIT_FILE_UNRELIABLE: return "UNRELIABLE";
    default:                  return "?";
    }
}

/* The op column: SCSI operation names for commands, event names for files. */
static const char *op_text(uint8_t type, uint8_t op)
{
    if (type == AUDIT_REC_FILE_EVENT || type == AUDIT_REC_FILE_BEFORE || type == AUDIT_REC_FILE_NAME) {
        return file_event_name(op);
    }
    if (type == AUDIT_REC_DRIVE_POWER) {
        return op ? "ON" : "OFF";
    }
    if (type == AUDIT_REC_SECTOR) {
        return op ? "WRITE" : "READ";
    }
    if (type == AUDIT_REC_HOST_POWER) {
        return op ? "PRESENT" : "GONE";
    }
    if (type == AUDIT_REC_MODEL) {
        return op == AUDIT_MODEL_SAVED ? "SAVED" : op == AUDIT_MODEL_LOADED ? "LOADED" : "REFUSED";
    }
    if (type == AUDIT_REC_CARD_CHECK) {
        return op == AUDIT_CHECK_PASS ? "PASS" : op == AUDIT_CHECK_ACCEPT ? "ACCEPT" : "FAIL";
    }
    return msc_op_name((msc_op_t)op);
}

/* The SECTOR digest and FILE_NAME bytes sit where the record layout says. */
_Static_assert(offsetof(audit_body_t, block_count) == 40u && offsetof(audit_body_t, dev_addr) == 56u,
               "SECTOR records carry 16 digest bytes in body bytes 40-55");
_Static_assert(offsetof(audit_body_t, lba) == 32u &&
               offsetof(audit_body_t, dev_addr) - offsetof(audit_body_t, lba) == AUDIT_NAME_CHUNK,
               "FILE_NAME records carry name bytes in body bytes 32-55");

/* Writes a 32-byte hash as 64 lowercase hex digits. */
static void hex32(const uint8_t *h, char out[65])
{
    static const char digits[] = "0123456789abcdef";
    for (int i = 0; i < SHA256_DIGEST_SIZE; i++) {
        out[i * 2]     = digits[h[i] >> 4];
        out[i * 2 + 1] = digits[h[i] & 0x0Fu];
    }
    out[64] = '\0';
}

/* Starts a log for one session, with an all-zero genesis and no key. */
void audit_log_init(audit_log_t *log, uint64_t session_id, store_t *store)
{
    memset(log, 0, sizeof(*log));
    log->session_id = session_id;
    log->store = store;
    /* The genesis stays zero until set; SESSION_START binds the chain to the session. */
}

/* Sets the chain key, so records are sealed with HMAC-SHA256 (version 2). */
void audit_log_set_key(audit_log_t *log, const hmac_sha256_key_t *key)
{
    log->key = key;
}

/* Makes the chain follow `head`, the card's last hash, so sessions are linked. */
void audit_log_set_genesis(audit_log_t *log, const uint8_t head[SHA256_DIGEST_SIZE])
{
    memcpy(log->genesis, head, SHA256_DIGEST_SIZE);
    memcpy(log->prev_hash, head, SHA256_DIGEST_SIZE);
}

/* Derives the chain key from the log key: HMAC(log key, "usbtap chain v1"). */
void audit_chain_key(hmac_sha256_key_t *k, const uint8_t log_key[32])
{
    hmac_sha256_key_t m;
    uint8_t derived[SHA256_DIGEST_SIZE];
    static const char label[] = "usbtap chain v1";
    hmac_sha256_key(&m, log_key, 32);
    hmac_sha256(&m, label, sizeof(label) - 1u, derived);
    hmac_sha256_key(k, derived, sizeof(derived));
    memset(derived, 0, sizeof(derived));
    memset(&m, 0, sizeof(m));
}

/* Gives a key's id for the banner: the first 4 bytes of HMAC(key, "key id"), not the key. */
uint32_t audit_key_id(const hmac_sha256_key_t *k)
{
    uint8_t h[SHA256_DIGEST_SIZE];
    hmac_sha256(k, "key id", 6u, h);
    return ((uint32_t)h[0] << 24) | ((uint32_t)h[1] << 16) | ((uint32_t)h[2] << 8) | h[3];
}

/* Computes a record's hash from the previous one and its body, keyed or plain. */
void audit_record_hash(const hmac_sha256_key_t *key, const uint8_t prev[SHA256_DIGEST_SIZE],
                       const audit_body_t *body, uint8_t out[SHA256_DIGEST_SIZE])
{
    static sha256_ctx_t ctx;   /* static: see append */
    if (key != NULL) {
        hmac_sha256_start(key, &ctx);
    } else {
        sha256_init(&ctx);
    }
    sha256_update(&ctx, prev, SHA256_DIGEST_SIZE);
    sha256_update(&ctx, body, sizeof(*body));
    if (key != NULL) {
        hmac_sha256_finish(key, &ctx, out);
    } else {
        sha256_final(&ctx, out);
    }
}

/* Gives the first 8 bytes of a hash as a number, for SESSION_START's lba. */
uint64_t audit_genesis_tag(const uint8_t head[SHA256_DIGEST_SIZE])
{
    uint64_t v = 0;
    for (int i = 7; i >= 0; i--) {
        v = (v << 8) | head[i];
    }
    return v;
}

/* Writes the chain's current head (the last record's hash) in hex. */
void audit_log_head_hex(const audit_log_t *log, char out[65])
{
    hex32(log->prev_hash, out);
}

/* Seals one record (HMAC-SHA256 with the chain key, or SHA-256 without, over prev_hash || body) and
 * stores it. */
static void append(audit_log_t *log, audit_body_t *body)
{
    body->magic      = AUDIT_MAGIC;
    body->version    = (uint8_t)(log->key != NULL ? AUDIT_VERSION_KEYED : AUDIT_VERSION_PLAIN);
    body->seq        = log->seq++;
    body->session_id = log->session_id;

    if (log->gap_pending) {
        body->flags |= AUDIT_FLAG_AFTER_GAP;
        log->gap_pending = false;
    }

    /* Static, not on the stack: core0 only, never re-entered, at the bottom of its deepest call
     * chain. */
    static audit_record_t rec;
    rec.body = *body;

    audit_record_hash(log->key, log->prev_hash, &rec.body, rec.hash);

    memcpy(log->prev_hash, rec.hash, SHA256_DIGEST_SIZE);
    log->records++;

    /* A backend that cannot take the record counts the failure itself (the [store] line). */
    if (log->store) {
        store_write(log->store, STORE_ITEM_AUDIT_RECORD, (const uint8_t *)&rec,
                    sizeof(rec));
    }
}

/* Logs SESSION_START: the bus speed, the sample rate and the session it follows. */
void audit_log_session_start(audit_log_t *log, uint64_t ts_ns,
                             usb_speed_t speed, uint32_t sample_hz)
{
    audit_body_t b;
    memset(&b, 0, sizeof(b));
    b.type     = AUDIT_REC_SESSION_START;
    b.ts_ns    = ts_ns;
    b.data_len = sample_hz;
    b.aux      = (uint8_t)speed;
    if (log->key != NULL) {
        b.lba = audit_genesis_tag(log->genesis);   /* which session this one follows */
    }
    append(log, &b);
}

/* Logs one SCSI command with its LBA, length, status and flags. */
void audit_log_command(audit_log_t *log, const msc_command_t *cmd)
{
    audit_body_t b;
    memset(&b, 0, sizeof(b));
    b.type        = AUDIT_REC_SCSI_COMMAND;
    b.ts_ns       = cmd->ts_cbw_ns;
    b.lba         = cmd->lba;
    b.block_count = cmd->block_count;
    b.data_len    = cmd->data_len;
    b.residue     = cmd->residue;
    b.tag         = cmd->tag;
    b.dev_addr    = cmd->dev_addr;
    b.endpoint    = cmd->endpoint;
    b.lun         = cmd->lun;
    b.opcode      = cmd->opcode;
    b.op          = (uint8_t)cmd->op;
    b.status      = cmd->status;
    b.aux         = cmd->cdb_flags;

    if (cmd->completed) {
        b.flags |= AUDIT_FLAG_COMPLETED;
    }
    if (cmd->lba_valid) {
        b.flags |= AUDIT_FLAG_LBA_VALID;
    }
    if (cmd->data_in) {
        b.flags |= AUDIT_FLAG_DATA_IN;
    }
    append(log, &b);
}

/* Logs one bus event (a group of `count` of them), with its duration in microseconds. */
void audit_log_bus_event(audit_log_t *log, uint8_t event_code,
                         uint64_t ts_ns, uint64_t duration_ns, uint32_t count)
{
    audit_body_t b;
    memset(&b, 0, sizeof(b));
    b.type        = AUDIT_REC_BUS_EVENT;
    b.ts_ns       = ts_ns;
    b.opcode      = event_code;
    b.data_len    = (uint32_t)(duration_ns / 1000u);
    b.block_count = count ? count : 1u;
    append(log, &b);
}

/* Starts the digest of a transfer's sectors for a SECTOR record. */
void audit_sectors_start(sha256_ctx_t *ctx)
{
    sha256_init(ctx);
}

/* Adds one sector to the digest: its LBA (8 bytes, little-endian), then its 512 bytes. */
void audit_sectors_add(sha256_ctx_t *ctx, uint64_t lba, const uint8_t sector[512])
{
    uint8_t le[8];
    for (int i = 0; i < 8; i++) {
        le[i] = (uint8_t)(lba >> (8 * i));
    }
    sha256_update(ctx, le, sizeof(le));
    sha256_update(ctx, sector, 512u);
}

/* Finishes the digest and keeps its first 16 bytes. */
void audit_sectors_end(sha256_ctx_t *ctx, uint8_t digest[16])
{
    uint8_t h[SHA256_DIGEST_SIZE];
    sha256_final(ctx, h);
    memcpy(digest, h, 16u);
}

/* Logs a SECTOR record vouching for `count` sectors from `lba` stored on the card. */
void audit_log_sectors(audit_log_t *log, uint64_t ts_ns, uint64_t lba, uint8_t count,
                       const uint8_t digest[16], bool from_write, uint8_t refused)
{
    static audit_body_t b;    /* static: see append */
    memset(&b, 0, sizeof(b));
    b.type   = AUDIT_REC_SECTOR;
    b.ts_ns  = ts_ns;
    b.lba    = lba;
    b.aux    = count;
    b.status = refused;
    b.op    = from_write ? 1u : 0u;
    if (from_write) {
        b.flags = AUDIT_FLAG_FROM_WRITE;
    }
    memcpy((uint8_t *)&b + offsetof(audit_body_t, block_count), digest, 16u);   /* bytes 40-55 */
    append(log, &b);
}

/* Logs HOST_POWER: the PC side's VBUS came or went, with the voltages read. */
void audit_log_host_power(audit_log_t *log, uint64_t ts_ns, bool present, uint32_t mv, uint32_t mv_min)
{
    audit_body_t b;
    memset(&b, 0, sizeof(b));
    b.type        = AUDIT_REC_HOST_POWER;
    b.ts_ns       = ts_ns;
    b.op          = present ? 1u : 0u;
    b.data_len    = mv;
    b.block_count = present ? 0u : mv_min;
    append(log, &b);
}

/* Logs a MODEL record: an exFAT model saved or loaded, where, for which volume, and its digest. */
void audit_log_model(audit_log_t *log, uint64_t ts_ns, uint8_t op, uint8_t aux, uint8_t why,
                     uint32_t first_block, uint32_t serial, const uint8_t digest[16])
{
    static audit_body_t b;    /* static: see append */
    memset(&b, 0, sizeof(b));
    b.type   = AUDIT_REC_MODEL;
    b.ts_ns  = ts_ns;
    b.lba    = first_block;
    b.op     = op;
    b.aux    = aux;
    b.status = why;
    memcpy((uint8_t *)&b + offsetof(audit_body_t, block_count), digest, 16u);   /* bytes 40-55 */
    uint8_t *const s = (uint8_t *)&b + offsetof(audit_body_t, dev_addr);       /* bytes 56-59 */
    for (int i = 0; i < 4; i++) {
        s[i] = (uint8_t)(serial >> (8 * i));
    }
    append(log, &b);
}

/* Logs DRIVE_POWER: the relay switched the drive on or off, and why. */
void audit_log_drive_power(audit_log_t *log, uint64_t ts_ns, bool on, uint8_t reason)
{
    audit_body_t b;
    memset(&b, 0, sizeof(b));
    b.type  = AUDIT_REC_DRIVE_POWER;
    b.ts_ns = ts_ns;
    b.op    = on ? 1u : 0u;
    b.aux   = reason;
    append(log, &b);
}

/* Starts a chain check of the card's records with the chain key. */
void audit_chain_check_init(audit_chain_check_t *c, const hmac_sha256_key_t *key)
{
    memset(c, 0, sizeof(*c));
    c->key = key;
}

/* Gives the check the checkpoint's record, which the walk must meet with this hash. */
void audit_chain_check_watch(audit_chain_check_t *c, uint64_t session, uint64_t seq,
                             const uint8_t hash[SHA256_DIGEST_SIZE])
{
    c->watch = true;
    c->watch_session = session;
    c->watch_seq = seq;
    memcpy(c->watch_hash, hash, SHA256_DIGEST_SIZE);
}

/* Marks the chain broken at this record, with the reason, and stops the walk. */
static bool chain_break(audit_chain_check_t *c, const audit_body_t *b, const char *why)
{
    c->broken = true;
    c->broken_session = b->session_id;
    c->broken_seq = b->seq;
    c->why = why;
    return false;
}

/* Checks the card's next record against the chain so far; false stops the walk. */
bool audit_chain_check_visit(void *vctx, const uint8_t *data, uint32_t len)
{
    audit_chain_check_t *const c = vctx;
    static audit_record_t rec;
    static uint8_t h[SHA256_DIGEST_SIZE];
    if (c->broken) {
        return false;
    }
    if (len != sizeof(rec)) {
        memset(&rec, 0, sizeof(rec));
        return chain_break(c, &rec.body, "an item that is not an audit record");
    }
    memcpy(&rec, data, sizeof(rec));
    const bool keyed = rec.body.version == AUDIT_VERSION_KEYED;
    if (rec.body.magic != AUDIT_MAGIC || (!keyed && rec.body.version != AUDIT_VERSION_PLAIN)) {
        return chain_break(c, &rec.body, "a record with the wrong magic or version");
    }
    if (keyed && c->key == NULL) {
        return chain_break(c, &rec.body, "a keyed record, and no key to check it with");
    }
    /* A new session: another id, or a SESSION_START at seq 0 (two sessions can share an id). */
    if (!c->in_session || rec.body.session_id != c->session_id ||
        (rec.body.type == AUDIT_REC_SESSION_START && rec.body.seq == 0u)) {
        if (c->in_session && !c->last_was_end) {
            c->unfinished++;
        }
        if (rec.body.seq != 0u || rec.body.type != AUDIT_REC_SESSION_START) {
            return chain_break(c, &rec.body, "a session that does not start with SESSION_START at seq 0");
        }
        /* A keyed session follows the last hash before it (zero before the first); a plain one
         * starts from zero. */
        if (keyed && rec.body.lba != audit_genesis_tag(c->prev)) {
            return chain_break(c, &rec.body,
                               "a session that does not follow the one before it (a session missing, "
                               "reordered or replaced)");
        }
        if (!keyed) {
            memset(c->prev, 0, sizeof(c->prev));
        }
        c->session_id = rec.body.session_id;
        c->version = rec.body.version;
        c->next_seq = 0u;
        c->in_session = true;
        c->sessions++;
    }
    if (rec.body.version != c->version) {
        return chain_break(c, &rec.body, "a session whose records change version");
    }
    if (rec.body.seq != c->next_seq) {
        return chain_break(c, &rec.body, "records missing or out of order (seq gap)");
    }
    audit_record_hash(keyed ? c->key : NULL, c->prev, &rec.body, h);
    if (memcmp(h, rec.hash, SHA256_DIGEST_SIZE) != 0) {
        return chain_break(c, &rec.body, "a record whose hash does not re-derive (altered)");
    }
    if (c->watch && rec.body.session_id == c->watch_session && rec.body.seq == c->watch_seq) {
        c->watch_seen = true;
        if (memcmp(h, c->watch_hash, SHA256_DIGEST_SIZE) == 0) {
            c->watch_ok = true;   /* met; another session with the same id cannot undo it */
        }
    }
    memcpy(c->prev, h, SHA256_DIGEST_SIZE);
    c->next_seq++;
    c->records++;
    c->last_was_end = rec.body.type == AUDIT_REC_SESSION_END;
    return true;
}

/* Ends the walk, counting a last session with no SESSION_END as unfinished. */
void audit_chain_check_finish(audit_chain_check_t *c)
{
    if (c->in_session && !c->last_was_end && !c->broken) {
        c->unfinished++;
    }
    c->in_session = false;
}

/* Logs CARD_CHECK: the check's verdict, the records, sessions and blocks it read, and where it broke. */
void audit_log_card_check(audit_log_t *log, uint64_t ts_ns, const audit_chain_check_t *c, uint8_t op,
                          uint8_t aux, uint32_t blocks_read)
{
    audit_body_t b;
    memset(&b, 0, sizeof(b));
    b.type        = AUDIT_REC_CARD_CHECK;
    b.ts_ns       = ts_ns;
    b.op          = op;
    b.aux         = aux;
    b.block_count = (uint32_t)c->records;
    b.data_len    = (uint32_t)c->sessions;
    b.residue     = (uint32_t)c->unfinished;
    b.lba         = blocks_read;
    b.tag         = c->broken ? (uint32_t)c->broken_seq : 0u;
    append(log, &b);
}

/* Logs a GAP: capture words lost, and for how long, and flags the next record too. */
void audit_log_gap(audit_log_t *log, uint64_t ts_ns, uint32_t lost_words,
                   uint64_t lost_ns)
{
    audit_body_t b;
    memset(&b, 0, sizeof(b));
    b.type        = AUDIT_REC_GAP;
    b.ts_ns       = ts_ns;
    b.block_count = lost_words;
    b.data_len    = (uint32_t)(lost_ns / 1000u);
    append(log, &b);

    /* Everything after a gap is suspect until the next clean record, so the next record is marked
     * too. */
    log->gap_pending = true;
}

/* Logs a name as FILE_NAME records, AUDIT_NAME_CHUNK bytes each (`old`: a rename's old name). */
static void file_name_records(audit_log_t *log, uint64_t ts_ns, uint32_t tag, uint8_t event,
                              const char *name, bool old)
{
    const size_t len = name ? strlen(name) : 0u;
    const uint32_t chunks = len == 0u ? 1u : (uint32_t)((len + AUDIT_NAME_CHUNK - 1u) / AUDIT_NAME_CHUNK);
    (void)tag;
    for (uint32_t c = 0; c < chunks; c++) {
        static audit_body_t b;                 /* static: see append */
        memset(&b, 0, sizeof(b));
        b.type     = AUDIT_REC_FILE_NAME;
        b.ts_ns    = ts_ns;
        b.op       = event;
        b.dev_addr = (uint8_t)c;
        b.endpoint = (uint8_t)chunks;
        const size_t used = (len > (size_t)c * AUDIT_NAME_CHUNK)
            ? ((len - (size_t)c * AUDIT_NAME_CHUNK) < AUDIT_NAME_CHUNK ? len - (size_t)c * AUDIT_NAME_CHUNK
                                                                       : AUDIT_NAME_CHUNK)
            : 0u;
        b.lun = (uint8_t)used;
        static uint8_t chunk[AUDIT_NAME_CHUNK];
        memset(chunk, 0, sizeof(chunk));
        if (used != 0u) {
            memcpy(chunk, &name[(size_t)c * AUDIT_NAME_CHUNK], used);
        }
        memcpy((uint8_t *)&b + offsetof(audit_body_t, lba), chunk, AUDIT_NAME_CHUNK);
        if (old) {
            b.flags = AUDIT_FLAG_OLD_NAME;
        }
        append(log, &b);
    }
}

/* Logs a FILE event (a volume, create, rename, delete, ...), the file as it was before if known, and its name records. */
void audit_log_file_event(audit_log_t *log, uint64_t ts_ns, uint32_t tag,
                          const audit_file_event_t *ev)
{
    static audit_body_t b;                     /* static: see append */
    memset(&b, 0, sizeof(b));
    b.type  = AUDIT_REC_FILE_EVENT;
    b.ts_ns = ts_ns;
    b.tag   = tag;
    b.op    = ev->event;
    b.lba   = ev->lba;
    if (ev->from_write) {
        b.flags |= AUDIT_FLAG_FROM_WRITE;
    }
    if (ev->event == AUDIT_FILE_VOLUME) {
        b.block_count = ev->serial;
        b.data_len    = ev->heap_offset;
        b.residue     = ev->root_cluster;
        b.dev_addr    = ev->cluster_shift;
        if (ev->boot_checked) {
            b.flags |= AUDIT_FLAG_BOOT_CHECKED;
        }
        if (ev->boot_ok) {
            b.flags |= AUDIT_FLAG_BOOT_OK;
        }
        append(log, &b);
        return;
    }
    if (ev->event == AUDIT_FILE_UNRELIABLE) {
        b.block_count = ev->blocks;
        b.data_len    = ev->bytes;
        b.residue     = ev->missing ? 1u : 0u;
        b.flags      |= AUDIT_FLAG_DIRECTORY;
        append(log, &b);
        file_name_records(log, ts_ns, tag, ev->event, ev->name, false);
        return;
    }
    b.dev_addr    = ev->index;
    b.block_count = ev->first_cluster;
    b.data_len    = (uint32_t)ev->size;
    b.residue     = (uint32_t)(ev->size >> 32);
    if (ev->directory) {
        b.flags |= AUDIT_FLAG_DIRECTORY;
    }
    append(log, &b);

    if (ev->have_before) {
        static audit_body_t o;
        o = b;
        o.type        = AUDIT_REC_FILE_BEFORE;
        o.flags      &= (uint16_t)~AUDIT_FLAG_AFTER_GAP;
        o.block_count = ev->old_first_cluster;
        o.data_len    = (uint32_t)ev->old_size;
        o.residue     = (uint32_t)(ev->old_size >> 32);
        append(log, &o);
    }
    file_name_records(log, ts_ns, tag, ev->event, ev->name, false);
    if (ev->event == AUDIT_FILE_RENAME && ev->old_name) {
        file_name_records(log, ts_ns, tag, ev->event, ev->old_name, true);
    }
}

/* Logs SESSION_END with the number of records the session made. */
void audit_log_session_end(audit_log_t *log, uint64_t ts_ns)
{
    audit_body_t b;
    memset(&b, 0, sizeof(b));
    b.type  = AUDIT_REC_SESSION_END;
    b.ts_ns = ts_ns;
    b.data_len = (uint32_t)log->records;
    append(log, &b);
}

/* ---- console backend ------------------------------------------------- */

/* Prints one record as an AUD| line. */
static bool console_write(void *ctx, store_item_t kind, const uint8_t *data, uint32_t len)
{
    (void)ctx;
    if (kind != STORE_ITEM_AUDIT_RECORD || len != sizeof(audit_record_t)) {
        return false;
    }
    audit_record_t rec;
    memcpy(&rec, data, sizeof(rec));

    char hash_hex[65];
    hex32(rec.hash, hash_hex);
    /* Pipe-delimited so the chain can be re-derived from the console alone; columns 17-21 are the
     * rest of the body. */
    printf("AUD|%llu|%llu|%s|%s|0x%02x|%llu|%lu|%lu|%lu|%u|%u|%u|0x%08lx|%u|0x%04x|%s|%u|%016llx|%u|%u|%u\n",
           (unsigned long long)rec.body.seq,
           (unsigned long long)rec.body.ts_ns,
           rec_type_name(rec.body.type),
           op_text(rec.body.type, rec.body.op),
           rec.body.opcode,
           (unsigned long long)rec.body.lba,
           (unsigned long)rec.body.block_count,
           (unsigned long)rec.body.data_len,
           (unsigned long)rec.body.residue,
           rec.body.dev_addr,
           rec.body.endpoint,
           rec.body.lun,
           (unsigned long)rec.body.tag,
           rec.body.status,
           rec.body.flags,
           hash_hex,
           rec.body.op,
           (unsigned long long)rec.body.session_id,
           rec.body.aux,
           rec.body.reserved,
           rec.body.version);
    return true;
}

/* Makes `b` the store backend that prints records on the console. */
void audit_log_console_backend(store_backend_t *b)
{
    memset(b, 0, sizeof(*b));
    b->name  = "console";
    b->write = console_write;
}
