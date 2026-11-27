/*
 * The append-only, hash-chained audit log: each record is a 64-byte little-endian body and a 32-byte
 * hash of (previous hash || body), so a record altered, moved or removed breaks the chain after it.
 * The layout is frozen (Phase 2 emits the same records); sealed records go to a store (store.h).
 */
#ifndef AUDIT_LOG_H
#define AUDIT_LOG_H

/* The SCSI commands records are made from, SHA-256 and HMAC, and the store
 * records are written to. */
#include "msc_parse.h"
#include "sha256.h"
#include "store.h"

#define AUDIT_MAGIC   0x54494455u   /* 'UDIT' little-endian */
/* Record versions: 1 plain SHA-256 from zero; 2 HMAC-SHA256 with the chain key, each session
 * following the card's last hash. */
#define AUDIT_VERSION_PLAIN 1u      /* SHA-256, every session from zero */
#define AUDIT_VERSION_KEYED 2u      /* HMAC-SHA256, sessions linked */

/* What a record is about. */
typedef enum {
    AUDIT_REC_SESSION_START = 1,
    AUDIT_REC_SCSI_COMMAND  = 2,
    AUDIT_REC_BUS_EVENT     = 3,
    AUDIT_REC_GAP           = 4,   /* capture overran: bus traffic was missed */
    AUDIT_REC_SESSION_END   = 5,
    AUDIT_REC_FILE_EVENT    = 6,   /* a file or directory change seen in exFAT metadata */
    AUDIT_REC_FILE_BEFORE   = 7,   /* the state before it (DELETE, RENAME, MODIFY, completed CREATE) */
    AUDIT_REC_FILE_NAME     = 8,   /* part of the name of the FILE_EVENT before it */
    AUDIT_REC_DRIVE_POWER   = 9,   /* The tap switched the drive's VBUS relay */
    AUDIT_REC_CARD_CHECK    = 10,  /* The card's log was checked before this session */
    AUDIT_REC_SECTOR        = 11,  /* a digest of the metadata sectors a transfer stored on the card */
    AUDIT_REC_MODEL         = 12,  /* the exFAT name model saved to the card, or loaded from it */
    AUDIT_REC_HOST_POWER    = 13,  /* the PC side's VBUS seen present, or gone */
} audit_rec_type_t;

/* MODEL `op`: what was done with a snapshot of the exFAT model. */
#define AUDIT_MODEL_SAVED   1u   /* written to the card (when the drive went away, or at the end) */
#define AUDIT_MODEL_LOADED  2u   /* read back and checked against the record that saved it */
#define AUDIT_MODEL_REFUSED 3u   /* read back and NOT what that record vouches for, or unreadable */
/* MODEL `aux` flags. */
#define AUDIT_MODEL_STALE     1u   /* a later session saw this volume and saved no model after it */
#define AUDIT_MODEL_INSERTION 2u   /* loaded when this volume's boot sector was seen, not at boot */

/* DRIVE_POWER `aux` values: why the relay was switched. */
#define AUDIT_POWER_BOOT_CHECKS 1u   /* on: the boot checks passed */
#define AUDIT_POWER_OPERATOR    2u   /* on or off: a console key */
#define AUDIT_POWER_SESSION_END 3u   /* off: the session was closed */
#define AUDIT_POWER_HOST_GONE   4u   /* off: the PC side's VBUS went away */
#define AUDIT_POWER_CARD_FULL   5u   /* off: the card's log reached its reserve and cannot grow */

/* CARD_CHECK `op` and `aux`: how the card compared with the checkpoint in the Pico's flash. */
#define AUDIT_CHECK_FAIL   0u          /* a chain did not re-derive, or the checkpoint was not met */
#define AUDIT_CHECK_PASS   1u          /* every chain re-derived and the checkpoint was met */
#define AUDIT_CHECK_ACCEPT 2u          /* the card accepted as it is (key c; or, the session after, its card_password.txt) */
#define AUDIT_CHECKPOINT_NONE     1u   /* the Pico had none: first use */
#define AUDIT_CHECKPOINT_OK       2u   /* the card still holds that record */
#define AUDIT_CHECKPOINT_ACCEPTED 4u   /* it was set by an operator's accept, not a session end */
#define AUDIT_CHECKPOINT_LOST     8u   /* the card no longer holds it, or is another card */
#define AUDIT_CHECKPOINT_PASSWORD 16u  /* that accept was by card_password.txt (with ACCEPTED) */
#define AUDIT_CHECKPOINT_FULL     32u  /* the card's log is full and cannot grow: the drive stays off */

/* Record flags. */
#define AUDIT_FLAG_COMPLETED    (1u << 0)  /* CSW was seen for this command */
#define AUDIT_FLAG_LBA_VALID    (1u << 1)  /* the command carries an LBA */
#define AUDIT_FLAG_DATA_IN      (1u << 2)  /* device-to-host */
#define AUDIT_FLAG_AFTER_GAP    (1u << 3)  /* traffic was lost before this record */
#define AUDIT_FLAG_FROM_WRITE   (1u << 4)  /* FILE_*: seen in a WRITE (else only in a READ) */
#define AUDIT_FLAG_DIRECTORY    (1u << 5)  /* FILE_*: a directory, not a file */
#define AUDIT_FLAG_BOOT_CHECKED (1u << 6)  /* FILE_EVENT VOLUME: boot checksum verified ... */
#define AUDIT_FLAG_BOOT_OK      (1u << 7)  /* ... and it matched */
#define AUDIT_FLAG_OLD_NAME     (1u << 8)  /* FILE_NAME: the name before a RENAME */

/* FILE_EVENT `op` values (the same numbers as exfat_event_type_t). */
#define AUDIT_FILE_VOLUME   1u   /* a boot sector: the volume's layout */
#define AUDIT_FILE_EXISTING 2u   /* a file or directory seen for the first time */
#define AUDIT_FILE_CREATE   3u   /* created */
#define AUDIT_FILE_DELETE   4u   /* deleted */
#define AUDIT_FILE_RENAME   5u   /* renamed or moved */
#define AUDIT_FILE_MODIFY   6u   /* a new size or first cluster */
#define AUDIT_FILE_CREATED  7u   /* a file created empty got its data: the creation completed */
/* Not a model event: a directory WRITE not decoded whole, so a change there may be missing. */
#define AUDIT_FILE_UNRELIABLE 8u

/* Bytes of name per FILE_NAME record: body bytes 32-55 (lba .. tag). */
#define AUDIT_NAME_CHUNK 24u

/* The 64-byte record body. Fields are overloaded by record type, so the record stays one size:
 *   SESSION_START  data_len = sample rate (Hz), aux = usb_speed_t; keyed: lba = the genesis's first 8 bytes
 *   SCSI_COMMAND   op = msc_op_t, aux = cdb_flags
 *   BUS_EVENT      opcode = usb_bus_event_t, data_len = duration (us), block_count = occurrences
 *   GAP            block_count = sample words lost, data_len = duration (us)
 *   FILE_EVENT     op = AUDIT_FILE_*; ts_ns, tag = the command that showed it; lba = directory sector,
 *                  dev_addr = entry, block_count = first cluster, data_len / residue = size (low / high).
 *                  VOLUME: block_count = serial, data_len = heap offset, residue = root cluster, dev_addr = shift.
 *                  UNRELIABLE: lba, block_count = the WRITE's sectors, data_len = bytes decoded, residue = 1 if none
 *   FILE_BEFORE    the FILE_EVENT fields before the change
 *   FILE_NAME      bytes 32-55 = up to 24 bytes of UTF-8 path, lun = bytes used, dev_addr / endpoint = chunk n / count
 *   DRIVE_POWER    op = 1 on, 0 off; aux = AUDIT_POWER_*
 *   CARD_CHECK     op = AUDIT_CHECK_*, aux = AUDIT_CHECKPOINT_*; block_count = records, data_len = sessions,
 *                  residue = sessions never ended, lba = blocks read; on failure tag = the seq it failed at
 *   SECTOR         lba = first sector, aux = count, status = new sectors the card refused; bytes 40-55 = first 16 bytes of SHA-256 over each (LBA, 512 bytes)
 *   HOST_POWER     op = 1 present, 0 gone; data_len = mV; block_count = lowest mV while present
 *   MODEL          op = AUDIT_MODEL_*; lba = snapshot's first block; bytes 40-55 = its digest; bytes 56-59 = serial;
 *                  aux = AUDIT_MODEL_* flags; status (REFUSED) = 1 unreadable, 2 not what was vouched for */
typedef struct __attribute__((packed)) {
    uint32_t magic;
    uint8_t  version;
    uint8_t  type;
    uint16_t flags;
    uint64_t seq;
    uint64_t session_id;
    uint64_t ts_ns;
    uint64_t lba;
    uint32_t block_count;
    uint32_t data_len;
    uint32_t residue;
    uint32_t tag;
    uint8_t  dev_addr;
    uint8_t  endpoint;
    uint8_t  lun;
    uint8_t  opcode;
    uint8_t  op;        /* msc_op_t */
    uint8_t  status;    /* bCSWStatus */
    uint8_t  aux;
    uint8_t  reserved;
} audit_body_t;

/* A sealed record: its 64-byte body and the 32-byte hash that chains it. */
typedef struct __attribute__((packed)) {
    audit_body_t body;
    uint8_t      hash[SHA256_DIGEST_SIZE];
} audit_record_t;

/* The log being written: its session, the next sequence number, the chain's last hash and key, and
 * its store. */
typedef struct {
    uint64_t  session_id;
    uint64_t  seq;
    uint8_t   prev_hash[SHA256_DIGEST_SIZE];
    uint8_t   genesis[SHA256_DIGEST_SIZE];   /* what the session's first record follows */
    const hmac_sha256_key_t *key;            /* chain key; NULL: version 1 records */
    bool      gap_pending;  /* tag the next record as following a gap */
    store_t  *store;        /* where sealed records go (STORE_ITEM_AUDIT_RECORD) */
    uint64_t  records;
} audit_log_t;

/* Starts a log; `store` may be NULL (records sealed and chained, kept nowhere). Version 1 unless a
 * key is set. */
void audit_log_init(audit_log_t *log, uint64_t session_id, store_t *store);

/* Version 2 records with this chain key (kept by the caller); set before the first record. */
void audit_log_set_key(audit_log_t *log, const hmac_sha256_key_t *key);

/* The hash the session's first record follows (the card's last); set before the first record. */
void audit_log_set_genesis(audit_log_t *log, const uint8_t head[SHA256_DIGEST_SIZE]);

/* The chain key: HMAC-SHA256(log key, "usbtap chain v1"), so it differs from the card's cipher key. */
void audit_chain_key(hmac_sha256_key_t *k, const uint8_t log_key[32]);

/* 32 bits naming a chain key without revealing it, for the banner. */
uint32_t audit_key_id(const hmac_sha256_key_t *k);

/* A record's hash: version 2 with `key`, version 1 when it is NULL. */
void audit_record_hash(const hmac_sha256_key_t *key, const uint8_t prev[SHA256_DIGEST_SIZE],
                       const audit_body_t *body, uint8_t out[SHA256_DIGEST_SIZE]);

/* The first 8 bytes of a hash as a number: a version 2 SESSION_START's lba. */
uint64_t audit_genesis_tag(const uint8_t head[SHA256_DIGEST_SIZE]);

/* The first record of a session: the bus speed and sample rate. */
void audit_log_session_start(audit_log_t *log, uint64_t ts_ns,
                             usb_speed_t speed, uint32_t sample_hz);
/* A record for one SCSI command. */
void audit_log_command(audit_log_t *log, const msc_command_t *cmd);
/* A record for one bus event (or a coalesced group of `count`). */
void audit_log_bus_event(audit_log_t *log, uint8_t event_code,
                         uint64_t ts_ns, uint64_t duration_ns, uint32_t count);
/* A record that capture missed `lost_words` words of the bus. */
void audit_log_gap(audit_log_t *log, uint64_t ts_ns, uint32_t lost_words,
                   uint64_t lost_ns);
/* The last record of a session. */
void audit_log_session_end(audit_log_t *log, uint64_t ts_ns);

/* A file or directory event: one FILE_EVENT, a FILE_BEFORE if have_before, and FILE_NAME records
 * for the names. */
typedef struct {
    uint8_t     event;              /* AUDIT_FILE_* */
    bool        from_write;
    bool        directory;
    uint64_t    lba;                /* directory sector */
    uint8_t     index;              /* entry in it */
    uint32_t    first_cluster;
    uint64_t    size;
    bool        have_before;
    uint32_t    old_first_cluster;
    uint64_t    old_size;
    const char *name;               /* UTF-8, NULL for none */
    const char *old_name;           /* RENAME only */
    /* AUDIT_FILE_VOLUME */
    uint32_t    serial;
    uint32_t    heap_offset;
    uint32_t    root_cluster;
    uint8_t     cluster_shift;
    bool        boot_checked;
    bool        boot_ok;
    /* AUDIT_FILE_UNRELIABLE (name = the directory's path) */
    uint32_t    blocks;
    uint32_t    bytes;
    bool        missing;
} audit_file_event_t;

/* Writes the records for one file or directory event. */
void audit_log_file_event(audit_log_t *log, uint64_t ts_ns, uint32_t tag,
                          const audit_file_event_t *ev);

/* The drive's power was switched on (`on`) or off, for `reason`
 * (AUDIT_POWER_*). */
void audit_log_drive_power(audit_log_t *log, uint64_t ts_ns, bool on, uint8_t reason);

/* Re-derives the chains of stored records, session after session, as tools/read_log.py does: a gap, a
 * hash that does not re-derive, or a session starting mid-way fails; a session with no SESSION_END is counted. */
typedef struct {
    const hmac_sha256_key_t *key;   /* for version 2 records; NULL: they fail */
    uint64_t    session_id;    /* the session being followed */
    uint64_t    next_seq;
    uint8_t     prev[SHA256_DIGEST_SIZE];
    bool        in_session, last_was_end;
    uint8_t     version;       /* the session's record version */
    uint64_t    records, sessions, unfinished;
    bool        broken;
    uint64_t    broken_session, broken_seq;
    const char *why;           /* why it failed */
    /* The checkpoint: a record the card must still hold (audit_chain_check_watch). */
    bool        watch, watch_seen, watch_ok;
    uint64_t    watch_session, watch_seq;
    uint8_t     watch_hash[SHA256_DIGEST_SIZE];
} audit_chain_check_t;

/* Starts a check with the chain key (NULL: version 2 records fail). */
void audit_chain_check_init(audit_chain_check_t *c, const hmac_sha256_key_t *key);
/* Also looks for the checkpoint's record: watch_seen when met, watch_ok when its hash matches. */
void audit_chain_check_watch(audit_chain_check_t *c, uint64_t session, uint64_t seq,
                             const uint8_t hash[SHA256_DIGEST_SIZE]);
/* A store_visit_t: one stored record. Returns false (stop) once broken. */
bool audit_chain_check_visit(void *vctx, const uint8_t *data, uint32_t len);
/* After the last record: counts the last session if it did not end. */
void audit_chain_check_finish(audit_chain_check_t *c);
/* The CARD_CHECK record for a check over `blocks_read` blocks. */
void audit_log_card_check(audit_log_t *log, uint64_t ts_ns, const audit_chain_check_t *c, uint8_t op,
                          uint8_t aux, uint32_t blocks_read);

/* A SECTOR record for `count` sectors from `lba`, with the digest built by
 * audit_sectors_start/add/end, and how many new sectors the card refused. */
void audit_log_sectors(audit_log_t *log, uint64_t ts_ns, uint64_t lba, uint8_t count,
                       const uint8_t digest[16], bool from_write, uint8_t refused);
/* The digest a SECTOR record carries, built one sector at a time. */
void audit_sectors_start(sha256_ctx_t *ctx);
/* Adds one sector, with its LBA. */
void audit_sectors_add(sha256_ctx_t *ctx, uint64_t lba, const uint8_t sector[512]);
/* Finishes it: the first 16 bytes of the SHA-256. */
void audit_sectors_end(sha256_ctx_t *ctx, uint8_t digest[16]);

/* A HOST_POWER record (see above). */
void audit_log_host_power(audit_log_t *log, uint64_t ts_ns, bool present, uint32_t mv, uint32_t mv_min);

/* A MODEL record (see above). `digest` is the snapshot's first 16 bytes of SHA-256. */
void audit_log_model(audit_log_t *log, uint64_t ts_ns, uint8_t op, uint8_t aux, uint8_t why,
                     uint32_t first_block, uint32_t serial, const uint8_t digest[16]);

/* Hex of the current chain head: the one value an auditor needs to pin. */
void audit_log_head_hex(const audit_log_t *log, char out[65]);

/* Fills `b` as a backend that prints each record as one AUD| line on stdout (no read-back). */
void audit_log_console_backend(store_backend_t *b);

#endif /* AUDIT_LOG_H */
