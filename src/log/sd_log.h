/*
 * The audit log on the SD card: preallocated, contiguous parts of one length (AUDIT.BIN, AUDIT001.BIN, ...)
 * written block by block by LBA, so a power cut tears at most one block, never the filesystem.
 * Indexes run on across parts; part k's first block (index k x length) is its header: magic, file id, its
 * LBA, its length. Every block: a 32-byte header, then by kind:
 *   [0 8B "USBTAPLG"][8 8B file id][16 4B index][20 1B items][21 1B version][22 1B kind]
 *   [23 1B boot tag (v3)][24 4B block 0: blocks; kinds 5, 6: two u16][28 4B CRC-32, itself as zero]
 * Kinds: 0 records (1-5 x 96 B); 5 metadata sectors as a byte stream of items (n u16, LBA u64, n bytes);
 * 6 a model snapshot in 480-byte pieces; 1-4 an older sector layout, read only.
 * Version 3: bytes 32-511 ChaCha20-encrypted with the cipher key, nonce = index then file id, counter =
 * boot tag x 8; the header and CRC stay plain, so the end is found without the key.
 * Blocks are written in order and never rewritten: the log is the valid run from block 1.
 */
#ifndef SD_LOG_H
#define SD_LOG_H

/* bool and the fixed-width integers. */
#include <stdbool.h>
#include <stdint.h>

/* The store backend this module provides, and its visitor type. */
#include "store.h"

#define SD_LOG_BLOCK_BYTES       512u  /* one card block */
#define SD_LOG_HEADER_BYTES      32u   /* the header at the front of every block */
#define SD_LOG_RECORD_BYTES      96u   /* sizeof(audit_record_t) */
#define SD_LOG_RECORDS_PER_BLOCK 5u    /* 32 + 5 x 96 = 512 */
#define SD_LOG_VERSION           2u    /* block kinds; 1 = records only */
#define SD_LOG_VERSION_ENC       3u    /* block kinds, payload encrypted */
#define SD_LOG_SECTOR_BYTES      512u  /* a metadata sector, as the drive has it */
#define SD_LOG_PART1_BYTES       472u  /* 512 - 32 header - 8 LBA */

/* Block kinds (byte 22). */
#define SD_KIND_RECORDS   0u   /* 1-5 audit records */
#define SD_KIND_SECTOR_1  1u   /* older format: a sector's first part */
#define SD_KIND_SECTOR_2  2u   /* older format: its second part */
#define SD_KIND_ZERO      3u   /* older format: an all-zero sector */
#define SD_KIND_SHORT     4u   /* older format, read only */
#define SD_KIND_STREAM    5u   /* what sectors are written as */
#define SD_KIND_BLOB      6u   /* a model snapshot, in pieces */

#define SD_STREAM_PAYLOAD  480u                        /* stream bytes per block */
#define SD_STREAM_ITEM_HDR 10u                         /* n (u16) + LBA (u64) */
#define SD_STREAM_ITEM_MAX (SD_STREAM_ITEM_HDR + SD_LOG_SECTOR_BYTES)   /* the longest item */
#define SD_STREAM_NONE     0xFFFFu                     /* "no item starts in this block" */
#define SD_LOG_MAGIC             "USBTAPLG"            /* the first 8 bytes of every block */

/* A partly filled block is written once its first record has waited this long: a power cut costs at
 * most this. */
#define SD_LOG_FLUSH_US 1000000u

/* Failed writes in a row before the card is given up for the session (one failure may be
 * transient). */
#define SD_LOG_MAX_WRITE_RETRIES 8u

/* The most parts a log has: 128 x 256 MB = 32 GB. */
#define SD_LOG_MAX_PARTS 128u
/* Blocks kept back to close a session once no part can be added (its last records, a model snapshot). */
#define SD_LOG_RESERVE_BLOCKS 256u

/* One-block access to the card; `ready` must not block, `sync` waits until the card has finished. */
typedef struct {
    bool (*read)(void *ctx, uint32_t lba, uint8_t *buf);
    bool (*write)(void *ctx, uint32_t lba, const uint8_t *buf);
    bool (*ready)(void *ctx);
    bool (*sync)(void *ctx);
    void *ctx;
} sd_dev_t;

/* Whether the card is being written. */
typedef enum {
    SD_LOG_WAITING = 0,   /* not opened yet: records wait in the FIFO in front */
    SD_LOG_OPEN,          /* writing */
    SD_LOG_FULL,          /* every block of the file is used */
    SD_LOG_OFF,           /* no usable card, or it failed: records are refused (counted) */
} sd_log_state_t;

/* What attaching to a log file found. */
typedef enum {
    SD_ATTACH_OK = 0,
    SD_ATTACH_READ_ERROR,     /* a block could not be read */
    SD_ATTACH_NOT_OURS,       /* block 0 is not a header this module wrote for this place */
    SD_ATTACH_TOO_SMALL,      /* fewer than two blocks */
} sd_attach_result_t;

/* The log on the card: where it is, how far it is written, the blocks being filled, and the stats
 * counts. */
typedef struct {
    sd_dev_t       dev;
    sd_log_state_t state;
    const uint8_t *cipher_key;  /* ChaCha20 key (32 bytes); NULL: blocks written plain */
    uint8_t        boot_tag;    /* this boot's tag in the nonce (header byte 23) */
    uint32_t       part_lba[SD_LOG_MAX_PARTS];   /* LBA of each part's header */
    uint32_t       parts;
    uint32_t       blocks;      /* blocks in each part, its header included */
    uint64_t       file_id;
    uint32_t       next;        /* index of the next block to write (past the last part: full) */
    uint32_t       boot_first;  /* the first block this boot writes */

    uint8_t        block[SD_LOG_BLOCK_BYTES];   /* the record block being filled */
    /* Metadata sectors packed into the stream block being filled; what does not fit waits in
     * `item`. */
    uint8_t        stream[SD_LOG_BLOCK_BYTES];
    uint32_t       stream_used;     /* stream bytes in it */
    uint32_t       stream_starts;   /* items starting in it */
    uint32_t       stream_first;    /* offset of the first of them, or SD_STREAM_NONE */
    uint32_t       stream_ends;     /* items ending in it: on the card once it is written */
    uint64_t       stream_since_us; /* when sd_log_tick first saw it non-empty (0: not yet) */
    uint8_t        item[SD_STREAM_ITEM_MAX];
    uint32_t       item_len, item_pos;   /* item_pos < item_len: part of it still to copy */
    uint32_t       held;        /* records in it */
    uint64_t       held_since_us;   /* when sd_log_tick first saw it non-empty (0: not yet) */
    uint32_t       fails_in_row;

    /* For the stats line. */
    uint64_t       blocks_written;
    uint64_t       partial_blocks;  /* written before they were full (timer, sync) */
    uint64_t       write_errors;    /* failed block writes, retried or not */
    uint64_t       records_lost;    /* records the card will never have */
    uint64_t       sectors_written; /* metadata sectors wholly on the card (zero ones included) */
    uint64_t       sectors_zero;    /* of the sectors taken, all-zero ones */
    uint64_t       sectors_lost;    /* sectors the card will never have */
} sd_log_t;

/* A sector taken but not yet wholly in the stream block: the next item waits. */
static inline bool sd_log_sector_pending(const sd_log_t *l)
{
    return l->item_pos < l->item_len;
}

/* State WAITING: the backend can be attached before the card is opened. */
void sd_log_init(sd_log_t *l);

/* Writes a fresh header for part `part` into `blk` (a whole block). */
void sd_log_make_header(uint8_t blk[SD_LOG_BLOCK_BYTES], uint64_t file_id, uint32_t part, uint32_t first_lba,
                        uint32_t blocks);

/* Writes the header of a new log whose first part is the blocks [first_lba, first_lba + blocks). */
bool sd_log_create(const sd_dev_t *dev, uint64_t file_id, uint32_t first_lba, uint32_t blocks);

/* Writes the header of part `part` (1 on) of log `file_id`, at the blocks [first_lba, first_lba + blocks). */
bool sd_log_create_part(const sd_dev_t *dev, uint64_t file_id, uint32_t part, uint32_t first_lba,
                        uint32_t blocks);

/* Checks the first part's header and finds the log's end by binary search; OPEN (or FULL) on success,
 * else unchanged. */
sd_attach_result_t sd_log_attach(sd_log_t *l, const sd_dev_t *dev, uint32_t first_lba,
                                 uint32_t blocks);

/* Adds the next part (its header at `first_lba`), finding the end in it if the log had filled; before
 * anything is written. */
sd_attach_result_t sd_log_add_part(sd_log_t *l, uint32_t first_lba);

/* Blocks the log can still take. */
uint32_t sd_log_blocks_free(const sd_log_t *l);

/* The card LBA of block `index`. */
uint32_t sd_log_lba(const sd_log_t *l, uint32_t index);

/* Encrypts blocks written from now on (version 3) with `key`; `boot_tag` differs per boot. Before
 * the first read. */
void sd_log_set_key(sd_log_t *l, const uint8_t key[32], uint8_t boot_tag);

/* No usable card: records are refused from now on, and counted as failures. */
void sd_log_set_off(sd_log_t *l);

/* Fills `b` as a store backend over `l` for records and metadata sectors; put it behind a
 * store_fifo_t. */
void sd_log_backend(sd_log_t *l, store_backend_t *b);

/* Walks every record in the file, every session, for the boot-time chain check. */
bool sd_log_for_each_record_all(sd_log_t *l, store_visit_t visit, void *vctx, uint32_t *blocks_read);

/* True when the next item can be taken without waiting for the card; it may write a full stream
 * block first. */
bool sd_log_ready(void *vl);

/* Writes a block if the card is idle: a full stream block, one that has waited SD_LOG_FLUSH_US, or
 * a full record block. */
void sd_log_tick(sd_log_t *l, uint64_t now_us);

/* ---- blobs: a model snapshot on the card (kind 6) -------------------- */

/* A blob being written: block after block at the end of the log while the bus is quiet; no record names an incomplete one. */
typedef struct {
    sd_log_t *l;
    uint8_t   blk[SD_LOG_BLOCK_BYTES];
    uint32_t  used;      /* payload bytes in blk */
    uint32_t  number;    /* blocks of the blob written so far */
    uint32_t  first;     /* index of its first block */
    uint32_t  bytes;     /* bytes taken */
    bool      ok;
} sd_blob_writer_t;

/* False if the card is not open for writing. */
bool sd_blob_begin(sd_blob_writer_t *w, sd_log_t *l);
/* Takes bytes (an exfat_snapshot_sink_t); full blocks are written as they fill. */
void sd_blob_put(void *w, const uint8_t *bytes, uint32_t len);
/* Writes the last block. True if every block of the blob is on the card. */
bool sd_blob_end(sd_blob_writer_t *w);

/* Reads a blob back, one block at a time, decrypting each. */
typedef struct {
    sd_log_t *l;
    uint8_t   blk[SD_LOG_BLOCK_BYTES];   /* the block being read, decrypted */
    uint32_t  index;     /* its index in the file */
    uint32_t  number;    /* its number in the blob */
    uint32_t  pos, used; /* payload bytes given, and in it */
    uint32_t  blocks_read;
} sd_blob_reader_t;

/* Opens the blob whose first block is `first`; false if that block is not a valid blob start. */
bool sd_blob_open(sd_blob_reader_t *r, sd_log_t *l, uint32_t first);
/* Gives exactly `len` bytes (an exfat_snapshot_source_t), reading on; false if the blob ends first. */
bool sd_blob_get(void *r, uint8_t *bytes, uint32_t len);

/* CRC-32 (IEEE 802.3, the one zlib.crc32 computes). */
uint32_t sd_log_crc32(const uint8_t *p, uint32_t n);

#endif /* SD_LOG_H */
