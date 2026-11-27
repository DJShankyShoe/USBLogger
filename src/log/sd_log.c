/*
 * The audit log on the SD card: blocks of records, a stream of metadata sectors and model blobs,
 * sealed and encrypted.
 */

/* memset, memcpy. */
#include <string.h>

/* The cipher for the blocks' payloads, and what this file defines. */
#include "chacha20.h"
#include "sd_log.h"

/* ---- little-endian fields and the CRC -------------------------------- */

/* Writes a 32-bit field, little-endian. */
static void put32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

/* Reads a little-endian 32-bit field. */
static uint32_t get32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

/* Writes a 64-bit field, little-endian. */
static void put64(uint8_t *p, uint64_t v)
{
    put32(p, (uint32_t)v);
    put32(p + 4, (uint32_t)(v >> 32));
}

/* Reads a little-endian 16-bit field. */
static uint32_t get16(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8);
}

/* Reads a little-endian 64-bit field. */
static uint64_t get64(const uint8_t *p)
{
    return (uint64_t)get32(p) | ((uint64_t)get32(p + 4) << 32);
}

/* CRC-32 four bits at a time: a 16-entry table instead of 256 (~50 us per block, against ~400 us to
 * send it). */
uint32_t sd_log_crc32(const uint8_t *p, uint32_t n)
{
    static const uint32_t t[16] = {
        0x00000000u, 0x1DB71064u, 0x3B6E20C8u, 0x26D930ACu, 0x76DC4190u, 0x6B6B51F4u,
        0x4DB26158u, 0x5005713Cu, 0xEDB88320u, 0xF00F9344u, 0xD6D6A3E8u, 0xCB61B38Cu,
        0x9B64C2B0u, 0x86D3D2D4u, 0xA00AE278u, 0xBDBDF21Cu,
    };
    uint32_t crc = 0xFFFFFFFFu;
    for (uint32_t i = 0; i < n; i++) {
        crc ^= p[i];
        crc = (crc >> 4) ^ t[crc & 15u];
        crc = (crc >> 4) ^ t[crc & 15u];
    }
    return ~crc;
}

/* The block's CRC with its own field (bytes 28-31) counted as zero. */
static uint32_t block_crc(uint8_t blk[SD_LOG_BLOCK_BYTES])
{
    const uint32_t stored = get32(blk + 28);
    put32(blk + 28, 0u);
    const uint32_t crc = sd_log_crc32(blk, SD_LOG_BLOCK_BYTES);
    put32(blk + 28, stored);
    return crc;
}

/* XORs a version 3 block's payload with its keystream (nonce and counter from its own header). */
static void crypt_payload(const uint8_t *key, uint8_t blk[SD_LOG_BLOCK_BYTES])
{
    uint8_t nonce[12];
    memcpy(nonce, blk + 16, 4);       /* block index */
    memcpy(nonce + 4, blk + 8, 8);    /* file id */
    chacha20_xor(key, nonce, (uint32_t)blk[23] * 8u, blk + SD_LOG_HEADER_BYTES,
                 SD_LOG_BLOCK_BYTES - SD_LOG_HEADER_BYTES);
}

/* Fills the header, encrypts the payload when `key` is given, then the CRC over the block as it
 * will be on the card. */
static void seal(uint8_t blk[SD_LOG_BLOCK_BYTES], uint64_t file_id, uint32_t index, uint8_t count,
                 uint8_t kind, uint32_t extra, const uint8_t *key, uint8_t tag)
{
    memcpy(blk, SD_LOG_MAGIC, 8);
    put64(blk + 8, file_id);
    put32(blk + 16, index);
    blk[20] = count;
    blk[21] = (uint8_t)(key != NULL ? SD_LOG_VERSION_ENC : SD_LOG_VERSION);
    blk[22] = kind;
    blk[23] = key != NULL ? tag : 0u;
    put32(blk + 24, extra);
    if (key != NULL) {
        crypt_payload(key, blk);
    }
    put32(blk + 28, 0u);
    put32(blk + 28, sd_log_crc32(blk, SD_LOG_BLOCK_BYTES));
}

/* True for a block of this file at `index` (a part's header if `header`): header fields right, item
 * count plausible for its kind, CRC matching. */
static bool block_valid(uint8_t blk[SD_LOG_BLOCK_BYTES], uint64_t file_id, uint32_t index, bool header)
{
    const uint8_t count = blk[20];
    const uint8_t kind  = blk[22];
    const bool kind_ok = blk[21] == 1u ? kind == SD_KIND_RECORDS
                       : blk[21] == SD_LOG_VERSION ? kind <= SD_KIND_BLOB
                       : blk[21] == SD_LOG_VERSION_ENC &&
                             (kind == SD_KIND_RECORDS || kind == SD_KIND_STREAM || kind == SD_KIND_BLOB);
    bool count_ok;
    if (header) {
        count_ok = count == 0u && kind == SD_KIND_RECORDS;
    } else if (kind == SD_KIND_RECORDS) {
        count_ok = count >= 1u && count <= SD_LOG_RECORDS_PER_BLOCK;
    } else if (kind == SD_KIND_STREAM) {
        const uint32_t first = get16(blk + 24), used = get16(blk + 26);
        count_ok = used >= 1u && used <= SD_STREAM_PAYLOAD && count <= SD_STREAM_PAYLOAD / SD_STREAM_ITEM_HDR &&
                   (count == 0u ? first == SD_STREAM_NONE : first < used);
    } else if (kind == SD_KIND_BLOB) {
        const uint32_t used = get16(blk + 26);
        count_ok = used >= 1u && used <= SD_STREAM_PAYLOAD && count == (get16(blk + 24) == 0u ? 1u : 0u);
    } else {
        count_ok = count == 1u;
    }
    return memcmp(blk, SD_LOG_MAGIC, 8) == 0 && get64(blk + 8) == file_id &&
           get32(blk + 16) == index && kind_ok && count_ok &&
           (blk[23] == 0u || blk[21] == SD_LOG_VERSION_ENC) &&
           get32(blk + 28) == block_crc(blk);
}

/* ---- creating and finding the file ----------------------------------- */

/* Starts the log WAITING: records queue in front of it until the card is opened. */
void sd_log_init(sd_log_t *l)
{
    memset(l, 0, sizeof(*l));
    l->state = SD_LOG_WAITING;
}

/* Builds a part's header: the file id, where the part is and how long, and a note for whoever opens it. */
void sd_log_make_header(uint8_t blk[SD_LOG_BLOCK_BYTES], uint64_t file_id, uint32_t part, uint32_t first_lba,
                        uint32_t blocks)
{
    static const char note[] =
        "Forensic USB audit tap: hash-chained audit records, 5 x 96 bytes per 512-byte block "
        "after a 32-byte header, and the raw metadata sectors they were derived from. "
        "Read it with tools/read_log.py. Do not edit this file.";
    memset(blk, 0, SD_LOG_BLOCK_BYTES);
    put32(blk + 32, first_lba);
    blk[36] = (uint8_t)SD_LOG_RECORD_BYTES;
    blk[37] = (uint8_t)SD_LOG_RECORDS_PER_BLOCK;
    memcpy(blk + 64, note, sizeof(note) < SD_LOG_BLOCK_BYTES - 64u ? sizeof(note) : SD_LOG_BLOCK_BYTES - 64u);
    seal(blk, file_id, part * blocks, 0u, SD_KIND_RECORDS, blocks, NULL, 0u);   /* headers stay plain */
}

/* Writes a new header to the first part's block 0, making it an empty log. */
bool sd_log_create(const sd_dev_t *dev, uint64_t file_id, uint32_t first_lba, uint32_t blocks)
{
    return sd_log_create_part(dev, file_id, 0u, first_lba, blocks);
}

/* Writes the header of part `part`, making its blocks room for the log to run on into. */
bool sd_log_create_part(const sd_dev_t *dev, uint64_t file_id, uint32_t part, uint32_t first_lba,
                        uint32_t blocks)
{
    uint8_t blk[SD_LOG_BLOCK_BYTES];
    sd_log_make_header(blk, file_id, part, first_lba, blocks);
    return dev->write(dev->ctx, first_lba, blk);
}

/* True if `blk` is the header of part `part` of a log `blocks` long, found at `first_lba`. */
static bool header_ok(uint8_t blk[SD_LOG_BLOCK_BYTES], uint64_t file_id, uint32_t part, uint32_t first_lba,
                      uint32_t blocks)
{
    return block_valid(blk, file_id, part * blocks, true) && get32(blk + 24) == blocks &&
           get32(blk + 32) == first_lba && blk[36] == SD_LOG_RECORD_BYTES && blk[37] == SD_LOG_RECORDS_PER_BLOCK;
}

/* The card LBA of block `index`. */
uint32_t sd_log_lba(const sd_log_t *l, uint32_t index)
{
    return l->part_lba[index / l->blocks] + index % l->blocks;
}

/* The block after `index`, past the next part's header. */
static uint32_t after(const sd_log_t *l, uint32_t index)
{
    index++;
    return index % l->blocks == 0u ? index + 1u : index;
}

/* Blocks the log can still take: those from `next` on, less the headers of the parts after it. */
uint32_t sd_log_blocks_free(const sd_log_t *l)
{
    const uint32_t total = l->parts * l->blocks;
    if (l->parts == 0u || l->next >= total) {
        return 0u;
    }
    return total - l->next - (l->parts - 1u - l->next / l->blocks);
}

/* Finds the first unwritten block of part `part` by binary search (blocks are written in order). */
static sd_attach_result_t find_end(sd_log_t *l, const sd_dev_t *dev, uint32_t part, uint32_t *end)
{
    uint8_t *const blk = l->block;
    uint32_t lo = 1u, hi = l->blocks;
    while (lo < hi) {
        const uint32_t mid = lo + (hi - lo) / 2u;
        if (!dev->read(dev->ctx, l->part_lba[part] + mid, blk)) {
            return SD_ATTACH_READ_ERROR;
        }
        if (block_valid(blk, l->file_id, part * l->blocks + mid, false)) {
            lo = mid + 1u;
        } else {
            hi = mid;
        }
    }
    *end = lo < l->blocks ? part * l->blocks + lo : (part + 1u) * l->blocks + 1u;
    return SD_ATTACH_OK;
}

/* Checks the first part's header and finds the end of the log by binary search; OPEN (or FULL) on success. */
sd_attach_result_t sd_log_attach(sd_log_t *l, const sd_dev_t *dev, uint32_t first_lba,
                                 uint32_t blocks)
{
    if (blocks < 2u) {
        return SD_ATTACH_TOO_SMALL;
    }
    uint8_t *const blk = l->block;
    if (!dev->read(dev->ctx, first_lba, blk)) {
        return SD_ATTACH_READ_ERROR;
    }
    /* Block 0 names the file; its LBA and length must be where it was found, so a copied header is
     * not taken. */
    const uint64_t file_id = get64(blk + 8);
    if (!header_ok(blk, file_id, 0u, first_lba, blocks)) {
        return SD_ATTACH_NOT_OURS;
    }
    l->part_lba[0] = first_lba;
    l->parts       = 1u;
    l->blocks      = blocks;
    l->file_id     = file_id;
    /* Blocks are written in order, so the end of the log is the first invalid block. */
    uint32_t lo;
    const sd_attach_result_t found = find_end(l, dev, 0u, &lo);
    if (found != SD_ATTACH_OK) {
        l->parts = 0u;
        return found;
    }

    l->dev        = *dev;
    l->next       = lo;
    l->boot_first = lo;
    l->held       = 0u;
    l->held_since_us = 0u;
    l->fails_in_row  = 0u;
    memset(l->block, 0, sizeof(l->block));
    memset(l->stream, 0, sizeof(l->stream));
    l->stream_used = l->stream_starts = l->stream_ends = 0u;
    l->stream_first = SD_STREAM_NONE;
    l->stream_since_us = 0u;
    l->item_len = l->item_pos = 0u;
    l->state = lo >= blocks ? SD_LOG_FULL : SD_LOG_OPEN;
    return SD_ATTACH_OK;
}

/* Adds the next part; a log that had filled runs on into it, from its end if it was written before. */
sd_attach_result_t sd_log_add_part(sd_log_t *l, uint32_t first_lba)
{
    if ((l->state != SD_LOG_OPEN && l->state != SD_LOG_FULL) || l->parts >= SD_LOG_MAX_PARTS || l->held != 0u ||
        l->stream_used != 0u || sd_log_sector_pending(l) || l->blocks_written != 0u) {
        return SD_ATTACH_NOT_OURS;
    }
    uint8_t *const blk = l->block;
    const uint32_t part = l->parts;
    if (!l->dev.read(l->dev.ctx, first_lba, blk)) {
        return SD_ATTACH_READ_ERROR;
    }
    const bool ok = header_ok(blk, l->file_id, part, first_lba, l->blocks);
    memset(blk, 0, SD_LOG_BLOCK_BYTES);
    if (!ok) {
        return SD_ATTACH_NOT_OURS;
    }
    l->part_lba[part] = first_lba;
    l->parts++;
    if (l->state == SD_LOG_FULL) {
        uint32_t end;
        const sd_attach_result_t found = find_end(l, &l->dev, part, &end);
        memset(blk, 0, SD_LOG_BLOCK_BYTES);
        if (found != SD_ATTACH_OK) {
            l->parts--;
            return found;
        }
        l->next = l->boot_first = end;
        l->state = end >= l->parts * l->blocks ? SD_LOG_FULL : SD_LOG_OPEN;
    }
    return SD_ATTACH_OK;
}

/* Sets the cipher key and this boot's tag, so blocks are written encrypted (version 3). */
void sd_log_set_key(sd_log_t *l, const uint8_t key[32], uint8_t boot_tag)
{
    l->cipher_key = key;
    l->boot_tag = boot_tag;
}

/* Decrypts a valid version 3 block; false if there is no key to read it with. */
static bool open_block(const sd_log_t *l, uint8_t blk[SD_LOG_BLOCK_BYTES])
{
    if (blk[21] != SD_LOG_VERSION_ENC) {
        return true;
    }
    if (l->cipher_key == NULL) {
        return false;
    }
    crypt_payload(l->cipher_key, blk);
    return true;
}

/* Turns the card log off for the session, counting what it held as lost. */
void sd_log_set_off(sd_log_t *l)
{
    l->records_lost += l->held;
    l->held  = 0u;
    /* Sectors ending in the unwritten stream block, and one still waiting. */
    l->sectors_lost += l->stream_ends + (sd_log_sector_pending(l) ? 1u : 0u);
    l->stream_used = l->stream_starts = l->stream_ends = 0u;
    l->item_len = l->item_pos = 0u;
    l->state = SD_LOG_OFF;
}

/* ---- writing --------------------------------------------------------- */

/* Seals `blk` as block `next` and writes it; the caller keeps what it held for a retry unless the
 * card is gone. */
static bool put_block(sd_log_t *l, uint8_t *blk, uint8_t count, uint8_t kind, uint32_t extra)
{
    seal(blk, l->file_id, l->next, count, kind, extra, l->cipher_key, l->boot_tag);
    if (!l->dev.write(l->dev.ctx, sd_log_lba(l, l->next), blk)) {
        if (l->cipher_key != NULL) {
            crypt_payload(l->cipher_key, blk);   /* plain again, for the retry */
        }
        l->write_errors++;
        if (++l->fails_in_row >= SD_LOG_MAX_WRITE_RETRIES) {
            sd_log_set_off(l);
        }
        return false;
    }
    l->fails_in_row = 0u;
    l->blocks_written++;
    l->next = after(l, l->next);
    if (l->next >= l->parts * l->blocks) {
        l->state = SD_LOG_FULL;
    }
    return true;
}

/* Writes the record block being filled. */
static bool write_block(sd_log_t *l)
{
    if (!put_block(l, l->block, (uint8_t)l->held, SD_KIND_RECORDS, 0u)) {
        return false;
    }
    if (l->held < SD_LOG_RECORDS_PER_BLOCK) {
        l->partial_blocks++;
    }
    l->held = 0u;
    l->held_since_us = 0u;
    memset(l->block, 0, sizeof(l->block));   /* a partial block's unused slots stay zero */
    return true;
}

/* Writes the stream block, full or (timer, sync) partly filled. */
static bool write_stream(sd_log_t *l)
{
    const uint32_t extra = (l->stream_first & 0xFFFFu) | (l->stream_used << 16);
    if (!put_block(l, l->stream, (uint8_t)l->stream_starts, SD_KIND_STREAM, extra)) {
        return false;
    }
    if (l->stream_used < SD_STREAM_PAYLOAD) {
        l->partial_blocks++;
    }
    l->sectors_written += l->stream_ends;
    l->stream_used = l->stream_starts = l->stream_ends = 0u;
    l->stream_first = SD_STREAM_NONE;
    l->stream_since_us = 0u;
    memset(l->stream, 0, sizeof(l->stream));
    return true;
}

/* Copies as much of the waiting sector as fits into the stream block. */
static void stream_fill(sd_log_t *l)
{
    if (!sd_log_sector_pending(l) || l->stream_used == SD_STREAM_PAYLOAD) {
        return;
    }
    if (l->item_pos == 0u) {
        if (l->stream_first == SD_STREAM_NONE) {
            l->stream_first = l->stream_used;
        }
        l->stream_starts++;
    }
    uint32_t n = SD_STREAM_PAYLOAD - l->stream_used;
    if (n > l->item_len - l->item_pos) {
        n = l->item_len - l->item_pos;
    }
    memcpy(l->stream + SD_LOG_HEADER_BYTES + l->stream_used, l->item + l->item_pos, n);
    l->stream_used += n;
    l->item_pos += n;
    if (!sd_log_sector_pending(l)) {
        l->stream_ends++;
    }
}

/* Fills the stream block from the waiting sector and writes it once full, if the card is idle. */
static void stream_progress(sd_log_t *l)
{
    for (;;) {
        stream_fill(l);
        if (l->stream_used < SD_STREAM_PAYLOAD || !l->dev.ready(l->dev.ctx) || !write_stream(l) ||
            l->state != SD_LOG_OPEN) {
            return;
        }
    }
}

/* A sector's length with its trailing zero bytes left off. */
static uint32_t trimmed(const uint8_t *bytes, uint32_t n)
{
    while (n != 0u && bytes[n - 1u] == 0u) {
        n--;
    }
    return n;
}

/* Takes one metadata sector (its LBA, then 512 bytes) as the next stream item, trailing zeros trimmed. */
static bool take_sector(sd_log_t *l, const uint8_t *data, uint32_t len)
{
    if (len < 8u || len > 8u + SD_LOG_SECTOR_BYTES) {
        return false;
    }
    if (l->state != SD_LOG_OPEN || sd_log_sector_pending(l)) {
        l->sectors_lost++;
        return false;
    }
    const uint32_t n = trimmed(data + 8u, len - 8u);
    l->item[0] = (uint8_t)n;
    l->item[1] = (uint8_t)(n >> 8);
    memcpy(l->item + 2u, data, 8u + n);   /* the LBA, then the sector's first n bytes */
    l->item_len = SD_STREAM_ITEM_HDR + n;
    l->item_pos = 0u;
    if (n == 0u) {
        l->sectors_zero++;
    }
    stream_progress(l);
    return true;
}

/* The store's write: a sector goes to the stream, a record into the block being filled. */
static bool sd_write(void *ctx, store_item_t kind, const uint8_t *data, uint32_t len)
{
    sd_log_t *const l = ctx;
    if (kind == STORE_ITEM_METADATA_SECTOR) {
        return take_sector(l, data, len);
    }
    if (kind != STORE_ITEM_AUDIT_RECORD || len != SD_LOG_RECORD_BYTES) {
        return false;
    }
    /* A full block still held is one whose write failed: retry it first. */
    if (l->state == SD_LOG_OPEN && l->held == SD_LOG_RECORDS_PER_BLOCK) {
        (void)write_block(l);
    }
    if (l->state != SD_LOG_OPEN || l->held == SD_LOG_RECORDS_PER_BLOCK) {
        l->records_lost++;
        return false;
    }
    memcpy(l->block + SD_LOG_HEADER_BYTES + l->held * SD_LOG_RECORD_BYTES, data, SD_LOG_RECORD_BYTES);
    l->held++;
    if (l->held == SD_LOG_RECORDS_PER_BLOCK) {
        (void)write_block(l);   /* on failure the record is still held, and retried */
    }
    return true;
}

/* Tells the FIFO in front whether the log can take an item now (the card idle, no sector waiting). */
bool sd_log_ready(void *vl)
{
    sd_log_t *const l = vl;
    if (l->state == SD_LOG_WAITING) {
        return false;
    }
    if (l->state != SD_LOG_OPEN) {
        return true;   /* refused at once */
    }
    if (sd_log_sector_pending(l)) {
        /* The FIFO's pump drives the card: with a sector waiting, the full stream block goes out
         * here once the card is idle. */
        stream_progress(l);
        if (l->state != SD_LOG_OPEN) {
            return true;   /* the card failed or filled: refused at once */
        }
        if (sd_log_sector_pending(l)) {
            return false;
        }
    }
    if (l->held + 1u < SD_LOG_RECORDS_PER_BLOCK) {
        return true;   /* a record is taken without a write; a sector is staged */
    }
    return l->dev.ready(l->dev.ctx);
}

/* Writes a block if the card is idle and one is due: a full stream block, else one that has waited SD_LOG_FLUSH_US. */
void sd_log_tick(sd_log_t *l, uint64_t now_us)
{
    if (l->state == SD_LOG_OPEN && (sd_log_sector_pending(l) || l->stream_used == SD_STREAM_PAYLOAD)) {
        stream_progress(l);
        if (l->state != SD_LOG_OPEN || sd_log_sector_pending(l) || l->stream_used == SD_STREAM_PAYLOAD) {
            return;
        }
        /* The stream is caught up: a record block may go next, if the card is still idle. */
    }
    /* A partly filled stream block waits at most SD_LOG_FLUSH_US, as records do. */
    if (l->state == SD_LOG_OPEN && l->stream_used != 0u) {
        if (l->stream_since_us == 0u) {
            l->stream_since_us = now_us | 1u;
        } else if (now_us - l->stream_since_us >= SD_LOG_FLUSH_US && l->dev.ready(l->dev.ctx)) {
            (void)write_stream(l);
        }
    } else {
        l->stream_since_us = 0u;
    }
    if (l->state != SD_LOG_OPEN || l->held == 0u) {
        l->held_since_us = 0u;
        return;
    }
    if (l->held_since_us == 0u) {
        l->held_since_us = now_us | 1u;   /* 0 means "not yet" */
        return;
    }
    if ((l->held == SD_LOG_RECORDS_PER_BLOCK || now_us - l->held_since_us >= SD_LOG_FLUSH_US) &&
        l->dev.ready(l->dev.ctx)) {
        (void)write_block(l);
    }
}

/* Blocking, at the session's end: writes everything held; the driver waits out a busy card. */
static bool sd_sync(void *ctx)
{
    sd_log_t *const l = ctx;
    /* The stream first: each pass fills a block and writes it, the last one partly filled. */
    for (uint32_t i = 0; l->state == SD_LOG_OPEN && (sd_log_sector_pending(l) || l->stream_used != 0u) &&
                         i < 4u * SD_LOG_MAX_WRITE_RETRIES;
         i++) {
        stream_fill(l);
        (void)write_stream(l);
    }
    for (uint32_t i = 0; l->state == SD_LOG_OPEN && l->held != 0u && i < SD_LOG_MAX_WRITE_RETRIES; i++) {
        (void)write_block(l);
    }
    if (l->state == SD_LOG_OPEN && (l->held != 0u || sd_log_sector_pending(l) || l->stream_used != 0u)) {
        sd_log_set_off(l);
    }
    if (l->state == SD_LOG_WAITING || l->state == SD_LOG_OFF) {
        return true;   /* nothing of ours to commit; what was lost is counted */
    }
    return l->dev.sync(l->dev.ctx);
}

/* Reads this boot's blocks back (after a sync); sectors come back as the items they were given as. */
static bool sd_for_each(void *ctx, store_item_t kind, store_visit_t visit, void *vctx)
{
    sd_log_t *const l = ctx;
    if (l->held != 0u || sd_log_sector_pending(l) || l->stream_used != 0u ||
        (l->state != SD_LOG_OPEN && l->state != SD_LOG_FULL)) {
        return false;
    }
    if (kind != STORE_ITEM_AUDIT_RECORD && kind != STORE_ITEM_METADATA_SECTOR) {
        return true;
    }
    uint8_t *const blk = l->block;
    uint8_t *const it = l->item;
    uint32_t have = 0u, need = SD_STREAM_ITEM_HDR;
    bool ok = true, more = true;
    for (uint32_t i = l->boot_first; i < l->next && ok && more; i = after(l, i)) {
        if (!l->dev.read(l->dev.ctx, sd_log_lba(l, i), blk) || !block_valid(blk, l->file_id, i, false) ||
            !open_block(l, blk)) {
            ok = false;
            break;
        }
        const uint8_t bk = blk[22];
        if (kind == STORE_ITEM_AUDIT_RECORD) {
            for (uint32_t r = 0; bk == SD_KIND_RECORDS && r < blk[20] && more; r++) {
                more = visit(vctx, blk + SD_LOG_HEADER_BYTES + r * SD_LOG_RECORD_BYTES, SD_LOG_RECORD_BYTES);
            }
            continue;
        }
        if (bk == SD_KIND_RECORDS || bk == SD_KIND_BLOB) {
            continue;
        }
        if (bk != SD_KIND_STREAM) {
            ok = false;   /* kinds 1-4 are an older format, no longer written */
            break;
        }
        const uint32_t used = get16(blk + 26);
        uint32_t starts = 0u, first = SD_STREAM_NONE;
        for (uint32_t p = 0; p < used && ok && more; p++) {
            if (have == 0u) {
                starts++;
                first = first == SD_STREAM_NONE ? p : first;
            }
            it[have++] = blk[SD_LOG_HEADER_BYTES + p];
            if (have == 2u) {
                need = SD_STREAM_ITEM_HDR + get16(it);
                ok = need <= SD_STREAM_ITEM_MAX;
            }
            if (have == need) {
                more = visit(vctx, it + 2u, need - 2u);
                have = 0u;
                need = SD_STREAM_ITEM_HDR;
            }
        }
        ok = ok && (!more || (starts == blk[20] && first == get16(blk + 24)));
    }
    ok = ok && (!more || have == 0u);   /* the session's stream ends on an item boundary */
    memset(blk, 0, SD_LOG_BLOCK_BYTES);
    l->item_len = l->item_pos = 0u;
    return ok;
}

/* Walks every record on the card, every session, for the boot-time chain check. */
bool sd_log_for_each_record_all(sd_log_t *l, store_visit_t visit, void *vctx, uint32_t *blocks_read)
{
    *blocks_read = 0u;
    if (l->held != 0u || sd_log_sector_pending(l) || l->stream_used != 0u ||
        (l->state != SD_LOG_OPEN && l->state != SD_LOG_FULL)) {
        return false;
    }
    uint8_t *const blk = l->block;
    bool ok = true, more = true;
    for (uint32_t i = 1u; i < l->next && more; i = after(l, i)) {
        (*blocks_read)++;
        if (!l->dev.read(l->dev.ctx, sd_log_lba(l, i), blk) || !block_valid(blk, l->file_id, i, false) ||
            !open_block(l, blk)) {
            ok = false;   /* every block before `next` was valid when the end was found */
            break;
        }
        for (uint32_t r = 0; blk[22] == SD_KIND_RECORDS && r < blk[20] && more; r++) {
            more = visit(vctx, blk + SD_LOG_HEADER_BYTES + r * SD_LOG_RECORD_BYTES, SD_LOG_RECORD_BYTES);
        }
    }
    memset(blk, 0, SD_LOG_BLOCK_BYTES);
    return ok;
}

/* ---- blobs ----------------------------------------------------------- */

/* Starts a blob at the next block; false if the card is not open. */
bool sd_blob_begin(sd_blob_writer_t *w, sd_log_t *l)
{
    memset(w, 0, sizeof(*w));
    w->l     = l;
    w->first = l->next;
    w->ok    = l->state == SD_LOG_OPEN;
    return w->ok;
}

/* Writes the block being filled, retried until it is on the card or the card is given up. */
static void blob_flush(sd_blob_writer_t *w)
{
    sd_log_t *const l = w->l;
    const uint32_t extra = (w->number & 0xFFFFu) | (w->used << 16);
    while (w->ok && !put_block(l, w->blk, w->number == 0u ? 1u : 0u, SD_KIND_BLOB, extra)) {
        w->ok = l->state == SD_LOG_OPEN;
    }
    w->ok = w->ok && w->number < 0xFFFFu;
    w->number++;
    w->used = 0u;
    memset(w->blk, 0, sizeof(w->blk));
}

/* Adds bytes to the blob, writing each block as it fills. */
void sd_blob_put(void *vw, const uint8_t *bytes, uint32_t len)
{
    sd_blob_writer_t *const w = vw;
    w->bytes += len;
    while (w->ok && len != 0u) {
        if (w->l->state != SD_LOG_OPEN) {
            w->ok = false;   /* the card filled or failed */
            break;
        }
        uint32_t n = SD_STREAM_PAYLOAD - w->used;
        if (n > len) {
            n = len;
        }
        memcpy(w->blk + SD_LOG_HEADER_BYTES + w->used, bytes, n);
        w->used += n;
        bytes += n;
        len -= n;
        if (w->used == SD_STREAM_PAYLOAD) {
            blob_flush(w);
        }
    }
}

/* Writes the blob's last, partly filled block; true if every block reached the card. */
bool sd_blob_end(sd_blob_writer_t *w)
{
    if (w->ok && w->used != 0u) {
        if (w->l->state != SD_LOG_OPEN) {
            w->ok = false;
        } else {
            blob_flush(w);
        }
    }
    return w->ok && w->number != 0u;
}

/* Reads block `index` into the reader: valid, a blob block, numbered `number`. */
static bool blob_read(sd_blob_reader_t *r, uint32_t index, uint32_t number)
{
    sd_log_t *const l = r->l;
    if (index % l->blocks == 0u || index >= l->next) {
        return false;
    }
    r->blocks_read++;
    if (!l->dev.read(l->dev.ctx, sd_log_lba(l, index), r->blk) || !block_valid(r->blk, l->file_id, index, false) ||
        r->blk[22] != SD_KIND_BLOB || get16(r->blk + 24) != number || !open_block(l, r->blk)) {
        return false;
    }
    r->index  = index;
    r->number = number;
    r->pos    = 0u;
    r->used   = get16(r->blk + 26);
    return true;
}

/* Opens the blob that starts at block `first` for reading. */
bool sd_blob_open(sd_blob_reader_t *r, sd_log_t *l, uint32_t first)
{
    memset(r, 0, sizeof(*r));
    r->l = l;
    return (l->state == SD_LOG_OPEN || l->state == SD_LOG_FULL) && blob_read(r, first, 0u);
}

/* Reads the blob's next len bytes, following its blocks; false if it ends first or a block is bad. */
bool sd_blob_get(void *vr, uint8_t *bytes, uint32_t len)
{
    sd_blob_reader_t *const r = vr;
    while (len != 0u) {
        if (r->pos == r->used) {
            /* Only a full block goes on: a partly filled one is the blob's last. */
            if (r->used != SD_STREAM_PAYLOAD || !blob_read(r, after(r->l, r->index), r->number + 1u)) {
                return false;
            }
        }
        uint32_t n = r->used - r->pos;
        if (n > len) {
            n = len;
        }
        memcpy(bytes, r->blk + SD_LOG_HEADER_BYTES + r->pos, n);
        r->pos += n;
        bytes += n;
        len -= n;
    }
    return true;
}

/* Makes `b` the store backend that writes to this log. */
void sd_log_backend(sd_log_t *l, store_backend_t *b)
{
    memset(b, 0, sizeof(*b));
    b->name     = "sd";
    b->write    = sd_write;
    b->sync     = sd_sync;
    b->for_each = sd_for_each;
    b->ctx      = l;
}
