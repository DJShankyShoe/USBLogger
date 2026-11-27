/*
 * Pairs each Bulk-Only CBW with its CSW and turns the CDB into a SCSI command (op, LBA, block
 * count).
 */

/* printf for the stats line; memset. */
#include <stdio.h>
#include <string.h>

/* What this file defines. */
#include "msc_parse.h"

/* Reads a little-endian 32-bit field (CBW and CSW fields are little-endian). */
static inline uint32_t le32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

/* Reads a big-endian 32-bit field (CDB fields are big-endian). */
static inline uint32_t be32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

/* Reads a big-endian 16-bit field. */
static inline uint16_t be16(const uint8_t *p)
{
    return (uint16_t)(((uint16_t)p[0] << 8) | p[1]);
}

/* Reads a big-endian 64-bit field (the 16-byte CDBs' LBA). */
static inline uint64_t be64(const uint8_t *p)
{
    return ((uint64_t)be32(p) << 32) | be32(p + 4);
}

/* Gives an operation's name as the console prints it ("READ", "WRITE", ...). */
const char *msc_op_name(msc_op_t op)
{
    switch (op) {
    case MSC_OP_READ:     return "READ";
    case MSC_OP_WRITE:    return "WRITE";
    case MSC_OP_QUERY:    return "QUERY";
    case MSC_OP_FLUSH:    return "FLUSH";
    case MSC_OP_LOCK:     return "LOCK";
    case MSC_OP_UNLOCK:   return "UNLOCK";
    case MSC_OP_EJECT:    return "EJECT";
    case MSC_OP_LOAD:     return "LOAD";
    case MSC_OP_STOP:     return "STOP";
    case MSC_OP_START:    return "START";
    case MSC_OP_VERIFY:   return "VERIFY";
    case MSC_OP_TRIM:     return "TRIM";
    case MSC_OP_FORMAT:   return "FORMAT";
    case MSC_OP_SETTINGS: return "SETTINGS";
    default:              return "OTHER";
    }
}

/* The sector-range opcodes' meaning: READ, WRITE, VERIFY and SYNCHRONIZE CACHE share a layout per
 * CDB size. */
static msc_op_t range_op(uint8_t opcode)
{
    switch (opcode) {
    case SCSI_READ_6:
    case SCSI_READ_10:
    case SCSI_READ_12:
    case SCSI_READ_16:
        return MSC_OP_READ;
    case SCSI_VERIFY_10:
    case SCSI_VERIFY_12:
    case SCSI_VERIFY_16:
        return MSC_OP_VERIFY;
    case SCSI_SYNC_CACHE_10:
    case SCSI_SYNC_CACHE_16:
        return MSC_OP_FLUSH;
    default:
        return MSC_OP_WRITE;   /* WRITE, WRITE AND VERIFY, WRITE SAME */
    }
}

/* Fills op, lba, block_count and cdb_flags from the command block; a CDB too short stays
 * MSC_OP_OTHER. */
static void parse_cdb(msc_command_t *cmd, const uint8_t *cdb, uint8_t cdb_len)
{
    cmd->opcode    = cdb[0];
    cmd->op        = MSC_OP_OTHER;
    cmd->lba_valid = false;
    cmd->cdb_flags = 0;

    switch (cdb[0]) {
    /* Sector ranges, 6-byte CDB: 21-bit LBA, 8-bit count. */
    case SCSI_READ_6:
    case SCSI_WRITE_6:
        if (cdb_len < 6) {
            return;
        }
        cmd->op = range_op(cdb[0]);
        cmd->lba = ((uint32_t)(cdb[1] & 0x1Fu) << 16) |
                   ((uint32_t)cdb[2] << 8) | cdb[3];
        /* A transfer length of zero means 256 blocks in the 6-byte forms. */
        cmd->block_count = cdb[4] ? cdb[4] : 256u;
        cmd->lba_valid = true;
        break;

    /* Sector ranges, 10-byte CDB: 32-bit LBA at byte 2, 16-bit count at 7. */
    case SCSI_READ_10:
    case SCSI_WRITE_10:
    case SCSI_WRITE_VERIFY_10:
    case SCSI_WRITE_SAME_10:
    case SCSI_VERIFY_10:
    case SCSI_SYNC_CACHE_10:
        if (cdb_len < 10) {
            return;
        }
        cmd->op = range_op(cdb[0]);
        cmd->lba = be32(&cdb[2]);
        cmd->block_count = be16(&cdb[7]);
        cmd->lba_valid = true;
        break;

    /* Sector ranges, 12-byte CDB: 32-bit LBA at byte 2, 32-bit count at 6. */
    case SCSI_READ_12:
    case SCSI_WRITE_12:
    case SCSI_WRITE_VERIFY_12:
    case SCSI_VERIFY_12:
        if (cdb_len < 12) {
            return;
        }
        cmd->op = range_op(cdb[0]);
        cmd->lba = be32(&cdb[2]);
        cmd->block_count = be32(&cdb[6]);
        cmd->lba_valid = true;
        break;

    /* Sector ranges, 16-byte CDB: 64-bit LBA at byte 2, 32-bit count at 10. */
    case SCSI_READ_16:
    case SCSI_WRITE_16:
    case SCSI_WRITE_VERIFY_16:
    case SCSI_WRITE_SAME_16:
    case SCSI_VERIFY_16:
    case SCSI_SYNC_CACHE_16:
        if (cdb_len < 16) {
            return;
        }
        cmd->op = range_op(cdb[0]);
        cmd->lba = be64(&cdb[2]);
        cmd->block_count = be32(&cdb[10]);
        cmd->lba_valid = true;
        break;

    /* The host asking about the drive. */
    case SCSI_TEST_UNIT_READY:
    case SCSI_REQUEST_SENSE:
    case SCSI_INQUIRY:
    case SCSI_MODE_SENSE_6:
    case SCSI_READ_FORMAT_CAPACITIES:
    case SCSI_READ_CAPACITY:
    case SCSI_MODE_SENSE_10:
    case SCSI_SERVICE_ACTION_IN_16:
        cmd->op = MSC_OP_QUERY;
        break;

    /* Byte 4: bit 0 START, bit 1 LOEJ, bits 7-4 power condition (non-zero: START and LOEJ ignored,
     * so OTHER). */
    case SCSI_START_STOP_UNIT:
        if (cdb_len < 5) {
            return;
        }
        cmd->cdb_flags = cdb[4];
        if ((cdb[4] & 0xF0u) == 0u) {
            static const msc_op_t start_stop[4] = {
                MSC_OP_STOP, MSC_OP_START, MSC_OP_EJECT, MSC_OP_LOAD,
            };
            cmd->op = start_stop[cdb[4] & 0x03u];
        }
        break;

    /* Byte 4, bits 1-0 PREVENT: 00 allows removal, anything else prevents. */
    case SCSI_PREVENT_ALLOW_REMOVAL:
        if (cdb_len < 5) {
            return;
        }
        cmd->cdb_flags = cdb[4];
        cmd->op = (cdb[4] & 0x03u) ? MSC_OP_LOCK : MSC_OP_UNLOCK;
        break;

    case SCSI_UNMAP:
        cmd->op = MSC_OP_TRIM;
        break;

    case SCSI_FORMAT_UNIT:
        cmd->op = MSC_OP_FORMAT;
        break;

    case SCSI_MODE_SELECT_6:
    case SCSI_MODE_SELECT_10:
        cmd->op = MSC_OP_SETTINGS;
        break;

    default:
        break;
    }
}

/* Starts a parser with no pending commands and the default timeout. */
void msc_parser_init(msc_parser_t *p, msc_command_cb_t cb, void *ctx)
{
    memset(p, 0, sizeof(*p));
    p->on_command = cb;
    p->ctx = ctx;
    p->timeout_ns = MSC_DEFAULT_TIMEOUT_NS;
    p->next_expiry_ns = UINT64_MAX;
}

/* Counts a finished (or given-up) command and hands it to the callback. */
static void USB_TIME_CRITICAL emit(msc_parser_t *p, const msc_command_t *cmd)
{
    if (cmd->op == MSC_OP_READ) {
        p->read_commands++;
        p->blocks_read += cmd->block_count;
    } else if (cmd->op == MSC_OP_WRITE) {
        p->write_commands++;
        p->blocks_written += cmd->block_count;
    }
    if (p->on_command) {
        p->on_command(cmd, p->ctx);
    }
}

/* Finds the pending command with this tag; -1 if there is none. */
static int USB_TIME_CRITICAL find_slot_by_tag(const msc_parser_t *p, uint32_t tag)
{
    for (int i = 0; i < MSC_MAX_PENDING; i++) {
        if (p->slot_used[i] && p->pending[i].tag == tag) {
            return i;
        }
    }
    return -1;
}

/* Finds a free slot for a new command, evicting the oldest when all are in use. */
static int alloc_slot(msc_parser_t *p)
{
    for (int i = 0; i < MSC_MAX_PENDING; i++) {
        if (!p->slot_used[i]) {
            return i;
        }
    }

    /* Full: the oldest outstanding command is reported unfinished, so a lost CSW leaves a visible
     * gap. */
    int oldest = 0;
    for (int i = 1; i < MSC_MAX_PENDING; i++) {
        if (p->slot_seq[i] < p->slot_seq[oldest]) {
            oldest = i;
        }
    }
    p->evicted++;
    p->pending[oldest].completed = false;
    emit(p, &p->pending[oldest]);
    p->slot_used[oldest] = false;
    return oldest;
}

/* Starts a pending command from a CBW (a re-sent one is counted, not added twice). */
static void handle_cbw(msc_parser_t *p, const usb_packet_t *pkt)
{
    const uint8_t *b = pkt->payload;
    uint32_t tag = le32(&b[4]);

    /* A CBW re-sent after a NAK carries the same tag and opcode: the same command. */
    int existing = find_slot_by_tag(p, tag);
    if (existing >= 0 && p->pending[existing].opcode == b[15]) {
        p->duplicate_cbw++;
        return;
    }

    int slot = alloc_slot(p);
    msc_command_t *cmd = &p->pending[slot];
    /* Not memset: it is in flash, and this runs on the capture core. */
    usb_zero_bytes((uint8_t *)cmd, sizeof(*cmd));

    cmd->ts_cbw_ns = pkt->timestamp_ns;
    cmd->tag       = tag;
    cmd->data_len  = le32(&b[8]);
    cmd->data_in   = (b[12] & 0x80u) != 0u;
    cmd->lun       = b[13] & 0x0Fu;
    cmd->dev_addr  = p->have_token ? p->last_addr : 0xFFu;
    cmd->endpoint  = p->have_token ? p->last_ep : 0xFFu;

    uint8_t cdb_len = b[14] & 0x1Fu;
    if (cdb_len > 16u) {
        cdb_len = 16u;
    }
    parse_cdb(cmd, &b[15], cdb_len);

    p->slot_used[slot] = true;
    p->slot_seq[slot]  = ++p->seq;
    p->cbw_count++;

    if (cmd->ts_cbw_ns + p->timeout_ns < p->next_expiry_ns) {
        p->next_expiry_ns = cmd->ts_cbw_ns + p->timeout_ns;
    }
}

/* Completes the pending command a CSW answers, or counts the CSW as an orphan. */
static void handle_csw(msc_parser_t *p, const usb_packet_t *pkt)
{
    const uint8_t *b = pkt->payload;
    uint32_t tag = le32(&b[4]);

    p->csw_count++;

    int slot = find_slot_by_tag(p, tag);
    if (slot < 0) {
        p->orphan_csw++;
        return;
    }

    msc_command_t *cmd = &p->pending[slot];
    cmd->ts_csw_ns = pkt->timestamp_ns;
    cmd->residue   = le32(&b[8]);
    cmd->status    = b[12];
    cmd->completed = true;

    emit(p, cmd);
    p->slot_used[slot] = false;
}

/* Closes out commands whose status never came, so a later CSW reusing the tag cannot pair with a
 * stale one. */
static void expire_pending(msc_parser_t *p, uint64_t now_ns)
{
    if (p->timeout_ns == 0) {
        return;
    }
    /* Nothing can expire before next_expiry_ns, so the scan below runs only when one might. */
    if (now_ns <= p->next_expiry_ns) {
        return;
    }
    /* Oldest first, so the log's order follows the bus, not the table's slots. */
    for (;;) {
        int oldest = -1;
        for (int i = 0; i < MSC_MAX_PENDING; i++) {
            if (!p->slot_used[i]) {
                continue;
            }
            uint64_t started = p->pending[i].ts_cbw_ns;
            if (now_ns > started && (now_ns - started) > p->timeout_ns &&
                (oldest < 0 || p->slot_seq[i] < p->slot_seq[oldest])) {
                oldest = i;
            }
        }
        if (oldest < 0) {
            break;
        }
        p->timed_out++;
        p->pending[oldest].completed = false;
        emit(p, &p->pending[oldest]);
        p->slot_used[oldest] = false;
    }

    /* The earliest expiry of the commands still pending. */
    p->next_expiry_ns = UINT64_MAX;
    for (int i = 0; i < MSC_MAX_PENDING; i++) {
        if (p->slot_used[i] &&
            p->pending[i].ts_cbw_ns + p->timeout_ns < p->next_expiry_ns) {
            p->next_expiry_ns = p->pending[i].ts_cbw_ns + p->timeout_ns;
        }
    }
}

/* Takes one decoded packet: notes tokens, and passes CBWs and CSWs on. */
void USB_TIME_CRITICAL msc_parser_feed(msc_parser_t *p, const usb_packet_t *pkt)
{
    /* Only trust packets that decoded cleanly. */
    if (pkt->status != USB_DEC_OK) {
        return;
    }

    expire_pending(p, pkt->timestamp_ns);

    if (pkt->type == USB_PKT_TYPE_TOKEN) {
        if (pkt->pid == USB_PID_IN || pkt->pid == USB_PID_OUT) {
            p->last_addr   = pkt->addr;
            p->last_ep     = pkt->endpoint;
            p->last_was_in = (pkt->pid == USB_PID_IN);
            p->have_token  = true;
        }
        return;
    }

    if (pkt->type != USB_PKT_TYPE_DATA || !pkt->crc_ok) {
        return;
    }

    /* CBW and CSW are told by signature and exact length, not by the interface descriptors. */
    if (pkt->payload_len == MSC_CBW_LENGTH &&
        le32(pkt->payload) == MSC_CBW_SIGNATURE) {
        handle_cbw(p, pkt);
    } else if (pkt->payload_len == MSC_CSW_LENGTH &&
               le32(pkt->payload) == MSC_CSW_SIGNATURE) {
        handle_csw(p, pkt);
    }
}

/* Emits every command still pending as incomplete, oldest first (at the session's end). */
void msc_parser_flush(msc_parser_t *p)
{
    /* Oldest first, for the same reason as expire_pending(). */
    for (;;) {
        int oldest = -1;
        for (int i = 0; i < MSC_MAX_PENDING; i++) {
            if (p->slot_used[i] && (oldest < 0 || p->slot_seq[i] < p->slot_seq[oldest])) {
                oldest = i;
            }
        }
        if (oldest < 0) {
            return;
        }
        p->pending[oldest].completed = false;
        emit(p, &p->pending[oldest]);
        p->slot_used[oldest] = false;
    }
}

/* Prints the [msc] line: CBWs, CSWs, duplicates, orphans, evictions, timeouts. */
void msc_parser_print_stats(const msc_parser_t *p)
{
    printf("[msc]   cbw=%llu csw=%llu dup=%llu orphan=%llu evicted=%llu "
           "timed_out=%llu\n",
           (unsigned long long)p->cbw_count,
           (unsigned long long)p->csw_count,
           (unsigned long long)p->duplicate_cbw,
           (unsigned long long)p->orphan_csw,
           (unsigned long long)p->evicted,
           (unsigned long long)p->timed_out);
    printf("        reads=%llu (%llu blocks)  writes=%llu (%llu blocks)\n",
           (unsigned long long)p->read_commands,
           (unsigned long long)p->blocks_read,
           (unsigned long long)p->write_commands,
           (unsigned long long)p->blocks_written);
}
