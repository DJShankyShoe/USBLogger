/*
 * The USB Mass Storage (Bulk-Only) command parser: pairs each CBW with its CSW by tag and gives one
 * msc_command_t per SCSI command. It takes only decoded packets, so it lifts to Phase 2 unchanged.
 */
#ifndef MSC_PARSE_H
#define MSC_PARSE_H

/* The decoded packet this parser consumes. */
#include "usb_proto.h"

/* Bulk-Only Transport wrappers (USB MSC BOT 1.0). */
#define MSC_CBW_SIGNATURE 0x43425355u   /* 'USBC' */
#define MSC_CSW_SIGNATURE 0x53425355u   /* 'USBS' */
#define MSC_CBW_LENGTH    31u           /* a command block wrapper, in bytes */
#define MSC_CSW_LENGTH    13u           /* a command status wrapper, in bytes */

/* SCSI opcodes classified; any other is MSC_OP_OTHER with its opcode kept, so no command is
 * dropped. */
#define SCSI_TEST_UNIT_READY        0x00   /* is the drive ready? */
#define SCSI_REQUEST_SENSE          0x03   /* why did the last command fail? */
#define SCSI_FORMAT_UNIT            0x04   /* rewrite the whole medium */
#define SCSI_READ_6                 0x08   /* read sectors (6-byte command) */
#define SCSI_WRITE_6                0x0A   /* write sectors (6-byte command) */
#define SCSI_INQUIRY                0x12   /* who are you? (vendor, product) */
#define SCSI_MODE_SELECT_6          0x15   /* change device parameters */
#define SCSI_MODE_SENSE_6           0x1A   /* read device parameters */
#define SCSI_START_STOP_UNIT        0x1B   /* spin up, stop, load or eject */
#define SCSI_PREVENT_ALLOW_REMOVAL  0x1E   /* lock or unlock the medium */
#define SCSI_READ_FORMAT_CAPACITIES 0x23   /* which formats and sizes it supports */
#define SCSI_READ_CAPACITY          0x25   /* the last sector and the sector size */
#define SCSI_READ_10                0x28   /* read sectors (10-byte command) */
#define SCSI_WRITE_10               0x2A   /* write sectors (10-byte command) */
#define SCSI_WRITE_VERIFY_10        0x2E   /* write, then check what was written */
#define SCSI_VERIFY_10              0x2F   /* check sectors, no data moves */
#define SCSI_SYNC_CACHE_10          0x35   /* commit cached writes to the medium */
#define SCSI_WRITE_SAME_10          0x41   /* write one block's data over a range */
#define SCSI_UNMAP                  0x42   /* discard sectors (trim) */
#define SCSI_MODE_SELECT_10         0x55   /* change device parameters (10-byte) */
#define SCSI_MODE_SENSE_10          0x5A   /* read device parameters (10-byte) */
#define SCSI_READ_16                0x88   /* read sectors (16-byte command) */
#define SCSI_WRITE_16               0x8A   /* write sectors (16-byte command) */
#define SCSI_WRITE_VERIFY_16        0x8E   /* write and check (16-byte) */
#define SCSI_VERIFY_16              0x8F   /* check sectors (16-byte) */
#define SCSI_SYNC_CACHE_16          0x91   /* commit cached writes (16-byte) */
#define SCSI_WRITE_SAME_16          0x93   /* write one block over a range (16-byte) */
#define SCSI_SERVICE_ACTION_IN_16   0x9E   /* READ CAPACITY(16) */
#define SCSI_READ_12                0xA8   /* read sectors (12-byte command) */
#define SCSI_WRITE_12               0xAA   /* write sectors (12-byte command) */
#define SCSI_WRITE_VERIFY_12        0xAE   /* write and check (12-byte) */
#define SCSI_VERIFY_12              0xAF   /* check sectors (12-byte) */

/* What a command means for the audit trail, from its command block alone; stored in the record's
 * `op` byte (append only). */
typedef enum {
    MSC_OP_OTHER = 0,   /* anything not listed below; raw opcode is kept */
    MSC_OP_READ,        /* sectors read */
    MSC_OP_WRITE,       /* sectors modified: WRITE, WRITE AND VERIFY, WRITE SAME */
    MSC_OP_QUERY,       /* the host asking about the drive (TEST UNIT READY, INQUIRY, capacity ...) */
    MSC_OP_FLUSH,       /* SYNCHRONIZE CACHE: host committing its writes */
    MSC_OP_LOCK,        /* PREVENT MEDIUM REMOVAL: drive in use */
    MSC_OP_UNLOCK,      /* ALLOW MEDIUM REMOVAL: host says it is safe to remove */
    MSC_OP_EJECT,       /* START STOP UNIT, LoEj=1 Start=0 */
    MSC_OP_LOAD,        /* START STOP UNIT, LoEj=1 Start=1 */
    MSC_OP_STOP,        /* START STOP UNIT, LoEj=0 Start=0 */
    MSC_OP_START,       /* START STOP UNIT, LoEj=0 Start=1 */
    MSC_OP_VERIFY,      /* VERIFY: host checking sectors, no data changed */
    MSC_OP_TRIM,        /* UNMAP: sectors discarded (the ranges are in the data phase, not decoded) */
    MSC_OP_FORMAT,      /* FORMAT UNIT: the whole medium is rewritten */
    MSC_OP_SETTINGS,    /* MODE SELECT: device parameters changed */
} msc_op_t;

/* A classification's name, for the console ("READ", "EJECT", ...). */
const char *msc_op_name(msc_op_t op);

/* One SCSI command as the audit log records it: when, what, which sectors, and the drive's answer. */
typedef struct {
    uint64_t ts_cbw_ns;      /* when the command crossed the bus */
    uint64_t ts_csw_ns;      /* when its status came back (0 if never) */
    uint32_t tag;            /* dCBWTag, links CBW to CSW */

    uint8_t  dev_addr;       /* USB device address the command was sent to */
    uint8_t  endpoint;       /* bulk-OUT endpoint carrying the CBW */
    uint8_t  lun;
    uint8_t  opcode;         /* raw SCSI opcode */
    msc_op_t op;
    uint8_t  cdb_flags;      /* byte 4 of START STOP UNIT / PREVENT ALLOW MEDIUM REMOVAL, else 0 */

    bool     data_in;        /* true = device-to-host */
    bool     completed;      /* CSW was matched */
    bool     lba_valid;      /* opcode had an LBA/length we understand */

    uint64_t lba;
    uint32_t block_count;
    uint32_t data_len;       /* dCBWDataTransferLength */
    uint32_t residue;        /* dCSWDataResidue */
    uint8_t  status;         /* bCSWStatus: 0 good, 1 failed, 2 phase error */
} msc_command_t;

/* Called with each command once its status arrives (or it is closed out). */
typedef void (*msc_command_cb_t)(const msc_command_t *cmd, void *ctx);

/* Commands waiting for their status at once. */
#define MSC_MAX_PENDING 16

/* The parser: the last token's device and endpoint, the commands awaiting their status, and the
 * counts. */
typedef struct {
    /* The most recent token's address and endpoint, so a following DATA packet is attributed to a
     * device. */
    uint8_t  last_addr;
    uint8_t  last_ep;
    bool     last_was_in;
    bool     have_token;

    msc_command_t    pending[MSC_MAX_PENDING];
    bool             slot_used[MSC_MAX_PENDING];
    uint32_t         slot_seq[MSC_MAX_PENDING];  /* for oldest-first eviction */
    uint32_t         seq;

    msc_command_cb_t on_command;
    void            *ctx;

    /* Age at which a command with no CSW is closed out, so a later CSW reusing its tag cannot pair
     * with it. */
    uint64_t         timeout_ns;
    /* No pending command times out before this (UINT64_MAX: none), so the slot scan runs only when
     * one might. */
    uint64_t         next_expiry_ns;

    /* Diagnostics. */
    uint64_t cbw_count;
    uint64_t csw_count;
    uint64_t duplicate_cbw;
    uint64_t orphan_csw;
    uint64_t evicted;
    uint64_t timed_out;
    uint64_t read_commands;
    uint64_t write_commands;
    uint64_t blocks_read;
    uint64_t blocks_written;
} msc_parser_t;

/* Default age at which an unanswered command is closed out as incomplete. */
#define MSC_DEFAULT_TIMEOUT_NS 2000000000ull   /* 2 seconds */

/* Starts a parser that reports commands through `cb`, with the default timeout. */
void msc_parser_init(msc_parser_t *p, msc_command_cb_t cb, void *ctx);

/* Feeds one decoded packet; packets that failed decode are ignored. */
void msc_parser_feed(msc_parser_t *p, const usb_packet_t *pkt);

/* Emits every pending command as incomplete; call at shutdown or after a bus reset. */
void msc_parser_flush(msc_parser_t *p);

/* Prints the parser's counts (the [msc] line). */
void msc_parser_print_stats(const msc_parser_t *p);

#endif /* MSC_PARSE_H */
