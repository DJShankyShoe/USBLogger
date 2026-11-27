/*
 * Filesystem metadata sectors, from the bus to core0. core1 copies the sample words of small READ and
 * WRITE transfers (1-16 sectors) into a ring, undecoded; core0 decodes them with a never-skipping build
 * of the decoder and reassembles each transfer's data. A hole in the copy makes a transfer incomplete.
 */
#ifndef META_CAPTURE_H
#define META_CAPTURE_H

/* The parser's commands, the capture ring and the decoder this module uses. */
#include "msc_parse.h"
#include "usb_capture.h"
#include "usb_decode.h"

#define META_MAX_BLOCKS    16u   /* the longest transfer copied, in sectors */
#define META_SECTOR_BYTES  512u  /* bytes per sector */
#define META_MAX_BYTES     (META_MAX_BLOCKS * META_SECTOR_BYTES)   /* the most data one transfer brings */

/* Window over which peak copy demand is measured: 2^15 sample words (~10.9 ms of bus). */
#define META_WIN_SHIFT 15u
/* A window counts as loaded when three quarters of its words were copied. */
#define META_WIN_LOADED ((1u << META_WIN_SHIFT) * 3u / 4u)

/* Chunk layout in the word ring: magic | flags, word count n, first word index (low, high), then n
 * words. */
#define META_CHUNK_HEADER_WORDS 4u
#define META_CHUNK_MAGIC        0x4D430000u   /* "MC" in the header's top half */
#define META_CHUNK_MAGIC_MASK   0xFFFF0000u   /* the bits the magic occupies */
#define META_CHUNK_BREAK        0x0001u   /* a capture drop or resync came before these words */

/* Directory extents core0's exFAT model asks core1 to copy. */
#define META_MAX_RANGES 32u

/* ---- core1 -> core0 link --------------------------------------------- */

/* The ring core1 copies sample words into and core0 reads them from, with its counts. */
typedef struct {
    volatile uint32_t *ring;    /* the words; volatile, so they are stored before the head moves */
    uint32_t           size;    /* words, any size; holds size - 1 */
    volatile uint32_t  head;    /* index below size, written by core1 only */
    volatile uint32_t  tail;    /* index below size, written by core0 only; head == tail: empty */

    /* Interest table (core0 writes, core1 reads): an odd or changed version means "copy", so a torn
     * read copies too much. */
    volatile uint32_t  interest_version;
    volatile uint32_t  interest_count;
    volatile bool      interest_active;
    /* Until the volume is known, only single-sector transfers qualify (the mount's MBR and boot
     * sector reads). */
    volatile bool      single_block_until_known;
    struct {
        volatile uint32_t lba_lo;
        volatile uint32_t lba_hi;
        volatile uint32_t sectors;
    } interest[META_MAX_RANGES];

    /* The busiest window of bus time, in words core1 needed to copy (wanted, not fitted), for the
     * stats. */
    uint64_t win_index;         /* which window the counting belongs to */
    uint32_t win_words;         /* words wanted in it so far */
    uint32_t win_peak;          /* the most any window has wanted */
    /* How long the demand stays high: windows where core1 needed more than META_WIN_LOADED words. */
    uint32_t win_loaded;        /* loaded windows in the session */
    uint32_t win_run;           /* loaded windows in a row, now */
    uint32_t win_run_max;       /* the longest such run */

    /* core1 only */
    bool     was_pending;       /* a qualifying command was pending after the last pass */
    bool     done_in_pass;      /* a qualifying command was emitted during this pass */
    bool     copy_next;         /* one was emitted in the last pass: copy this one too */
    bool     break_pending;     /* mark the next chunk META_CHUNK_BREAK */
    uint64_t seen_cbw;          /* parser cbw_count at the last pending scan */
    uint64_t seen_done;         /* done_count at the last pending scan */
    uint64_t done_count;        /* commands emitted by the parser */

    /* Written by core1, read by core0 for the stats line only. */
    uint64_t chunks;
    uint64_t words;
    uint64_t drops;             /* chunks that did not fit */
    uint64_t behind_skips;      /* passes not copied because core1 was behind */
    uint32_t high_water;        /* most words ever held */
} meta_link_t;

/* Starts an empty link over `storage`. */
void meta_link_init(meta_link_t *l, volatile uint32_t *storage, uint32_t size_words);

/* Words held in the link; read from the other core it may be one update stale: a threshold, never
 * an index. */
static inline uint32_t meta_link_used(const meta_link_t *l)
{
    const uint32_t h = l->head;
    const uint32_t t = l->tail;
    return h >= t ? h - t : h + l->size - t;
}

/* True for a READ or WRITE of 1..META_MAX_BLOCKS blocks that, once the table is active, overlaps a
 * range. */
bool meta_command_qualifies(const meta_link_t *l, const msc_command_t *c);

/* core0: only commands overlapping these LBA ranges qualify from now on. */
void meta_set_interest(meta_link_t *l, const uint64_t *lba, const uint32_t *sectors, uint32_t n);

/* core0, before core1 starts: until meta_set_interest, only single-sector
 * transfers qualify. */
void meta_set_single_block_until_known(meta_link_t *l);

/* core0: back to copying only single-sector transfers (the drive went away). */
void meta_clear_interest(meta_link_t *l);

/* core1, for every command the parser emits (its on_command callback). */
void meta_note_command(meta_link_t *l, const msc_command_t *cmd);

/* core1, after each decode pass: copies the pass's words if a qualifying command was in it. */
/* `unreliable`: a drop or resync since the last call; `behind`: capture is near a drop, so the pass
 * is not copied. */
void meta_after_pass(meta_link_t *l, const usb_capture_t *cap, const msc_parser_t *p,
                     uint32_t read_idx_before, uint64_t total_read_before, bool unreliable,
                     bool behind);

/* ---- core0: decode and reassemble ------------------------------------ */

#define META_COMPLETE  (1u << 0)   /* CSW status 0, every byte of every block, nothing extra */
#define META_NO_CSW    (1u << 1)   /* no CSW before a hole, the next CBW or the end */
#define META_SHORT     (1u << 2)   /* fewer bytes than the command transfers */
#define META_FAILED    (1u << 3)   /* CSW status not 0, or a WRITE with residue */
#define META_OVERLONG  (1u << 4)   /* more data than the CBW announced */

/* One directory transfer reassembled from the copied words: its command, its status and its
 * sectors. */
typedef struct {
    uint64_t       ts_ns;      /* the CBW's time: equal to the audit SCSI record's ts_ns */
    uint32_t       tag;
    uint8_t        opcode;
    bool           write;
    int16_t        status;     /* bCSWStatus, or -1 without a CSW */
    uint64_t       lba;
    uint32_t       blocks;
    uint32_t       data_len;   /* from the CBW */
    uint32_t       residue;    /* from the CSW */
    uint32_t       bytes;      /* data bytes reassembled */
    uint32_t       packets;    /* DATA packets taken */
    uint32_t       dup_packets;/* retransmissions dropped */
    uint32_t       bad_packets;/* DATA packets that failed decode or CRC */
    uint32_t       flags;
    const uint8_t *data;       /* `bytes` bytes, valid during the callback */
} meta_result_t;

/* Called with each reassembled transfer. */
typedef void (*meta_result_cb_t)(const meta_result_t *r, void *ctx);

/* Packet kinds for meta_rx_t's per-kind counters. */
#define META_KIND_XFER_DATA  0u   /* DATA taken, dropped as a duplicate, or bad, for the transfer */
#define META_KIND_OTHER_DATA 1u   /* CBW, CSW, and DATA of no transfer */
#define META_KIND_TOKEN      2u   /* IN, OUT, SETUP */
#define META_KIND_SOF        3u   /* start of frame */
#define META_KIND_HANDSHAKE  4u   /* ACK, NAK, STALL */
#define META_KIND_OTHER      5u   /* anything else */

/* core0's receiver: the decoder over the copied words, the transfer being reassembled, and its
 * counts. */
typedef struct {
    usb_decoder_t dec;          /* the never-skipping decoder build */
    usb_capture_t cap;          /* a capture over `ring`, fed from the link */
    uint32_t      ring[USB_CAPTURE_RING_WORDS];
    bool          in_span;
    uint64_t      next_word;    /* first word index the next contiguous chunk must have */
    uint32_t      ns_per_sample_q16;   /* the capture's, so packet times match core1's */
    uint64_t      cbw_ts_ns;    /* the transfer's CBW time */

    /* The last IN/OUT token. */
    bool          have_tok;
    uint8_t       tok_pid;
    uint8_t       tok_addr;
    uint8_t       tok_ep;

    /* The transfer being reassembled. */
    bool          active;
    bool          data_in;
    uint8_t       opcode;
    uint8_t       addr;
    int16_t       last_toggle;  /* PID of the last DATA packet taken, -1 none */
    bool          overlong;
    uint32_t      tag;
    uint64_t      lba;
    uint32_t      blocks;
    uint32_t      data_len;
    uint32_t      bytes;
    uint32_t      packets;
    uint32_t      dup_packets;
    uint32_t      bad_packets;
    uint64_t      data_first_ns;/* bus times of the first and last DATA packet taken */
    uint64_t      data_last_ns;
    uint64_t      csw_ns;
    uint8_t       buf[META_MAX_BYTES];

    meta_result_cb_t cb;
    void            *ctx;

    /* Counters for the stats line. */
    uint64_t chunks;
    uint64_t words;
    uint64_t spans;
    uint64_t holes;             /* spans ended by a hole or a BREAK flag */
    uint64_t breaks;            /* chunks flagged BREAK: core1 dropped a chunk, or capture dropped */
    uint64_t last_break_word;   /* first sample word index of the last such chunk */

    /* core0's cycle counter (DWT; 0 on the host): where core0's time goes while it decodes copied
     * words. */
    uint64_t decode_cyc;
    uint64_t decode_calls;
    uint64_t feed_cyc;          /* copying chunk words into the decoder's ring */
    uint64_t restart_cyc;       /* fresh decoder per span */
    uint64_t bad_chunks;        /* chunk headers that made no sense */
    uint64_t dup_cbws;          /* a CBW sent again after a NAK */
    uint64_t complete;
    uint64_t incomplete;

    /* Bus time of a complete transfer, [0] READs, [1] WRITEs: CBW to data, data, data to CSW (the
     * phase_* fields). */
    /* Inside decode_cyc: the packet callback's cycles, and the result callbacks' alone. */
    uint64_t packet_cyc;
    uint64_t result_cyc;

    /* Decode cycles and bus time charged to each packet kind (META_KIND_*). */
    uint64_t kind_n[6];
    uint64_t kind_cyc[6];
    uint64_t kind_pkt_words[6];  /* the packets' own words (bits x oversample / 16) */
    uint64_t kind_gap_ns[6];     /* bus time between the previous packet's end and this one */
    uint32_t last_cb_cyc;        /* cycle count at the last packet callback's end, or a decode call's start */
    uint64_t decoded_upto;       /* Cap.total_written at the last decode call */
    bool     have_last_pkt;      /* last_pkt_end_ns is valid (this span) */
    uint64_t last_pkt_end_ns;

    uint64_t phase_cmds[2];
    uint64_t phase_to_data_ns[2];
    uint64_t phase_data_ns[2];
    uint64_t phase_to_csw_ns[2];
} meta_rx_t;

/* Starts the receiver; it reports each transfer through `cb`. */
void meta_rx_init(meta_rx_t *rx, meta_result_cb_t cb, void *ctx);

/* meta_decoder.c: core0 cycles inside CRC16, and the bytes checked. */
extern uint64_t meta_crc16_cyc;   /* cycles */
extern uint64_t meta_crc16_bytes; /* bytes */

/* core0's table-driven CRC16 (meta_decoder.c); meta_rx_init builds the table. */
void     meta_crc16_init(void);
/* The CRC16 of `len` bytes, by table. */
uint16_t meta_crc16(const uint8_t *data, size_t len);

/* Sets the nanoseconds per sample, so result times equal the audit records' times (default: 48
 * MHz). */
void meta_rx_set_timebase(meta_rx_t *rx, uint32_t ns_per_sample_q16);

/* core0: takes up to `max_chunks` chunks from the link and decodes them; returns how many. */
uint32_t meta_rx_pump(meta_rx_t *rx, meta_link_t *l, uint32_t max_chunks);

/* core0, end of session: reports a transfer still open as incomplete. */
void meta_rx_finish(meta_rx_t *rx);

#endif /* META_CAPTURE_H */
