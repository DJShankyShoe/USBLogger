/*
 * The metadata side channel: core1 copies the sample words of small transfers, core0 decodes and
 * reassembles them.
 */

/* memset. */
#include <string.h>

/* What this file defines, with the decoder, parser and capture types it uses. */
#include "meta_capture.h"

/* No USB address is 0xFF (they are 0-127). */
#define META_ADDR_UNKNOWN 0xFFu

/* The decoder built with USB_DECODE_NO_SKIP=1, its public symbols renamed meta_* (meta_decoder.c). */
void     meta_usb_decoder_init(usb_decoder_t *d, usb_speed_t speed, uint32_t oversample);
uint32_t meta_usb_decode_run(usb_decoder_t *d, usb_capture_t *cap);

/* Reads a little-endian 32-bit field (CBW and CSW fields). */
static inline uint32_t le32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}

/* Reads a big-endian 32-bit field (CDB fields). */
static inline uint32_t be32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) |
           (uint32_t)p[3];
}

/* True for a small READ or WRITE inside the interest table (all of them while core0 is changing
 * it). */
bool USB_TIME_CRITICAL meta_command_qualifies(const meta_link_t *l, const msc_command_t *c)
{
    if (!((c->op == MSC_OP_READ || c->op == MSC_OP_WRITE) && c->lba_valid &&
          c->block_count >= 1u && c->block_count <= META_MAX_BLOCKS &&
          c->data_len <= META_MAX_BYTES)) {
        return false;
    }
    const uint32_t version = l->interest_version;
    if ((version & 1u) != 0u) {
        return true;
    }
    if (!l->interest_active) {
        return !l->single_block_until_known || c->block_count == 1u;
    }
    uint32_t count = l->interest_count;
    if (count > META_MAX_RANGES) {
        count = META_MAX_RANGES;
    }
    bool hit = false;
    for (uint32_t i = 0; i < count && !hit; i++) {
        const uint64_t start = ((uint64_t)l->interest[i].lba_hi << 32) | l->interest[i].lba_lo;
        const uint64_t end   = start + l->interest[i].sectors;
        hit = c->lba < end && start < c->lba + c->block_count;
    }
    return hit || l->interest_version != version;
}

/* Lets only single-sector transfers qualify until the first interest table. */
void meta_set_single_block_until_known(meta_link_t *l)
{
    l->single_block_until_known = true;
}

/* Empties the interest table, odd version first so core1 copies everything meanwhile. */
void meta_clear_interest(meta_link_t *l)
{
    l->interest_version = l->interest_version + 1u;   /* odd: core1 copies everything */
    l->interest_count   = 0u;
    l->interest_active  = false;
    l->interest_version = l->interest_version + 1u;
}

/* Replaces the interest table with n LBA ranges, odd version first so core1 copies everything
 * meanwhile. */
void meta_set_interest(meta_link_t *l, const uint64_t *lba, const uint32_t *sectors, uint32_t n)
{
    if (n > META_MAX_RANGES) {
        n = META_MAX_RANGES;
    }
    l->interest_version = l->interest_version + 1u;   /* odd: core1 copies everything */
    for (uint32_t i = 0; i < n; i++) {
        l->interest[i].lba_lo  = (uint32_t)lba[i];
        l->interest[i].lba_hi  = (uint32_t)(lba[i] >> 32);
        l->interest[i].sectors = sectors[i];
    }
    l->interest_count  = n;
    l->interest_active = true;
    l->interest_version = l->interest_version + 1u;   /* even again */
}

/* ---- core1 ----------------------------------------------------------- */

/* Starts an empty link ring over `storage`. */
void meta_link_init(meta_link_t *l, volatile uint32_t *storage, uint32_t size_words)
{
    memset(l, 0, sizeof(*l));
    l->ring = storage;
    l->size = size_words;
}

/* Counts an emitted command, and notes when it was one being copied. */
void USB_TIME_CRITICAL meta_note_command(meta_link_t *l, const msc_command_t *cmd)
{
    l->done_count++;
    if (meta_command_qualifies(l, cmd)) {
        l->done_in_pass = true;
    }
}

/* Link index `i` plus `k`, wrapped by a compare: the link's size need not be a power of two. */
static inline uint32_t link_add(uint32_t i, uint32_t k, uint32_t size)
{
    i += k;
    return i >= size ? i - size : i;
}

/* Copies n capture-ring words from index `src` into the link at `dst`, in runs that cross neither
 * ring's end. */
static void USB_TIME_CRITICAL copy_words(meta_link_t *l, uint32_t dst,
                                         const uint32_t *src_ring, uint32_t src, uint32_t n)
{
    const uint32_t smask = USB_CAPTURE_RING_WORDS - 1u;
    while (n != 0u) {
        uint32_t run = USB_CAPTURE_RING_WORDS - src;
        if (run > l->size - dst) {
            run = l->size - dst;
        }
        if (run > n) {
            run = n;
        }
        volatile uint32_t *const d = &l->ring[dst];
        const uint32_t *const s = &src_ring[src];
        for (uint32_t i = 0; i < run; i++) {
            d[i] = s[i];
        }
        dst = link_add(dst, run, l->size);
        src = (src + run) & smask;
        n  -= run;
    }
}

/* After a decode pass, copies the pass's words into the link while a qualifying command is pending
 * (core1). */
void USB_TIME_CRITICAL meta_after_pass(meta_link_t *l, const usb_capture_t *cap,
                                       const msc_parser_t *p, uint32_t read_idx_before,
                                       uint64_t total_read_before, bool unreliable,
                                       bool behind)
{
    if (unreliable) {
        l->break_pending = true;
    }

    /* Is a qualifying command pending now? Only a new CBW or an emitted command can change it, so
     * scan only then. */
    bool pending_now = l->was_pending;
    if (p->cbw_count != l->seen_cbw || l->done_count != l->seen_done) {
        l->seen_cbw  = p->cbw_count;
        l->seen_done = l->done_count;
        pending_now  = false;
        for (int i = 0; i < MSC_MAX_PENDING; i++) {
            if (p->slot_used[i] && meta_command_qualifies(l, &p->pending[i])) {
                pending_now = true;
                break;
            }
        }
    }

    /* Copy if a qualifying command was pending before, after, or ended in the pass, and the pass
     * after (its CSW's idle). */
    const bool copy = l->was_pending || l->done_in_pass || pending_now || l->copy_next;
    l->was_pending  = pending_now;
    l->copy_next    = l->done_in_pass;
    l->done_in_pass = false;

    const uint32_t n = (uint32_t)(cap->total_read - total_read_before);
    if (!copy || n == 0u) {
        return;
    }

    /* Demand, counted before the link can refuse it, split at window boundaries so no window
     * exceeds the bus. */
    {
        uint64_t at   = total_read_before;
        uint32_t left = n;
        while (left != 0u) {
            const uint64_t idx = at >> META_WIN_SHIFT;
            if (idx != l->win_index) {
                if (l->win_words > l->win_peak) {
                    l->win_peak = l->win_words;
                }
                if (l->win_words >= META_WIN_LOADED) {
                    l->win_loaded++;
                    l->win_run++;
                    if (l->win_run > l->win_run_max) {
                        l->win_run_max = l->win_run;
                    }
                } else {
                    l->win_run = 0;
                }
                l->win_index = idx;
                l->win_words = 0;
            }
            const uint64_t win_end = (idx + 1u) << META_WIN_SHIFT;
            uint32_t take = left;
            if (at + take > win_end) {
                take = (uint32_t)(win_end - at);
            }
            l->win_words += take;
            at   += take;
            left -= take;
        }
        if (l->win_words > l->win_peak) {
            l->win_peak = l->win_words;
        }
    }

    if (behind) {
        /* Close to a capture drop: the audit log comes first; core0 sees the hole and the check
         * reports it. */
        l->behind_skips++;
        l->break_pending = true;
        return;
    }

    /* One slot stays empty, so head == tail means empty; a stale tail only overstates `used`. */
    const uint32_t size = l->size;
    const uint32_t h    = l->head;
    const uint32_t t    = l->tail;
    const uint32_t used = h >= t ? h - t : h + size - t;
    const uint32_t need = META_CHUNK_HEADER_WORDS + n;
    if (need > size - 1u - used) {
        l->drops++;
        l->break_pending = true;   /* core0 would also see the hole */
        return;
    }
    l->ring[h]                     = META_CHUNK_MAGIC | (l->break_pending ? META_CHUNK_BREAK : 0u);
    l->ring[link_add(h, 1u, size)] = n;
    l->ring[link_add(h, 2u, size)] = (uint32_t)total_read_before;
    l->ring[link_add(h, 3u, size)] = (uint32_t)(total_read_before >> 32);
    copy_words(l, link_add(h, META_CHUNK_HEADER_WORDS, size), cap->ring, read_idx_before, n);
    l->head = link_add(h, need, size);

    l->break_pending = false;
    l->chunks++;
    l->words += n;
    if (used + need > l->high_water) {
        l->high_water = used + need;
    }
}

/* ---- core0 ----------------------------------------------------------- */

/* LBA and block count of a READ or WRITE command block. */
static bool rw_command(const uint8_t *cdb, uint32_t len, uint64_t *lba, uint32_t *blocks,
                       bool *write)
{
    switch (cdb[0]) {
    case SCSI_READ_6:
    case SCSI_WRITE_6:
        if (len < 6u) {
            return false;
        }
        *lba    = ((uint32_t)(cdb[1] & 0x1Fu) << 16) | ((uint32_t)cdb[2] << 8) | cdb[3];
        *blocks = cdb[4] ? cdb[4] : 256u;
        *write  = cdb[0] == SCSI_WRITE_6;
        return true;
    case SCSI_READ_10:
    case SCSI_WRITE_10:
        if (len < 10u) {
            return false;
        }
        *lba    = be32(&cdb[2]);
        *blocks = ((uint32_t)cdb[7] << 8) | cdb[8];
        *write  = cdb[0] == SCSI_WRITE_10;
        return true;
    case SCSI_READ_12:
    case SCSI_WRITE_12:
        if (len < 12u) {
            return false;
        }
        *lba    = be32(&cdb[2]);
        *blocks = be32(&cdb[6]);
        *write  = cdb[0] == SCSI_WRITE_12;
        return true;
    case SCSI_READ_16:
    case SCSI_WRITE_16:
        if (len < 16u) {
            return false;
        }
        *lba    = ((uint64_t)be32(&cdb[2]) << 32) | be32(&cdb[6]);
        *blocks = be32(&cdb[10]);
        *write  = cdb[0] == SCSI_WRITE_16;
        return true;
    default:
        return false;
    }
}

/* Reports the transfer being reassembled and forgets it. */
static void rx_end(meta_rx_t *rx, bool have_csw, uint8_t status, uint32_t residue)
{
    meta_result_t r;
    memset(&r, 0, sizeof(r));
    r.ts_ns       = rx->cbw_ts_ns;
    r.tag         = rx->tag;
    r.opcode      = rx->opcode;
    r.write       = !rx->data_in;
    r.status      = have_csw ? (int16_t)status : (int16_t)-1;
    r.lba         = rx->lba;
    r.blocks      = rx->blocks;
    r.data_len    = rx->data_len;
    r.residue     = have_csw ? residue : 0u;
    r.bytes       = rx->bytes;
    r.packets     = rx->packets;
    r.dup_packets = rx->dup_packets;
    r.bad_packets = rx->bad_packets;
    r.data        = rx->buf;

    uint32_t flags = 0;
    if (rx->overlong) {
        flags |= META_OVERLONG;
    }
    if (!have_csw) {
        flags |= META_NO_CSW;
        if (rx->bytes < rx->data_len) {
            flags |= META_SHORT;
        }
    } else {
        if (status != 0u || (!rx->data_in && residue != 0u)) {
            flags |= META_FAILED;
        }
        const uint32_t expected = rx->data_in
            ? (residue <= rx->data_len ? rx->data_len - residue : 0u)
            : rx->data_len;
        if (rx->bytes != expected) {
            flags |= META_SHORT;
        }
        if (flags == 0u && rx->bytes == rx->blocks * META_SECTOR_BYTES) {
            flags |= META_COMPLETE;
        }
    }
    r.flags = flags;

    if (flags & META_COMPLETE) {
        rx->complete++;
        const unsigned w = r.write ? 1u : 0u;
        if (rx->packets != 0u && rx->data_first_ns >= rx->cbw_ts_ns &&
            rx->data_last_ns >= rx->data_first_ns && rx->csw_ns >= rx->data_last_ns) {
            rx->phase_cmds[w]++;
            rx->phase_to_data_ns[w] += rx->data_first_ns - rx->cbw_ts_ns;
            rx->phase_data_ns[w]    += rx->data_last_ns - rx->data_first_ns;
            rx->phase_to_csw_ns[w]  += rx->csw_ns - rx->data_last_ns;
        }
    } else {
        rx->incomplete++;
    }
    rx->active = false;
    if (rx->cb) {
        const uint32_t t0 = usb_cycles();
        rx->cb(&r, rx->ctx);
        rx->result_cyc += (uint32_t)(usb_cycles() - t0);
    }
}

/* The per-packet and per-word functions below run from SRAM (from flash core0 decoded ~73,000
 * words/s). */
static void USB_TIME_CRITICAL rx_cbw(meta_rx_t *rx, const usb_packet_t *pkt)
{
    const uint8_t *const b = pkt->payload;
    const uint32_t tag = le32(&b[4]);

    /* The host sends a CBW again, unchanged, when the drive NAKed it. */
    if (rx->active && tag == rx->tag && rx->packets == 0u && rx->bytes == 0u) {
        rx->dup_cbws++;
        return;
    }
    /* Bulk-Only is one command at a time: a new CBW means the one before got no CSW in the copy. */
    if (rx->active) {
        rx_end(rx, false, 0u, 0u);
    }

    uint64_t lba = 0;
    uint32_t blocks = 0;
    bool     write = false;
    const uint32_t data_len = le32(&b[8]);
    const bool     data_in  = (b[12] & 0x80u) != 0u;
    uint32_t cdb_len = b[14] & 0x1Fu;
    if (cdb_len > 16u) {
        cdb_len = 16u;
    }
    if (!rw_command(&b[15], cdb_len, &lba, &blocks, &write) || write == data_in ||
        blocks == 0u || blocks > META_MAX_BLOCKS ||
        data_len == 0u || data_len > META_MAX_BYTES) {
        return;
    }

    rx->active      = true;
    rx->cbw_ts_ns   = pkt->timestamp_ns;   /* absolute: the capture's word index is kept */
    rx->tag         = tag;
    rx->opcode      = b[15];
    rx->data_in     = data_in;
    rx->addr        = (rx->have_tok && rx->tok_pid == (uint8_t)USB_PID_OUT && rx->tok_ep != 0u)
                      ? rx->tok_addr : META_ADDR_UNKNOWN;
    rx->lba         = lba;
    rx->blocks      = blocks;
    rx->data_len    = data_len;
    rx->bytes       = 0;
    rx->packets     = 0;
    rx->dup_packets = 0;
    rx->bad_packets = 0;
    rx->overlong    = false;
    /* A WRITE's first DATA PID follows its CBW's on the same OUT pipe; a READ's arrives on the IN
     * pipe. */
    rx->last_toggle = data_in ? (int16_t)-1 : (int16_t)pkt->pid;
}

/* Ignores bus events: core1's decoder reports them; this one decodes copies. */
static void rx_event(usb_bus_event_t ev, uint64_t ts_ns, uint64_t duration_ns,
                     uint32_t count, void *ctx)
{
    (void)ev; (void)ts_ns; (void)duration_ns; (void)count; (void)ctx;
}

/* Takes one packet from the copy: a CBW starts a transfer, its data is gathered, its CSW ends it. */
static void USB_TIME_CRITICAL rx_packet_body(const usb_packet_t *pkt, void *ctx)
{
    meta_rx_t *const rx = ctx;

    if (pkt->type == USB_PKT_TYPE_TOKEN) {
        if (pkt->status == USB_DEC_OK && pkt->pid != USB_PID_SOF) {
            rx->have_tok = true;
            rx->tok_pid  = (uint8_t)pkt->pid;
            rx->tok_addr = pkt->addr;
            rx->tok_ep   = pkt->endpoint;
        }
        return;
    }
    if (pkt->type != USB_PKT_TYPE_DATA) {
        return;
    }
    const bool ok  = pkt->status == USB_DEC_OK && pkt->crc_ok;
    const bool out = rx->have_tok && rx->tok_pid == (uint8_t)USB_PID_OUT;
    const bool in  = rx->have_tok && rx->tok_pid == (uint8_t)USB_PID_IN;

    /* A CBW is known by its length, signature and CRC; its OUT token may be in the pass before. */
    if (ok && !in && pkt->payload_len == MSC_CBW_LENGTH &&
        le32(pkt->payload) == MSC_CBW_SIGNATURE) {
        rx_cbw(rx, pkt);
        return;
    }
    if (!rx->active || (!in && !out) || rx->tok_ep == 0u) {
        return;
    }
    /* Without the CBW's token, the address comes from the command's first data or CSW token. */
    if (rx->addr != META_ADDR_UNKNOWN && rx->tok_addr != rx->addr) {
        return;
    }
    /* Sector data comes in 64-byte packets, so a 13-byte packet with this command's tag is its CSW. */
    if (ok && in && pkt->payload_len == MSC_CSW_LENGTH &&
        le32(pkt->payload) == MSC_CSW_SIGNATURE && le32(&pkt->payload[4]) == rx->tag) {
        rx->csw_ns = pkt->timestamp_ns;
        rx_end(rx, true, pkt->payload[12], le32(&pkt->payload[8]));
        return;
    }
    if (rx->data_in ? !in : !out) {
        return;
    }
    if (!ok) {
        rx->bad_packets++;          /* the sender retries it with the same PID */
        return;
    }
    if (rx->last_toggle == (int16_t)pkt->pid) {
        rx->dup_packets++;          /* a retransmission of the packet already taken */
        return;
    }
    rx->last_toggle = (int16_t)pkt->pid;
    rx->addr = rx->tok_addr;
    if (rx->packets == 0u) {
        rx->data_first_ns = pkt->timestamp_ns;
    }
    rx->data_last_ns = pkt->timestamp_ns;
    rx->packets++;
    uint32_t len = pkt->payload_len;
    const uint32_t room = rx->data_len - rx->bytes;
    if (len > room) {
        rx->overlong = true;
        len = room;
    }
    usb_copy_bytes(&rx->buf[rx->bytes], pkt->payload, len);   /* memcpy is in flash */
    rx->bytes += len;
}

/* The decoder's packet callback, timed; the cycles and bus time since the previous packet go to
 * this packet's kind. */
static void USB_TIME_CRITICAL rx_packet(const usb_packet_t *pkt, void *ctx)
{
    meta_rx_t *const rx = ctx;
    const uint32_t t0 = usb_cycles();
    const uint32_t before = rx->packets + rx->dup_packets + rx->bad_packets;
    const bool     was_active = rx->active;
    rx_packet_body(pkt, ctx);
    const uint32_t t1 = usb_cycles();
    rx->packet_cyc += (uint32_t)(t1 - t0);

    uint32_t kind = META_KIND_OTHER;
    if (pkt->type == USB_PKT_TYPE_TOKEN) {
        kind = pkt->pid == USB_PID_SOF ? META_KIND_SOF : META_KIND_TOKEN;
    } else if (pkt->type == USB_PKT_TYPE_HANDSHAKE) {
        kind = META_KIND_HANDSHAKE;
    } else if (pkt->type == USB_PKT_TYPE_DATA) {
        kind = (was_active && rx->active &&
                rx->packets + rx->dup_packets + rx->bad_packets != before)
               ? META_KIND_XFER_DATA : META_KIND_OTHER_DATA;
    }
    const uint32_t words = ((uint32_t)pkt->bit_count * USB_CAPTURE_OVERSAMPLE) >> 4;
    const uint64_t ns_per_word = ((uint64_t)rx->ns_per_sample_q16 * USB_CAPTURE_SAMPLES_PER_WORD) >> 16;
    rx->kind_n[kind]++;
    rx->kind_cyc[kind]       += (uint32_t)(t0 - rx->last_cb_cyc);
    rx->kind_pkt_words[kind] += words;
    if (rx->have_last_pkt && pkt->timestamp_ns > rx->last_pkt_end_ns) {
        rx->kind_gap_ns[kind] += pkt->timestamp_ns - rx->last_pkt_end_ns;
    }
    rx->last_pkt_end_ns = pkt->timestamp_ns + (uint64_t)words * ns_per_word;
    rx->have_last_pkt   = true;
    rx->last_cb_cyc     = t1;
}

/* A fresh decoder and capture for a span, counting from its first word index, so packet times are
 * core1's. */
static void rx_restart(meta_rx_t *rx, uint64_t first_word)
{
    meta_usb_decoder_init(&rx->dec, USB_SPEED_FULL, USB_CAPTURE_OVERSAMPLE);
    usb_decoder_set_callbacks(&rx->dec, rx_packet, rx_event, rx);
    rx->have_last_pkt = false;        /* a new span: no gap across the hole */
    memset(&rx->cap, 0, sizeof(rx->cap));
    rx->cap.ring              = rx->ring;
    rx->cap.speed             = USB_SPEED_FULL;
    rx->cap.oversample        = USB_CAPTURE_OVERSAMPLE;
    rx->cap.sample_hz         = 48000000.0f;
    rx->cap.ns_per_sample_q16 = rx->ns_per_sample_q16;
    rx->cap.total_read        = first_word;
    rx->cap.total_written     = first_word;
    rx->cap.idle_word         = USB_CAPTURE_IDLE_FS;
    rx->cap.dma_a             = -1;
    rx->cap.dma_b             = -1;
    rx->have_tok = false;
}

/* Decodes the words held (defined below). */
static void USB_TIME_CRITICAL rx_decode(meta_rx_t *rx);

/* Ends the current span: a transfer still open had words cut from it. */
static void rx_end_span(meta_rx_t *rx)
{
    /* Words held for a batch belong to this span: decode them first. */
    if (rx->in_span && rx->cap.total_written != rx->decoded_upto) {
        rx_decode(rx);
    }
    if (rx->active) {
        rx_end(rx, false, 0u, 0u);
    }
    rx->in_span = false;
}

/* Starts core0's side: the CRC table, the callback and a 48 MHz timebase. */
void meta_rx_init(meta_rx_t *rx, meta_result_cb_t cb, void *ctx)
{
    memset(rx, 0, sizeof(*rx));
    meta_crc16_init();
    rx->cb  = cb;
    rx->ctx = ctx;
    rx->ns_per_sample_q16 = (uint32_t)((1000000000ull << 16) / 48000000u);
    rx_restart(rx, 0u);
}

/* Sets the nanoseconds per sample, so result times match the audit records'. */
void meta_rx_set_timebase(meta_rx_t *rx, uint32_t ns_per_sample_q16)
{
    rx->ns_per_sample_q16     = ns_per_sample_q16;
    rx->cap.ns_per_sample_q16 = ns_per_sample_q16;
}

/* Decodes every word fed so far, and times it. */
static void USB_TIME_CRITICAL rx_decode(meta_rx_t *rx)
{
    const uint32_t t0 = usb_cycles();
    rx->last_cb_cyc = t0;             /* nothing before this call is charged */
    while (rx->cap.total_written != rx->cap.total_read) {
        rx->decode_calls++;
        if (meta_usb_decode_run(&rx->dec, &rx->cap) == 0u) {
            break;
        }
    }
    rx->decoded_upto = rx->cap.total_written;
    rx->decode_cyc += (uint32_t)(usb_cycles() - t0);
}

/* Words held before a decode call: batched as on core1, so a packet across a chunk's end is not
 * walked twice. */
#define META_DECODE_BATCH_WORDS 2048u

/* Appends n link words from `from` to the decoder's ring, decoding as it goes so the ring never
 * overflows. */
static void USB_TIME_CRITICAL rx_feed(meta_rx_t *rx, const meta_link_t *l, uint32_t from, uint32_t n)
{
    const uint32_t rmask = USB_CAPTURE_RING_WORDS - 1u;
    while (n != 0u) {
        uint32_t held = (uint32_t)(rx->cap.total_written - rx->cap.total_read);
        if (held > USB_CAPTURE_RING_WORDS / 2u) {
            rx_decode(rx);
            held = (uint32_t)(rx->cap.total_written - rx->cap.total_read);
            if (held > USB_CAPTURE_RING_WORDS / 2u) {
                /* Nothing decodable in half a ring: not a USB packet stream. Start over rather than
                 * overflow. */
                rx_end_span(rx);
                rx_restart(rx, rx->cap.total_written);
                rx->in_span = true;
                held = 0;
            }
        }
        uint32_t piece = USB_CAPTURE_RING_WORDS / 2u - held;
        if (piece > n) {
            piece = n;
        }
        uint32_t w = (rx->cap.read_idx + held) & rmask;
        const uint32_t t0 = usb_cycles();
        /* Contiguous runs: each ring's wrap tested once per run, not per word. */
        for (uint32_t left = piece; left != 0u;) {
            uint32_t run = left;
            if (run > l->size - from) {
                run = l->size - from;
            }
            if (run > USB_CAPTURE_RING_WORDS - w) {
                run = USB_CAPTURE_RING_WORDS - w;
            }
            const volatile uint32_t *const src = &l->ring[from];
            uint32_t *const dst = &rx->ring[w];
            /* Four words a turn; the loads stay volatile, core1 writing the link. */
            uint32_t i = 0;
            for (; i + 4u <= run; i += 4u) {
                const uint32_t a = src[i], b = src[i + 1u], c = src[i + 2u], d = src[i + 3u];
                dst[i] = a; dst[i + 1u] = b; dst[i + 2u] = c; dst[i + 3u] = d;
            }
            for (; i < run; i++) {
                dst[i] = src[i];
            }
            from += run;
            if (from == l->size) {
                from = 0u;
            }
            w = (w + run) & rmask;
            left -= run;
        }
        rx->feed_cyc += (uint32_t)(usb_cycles() - t0);
        rx->cap.total_written += piece;
        n   -= piece;
        if ((uint32_t)(rx->cap.total_written - rx->cap.total_read) >= META_DECODE_BATCH_WORDS) {
            rx_decode(rx);
        }
    }
}

/* Takes up to max_chunks chunks from the link and decodes them; returns how many (core0). */
uint32_t USB_TIME_CRITICAL meta_rx_pump(meta_rx_t *rx, meta_link_t *l, uint32_t max_chunks)
{
    const uint32_t size = l->size;
    uint32_t taken = 0;
    while (taken < max_chunks) {
        const uint32_t t = l->tail;
        const uint32_t h = l->head;
        if (h == t) {
            break;
        }
        const uint32_t held  = h >= t ? h - t : h + size - t;
        const uint32_t w0    = l->ring[t];
        const uint32_t n     = l->ring[link_add(t, 1u, size)];
        const uint64_t first = (uint64_t)l->ring[link_add(t, 2u, size)] |
                               ((uint64_t)l->ring[link_add(t, 3u, size)] << 32);
        if ((w0 & META_CHUNK_MAGIC_MASK) != META_CHUNK_MAGIC || held < META_CHUNK_HEADER_WORDS ||
            n > held - META_CHUNK_HEADER_WORDS) {
            /* Cannot happen with one writer and one reader; if it does, drop everything and start a
             * new span. */
            rx->bad_chunks++;
            rx_end_span(rx);
            l->tail = h;
            break;
        }

        if (w0 & META_CHUNK_BREAK) {
            rx->breaks++;
            rx->last_break_word = first;
        }
        if (!rx->in_span || first != rx->next_word || (w0 & META_CHUNK_BREAK)) {
            if (rx->in_span) {
                rx->holes++;
                rx_end_span(rx);
            }
            const uint32_t t0 = usb_cycles();
            rx_restart(rx, first);
            rx->restart_cyc += (uint32_t)(usb_cycles() - t0);
            rx->in_span = true;
            rx->spans++;
        }
        rx_feed(rx, l, link_add(t, META_CHUNK_HEADER_WORDS, size), n);
        rx->next_word = first + n;
        rx->chunks++;
        rx->words += n;
        l->tail = link_add(t, META_CHUNK_HEADER_WORDS + n, size);
        taken++;
    }
    /* The link is empty: decode what the batch holds now, so a transfer's result does not wait for
     * the next one. */
    if (taken < max_chunks && rx->in_span && rx->cap.total_written != rx->decoded_upto) {
        rx_decode(rx);
    }
    return taken;
}

/* Decodes what is held and reports a transfer still open as incomplete (end of session). */
void meta_rx_finish(meta_rx_t *rx)
{
    rx_decode(rx);
    rx_end_span(rx);
}
