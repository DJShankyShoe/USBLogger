/*
 * The USB decoder (core1): finds each packet's start in the sample words, decodes NRZI and bit stuffing,
 * checks CRCs, skips file data (Option A), and reports bus events coalesced and timed by bus position.
 * core0 runs a never-skipping build of it (meta_decoder.c).
 */

/* printf for the stats lines; memset. */
#include <stdio.h>
#include <string.h>

/* What this file defines, and the CBW/CSW signatures. */
#include "usb_decode.h"
#include "msc_parse.h"   /* CBW/CSW signatures, to recognise file data */

/* Puts the decode loops in SRAM: they have a hard deadline, and a flash cache miss costs more than
 * the work. */
#ifndef __not_in_flash_func
#define __not_in_flash_func(fn) fn
#endif

/* The longest packet in bytes: SYNC, PID, the largest payload and CRC16. */
#define DECODE_MAX_BYTES (2u + USB_MAX_PAYLOAD + 2u)

/* Words of new work per pass: short enough to finish before the DMA could overwrite a word it has
 * yet to read. */
#ifndef DECODE_PASS_MAX_WORDS
#define DECODE_PASS_MAX_WORDS 1024u
#endif

/* NRZI-decoded SYNC field, LSB-first: seven 0s then a 1. */
#define SYNC_BYTE 0x80u

/* Gives a bus event's name as the console prints it ("BUS-RESET", "DETACH", ...). */
const char *usb_bus_event_name(usb_bus_event_t ev)
{
    switch (ev) {
    case USB_BUS_EVENT_RESET:        return "BUS-RESET";
    case USB_BUS_EVENT_CHIRP:        return "HS-CHIRP";
    case USB_BUS_EVENT_HS_SUSPECTED: return "HIGH-SPEED-SUSPECTED";
    case USB_BUS_EVENT_SE1:          return "SE1";
    case USB_BUS_EVENT_OVERRUN:      return "CAPTURE-OVERRUN";
    case USB_BUS_EVENT_NO_DEVICE:    return "NO-DEVICE";
    case USB_BUS_EVENT_SUSPEND:      return "SUSPEND";
    case USB_BUS_EVENT_SUSPEND_END:  return "SUSPEND-END";
    case USB_BUS_EVENT_DETACH:       return "DETACH";
    case USB_BUS_EVENT_ATTACH:       return "ATTACH";
    default:                         return "?";
    }
}

/* Starts a decoder for one bus speed and oversampling, with every threshold in samples. */
void usb_decoder_init(usb_decoder_t *d, usb_speed_t speed, uint32_t oversample)
{
    memset(d, 0, sizeof(*d));

    if (oversample == 0) {
        oversample = USB_CAPTURE_OVERSAMPLE;
    }

    d->speed      = speed;
    d->oversample = oversample;
    d->token_crc_ok = UINT32_MAX;   /* no token has passed CRC5 yet */
    /* Full Speed idle is J = D+ high; Low Speed inverts the pair. */
    d->idle_line  = (speed == USB_SPEED_LOW) ? USB_LINE_DM : USB_LINE_DP;
    d->idle_word  = (speed == USB_SPEED_LOW) ? USB_CAPTURE_IDLE_LS
                                             : USB_CAPTURE_IDLE_FS;

    uint32_t samples_per_us = (usb_speed_bitrate(speed) / 1000000u) * oversample;
    if (samples_per_us == 0) {
        samples_per_us = 1;
    }

    d->eop_se0_samples   = oversample;               /* 1 bit time of SE0 */
    d->eop_max_samples   = oversample * 3u;          /* an EOP is 2 bit times */

    /* More than 7 bit times by decode_packet's rounding, without dividing: gap >= 8 * oversample -
     * half. */
    d->stuff_gap_samples = 8u * oversample - ((oversample >= 2u) ? (oversample / 2u) : 1u);

    /* Coalescing interval: the largest power of two samples under 100 ms, so grouping is a shift,
     * not a 64-bit divide. */
    {
        const uint64_t target = (uint64_t)samples_per_us * 100000u;
        uint32_t s = 0;
        while ((2ull << s) <= target) {
            s++;
        }
        d->burst_shift = s;
    }
    d->reset_se0_samples = samples_per_us * 3u;      /* >2.5 us -> reset */
    d->chirp_samples     = samples_per_us * 50u;     /* 50 us stuck in one state */

    /* SE0 this long means High Speed (or a detach); a normal reset lasts 10-50 ms, far below it. */
    d->hs_quiet_samples  = samples_per_us * 200000u; /* 200 ms of SE0 */
    /* A host drives reset for at least 10 ms; shorter reset-length SE0s are contact bounce. */
    d->host_reset_samples = samples_per_us * 10000u;

    /* Chirps since the last reset that make a High Speed negotiation (20 or more; bounce parks a K
     * once or twice). */
    d->hs_chirps = 16u;

    /* 3 ms of idle J with no SOF is USB's suspend (as Windows' safe eject does), in whole words. */
    d->suspend_words     = (samples_per_us * 3000u + 15u) / 16u;

    /* SE1 shorter than a bit time is a sample landing mid-transition: ridden through, not a fault. */
    d->se1_glitch_samples = oversample;

    /* The longest legal packet with worst-case stuffing, plus slack: past it without an EOP, the
     * line holds no packet. */
    d->max_packet_samples = ((DECODE_MAX_BYTES * 8u * 7u) / 6u + 16u) * oversample;
    d->se1_report_samples = samples_per_us * 100000u; /* at most one SE1 report per 100 ms */
}

/* ---- sample access --------------------------------------------------- */

/* Population count without __builtin_popcount, which is a libgcc call on the Cortex-M33. */
static inline uint32_t popcount32(uint32_t x)
{
    x = x - ((x >> 1) & 0x55555555u);
    x = (x & 0x33333333u) + ((x >> 2) & 0x33333333u);
    x = (x + (x >> 4)) & 0x0F0F0F0Fu;
    return (x * 0x01010101u) >> 24;
}

/* Gives every glitch sample (SE1, short SE0) the level of the sample before it, so it makes no
 * transition. */
static inline uint32_t repair_glitches(uint32_t lo, uint32_t glitch, uint32_t prev_dp)
{
    while (glitch) {
        const uint32_t i   = (uint32_t)__builtin_ctz(glitch) >> 1;
        const uint32_t src = (i == 0u) ? prev_dp : ((lo >> ((i - 1u) * 2u)) & 1u);
        lo = (lo & ~(1u << (i * 2u))) | (src << (i * 2u));
        glitch &= glitch - 1u;
    }
    return lo;
}

/* repair_glitches() in one step, for glitches none of which follows another. */
static inline uint32_t repair_lone_glitches(uint32_t lo, uint32_t glitch, uint32_t prev_dp)
{
    return (lo & ~glitch) | (((lo << 2) | prev_dp) & glitch);
}

/* SE1 samples in a sample word (both lines high), one bit per sample. */
static inline uint32_t se1_mask(uint32_t w)
{
    return w & (w >> 1) & 0x55555555u;
}

/* Converts a position in this pass (samples) into a bus time in nanoseconds. */
static inline uint64_t pos_to_ns(const usb_capture_t *cap, uint64_t pos)
{
    return usb_capture_sample_to_ns(cap, usb_capture_sample_index(cap) + pos);
}

/* Reports one bus event at an absolute sample index, so events spanning passes are timed right. */
static void __not_in_flash_func(emit_event_abs)(usb_decoder_t *d, const usb_capture_t *cap,
                       usb_bus_event_t ev, uint64_t abs_pos, uint64_t dur_samples)
{
    if (d->on_event) {
        d->on_event(ev, usb_capture_sample_to_ns(cap, abs_pos),
                    usb_capture_sample_to_ns(cap, dur_samples), 1, d->ctx);
    }
}

/* Counts n SE1 samples for the coalesced report (se1_flush reports them). */
/* Positions are absolute sample indices: a burst spans passes, and `pos` restarts at zero in each. */
static inline void se1_note_n(usb_decoder_t *d, const usb_capture_t *cap,
                              uint64_t pos, uint32_t n)
{
    d->err_se1 += n;
    if (d->se1_burst == 0) {
        d->se1_first_abs = usb_capture_sample_index(cap) + pos;
    }
    d->se1_burst += n;
}

/* Records one SE1 sample (se1_note_n with n = 1). */
static inline void se1_note(usb_decoder_t *d, const usb_capture_t *cap,
                            uint64_t pos)
{
    se1_note_n(d, cap, pos, 1);
}

/* Reports the SE1 counted so far as one event, at most once per se1_report_samples. */
static void __not_in_flash_func(se1_flush)(usb_decoder_t *d, const usb_capture_t *cap, uint64_t pos)
{
    if (d->se1_burst == 0) {
        return;
    }
    uint64_t now = usb_capture_sample_index(cap) + pos;
    if (d->se1_last_report_abs != 0 &&
        (now - d->se1_last_report_abs) < d->se1_report_samples) {
        return;   /* keep accumulating into the current burst */
    }

    uint64_t span = (now > d->se1_first_abs) ? (now - d->se1_first_abs) : 0;
    if (d->on_event) {
        d->on_event(USB_BUS_EVENT_SE1,
                    usb_capture_sample_to_ns(cap, d->se1_first_abs),
                    usb_capture_sample_to_ns(cap, span),
                    d->se1_burst, d->ctx);
    }
    d->se1_last_report_abs = now;
    d->se1_burst = 0;
}

/* ---- coalesced bus conditions ---------------------------------------- */

/* Reports a group of resets or chirps as one counted event, grouped by bus position so passes cannot
 * change it. */
static void __not_in_flash_func(burst_emit)(usb_decoder_t *d, const usb_capture_t *cap,
                                            usb_event_burst_t *b, usb_bus_event_t ev)
{
    if (d->on_event) {
        d->on_event(ev, usb_capture_sample_to_ns(cap, b->first_abs),
                    usb_capture_sample_to_ns(cap, b->first_dur), b->count, d->ctx);
    }
    b->count = 0;
}

/* Occurrences arrive in bus order, so a later interval closes the previous one. */
static inline void burst_note(usb_decoder_t *d, const usb_capture_t *cap,
                              usb_event_burst_t *b, usb_bus_event_t ev,
                              uint64_t abs_pos, uint64_t dur)
{
    uint64_t k = abs_pos >> d->burst_shift;
    if (b->count != 0u && k != b->bucket) {
        burst_emit(d, cap, b, ev);
    }
    if (b->count == 0u) {
        b->bucket    = k;
        b->first_abs = abs_pos;
        b->first_dur = dur;
    }
    b->count++;
}

/* Reports a pending group once decoding has passed its interval and nothing unfinished can still
 * join it. */
static void __not_in_flash_func(burst_flush_ready)(usb_decoder_t *d, const usb_capture_t *cap)
{
    const uint64_t now = usb_capture_sample_index(cap);

    usb_event_burst_t *r = &d->reset_burst;
    if (r->count != 0u) {
        const uint64_t end = (r->bucket + 1u) << d->burst_shift;
        const bool run_open = (d->se0_run != 0u) && (d->se0_start_abs < end);
        if (now >= end && !run_open) {
            burst_emit(d, cap, r, USB_BUS_EVENT_RESET);
        }
    }

    usb_event_burst_t *c = &d->chirp_burst;
    if (c->count != 0u && now >= ((c->bucket + 1u) << d->burst_shift)) {
        burst_emit(d, cap, c, USB_BUS_EVENT_CHIRP);
    }

    /* A suspend is timed from its idle run's start, so an open run begun inside the interval can
     * still join. */
    usb_event_burst_t *s = &d->suspend_burst;
    if (s->count != 0u) {
        const uint64_t end = (s->bucket + 1u) << d->burst_shift;
        const bool run_open = d->idle_open && !d->suspended && (d->idle_start_abs < end);
        if (now >= end && !run_open) {
            burst_emit(d, cap, s, USB_BUS_EVENT_SUSPEND);
        }
    }

    usb_event_burst_t *e = &d->suspend_end_burst;
    if (e->count != 0u && now >= ((e->bucket + 1u) << d->burst_shift)) {
        burst_emit(d, cap, e, USB_BUS_EVENT_SUSPEND_END);
    }
}

/* Reports the SE1 burst and every coalesced group whose interval has ended. */
void __not_in_flash_func(usb_decode_flush_events)(usb_decoder_t *d, usb_capture_t *cap)
{
    se1_flush(d, cap, 0);
    burst_flush_ready(d, cap);
}

/* Reports every group and SE1 burst still held, at the session's end. */
void usb_decode_finish(usb_decoder_t *d, usb_capture_t *cap)
{
    if (d->reset_burst.count != 0u) {
        burst_emit(d, cap, &d->reset_burst, USB_BUS_EVENT_RESET);
    }
    if (d->chirp_burst.count != 0u) {
        burst_emit(d, cap, &d->chirp_burst, USB_BUS_EVENT_CHIRP);
    }
    /* A bus still suspended at session end gets no SUSPEND-END: it never left idle. */
    if (d->suspend_burst.count != 0u) {
        burst_emit(d, cap, &d->suspend_burst, USB_BUS_EVENT_SUSPEND);
    }
    if (d->suspend_end_burst.count != 0u) {
        burst_emit(d, cap, &d->suspend_end_burst, USB_BUS_EVENT_SUSPEND_END);
    }
    d->se1_last_report_abs = 0;   /* lift the rate limit for the last SE1 report */
    se1_flush(d, cap, 0);
}

/* Extends the current SE0 run by n samples, and reports a long quiet one as High Speed, no device or a detach. */
static void __not_in_flash_func(se0_advance)(usb_decoder_t *d, const usb_capture_t *cap,
                        uint64_t pos, uint32_t n)
{
    if (d->se0_run == 0u) {
        d->se0_start_abs = usb_capture_sample_index(cap) + pos;
    }
    d->se0_run += n;

    /* Everything about an SE0 run is timed from its start in whole words, never from what the pass
     * held. */
    /* A long quiet SE0: NO-DEVICE if the bus never idled at J (the host's pulldowns), DETACH after packets
     * since the last reset (High Speed is impossible through the ADuM3160), HIGH-SPEED-SUSPECTED only after
     * a device's chirps (hs_chirps of them since the last reset), DETACH otherwise. */
    if (!d->hs_reported && d->se0_run >= d->hs_quiet_samples) {
        d->hs_reported = true;
        const usb_bus_event_t ev = !d->idle_words_skipped ? USB_BUS_EVENT_NO_DEVICE
                                 : d->packets_ok != d->packets_at_reset ? USB_BUS_EVENT_DETACH
                                 : d->chirps - d->chirps_at_reset >= d->hs_chirps ? USB_BUS_EVENT_HS_SUSPECTED
                                                                        : USB_BUS_EVENT_DETACH;
        /* Duration: the threshold itself, in whole words from the run start. */
        emit_event_abs(d, cap, ev, d->se0_start_abs, ((d->hs_quiet_samples + 15u) / 16u) * 16u);
    }
}

/* The bus has left SE0: a run long enough is reported as a reset now, with its full length. */
static inline void se0_end(usb_decoder_t *d, const usb_capture_t *cap)
{
    if (d->se0_run == 0u) {
        return;
    }
    /* A host reset (or a reported quiet SE0) starts a new insertion; shorter bounce SE0s must not
     * hide the packets before. */
    if (d->hs_reported || d->se0_run >= d->host_reset_samples) {
        d->packets_at_reset = d->packets_ok;
        d->chirps_at_reset  = d->chirps;
    }
    if (!d->hs_reported && d->se0_run >= d->reset_se0_samples) {
        d->resets++;
        burst_note(d, cap, &d->reset_burst, USB_BUS_EVENT_RESET,
                   d->se0_start_abs, d->se0_run);
    }
    d->se0_run     = 0;
    d->hs_reported = false;
}

/* ---- suspend --------------------------------------------------------- */

/* The idle run has ended: one reported as a suspend is reported ending, with its whole length. */
static inline void idle_run_end(usb_decoder_t *d, const usb_capture_t *cap)
{
    if (d->suspended && !d->attach_idle) {
        burst_note(d, cap, &d->suspend_end_burst, USB_BUS_EVENT_SUSPEND_END,
                   d->idle_end_abs, d->idle_end_abs - d->idle_start_abs);
    }
    d->suspended   = false;
    d->attach_idle = false;
    d->idle_open   = false;
}

/* Notes n whole idle words; reports a suspend or attach at the threshold, timed by bus position
 * (noinline: keeps usb_decode_run's loop). */
__attribute__((noinline))
static void __not_in_flash_func(idle_run_note)(usb_decoder_t *d, const usb_capture_t *cap,
                                               uint32_t run, uint32_t n, bool ended)
{
    const uint64_t start = usb_capture_sample_index(cap) + ((uint64_t)run << 4);
    if (!d->idle_open) {
        d->idle_open      = true;
        d->idle_start_abs = start;
    }
    d->idle_end_abs = start + ((uint64_t)n << 4);

    const uint64_t threshold = (uint64_t)d->suspend_words << 4;
    if (!d->suspended && d->idle_end_abs - d->idle_start_abs >= threshold) {
        d->suspended = true;
        if (d->packets_ok == d->packets_at_reset) {
            /* No packet since power-up, a host reset or a quiet SE0: a device just attached
             * (ATTACH, not SUSPEND). */
            d->attach_idle = true;
            emit_event_abs(d, cap, USB_BUS_EVENT_ATTACH, d->idle_start_abs, threshold);
        } else {
            burst_note(d, cap, &d->suspend_burst, USB_BUS_EVENT_SUSPEND,
                       d->idle_start_abs, threshold);
        }
    }
    if (ended) {
        idle_run_end(d, cap);
    }
}

/* ---- packet assembly ------------------------------------------------- */

/* Fills in one decoded packet (PID, fields, payload, CRC result), counts it and hands it on. */
static void finish_packet(usb_decoder_t *d, const usb_capture_t *cap,
                          const uint8_t *bytes, uint32_t nbytes,
                          usb_decode_status_t status, uint32_t bit_count,
                          uint64_t start_pos, uint64_t end_pos)
{
    /* Static: a usb_packet_t is over a kilobyte, and core1's stack is small. */
    static usb_packet_t pkt;
    /* Only the header is cleared: the payload is read only up to payload_len. */
    memset(&pkt, 0, offsetof(usb_packet_t, payload));
    pkt.timestamp_ns = pos_to_ns(cap, start_pos);
    pkt.bit_count    = (uint16_t)bit_count;
    /* Absolute, like the timestamp: start_pos counts from this pass's start. */
    pkt.first_sample = usb_capture_sample_index(cap) + start_pos;
    pkt.samples      = (uint32_t)(end_pos - start_pos);

    if (status == USB_DEC_OK) {
        if (nbytes < 2) {
            status = USB_DEC_ERR_TRUNCATED;
        } else if (bytes[0] != SYNC_BYTE) {
            status = USB_DEC_ERR_NO_SYNC;
        }
    }

    if (status == USB_DEC_OK) {
        uint8_t pid_byte = bytes[1];
        if ((uint8_t)(((pid_byte >> 4) ^ pid_byte) & 0x0Fu) != 0x0Fu) {
            status = USB_DEC_ERR_PID_CHECK;
        } else {
            pkt.pid  = (usb_pid_t)(pid_byte & 0x0Fu);
            pkt.type = usb_pid_type(pkt.pid);

            switch (pkt.type) {
            case USB_PKT_TYPE_TOKEN: {
                if (nbytes < 4) {
                    status = USB_DEC_ERR_TRUNCATED;
                    break;
                }
                uint16_t field = (uint16_t)(bytes[2] | ((bytes[3] & 0x07u) << 8));
                uint8_t  crc5  = (uint8_t)(bytes[3] >> 3);
                /* A token identical to the last that passed CRC5 passes too, without the bit loop
                 * (~130 cycles). */
                const uint32_t wire = (uint32_t)bytes[2] | ((uint32_t)bytes[3] << 8);
                if (wire != d->token_crc_ok) {
                    if (usb_crc5(field, 11) != crc5) {
                        status = USB_DEC_ERR_CRC5;
                        break;
                    }
                    d->token_crc_ok = wire;
                }
                if (pkt.pid == USB_PID_SOF) {
                    pkt.frame = field;
                } else {
                    pkt.addr     = (uint8_t)(field & 0x7Fu);
                    pkt.endpoint = (uint8_t)((field >> 7) & 0x0Fu);
                    d->last_token_ep = pkt.endpoint;
                    d->last_token_in = (pkt.pid == USB_PID_IN);
                    d->have_token    = true;
                }
                pkt.crc_ok = true;
                break;
            }
            case USB_PKT_TYPE_DATA: {
                if (nbytes < 4) {
                    status = USB_DEC_ERR_TRUNCATED;
                    break;
                }
                uint32_t len = nbytes - 4u;
                if (len > USB_MAX_PAYLOAD) {
                    status = USB_DEC_ERR_TOO_LONG;
                    break;
                }
                usb_copy_bytes(pkt.payload, &bytes[2], len);   /* not memcpy: flash */
                pkt.payload_len = (uint16_t)len;
                pkt.crc16 = (uint16_t)(bytes[nbytes - 2] | (bytes[nbytes - 1] << 8));
                pkt.crc_ok = (usb_crc16(pkt.payload, len) == pkt.crc16);
                if (!pkt.crc_ok) {
                    status = USB_DEC_ERR_CRC16;
                }
                break;
            }
            case USB_PKT_TYPE_HANDSHAKE:
                pkt.crc_ok = true;
                break;
            default:
                break;
            }
        }
    }

    pkt.status = status;

    switch (status) {
    case USB_DEC_OK:             d->packets_ok++;    break;
    case USB_DEC_ERR_NO_SYNC:    d->err_no_sync++;   d->packets_err++; break;
    case USB_DEC_ERR_PID_CHECK:  d->err_pid++;       d->packets_err++; break;
    case USB_DEC_ERR_CRC5:       d->err_crc5++;      d->packets_err++; break;
    case USB_DEC_ERR_CRC16:      d->err_crc16++;     d->packets_err++; break;
    case USB_DEC_ERR_BITSTUFF:   d->err_stuff++;     d->packets_err++; break;
    case USB_DEC_ERR_TRUNCATED:  d->err_truncated++; d->packets_err++; break;
    case USB_DEC_ERR_TOO_LONG:   d->err_too_long++;  d->packets_err++; break;
    case USB_DEC_ERR_SE1:        d->packets_err++; break;  /* counted by se1_note */
    }

    /* SOFs (one a millisecond) are counted, not kept in the ring. */
    if (status == USB_DEC_OK && pkt.pid == USB_PID_SOF) {
        d->sof_count++;
    } else if (status == USB_DEC_OK) {
        usb_pkt_summary_t *sum = &d->recent[d->recent_head];
        sum->ts_ns       = pkt.timestamp_ns;
        sum->payload_len = pkt.payload_len;
        sum->frame       = pkt.frame;
        sum->pid         = (uint8_t)pkt.pid;
        sum->type        = (uint8_t)pkt.type;
        sum->addr        = pkt.addr;
        sum->endpoint    = pkt.endpoint;
        /* The `p` printer shows at most 8 bytes, so all 8 are copied at once. */
        memcpy(sum->head, pkt.payload, sizeof(sum->head));
        d->recent_head = (d->recent_head + 1u) % USB_DECODE_RECENT;
        if (d->recent_count < USB_DECODE_RECENT) {
            d->recent_count++;
        }
    }

    if (d->on_packet) {
        d->on_packet(&pkt, d->ctx);
    }
}

/* ---- bit assembly ---------------------------------------------------- */

/* The NRZI bit stream assembled into bytes, stuffed bits dropped; bits accumulate LSB-first and
 * bytes fall out whole. */
typedef struct {
    uint8_t *bytes;
    uint32_t max;
    uint32_t nbytes;
    uint32_t acc;        /* pending data bits, LSB-first at bit 0 */
    uint32_t acc_bits;   /* how many of `acc` are valid (< 8 between calls) */
    uint32_t bit_count;  /* wire bits consumed, stuffed zeros included */
    uint8_t  ones;       /* consecutive data ones, for the stuffing rule */
    bool     overflow;
    bool     stuff_error;
} bitbuf_t;

/* Moves whole bytes from the bit accumulator into the byte buffer. */
static inline void bb_flush(bitbuf_t *b)
{
    while (b->acc_bits >= 8u) {
        if (b->nbytes >= b->max) {
            b->overflow = true;
            return;
        }
        b->bytes[b->nbytes++] = (uint8_t)b->acc;
        b->acc >>= 8;
        b->acc_bits -= 8u;
    }
}

/* Adds one wire bit: drops a stuffed zero, flags a missing one, and keeps data bits. */
static inline void bb_push(bitbuf_t *b, uint32_t bit)
{
    if (b->ones == 6u) {
        /* The bit after six ones is a stuffed zero: mandatory, and not data. */
        if (bit != 0u) {
            b->stuff_error = true;
            return;
        }
        b->ones = 0;
        b->bit_count++;
        return;
    }

    if (bit) {
        b->acc |= 1u << b->acc_bits;
        b->ones++;
    } else {
        b->ones = 0;
    }
    b->acc_bits++;
    b->bit_count++;
    bb_flush(b);
}

/* Under NRZI a gap of n bit times between transitions is n - 1 ones and the zero the transition
 * carries. */
static inline void bb_gap(bitbuf_t *b, uint32_t n, bool trailing)
{
    for (uint32_t i = 1; i < n; i++) {
        bb_push(b, 1);
    }
    if (!trailing) {
        bb_push(b, 0);
    }
}

/* bb_gap(b, n, false) in one step for a mid-packet gap of n <= 7 (no stuffing error possible). */
static inline void bb_gap_mid(bitbuf_t *b, uint32_t n)
{
    b->acc |= ((1u << (n - 1u)) - 1u) << b->acc_bits;
    b->acc_bits  += (n == 7u) ? 6u : n;
    b->bit_count += n;
    bb_flush(b);
}

/* ---- end of packet --------------------------------------------------- */

/* The first sample at or after `pos` that is not SE0, up to `limit` (the longest EOP) or `total`; a
 * word at a time. */
static inline uint32_t swallow_eop(const uint32_t *ring, uint32_t rbase, uint32_t pos,
                                   uint32_t total, uint32_t limit)
{
    while (pos < total && pos < limit) {
        const uint32_t w     = ring[(rbase + (pos >> 4)) & (USB_CAPTURE_RING_WORDS - 1u)];
        const uint32_t level = ((w | (w >> 1)) & 0x55555555u) >> ((pos & 15u) * 2u);
        if (level) {
            pos += (uint32_t)__builtin_ctz(level) >> 1;
            break;
        }
        pos = (pos | 15u) + 1u;   /* whole rest of the word is SE0 */
    }
    return (pos < limit) ? pos : limit;
}

/* ---- Option A: skip file data ---------------------------------------- */

/* Bytes decoded before a DATA packet on a non-zero endpoint can be skipped: 'U' (both signatures' first
 * byte) decides at 3, else at 6. */
#define OPTION_A_HEAD_BYTES 3u   /* SYNC, PID, first payload byte */

/* USB_DECODE_NO_SKIP=1 builds a decoder that decodes every DATA packet (core0's build); core1's
 * leaves it 0. */
#ifndef USB_DECODE_NO_SKIP
#define USB_DECODE_NO_SKIP 0
#endif

/* Decides from a packet's first bytes whether it is file data to skip (1), to decode (0), or to ask again at 6 bytes (-1). */
static inline int file_data_verdict(const usb_decoder_t *d, const uint8_t *b, uint32_t n)
{
#if USB_DECODE_NO_SKIP
    (void)d; (void)b; (void)n;
    return 0;
#endif
    /* skip_packet checks bit stuffing once per word, which needs an illegal gap longer than a word:
     * 3x or more. */
    if (d->oversample < 3u) {
        return 0;
    }
    uint8_t pid = b[1];
    if (b[0] != SYNC_BYTE || (((pid >> 4) ^ pid) & 0x0Fu) != 0x0Fu) {
        return 0;
    }
    if (usb_pid_type((usb_pid_t)(pid & 0x0Fu)) != USB_PKT_TYPE_DATA) {
        return 0;
    }
    if (!d->have_token || d->last_token_ep == 0u) {
        return 0;
    }
    if (b[2] != (uint8_t)MSC_CBW_SIGNATURE && b[2] != (uint8_t)MSC_CSW_SIGNATURE) {
        return 1;
    }
    if (n < 6u) {
        return -1;
    }
    uint32_t sig = (uint32_t)b[2] | ((uint32_t)b[3] << 8) |
                   ((uint32_t)b[4] << 16) | ((uint32_t)b[5] << 24);
    return (sig != MSC_CBW_SIGNATURE && sig != MSC_CSW_SIGNATURE) ? 1 : 0;
}

/* Walks words with no SE0 in bulk, stopping before the first that needs skip_packet's full rules
 * (noinline: its variables stay in registers). */
__attribute__((noinline))
static uint32_t __not_in_flash_func(skip_plain_run)(const uint32_t *ring, uint32_t rbase,
                                                    uint32_t p, uint32_t bound,
                                                    uint32_t stuff, uint32_t early,
                                                    uint32_t chirp,
                                                    uint32_t *last_edge_io,
                                                    uint32_t *prev_dp_io,
                                                    uint32_t *se1_count_io)
{
    uint32_t last_edge  = *last_edge_io;
    uint32_t prev_dp    = *prev_dp_io;
    uint32_t se1_count  = 0;
    /* Transitions of the word before, if it had any; while non-zero, last_edge is stale. */
    uint32_t prev_edges = 0;

    /* The loop steps word indices; `bound` combines the end of the data with the length bound. */
    const uint32_t first = rbase + (p >> 4);
    const uint32_t stop  = first + ((p < bound) ? ((bound - p + 15u) >> 4) : 0u);
    uint32_t idx = first;

    while (idx != stop) {
        const uint32_t w   = ring[idx & (USB_CAPTURE_RING_WORDS - 1u)];
        uint32_t       lo  = w & 0x55555555u;
        const uint32_t se1 = se1_mask(w);
        if ((lo | ((w >> 1) & 0x55555555u)) != 0x55555555u) {
            break;                                   /* SE0 in this word */
        }
        if (se1) {
            if (se1 & (se1 << 2)) {
                break;                               /* adjacent SE1: general path */
            }
            se1_count += popcount32(se1);
            lo = repair_lone_glitches(lo, se1, prev_dp);
        }
        const uint32_t edges = (lo ^ ((lo << 2) | prev_dp)) & 0x55555555u;
        if (prev_edges == 0u || (edges & early) == 0u) {
            /* Not the common case: bring last_edge up to date, then apply the stuffing and chirp
             * rules exactly. */
            const uint32_t pw = p + ((idx - first) << 4);   /* this word's first sample */
            if (prev_edges) {
                last_edge = (pw - 16u) + ((31u - (uint32_t)__builtin_clz(prev_edges)) >> 1);
            }
            if (edges) {
                if (pw + ((uint32_t)__builtin_ctz(edges) >> 1) - last_edge >= stuff) {
                    /* bit-stuffing violation; the word is handed back uncounted */
                    se1_count -= popcount32(se1_mask(ring[idx & (USB_CAPTURE_RING_WORDS - 1u)]));
                    break;
                }
            } else if ((pw + 16u) - last_edge > chirp) {
                /* parked line; the word is handed back uncounted */
                se1_count -= popcount32(se1_mask(ring[idx & (USB_CAPTURE_RING_WORDS - 1u)]));
                break;
            }
        }
        prev_edges = edges;
        prev_dp = (lo >> 30) & 1u;
        idx++;
    }

    p += (idx - first) << 4;                         /* first sample not walked */

    /* The last word consumed: if it had transitions, its last is the last transition. */
    if (prev_edges) {
        last_edge = (p - 16u) + ((31u - (uint32_t)__builtin_clz(prev_edges)) >> 1);
    }
    *last_edge_io = last_edge;
    *prev_dp_io   = prev_dp;
    *se1_count_io = se1_count;
    return p;
}

/* Notes the SE1 samples a plain run repaired over words [from, to), as the general path would per
 * word. */
static void __not_in_flash_func(note_run_se1)(usb_decoder_t *d, const usb_capture_t *cap,
                                             const uint32_t *ring, uint32_t rbase,
                                             uint32_t from, uint32_t to, uint32_t count)
{
    uint32_t pos = from & ~15u;   /* notes carry the word's start, as in the general paths */
    if (d->se1_burst == 0u) {
        uint32_t keep = 0x55555555u << ((from & 15u) * 2u);   /* a partial first word */
        while (pos < to &&
               (se1_mask(ring[(rbase + (pos >> 4)) & (USB_CAPTURE_RING_WORDS - 1u)]) & keep) == 0u) {
            pos += 16u;
            keep = 0x55555555u;
        }
    }
    se1_note_n(d, cap, pos, count);
}

/* Walks over a file-data packet with every framing rule but no bit assembly; returns its length in samples, or 0 if it has not ended yet. */
static uint32_t __not_in_flash_func(skip_packet)(usb_decoder_t *d, usb_capture_t *cap,
                                                 uint32_t start,
                                                 uint32_t from, uint32_t total,
                                                 uint32_t prev_dp, uint32_t last_edge)
{
    const uint32_t *ring  = cap->ring;
    const uint32_t  rbase = cap->read_idx;
    const uint32_t  rmask = USB_CAPTURE_RING_WORDS - 1u;
    const uint32_t  need  = d->eop_se0_samples;
    const uint32_t  stuff = d->stuff_gap_samples;
    const uint32_t  chirp = d->chirp_samples;
    const uint32_t  max_len = d->max_packet_samples;
    uint32_t words  = 0;
    uint32_t result = 0;

    /* skip_plain_run's single limit: the end of the data and the length bound. */
    const uint32_t len_bound   = start + max_len - 15u;
    const uint32_t plain_bound = (total < len_bound) ? total : len_bound;
    /* skip_plain_run's early-transition mask: samples 0 .. stuff-17 of a word. */
    const uint32_t early_n = stuff - 16u;
    const uint32_t early   = (early_n >= 16u) ? 0x55555555u
                                              : (((1u << (2u * early_n)) - 1u) & 0x55555555u);

    uint32_t p = from;
    while (p < total) {
        /* Plain J/K words in bulk; skip_plain_run stops before any word the rules below decide. */
        uint32_t se1_count;
        USB_DPROF_START(plain_t0);
        const uint32_t q = skip_plain_run(ring, rbase, p, plain_bound,
                                          stuff, early, chirp, &last_edge, &prev_dp, &se1_count);
        USB_DPROF_ADD(d->prof_skip_plain_cyc, plain_t0);
        if (se1_count) {
            note_run_se1(d, cap, ring, rbase, p, q, se1_count);
        }
        USB_DPROF_COUNT(d->prof_skip_plain_words, (q - p) >> 4);
        words += (q - p) >> 4;
        p = q;
        if (p >= total) {
            break;
        }

        uint32_t w  = ring[(rbase + (p >> 4)) & rmask];
        uint32_t lo = w & 0x55555555u;
        uint32_t hi = (w >> 1) & 0x55555555u;
        words++;

        /* General path: the word holds SE0 or SE1, or is a plain word that ends the skip. */
        uint32_t se0    = (~(lo | hi)) & 0x55555555u;
        uint32_t se1    = lo & hi;
        uint32_t glitch = se1;
        uint32_t eop_at = 16u;           /* sample of the EOP in this word; 16 = none */
        if (se0) {
            USB_DPROF_COUNT(d->skip_fallback_se0, 1u);
        }

        /* 1. End of packet. */
        if (se0) {
            const bool have_next = (p + 16u) < total;
            uint64_t se0e = (uint64_t)se0;
            if (have_next) {
                uint32_t wn  = ring[(rbase + (p >> 4) + 1u) & rmask];
                uint32_t lon = wn & 0x55555555u;
                uint32_t hin = (wn >> 1) & 0x55555555u;
                se0e |= (uint64_t)((~(lon | hin)) & 0x55555555u) << 32;
            }
            uint64_t runs = se0e;
            for (uint32_t k = 1u; k < need; k++) {
                runs &= se0e >> (k * 2u);
            }

            uint32_t eop = (uint32_t)runs & se0;
            if (eop) {
                eop_at  = (uint32_t)__builtin_ctz(eop) >> 1;
                glitch |= se0 & ((1u << (eop_at * 2u)) - 1u);
            } else {
                if (!have_next) {
                    uint32_t hi_i = (31u - (uint32_t)__builtin_clz(se0)) >> 1;
                    if (p + hi_i + need > total) {
                        break;   /* cannot tell yet; wait for more samples */
                    }
                }
                glitch |= se0;
            }
        }

        if (se1) {
            se1_note_n(d, cap, p, popcount32(se1));
        }

        /* 2. Glitch repair. */
        lo = repair_glitches(lo, glitch, prev_dp);

        /* 3. Bit-stuffing rule, on transitions before the EOP. */
        uint32_t edges = (lo ^ ((lo << 2) | prev_dp)) & 0x55555555u;
        if (eop_at < 16u) {
            edges &= (1u << (eop_at * 2u)) - 1u;
        }
        if (edges) {
            uint32_t first = p + ((uint32_t)__builtin_ctz(edges) >> 1);
            if (first - last_edge >= stuff) {   /* more than 7 bit times, no divide */
                d->err_stuff++;
                d->packets_err++;
                d->sop_count++;
                result = first - start;   /* resume at the transition, as decode_packet does */
                break;
            }
            last_edge = p + ((31u - (uint32_t)__builtin_clz(edges)) >> 1);
        }

        if (eop_at < 16u) {
            /* Swallows the EOP, no longer than an EOP can be. */
            const uint32_t pos = swallow_eop(ring, rbase, p + eop_at, total,
                                             p + eop_at + d->eop_max_samples);
            d->packets_skipped++;
            d->packets_skipped_in += d->last_token_in ? 1u : 0u;
            d->sop_count++;
            result = pos - start;
            break;
        }

        /* 4. A parked line is a chirp or a stuck driver, not data. */
        if ((p + 16u) - last_edge > chirp) {
            d->chirps++;
            burst_note(d, cap, &d->chirp_burst, USB_BUS_EVENT_CHIRP,
                       usb_capture_sample_index(cap) + start, (p + 16u) - last_edge);
            result = (p + 16u) - start;
            break;
        }

        if ((p + 16u) - start > max_len) {
            /* No end of packet within the longest legal packet. */
            d->err_too_long++;
            d->packets_err++;
            d->sop_count++;
            result = (p + 16u) - start;
            break;
        }

        prev_dp = (lo >> 30) & 1u;
        p += 16u;
    }

    d->packet_words += words;
    d->skip_words   += words;
    return result;
}

/* For decode_plain_run: where a clean end of packet starts in a word holding SE0, or 16 if there is
 * none to be sure of. */
__attribute__((noinline))
static uint32_t __not_in_flash_func(eop_start)(const uint32_t *ring, uint32_t rbase,
                                               uint32_t p, uint32_t end,
                                               uint32_t se0, uint32_t need)
{
    const uint32_t at = (uint32_t)__builtin_ctz(se0) >> 1;
    uint64_t se0e = se0;
    if (at + need > 16u) {
        if (p + 16u >= end) {
            return 16u;                        /* the run may continue past the data */
        }
        const uint32_t wn = ring[(rbase + (p >> 4) + 1u) & (USB_CAPTURE_RING_WORDS - 1u)];
        se0e |= (uint64_t)((~(wn | (wn >> 1))) & 0x55555555u) << 32;
    }
    const uint64_t run = ((1ull << (2u * need)) - 1u) & 0x5555555555555555ull;
    return (((se0e >> (at * 2u)) & run) == run) ? at : 16u;
}

/* Bit 31 of decode_plain_run's `keep` marks the word holding the end of packet (no sample mask has
 * it). */
#define KEEP_EOP 0x80000000u

/* decode_packet's word loop for words with no SE0, stopping before any word that needs the full loop
 * (noinline, as skip_plain_run). */
__attribute__((noinline))
static uint32_t __not_in_flash_func(decode_plain_run)(const uint32_t *ring, uint32_t rbase,
                                                      uint32_t p, uint32_t end,
                                                      uint32_t os, uint32_t stuff,
                                                      uint32_t chirp, uint32_t stop_bytes,
                                                      uint32_t need,
                                                      bitbuf_t *bb,
                                                      uint32_t *last_edge_io,
                                                      uint32_t *prev_dp_io,
                                                      uint32_t *se1_count_io,
                                                      uint32_t *eop_at_io)
{
    *eop_at_io = UINT32_MAX;                   /* set if the run ends at the EOP */
    const uint32_t half    = (os >= 2u) ? (os / 2u) : 1u;
    const uint32_t one_bit = 2u * os - half;   /* gap < one_bit: (gap + half) / os <= 1 */
    const uint32_t p_in    = p;
    uint32_t se1_count = 0;
    uint32_t stuffed   = 0;                    /* stuffed zeros: wire bits, not data */
    /* Bytes go out through a pointer, and the limit is a pointer too: one register instead of
     * three. */
    uint8_t       *out      = bb->bytes + bb->nbytes;
    const uint8_t *out_stop = bb->bytes + stop_bytes;
    uint32_t acc       = bb->acc;
    uint32_t acc_bits  = bb->acc_bits;
    uint32_t last_edge = *last_edge_io;
    uint32_t prev_dp   = *prev_dp_io;

    /* Only the first word's samples from `p` on are the packet's. */
    uint32_t keep = 0x55555555u << ((p & 15u) * 2u);
    p &= ~15u;

    while (p < end) {
        if (out >= out_stop) {
            /* A non-DATA PID is never skipped: run on to the byte limit rather than stop at the
             * head check. */
            if (out_stop != bb->bytes + OPTION_A_HEAD_BYTES || (out_stop[-2] & 0x3u) == 0x3u) {
                break;
            }
            out_stop = bb->bytes + (DECODE_MAX_BYTES - 3u);
        }
        const uint32_t w   = ring[(rbase + (p >> 4)) & (USB_CAPTURE_RING_WORDS - 1u)];
        uint32_t       lo  = w & 0x55555555u;
        const uint32_t se1 = se1_mask(w) & keep;
        if (((lo | (w >> 1) | ~keep) & 0x55555555u) != 0x55555555u) {
            /* SE0 here: a clean end of packet is handled; a glitch, or a run that may continue,
             * goes to the general path. */
            const uint32_t at = eop_start(ring, rbase, p, end,
                                          (~(lo | (w >> 1))) & keep & 0x55555555u, need);
            if (at == 16u) {
                break;
            }
            *eop_at_io = p + at;
            keep = (keep & ((1u << (at * 2u)) - 1u)) | KEEP_EOP;
        }
        if (se1) {
            if (se1 & (se1 << 2)) {
                *eop_at_io = UINT32_MAX;             /* handed back, so not ended here */
                break;                               /* adjacent SE1: general path */
            }
            se1_count += popcount32(se1);            /* the whole word, as the general path notes it */
            lo = repair_lone_glitches(lo, se1, prev_dp);
        }
        uint32_t edges = (lo ^ ((lo << 2) | prev_dp)) & keep;
        if (edges) {
            if (p + ((uint32_t)__builtin_ctz(edges) >> 1) - last_edge >= stuff) {
                /* Bit-stuffing violation: the word goes back to the general path, uncounted and not
                 * ended. */
                se1_count -= popcount32(se1);
                *eop_at_io = UINT32_MAX;
                break;
            }
            do {
                const uint32_t epos = p + ((uint32_t)__builtin_ctz(edges) >> 1);
                const uint32_t gap  = epos - last_edge;
                if (gap < one_bit) {
                    acc_bits++;                      /* a single zero bit */
                } else {
                    /* n - 1 ones, then a zero unless it is the stuffed zero. */
                    const uint32_t n = (gap + half) / os;   /* 2..7 */
                    acc |= ((1u << (n - 1u)) - 1u) << acc_bits;
                    if (n == 7u) {
                        acc_bits += 6u;
                        stuffed++;
                    } else {
                        acc_bits += n;
                    }
                }
                if (acc_bits >= 8u) {
                    *out++ = (uint8_t)acc;
                    acc >>= 8;
                    acc_bits -= 8u;
                }
                last_edge = epos;
                edges &= edges - 1u;
            } while (edges);
        } else if ((keep & KEEP_EOP) == 0u && (p + 16u) - last_edge > chirp) {
            /* parked line; the word is handed back uncounted */
            se1_count -= popcount32(se1_mask(ring[(rbase + (p >> 4)) & (USB_CAPTURE_RING_WORDS - 1u)]) & keep);
            break;
        }
        if (keep & KEEP_EOP) {
            p += 16u;                                /* the EOP word is consumed */
            break;
        }
        prev_dp = (lo >> 30) & 1u;
        p += 16u;
        keep = 0x55555555u;
    }

    /* Wire bits: the data bits added plus stuffed zeros. */
    const uint32_t nbytes = (uint32_t)(out - bb->bytes);
    bb->bit_count += 8u * (nbytes - bb->nbytes) + (acc_bits - bb->acc_bits) + stuffed;
    bb->nbytes    = nbytes;
    bb->acc       = acc;
    bb->acc_bits  = acc_bits;
    *last_edge_io = last_edge;
    *prev_dp_io   = prev_dp;
    *se1_count_io = se1_count;
    /* A first word not consumed is handed back where it started. */
    return (p == (p_in & ~15u)) ? p_in : p;
}

/* decode_packet's steps, one function each; forced inline, so their locals stay in registers. */
#define DECODE_STEP static inline __attribute__((always_inline))

/* What find_eop found in a word: no end of packet, one, or one that needs more data to be sure. */
typedef enum { EOP_NONE = 0, EOP_FOUND, EOP_WAIT } eop_find_t;

/* The end of packet in a word: the first SE0 lasting a bit time, found with masks (shorter SE0 is a
 * glitch). */
DECODE_STEP eop_find_t find_eop(usb_decoder_t *d, const uint32_t *ring, uint32_t rbase,
                                uint32_t widx, uint32_t wbase, uint32_t total, uint32_t se0,
                                uint32_t *stop, uint32_t *glitch)
{
    const uint32_t rmask     = USB_CAPTURE_RING_WORDS - 1u;
    const uint32_t need      = d->eop_se0_samples;
    const bool     have_next = (wbase + 16u) < total;
    const uint32_t cand      = se0;   /* already restricted by keep */
    eop_find_t     found     = EOP_NONE;

    uint64_t se0e = (uint64_t)se0;
    if (have_next) {
        uint32_t wn  = ring[(rbase + widx + 1u) & rmask];
        uint32_t lon = wn & 0x55555555u;
        uint32_t hin = (wn >> 1) & 0x55555555u;
        se0e |= (uint64_t)((~(lon | hin)) & 0x55555555u) << 32;
    }

    uint64_t runs = se0e;
    for (uint32_t k = 1u; k < need; k++) {
        runs &= se0e >> (k * 2u);
    }

    uint32_t eop = (uint32_t)runs & cand;
    if (eop) {
        uint32_t i = (uint32_t)__builtin_ctz(eop) >> 1;
        *stop = wbase + i;
        found = EOP_FOUND;
        /* SE0 samples before the EOP were glitches. */
        *glitch |= cand & ((1u << (i * 2u)) - 1u);
    } else {
        /* No run begins in this word; with no next word held, a candidate near the end cannot be
         * judged yet. */
        if (!have_next) {
            uint32_t hi_i = (31u - (uint32_t)__builtin_clz(cand)) >> 1;
            if (wbase + hi_i + need > total) {
                return EOP_WAIT;
            }
        }
        *glitch |= cand;
    }
    USB_DPROF_COUNT(d->prof_se0_bits, popcount32(cand));
    return found;
}

/* Turns a word's transitions into bits; an illegal gap, stuffing error or overlong packet ends the
 * packet. */
DECODE_STEP void decode_edges(bitbuf_t *bb, uint32_t edges, uint32_t wbase, uint32_t os, uint32_t half,
                              uint32_t *last_edge, uint32_t *stop, bool *done, usb_decode_status_t *status)
{
    uint32_t e = edges;
    while (e) {
        uint32_t i    = (uint32_t)__builtin_ctz(e) >> 1;
        uint32_t epos = wbase + i;
        uint32_t gap  = epos - *last_edge;

        /* A 32-bit divide (one UDIV): a 64-bit gap would call __aeabi_uldivmod once per transition. */
        uint32_t n = (gap + half) / os;
        if (n == 0u) {
            n = 1u;
        }
        if (n > 7u) {
            *status = USB_DEC_ERR_BITSTUFF;
            *stop = epos;
            *done = true;
            break;
        }

        bb_gap_mid(bb, n);
        *last_edge = epos;
        e &= e - 1u;

        if (bb->stuff_error || bb->overflow) {
            break;
        }
    }

    if (bb->stuff_error) {
        *status = USB_DEC_ERR_BITSTUFF;
        *done = true;
        *stop = *last_edge;
    } else if (bb->overflow) {
        *status = USB_DEC_ERR_TOO_LONG;
        *done = true;
        *stop = *last_edge;
    }
}

/* Adds the bits after the last transition, then swallows the EOP (no longer: a longer SE0 is a
 * reset). */
DECODE_STEP uint32_t finish_bits(const usb_decoder_t *d, bitbuf_t *bb, const uint32_t *ring, uint32_t rbase,
                                 uint32_t pos, uint32_t total, uint32_t last_edge, uint32_t os, uint32_t half,
                                 usb_decode_status_t *status)
{
    if (*status == USB_DEC_OK && pos > last_edge) {
        uint32_t n = ((pos - last_edge) + half) / os;
        if (n > 1u && n <= 8u) {
            bb_gap(bb, n, true);
        }
        if (bb->stuff_error) {
            *status = USB_DEC_ERR_BITSTUFF;
        } else if (bb->overflow) {
            *status = USB_DEC_ERR_TOO_LONG;
        }
    }
    return swallow_eop(ring, rbase, pos, total, pos + d->eop_max_samples);
}

/* Decodes one packet from its first non-idle sample; returns the samples consumed, or 0 if it runs past
 * the data held. A word at a time: one XOR finds a word's transitions, and the gaps between them give the bits. */
static uint32_t __not_in_flash_func(decode_packet)(usb_decoder_t *d, usb_capture_t *cap,
                              uint32_t start, uint32_t total)
{
    const uint32_t os   = d->oversample;
    const uint32_t half = (os >= 2u) ? (os / 2u) : 1u;

    /* The ring through locals, not reloaded from cap on every word. */
    const uint32_t *ring  = cap->ring;
    const uint32_t  rbase = cap->read_idx;
    const uint32_t  rmask = USB_CAPTURE_RING_WORDS - 1u;

    static uint8_t bytes[DECODE_MAX_BYTES];
    bitbuf_t bb;
    memset(&bb, 0, sizeof(bb));
    bb.bytes = bytes;
    bb.max   = DECODE_MAX_BYTES;

    /* D+ level while idle; a packet begins with the line in the opposite state. */
    const uint32_t idle_dp = (d->idle_line == USB_LINE_DP) ? 1u : 0u;
    uint32_t prev_dp   = 1u - idle_dp;
    uint32_t last_edge = start;

    /* The start-of-packet transition is itself the first NRZI zero. */
    bb_push(&bb, 0);

    usb_decode_status_t status = USB_DEC_OK;
    uint32_t pos  = start + 1u;
    bool     done = false;
    /* Bytes needed before the next Option A decision: 3, then 6 if that byte was 'U'; 0 once
     * decided. */
    uint32_t head_need = OPTION_A_HEAD_BYTES;

    while (pos < total) {
        /* Option A: enough of the head is in; file data is skipped from here, carrying the line
         * level and last edge. */
        if (head_need != 0u && bb.nbytes >= head_need) {
            const int verdict = file_data_verdict(d, bytes, bb.nbytes);
            if (verdict > 0) {
                USB_DPROF_START(skip_t0);
                uint32_t skipped = skip_packet(d, cap, start, pos, total,
                                               prev_dp, last_edge);
                USB_DPROF_ADD(d->prof_skip_cyc, skip_t0);
                return skipped;
            }
            head_need = (verdict < 0) ? 6u : 0u;
        }

        /* Plain words in bulk; decode_plain_run stops before any word the rules below decide, and
         * before the head check. */
        uint32_t se1_count, eop_at;
        USB_DPROF_START(plain_t0);
        const uint32_t q = decode_plain_run(ring, rbase, pos, total, os,
                                            d->stuff_gap_samples, d->chirp_samples,
                                            head_need ? head_need : DECODE_MAX_BYTES - 3u,
                                            d->eop_se0_samples,
                                            &bb, &last_edge, &prev_dp, &se1_count, &eop_at);
        USB_DPROF_ADD(d->prof_plain_cyc, plain_t0);
        if (se1_count) {
            note_run_se1(d, cap, ring, rbase, pos, q, se1_count);
        }
        /* Words consumed (q is a word start whenever any were). */
        USB_DPROF_COUNT(d->prof_plain_words, (q - (pos & ~15u)) >> 4);
        USB_DPROF_COUNT(d->prof_plain_calls, 1u);
        d->packet_words     += (q - (pos & ~15u)) >> 4;
        pos = q;
        if (eop_at != UINT32_MAX) {
            /* The plain run reached the end of packet: finish as the general path does. */
            pos  = eop_at;
            done = true;
            break;
        }
        if (pos >= total) {
            break;
        }
        if (head_need != 0u && bb.nbytes >= head_need) {
            continue;
        }

        uint32_t widx  = pos >> 4;
        uint32_t off   = pos & 15u;
        uint32_t w     = ring[(rbase + widx) & rmask];
        uint32_t wbase = widx << 4;

        d->packet_words++;

        uint32_t lo  = w & 0x55555555u;
        uint32_t hi  = (w >> 1) & 0x55555555u;
        uint32_t se0 = (~(lo | hi)) & 0x55555555u;
        uint32_t se1 = lo & hi;

        uint32_t keep = 0x55555555u << (off * 2u);
        se0 &= keep;
        se1 &= keep;
        if (off != 0u) {
            USB_DPROF_COUNT(d->dec_fallback_first, 1u);
        } else if (se0) {
            USB_DPROF_COUNT(d->dec_fallback_se0, 1u);
        }

        /* The end of packet, if it is in this word, and the SE0 glitches. */
        uint32_t stop   = wbase + 16u;   /* exclusive unless an EOP is found */
        uint32_t glitch = se1;
        if (se0) {
            const eop_find_t f = find_eop(d, ring, rbase, widx, wbase, total, se0, &stop, &glitch);
            if (f == EOP_WAIT) {
                return 0;   /* cannot tell yet; wait for more samples */
            }
            done = (f == EOP_FOUND);
        }

        if (se1) {
            se1_note_n(d, cap, wbase, popcount32(se1));
        }

        /* Glitch samples take the level of the sample before them. */
        lo = repair_glitches(lo, glitch, prev_dp);

        /* Every transition in the word, in one XOR. */
        uint32_t shifted = (lo << 2) | prev_dp;
        uint32_t edges   = (lo ^ shifted) & 0x55555555u & keep;

        /* Transitions at or past the end of packet are not data. */
        if (done) {
            uint32_t upto = stop - wbase;
            edges &= (upto >= 16u) ? 0x55555555u : ((1u << (upto * 2u)) - 1u);
        }

        decode_edges(&bb, edges, wbase, os, half, &last_edge, &stop, &done, &status);

        if (done) {
            pos = stop;
            break;
        }

        /* A line parked far longer than any packet is a chirp or a stuck driver, not data. */
        if ((wbase + 16u) - last_edge > d->chirp_samples) {
            uint32_t held = (wbase + 16u) - last_edge;
            d->chirps++;
            burst_note(d, cap, &d->chirp_burst, USB_BUS_EVENT_CHIRP,
                       usb_capture_sample_index(cap) + start, held);
            return (wbase + 16u) - start;
        }

        prev_dp = (lo >> 30) & 1u;    /* level of sample 15, for the next word */
        pos = wbase + 16u;
    }

    if (!done) {
        return 0;   /* incomplete: ask for more samples */
    }

    USB_DPROF_START(tail_t0);
    pos = finish_bits(d, &bb, ring, rbase, pos, total, last_edge, os, half, &status);
    USB_DPROF_ADD(d->prof_tail_cyc, tail_t0);

    d->sop_count++;
    USB_DPROF_START(fin_t0);
    finish_packet(d, cap, bytes, bb.nbytes, status, bb.bit_count, start, pos);
    USB_DPROF_ADD(d->prof_finish_cyc, fin_t0);
    return pos - start;
}

/* ---- main loop ------------------------------------------------------- */

/* The main loop: consumes everything available in `cap`. */
/* Index just past the run of words equal to `value` from word i, up to `avail`, walked by pointer
 * up to the wrap. */
static inline uint32_t same_word_run(const uint32_t *ring, uint32_t base, uint32_t i,
                                     uint32_t avail, uint32_t value)
{
    const uint32_t mask = USB_CAPTURE_RING_WORDS - 1u;
    do {
        const uint32_t at = (base + i) & mask;
        uint32_t n = USB_CAPTURE_RING_WORDS - at;      /* words before the wrap */
        if (n > avail - i) {
            n = avail - i;
        }
        const uint32_t *const first = ring + at;
        const uint32_t *const end   = first + n;
        const uint32_t *q = first + 1;                 /* *first is known equal */
        while (q < end && *q == value) {
            q++;
        }
        i += (uint32_t)(q - first);
    } while (i < avail && ring[(base + i) & mask] == value);
    return i;
}

/* Decodes what the capture holds, up to DECODE_PASS_MAX_WORDS of new work; returns the words consumed.
 * Over 97% of words are idle or flat SE0, so it is first a skipping loop, on 32-bit indices, per run of words. */
uint32_t __not_in_flash_func(usb_decode_run)(usb_decoder_t *d, usb_capture_t *cap)
{
    uint32_t avail = usb_capture_available(cap);
    if (avail == 0u) {
        return 0;
    }
    /* Words beyond one ring were already overwritten; usb_capture_poll counts them as lost. */
    if (avail > USB_CAPTURE_RING_WORDS) {
        avail = USB_CAPTURE_RING_WORDS;
    }

    const uint32_t *ring = cap->ring;
    const uint32_t  mask = USB_CAPTURE_RING_WORDS - 1u;
    const uint32_t  base = cap->read_idx;
    const uint32_t  idle = d->idle_word;
    const bool      idle_is_dp = (d->idle_line == USB_LINE_DP);
    const uint32_t total = avail * USB_CAPTURE_SAMPLES_PER_WORD;

    uint32_t i   = 0;   /* word index within the available run */
    uint32_t off = 0;   /* sample offset to resume at inside word i */

    /* Resume at the incomplete packet's first sample, not its word's start (unless a capture drop
     * moved the position). */
    if (d->resume_off != 0u && d->resume_at_read == cap->total_read) {
        off = d->resume_off;
    }
    d->resume_off = 0;

    /* An idle run left open continues only if this pass starts exactly where it stopped, on a whole
     * idle word. */
    if (d->idle_open &&
        (off != 0u || ring[base] != idle ||
         usb_capture_sample_index(cap) != d->idle_end_abs)) {
        idle_run_end(d, cap);
    }

    /* A drop since the last pass: the stream resumes wherever the drop left it, usually inside a
     * packet. */
    if (cap->overrun_words != d->seen_overrun_words) {
        d->seen_overrun_words = cap->overrun_words;
        d->resync = true;
        d->resyncs++;
    }

    while (i < avail) {
        /* The pass length bound: resume at exactly this sample next pass, so pass ends never change
         * the output. */
        if (i >= DECODE_PASS_MAX_WORDS) {
            d->resume_off     = off;
            d->resume_at_read = cap->total_read + i;   /* after the consume below */
            break;
        }

        uint32_t w = ring[(base + i) & mask];

        /* Run of pure bus idle. */
        if (w == idle && off == 0u) {
            uint32_t run = i;
            i = same_word_run(ring, base, i, avail, idle);

            d->idle_words_skipped += (i - run);
            /* The SE0 run before this idle ends first, so ATTACH or SUSPEND does not depend on pass
             * boundaries. */
            if (d->se0_run != 0u) {
                se0_end(d, cap);
            }
            if (d->idle_open || i >= avail || (i - run) >= d->suspend_words) {
                idle_run_note(d, cap, run, i - run, i < avail);
            }
            if (d->resync && (i - run) >= 2u) {
                /* 32 samples of J, longer than any J inside a packet: the bus is idle. */
                d->resync = false;
            }
            continue;
        }

        /* Run of flat SE0: an unpopulated port, or a bus reset in progress. */
        if (w == 0u && off == 0u) {
            uint32_t run = i;
            i = same_word_run(ring, base, i, avail, 0u);

            uint32_t n = i - run;
            d->se0_words += n;
            d->resync = false;   /* a whole word of SE0 is at least an end of packet */
            se0_advance(d, cap, (uint64_t)run << 4,
                        n * USB_CAPTURE_SAMPLES_PER_WORD);
            continue;
        }

        /* A run of whole SE1 words (as while a drive is plugged in) is noted at once, not word by
         * word. */
        if (w == 0xFFFFFFFFu && off == 0u && !d->resync) {
            const uint32_t run = i;
            const uint32_t lim = (avail < DECODE_PASS_MAX_WORDS) ? avail : DECODE_PASS_MAX_WORDS;
            i = same_word_run(ring, base, i, lim, 0xFFFFFFFFu);
            const uint32_t n = i - run;
            se1_note_n(d, cap, (uint64_t)run << 4, n * USB_CAPTURE_SAMPLES_PER_WORD);
            d->nonidle_words += n;
            for (uint32_t k = 0; k < n && d->raw_count < USB_DECODE_RAW_SLOTS; k++) {
                d->raw_words[d->raw_count++] = w;
            }
            if (d->se0_run != 0u) {
                se0_end(d, cap);
            }
            continue;
        }

        /* Anything else: work out whether a packet can start in this word. */
        uint32_t lo  = w & 0x55555555u;
        uint32_t hi  = (w >> 1) & 0x55555555u;
        uint32_t se1 = lo & hi;
        uint32_t sop = idle_is_dp ? (hi & ~lo) : (lo & ~hi);

        if (off != 0u) {
            sop &= 0x55555555u << (off * 2u);
            se1 &= 0x55555555u << (off * 2u);
        }

        if (se1 != 0u) {
            se1_note_n(d, cap, (uint64_t)i << 4,
                       popcount32(se1));
        }

        /* After a capture drop no packet starts until the bus is provably between packets (an EOP,
         * SE0 word, idle or long K). */
        if (d->resync) {
            if (d->se0_run != 0u) {
                se0_end(d, cap);
            }
            /* A word with no SE0 that is neither all idle nor all K cannot end the resync: passed
             * over with one mask test. */
            if (w != ~idle &&
                ((lo | hi | ~(0x55555555u << (off * 2u))) & 0x55555555u) == 0x55555555u) {
                uint32_t j = i + 1u, se1_n = 0u, se1_at = 0u;
                uint32_t all_se1 = (w == 0xFFFFFFFFu) ? 1u : 0u;
                while (j < avail && j < DECODE_PASS_MAX_WORDS) {
                    const uint32_t wj = ring[(base + j) & mask];
                    if (wj == idle || wj == ~idle ||
                        ((wj | (wj >> 1)) & 0x55555555u) != 0x55555555u) {
                        break;
                    }
                    all_se1 += (wj == 0xFFFFFFFFu) ? 1u : 0u;
                    const uint32_t s1 = wj & (wj >> 1) & 0x55555555u;
                    if (s1) {
                        if (se1_n == 0u) {
                            se1_at = j;
                        }
                        se1_n += popcount32(s1);
                    }
                    j++;
                }
                if (se1_n) {
                    se1_note_n(d, cap, (uint64_t)se1_at << 4, se1_n);
                }
                d->resync_words     += j - i;
                d->resync_se1_words += all_se1;
                i   = j;
                off = 0;
                continue;
            }
            const uint32_t need = d->eop_se0_samples;
            uint64_t se0e = (uint64_t)((~(lo | hi)) & 0x55555555u);
            if (i + 1u < avail) {
                const uint32_t wn = ring[(base + i + 1u) & mask];
                se0e |= (uint64_t)((~(wn | (wn >> 1))) & 0x55555555u) << 32;
            }
            uint64_t runs = se0e;
            for (uint32_t r = 1u; r < need; r++) {
                runs &= se0e >> (r * 2u);
            }
            const uint32_t eop = (uint32_t)runs & (0x55555555u << (off * 2u));
            if (eop) {
                d->resync = false;
                const uint32_t next = (i << 4) + ((uint32_t)__builtin_ctz(eop) >> 1) + need;
                i   = next >> 4;
                off = next & 15u;
                continue;
            }
            if (w == ~idle && i > 0u && ring[(base + i - 1u) & mask] == ~idle) {
                d->resync = false;   /* fall through to the normal path */
            } else {
                d->resync_words++;
                if (w == 0xFFFFFFFFu) {
                    d->resync_se1_words++;
                }
                i++;
                off = 0;
                continue;
            }
        }

        if (sop == 0u) {
            /* No transition into the non-idle state, so no packet begins here. */
            d->nonidle_words++;
            if (d->raw_count < USB_DECODE_RAW_SLOTS) {
                d->raw_words[d->raw_count++] = w;
            }
            if (d->se0_run != 0u) {
                se0_end(d, cap);
            }
            i++;
            off = 0;
            continue;
        }

        if (d->raw_count < USB_DECODE_RAW_SLOTS) {
            d->raw_words[d->raw_count++] = w;
        }
        se0_end(d, cap);

        uint32_t k = (uint32_t)__builtin_ctz(sop) >> 1;
        uint32_t p = (i << 4) + k;

        const uint64_t words_before = d->packet_words;
        USB_DPROF_START(pkt_t0);
        uint32_t used = decode_packet(d, cap, p, total);
        USB_DPROF_ADD(d->prof_pkt_cyc, pkt_t0);
        USB_DPROF_COUNT(d->prof_pkt_calls, 1u);
        if (used == 0u) {
            d->rewalk_words += d->packet_words - words_before;
            /* The packet runs past the data held: left for the next pass. It cannot stall: every
             * packet ends within the longest legal one. */
            d->incomplete_calls++;
            d->resume_off     = k;
            d->resume_at_read = cap->total_read + i;   /* after the consume below */
            break;
        }

        uint32_t next = p + used;
        i   = next >> 4;
        off = next & 15u;
    }

    if (i > avail) {
        i = avail;
    }
    usb_capture_consume(cap, i);
    return i;
}

/* Prints the [stats] lines: capture, packets, errors, skips, resets, SOFs. */
void usb_decoder_print_stats(const usb_decoder_t *d, const usb_capture_t *cap)
{
    printf("[stats] %s  sample_rate=%.3f MHz  oversample=%lu\n",
           usb_speed_name(d->speed), (double)(cap->sample_hz / 1e6f),
           (unsigned long)d->oversample);
    unsigned long long written = (unsigned long long)cap->total_written;
    printf("        words: written=%llu read=%llu idle_skipped=%llu\n",
           written, (unsigned long long)cap->total_read,
           (unsigned long long)d->idle_words_skipped);
    printf("        LOSS:  missed=%llu words (%.1f%% of bus)  ring_laps=%llu\n",
           (unsigned long long)cap->overrun_words,
           written ? (100.0 * (double)cap->overrun_words / (double)written) : 0.0,
           (unsigned long long)cap->ring_laps);
    printf("        drops=%llu  resyncs=%llu (words passed over while resyncing=%llu, of"
           " which all-SE1=%llu; GAP records count the rest as lost)\n",
           (unsigned long long)cap->overrun_events,
           (unsigned long long)d->resyncs,
           (unsigned long long)d->resync_words,
           (unsigned long long)d->resync_se1_words);
    /* Word counts, not cycles: the packet path costs far more per word than skipping. */
    printf("        paths (words examined, not cycles): idle=%llu se0=%llu "
           "nonidle=%llu packet=%llu\n",
           (unsigned long long)d->idle_words_skipped,
           (unsigned long long)d->se0_words,
           (unsigned long long)d->nonidle_words,
           (unsigned long long)d->packet_words);
    printf("        packets: ok=%llu err=%llu (sync=%llu pid=%llu crc5=%llu "
           "crc16=%llu stuff=%llu trunc=%llu long=%llu se1=%llu)\n",
           (unsigned long long)d->packets_ok,
           (unsigned long long)d->packets_err,
           (unsigned long long)d->err_no_sync,
           (unsigned long long)d->err_pid,
           (unsigned long long)d->err_crc5,
           (unsigned long long)d->err_crc16,
           (unsigned long long)d->err_stuff,
           (unsigned long long)d->err_truncated,
           (unsigned long long)d->err_too_long,
           (unsigned long long)d->err_se1);
    /* Skipped packets are neither "ok" nor errors: their CRCs were never checked. */
    printf("        file-data packets skipped=%llu (%llu words)  "
           "incomplete decode attempts=%llu (words walked in them=%llu)\n",
           (unsigned long long)d->packets_skipped,
           (unsigned long long)d->skip_words,
           (unsigned long long)d->incomplete_calls,
           (unsigned long long)d->rewalk_words);
    printf("        bus resets=%llu  frame markers (SOF)=%llu\n",
           (unsigned long long)d->resets, (unsigned long long)d->sof_count);
}

/* Prints the last USB_DECODE_RECENT cleanly decoded packets (key p). */
void usb_decoder_print_recent(const usb_decoder_t *d)
{
    if (d->recent_count == 0) {
        printf("[pkts]  no cleanly decoded packets yet\n");
        return;
    }

    printf("[pkts]  last %lu good packets (oldest first)\n",
           (unsigned long)d->recent_count);

    uint32_t start = (d->recent_head + USB_DECODE_RECENT - d->recent_count) %
                     USB_DECODE_RECENT;
    for (uint32_t i = 0; i < d->recent_count; i++) {
        const usb_pkt_summary_t *s = &d->recent[(start + i) % USB_DECODE_RECENT];
        printf("        %12llu ns  %-6s", (unsigned long long)s->ts_ns,
               usb_pid_name((usb_pid_t)s->pid));

        if (s->pid == USB_PID_SOF) {
            printf(" frame=%u", s->frame);
        } else if (s->type == USB_PKT_TYPE_TOKEN) {
            printf(" addr=%u ep=%u", s->addr, s->endpoint);
        } else if (s->type == USB_PKT_TYPE_DATA) {
            printf(" len=%u data=", s->payload_len);
            uint32_t n = (s->payload_len < 8u) ? s->payload_len : 8u;
            for (uint32_t b = 0; b < n; b++) {
                printf("%02x ", s->head[b]);
            }
        }
        printf("\n");
    }
}
