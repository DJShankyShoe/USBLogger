/*
 * The USB decoder: oversampled line states in, packets out. It recovers the clock in software, decodes
 * NRZI and bit stuffing, frames packets, checks CRC5/CRC16 and hands each packet to a callback.
 * It also reports bus conditions (resets, chirps, suspends, detaches, SE1), never guessed around.
 */
#ifndef USB_DECODE_H
#define USB_DECODE_H

/* The capture ring the decoder reads, and the packet it produces. */
#include "usb_capture.h"
#include "usb_proto.h"

/* Bus conditions the decoder reports beside packets. */
typedef enum {
    USB_BUS_EVENT_RESET = 0,     /* SE0 held > 2.5 us */
    USB_BUS_EVENT_CHIRP,         /* long single-ended-ish K: HS handshake attempt */
    USB_BUS_EVENT_HS_SUSPECTED,  /* bus quiet at SE0: link is probably running HS */
    USB_BUS_EVENT_SE1,           /* illegal bus state */
    USB_BUS_EVENT_OVERRUN,       /* capture ring lapped; samples were lost */
    USB_BUS_EVENT_NO_DEVICE,     /* bus held at SE0 and never seen idle: nothing attached */
    USB_BUS_EVENT_SUSPEND,       /* bus idle (J) for 3 ms: no SOFs, the host suspended the port */
    USB_BUS_EVENT_SUSPEND_END,   /* a suspended bus left idle; duration = the whole idle time */
    USB_BUS_EVENT_DETACH,        /* SE0 held 200 ms after packets since the last reset: the device went away */
    USB_BUS_EVENT_ATTACH,        /* idle J 3 ms with no packet since start or the last host reset: a device attached */
} usb_bus_event_t;

/* A bus event's name, for the console ("BUS-RESET", "DETACH", ...). */
const char *usb_bus_event_name(usb_bus_event_t ev);

/* How many raw sample words are retained for the raw-activity dump. */
#define USB_DECODE_RAW_SLOTS 8u

/* ---- cycle profiling ------------------------------------------------- */

/* The core's own cycle counter (one load, no flash call, ~3 cycles a read), since word counts cannot say
 * where core1's time goes. */
#if defined(PICO_ON_DEVICE) && PICO_ON_DEVICE
/* The Cortex-M33's cycle counter and the registers that switch it on. */
#define USB_DWT_CYCCNT (*(volatile uint32_t *)0xE0001004u)
#define USB_DWT_CTRL   (*(volatile uint32_t *)0xE0001000u)   /* control: bit 0 starts the counter */
#define USB_DWT_LAR    (*(volatile uint32_t *)0xE0001FB0u)   /* lock access: unlocks the block */
#define USB_CM_DEMCR   (*(volatile uint32_t *)0xE000EDFCu)   /* debug control: bit 24 powers it up */

/* The core's cycle count now. */
static inline uint32_t usb_cycles(void) { return USB_DWT_CYCCNT; }

/* True if the counter runs; otherwise every profile figure would read zero and look free. */
static inline bool usb_cycles_init(void)
{
    USB_CM_DEMCR |= (1u << 24);   /* TRCENA: power up the trace/DWT block */
    USB_DWT_LAR   = 0xC5ACCE55u;  /* unlock, where the part requires it */
    USB_DWT_CTRL |= 1u;           /* CYCCNTENA */
    uint32_t a = USB_DWT_CYCCNT;
    for (volatile int i = 0; i < 16; i++) { }
    return USB_DWT_CYCCNT != a;
}
#else
/* Host build: no cycle counter. */
static inline uint32_t usb_cycles(void) { return 0; }
/* Host build: says there is no counter to start. */
static inline bool usb_cycles_init(void) { return false; }
#endif

/* USB_PROFILE (default 1) compiles the cycle profile in (~2% of the budget during a copy); 0
 * compiles it away. */
#ifndef USB_PROFILE
/* On unless the build says otherwise. */
#define USB_PROFILE 1
#endif
#if USB_PROFILE
#define USB_PROF_START(t)       const uint32_t t = usb_cycles()   /* t = the cycle count now */
#define USB_PROF_ADD(acc, t)    ((acc) += (uint32_t)(usb_cycles() - (t)))   /* acc += cycles since t */
#define USB_PROF_COUNT(acc, n)  ((acc) += (n))                    /* acc += n */
#else
#define USB_PROF_START(t)       ((void)0)                         /* profile off: nothing */
#define USB_PROF_ADD(acc, t)    ((void)0)                         /* nothing */
#define USB_PROF_COUNT(acc, n)  ((void)0)                         /* nothing */
#endif

/* USB_PROFILE_DETAIL (default: USB_PROFILE) compiles in the decoder's own breakdown; 0 keeps the
 * loop-level profile. */
#ifndef USB_PROFILE_DETAIL
/* Follows USB_PROFILE unless the build says otherwise. */
#define USB_PROFILE_DETAIL USB_PROFILE
#endif
#if USB_PROFILE_DETAIL
#define USB_DPROF_START(t)      const uint32_t t = usb_cycles()   /* as USB_PROF_START, for the decoder's split */
#define USB_DPROF_ADD(acc, t)   ((acc) += (uint32_t)(usb_cycles() - (t)))   /* acc += cycles since t */
#define USB_DPROF_COUNT(acc, n) ((acc) += (n))                    /* acc += n */
#else
#define USB_DPROF_START(t)      ((void)0)                         /* detail off: nothing */
#define USB_DPROF_ADD(acc, t)   ((void)0)                         /* nothing */
#define USB_DPROF_COUNT(acc, n) ((void)0)                         /* nothing */
#endif

/* Called with each packet the decoder finishes. */
typedef void (*usb_packet_cb_t)(const usb_packet_t *pkt, void *ctx);
/* Called with each bus event; `count` is how many occurrences a coalesced report stands for (SE1
 * can repeat thousands of times). */
typedef void (*usb_bus_event_cb_t)(usb_bus_event_t ev, uint64_t ts_ns,
                                   uint64_t duration_ns, uint32_t count,
                                   void *ctx);

/* Summary of one cleanly decoded packet, kept for the `p` dump. */
typedef struct {
    uint64_t ts_ns;
    uint16_t payload_len;
    uint16_t frame;
    uint8_t  pid;
    uint8_t  type;
    uint8_t  addr;
    uint8_t  endpoint;
    uint8_t  head[8];
} usb_pkt_summary_t;

/* Packets kept for the `p` dump. */
#define USB_DECODE_RECENT 16u

/* A condition that can repeat faster than the log can take (resets, chirps), coalesced per interval
 * of bus time. */
typedef struct {
    uint32_t count;        /* occurrences in the pending group */
    uint64_t bucket;       /* which interval the group covers */
    uint64_t first_abs;    /* sample index of the group's first occurrence */
    uint64_t first_dur;    /* that occurrence's duration, in samples */
} usb_event_burst_t;

/* The decoder: its thresholds, where it stands in the stream, the packet and bus run in progress,
 * and its counts. */
typedef struct {
    usb_speed_t speed;
    uint32_t    oversample;
    uint32_t    idle_line;      /* USB_LINE_DP at FS, USB_LINE_DM at LS */
    uint32_t    idle_word;
    uint32_t    eop_se0_samples;    /* SE0 run that ends a packet */
    uint32_t    reset_se0_samples;  /* SE0 run that counts as a bus reset */
    uint32_t    chirp_samples;      /* K run long enough to be an HS chirp */
    uint32_t    hs_quiet_samples;   /* SE0 run after which we suspect HS */
    uint32_t    host_reset_samples; /* SE0 run that is a host's bus reset (10 ms), not contact bounce */
    uint32_t    hs_chirps;          /* chirps since the last reset that make a High Speed negotiation */
    uint32_t    se1_glitch_samples; /* SE1 shorter than this is a sampling artifact */
    uint32_t    max_packet_samples; /* longest legal packet, bounds a skip */
    uint32_t    stuff_gap_samples;  /* transition gap that breaks bit stuffing */
    uint32_t    burst_shift;        /* reset/chirp coalescing interval = 2^shift samples */
    uint32_t    suspend_words;      /* whole idle words after which the bus is suspended */
    uint32_t    eop_max_samples;    /* longest SE0 still treated as an EOP */

    usb_packet_cb_t    on_packet;
    usb_bus_event_cb_t on_event;
    void              *ctx;

    /* The running SE0 length, carried across calls so a reset spanning several passes is measured
     * whole. */
    uint64_t    se0_run;
    uint64_t    se0_start_abs;      /* absolute sample index where that run began */
    bool        hs_reported;
    uint64_t    packets_at_reset;   /* packets_ok when the last reset, or a reported long SE0, ended */
    uint64_t    chirps;             /* parked K/J runs seen (each one also counted in a CHIRP report) */
    uint64_t    chirps_at_reset;    /* chirps at the same moment as packets_at_reset */

    /* The running idle (whole J words), for suspend detection; idle_open: it may continue in the
     * next pass. */
    bool        idle_open;
    bool        suspended;          /* the current idle run was reported as a suspend (or an attach) */
    bool        attach_idle;        /* it was reported as ATTACH, so its end is not a SUSPEND-END */
    uint64_t    idle_start_abs;     /* sample index of the run's first word */
    uint64_t    idle_end_abs;       /* sample index just after its last word so far */

    /* Where to resume inside the next pass's first word after a packet ran past the data (while
     * total_read == resume_at_read). */
    uint32_t    resume_off;
    uint64_t    resume_at_read;

    /* After a capture drop no packet is started until the bus is provably between packets
     * (usb_decode_run). */
    uint64_t    seen_overrun_words;  /* cap->overrun_words when last checked */
    bool        resync;
    uint64_t    resyncs;             /* drops that started a resync */
    uint64_t    resync_words;        /* words passed over while resyncing */
    uint64_t    resync_se1_words;    /* of those, words entirely SE1: no packet data */

    /* The last IN/OUT/SETUP token's endpoint: a DATA packet on a bulk endpoint may be file data, on
     * endpoint 0 is decoded. */
    bool        have_token;
    uint8_t     last_token_ep;
    /* The last token's two field bytes that passed CRC5; UINT32_MAX for none. */
    uint32_t    token_crc_ok;
    /* The last token was IN, so file data skipped after it is a READ, else a WRITE. */
    bool        last_token_in;

    /* Diagnostics: is the tap seeing the bus at all, and where do the words go. */
    uint64_t packets_ok;
    uint64_t packets_err;
    uint64_t err_no_sync;
    uint64_t err_pid;
    uint64_t err_crc5;
    uint64_t err_crc16;
    uint64_t err_stuff;
    uint64_t err_truncated;
    uint64_t err_too_long;
    uint64_t err_se1;
    uint64_t sop_count;
    uint64_t sof_count;
    uint64_t resets;
    uint64_t idle_words_skipped;
    uint64_t nonidle_words;
    uint64_t packet_words;   /* words walked inside packet decoding */
    uint64_t se0_words;
    uint64_t packets_skipped; /* file-data packets passed over undecoded */
    uint64_t packets_skipped_in; /* of those, after an IN token (READ data) */
    uint64_t skip_words;      /* the part of packet_words spent skipping */
    uint64_t incomplete_calls; /* attempts that ran off the end of the data, left for the next pass */
    uint64_t rewalk_words;     /* words walked by those attempts, walked again next pass */

    /* Cycle profile: pkt_cyc covers decode_packet, with finish_packet, the CRCs and the MSC parser
     * it calls. */
    uint64_t prof_pkt_cyc;
    uint64_t prof_pkt_calls;
    uint64_t prof_finish_cyc;   /* the finish_packet() part of prof_pkt_cyc */
    uint64_t prof_se0_bits;     /* SE0 candidate samples examined in-packet */
    uint64_t prof_skip_cyc;     /* the skip_packet() part of prof_pkt_cyc */
    /* Where each half's cycles go: the plain-word loops against the general paths around them. */
    uint64_t prof_plain_cyc;        /* decode_plain_run(), inside decode_packet */
    uint64_t prof_plain_words;
    uint64_t prof_plain_calls;      /* decode_plain_run() calls */
    uint64_t prof_skip_plain_cyc;   /* skip_plain_run(), inside skip_packet */
    uint64_t prof_skip_plain_words;
    uint64_t prof_tail_cyc;         /* decode_packet's trailing bits and EOP swallow */
    /* Why words take the general paths (others stopped a plain run on a rule). */
    uint64_t skip_fallback_se0;     /* skip words holding SE0: the EOP, or a glitch */
    uint64_t dec_fallback_first;    /* each packet's partial first word */
    uint64_t dec_fallback_se0;      /* whole decode words holding SE0 */

    /* Recent non-idle sample words, to confirm the PIO sees line activity. */
    uint32_t raw_words[USB_DECODE_RAW_SLOTS];
    uint32_t raw_count;

    /* SE1 coalescing: a bus we cannot interpret produces SE1 continuously, and one record each
     * would flood the log. */
    uint32_t se1_report_samples;
    uint32_t se1_burst;
    uint64_t se1_first_abs;
    uint64_t se1_last_report_abs;

    /* Bus resets and chirps, coalesced the same way. */
    usb_event_burst_t reset_burst;
    usb_event_burst_t chirp_burst;
    usb_event_burst_t suspend_burst;
    usb_event_burst_t suspend_end_burst;

    /* Ring of recently decoded good packets. */
    usb_pkt_summary_t recent[USB_DECODE_RECENT];
    uint32_t recent_head;
    uint32_t recent_count;
} usb_decoder_t;

/* Sets the decoder up for a bus speed and samples per bit, with every count at zero. */
void usb_decoder_init(usb_decoder_t *d, usb_speed_t speed, uint32_t oversample);

/* Sets where packets and bus events go. */
static inline void usb_decoder_set_callbacks(usb_decoder_t *d,
                                             usb_packet_cb_t on_packet,
                                             usb_bus_event_cb_t on_event,
                                             void *ctx)
{
    d->on_packet = on_packet;
    d->on_event  = on_event;
    d->ctx       = ctx;
}

/* Decodes everything available in `cap` through the callbacks; returns the words consumed. Poll the
 * capture first. */
uint32_t usb_decode_run(usb_decoder_t *d, usb_capture_t *cap);

/* Prints the decoder's counts and profile for the stats block. */
void usb_decoder_print_stats(const usb_decoder_t *d, const usb_capture_t *cap);
/* Prints the last USB_DECODE_RECENT packets (the `p` key). */
void usb_decoder_print_recent(const usb_decoder_t *d);

/* Flushes any coalesced bus-state report that is still pending. */
void usb_decode_flush_events(usb_decoder_t *d, usb_capture_t *cap);

/* End of session: reports every coalesced condition still pending. */
void usb_decode_finish(usb_decoder_t *d, usb_capture_t *cap);

#endif /* USB_DECODE_H */
