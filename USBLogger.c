/*
 * The passive forensic USB audit tap (Phase 1, USB 1.1): main, the core-to-core rings, core1's loop and
 * core0's main loop, keys and boot. core1 captures, decodes and parses; core0 logs, prints and drives the
 * card, LED and relay. It never drives D+/D-, never answers a token and never changes traffic.
 *   PC <-> [tapped cable: D+ GPIO 10, D- GPIO 11, inputs only] <-> drive
 */

/* printf, snprintf; memset, memcpy. */
#include <stdio.h>
#include <string.h>

/* The SDK: cores, the board id, random numbers, the LED's wireless chip, clocks, flash, the regulator, the ADC, the watchdog. */
#include "pico/stdlib.h"
#include "pico/multicore.h"
#include "pico/unique_id.h"
#include "pico/rand.h"
#include "pico/cyw43_arch.h"
#include "hardware/clocks.h"
#include "hardware/flash.h"
#include "hardware/structs/qmi.h"
#include "hardware/sync.h"
#include "hardware/vreg.h"
#include "hardware/adc.h"
#include "hardware/watchdog.h"

/* The tap's own modules, the log key (secrets/log_key.txt) and the card password's hash, as
 * generated headers. */
#include "card_password.h"
#include "audit_log.h"
#include "exfat_model.h"
#include "meta_capture.h"
#include "meta_expect.h"
#include "msc_parse.h"
#include "sd_card.h"
#include "sd_log.h"
#include "selftest.h"
#include "sha256.h"
#include "store.h"
#include "card_password_hash.h"   /* generated from secrets/card_password_hash.txt (CMakeLists.txt) */
#include "tap_debug.h"   /* TAP_DEBUG: the console, or none */
#include "log_key.h"   /* generated from secrets/log_key.txt (CMakeLists.txt) */
#include "usb_capture.h"
#include "usb_decode.h"
#include "vbus_sense.h"

/* The measurement lines are console output: they need the debug build. */
#if TAP_MEASURE && !TAP_DEBUG
#error "TAP_MEASURE needs TAP_DEBUG"
#endif

/* Tap pins. D- must be D+ plus one: the PIO samples the pair as consecutive
 * input pins. */
#define TAP_DP_PIN 10
#define TAP_DM_PIN (TAP_DP_PIN + 1)

/* The relay in the drive's VBUS (normally open): low = no power, as at reset. A power switch only:
 * D+/D- never pass it. */
#define RELAY_PIN 21u   /* physical pin 27 */
static bool g_drive_power;   /* the relay's state, as last set */

/* Holds the PowerBoost's EN high through a diode, so the battery keeps the tap up after the PC side goes. */
#define POWER_HOLD_PIN 20u   /* physical pin 26 */

/* The system clock: 384 MHz divides the 48 MHz sample clock by 8 (128 cycles per sample word). Above the
 * rated 150 MHz, so the core runs at 1.30 V with the flash slowed (clock_setup), falling back to 192 then 144 MHz. */
#define SYS_CLOCK_KHZ          384000
#define SYS_CLOCK_MID_KHZ      192000
#define SYS_CLOCK_FALLBACK_KHZ 144000

/* Gap reports are coalesced to this interval; see core1_main(). */
#define GAP_REPORT_INTERVAL_US 250000u

/* Sample words gathered before a decode pass: twice the pass bound, so a pass rarely ends inside a
 * packet. */
#define DECODE_BATCH_WORDS 2048u

/* Ring depths: a USB CDC write can stall a third of a second, and the mount brings ~325 records/s. */
#define CMD_QUEUE_DEPTH 128u  /* powers of two: ring indices are masked */
#define EVT_QUEUE_DEPTH 32u

/* Longest core1 loop iteration (profile builds) and where its time went, to explain a capture drop. */
typedef struct {
    uint32_t cyc;     /* the whole iteration */
    uint32_t poll;    /* usb_capture_poll and the overwrite check */
    uint32_t run;     /* usb_decode_run, including the parser and pushes it calls */
    uint32_t flush;   /* usb_decode_flush_events */
    uint32_t words;   /* words the decode pass consumed */
    uint32_t se1;     /* SE1 samples noted in the pass */
    uint64_t at;      /* bus sample index where the pass started */
} iter_max_t;

/* One bus event or capture gap, as core1 hands it to core0. */
typedef struct {
    uint8_t  code;      /* usb_bus_event_t, or 0xFF for a capture gap */
    uint64_t ts_ns;
    uint64_t duration_ns;
    uint32_t lost_words;
    uint32_t count;     /* raw occurrences this report stands for */
    /* Capture gaps only, console only: how hard the host was sending over the span. */
    uint32_t data_pkts; /* file-data packets skipped since the previous gap report */
    uint32_t span_us;   /* time since the previous gap report */
    iter_max_t iter;    /* longest core1 iteration since the previous gap report */
} bus_evt_t;

/* core1 -> core0 hand-off: one single-producer, single-consumer ring per record type, no lock. core1 alone
 * writes `head`, core0 alone `tail`. The storage is volatile so each element is stored before its index
 * moves (a plain array let the compiler move the index first, and core0 popped torn records). */
static volatile msc_command_t g_cmd_ring[CMD_QUEUE_DEPTH];   /* finished SCSI commands */
static volatile uint32_t      g_cmd_head, g_cmd_tail;        /* head: core1 writes it; tail: core0 */
static volatile bus_evt_t     g_evt_ring[EVT_QUEUE_DEPTH];   /* bus events and capture gaps */
static volatile uint32_t      g_evt_head, g_evt_tail;        /* as for the command ring */

/* core0's headroom: how deep each ring has been (core1 measures), and core0's longest iteration and
 * drain. */
static volatile uint32_t g_cmd_high, g_evt_high;   /* written by core1 only */
static uint64_t g_core0_iter_max_us, g_core0_drain_max_us;   /* core0 only */

/* Where core0's time goes while away from the metadata link, split by main-loop part; the longest
 * gap is kept. */
enum { GAP_BANNER = 0, GAP_DRAIN, GAP_CONSOLE, GAP_TAIL, GAP_KEYS, GAP_LED, GAP_STATS, GAP_PARTS };
static const char *const g_gap_name[GAP_PARTS] = {
    "banner", "queue drain", "console pump", "expect/sector/names", "keys", "LED", "stats print"
};
static uint64_t g_gap_us[GAP_PARTS], g_gap_max_us[GAP_PARTS];

#if TAP_MEASURE
/* Adds the time since `t0` to part `i` and returns now, so one call closes a part and opens the
 * next. */
static uint64_t gap_mark(unsigned i, uint64_t t0)
{
    const uint64_t now = time_us_64();
    g_gap_us[i] += now - t0;
    return now;
}
#else
/* Without TAP_MEASURE the main loop's parts are not timed. */
static inline uint64_t gap_mark(unsigned i, uint64_t t0)
{
    (void)i;
    return t0;
}
#endif

/* Hands one command to core0; false when the ring is full (core1). */
static inline bool cmd_push(const msc_command_t *c)
{
    const uint32_t h = g_cmd_head;
    if (h - g_cmd_tail >= CMD_QUEUE_DEPTH) {
        return false;                                   /* full */
    }
    g_cmd_ring[h & (CMD_QUEUE_DEPTH - 1u)] = *c;
    g_cmd_head = h + 1u;
    const uint32_t depth = h + 1u - g_cmd_tail;         /* a stale tail only overstates */
    if (depth > g_cmd_high) {
        g_cmd_high = depth;
    }
    return true;
}

/* Hands a bus event or gap to core0, field by field: a struct copy compiles to memcpy, which is in
 * flash. */
static inline bool evt_push(uint8_t code, uint64_t ts_ns, uint64_t duration_ns,
                            uint32_t lost_words, uint32_t count, uint32_t data_pkts,
                            uint32_t span_us, const iter_max_t *iter)
{
    const uint32_t h = g_evt_head;
    if (h - g_evt_tail >= EVT_QUEUE_DEPTH) {
        return false;
    }
    volatile bus_evt_t *const s = &g_evt_ring[h & (EVT_QUEUE_DEPTH - 1u)];
    s->code        = code;
    s->ts_ns       = ts_ns;
    s->duration_ns = duration_ns;
    s->lost_words  = lost_words;
    s->count       = count;
    s->data_pkts   = data_pkts;
    s->span_us     = span_us;
    s->iter.cyc    = iter ? iter->cyc   : 0u;
    s->iter.poll   = iter ? iter->poll  : 0u;
    s->iter.run    = iter ? iter->run   : 0u;
    s->iter.flush  = iter ? iter->flush : 0u;
    s->iter.words  = iter ? iter->words : 0u;
    s->iter.se1    = iter ? iter->se1   : 0u;
    s->iter.at     = iter ? iter->at    : 0u;
    g_evt_head = h + 1u;
    const uint32_t depth = h + 1u - g_evt_tail;
    if (depth > g_evt_high) {
        g_evt_high = depth;
    }
    return true;
}

/* Takes the oldest command from its ring; false when it is empty (core0). */
static bool cmd_pop(msc_command_t *c)
{
    const uint32_t t = g_cmd_tail;
    if (t == g_cmd_head) {
        return false;                                   /* empty */
    }
    *c = g_cmd_ring[t & (CMD_QUEUE_DEPTH - 1u)];
    g_cmd_tail = t + 1u;
    return true;
}

/* Takes the oldest bus event from its ring; false when it is empty (core0). */
static bool evt_pop(bus_evt_t *e)
{
    const uint32_t t = g_evt_tail;
    if (t == g_evt_head) {
        return false;
    }
    *e = g_evt_ring[t & (EVT_QUEUE_DEPTH - 1u)];
    g_evt_tail = t + 1u;
    return true;
}

/* core1's capture, decoder and parser (core0 sets them up before core1 starts). */
static usb_capture_t g_capture;
static usb_decoder_t g_decoder;
static msc_parser_t  g_parser;

/* The metadata link: 55,000 words (~18 ms of copying at 3 M words/s), most of the RAM left. */
#define META_LINK_WORDS 55000u

/* core1 skips copying a pass above this backlog (drops start at 4,096): capture comes first. */
#define META_COPY_BEHIND_WORDS 3072u
static volatile uint32_t g_meta_storage[META_LINK_WORDS];   /* the link ring's words */
static meta_link_t       g_meta_link;                       /* the link: core1 writes, core0 reads */
static meta_rx_t         g_meta_rx;                         /* core0's decoder and reassembly of the copies */

/* Metadata sectors' own store (core0): to the SD card, or as SEC lines to the console without one. */
static store_backend_t g_sector_route;   /* to the card, or to the console without one */
static store_t         g_sector_store;   /* the sectors' own store */
static uint64_t        g_sectors_to_console, g_sectors_console_refused;
static uint64_t        g_sectors_new, g_sectors_repeated;

/* The exFAT name model (core0): fed every complete metadata transfer; tells core1 which LBAs are
 * directories. */
static exfat_model_t g_exfat;
static uint32_t      g_exfat_dirs_sent;       /* the model's state when the table was last set */
static uint64_t      g_exfat_heap_sent;       /* its cluster heap's LBA then */
static uint32_t      g_exfat_serial_sent;     /* its volume serial then */
static bool          g_exfat_interest_sent;   /* a table has been sent for this volume */

/* How long a directory command waits for its sectors before it is reported missing. */
#define META_EXPECT_TIMEOUT_US 3000000u
static meta_expect_t g_expect;               /* the directory check */
static uint64_t      g_dir_writes_unreliable, g_dir_reads_missed;
static uint64_t      g_names_changes_lost;   /* creations/deletions over EXFAT_MAX_CHANGES in one transfer */
static uint64_t      g_meta_pump_last_us, g_meta_pump_gap_max_us;
static uint64_t      g_meta_busy_us;         /* time in meta_service calls that decoded something */
static uint64_t      g_meta_bursts, g_meta_burst_max_us;
static uint64_t      g_meta_result_us;       /* of that, handling results (model, printing, records) */
static uint64_t      g_model_cyc;            /* core0 cycles in exfat_model_feed (with its events) */
static uint64_t      g_names_cyc;            /* of those, the [names] events (printing, audit records) */
static uint64_t      g_sector_cyc;           /* per-sector hashing, storing new sectors, SECTOR records */
static uint64_t      g_expect_cyc;           /* the directory check (meta_expect_result, WARNINGs) */
/* Main-loop time while the link is more than a quarter full, and the console and sector pumps held
 * back then. */
static uint64_t      g_busy_us, g_busy_drain_us, g_busy_meta_us;
static uint64_t      g_console_held_back, g_sector_held_back;
/* Stack regions from the linker, for the stack high-water lines. */
extern uint32_t __StackOneBottom, __StackOneTop, __StackTop;
static uint32_t stack_used(const uint32_t *from, const uint32_t *to);
static bool          g_core0_cyc_ok;     /* core0's cycle counter is running */

/* The audit log: seals every record and hands it to g_store (core0 only). */
static audit_log_t   g_log;

/* Every persistent output goes through g_store: the console and the SD card, each behind its RAM
 * FIFO. */
static store_t         g_store;
static store_backend_t g_console;   /* prints records as AUD| lines */

/* The console's RAM FIFO: records wait there while no terminal is connected (18 KB, ~180 records). */
#define CONSOLE_FIFO_BYTES (18u * 1024u - 512u)   /* 512 B went to the log's part table */
static store_backend_t g_console_any;                            /* prints records and, without a card, sectors */
static uint8_t         g_console_fifo_buf[CONSOLE_FIFO_BYTES];   /* the FIFO's bytes */
static store_fifo_t    g_console_fifo;                           /* records waiting for the console */
static store_backend_t g_console_fifo_b;                         /* the FIFO as g_store sees it */

/* The SD card's RAM FIFO, forwarding only while the card is idle, so core0 never waits out a write
 * pause. */
#define SD_FIFO_BYTES (24u * 1024u)
static uint8_t         g_sd_fifo_buf[SD_FIFO_BYTES];   /* the FIFO's bytes */
static store_fifo_t    g_sd_fifo;                      /* records and sectors waiting for the card */
static store_backend_t g_sd_fifo_b;                    /* the FIFO as g_store sees it */
static sd_log_t        g_sd_log;                       /* the log on the card */
static store_backend_t g_sd_b;                         /* the card log as the FIFO's target */
static sd_card_info_t  g_sd_info;                      /* what opening the card found, and its timings */
/* Items per pump call: a block write leaves the card busy, so one call sends at most one block. */
#define SD_PUMP_ITEMS 8u
static uint64_t        g_sd_pumped_in_decode;   /* sd_make_room calls that pumped */
static void            sd_make_room(void);

/* FIFO bytes kept for records: a burst of sectors can never crowd out an audit record. */
#define SD_SECTOR_RESERVE (4u * 1024u)
static store_backend_t g_sd_sector_b;       /* sectors into the SD FIFO, room kept for records */
static uint64_t        g_sd_sectors_given, g_sd_sectors_refused;
static uint64_t        g_sd_sectors_hash;   /* over every sector given, in order, for the read-back */
/* Decoding the link waits while the card cannot take more sectors (decode_waits_for_card). */
static uint64_t        g_decode_waits, g_decode_wait_us, g_decode_wait_since_us;
static bool            decode_waits_for_card(void);

/* The boot check of the card's log: only if every chain holds (and the self-test passed) is the
 * drive powered. */
static audit_chain_check_t g_card_check;
static hmac_sha256_key_t   g_chain_key;       /* the audit chain's HMAC key, from TAP_LOG_KEY */
static uint8_t             g_cipher_key[32];  /* the card's ChaCha20 key, from TAP_LOG_KEY */
static bool            g_card_check_ran, g_card_check_ok, g_card_check_walked;
static uint8_t         g_card_check_aux;      /* AUDIT_CHECKPOINT_*: the card against the flash checkpoint */
static bool            g_card_full;           /* the log is in its reserve and cannot grow: the drive stays off */
static uint64_t        g_last_io_us;          /* when core0 last took a READ or WRITE off the ring */
static uint32_t        g_card_check_blocks;   /* blocks the check read */
static uint64_t        g_card_check_us;       /* how long it took */

/* Fast boot: capture starts before any terminal connects; the banner is printed when one first
 * does. */
static bool     g_banner_done;
static uint64_t g_connect_since_us;  /* when the terminal was first seen connected (0: not yet) */
/* The banner waits this long after a terminal connects (its first lines were lost when printed at
 * once). */
#define BANNER_DELAY_US 300000u
static uint32_t g_qmi_timing_boot, g_qmi_timing_run;   /* flash interface timing */
static bool     g_selftest_pass;     /* the boot self-test's verdict */
static uint64_t g_boot_capture_us;   /* time since power-up when capture started */
static uint64_t g_boot_cyw43_us;     /* how long starting the wireless chip (LED) took */

/* Tells the console FIFO whether it may print: the banner is out and a terminal is connected. */
static bool console_ready(void *ctx)
{
    (void)ctx;
#if TAP_DEBUG
    return g_banner_done && stdio_usb_connected();
#else
    return false;   /* no console */
#endif
}

/* Items forwarded per console pump call, so a backlog cannot keep core0 from the rings for long. */
#define CONSOLE_PUMP_ITEMS 16u

/* Cleared to end the session (`q`, or the PC side's power gone). */
static volatile bool     g_running = true;
static volatile uint64_t g_dropped_cmds;   /* commands core1 could not hand over (ring full) */
static volatile uint64_t g_dropped_evts;   /* bus events likewise */

/* core1's cycle profile; written by core1 only, read by core0 for the stats. */
static uint64_t g_prof_poll_cyc;
static uint64_t g_prof_run_cyc;
static uint64_t g_prof_flush_cyc;
static uint64_t g_prof_loop_cyc;
static uint64_t g_prof_iters;
static uint64_t g_prof_passes;
static uint64_t g_prof_spin_cyc;
static bool     g_prof_ok;

/* ---- core1: capture -> decode -> parse ------------------------------- */

/* The decoder's packet callback: every packet goes to the parser (core1). */
static void __not_in_flash_func(on_packet)(const usb_packet_t *pkt, void *ctx)
{
    msc_parser_feed((msc_parser_t *)ctx, pkt);
}

/* The decoder's bus event callback: the event goes to core0, or is counted as dropped (core1). */
static void __not_in_flash_func(on_bus_event)(usb_bus_event_t ev, uint64_t ts_ns,
                         uint64_t duration_ns, uint32_t count, void *ctx)
{
    (void)ctx;
    if (!evt_push((uint8_t)ev, ts_ns, duration_ns, 0u, count, 0u, 0u, NULL)) {
        g_dropped_evts++;
    }
}

/* The parser's command callback: noted for the metadata copy, then handed to core0 (core1). */
static void __not_in_flash_func(on_command)(const msc_command_t *cmd, void *ctx)
{
    (void)ctx;
    meta_note_command(&g_meta_link, cmd);
    if (!cmd_push(cmd)) {
        g_dropped_cmds++;
    }
}

/* Decode passes that may have read words the DMA had already overwritten; must stay 0. */
static uint64_t g_overwrite_suspect;

/* Demand per 250 ms window, lossy or not, so loss can be read against how hard the host was
 * sending. */
static uint32_t g_win_peak_pkts, g_win_peak_lost;
static uint64_t g_win_lossy, g_win_lossy_pkts, g_win_active;

/* Headroom per window (profile builds): core1's spin cycles over its loop cycles, 0 meaning it
 * never waited. */
static uint32_t g_win_peak_spin, g_win_peak_loop;
static uint32_t g_win_min_spin, g_win_min_loop, g_win_min_pkts;

/* The least-spare window kept apart for READs and WRITEs, with its length, for the margins in
 * [load]. */
typedef struct {
    uint32_t spin, loop, pkts, dur_us;
} win_rec_t;
static win_rec_t g_win_min_dir[2];     /* [0] WRITE windows, [1] READ windows */
static uint64_t  g_win_dir_count[2];   /* READ and WRITE windows seen */

static iter_max_t g_iter_max;   /* longest core1 iteration of the session */

/* core1's loop: polls the capture, decodes a batch, copies metadata passes, and reports gaps, until the session ends. */
static void __not_in_flash_func(core1_main)(void)
{
    /* The DWT cycle counter is per core: core1 starts its own. */
    g_prof_ok = usb_cycles_init();

    uint64_t last_overrun = 0;
    uint64_t pending_lost  = 0;
    uint64_t last_gap_us   = 0;
    uint64_t last_resync     = 0;     /* resync data words already reported */
    uint64_t gap_skipped     = 0;     /* packets_skipped at the last gap report */
    uint64_t win_start_us    = 0;     /* current demand window */
    uint64_t win_skipped     = 0;
    uint64_t win_skipped_in  = 0;     /* packets_skipped_in at the window start */
    uint64_t win_lost        = 0;
    uint64_t win_spin0       = 0;     /* g_prof_spin_cyc at the window start */
    uint64_t win_loop0       = 0;     /* g_prof_loop_cyc at the window start */
    uint64_t pass_start_read = 0;     /* first word the previous pass read */
    bool     had_pass        = false;
    uint64_t meta_lost_seen  = 0;     /* drops + resync words + suspect passes, for meta_after_pass */
#if USB_PROFILE
    iter_max_t win_iter = { 0 };      /* longest iteration since the last gap report */
#endif

    while (g_running) {
        /* Cycle profile: these counters and the iteration count account for all of core1's time. */
        USB_PROF_START(it_t0);

        /* Spins on the cheap DMA hint; the full poll (and its flash timer call) runs once per
         * batch. */
        bool did_pass = false;
#if USB_PROFILE
        iter_max_t st = { 0 };        /* this iteration's pass, if it runs one */
#endif
        if (usb_capture_available_hint(&g_capture) >= DECODE_BATCH_WORDS) {
            usb_capture_poll(&g_capture);

            /* Proves the previous pass read no word the DMA had overwritten, or flags it (possibly,
             * never missed). */
            if (had_pass &&
                g_capture.total_written > pass_start_read + USB_CAPTURE_RING_WORDS) {
                g_overwrite_suspect++;
            }
            pass_start_read = g_capture.total_read;
            const uint32_t meta_idx0 = g_capture.read_idx;
            had_pass = true;

            USB_PROF_ADD(g_prof_poll_cyc, it_t0);

            USB_PROF_START(run_t0);
#if USB_PROFILE
            st.poll = (uint32_t)(run_t0 - it_t0);
            st.at   = usb_capture_sample_index(&g_capture);
            const uint64_t se1_before = g_decoder.err_se1;
#endif
            const uint32_t used = usb_decode_run(&g_decoder, &g_capture);
            (void)used;
            USB_PROF_ADD(g_prof_run_cyc, run_t0);

            USB_PROF_START(flush_t0);
            usb_decode_flush_events(&g_decoder, &g_capture);
            /* Metadata: copies this pass's words if a transfer is in them (counted in flush's
             * cycles). */
            {
                const uint64_t lost_now = g_capture.overrun_words + g_decoder.resync_words +
                                          g_overwrite_suspect;
                meta_after_pass(&g_meta_link, &g_capture, &g_parser, meta_idx0,
                                pass_start_read, lost_now != meta_lost_seen,
                                usb_capture_available_hint(&g_capture) > META_COPY_BEHIND_WORDS);
                meta_lost_seen = lost_now;
            }
            USB_PROF_ADD(g_prof_flush_cyc, flush_t0);
#if USB_PROFILE
            st.run   = (uint32_t)(flush_t0 - run_t0);
            st.flush = (uint32_t)(usb_cycles() - flush_t0);
            st.words = used;
            st.se1   = (uint32_t)(g_decoder.err_se1 - se1_before);
#endif

            USB_PROF_COUNT(g_prof_passes, 1u);
            did_pass = true;
        } else {
            USB_PROF_ADD(g_prof_spin_cyc, it_t0);
        }

        USB_PROF_COUNT(g_prof_iters, 1u);

        /* Nothing polled, so nothing new to report (and no flash timer call). */
        if (!did_pass) {
            USB_PROF_ADD(g_prof_loop_cyc, it_t0);
            continue;
        }

        /* A capture overrun is bus traffic unobserved: reported as GAP records, accumulated and
         * sent periodically. */
        if (g_capture.overrun_words != last_overrun) {
            pending_lost += g_capture.overrun_words - last_overrun;
            last_overrun = g_capture.overrun_words;
        }
        /* Words passed over while resyncing were never decoded either: counted in the same GAP
         * records. */
        /* A word entirely SE1 carries no packet data (the SE1 events report it): not counted as
         * lost. */
        {
            const uint64_t data_words = g_decoder.resync_words - g_decoder.resync_se1_words;
            if (data_words != last_resync) {
                pending_lost += data_words - last_resync;
                last_resync = data_words;
            }
        }

        uint64_t now_us = usb_capture_time_us();

        /* Closes a demand window every GAP_REPORT_INTERVAL_US, lossy or not. */
        if (now_us - win_start_us >= GAP_REPORT_INTERVAL_US) {
            const uint64_t lost_now = g_capture.overrun_words +
                                      (g_decoder.resync_words - g_decoder.resync_se1_words);
            const uint32_t pk = (uint32_t)(g_decoder.packets_skipped - win_skipped);
            const uint32_t lw = (uint32_t)(lost_now - win_lost);
#if USB_PROFILE
            /* A 250 ms window is ~48 M cycles: both fit 32 bits, so the ratios compare without a
             * division. */
            const uint32_t spin = (uint32_t)(g_prof_spin_cyc - win_spin0);
            const uint32_t loop = (uint32_t)(g_prof_loop_cyc - win_loop0);
            win_spin0 = g_prof_spin_cyc;
            win_loop0 = g_prof_loop_cyc;
            if (pk > g_win_peak_pkts) {
                g_win_peak_spin = spin;
                g_win_peak_loop = loop;
            }
            if (pk != 0u && loop != 0u &&
                (g_win_min_loop == 0u ||
                 (uint64_t)spin * g_win_min_loop < (uint64_t)g_win_min_spin * loop)) {
                g_win_min_spin = spin;
                g_win_min_loop = loop;
                g_win_min_pkts = pk;
            }
            if (pk != 0u && loop != 0u) {
                /* READ window if most of its file data followed IN tokens. */
                const uint32_t pk_in = (uint32_t)(g_decoder.packets_skipped_in - win_skipped_in);
                const uint32_t dir   = (2u * pk_in > pk) ? 1u : 0u;
                win_rec_t *const m   = &g_win_min_dir[dir];
                g_win_dir_count[dir]++;
                if (m->loop == 0u ||
                    (uint64_t)spin * m->loop < (uint64_t)m->spin * loop) {
                    m->spin   = spin;
                    m->loop   = loop;
                    m->pkts   = pk;
                    m->dur_us = (uint32_t)(now_us - win_start_us);
                }
            }
#endif
            if (pk > g_win_peak_pkts) {
                g_win_peak_pkts = pk;
                g_win_peak_lost = lw;
            }
            if (pk != 0u) {
                g_win_active++;
            }
            if (lw != 0u) {
                g_win_lossy++;
                g_win_lossy_pkts += pk;
            }
            win_skipped    = g_decoder.packets_skipped;
            win_skipped_in = g_decoder.packets_skipped_in;
            win_lost     = lost_now;
            win_start_us = now_us;
        }

        if (pending_lost != 0 && (now_us - last_gap_us) >= GAP_REPORT_INTERVAL_US) {
            uint32_t lost = (pending_lost > UINT32_MAX) ? UINT32_MAX
                                                        : (uint32_t)pending_lost;
            const uint64_t span_us = now_us - last_gap_us;
            if (evt_push(0xFFu,
                         usb_capture_sample_to_ns(&g_capture,
                             usb_capture_sample_index(&g_capture)),
                         usb_capture_sample_to_ns(&g_capture,
                             pending_lost * USB_CAPTURE_SAMPLES_PER_WORD),
                         lost, 1u,
                         (uint32_t)(g_decoder.packets_skipped - gap_skipped),
                         (span_us > UINT32_MAX) ? UINT32_MAX : (uint32_t)span_us,
#if USB_PROFILE
                         &win_iter
#else
                         NULL
#endif
                         )) {
                pending_lost = 0;
                last_gap_us = now_us;
                gap_skipped = g_decoder.packets_skipped;
#if USB_PROFILE
                win_iter = (iter_max_t){ 0 };
#endif
            } else {
                g_dropped_evts++;
            }
        }

        /* The whole iteration, to compare against elapsed wall cycles. */
#if USB_PROFILE
        {
            const uint32_t it = (uint32_t)(usb_cycles() - it_t0);
            g_prof_loop_cyc += it;
            if (it > win_iter.cyc) {
                st.cyc   = it;
                win_iter = st;
                if (it > g_iter_max.cyc) {
                    g_iter_max = st;
                }
            }
        }
#endif
    }

    usb_decode_finish(&g_decoder, &g_capture);
    msc_parser_flush(&g_parser);
}

/* ---- core0: logging and operator console ----------------------------- */

/* Makes a session id: the board's unique id mixed with a hardware random number (boot time alone
 * repeats). */
static uint64_t make_session_id(void)
{
    pico_unique_board_id_t id;
    pico_get_unique_board_id(&id);

    uint64_t board = 0;
    for (int i = 0; i < 8 && i < PICO_UNIQUE_BOARD_ID_SIZE_BYTES; i++) {
        board = (board << 8) | id.id[i];
    }
    return board ^ get_rand_64() ^ (time_us_64() * 0x9E3779B97F4A7C15ull);
}

/* Writes the flash interface's timing register, from SRAM with interrupts off and core1 not
 * started. */
static void __noinline USB_TIME_CRITICAL qmi_set_timing(uint32_t timing)
{
    qmi_hw->m[0].timing = timing;
}

/* Sets 384 MHz at 1.30 V, the flash clock divider and read delay scaled up so the flash runs as at
 * 192 MHz; falls back to 192, then 144. */
static void clock_setup(void)
{
    g_qmi_timing_boot = qmi_hw->m[0].timing;
    const uint32_t div = (g_qmi_timing_boot & QMI_M0_TIMING_CLKDIV_BITS) >> QMI_M0_TIMING_CLKDIV_LSB;
    const uint32_t rx  = (g_qmi_timing_boot & QMI_M0_TIMING_RXDELAY_BITS) >> QMI_M0_TIMING_RXDELAY_LSB;
    uint32_t new_div = (div * SYS_CLOCK_KHZ + SYS_CLOCK_MID_KHZ - 1u) / SYS_CLOCK_MID_KHZ;
    uint32_t new_rx  = (rx * SYS_CLOCK_KHZ + SYS_CLOCK_MID_KHZ - 1u) / SYS_CLOCK_MID_KHZ;
    if (new_div > (QMI_M0_TIMING_CLKDIV_BITS >> QMI_M0_TIMING_CLKDIV_LSB)) {
        new_div = QMI_M0_TIMING_CLKDIV_BITS >> QMI_M0_TIMING_CLKDIV_LSB;
    }
    if (new_rx > (QMI_M0_TIMING_RXDELAY_BITS >> QMI_M0_TIMING_RXDELAY_LSB)) {
        new_rx = QMI_M0_TIMING_RXDELAY_BITS >> QMI_M0_TIMING_RXDELAY_LSB;
    }
    const uint32_t slow = (g_qmi_timing_boot & ~(QMI_M0_TIMING_CLKDIV_BITS | QMI_M0_TIMING_RXDELAY_BITS)) |
                          (new_div << QMI_M0_TIMING_CLKDIV_LSB) | (new_rx << QMI_M0_TIMING_RXDELAY_LSB);

    uint32_t irq = save_and_disable_interrupts();
    qmi_set_timing(slow);
    restore_interrupts(irq);
    vreg_set_voltage(VREG_VOLTAGE_1_30);   /* the most the SDK allows without unlocking the regulator */
    busy_wait_us(10000u);                     /* let the regulator settle */

    if (!set_sys_clock_khz(SYS_CLOCK_KHZ, false)) {
        irq = save_and_disable_interrupts();
        qmi_set_timing(g_qmi_timing_boot);
        restore_interrupts(irq);
        vreg_set_voltage(VREG_VOLTAGE_DEFAULT);
        if (!set_sys_clock_khz(SYS_CLOCK_MID_KHZ, false)) {
            set_sys_clock_khz(SYS_CLOCK_FALLBACK_KHZ, true);
        }
    }
    g_qmi_timing_run = qmi_hw->m[0].timing;
}


/* Most time core0 keeps decoding a backed-up link in one call, so the rings are still drained. */
#define META_BURST_US 15000u

/* Decodes copied metadata, longer while the link is over half full, and measures the longest time
 * it was left alone. */
static void meta_service(void)
{
    const uint64_t start = time_us_64();
    /* Only while the session runs: the shutdown flush after `q` says nothing about capture. */
    if (g_running && g_meta_pump_last_us != 0u &&
        start - g_meta_pump_last_us > g_meta_pump_gap_max_us) {
        g_meta_pump_gap_max_us = start - g_meta_pump_last_us;
        for (unsigned i = 0; i < GAP_PARTS; i++) {   /* what that gap was made of */
            g_gap_max_us[i] = g_gap_us[i];
        }
    }
    for (unsigned i = 0; i < GAP_PARTS; i++) {
        g_gap_us[i] = 0;
    }
    if (decode_waits_for_card()) {
        g_meta_pump_last_us = time_us_64();   /* attended: left in the link on purpose */
        return;
    }
    uint32_t taken = meta_rx_pump(&g_meta_rx, &g_meta_link, 8u);
    uint32_t total = taken;
    if (meta_link_used(&g_meta_link) > META_LINK_WORDS / 2u) {
        g_meta_bursts++;
        while (taken != 0u && meta_link_used(&g_meta_link) > META_LINK_WORDS / 4u &&
               time_us_64() - start < META_BURST_US && !decode_waits_for_card()) {
            taken = meta_rx_pump(&g_meta_rx, &g_meta_link, 8u);
            total += taken;
        }
    }
    g_meta_pump_last_us = time_us_64();
    if (total != 0u) {
        g_meta_busy_us += g_meta_pump_last_us - start;
    }
    if (g_meta_pump_last_us - start > g_meta_burst_max_us) {
        g_meta_burst_max_us = g_meta_pump_last_us - start;
    }

    /* Where copied words went missing, on the bus timebase, so a drop can be matched with the
     * commands around it. */
    static uint64_t breaks_seen;
    if (g_meta_rx.breaks != breaks_seen) {
        breaks_seen = g_meta_rx.breaks;
        const uint64_t ns = ((g_meta_rx.last_break_word * USB_CAPTURE_SAMPLES_PER_WORD) *
                             g_capture.ns_per_sample_q16) >> 16;
        tap_printf("[meta]  link gap before bus time %llu ns: copied words were dropped (link full) or"
               " capture dropped; %llu gap(s) so far, core1 drop count %llu\n",
               (unsigned long long)ns, (unsigned long long)g_meta_rx.breaks,
               (unsigned long long)g_meta_link.drops);
    }
}


/* While the link is backed up the console FIFO waits until it is half full: records wait in RAM, in
 * order. */
/* Checks whether the link is backed up: over a quarter full. */
static bool link_busy(void)
{
    return meta_link_used(&g_meta_link) > META_LINK_WORDS / 4u;
}

/* Prints held console output, unless the link is backed up and the FIFO is under half full. */
static void console_pump(void)
{
#if TAP_DEBUG
    if (link_busy() && store_fifo_held(&g_console_fifo) < CONSOLE_FIFO_BYTES / 2u) {
        g_console_held_back++;
        return;
    }
    /* The FIFO itself, not console_pump(): calling itself here would spin until the link drained
     * (self_call_scan checks). */
    store_fifo_pump(&g_console_fifo, CONSOLE_PUMP_ITEMS);
#endif
}


/* The [core0] figures for one main-loop iteration. */
static inline void loop_account(uint64_t it_t0, uint64_t drain_us, uint64_t meta_us, bool busy_iter)
{
#if TAP_MEASURE
    if (drain_us > g_core0_drain_max_us) {
        g_core0_drain_max_us = drain_us;
    }
    const uint64_t it_us = time_us_64() - it_t0;
    if (it_us > g_core0_iter_max_us) {
        g_core0_iter_max_us = it_us;
    }
    if (busy_iter) {
        g_busy_us       += it_us;
        g_busy_drain_us += drain_us;
        g_busy_meta_us  += meta_us;
    }
#else
    (void)it_t0;
    (void)drain_us;
    (void)meta_us;
    (void)busy_iter;
#endif
}

/* ---- the parts of this file (each has its own head comment) ---------- */

/* Defined in tap_names.c, used by tap_sd.c's console routing. */
static bool sector_console_write(void *ctx, store_item_t kind, const uint8_t *data, uint32_t len);
/* Defined below the parts, used by tap_vbus.c when the PC side's power goes. */
static void drive_power(bool on, uint8_t reason);

/* The parts, in dependency order: they share this file's globals. */
#include "src/app/tap_led.c"
#include "src/app/tap_sd.c"
#include "src/app/tap_model.c"
#include "src/app/tap_names.c"
#include "src/app/tap_checkpoint.c"
#include "src/app/tap_vbus.c"
#include "src/app/tap_bus.c"
#include "src/app/tap_stats.c"

/* Switches the drive's power and logs it, timed on core0's clock since capture began. */
static void drive_power(bool on, uint8_t reason)
{
    gpio_put(RELAY_PIN, on);
    g_drive_power = on;
    audit_log_drive_power(&g_log, (time_us_64() - g_capture.start_us) * 1000u, on, reason);
}

#if TAP_DEBUG
/* Acts on one key from the console: 0/1 relay, s stats, r samples, p packets, h chain head, c accept the card, q end. */
static void handle_key(int c)
{
    switch (c) {
    case '0':
    case '1':
        drive_power(c == '1', AUDIT_POWER_OPERATOR);
        tap_printf("[relay] drive power %s (key)\n", g_drive_power ? "ON" : "OFF");
        break;
    case 's': case 'S':
        print_stats();
        break;
    case 'r': case 'R':
        print_raw();
        break;
    case 'p': case 'P':
        usb_decoder_print_recent(&g_decoder);
        break;
    case 'h': case 'H': {
        char head[65];
        audit_log_head_hex(&g_log, head);
        tap_printf("[chain] head=%s records=%llu\n", head,
               (unsigned long long)g_log.records);
        break;
    }
    case 'c': case 'C':
        /* Accepts the card as it is, only when its chains are sound and only the checkpoint
         * disagrees. */
        if (g_card_check_ran && g_card_check_walked && !g_card_check.broken &&
            (g_card_check_aux & AUDIT_CHECKPOINT_LOST) && !g_ckpt_accept) {
            g_ckpt_accept = true;
            audit_log_card_check(&g_log, (time_us_64() - g_capture.start_us) * 1000u, &g_card_check,
                                 AUDIT_CHECK_ACCEPT, g_card_check_aux, g_card_check_blocks);
            tap_printf("[check] accepted: this card's log becomes the reference when the session ends (q);"
                   " reboot after that to use the card\n");
        } else {
            tap_printf("[check] nothing to accept (only a sound card whose checkpoint differs can be)\n");
        }
        break;
    case 'q': case 'Q':
        tap_printf("[log]   closing session\n");
        g_running = false;
        break;
    default:
        break;
    }
}
#endif


/* A slice of metadata decoding while core0 drains the rings and prints (bounded to 2 chunks). */
static void drain_link_slice(void)
{
    if (!decode_waits_for_card()) {
        (void)meta_rx_pump(&g_meta_rx, &g_meta_link, 2u);
    }
    g_meta_pump_last_us = time_us_64();   /* the link was attended to just now */
}

/* Logs every bus event and command core1 has handed over, servicing the link between them. */
static void drain_queues(void)
{
    bus_evt_t e;
    while (evt_pop(&e)) {
        if (e.code == 0xFFu) {
            tap_printf("[warn]  capture overrun: %lu sample words lost (%llu us);"
                   " %lu file-data packets in the last %lu ms\n",
                   (unsigned long)e.lost_words,
                   (unsigned long long)(e.duration_ns / 1000u),
                   (unsigned long)e.data_pkts,
                   (unsigned long)(e.span_us / 1000u));
#if USB_PROFILE
            print_iter("[warn]  longest core1 iteration since the previous report", &e.iter);
#endif
            audit_log_gap(&g_log, e.ts_ns, e.lost_words, e.duration_ns);
            console_pump();
            sd_pump();
            drain_link_slice();
        } else {
            usb_bus_event_t ev = (usb_bus_event_t)e.code;
            se1_note(ev, &e);
            if (ev == USB_BUS_EVENT_ATTACH && attach_hold(&e)) {
                g_model_save_due = true;   /* as for any ATTACH; the record comes later (tap_bus.c) */
                continue;
            }
            /* One printf per line, so a PC logger cannot misplace pieces around AUD lines. */
            char count[16] = "";
            if (e.count > 1u) {
                snprintf(count, sizeof(count), "  x%lu", (unsigned long)e.count);   /* coalesced */
            }
            tap_printf("[bus]   %s at %llu ns (%llu us)%s\n", usb_bus_event_name(ev),
                   (unsigned long long)e.ts_ns,
                   (unsigned long long)(e.duration_ns / 1000u), count);
            if (ev == USB_BUS_EVENT_SUSPEND) {
                tap_printf("[info]  bus idle with no SOF for 3 ms: the host has suspended the "
                       "port (safe eject, sleep or selective suspend)\n");
            }
            if (ev == USB_BUS_EVENT_ATTACH) {
                tap_printf("[info]  bus idle at J for 3 ms with no traffic since power-up or the last reset: a"
                       " device attached and the host has not started using it yet (or the tap started on"
                       " a port already suspended)\n");
            }
            if (ev == USB_BUS_EVENT_DETACH) {
                tap_printf("[info]  device detached: SE0 held 200 ms after bus traffic (drive unplugged,"
                       " or its power lost)\n");
            }
            /* The insertion is over (the drive gone, or a device newly attached): save the model,
             * wait for the next boot sector. */
            if (ev == USB_BUS_EVENT_DETACH || ev == USB_BUS_EVENT_NO_DEVICE || ev == USB_BUS_EVENT_ATTACH ||
                ev == USB_BUS_EVENT_HS_SUSPECTED) {
                g_model_save_due = true;   /* model_tick */
            }
            if (ev == USB_BUS_EVENT_HS_SUSPECTED) {
                tap_printf("[warn]  bus appears to be running High Speed. The "
                       "RP2350 cannot sample HS signalling -- insert a Full "
                       "Speed isolator (e.g. ADuM3160) between host and drive. "
                       "No HS traffic is being decoded.\n");
            }
            audit_log_bus_event(&g_log, e.code, e.ts_ns, e.duration_ns, e.count);
            console_pump();
            sd_pump();
            drain_link_slice();
        }
    }

    msc_command_t cmd;
    while (cmd_pop(&cmd)) {
        if (cmd.op == MSC_OP_READ || cmd.op == MSC_OP_WRITE) {
            g_last_io_us = time_us_64();   /* the PC's once-a-second polls do not count */
        }
        audit_log_command(&g_log, &cmd);
        console_pump();
        sd_pump();
        note_io(&cmd);
        names_expect(&cmd);
        drain_link_slice();
    }
}


/* Boots fail-closed, starts capture within milliseconds, checks the card, then runs the session until it ends. */
int main(void)
{
    /* Fail-closed first: the drive stays unpowered until the checks pass. */
    gpio_init(RELAY_PIN);
    gpio_put(RELAY_PIN, false);
    gpio_set_dir(RELAY_PIN, GPIO_OUT);
    /* The battery hold: on before anything slow, released once the session is saved. */
    gpio_init(POWER_HOLD_PIN);
    gpio_put(POWER_HOLD_PIN, true);
    gpio_set_dir(POWER_HOLD_PIN, GPIO_OUT);
    sd_card_park();   /* the card deselected before any pin is set up */
    clock_setup();
    stdio_init_all();

    /* Fast boot to capture: a host reads the boot sector ~1.7 s after plug-in, so capture starts
     * first. */
    if (!usb_capture_init(&g_capture, pio0, TAP_DP_PIN, USB_SPEED_FULL,
                          USB_CAPTURE_OVERSAMPLE)) {
        tap_printf("FATAL: could not claim PIO/DMA resources for the tap\n");
        gpio_put(POWER_HOLD_PIN, false);   /* nothing to save: let the battery go */
        while (true) {
            tight_loop_contents();
        }
    }

    /* The self-test before trusting the wire; the banner repeats its result. */
    g_selftest_pass = usb_selftest_run(&g_capture, false);

    usb_decoder_init(&g_decoder, g_capture.speed, g_capture.oversample);
    msc_parser_init(&g_parser, on_command, NULL);
    meta_link_init(&g_meta_link, g_meta_storage, META_LINK_WORDS);
    /* Until the volume is known, copy only single-sector transfers (the mount's MBR and boot sector
     * reads). */
    meta_set_single_block_until_known(&g_meta_link);
    meta_rx_init(&g_meta_rx, on_meta_result_timed, NULL);
    meta_rx_set_timebase(&g_meta_rx, g_capture.ns_per_sample_q16);
    exfat_model_init(&g_exfat, on_names_event, NULL);
    meta_expect_init(&g_expect, on_expect, NULL);
    g_core0_cyc_ok = usb_cycles_init();   /* core0's own cycle counter: DWT is per core */
#if TAP_MEASURE
    (void)usb_selftest_bench(&g_capture, &g_bench);   /* before capture starts: it uses the ring */
#endif
    store_init(&g_sector_store);
    memset(&g_sector_route, 0, sizeof(g_sector_route));
    g_sector_route.name  = "sectors";
    g_sector_route.write = sector_route_write;   /* the card, or the console without one */
    store_attach(&g_sector_store, &g_sector_route);
    usb_decoder_set_callbacks(&g_decoder, on_packet, on_bus_event, &g_parser);

    store_init(&g_store);
#if TAP_DEBUG
    audit_log_console_backend(&g_console);
    memset(&g_console_any, 0, sizeof(g_console_any));
    g_console_any.name  = "console";
    g_console_any.write = console_any_write;
    store_fifo_init(&g_console_fifo, &g_console_fifo_b, "console-fifo", g_console_fifo_buf,
                    CONSOLE_FIFO_BYTES, &g_console_any, console_ready, NULL);
    store_attach(&g_store, &g_console_fifo_b);
#endif
    /* The card is opened after capture has started; its records wait in the SD FIFO until then. */
    sd_log_init(&g_sd_log);
    sd_log_backend(&g_sd_log, &g_sd_b);
    store_fifo_init(&g_sd_fifo, &g_sd_fifo_b, "sd-fifo", g_sd_fifo_buf, SD_FIFO_BYTES, &g_sd_b,
                    sd_log_ready, &g_sd_log);
    store_attach(&g_store, &g_sd_fifo_b);
    audit_log_init(&g_log, make_session_id(), &g_store);

    /* The chain is keyed; SESSION_START waits for the card check, as it follows the card's last
     * hash. */
    audit_chain_key(&g_chain_key, TAP_LOG_KEY);
    audit_log_set_key(&g_log, &g_chain_key);

    /* Paints both stacks before core1 starts, for the stack high-water lines. */
    stack_paint(&__StackOneBottom, &__StackOneTop);
    stack_paint(&__StackOneTop, (uint32_t *)__builtin_frame_address(0) - 128);
    usb_capture_start(&g_capture);
    multicore_launch_core1(core1_main);
    g_boot_capture_us = time_us_64();

    /* The wireless chip (LED) starts after capture; the rings hold the records meanwhile. */
    {
        const uint64_t t0 = time_us_64();
        g_led_ok = cyw43_arch_init() == 0;
        led_set(LED_CHECKING);   /* slow blink through the card check */
        g_boot_cyw43_us = time_us_64() - t0;
    }

    /* Opens the SD card, after capture (~50 ms; longer the first time a card gets its log file). */
    (void)sd_card_open(&g_sd_info, &g_sd_log, g_log.session_id);

    /* The card's cipher key: derived from the log key under another label; the session id's low
     * byte is the boot tag. */
    {
        hmac_sha256_key_t m;
        hmac_sha256_key(&m, TAP_LOG_KEY, sizeof(TAP_LOG_KEY));
        hmac_sha256(&m, "usbtap card v1", 14u, g_cipher_key);
        memset(&m, 0, sizeof(m));
        sd_log_set_key(&g_sd_log, g_cipher_key, (uint8_t)g_log.session_id);
    }

    /* Checks the card's log before writing to it, with the drive still unpowered. */
    if (g_sd_log.state == SD_LOG_OPEN || g_sd_log.state == SD_LOG_FULL) {
        const uint64_t t0 = time_us_64();
        audit_chain_check_init(&g_card_check, &g_chain_key);
        if (checkpoint_load() && g_ckpt.file_id == g_sd_log.file_id && !(g_ckpt.flags & CKPT_EMPTY)) {
            audit_chain_check_watch(&g_card_check, g_ckpt.session_id, g_ckpt.seq, g_ckpt.head);
        }
        /* The walk also finds each volume's last model snapshot (tap_model.c). */
        const bool walked = sd_log_for_each_record_all(&g_sd_log, model_index_visit, &g_card_check,
                                                       &g_card_check_blocks);
        audit_chain_check_finish(&g_card_check);
        g_card_check_us = time_us_64() - t0;
        g_card_check_ran = true;
        g_card_check_walked = walked;
        g_card_check_aux = checkpoint_compare(&g_card_check, g_sd_log.file_id);
        g_card_check_ok = walked && !g_card_check.broken && !(g_card_check_aux & AUDIT_CHECKPOINT_LOST);
        g_card_full = g_card_check_ok && sd_log_blocks_free(&g_sd_log) <= SD_LOG_RESERVE_BLOCKS;
        if (g_card_full) {
            g_card_check_aux |= AUDIT_CHECKPOINT_FULL;
        }
        if (g_card_check_ok) {
            audit_log_set_genesis(&g_log, g_card_check.prev);   /* the card's last hash */
        } else {
            sd_log_set_off(&g_sd_log);   /* refuse to append to a log that does not verify */
            snprintf(g_sd_info.why, sizeof(g_sd_info.why), "the log on the card failed its chain check");
        }
    }
    /* A new card with the right card_password.txt becomes the reference, and the tap starts again
     * with it. */
    accept_by_password();
    audit_log_session_start(&g_log, 0, g_capture.speed,
                            (uint32_t)g_capture.sample_hz);
    if (g_card_check_ran) {
        const uint8_t op = !g_card_check_ok ? AUDIT_CHECK_FAIL
                         : checkpoint_first_after_password(&g_card_check, g_card_check_aux) ? AUDIT_CHECK_ACCEPT
                                                                                            : AUDIT_CHECK_PASS;
        audit_log_card_check(&g_log, (time_us_64() - g_capture.start_us) * 1000u, &g_card_check, op,
                             g_card_check_aux, g_card_check_blocks);
    }

    /* The PC side's VBUS (GPIO 26): read from the main loop on. */
    vbus_setup();

    /* Loads the volume saved last before the drive is powered, so the mount's reads are compared
     * with it. */
    if (g_card_check_ok) {
        model_preload();
    }

    /* Powers the drive only if the self-test passed and the card's log checked clean with room left. */
    if (g_selftest_pass && g_card_check_ok && !g_card_full) {
        drive_power(true, AUDIT_POWER_BOOT_CHECKS);
    }
    led_set(g_drive_power ? LED_READY : LED_FAULT);

#if TAP_DEBUG
    absolute_time_t next_stats = make_timeout_time_ms(10000);
#endif

    while (g_running) {
        uint64_t part_t0 = time_us_64();
#if TAP_DEBUG
        if (!g_banner_done) {
            if (!stdio_usb_connected()) {
                g_connect_since_us = 0u;
            } else if (g_connect_since_us == 0u) {
                g_connect_since_us = time_us_64();
            } else if (time_us_64() - g_connect_since_us >= BANNER_DELAY_US) {
                print_banner();
                g_banner_done = true;     /* held records go out from here on */
            }
        }
#endif
        const uint64_t it_t0 = gap_mark(GAP_BANNER, part_t0);
        const bool busy_iter = link_busy();
        drain_queues();
        part_t0 = gap_mark(GAP_DRAIN, it_t0);
        const uint64_t drain_us = part_t0 - it_t0;
        /* Records held while no terminal was connected go out once one is. */
        console_pump();
        sd_pump();
        /* Metadata: decode copied chunks, print at most one sector line, report directory commands
         * whose sectors never came. */
        const uint64_t meta_t0 = gap_mark(GAP_CONSOLE, part_t0);
        meta_service();
        part_t0 = time_us_64();
        const uint64_t meta_us = part_t0 - meta_t0;
        meta_expect_tick(&g_expect, part_t0, META_EXPECT_TIMEOUT_US);
        names_runs_tick(false);
        model_tick();
        vbus_tick();
        card_full_tick(time_us_64());
        attach_flush(false);
        part_t0 = gap_mark(GAP_TAIL, part_t0);

#if TAP_DEBUG
        int c = getchar_timeout_us(0);
        if (c != PICO_ERROR_TIMEOUT) {
            handle_key(c);
        }
#endif
        part_t0 = gap_mark(GAP_KEYS, part_t0);

        /* The LED, as a part of its own; a blink waits while the link is backed up (it talks to the
         * wireless chip). */
        if (g_led_state == LED_READY && (g_sd_log.state == SD_LOG_OFF || g_sd_log.state == SD_LOG_FULL)) {
            led_set(LED_FAULT);
        }
        if (!link_busy()) {
            led_tick();
        }
        part_t0 = gap_mark(GAP_LED, part_t0);
#if TAP_DEBUG
        if (absolute_time_diff_us(get_absolute_time(), next_stats) < 0) {
            print_stats();          /* attributes its own printing to the stats part */
            part_t0 = time_us_64();
            next_stats = make_timeout_time_ms(10000);
        }
#endif
        (void)gap_mark(GAP_STATS, part_t0);
        loop_account(it_t0, drain_us, meta_us, busy_iter);
        tight_loop_contents();
    }

    /* core1 flushes any outstanding commands on its way out. */
    sleep_ms(50);
    drain_queues();
    while (meta_rx_pump(&g_meta_rx, &g_meta_link, 64u) != 0u) {
    }
    meta_rx_finish(&g_meta_rx);
    meta_expect_tick(&g_expect, time_us_64(), 0u);   /* whatever is still waiting never came */
    store_sync(&g_sector_store);
    names_runs_tick(true);
    /* Saves the model if the drive is still there (else it was saved when it went). */
    model_save(g_host_gone ? "the PC side's power went" : "the session ended");
    if (g_drive_power) {
        drive_power(false, AUDIT_POWER_SESSION_END);   /* nothing logs the drive after this */
    }
    attach_flush(true);
    audit_log_session_end(&g_log, 0);
    /* Gives the SD FIFO up to a second to empty before the sync writes the last partial block. */
    {
        const uint64_t until = time_us_64() + 1000000u;
        while ((store_fifo_held(&g_sd_fifo) != 0u || sd_log_sector_pending(&g_sd_log)) && time_us_64() < until) {
            sd_log_tick(&g_sd_log, time_us_64());   /* moves a waiting sector into the stream */
            store_fifo_pump(&g_sd_fifo, UINT32_MAX);
        }
    }
    store_sync(&g_store);
    usb_capture_stop(&g_capture);

    char head[65];
    audit_log_head_hex(&g_log, head);
    tap_printf("[chain] final head=%s over %llu records\n", head,
           (unsigned long long)g_log.records);
    const bool card_complete = sd_read_back();

    /* The checkpoint: the card's last record, now that the read-back proved the card holds it. */
    if (card_complete) {
        const bool ok = checkpoint_save(g_sd_log.file_id, g_log.session_id, g_log.seq - 1u, g_log.prev_hash, 0u);
        tap_printf("[ckpt]  checkpoint %s: session %016llx seq %llu (generation %lu)\n",
               ok ? "kept in flash" : "NOT kept (flash did not read back)",
               (unsigned long long)g_log.session_id, (unsigned long long)(g_log.seq - 1u),
               (unsigned long)g_ckpt.generation);
    } else if (g_ckpt_accept) {
        const bool ok = checkpoint_save_accepted(0u);
        tap_printf("[ckpt]  checkpoint %s from the operator's accept: the card as the check found it\n",
               ok ? "kept in flash" : "NOT kept (flash did not read back)");
    } else {
        tap_printf("[ckpt]  checkpoint unchanged: this session's card copy is not proven complete\n");
    }
    led_set(LED_OFF);   /* the session is closed and saved */
#if TAP_DEBUG
    print_stats();
#endif

    gpio_put(POWER_HOLD_PIN, false);   /* on battery the tap now turns off; on the PC's power it stays up */
    if (g_host_gone) {
        vbus_wait_and_reboot();   /* a new session when the PC side is back */
    }
    while (true) {
        sleep_ms(1000);
    }
}
