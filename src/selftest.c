/*
 * The boot self-test: known Full Speed packets encoded into the capture ring sample by sample (NRZI,
 * bit stuffing, glitches) and run through the real decoder, parser and audit log; also the [bench] stream.
 */

/* printf for the results; memset, memcpy, memcmp. */
#include <stdio.h>
#include <string.h>

/* The decoder, parser and log under test, and what this file defines. */
#include "audit_log.h"
#include "msc_parse.h"
#include "selftest.h"
#include "tap_debug.h"
#include "usb_decode.h"

/* ---- Full Speed line encoder ----------------------------------------- */

/* Writes line states into a ring of sample words, 16 two-bit samples per word. */
typedef struct {
    uint32_t *ring;
    uint32_t  capacity;     /* words */
    uint32_t  samples;
    uint32_t  oversample;
    bool      overflow;
} encoder_t;

/* Appends one sample (a line state: J, K, SE0 or SE1). */
static void put_sample(encoder_t *e, uint32_t line)
{
    uint32_t widx = e->samples >> 4;
    if (widx >= e->capacity) {
        e->overflow = true;
        return;
    }
    uint32_t shift = (e->samples & 15u) * 2u;
    if (shift == 0) {
        e->ring[widx] = 0;
    }
    e->ring[widx] |= (line & 0x3u) << shift;
    e->samples++;
}

/* Overwrites one already-emitted sample, used to inject bus artifacts. */
static void set_sample(encoder_t *e, uint32_t idx, uint32_t line)
{
    uint32_t widx  = idx >> 4;
    uint32_t shift = (idx & 15u) * 2u;
    if (widx < e->capacity) {
        e->ring[widx] = (e->ring[widx] & ~(0x3u << shift)) |
                        ((line & 0x3u) << shift);
    }
}

/* Appends `count` samples of the same line state. */
static void put_state(encoder_t *e, uint32_t line, uint32_t count)
{
    for (uint32_t i = 0; i < count; i++) {
        put_sample(e, line);
    }
}

/* The two data states on a Full Speed bus. */
#define LINE_J USB_LINE_DP   /* Full Speed idle / NRZI '1' hold state */
#define LINE_K USB_LINE_DM   /* the other state: an NRZI '0' toggles J and K */

/* NRZI-encodes one packet (SYNC + bytes, stuffing bits inserted) and appends a Full Speed EOP. */
static void emit_packet(encoder_t *e, const uint8_t *bytes, uint32_t nbytes)
{
    const uint32_t os = e->oversample;
    uint32_t line = LINE_J;
    uint32_t ones = 0;

    uint8_t stream[64 + 4];
    uint32_t n = 0;
    stream[n++] = 0x80u;   /* SYNC: 0000 0001, LSB first on the wire */
    for (uint32_t i = 0; i < nbytes && n < sizeof(stream); i++) {
        stream[n++] = bytes[i];
    }

    for (uint32_t byte = 0; byte < n; byte++) {
        for (uint32_t b = 0; b < 8; b++) {
            uint32_t bit = (stream[byte] >> b) & 1u;

            if (bit) {
                ones++;
            } else {
                line = (line == LINE_J) ? LINE_K : LINE_J;
                ones = 0;
            }
            put_state(e, line, os);

            if (ones == 6u) {
                /* Stuffed zero: a forced transition the decoder must discard. */
                line = (line == LINE_J) ? LINE_K : LINE_J;
                ones = 0;
                put_state(e, line, os);
            }
        }
    }

    put_state(e, USB_LINE_SE0, os * 2u);   /* EOP */
    put_state(e, LINE_J, os * 2u);         /* return to idle */
}

/* Builds a PID byte: the PID, then its complement in the high nibble. */
static uint8_t pid_byte(usb_pid_t pid)
{
    return (uint8_t)(pid | ((~(uint8_t)pid & 0x0Fu) << 4));
}

/* Emits a token packet: PID, the 11-bit address/endpoint field and its CRC5. */
static void emit_token(encoder_t *e, usb_pid_t pid, uint16_t field11)
{
    uint8_t b[3];
    b[0] = pid_byte(pid);
    b[1] = (uint8_t)(field11 & 0xFFu);
    b[2] = (uint8_t)(((field11 >> 8) & 0x07u) | (usb_crc5(field11, 11) << 3));
    emit_packet(e, b, 3);
}

/* Emits a data packet: PID, payload and its CRC16. */
static void emit_data(encoder_t *e, usb_pid_t pid, const uint8_t *payload,
                      uint32_t len)
{
    uint8_t b[64];
    uint32_t n = 0;
    b[n++] = pid_byte(pid);
    for (uint32_t i = 0; i < len && n < sizeof(b) - 2u; i++) {
        b[n++] = payload[i];
    }
    uint16_t crc = usb_crc16(payload, len);
    b[n++] = (uint8_t)(crc & 0xFFu);
    b[n++] = (uint8_t)(crc >> 8);
    emit_packet(e, b, n);
}

/* Emits a handshake packet: the PID alone. */
static void emit_handshake(encoder_t *e, usb_pid_t pid)
{
    uint8_t b = pid_byte(pid);
    emit_packet(e, &b, 1);
}

/* ---- expected results ------------------------------------------------ */

/* The test transfer: a READ(10) of TEST_BLOCKS sectors at TEST_LBA from device 3. */
#define TEST_ADDR   3
#define TEST_EP_OUT 2
#define TEST_EP_IN  1
#define TEST_TAG    0xDEADBEEFu
#define TEST_LBA    0x1234u
#define TEST_BLOCKS 8u

/* The first command the parser emitted, and how many it emitted. */
static msc_command_t g_seen;
static uint32_t      g_seen_count;

/* The all-ones DATA1 payload, captured: bit unstuffing must survive a stuffed zero every seven
 * bits. */
static uint8_t  g_stuff_payload[16];
static uint32_t g_stuff_len;
static bool     g_stuff_seen;

/* The glitched packet's payload, captured: single-sample SE1 and SE0 artifacts must be ridden
 * through. */
static uint8_t  g_glitch_payload[8];
static uint32_t g_glitch_len;
static bool     g_glitch_seen;

static msc_command_t g_seen_eject;   /* the second command: a safe-eject */

/* Keeps the first two commands the parser emits (the READ and the eject). */
static void selftest_command(const msc_command_t *cmd, void *ctx)
{
    (void)ctx;
    if (g_seen_count == 0) {
        g_seen = *cmd;
    } else if (g_seen_count == 1) {
        g_seen_eject = *cmd;
    }
    g_seen_count++;
}

/* Builds the test READ(10)'s CBW. */
static void build_cbw(uint8_t cbw[31])
{
    memset(cbw, 0, 31);
    cbw[0] = 'U'; cbw[1] = 'S'; cbw[2] = 'B'; cbw[3] = 'C';
    cbw[4] = (uint8_t)(TEST_TAG);
    cbw[5] = (uint8_t)(TEST_TAG >> 8);
    cbw[6] = (uint8_t)(TEST_TAG >> 16);
    cbw[7] = (uint8_t)(TEST_TAG >> 24);
    uint32_t xfer = TEST_BLOCKS * 512u;
    cbw[8]  = (uint8_t)(xfer);
    cbw[9]  = (uint8_t)(xfer >> 8);
    cbw[10] = (uint8_t)(xfer >> 16);
    cbw[11] = (uint8_t)(xfer >> 24);
    cbw[12] = 0x80u;   /* data in: device to host */
    cbw[13] = 0x00u;   /* LUN 0 */
    cbw[14] = 10u;     /* CDB length */

    uint8_t *cdb = &cbw[15];
    cdb[0] = SCSI_READ_10;
    cdb[2] = (uint8_t)(TEST_LBA >> 24);
    cdb[3] = (uint8_t)(TEST_LBA >> 16);
    cdb[4] = (uint8_t)(TEST_LBA >> 8);
    cdb[5] = (uint8_t)(TEST_LBA);
    cdb[7] = (uint8_t)(TEST_BLOCKS >> 8);
    cdb[8] = (uint8_t)(TEST_BLOCKS);
}

/* Builds its CSW: same tag, residue 0, passed. */
static void build_csw(uint8_t csw[13])
{
    memset(csw, 0, 13);
    csw[0] = 'U'; csw[1] = 'S'; csw[2] = 'B'; csw[3] = 'S';
    csw[4] = (uint8_t)(TEST_TAG);
    csw[5] = (uint8_t)(TEST_TAG >> 8);
    csw[6] = (uint8_t)(TEST_TAG >> 16);
    csw[7] = (uint8_t)(TEST_TAG >> 24);
    /* residue 0, status 0 (command passed) */
}

/* A safe-eject: START STOP UNIT with LoEj set and Start clear; the command block alone says
 * "eject". */
#define TEST_EJECT_TAG (TEST_TAG + 1u)

/* Builds the safe-eject's CBW and CSW. */
static void build_eject(uint8_t cbw[31], uint8_t csw[13])
{
    memset(cbw, 0, 31);
    cbw[0] = 'U'; cbw[1] = 'S'; cbw[2] = 'B'; cbw[3] = 'C';
    cbw[4] = (uint8_t)(TEST_EJECT_TAG);
    cbw[5] = (uint8_t)(TEST_EJECT_TAG >> 8);
    cbw[6] = (uint8_t)(TEST_EJECT_TAG >> 16);
    cbw[7] = (uint8_t)(TEST_EJECT_TAG >> 24);
    cbw[14] = 6u;                     /* CDB length */
    cbw[15] = SCSI_START_STOP_UNIT;
    cbw[15 + 4] = 0x02u;              /* LoEj=1, Start=0 */

    memset(csw, 0, 13);
    csw[0] = 'U'; csw[1] = 'S'; csw[2] = 'B'; csw[3] = 'S';
    memcpy(&csw[4], &cbw[4], 4);      /* same tag */
}

/* ---- the test -------------------------------------------------------- */

/* Prints one check's result (failures always, passes when verbose); returns cond. */
static bool check(bool cond, const char *what, bool verbose)
{
    if (!cond) {
        tap_printf("[self]  FAIL: %s\n", what);
    } else if (verbose) {
        tap_printf("[self]  ok:   %s\n", what);
    }
    return cond;
}

/* The decoder, parser and log the test runs (static: they are large for core0's stack). */
static usb_decoder_t g_test_decoder;
static msc_parser_t  g_test_parser;
static audit_log_t   g_test_log;

/* The SUSPEND and SUSPEND-END events the decoder reported: count, time, duration. */
static uint32_t g_suspend_n, g_suspend_end_n;
static uint64_t g_suspend_ts, g_suspend_dur, g_suspend_end_ts, g_suspend_end_dur;

/* Keeps the suspend events the decoder reports. */
static void selftest_event(usb_bus_event_t ev, uint64_t ts_ns, uint64_t duration_ns,
                           uint32_t count, void *ctx)
{
    (void)ctx;
    if (ev == USB_BUS_EVENT_SUSPEND) {
        g_suspend_n  += count;
        g_suspend_ts  = ts_ns;
        g_suspend_dur = duration_ns;
    } else if (ev == USB_BUS_EVENT_SUSPEND_END) {
        g_suspend_end_n  += count;
        g_suspend_end_ts  = ts_ns;
        g_suspend_end_dur = duration_ns;
    }
}

/* Keeps the stuffing and glitch packets' payloads, and feeds every packet to the parser. */
static void selftest_packet(const usb_packet_t *pkt, void *ctx)
{
    if (pkt->status == USB_DEC_OK && pkt->pid == USB_PID_DATA1 &&
        pkt->payload_len <= sizeof(g_stuff_payload)) {
        memcpy(g_stuff_payload, pkt->payload, pkt->payload_len);
        g_stuff_len = pkt->payload_len;
        g_stuff_seen = true;
    }
    if (pkt->status == USB_DEC_OK && pkt->pid == USB_PID_DATA0 &&
        pkt->payload_len == 4u) {
        memcpy(g_glitch_payload, pkt->payload, 4u);
        g_glitch_len = 4u;
        g_glitch_seen = true;
    }
    msc_parser_feed((msc_parser_t *)ctx, pkt);
}

/* Runs every check on the capture's ring, leaves the ring clean, and prints PASS or FAIL. */
bool usb_selftest_run(usb_capture_t *cap, bool verbose)
{
    bool pass = true;

    /* Arithmetic checks first; 0x02 is the CRC5 of an all-zero token (SETUP to address 0: 2D 00
     * 10). */
    pass &= check(usb_crc5(0, 11) == 0x02u, "crc5(addr 0, ep 0) == 0x02", verbose);
    pass &= check(usb_crc16(NULL, 0) == 0x0000u, "crc16(empty) == 0x0000", verbose);

    encoder_t enc = {
        .ring = cap->ring,
        .capacity = USB_CAPTURE_RING_WORDS,
        .samples = 0,
        .oversample = cap->oversample,
        .overflow = false,
    };

    uint8_t cbw[31], csw[13];
    build_cbw(cbw);
    build_csw(csw);

    /* A plausible slice of a Full Speed mass storage read. */
    put_state(&enc, LINE_J, cap->oversample * 8u);
    emit_token(&enc, USB_PID_SOF, 0x2A5u);
    put_state(&enc, LINE_J, cap->oversample * 8u);
    emit_token(&enc, USB_PID_OUT, (uint16_t)(TEST_ADDR | (TEST_EP_OUT << 7)));
    emit_data(&enc, USB_PID_DATA0, cbw, sizeof(cbw));
    emit_handshake(&enc, USB_PID_ACK);

    /* The data phase: file data on bulk-IN, to be skipped from its first four bytes ("USBC" inside
     * must not count). */
    put_state(&enc, LINE_J, cap->oversample * 8u);
    emit_token(&enc, USB_PID_IN, (uint16_t)(TEST_ADDR | (TEST_EP_IN << 7)));
    static const uint8_t file_payload[32] = {
        0xFF, 0xFF, 0xFF, 0x55, 0x53, 0x42, 0x43, 0x00,
        0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80,
        0x90, 0xA0, 0xB0, 0xC0, 0xD0, 0xE0, 0xF0, 0x0F,
        0x1E, 0x2D, 0x3C, 0x4B, 0x5A, 0x69, 0x78, 0x87,
    };
    emit_data(&enc, USB_PID_DATA1, file_payload, sizeof(file_payload));
    emit_handshake(&enc, USB_PID_ACK);

    put_state(&enc, LINE_J, cap->oversample * 8u);
    emit_token(&enc, USB_PID_IN, (uint16_t)(TEST_ADDR | (TEST_EP_IN << 7)));
    emit_data(&enc, USB_PID_DATA0, csw, sizeof(csw));
    emit_handshake(&enc, USB_PID_ACK);

    /* An all-ones payload: a stuffed zero every seven bits, inserted and dropped again. */
    put_state(&enc, LINE_J, cap->oversample * 8u);
    /* To control endpoint 0, always decoded in full, so these packets exercise the bit-level
     * decoder. */
    emit_token(&enc, USB_PID_OUT, (uint16_t)(TEST_ADDR | (0u << 7)));
    static const uint8_t ones_payload[8] = {
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
    };
    emit_data(&enc, USB_PID_DATA1, ones_payload, sizeof(ones_payload));
    emit_handshake(&enc, USB_PID_ACK);

    /* One packet with a single SE1 and a single SE0 sample in it, shorter than a bit: ridden
     * through. */
    put_state(&enc, LINE_J, cap->oversample * 8u);
    static const uint8_t glitch_payload[4] = { 0xA5, 0x5A, 0x3C, 0xC3 };
    uint32_t glitch_start = enc.samples;
    emit_data(&enc, USB_PID_DATA0, glitch_payload, sizeof(glitch_payload));
    set_sample(&enc, glitch_start + (cap->oversample * 12u), USB_LINE_SE1);
    set_sample(&enc, glitch_start + (cap->oversample * 20u), USB_LINE_SE0);

    /* The drive being ejected. */
    put_state(&enc, LINE_J, cap->oversample * 8u);
    uint8_t eject_cbw[31], eject_csw[13];
    build_eject(eject_cbw, eject_csw);
    emit_token(&enc, USB_PID_OUT, (uint16_t)(TEST_ADDR | (TEST_EP_OUT << 7)));
    /* DATA0: selftest_packet() treats short DATA1 packets as the stuffing test. */
    emit_data(&enc, USB_PID_DATA0, eject_cbw, sizeof(eject_cbw));
    emit_handshake(&enc, USB_PID_ACK);
    put_state(&enc, LINE_J, cap->oversample * 8u);
    emit_token(&enc, USB_PID_IN, (uint16_t)(TEST_ADDR | (TEST_EP_IN << 7)));
    emit_data(&enc, USB_PID_DATA0, eject_csw, sizeof(eject_csw));
    emit_handshake(&enc, USB_PID_ACK);

    /* The host suspending the port, as a safe eject does: idle with no SOF past the (lowered)
     * threshold, then a SOF. */
    while ((enc.samples & 15u) != 0u) {
        put_sample(&enc, LINE_J);
    }
    put_state(&enc, LINE_J, 48u * 16u);
    const uint32_t idle_to = enc.samples;
    uint32_t idle_from_w = idle_to / 16u;
    while (idle_from_w > 0u && cap->ring[idle_from_w - 1u] == cap->idle_word) {
        idle_from_w--;
    }
    emit_token(&enc, USB_PID_SOF, 0x2A6u);

    put_state(&enc, LINE_J, cap->oversample * 64u);

    pass &= check(!enc.overflow, "synthetic stream fits in the capture ring", verbose);

    while ((enc.samples & 15u) != 0u) {
        put_sample(&enc, LINE_J);   /* pad the final word with idle */
    }
    uint32_t words = enc.samples / 16u;

    cap->read_idx      = 0;
    cap->total_read    = 0;
    cap->total_written = words;

    g_seen_count  = 0;
    g_stuff_len   = 0;
    g_stuff_seen  = false;
    g_glitch_len  = 0;
    g_glitch_seen = false;
    memset(&g_seen, 0, sizeof(g_seen));

    usb_decoder_init(&g_test_decoder, cap->speed, cap->oversample);
    msc_parser_init(&g_test_parser, selftest_command, NULL);
    usb_decoder_set_callbacks(&g_test_decoder, selftest_packet, selftest_event,
                              &g_test_parser);
    g_test_decoder.suspend_words = 32u;
    g_suspend_n = g_suspend_end_n = 0;
    audit_log_init(&g_test_log, 0, NULL);

    usb_decode_run(&g_test_decoder, cap);
    usb_decode_finish(&g_test_decoder, cap);   /* reports the coalesced events */

    pass &= check(g_test_decoder.packets_ok == 20,
                  "20 packets decoded with valid PID and CRC", verbose);
    pass &= check(g_suspend_n == 1u && g_suspend_end_n == 1u,
                  "idle bus reported as one suspend and one suspend end", verbose);
    pass &= check(g_suspend_ts == usb_capture_sample_to_ns(cap, (uint64_t)idle_from_w * 16u) &&
                  g_suspend_dur == usb_capture_sample_to_ns(cap, 32u * 16u) &&
                  g_suspend_end_ts == usb_capture_sample_to_ns(cap, idle_to) &&
                  g_suspend_end_dur == usb_capture_sample_to_ns(cap, idle_to - idle_from_w * 16u),
                  "suspend timed from the idle start, its end with the whole idle time", verbose);
    pass &= check(g_test_decoder.packets_skipped == 1,
                  "file-data packet skipped without decoding", verbose);
    pass &= check(g_test_decoder.packets_err == 0, "no decode errors", verbose);
    pass &= check(g_test_parser.cbw_count == 2, "two CBWs recognised", verbose);
    pass &= check(g_test_parser.csw_count == 2, "two CSWs recognised", verbose);
    pass &= check(g_seen_count == 2, "two completed SCSI commands emitted", verbose);
    pass &= check(g_seen.op == MSC_OP_READ, "command classified as READ", verbose);
    pass &= check(g_seen.opcode == SCSI_READ_10, "opcode is READ(10)", verbose);
    pass &= check(g_seen.lba == TEST_LBA, "LBA extracted correctly", verbose);
    pass &= check(g_seen.block_count == TEST_BLOCKS, "block count correct", verbose);
    pass &= check(g_seen.data_len == TEST_BLOCKS * 512u,
                  "CBW transfer length correct", verbose);
    pass &= check(g_seen.tag == TEST_TAG, "CBW/CSW paired by tag", verbose);
    pass &= check(g_seen.completed && g_seen.status == 0,
                  "CSW reports command passed", verbose);
    pass &= check(g_seen.data_in, "direction is device-to-host", verbose);
    pass &= check(g_seen.dev_addr == TEST_ADDR && g_seen.endpoint == TEST_EP_OUT,
                  "device address and endpoint attributed", verbose);
    pass &= check(g_seen_eject.op == MSC_OP_EJECT &&
                  g_seen_eject.opcode == SCSI_START_STOP_UNIT,
                  "START STOP UNIT with LoEj classified as EJECT", verbose);
    pass &= check(g_seen_eject.cdb_flags == 0x02u && g_seen_eject.completed &&
                  g_seen_eject.tag == TEST_EJECT_TAG,
                  "eject flags kept and paired with its CSW", verbose);

    bool ones_ok = g_stuff_seen && g_stuff_len == 8u;
    for (uint32_t i = 0; ones_ok && i < g_stuff_len; i++) {
        ones_ok = (g_stuff_payload[i] == 0xFFu);
    }
    pass &= check(ones_ok, "all-ones payload survives bit stuffing", verbose);

    bool glitch_ok = g_glitch_seen && g_glitch_len == 4u &&
                     memcmp(g_glitch_payload, glitch_payload, 4u) == 0;
    pass &= check(glitch_ok, "packet survives single SE1 and SE0 artifacts", verbose);

    /* The hash chain must move, and must depend on the record contents. */
    uint8_t head_before[SHA256_DIGEST_SIZE];
    memcpy(head_before, g_test_log.prev_hash, sizeof(head_before));
    audit_log_command(&g_test_log, &g_seen);
    pass &= check(memcmp(head_before, g_test_log.prev_hash, sizeof(head_before)) != 0,
                  "audit record advances the hash chain", verbose);

    msc_command_t tweaked = g_seen;
    tweaked.lba ^= 1u;
    audit_log_t alt;
    audit_log_init(&alt, 0, NULL);
    audit_log_command(&alt, &tweaked);
    audit_log_t same;
    audit_log_init(&same, 0, NULL);
    audit_log_command(&same, &g_seen);
    pass &= check(memcmp(alt.prev_hash, same.prev_hash, SHA256_DIGEST_SIZE) != 0,
                  "changing one LBA changes the chain hash", verbose);

    /* Leaves the ring and the consumer pointers clean for real capture. */
    memset(cap->ring, 0, USB_CAPTURE_RING_BYTES);
    cap->read_idx      = 0;
    cap->total_read    = 0;
    cap->total_written = 0;

    tap_printf("[self]  decode/parse/log self-test: %s\n", pass ? "PASS" : "FAIL");
    return pass;
}

/* ---- decode benchmark ------------------------------------------------ */

/* The benchmark's command callback: does nothing, as the work is the decode. */
static void bench_command(const msc_command_t *cmd, void *ctx)
{
    (void)cmd;
    (void)ctx;
}

/* The decode benchmark: a CBW, 32 file-data transactions with SE1 glitches, SOFs and the CSW, decoded in
 * 2,048-word batches with core1's code. Same code, same input: the cycles say whether the chip counts the
 * same work the same from boot to boot. */
bool usb_selftest_bench(usb_capture_t *cap, usb_selftest_bench_t *out)
{
    memset(out, 0, sizeof(*out));
    encoder_t enc = {
        .ring = cap->ring,
        .capacity = USB_CAPTURE_RING_WORDS,
        .samples = 0,
        .oversample = cap->oversample,
        .overflow = false,
    };
    const uint32_t os = cap->oversample;

    uint8_t cbw[31], csw[13];
    build_cbw(cbw);
    cbw[12] = 0x00u;                   /* direction: host to device, a WRITE */
    cbw[15] = SCSI_WRITE_10;
    build_csw(csw);

    put_state(&enc, LINE_J, os * 8u);
    emit_token(&enc, USB_PID_SOF, 0x100u);
    put_state(&enc, LINE_J, os * 8u);
    emit_token(&enc, USB_PID_OUT, (uint16_t)(TEST_ADDR | (TEST_EP_OUT << 7)));
    emit_data(&enc, USB_PID_DATA0, cbw, sizeof(cbw));
    emit_handshake(&enc, USB_PID_ACK);

    uint8_t payload[64];
    for (uint32_t t = 0; t < BENCH_TRANSACTIONS; t++) {
        if (t % 16u == 15u) {
            put_state(&enc, LINE_J, os * 8u);
            emit_token(&enc, USB_PID_SOF, (uint16_t)(0x101u + t));
        }
        for (uint32_t k = 0; k < sizeof(payload); k++) {
            payload[k] = (uint8_t)("The quick brown fox jumps over the lazy dog. "[(t * 7u + k) % 45u]);
        }
        put_state(&enc, LINE_J, os * 3u);
        emit_token(&enc, USB_PID_OUT, (uint16_t)(TEST_ADDR | (TEST_EP_OUT << 7)));
        put_state(&enc, LINE_J, os * 2u);
        const uint32_t start = enc.samples;
        emit_data(&enc, (t & 1u) ? USB_PID_DATA0 : USB_PID_DATA1, payload, sizeof(payload));
        const uint32_t end = enc.samples - os * 6u;       /* before the EOP */
        for (uint32_t s = start + os * 16u + 1u; s < end; s += 48u) {
            set_sample(&enc, s, USB_LINE_SE1);
        }
        put_state(&enc, LINE_J, os * 2u);
        emit_handshake(&enc, USB_PID_ACK);
    }
    put_state(&enc, LINE_J, os * 8u);
    emit_token(&enc, USB_PID_IN, (uint16_t)(TEST_ADDR | (TEST_EP_IN << 7)));
    emit_data(&enc, USB_PID_DATA1, csw, sizeof(csw));
    emit_handshake(&enc, USB_PID_ACK);
    put_state(&enc, LINE_J, os * 64u);
    while ((enc.samples & 15u) != 0u) {
        put_sample(&enc, LINE_J);
    }
    const uint32_t words = enc.samples / 16u;
    bool ok = !enc.overflow;

    out->words = words;
    out->min_cycles = UINT32_MAX;
    for (uint32_t r = 0; r < BENCH_RUNS; r++) {
        usb_decoder_init(&g_test_decoder, cap->speed, cap->oversample);
        msc_parser_init(&g_test_parser, bench_command, NULL);
        usb_decoder_set_callbacks(&g_test_decoder, selftest_packet, selftest_event, &g_test_parser);
        cap->read_idx   = 0;
        cap->total_read = 0;
        uint32_t cycles = 0;
        for (uint32_t batch_end = DECODE_BENCH_BATCH; cap->total_read < words;
             batch_end += DECODE_BENCH_BATCH) {
            cap->total_written = batch_end < words ? batch_end : words;
            const uint64_t before = cap->total_read;
            const uint32_t c0 = usb_cycles();
            while (usb_decode_run(&g_test_decoder, cap) != 0u) {
            }
            cycles += usb_cycles() - c0;
            if (cap->total_read == before && cap->total_written == words) {
                break;                     /* a packet left open at the end */
            }
        }
        out->runs[r] = cycles;
        if (cycles < out->min_cycles) {
            out->min_cycles = cycles;
        }
        ok = ok && g_test_decoder.packets_skipped == BENCH_TRANSACTIONS &&
             g_test_parser.cbw_count == 1u && g_test_parser.csw_count == 1u &&
             g_test_decoder.packets_err == 0u;
    }
    out->skipped = (uint32_t)g_test_decoder.packets_skipped;
    out->ok = ok;

    memset(cap->ring, 0, USB_CAPTURE_RING_BYTES);
    cap->read_idx      = 0;
    cap->total_read    = 0;
    cap->total_written = 0;
    return ok;
}
