/*
 * Samples D+/D- with one PIO instruction into a 32 KiB ring that two chained DMA channels fill
 * forever.
 */

/* memset. */
#include <string.h>

/* The SDK: clocks for the PIO divider, the timer, GPIO. */
#include "hardware/clocks.h"
#include "pico/time.h"
#include "hardware/gpio.h"

/* What this file defines, and the assembled PIO program (usb_tap.pio). */
#include "usb_capture.h"
#include "usb_tap.pio.h"

/* The ring, aligned to its size for the DMA's address wrap; each chained run is a whole number of
 * rings. */
static uint32_t ring_buf[USB_CAPTURE_RING_WORDS]
    __attribute__((aligned(USB_CAPTURE_RING_BYTES)));

/* Words per DMA channel run (~2.8 s at Full Speed): a multiple of the ring, under the 2^28 count
 * limit. */
#define CAPTURE_CHAIN_WORDS (USB_CAPTURE_RING_WORDS * 1024u)

/* Unread words kept clear of the DMA before an overrun is declared: half the ring, more than one
 * decode pass reads. */
#define CAPTURE_OVERRUN_MARGIN (USB_CAPTURE_RING_WORDS / 2u)

/* Backlog left after a drop: half the drop limit, so a sustained overload drops rarely, in larger
 * pieces. */
#define CAPTURE_DROP_TO ((USB_CAPTURE_RING_WORDS - CAPTURE_OVERRUN_MARGIN) / 2u)

/* Gives the ring index the DMA writes next, read from whichever channel is running. */
static uint32_t __not_in_flash_func(capture_write_index)(const usb_capture_t *cap)
{
    int ch = dma_channel_is_busy(cap->dma_a) ? cap->dma_a : cap->dma_b;
    uintptr_t wa = (uintptr_t)dma_hw->ch[ch].write_addr;
    return (uint32_t)((wa - (uintptr_t)cap->ring) >> 2) & (USB_CAPTURE_RING_WORDS - 1u);
}

/* Sets one DMA channel to move PIO words into the ring and start `chain_to` when done. */
static void capture_configure_dma(usb_capture_t *cap, int ch, int chain_to)
{
    dma_channel_config c = dma_channel_get_default_config(ch);
    channel_config_set_transfer_data_size(&c, DMA_SIZE_32);
    channel_config_set_read_increment(&c, false);
    channel_config_set_write_increment(&c, true);
    channel_config_set_dreq(&c, pio_get_dreq(cap->pio, cap->sm, false));
    /* 2^15 bytes = 32 KiB write-address wrap. */
    channel_config_set_ring(&c, true, 15);
    channel_config_set_chain_to(&c, chain_to);

    dma_channel_configure(ch, &c, cap->ring, &cap->pio->rxf[cap->sm],
                          CAPTURE_CHAIN_WORDS, false);
}

/* Claims a state machine and two DMA channels, and loads the program at the sample rate. */
bool usb_capture_init(usb_capture_t *cap, PIO pio, uint dp_pin,
                      usb_speed_t speed, uint oversample)
{
    memset(cap, 0, sizeof(*cap));

    if (oversample == 0) {
        oversample = USB_CAPTURE_OVERSAMPLE;
    }

    cap->pio        = pio;
    cap->dp_pin     = dp_pin;
    cap->speed      = speed;
    cap->oversample = oversample;
    cap->ring       = ring_buf;
    cap->idle_word  = (speed == USB_SPEED_LOW) ? USB_CAPTURE_IDLE_LS
                                               : USB_CAPTURE_IDLE_FS;

    int sm = pio_claim_unused_sm(pio, false);
    if (sm < 0) {
        return false;
    }
    cap->sm = (uint)sm;

    if (!pio_can_add_program(pio, &usb_tap_sample_program)) {
        pio_sm_unclaim(pio, cap->sm);
        return false;
    }
    cap->offset = (uint)pio_add_program(pio, &usb_tap_sample_program);

    float target_hz = (float)usb_speed_bitrate(speed) * (float)oversample;
    cap->sample_hz = usb_tap_sample_program_init(pio, cap->sm, cap->offset,
                                                 dp_pin, target_hz);
    cap->ns_per_sample_q16 = (uint32_t)((1000000000.0f / cap->sample_hz) * 65536.0f);

    cap->dma_a = dma_claim_unused_channel(false);
    cap->dma_b = dma_claim_unused_channel(false);
    if (cap->dma_a < 0 || cap->dma_b < 0) {
        usb_capture_release(cap);
        return false;
    }

    capture_configure_dma(cap, cap->dma_a, cap->dma_b);
    capture_configure_dma(cap, cap->dma_b, cap->dma_a);
    return true;
}

/* Clears the ring and the counters, then starts the DMA and the state machine. */
void usb_capture_start(usb_capture_t *cap)
{
    if (cap->running) {
        return;
    }

    memset(cap->ring, 0, USB_CAPTURE_RING_BYTES);
    cap->read_idx      = 0;
    cap->total_read    = 0;
    cap->total_written = 0;
    cap->overrun_words = 0;

    cap->ring_laps = 0;
    cap->words_per_us_q16 =
        (uint32_t)((cap->sample_hz / (float)USB_CAPTURE_SAMPLES_PER_WORD /
                    1000000.0f) * 65536.0f);

    pio_sm_clear_fifos(cap->pio, cap->sm);
    pio_sm_restart(cap->pio, cap->sm);
    pio_sm_exec(cap->pio, cap->sm, pio_encode_jmp(cap->offset));

    /* Both channels back to the ring's start; A is armed and chains into B. */
    dma_channel_set_write_addr(cap->dma_a, cap->ring, false);
    dma_channel_set_write_addr(cap->dma_b, cap->ring, false);
    dma_channel_set_trans_count(cap->dma_a, CAPTURE_CHAIN_WORDS, false);
    dma_channel_set_trans_count(cap->dma_b, CAPTURE_CHAIN_WORDS, false);
    dma_channel_start(cap->dma_a);

    pio_sm_set_enabled(cap->pio, cap->sm, true);
    cap->start_us = time_us_64();
    cap->running = true;
}

/* Stops the state machine and both DMA channels. */
void usb_capture_stop(usb_capture_t *cap)
{
    if (!cap->running) {
        return;
    }
    pio_sm_set_enabled(cap->pio, cap->sm, false);
    dma_channel_abort(cap->dma_a);
    dma_channel_abort(cap->dma_b);
    pio_sm_clear_fifos(cap->pio, cap->sm);
    cap->running = false;
}

/* Stops the capture and gives back its DMA channels, PIO program and state machine. */
void usb_capture_release(usb_capture_t *cap)
{
    usb_capture_stop(cap);
    if (cap->dma_a >= 0) {
        dma_channel_unclaim(cap->dma_a);
        cap->dma_a = -1;
    }
    if (cap->dma_b >= 0) {
        dma_channel_unclaim(cap->dma_b);
        cap->dma_b = -1;
    }
    pio_remove_program(cap->pio, &usb_tap_sample_program, cap->offset);
    pio_sm_unclaim(cap->pio, cap->sm);
}

/* The timer's registers, for usb_capture_time_us. */
#include "hardware/timer.h"

/* timer_time_us_64() in SRAM: the high word, the low word, and again if the high word moved. */
uint64_t __not_in_flash_func(usb_capture_time_us)(void)
{
    timer_hw_t *const t = PICO_DEFAULT_TIMER_INSTANCE();
    uint32_t hi = t->timerawh;
    uint32_t lo;
    for (;;) {
        lo = t->timerawl;
        const uint32_t next_hi = t->timerawh;
        if (next_hi == hi) {
            break;
        }
        hi = next_hi;
    }
    return ((uint64_t)hi << 32) | lo;
}

/* Counts the words written since the last call, laps included, and drops the oldest if the consumer is too far behind. */
void __not_in_flash_func(usb_capture_poll)(usb_capture_t *cap)
{
    if (!cap->running) {
        return;
    }

    uint32_t widx = capture_write_index(cap);
    uint32_t prev = (uint32_t)cap->total_written & (USB_CAPTURE_RING_WORDS - 1u);
    uint32_t delta = (widx - prev) & (USB_CAPTURE_RING_WORDS - 1u);
    uint64_t candidate = cap->total_written + delta;

    /* The pointer is modulo the ring: add laps until it agrees with the words the clock says were
     * produced. */
    uint64_t elapsed_us = usb_capture_time_us() - cap->start_us;
    uint64_t expected = (elapsed_us * cap->words_per_us_q16) >> 16;
    while (expected > candidate + (USB_CAPTURE_RING_WORDS / 2u)) {
        candidate += USB_CAPTURE_RING_WORDS;
        cap->ring_laps++;
    }

    cap->total_written = candidate;

    /* A consumer too far behind loses the oldest samples, counted: a passive tap cannot slow the
     * bus. */
    uint32_t avail = usb_capture_available(cap);
    const uint32_t limit = USB_CAPTURE_RING_WORDS - CAPTURE_OVERRUN_MARGIN;
    if (avail > limit) {
        /* Drops down to CAPTURE_DROP_TO: every cut costs the rest of a packet, so fewer, larger
         * drops lose less. */
        uint32_t drop = avail - CAPTURE_DROP_TO;
        cap->overrun_words += drop;
        cap->overrun_events++;
        usb_capture_consume(cap, drop);
    }
}
