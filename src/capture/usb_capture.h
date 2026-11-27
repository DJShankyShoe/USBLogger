/*
 * The capture: one PIO state machine oversamples D+/D-, and two self-chaining DMA channels stream the
 * samples into a ring with no CPU. The decoder sees only 32-bit sample words.
 */
#ifndef USB_CAPTURE_H
#define USB_CAPTURE_H

/* The SDK's DMA and PIO drivers, and the bus speed type. */
#include "hardware/dma.h"
#include "hardware/pio.h"
#include "usb_proto.h"

/* Ring size in words: 32 KiB, the largest the DMA's address wrap covers (~2.7 ms of Full Speed
 * bus). */
#define USB_CAPTURE_RING_WORDS   8192u
/* The ring's size in bytes. */
#define USB_CAPTURE_RING_BYTES   (USB_CAPTURE_RING_WORDS * 4u)

/* Samples packed per 32-bit word (2 bits each), oldest in the low bits. */
#define USB_CAPTURE_SAMPLES_PER_WORD 16u

/* Default oversampling: 4 samples per bit, the least that lets software re-centre on each bit. */
#define USB_CAPTURE_OVERSAMPLE   4u

/* A word of Full Speed idle (J = D+ high), so idle can be skipped a word at a time. */
#define USB_CAPTURE_IDLE_FS      0x55555555u
/* The same for Low Speed, whose idle is K's levels. */
#define USB_CAPTURE_IDLE_LS      0xAAAAAAAAu

/* Line states, as read from one 2-bit sample. */
#define USB_LINE_SE0  0x0u   /* both low: a reset, an end of packet, or no device */
#define USB_LINE_DP   0x1u   /* D+ high, D- low  -> J at FS, K at LS */
#define USB_LINE_DM   0x2u   /* D- high, D+ low  -> K at FS, J at LS */
#define USB_LINE_SE1  0x3u   /* both high: not a legal state (a glitch, or a stuck bus) */

/* The capture: its PIO and DMA resources, the ring, the sample clock, and how far the consumer has
 * read. */
typedef struct {
    uint32_t   *ring;              /* 32 KiB, 32 KiB-aligned */
    PIO         pio;
    uint        sm;
    uint        offset;
    int         dma_a;
    int         dma_b;
    uint        dp_pin;

    usb_speed_t speed;
    uint        oversample;        /* samples per bit time */
    float       sample_hz;         /* actual achieved sample rate */
    uint32_t    ns_per_sample_q16; /* nanoseconds per sample, 16.16 fixed point */
    uint32_t    idle_word;         /* idle pattern for this speed */

    /* Consumer bookkeeping: read_idx is a ring index; the totals never wrap and double as the
     * timebase. */
    uint32_t    read_idx;
    uint64_t    total_read;
    uint64_t    total_written;
    uint64_t    overrun_words;     /* samples the consumer failed to keep up with */
    uint64_t    overrun_events;    /* how many separate drops made up overrun_words */

    /* Capture start in microseconds: the DMA pointer is only seen modulo the ring, so elapsed time
     * counts the laps. */
    uint64_t    start_us;
    uint32_t    words_per_us_q16;  /* words produced per microsecond, 16.16 */
    /* Laps the unwrap had to add: a stall indicator, not a loss figure (overrun_words is the loss). */
    uint64_t    ring_laps;

    bool        running;
} usb_capture_t;

/* Claims a PIO state machine, two DMA channels and the tap pins; dp_pin is D+, dp_pin + 1 is D-,
 * both inputs. */
bool usb_capture_init(usb_capture_t *cap, PIO pio, uint dp_pin,
                      usb_speed_t speed, uint oversample);

/* Starts sampling into the ring. */
void usb_capture_start(usb_capture_t *cap);
/* Stops sampling; the ring keeps what it holds. */
void usb_capture_stop(usb_capture_t *cap);
/* Gives back the PIO state machine and DMA channels. */
void usb_capture_release(usb_capture_t *cap);

/* Counts the words the DMA has written and any the consumer lost; call at least once per ring
 * period. */
void usb_capture_poll(usb_capture_t *cap);

/* Microseconds since boot, as time_us_64() but in SRAM, so the capture core never waits on flash. */
uint64_t usb_capture_time_us(void);

/* Readable words from the DMA pointer alone, cheap enough to spin on; modulo the ring, so never a
 * loss figure. */
#if defined(PICO_ON_DEVICE) && PICO_ON_DEVICE
/* Device build: from the DMA channel's live write address. */
static inline uint32_t usb_capture_available_hint(const usb_capture_t *cap)
{
    if (!cap->running) {
        return 0;
    }
    int ch = dma_channel_is_busy(cap->dma_a) ? cap->dma_a : cap->dma_b;
    uint32_t widx = (uint32_t)(((uintptr_t)dma_hw->ch[ch].write_addr -
                                (uintptr_t)cap->ring) >> 2);
    return (widx - cap->read_idx) & (USB_CAPTURE_RING_WORDS - 1u);
}
#else
/* Host build: no DMA, so the harness's totals give the exact figure. */
static inline uint32_t usb_capture_available_hint(const usb_capture_t *cap)
{
    return (uint32_t)(cap->total_written - cap->total_read);
}
#endif

/* Words currently readable. Only valid immediately after usb_capture_poll(). */
static inline uint32_t usb_capture_available(const usb_capture_t *cap)
{
    return (uint32_t)(cap->total_written - cap->total_read);
}

/* The word `off` words past the next unread one. */
static inline uint32_t usb_capture_peek(const usb_capture_t *cap, uint32_t off)
{
    return cap->ring[(cap->read_idx + off) & (USB_CAPTURE_RING_WORDS - 1u)];
}

/* Marks `words` words as read. */
static inline void usb_capture_consume(usb_capture_t *cap, uint32_t words)
{
    cap->read_idx = (cap->read_idx + words) & (USB_CAPTURE_RING_WORDS - 1u);
    cap->total_read += words;
}

/* Absolute index of the next unread sample: the tap's timebase. */
static inline uint64_t usb_capture_sample_index(const usb_capture_t *cap)
{
    return cap->total_read * USB_CAPTURE_SAMPLES_PER_WORD;
}

/* A sample index as nanoseconds since capture started. */
static inline uint64_t usb_capture_sample_to_ns(const usb_capture_t *cap,
                                                uint64_t sample_index)
{
    return (sample_index * cap->ns_per_sample_q16) >> 16;
}

/* Gives sample n (0..15) of a packed word. */
static inline uint32_t usb_capture_sample(uint32_t word, uint32_t n)
{
    return (word >> (n * 2u)) & 0x3u;
}

#endif /* USB_CAPTURE_H */
