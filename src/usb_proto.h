/*
 * USB 1.1 protocol definitions and the decoded packet, the hand-off from the decoder to the parser and log.
 * No capture hardware in here: a Phase 2 front-end produces the same usb_packet_t.
 */
#ifndef USB_PROTO_H
#define USB_PROTO_H

/* bool, the fixed-width integers and size_t. */
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

/* Puts a back-end function on the capture core's path in SRAM on the device (the CRCs, the MSC
 * parser). */
#ifndef USB_TIME_CRITICAL
#  if defined(PICO_ON_DEVICE) && PICO_ON_DEVICE
#    define USB_TIME_CRITICAL __attribute__((section(".time_critical.usbtap")))
#  else
#    define USB_TIME_CRITICAL
#  endif
#endif

/* Byte copy for core1 code: memcpy is in flash on this build, and a flash call can stall the
 * capture core. */
static inline void usb_copy_bytes(uint8_t *dst, const uint8_t *src, uint32_t n)
{
    for (uint32_t i = 0; i < n; i++) {
        dst[i] = src[i];
    }
}

/* Clears n bytes at dst, inline, for the same reason as usb_copy_bytes. */
static inline void usb_zero_bytes(uint8_t *dst, uint32_t n)
{
    for (uint32_t i = 0; i < n; i++) {
        dst[i] = 0u;
    }
}

/* Bus speeds this tap can sample; High Speed is only ever reported, never parsed. */
typedef enum {
    USB_SPEED_LOW  = 0,   /* 1.5 Mbps */
    USB_SPEED_FULL = 1,   /* 12 Mbps  */
} usb_speed_t;

/* The bus speed in bits per second: 1.5 M for Low Speed, 12 M for Full Speed. */
static inline uint32_t usb_speed_bitrate(usb_speed_t s)
{
    return (s == USB_SPEED_LOW) ? 1500000u : 12000000u;
}

/* The bus speed as the console prints it: "LS" or "FS". */
static inline const char *usb_speed_name(usb_speed_t s)
{
    return (s == USB_SPEED_LOW) ? "LS" : "FS";
}

/* Packet IDs (USB 2.0 table 8-1), as the low nibble; on the wire the PID byte is {~PID, PID}. */
typedef enum {
    USB_PID_OUT       = 0x1,
    USB_PID_IN        = 0x9,
    USB_PID_SOF       = 0x5,
    USB_PID_SETUP     = 0xD,
    USB_PID_DATA0     = 0x3,
    USB_PID_DATA1     = 0xB,
    USB_PID_DATA2     = 0x7,  /* HS only -- flagged, not parsed */
    USB_PID_MDATA     = 0xF,  /* HS only */
    USB_PID_ACK       = 0x2,
    USB_PID_NAK       = 0xA,
    USB_PID_STALL     = 0xE,
    USB_PID_NYET      = 0x6,  /* HS only */
    USB_PID_PRE       = 0xC,  /* also ERR in HS */
    USB_PID_SPLIT     = 0x8,  /* HS hub only */
    USB_PID_PING      = 0x4,  /* HS only */
    USB_PID_RESERVED  = 0x0,
} usb_pid_t;

/* What a packet is, from its PID's low two bits: token, data, handshake or special. */
typedef enum {
    USB_PKT_TYPE_UNKNOWN = 0,
    USB_PKT_TYPE_TOKEN,
    USB_PKT_TYPE_DATA,
    USB_PKT_TYPE_HANDSHAKE,
    USB_PKT_TYPE_SPECIAL,
} usb_pkt_type_t;

/* Which of the four packet types a PID belongs to. */
static inline usb_pkt_type_t usb_pid_type(usb_pid_t pid)
{
    switch (pid & 0x3) {
    case 0x1: return USB_PKT_TYPE_TOKEN;
    case 0x3: return USB_PKT_TYPE_DATA;
    case 0x2: return USB_PKT_TYPE_HANDSHAKE;
    default:  return USB_PKT_TYPE_SPECIAL;
    }
}

/* A PID's name, for the console ("OUT", "DATA0", "ACK", ...). */
const char *usb_pid_name(usb_pid_t pid);

/* Why a decode attempt failed; USB_DEC_OK means the packet is trustworthy. */
typedef enum {
    USB_DEC_OK = 0,
    USB_DEC_ERR_NO_SYNC,      /* SYNC field was not KJKJKJKK */
    USB_DEC_ERR_PID_CHECK,    /* PID check nibble mismatch */
    USB_DEC_ERR_CRC5,
    USB_DEC_ERR_CRC16,
    USB_DEC_ERR_BITSTUFF,     /* >6 consecutive 1s, or bad stuffed bit */
    USB_DEC_ERR_TRUNCATED,    /* EOP before a complete packet */
    USB_DEC_ERR_TOO_LONG,     /* payload exceeded the capture buffer */
    USB_DEC_ERR_SE1,          /* illegal single-ended-one on the bus */
} usb_decode_status_t;

/* A decode result's name, for the console ("ok", "crc16", ...). */
const char *usb_decode_status_name(usb_decode_status_t st);

/* Largest payload buffered: bulk and control carry 64 bytes, 1024 covers a non-compliant packet. */
#define USB_MAX_PAYLOAD 1024

/* One decoded packet: what the parser takes, never raw samples. */
typedef struct {
    uint64_t            timestamp_ns;  /* start-of-packet, capture-clock derived */
    usb_decode_status_t status;
    usb_pid_t           pid;
    usb_pkt_type_t      type;

    /* Token fields (type TOKEN, or SOF). */
    uint8_t  addr;        /* device address 0..127 */
    uint8_t  endpoint;    /* endpoint 0..15 */
    uint16_t frame;       /* SOF frame number 0..2047 */

    /* Data fields (type DATA). */
    uint16_t payload_len;
    uint16_t crc16;
    bool     crc_ok;

    uint16_t bit_count;   /* NRZI-decoded bits consumed, for diagnostics */

    /* Where the packet sat in the sample stream (absolute index and length), for core1's metadata
     * copy. */
    uint64_t first_sample;
    uint32_t samples;
    uint8_t  payload[USB_MAX_PAYLOAD];
} usb_packet_t;

/* The CRC5 of a token's `bits` low bits of `data`, to compare with the wire value (USB 2.0 8.3.5). */
uint8_t  usb_crc5(uint16_t data, int bits);
/* The CRC16 of a data payload. */
uint16_t usb_crc16(const uint8_t *data, size_t len);

#endif /* USB_PROTO_H */
