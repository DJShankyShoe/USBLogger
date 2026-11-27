/*
 * core0's decoder for metadata transfers: usb_decode.c compiled again, never skipping file data, with
 * its public functions renamed meta_* so it links beside core1's.
 */

/* No profiling in this copy, and no file data skipped. */
#undef  USB_PROFILE
#define USB_PROFILE 0
#undef  USB_PROFILE_DETAIL
#define USB_PROFILE_DETAIL 0
#define USB_DECODE_NO_SKIP 1

/* The public functions renamed, so this copy links beside core1's. */
#define usb_decoder_init         meta_usb_decoder_init
#define usb_decode_run           meta_usb_decode_run
#define usb_decode_flush_events  meta_usb_decode_flush_events
#define usb_decode_finish        meta_usb_decode_finish
#define usb_bus_event_name       meta_usb_bus_event_name
#define usb_decoder_print_stats  meta_usb_decoder_print_stats
#define usb_decoder_print_recent meta_usb_decoder_print_recent

/* CRC16 timed in this build only, to split core0's decode cost; only the decoder's calls are
 * renamed. */
#include "../usb_proto.h"
#include <stddef.h>
uint16_t meta_crc16_timed(const uint8_t *data, size_t len);   /* defined below */
#define usb_crc16 meta_crc16_timed                            /* the decoder's CRC16 calls, timed */

/* The decoder itself, built with the settings above. */
#include "../decode/usb_decode.c"

#undef usb_crc16
uint64_t meta_crc16_cyc;     /* core0 cycles inside the CRC16 */
uint64_t meta_crc16_bytes;   /* payload bytes checked */

/* A byte-at-a-time CRC16 table for core0 (the bitwise one costs ~51 cycles a byte), built from the
 * polynomial. */
static uint16_t crc16_table[256];

/* Fills the table from usb_crc16's polynomial (0xA001, reflected), once at boot. */
void meta_crc16_init(void)
{
    for (uint32_t i = 0; i < 256u; i++) {
        uint16_t crc = (uint16_t)i;
        for (int b = 0; b < 8; b++) {
            crc = (crc & 1u) ? (uint16_t)((crc >> 1) ^ 0xA001u) : (uint16_t)(crc >> 1);
        }
        crc16_table[i] = crc;
    }
}

/* Computes a packet's CRC16 a byte at a time from the table. */
uint16_t __not_in_flash_func(meta_crc16)(const uint8_t *data, size_t len)
{
    uint16_t crc = 0xFFFFu;
    for (size_t i = 0; i < len; i++) {
        crc = (uint16_t)((crc >> 8) ^ crc16_table[(crc ^ data[i]) & 0xFFu]);
    }
    return (uint16_t)(crc ^ 0xFFFFu);
}

/* Computes the CRC16 and adds the cycles and bytes to the [core0] counters. */
uint16_t __not_in_flash_func(meta_crc16_timed)(const uint8_t *data, size_t len)
{
    const uint32_t t0 = usb_cycles();
    const uint16_t crc = meta_crc16(data, len);
    meta_crc16_cyc   += (uint32_t)(usb_cycles() - t0);
    meta_crc16_bytes += len;
    return crc;
}
