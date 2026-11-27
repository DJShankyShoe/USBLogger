/*
 * Names for PIDs and decode results, and the two USB CRCs: CRC5 over tokens, CRC16 over data.
 */

/* The PID, decode-result and CRC declarations this file implements. */
#include "usb_proto.h"

/* A PID's name, for the console. */
const char *usb_pid_name(usb_pid_t pid)
{
    switch (pid) {
    case USB_PID_OUT:   return "OUT";
    case USB_PID_IN:    return "IN";
    case USB_PID_SOF:   return "SOF";
    case USB_PID_SETUP: return "SETUP";
    case USB_PID_DATA0: return "DATA0";
    case USB_PID_DATA1: return "DATA1";
    case USB_PID_DATA2: return "DATA2";
    case USB_PID_MDATA: return "MDATA";
    case USB_PID_ACK:   return "ACK";
    case USB_PID_NAK:   return "NAK";
    case USB_PID_STALL: return "STALL";
    case USB_PID_NYET:  return "NYET";
    case USB_PID_PRE:   return "PRE/ERR";
    case USB_PID_SPLIT: return "SPLIT";
    case USB_PID_PING:  return "PING";
    default:            return "RSVD";
    }
}

/* A decode result's name, for the console. */
const char *usb_decode_status_name(usb_decode_status_t st)
{
    switch (st) {
    case USB_DEC_OK:             return "ok";
    case USB_DEC_ERR_NO_SYNC:    return "no-sync";
    case USB_DEC_ERR_PID_CHECK:  return "pid-check";
    case USB_DEC_ERR_CRC5:       return "crc5";
    case USB_DEC_ERR_CRC16:      return "crc16";
    case USB_DEC_ERR_BITSTUFF:   return "bit-stuff";
    case USB_DEC_ERR_TRUNCATED:  return "truncated";
    case USB_DEC_ERR_TOO_LONG:   return "too-long";
    case USB_DEC_ERR_SE1:        return "se1";
    default:                     return "?";
    }
}

/* CRC5 (USB 2.0 8.3.5.1): x^5 + x^2 + 1, LSB first, all-ones start and final inversion. */
uint8_t USB_TIME_CRITICAL usb_crc5(uint16_t data, int bits)
{
    uint8_t crc = 0x1F;
    for (int i = 0; i < bits; i++) {
        uint8_t bit = (uint8_t)((data >> i) & 1u);
        if ((crc & 0x01u) ^ bit) {
            crc = (uint8_t)((crc >> 1) ^ 0x14u);
        } else {
            crc = (uint8_t)(crc >> 1);
        }
    }
    return (uint8_t)(crc ^ 0x1Fu);
}

/* CRC16 (USB 2.0 8.3.5.2): x^16 + x^15 + x^2 + 1, bit by bit; it only runs over CBWs, CSWs and
 * control data. */
uint16_t USB_TIME_CRITICAL usb_crc16(const uint8_t *data, size_t len)
{
    uint16_t crc = 0xFFFFu;
    for (size_t i = 0; i < len; i++) {
        crc ^= data[i];
        for (int b = 0; b < 8; b++) {
            crc = (crc & 1u) ? (uint16_t)((crc >> 1) ^ 0xA001u) : (uint16_t)(crc >> 1);
        }
    }
    return (uint16_t)(crc ^ 0xFFFFu);
}
