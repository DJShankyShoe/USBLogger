/*
 * Decides from ADC readings whether the PC side of the tapped cable is powered (rules in
 * vbus_sense.h).
 */

/* memset. */
#include <string.h>

/* The thresholds, the hold and the state this file updates. */
#include "vbus_sense.h"

/* Clears the state to VBUS_UNKNOWN, with no lowest reading yet. */
void vbus_sense_init(vbus_sense_t *v)
{
    memset(v, 0, sizeof(*v));
    v->mv_min = UINT32_MAX;
}

/* Converts a 12-bit ADC reading of the divider into millivolts on the bus. */
uint32_t vbus_mv_from_raw(uint32_t raw)
{
    const uint64_t pin_uv = (uint64_t)raw * VBUS_ADC_REF_MV * 1000u / 4096u;
    return (uint32_t)(pin_uv * (VBUS_DIVIDER_TOP_OHM + VBUS_DIVIDER_BOT_OHM) / VBUS_DIVIDER_BOT_OHM / 1000u);
}

/* Takes one reading and moves the state on; returns true when it changed. */
bool vbus_sense_update(vbus_sense_t *v, uint32_t mv, uint64_t now_us)
{
    v->mv = mv;
    v->readings++;
    if (mv > v->mv_max) {
        v->mv_max = mv;
    }

    if (v->state == VBUS_PRESENT) {
        if (mv < v->mv_min) {
            v->mv_min = mv;
        }
        v->low_run = mv < VBUS_LOST_MV ? v->low_run + 1u : 0u;
        if (v->low_run >= VBUS_LOST_SAMPLES) {
            v->state = VBUS_LOST;
            v->low_run = 0u;
            v->high_since_us = 0u;
            v->losses++;
            return true;
        }
        return false;
    }

    /* UNKNOWN or LOST: present again once it has held over the threshold. */
    if (mv < VBUS_PRESENT_MV) {
        v->high_since_us = 0u;
        return false;
    }
    if (v->high_since_us == 0u) {
        v->high_since_us = now_us | 1u;   /* 0 means "no run" */
        return false;
    }
    if (now_us - v->high_since_us < VBUS_PRESENT_HOLD_US) {
        return false;
    }
    v->state = VBUS_PRESENT;
    v->high_since_us = 0u;
    v->low_run = 0u;
    v->mv_min = mv;
    return true;
}
