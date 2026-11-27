/*
 * Whether the PC side of the tapped cable is powered, from its VBUS through a 10k/15k divider to an ADC.
 * Present after VBUS_PRESENT_HOLD_US over VBUS_PRESENT_MV; lost after VBUS_LOST_SAMPLES readings in a
 * row under VBUS_LOST_MV. No SDK: the caller reads the ADC.
 */
#ifndef VBUS_SENSE_H
#define VBUS_SENSE_H

/* bool and the fixed-width integers. */
#include <stdbool.h>
#include <stdint.h>

#define VBUS_ADC_REF_MV       3300u   /* the ADC's reference: the 3V3 rail */
#define VBUS_DIVIDER_TOP_OHM  10000u  /* from the bus to the pin */
#define VBUS_DIVIDER_BOT_OHM  15000u  /* from the pin to ground */

#define VBUS_PRESENT_MV       4000u   /* present over this (USB promises 4.4 V or more at a device) */
#define VBUS_LOST_MV          3600u   /* gone under this (the tap side feeds ~3 V back with the PC unplugged) */
#define VBUS_PRESENT_HOLD_US  100000u /* how long it must stay over VBUS_PRESENT_MV */
#define VBUS_LOST_SAMPLES     4u      /* readings in a row under VBUS_LOST_MV */

/* What the reading says about the PC side. */
typedef enum {
    VBUS_UNKNOWN = 0,   /* not yet seen present (or the divider is not wired) */
    VBUS_PRESENT,
    VBUS_LOST,
} vbus_state_t;

/* The decision's state: the last reading, the extremes, and the runs being counted. */
typedef struct {
    vbus_state_t state;
    uint32_t     mv;            /* the last reading */
    uint32_t     mv_min;        /* the lowest reading while present */
    uint32_t     mv_max;        /* the highest reading since init */
    uint64_t     high_since_us; /* first of the current run of readings over VBUS_PRESENT_MV (0: none) */
    uint32_t     low_run;       /* readings in a row under VBUS_LOST_MV, while present */
    uint32_t     losses;        /* PRESENT -> LOST */
    uint64_t     readings;
} vbus_sense_t;

/* Starts the decision at VBUS_UNKNOWN. */
void vbus_sense_init(vbus_sense_t *v);

/* The bus voltage for a 12-bit ADC reading of the divider. */
uint32_t vbus_mv_from_raw(uint32_t raw);

/* One reading (mV on the bus) at `now_us`; true when the state changed. */
bool vbus_sense_update(vbus_sense_t *v, uint32_t mv, uint64_t now_us);

#endif /* VBUS_SENSE_H */
