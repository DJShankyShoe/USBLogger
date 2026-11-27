/*
 * Bus events the decoder leaves to core0: repeated ATTACHes folded into one record a second, and a
 * bus stuck at SE1 named on the console. Part of USBLogger.c (#included).
 */

/* How long ATTACHes after a written one are held and counted: a device that never enumerates
 * attaches every few ms. */
#define ATTACH_HOLD_US 1000000u

static uint64_t g_attach_written_us;   /* when the last ATTACH record was written (0: none yet) */
static uint32_t g_attach_held;         /* ATTACHes since then, not written yet */
static uint64_t g_attach_held_ts_ns, g_attach_held_dur_ns;
static uint64_t g_attach_folded;       /* ATTACHes written as part of a counted record */

/* True if the ATTACH was held, to be written with the ones after it. */
static bool attach_hold(const bus_evt_t *e)
{
    const uint64_t now = time_us_64();
    if (g_attach_written_us == 0u || now - g_attach_written_us >= ATTACH_HOLD_US) {
        g_attach_written_us = now;
        return false;
    }
    if (g_attach_held == 0u) {
        g_attach_held_ts_ns  = e->ts_ns;
        g_attach_held_dur_ns = e->duration_ns;
    }
    g_attach_held += e->count != 0u ? e->count : 1u;
    return true;
}

/* Writes the held ATTACHes once their second is up (`force`: now). */
static void attach_flush(bool force)
{
    const uint64_t now = time_us_64();
    if (g_attach_held == 0u || (!force && now - g_attach_written_us < ATTACH_HOLD_US)) {
        return;
    }
    tap_printf("[bus]   ATTACH at %llu ns (%llu us)  x%lu -- attached again and again within a second: the device is"
           " not enumerating (one record for them)\n",
           (unsigned long long)g_attach_held_ts_ns, (unsigned long long)(g_attach_held_dur_ns / 1000u),
           (unsigned long)g_attach_held);
    audit_log_bus_event(&g_log, USB_BUS_EVENT_ATTACH, g_attach_held_ts_ns, g_attach_held_dur_ns, g_attach_held);
    g_attach_folded += g_attach_held;
    g_attach_held = 0u;
    g_attach_written_us = now;
}

/* A report this full of SE1 is a bus held there (both lines high), not a glitch. */
#define SE1_STUCK_FRACTION_PCT 90u
#define SE1_STUCK_REPORTS      10u   /* ~1 s of 100 ms reports */

static uint32_t g_se1_stuck_run;       /* stuck reports in a row */
static bool     g_se1_stuck_warned;    /* the warning has been printed for this episode */
static uint64_t g_se1_stuck_episodes;  /* episodes this boot, for the [bus] line */

/* Warns once when ~1 s of SE1 reports in a row say the bus is held at SE1. */
static void se1_note(usb_bus_event_t ev, const bus_evt_t *e)
{
    if (ev != USB_BUS_EVENT_SE1) {
        if (ev == USB_BUS_EVENT_RESET || ev == USB_BUS_EVENT_ATTACH) {
            g_se1_stuck_run = 0u;   /* the bus is doing something else */
        }
        return;
    }
    const uint64_t samples = (e->duration_ns / 1000u) * (uint64_t)(g_capture.sample_hz / 1e6f);
    const bool stuck = samples != 0u && (uint64_t)e->count * 100u >= samples * SE1_STUCK_FRACTION_PCT;
    if (!stuck) {
        if (g_se1_stuck_warned) {
            tap_printf("[bus]   the bus is no longer stuck at SE1\n");
        }
        g_se1_stuck_run = 0u;
        g_se1_stuck_warned = false;
        return;
    }
    if (++g_se1_stuck_run >= SE1_STUCK_REPORTS && !g_se1_stuck_warned) {
        g_se1_stuck_warned = true;
        g_se1_stuck_episodes++;
        tap_printf("[warn]  the bus has been stuck at SE1 (D+ and D- both high) for ~1 s: not a state any USB device"
               " drives, so nothing can enumerate. Seen with the ADuM3160 after a drive was pulled out:"
               " unplugging the PC side's cable for a few seconds power-cycles it\n");
    }
}

/* Prints the [bus] line: ATTACHes folded and SE1 episodes. */
static void print_bus_notes(void)
{
    tap_printf("[bus]   ATTACH records folded (a device not enumerating): %llu; stuck at SE1: %llu time(s)%s\n",
           (unsigned long long)g_attach_folded, (unsigned long long)g_se1_stuck_episodes,
           g_se1_stuck_warned ? " -- STUCK NOW" : "");
}
