/*
 * The PC side's power: VBUS read on GPIO 26 through a 10k/15k divider, recorded, and acted on.
 * When it goes: drive off, HOST_POWER GONE, the session closed as at `q`; when it comes back, a reboot.
 * Part of USBLogger.c (#included).
 */

#define VBUS_ADC_GPIO 26u    /* pin 31, the divider's middle */
#define VBUS_ADC_INPUT 0u    /* ADC0 is GPIO 26 */
#define VBUS_READ_US  250u   /* one reading every 250 us */

static vbus_sense_t g_vbus;           /* the present / gone decision */
static uint64_t     g_vbus_next_us;   /* when the next reading is due */
static bool         g_host_gone;      /* the session ended because the PC side's VBUS went */

/* Sets GPIO 26 up as an analogue input and starts the decision. */
static void vbus_setup(void)
{
    adc_init();
    adc_gpio_init(VBUS_ADC_GPIO);     /* digital input off: the pad is analogue only */
    adc_select_input(VBUS_ADC_INPUT);
    vbus_sense_init(&g_vbus);
}

/* Reads the ADC once and gives the bus voltage in millivolts. */
static uint32_t vbus_read_mv(void)
{
    return vbus_mv_from_raw(adc_read());
}

/* Reads VBUS when a reading is due; a loss ends the main loop, and the shutdown after it closes the
 * session. */
static void vbus_tick(void)
{
    const uint64_t now = time_us_64();
    if (now < g_vbus_next_us) {
        return;
    }
    g_vbus_next_us = now + VBUS_READ_US;
    if (!vbus_sense_update(&g_vbus, vbus_read_mv(), now)) {
        return;
    }
    const uint64_t ts = (now - g_capture.start_us) * 1000u;
    if (g_vbus.state == VBUS_PRESENT) {
        audit_log_host_power(&g_log, ts, true, g_vbus.mv, 0u);
        tap_printf("[vbus]  the PC side's VBUS is present: %.2f V\n", (double)g_vbus.mv / 1000.0);
        return;
    }
    if (g_drive_power) {
        drive_power(false, AUDIT_POWER_HOST_GONE);   /* first: nothing else is as urgent */
    }
    audit_log_host_power(&g_log, ts, false, g_vbus.mv, g_vbus.mv_min);
    tap_printf("[vbus]  the PC side's VBUS went (%.2f V, lowest while present %.2f V): drive off, the session"
           " ends\n", (double)g_vbus.mv / 1000.0, (double)g_vbus.mv_min / 1000.0);
    g_host_gone = true;
    g_running   = false;
}

/* Prints the [vbus] line: the state, the voltages and the readings. */
static void print_vbus_stats(void)
{
    tap_printf("[vbus]  PC side %s: %.2f V now, lowest while present %.2f V, highest %.2f V; readings %llu,"
           " losses %lu\n",
           g_vbus.state == VBUS_PRESENT ? "present" : g_vbus.state == VBUS_LOST ? "GONE"
                                                     : "not seen yet (is the divider on GPIO 26 wired?)",
           (double)g_vbus.mv / 1000.0,
           g_vbus.mv_min == UINT32_MAX ? 0.0 : (double)g_vbus.mv_min / 1000.0,
           (double)g_vbus.mv_max / 1000.0, (unsigned long long)g_vbus.readings,
           (unsigned long)g_vbus.losses);
}

/* Waits for the PC side's VBUS to come back, then reboots into a new session. */
static void vbus_wait_and_reboot(void)
{
    tap_printf("[vbus]  session closed; waiting for the PC side's VBUS to come back (then a reboot: a new"
           " session, its checks first)\n");
    for (;;) {
        const uint64_t now = time_us_64();
        if (vbus_sense_update(&g_vbus, vbus_read_mv(), now) && g_vbus.state == VBUS_PRESENT) {
            tap_printf("[vbus]  the PC side's VBUS is back (%.2f V): rebooting\n", (double)g_vbus.mv / 1000.0);
            sleep_ms(100);   /* the line above reaches the console */
            watchdog_reboot(0, 0, 0);
            for (;;) {
                tight_loop_contents();
            }
        }
        sleep_us(VBUS_READ_US);
    }
}
