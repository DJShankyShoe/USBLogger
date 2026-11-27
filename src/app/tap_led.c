/*
 * The status LED, so the tap's state can be seen without a console. Part of USBLogger.c (#included).
 * Slow blink: checking the card. On: ready, drive powered. Fast blink: a problem, drive kept off.
 * Off: session closed and saved.
 */

/* What the LED shows. */
typedef enum {
    LED_CHECKING = 0,   /* slow blink */
    LED_READY,          /* on */
    LED_FAULT,          /* fast blink */
    LED_OFF,            /* off */
} led_state_t;

/* Half a blink period: slow and fast. */
#define LED_SLOW_HALF_US 500000u
#define LED_FAST_HALF_US 100000u

static bool        g_led_ok;        /* the wireless chip started, so the LED can be driven */
static led_state_t g_led_state;     /* what it shows now */
static bool        g_led_lit;       /* the LED's level, as last set */
static uint64_t    g_led_next_us;   /* when a blink next toggles it */

/* Sets the LED's level through the wireless chip. */
static void led_put(bool on)
{
    if (g_led_ok) {
        cyw43_arch_gpio_put(CYW43_WL_GPIO_LED_PIN, on);
    }
    g_led_lit = on;
}

/* Shows a new state at once: a blink starts lit. */
static void led_set(led_state_t s)
{
    g_led_state = s;
    led_put(s != LED_OFF);
    g_led_next_us = time_us_64() + (s == LED_FAULT ? LED_FAST_HALF_US : LED_SLOW_HALF_US);
}

/* Toggles a blinking LED when its half period is up. Cheap enough to call for every record. */
static void led_tick(void)
{
    if (g_led_state != LED_CHECKING && g_led_state != LED_FAULT) {
        return;
    }
    const uint64_t now = time_us_64();
    if (now < g_led_next_us) {
        return;
    }
    led_put(!g_led_lit);
    g_led_next_us = now + (g_led_state == LED_FAULT ? LED_FAST_HALF_US : LED_SLOW_HALF_US);
}
