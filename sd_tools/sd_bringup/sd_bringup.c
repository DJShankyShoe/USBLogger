/*
 * SD card bring-up, a separate firmware with the tap not running (no PIO, DMA or core1): probes the lines,
 * finds a sound SPI clock, then writes and reads back a block ([00-a]), times the worst write pause ([00-b])
 * and the bandwidth. At the tap's 384 MHz / 1.30 V; nothing is written until the operator presses 'y'.
 */

/* printf; qsort for the pause percentiles; memcpy. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* The SDK: stdio and timer, clocks, SPI, the flash interface, interrupts, the regulator. */
#include "pico/stdlib.h"
#include "hardware/clocks.h"
#include "hardware/spi.h"
#include "hardware/structs/qmi.h"
#include "hardware/sync.h"
#include "hardware/vreg.h"

/* FatFs's types, its disk layer and the vendored card driver. */
#include "ff.h"        /* BYTE/DWORD/LBA_t for diskio.h */
#include "diskio.h"
#include "tf_card.h"

/* The card's pins: SPI0, clear of the tap's GPIO 10/11, PIO0 and DMA. */
#define SD_PIN_MISO   16u   /* physical pin 21 */
#define SD_PIN_CS     17u   /* physical pin 22 */
#define SD_PIN_SCK    18u   /* physical pin 24 */
#define SD_PIN_MOSI   19u   /* physical pin 25 */

/* The init clock: a card must be started at 400 kHz or less. */
#define SD_CLK_SLOW_HZ   (400u * 1000u)

/* The tap's clock, with its 192 MHz flash timing reference and 144 MHz fallback. */
#define SYS_CLOCK_KHZ           384000
#define SYS_CLOCK_MID_KHZ       192000   /* the flash timing reference */
#define SYS_CLOCK_FALLBACK_KHZ  144000

/* What the measurement covers. */
#define TEST_BASE_LBA     2048u    /* clear of any partition/boot area */
#define TEST_BLOCKS       8192u    /* 4 MB of single-block writes */
#define MULTI_BLOCKS        64u    /* blocks per multi-block call */

/* The pause of each single-block write, and the test blocks. */
static uint32_t g_us[TEST_BLOCKS];        /* one duration per single-block write */
static uint8_t  g_block[512];             /* one block for the single-block tests */
static uint8_t  g_multi[MULTI_BLOCKS * 512u];   /* MULTI_BLOCKS blocks for the bandwidth test */

/* The flash interface's timing at boot and after clock_setup, for [clock]. */
static uint32_t g_qmi_timing_boot;
static uint32_t g_qmi_timing_run;

/* ---- clock ----------------------------------------------------------- */

/* Writes the flash interface's timing register, from SRAM with interrupts off. */
static void __noinline __attribute__((section(".time_critical.sdbringup")))
qmi_set_timing(uint32_t timing)
{
    qmi_hw->m[0].timing = timing;
}

/* Sets 384 MHz at 1.30 V with the flash timing scaled: a copy of USBLogger.c's clock_setup(). */
static void clock_setup(void)
{
    g_qmi_timing_boot = qmi_hw->m[0].timing;
    const uint32_t div = (g_qmi_timing_boot & QMI_M0_TIMING_CLKDIV_BITS) >> QMI_M0_TIMING_CLKDIV_LSB;
    const uint32_t rx  = (g_qmi_timing_boot & QMI_M0_TIMING_RXDELAY_BITS) >> QMI_M0_TIMING_RXDELAY_LSB;
    uint32_t new_div = (div * SYS_CLOCK_KHZ + SYS_CLOCK_MID_KHZ - 1u) / SYS_CLOCK_MID_KHZ;
    uint32_t new_rx  = (rx * SYS_CLOCK_KHZ + SYS_CLOCK_MID_KHZ - 1u) / SYS_CLOCK_MID_KHZ;
    if (new_div > (QMI_M0_TIMING_CLKDIV_BITS >> QMI_M0_TIMING_CLKDIV_LSB)) {
        new_div = QMI_M0_TIMING_CLKDIV_BITS >> QMI_M0_TIMING_CLKDIV_LSB;
    }
    if (new_rx > (QMI_M0_TIMING_RXDELAY_BITS >> QMI_M0_TIMING_RXDELAY_LSB)) {
        new_rx = QMI_M0_TIMING_RXDELAY_BITS >> QMI_M0_TIMING_RXDELAY_LSB;
    }
    const uint32_t slow = (g_qmi_timing_boot & ~(QMI_M0_TIMING_CLKDIV_BITS | QMI_M0_TIMING_RXDELAY_BITS)) |
                          (new_div << QMI_M0_TIMING_CLKDIV_LSB) | (new_rx << QMI_M0_TIMING_RXDELAY_LSB);

    uint32_t irq = save_and_disable_interrupts();
    qmi_set_timing(slow);
    restore_interrupts(irq);
    vreg_set_voltage(VREG_VOLTAGE_1_30);
    busy_wait_us(10000u);

    if (!set_sys_clock_khz(SYS_CLOCK_KHZ, false)) {
        irq = save_and_disable_interrupts();
        qmi_set_timing(g_qmi_timing_boot);
        restore_interrupts(irq);
        vreg_set_voltage(VREG_VOLTAGE_DEFAULT);
        if (!set_sys_clock_khz(SYS_CLOCK_MID_KHZ, false)) {
            set_sys_clock_khz(SYS_CLOCK_FALLBACK_KHZ, true);
        }
    }
    g_qmi_timing_run = qmi_hw->m[0].timing;
}

/* ---- console --------------------------------------------------------- */

/* Waits until a terminal is connected, then a moment more. */
static void wait_for_terminal(void)
{
    while (!stdio_usb_connected()) {
        sleep_ms(50);
    }
    sleep_ms(300);   /* as the tap does: let the terminal settle */
}

/* Blocks until a key is pressed; returns it lower-cased. */
static int wait_key(void)
{
    for (;;) {
        const int c = getchar_timeout_us(500000);
        if (c != PICO_ERROR_TIMEOUT) {
            return (c >= 'A' && c <= 'Z') ? c + ('a' - 'A') : c;
        }
    }
}

/* ---- card set-up ----------------------------------------------------- */

/* Fills a test block with a pattern made from its LBA, so a read of the wrong sector is a mismatch. */
static void fill_block(uint8_t *buf, uint32_t lba)
{
    uint32_t w = lba * 0x9E3779B9u + 0x5BF03635u;
    for (uint32_t i = 0; i < 512u / 4u; i++) {
        w = w * 1664525u + 1013904223u;
        buf[i * 4u + 0u] = (uint8_t)(w);
        buf[i * 4u + 1u] = (uint8_t)(w >> 8);
        buf[i * 4u + 2u] = (uint8_t)(w >> 16);
        buf[i * 4u + 3u] = (uint8_t)(w >> 24);
    }
    buf[0] = 'S'; buf[1] = 'D'; buf[2] = 'T'; buf[3] = 'P';
    buf[4] = (uint8_t)(lba); buf[5] = (uint8_t)(lba >> 8);
    buf[6] = (uint8_t)(lba >> 16); buf[7] = (uint8_t)(lba >> 24);
}

/* Returns the index of the first differing byte, or -1. */
static int32_t first_diff(const uint8_t *a, const uint8_t *b, uint32_t len)
{
    for (uint32_t i = 0; i < len; i++) {
        if (a[i] != b[i]) {
            return (int32_t)i;
        }
    }
    return -1;
}

/* Brings the card up at `clk_fast_hz`; false if the pins are not SPI0's or the card does not start. */
static bool card_init(uint clk_fast_hz, uint32_t *init_ms)
{
    pico_fatfs_spi_config_t cfg = {
        spi0,
        SD_CLK_SLOW_HZ,
        clk_fast_hz,
        SD_PIN_MISO,
        SD_PIN_CS,
        SD_PIN_SCK,
        SD_PIN_MOSI,
        true,            /* internal pull-ups on MISO/MOSI; MISO's is a MUST */
    };

    if (!pico_fatfs_set_config(&cfg)) {
        printf("[spi]  REFUSED: those pins do not map to hardware SPI0, so the driver would fall\n"
               "       back to a PIO SPI -- and PIO0 belongs to the capture. Check the wiring.\n");
        return false;
    }

    const uint64_t t0 = time_us_64();
    const DSTATUS st = disk_initialize(0);
    *init_ms = (uint32_t)((time_us_64() - t0) / 1000u);

    if (st & STA_NOINIT) {
        printf("[card] disk_initialize FAILED (status 0x%02x) after %lu ms\n",
               (unsigned)st, (unsigned long)*init_ms);
        return false;
    }
    return true;
}

/* Writes and reads back `blocks` blocks from `lba`, to decide whether a clock is usable. */
static bool quick_verify(uint32_t lba, uint32_t blocks)
{
    for (uint32_t i = 0; i < blocks; i++) {
        fill_block(g_block, lba + i);
        if (disk_write(0, g_block, lba + i, 1) != RES_OK) {
            return false;
        }
    }
    if (disk_ioctl(0, CTRL_SYNC, NULL) != RES_OK) {
        return false;
    }
    for (uint32_t i = 0; i < blocks; i++) {
        uint8_t got[512];
        if (disk_read(0, got, lba + i, 1) != RES_OK) {
            return false;
        }
        fill_block(g_block, lba + i);
        if (first_diff(g_block, got, 512u) >= 0) {
            return false;
        }
    }
    return true;
}

/* ---- what the pins say ----------------------------------------------- */

/* What holds a line before any SPI: nothing (it follows our pull), or something external. */
typedef enum { PIN_FLOATING, PIN_HELD_LOW, PIN_HELD_HIGH } pin_state_t;

/* Reads a pin with the pull-up, then with the pull-down (after clearing RP2350-E9's latch), and says what holds it. */
static pin_state_t probe_pin(uint pin)
{
    gpio_init(pin);
    gpio_set_dir(pin, GPIO_IN);

    /* Low against the pull-up means something external holds it. */
    gpio_pull_up(pin);
    sleep_ms(2);                     /* far longer than any lead's RC */
    const bool with_pullup = gpio_get(pin);

    /* RP2350-E9 latches a pad high past the pull-down's strength: driving it low first clears the latch. */
    gpio_disable_pulls(pin);
    gpio_put(pin, 0);
    gpio_set_dir(pin, GPIO_OUT);     /* clears the E9 latch */
    sleep_us(50);
    gpio_set_dir(pin, GPIO_IN);
    gpio_pull_down(pin);
    sleep_ms(2);
    const bool with_pulldown = gpio_get(pin);

    gpio_disable_pulls(pin);

    if (with_pullup && !with_pulldown) { return PIN_FLOATING; }
    return with_pullup ? PIN_HELD_HIGH : PIN_HELD_LOW;
}

/* Gives a pin state as the [pins] line prints it. */
static const char *pin_state_name(pin_state_t s)
{
    switch (s) {
    case PIN_FLOATING:  return "floating (nothing driving it)";
    case PIN_HELD_LOW:  return "HELD LOW by something external";
    default:            return "held high externally";
    }
}

/* Two pins wired to nothing, probed as a control: if they do not read floating, the probe is wrong. */
#define SD_CTRL_PIN_A   20u   /* physical pin 26 */
#define SD_CTRL_PIN_B   22u   /* physical pin 29 */

/* Set when a line the Pico drives is held low: driving it would short the pad, so no SPI pin is set up. */
static bool g_driven_short = false;

/* Probes CS, SCK, MOSI, the two controls, then MISO with CS driven high; false if a line the Pico drives is held low. */
static bool probe_pins(void)
{
    /* CS, SCK and MOSI first, as inputs, which is what finds a short. */
    const pin_state_t mosi = probe_pin(SD_PIN_MOSI);
    const pin_state_t sck  = probe_pin(SD_PIN_SCK);
    const pin_state_t cs   = probe_pin(SD_PIN_CS);
    const pin_state_t ctrl_a = probe_pin(SD_CTRL_PIN_A);
    const pin_state_t ctrl_b = probe_pin(SD_CTRL_PIN_B);

    /* MISO last, with CS driven high: a buffered module's DO is enabled by CS and would read low. */
    gpio_init(SD_PIN_CS);
    gpio_put(SD_PIN_CS, 1);
    gpio_set_dir(SD_PIN_CS, GPIO_OUT);
    sleep_ms(2);
    const pin_state_t miso = probe_pin(SD_PIN_MISO);
    gpio_set_dir(SD_PIN_CS, GPIO_IN);

    printf("\n[pins]  control, GPIO%u and GPIO%u, which nothing is wired to: %s, %s\n",
           SD_CTRL_PIN_A, SD_CTRL_PIN_B, pin_state_name(ctrl_a), pin_state_name(ctrl_b));
    if (ctrl_a != PIN_FLOATING || ctrl_b != PIN_FLOATING) {
        printf("[pins]  THE CONTROL DID NOT COME OUT FLOATING, so this probe cannot be trusted and\n"
               "        nothing below is evidence. Either something is wired to those pins too, or\n"
               "        the reading itself is wrong.\n");
    }

    printf("\n[pins]  before any SPI (CS driven high for the MISO reading, so the module is\n"
           "        deselected, as a master leaves it between transactions):\n");
    printf("        MISO GPIO%u (pin 21): %s\n", SD_PIN_MISO, pin_state_name(miso));
    printf("        MOSI GPIO%u (pin 25): %s\n", SD_PIN_MOSI, pin_state_name(mosi));
    printf("        SCK  GPIO%u (pin 24): %s\n", SD_PIN_SCK,  pin_state_name(sck));
    printf("        CS   GPIO%u (pin 22): %s\n", SD_PIN_CS,   pin_state_name(cs));

    if (miso == PIN_HELD_LOW) {
        /* A fault only on a bare breakout: on a buffered module MISO is the 74LVC125's output. */
        printf("[pins]  MISO cannot go high. WHAT THAT MEANS DEPENDS ON THE BOARD:\n"
               "        * BARE BREAKOUT (socket and passives only) -- MISO is a passive line with\n"
               "          a pull-up, nothing drives it but the card, so held low IS a fault and no\n"
               "          SPI clock will fix it. Work down the list below.\n"
               "        * MODULE WITH A BUFFER (a ~14-pin 74LVC125 and a 3-pin regulator) -- MISO\n"
               "          is that buffer's OUTPUT. With an empty socket its input is undriven and\n"
               "          the output may sit low for no bad reason, so THIS READING PROVES NOTHING.\n"
               "          Put the card in and run again; that is the only test that can tell you\n"
               "          anything about this kind of board.\n");

        /* The other three held high by the module's pull-ups means its supply is live. */
        if (mosi == PIN_HELD_HIGH && sck == PIN_HELD_HIGH && cs == PIN_HELD_HIGH) {
            printf("[pins]  The other three are pulled high, which needs a live supply behind the\n"
                   "        module's pull-ups, so the board has power and the fault is the MISO\n"
                   "        path alone.\n");
        } else {
            printf("[pins]  The other three read floating. That is NOT proof of a missing supply --\n"
                   "        plenty of bare breakouts have no pull-ups on CLK, CMD and CS, so they\n"
                   "        float whether or not VCC is there. It only means they say nothing.\n");
        }

        /* Lists what can hold DO low, cheapest check first, and claims none of them. */
        printf("[pins]  A DO line sits at ground only if something ties it there. FIVE things can,\n"
               "        and this run has not told them apart -- work down the list, cheapest first:\n"
               "        1. THE WRONG HOLE. Is that lead in the hole this board labels MISO or DO?\n"
               "           Header orders differ between boards, so count by the silkscreen, not by\n"
               "           position. A lead in a GND hole reads exactly like this.\n"
               "        2. A 5 V MODULE RUN FROM 3V3. If the board carries a regulator (a 3-pin\n"
               "           chip) and a 74LVC125 buffer, its VCC belongs on pin 40, not pin 36: an\n"
               "           AMS1117-3.3 given 3.3 V sags to ~2.3 V, and a browned-out buffer holds\n"
               "           its output LOW -- this exact reading. A header ordered CS SCK MOSI MISO\n"
               "           VCC GND is usually that kind of board. Check for the chips first: 5 V\n"
               "           into a BARE breakout puts 5 V on this pin through its pull-up.\n"
               "        3. The lead touching its neighbour, most often the GND wire beside it.\n"
               "        4. The Pico's own pin: take the lead off pin 21 and run again. Floating\n"
               "           means GPIO%u is fine and the low arrives down the wire.\n"
               "        5. The module or the card. Swap the MISO and CS wires AT THE MODULE END\n"
               "           (signal against signal, which is safe): if the low follows the hole\n"
               "           rather than the wire, it is the board.\n"
               "        A 'held high' found while walking a lead is not a pull-up worth chasing --\n"
               "        on a header with VCC next to MISO, that is just the 3.3 V rail.\n",
               SD_PIN_MISO);
        /* Not fatal: disk_initialize settles it, and the ladder writes nothing. */
        printf("[pins]  Going on to the clock ladder anyway: this reading cannot settle it, and\n"
               "        disk_initialize can. Nothing is written either way.\n");
    }
    if (miso == PIN_FLOATING) {
        printf("[pins]  MISO is floating: nothing is pulling it either way. Either no card is in\n"
               "        the socket, or the module is unpowered, or the MISO lead is not on GPIO%u.\n",
               SD_PIN_MISO);
    }
    if (mosi == PIN_HELD_LOW || sck == PIN_HELD_LOW || cs == PIN_HELD_LOW) {
        g_driven_short = true;
        printf("[pins]  A LINE THE PICO DRIVES IS HELD LOW EXTERNALLY. Driving a pad high into a\n"
               "        grounded node is a short through that pad, so nothing further will touch\n"
               "        the SPI pins this run -- no CMD0, no clock ladder. UNPLUG THAT LEAD.\n");
        return false;
    }
    return true;
}

/* Probes MISO once a second for `seconds`, so the module's header can be mapped by moving the lead. */
static void watch_miso(uint32_t seconds)
{
    printf("\n[watch] MISO, GPIO%u (pin 21), read once a second for %lu seconds.\n"
           "        Move the LOOSE end of that lead along the module's header now, one hole at a\n"
           "        time, resting about four seconds on each, and remember the order you go in.\n"
           "        A hole that reads HELD LOW is a ground. A signal hole reads floating. The DO\n"
           "        hole reading HELD LOW with the card out is a dead board.\n"
           "        DO NOT put it in the module's VCC hole: if that board is fed from 5 V, that\n"
           "        would put 5 V on a 3.3 V input and damage the Pico.\n",
           SD_PIN_MISO, (unsigned long)seconds);

    /* Twenty readings a second, so a loose contact shows as intermittent rather than as a hole. */
    uint32_t unstable = 0;

    for (uint32_t t = 0; t < seconds; t++) {
        const uint64_t start = time_us_64();
        uint32_t n_low = 0, n_high = 0, n_float = 0;

        for (uint32_t i = 0; i < 20u; i++) {
            switch (probe_pin(SD_PIN_MISO)) {
            case PIN_HELD_LOW:  n_low++;   break;
            case PIN_HELD_HIGH: n_high++;  break;
            default:            n_float++; break;
            }
        }

        const bool steady = (n_low >= 19u) || (n_high >= 19u) || (n_float >= 19u);
        if (!steady) { unstable++; }

        printf("[watch] t=%2lus  low %2lu  high %2lu  floating %2lu   %s\n",
               (unsigned long)t, (unsigned long)n_low, (unsigned long)n_high,
               (unsigned long)n_float,
               steady ? (n_low >= 19u ? "steady: a GROUND"
                                      : (n_high >= 19u ? "steady: PULLED UP -- this is the one"
                                                       : "steady: nothing connected"))
                      : "INTERMITTENT -- the contact, not the hole");

        while (time_us_64() - start < 1000000u) {
            sleep_ms(5);
        }
    }

    printf("[watch] done: %lu of %lu seconds were intermittent.\n",
           (unsigned long)unstable, (unsigned long)seconds);
    if (unstable * 4u > seconds) {
        printf("[watch] THAT IS THE PROBLEM. A hole reads one thing steadily; a lead that keeps\n"
               "        making and breaking reads whatever it likes. Until this line is steady for\n"
               "        a whole second, nothing measured through it means anything -- so get the\n"
               "        lead gripping (solder the header if the holes are bare) before reading any\n"
               "        more into which hole is which.\n");
    }
}

/* Sends CMD0 by hand at 400 kHz, without the driver, and prints whatever the card answers. */
static void raw_cmd0_probe(void)
{
    spi_init(spi0, 400u * 1000u);
    spi_set_format(spi0, 8, SPI_CPOL_0, SPI_CPHA_0, SPI_MSB_FIRST);
    gpio_set_function(SD_PIN_SCK,  GPIO_FUNC_SPI);
    gpio_set_function(SD_PIN_MOSI, GPIO_FUNC_SPI);
    gpio_set_function(SD_PIN_MISO, GPIO_FUNC_SPI);
    gpio_pull_up(SD_PIN_MISO);            /* as the driver does: a MUST */
    gpio_init(SD_PIN_CS);
    gpio_set_dir(SD_PIN_CS, GPIO_OUT);
    gpio_put(SD_PIN_CS, 1);

    uint8_t tx, rx;
    uint8_t idle[10];
    for (uint32_t i = 0; i < 10u; i++) {  /* 80 clocks with CS high, as the spec wants */
        tx = 0xFF;
        spi_write_read_blocking(spi0, &tx, &idle[i], 1);
    }

    gpio_put(SD_PIN_CS, 0);
    tx = 0xFF; spi_write_read_blocking(spi0, &tx, &rx, 1);

    static const uint8_t cmd0[6] = { 0x40, 0x00, 0x00, 0x00, 0x00, 0x95 };
    for (uint32_t i = 0; i < 6u; i++) {
        tx = cmd0[i];
        spi_write_read_blocking(spi0, &tx, &rx, 1);
    }

    uint8_t resp[16];
    for (uint32_t i = 0; i < 16u; i++) {
        tx = 0xFF;
        spi_write_read_blocking(spi0, &tx, &resp[i], 1);
    }
    gpio_put(SD_PIN_CS, 1);

    printf("[cmd0]  80 idle clocks read:");
    for (uint32_t i = 0; i < 10u; i++) { printf(" %02x", (unsigned)idle[i]); }
    printf("\n[cmd0]  CMD0 answer:");
    for (uint32_t i = 0; i < 16u; i++) { printf(" %02x", (unsigned)resp[i]); }
    printf("\n");

    bool all_ff = true, all_00 = true;
    int32_t r1_at = -1;
    for (uint32_t i = 0; i < 16u; i++) {
        if (resp[i] != 0xFF) { all_ff = false; }
        if (resp[i] != 0x00) { all_00 = false; }
        if (r1_at < 0 && resp[i] != 0xFF) { r1_at = (int32_t)i; }
    }

    if (all_00) {
        printf("[cmd0]  every byte zero: the line is stuck low, so nothing was ever received.\n");
    } else if (all_ff) {
        printf("[cmd0]  every byte 0xff: the line idles high but the card never answered --\n"
               "        no card in the socket, no power to it, or MOSI/SCK/CS not reaching it.\n");
    } else if (resp[r1_at] == 0x01) {
        printf("[cmd0]  R1 = 0x01 at byte %ld: THE CARD ANSWERED and is in idle state. The card\n"
               "        and the wiring are good; a failure after this is further in.\n", (long)r1_at);
    } else {
        printf("[cmd0]  first non-0xff byte is 0x%02x at byte %ld -- not the 0x01 an idle card\n"
               "        answers CMD0 with. Bit 2 set means illegal command, bit 3 a CRC error;\n"
               "        a value with bit 7 set is not an R1 at all (noise or a half-clocked line).\n",
               (unsigned)resp[r1_at], (long)r1_at);
    }
}

/* ---- reporting ------------------------------------------------------- */

/* Orders two uint32_t for qsort. */
static int cmp_u32(const void *a, const void *b)
{
    const uint32_t x = *(const uint32_t *)a;
    const uint32_t y = *(const uint32_t *)b;
    return (x > y) - (x < y);
}

/* Prints the write pauses: worst and where, mean, median, percentiles and a count per band of milliseconds. */
static void report_pauses(uint32_t n)
{
    static uint32_t sorted[TEST_BLOCKS];
    uint64_t sum = 0;
    uint32_t worst = 0, worst_at = 0;

    for (uint32_t i = 0; i < n; i++) {
        sum += g_us[i];
        if (g_us[i] > worst) { worst = g_us[i]; worst_at = i; }
    }
    memcpy(sorted, g_us, (size_t)n * sizeof(uint32_t));
    qsort(sorted, n, sizeof(uint32_t), cmp_u32);

    printf("\n[00-b] %lu single-block writes at LBA %lu..%lu, each timed with its CTRL_SYNC so the\n"
           "       card's internal busy lands inside the measured window.\n",
           (unsigned long)n, (unsigned long)TEST_BASE_LBA,
           (unsigned long)(TEST_BASE_LBA + n - 1u));
    printf("       mean %.2f ms   median %.2f ms   p99 %.2f ms   p99.9 %.2f ms\n",
           (double)sum / (double)n / 1000.0,
           (double)sorted[n / 2u] / 1000.0,
           (double)sorted[(n * 99u) / 100u] / 1000.0,
           (double)sorted[(n * 999u) / 1000u] / 1000.0);
    printf("       WORST WRITE PAUSE: %.2f ms (write %lu, LBA %lu)  <-- this is the number that\n"
           "       sizes the RAM buffer in front of the card.\n",
           (double)worst / 1000.0, (unsigned long)worst_at,
           (unsigned long)(TEST_BASE_LBA + worst_at));

    static const uint32_t edge_us[] = { 1000u, 2000u, 5000u, 10000u, 20000u,
                                        50000u, 100000u, 250000u };
    static const char *const edge_name[] = { "<1", "1-2", "2-5", "5-10", "10-20",
                                             "20-50", "50-100", "100-250", ">250" };
    uint32_t bucket[9] = { 0 };
    for (uint32_t i = 0; i < n; i++) {
        uint32_t b = 8u;
        for (uint32_t e = 0; e < 8u; e++) {
            if (g_us[i] < edge_us[e]) { b = e; break; }
        }
        bucket[b]++;
    }
    printf("       ms:");
    for (uint32_t b = 0; b < 9u; b++) {
        printf(" %s=%lu", edge_name[b], (unsigned long)bucket[b]);
    }
    printf("\n");

    printf("       the eight worst, in order:");
    for (uint32_t k = 0; k < 8u && k < n; k++) {
        printf(" %.1f", (double)sorted[n - 1u - k] / 1000.0);
    }
    printf(" ms\n");
}

/* ---- the steps ------------------------------------------------------- */

/* Writes one block and reads it back, comparing every byte ([00-a]). */
static void step_00a(void)
{
    printf("\n[00-a] one block written and read back.\n");

    const uint32_t lba = TEST_BASE_LBA;
    fill_block(g_block, lba);

    const uint64_t t0 = time_us_64();
    const DRESULT wr = disk_write(0, g_block, lba, 1);
    const DRESULT sy = disk_ioctl(0, CTRL_SYNC, NULL);
    const uint32_t wus = (uint32_t)(time_us_64() - t0);

    if (wr != RES_OK || sy != RES_OK) {
        printf("       WRITE FAILED (disk_write %d, CTRL_SYNC %d)\n", (int)wr, (int)sy);
        return;
    }

    uint8_t got[512];
    const uint64_t t1 = time_us_64();
    const DRESULT rd = disk_read(0, got, lba, 1);
    const uint32_t rus = (uint32_t)(time_us_64() - t1);
    if (rd != RES_OK) {
        printf("       READ FAILED (disk_read %d)\n", (int)rd);
        return;
    }

    const int32_t diff = first_diff(g_block, got, 512u);
    if (diff >= 0) {
        printf("       MISMATCH at byte %ld: wrote 0x%02x, read 0x%02x. The card is not\n"
               "       returning what it was given -- do not go on to 00-b.\n",
               (long)diff, (unsigned)g_block[diff], (unsigned)got[diff]);
        return;
    }
    printf("       LBA %lu: 512 of 512 bytes identical. write+sync %lu us, read %lu us.\n",
           (unsigned long)lba, (unsigned long)wus, (unsigned long)rus);
}

/* Times TEST_BLOCKS single-block writes, each with its sync, and reports the pauses ([00-b]). */
static void step_00b(void)
{
    printf("\n[00-b] measuring the worst write pause over %lu blocks (%lu KB). This takes a\n"
           "       while and prints nothing until it is done.\n",
           (unsigned long)TEST_BLOCKS, (unsigned long)(TEST_BLOCKS / 2u));

    for (uint32_t i = 0; i < TEST_BLOCKS; i++) {
        const uint32_t lba = TEST_BASE_LBA + i;
        fill_block(g_block, lba);

        const uint64_t t0 = time_us_64();
        const DRESULT wr = disk_write(0, g_block, lba, 1);
        const DRESULT sy = disk_ioctl(0, CTRL_SYNC, NULL);
        g_us[i] = (uint32_t)(time_us_64() - t0);

        if (wr != RES_OK || sy != RES_OK) {
            printf("       FAILED at block %lu (LBA %lu): disk_write %d, CTRL_SYNC %d.\n"
                   "       Reporting what was measured up to there.\n",
                   (unsigned long)i, (unsigned long)lba, (int)wr, (int)sy);
            if (i > 0u) {
                report_pauses(i);
            }
            return;
        }
    }
    report_pauses(TEST_BLOCKS);
}

/* Measures sequential write and read bandwidth in multi-block calls, against the spill path's ~2.2 MB/s. */
static void step_bandwidth(void)
{
    const uint32_t chunks = TEST_BLOCKS / MULTI_BLOCKS;
    uint32_t worst_chunk_us = 0;

    printf("\n[band] sequential bandwidth in %lu-block (%lu KB) calls.\n",
           (unsigned long)MULTI_BLOCKS, (unsigned long)(MULTI_BLOCKS / 2u));

    for (uint32_t b = 0; b < MULTI_BLOCKS; b++) {
        fill_block(&g_multi[b * 512u], TEST_BASE_LBA + b);
    }

    const uint64_t tw = time_us_64();
    for (uint32_t c = 0; c < chunks; c++) {
        const uint32_t lba = TEST_BASE_LBA + c * MULTI_BLOCKS;
        const uint64_t t0 = time_us_64();
        if (disk_write(0, g_multi, lba, MULTI_BLOCKS) != RES_OK ||
            disk_ioctl(0, CTRL_SYNC, NULL) != RES_OK) {
            printf("       WRITE FAILED at chunk %lu (LBA %lu)\n",
                   (unsigned long)c, (unsigned long)lba);
            return;
        }
        const uint32_t us = (uint32_t)(time_us_64() - t0);
        if (us > worst_chunk_us) { worst_chunk_us = us; }
    }
    const uint64_t write_us = time_us_64() - tw;

    const uint64_t tr = time_us_64();
    for (uint32_t c = 0; c < chunks; c++) {
        if (disk_read(0, g_multi, TEST_BASE_LBA + c * MULTI_BLOCKS, MULTI_BLOCKS) != RES_OK) {
            printf("       READ FAILED at chunk %lu\n", (unsigned long)c);
            return;
        }
    }
    const uint64_t read_us = time_us_64() - tr;

    const double bytes = (double)TEST_BLOCKS * 512.0;
    printf("       write %.2f MB/s, read %.2f MB/s; worst single %lu-block call %.2f ms\n",
           bytes / (double)write_us, bytes / (double)read_us,
           (unsigned long)MULTI_BLOCKS, (double)worst_chunk_us / 1000.0);
    printf("       spilling raw capture to the card needs ~2.2 MB/s while a burst lasts: %s\n",
           bytes / (double)write_us >= 2.2 ? "this card reaches it."
                                           : "THIS CARD DOES NOT REACH IT at this clock.");
}

/* ---- read-only clock test -------------------------------------------- */

/* The blocks the clock test reads at each (clk_peri, SPI) pair, compared with reads at 48 / 12 MHz. */
#define RT_LBA     16448u   /* AUDIT.BIN's first block on this card: varied data */
#define RT_BLOCKS  512u     /* 256 KB per pass */
#define RT_PASSES  4u

/* Each block's hash at the reference clocks. */
static uint32_t g_rt_ref[RT_BLOCKS];

/* Gives a block's FNV-1a hash, to compare reads without keeping the blocks. */
static uint32_t block_sum(const uint8_t *b)
{
    uint32_t h = 2166136261u;
    for (uint32_t i = 0; i < 512u; i++) {
        h = (h ^ b[i]) * 16777619u;
    }
    return h;
}

/* Reads the test range once, storing the hashes (`ref`) or counting blocks that differ; false if a read failed. */
static bool rt_pass(bool ref, uint32_t *bad_blocks, uint64_t *us)
{
    bool ok = true;
    const uint64_t t0 = time_us_64();
    for (uint32_t i = 0; i < RT_BLOCKS; i += MULTI_BLOCKS) {
        if (disk_read(0, g_multi, RT_LBA + i, MULTI_BLOCKS) != RES_OK) {
            ok = false;
            *bad_blocks += MULTI_BLOCKS;
            continue;
        }
        for (uint32_t j = 0; j < MULTI_BLOCKS; j++) {
            const uint32_t s = block_sum(g_multi + j * 512u);
            if (ref) {
                g_rt_ref[i + j] = s;
            } else if (s != g_rt_ref[i + j]) {
                (*bad_blocks)++;
            }
        }
    }
    *us += time_us_64() - t0;
    return ok;
}

/* Reads the same blocks at each (clk_peri, SPI) pair and counts the ones that differ from the reference. */
static void read_clock_test(void)
{
    static const struct {
        uint32_t auxsrc;     /* clk_peri source */
        uint32_t div;        /* clk_peri = source / div */
        uint32_t spi_hz;     /* asked of the driver */
        const char *note;
    } combos[] = {
        { CLOCKS_CLK_PERI_CTRL_AUXSRC_VALUE_CLKSRC_PLL_USB, 1u, 12000000u, "reference (the tap's setting)" },
        { CLOCKS_CLK_PERI_CTRL_AUXSRC_VALUE_CLKSRC_PLL_USB, 1u, 24000000u, "control: failed the CSD read" },
        { CLOCKS_CLK_PERI_CTRL_AUXSRC_VALUE_CLK_SYS,        3u, 12800000u, "" },
        { CLOCKS_CLK_PERI_CTRL_AUXSRC_VALUE_CLK_SYS,        3u, 16000000u, "" },
        { CLOCKS_CLK_PERI_CTRL_AUXSRC_VALUE_CLK_SYS,        3u, 21333334u, "" },
        { CLOCKS_CLK_PERI_CTRL_AUXSRC_VALUE_CLK_SYS,        3u, 32000000u, "past the SD SPI limit of 25 MHz" },
        { CLOCKS_CLK_PERI_CTRL_AUXSRC_VALUE_CLKSRC_PLL_USB, 1u, 12000000u, "reference again: the card is still fine" },
    };
    printf("\n[rt]    READ-ONLY clock test: %u blocks from LBA %u, %u passes per setting.\n"
           "        Nothing is written.\n", RT_BLOCKS, RT_LBA, RT_PASSES);
    for (uint32_t c = 0; c < sizeof(combos) / sizeof(combos[0]); c++) {
        const uint32_t src_hz = combos[c].auxsrc == CLOCKS_CLK_PERI_CTRL_AUXSRC_VALUE_CLK_SYS
                                    ? clock_get_hz(clk_sys) : 48000000u;
        clock_configure(clk_peri, 0, combos[c].auxsrc, src_hz, src_hz / combos[c].div);
        uint32_t init_ms = 0;
        const bool up = card_init(combos[c].spi_hz, &init_ms);
        printf("[rt]    clk_peri %.1f MHz, SPI %.2f MHz%s%s: ", (double)clock_get_hz(clk_peri) / 1e6,
               up ? (double)pico_fatfs_get_clk_fast_freq() / 1e6 : (double)combos[c].spi_hz / 1e6,
               combos[c].note[0] ? " -- " : "", combos[c].note);
        if (!up) {
            printf("init FAILED\n");
            continue;
        }
        DWORD sectors = 0;
        const bool csd = disk_ioctl(0, GET_SECTOR_COUNT, &sectors) == RES_OK;
        uint32_t bad = 0;
        uint64_t us = 0;
        bool calls_ok = true;
        for (uint32_t p = 0; p < RT_PASSES; p++) {
            calls_ok &= rt_pass(c == 0u && p == 0u, &bad, &us);
        }
        const double mb = (double)RT_BLOCKS * RT_PASSES * 512.0 / 1e6;
        printf("CSD %s; %lu of %u blocks wrong%s; read %.2f MB/s\n", csd ? "ok" : "FAILED",
               (unsigned long)bad, RT_BLOCKS * RT_PASSES, calls_ok ? "" : " (read calls failed)",
               us ? mb / ((double)us / 1e6) : 0.0);
    }
    clock_configure(clk_peri, 0, CLOCKS_CLK_PERI_CTRL_AUXSRC_VALUE_CLKSRC_PLL_USB, 48000000u, 48000000u);
    printf("[done]  read-only clock test finished; clk_peri back to 48 MHz. Nothing was written.\n");
}

/* ---- main ------------------------------------------------------------ */

/* Prints the [clock] line: clk_sys, the core voltage, the flash timing and clk_peri. */
static void print_clock(void)
{
    const uint32_t d0 = (g_qmi_timing_boot & QMI_M0_TIMING_CLKDIV_BITS) >> QMI_M0_TIMING_CLKDIV_LSB;
    const uint32_t d1 = (g_qmi_timing_run & QMI_M0_TIMING_CLKDIV_BITS) >> QMI_M0_TIMING_CLKDIV_LSB;
    const uint32_t r1 = (g_qmi_timing_run & QMI_M0_TIMING_RXDELAY_BITS) >> QMI_M0_TIMING_RXDELAY_LSB;
    const double hz = (double)clock_get_hz(clk_sys);

    printf("[clock] %.0f MHz, core %.2f V; flash interface CLKDIV %lu -> %lu (flash clock %.0f MHz),"
           " RXDELAY %lu half cycles (%.2f ns)\n",
           hz / 1e6, 0.55 + 0.05 * (double)vreg_get_voltage(),
           (unsigned long)d0, (unsigned long)d1, d1 ? hz / (double)d1 / 1e6 : 0.0,
           (unsigned long)r1, (double)r1 * 1e9 / (2.0 * hz));
    /* The SDK points clk_peri at the USB PLL, so it stays at 48 MHz whatever clk_sys is. */
    printf("[clock] clk_peri %.1f MHz (the SPI block's input clock: the SDK points it at the USB\n"
           "        PLL, so raising clk_sys does not raise it)\n",
           (double)clock_get_hz(clk_peri) / 1e6);
}

/* Sets the tap's clocks, probes the lines, starts the card, and runs the tests after a 'y'. */
int main(void)
{
    clock_setup();
    stdio_init_all();
    wait_for_terminal();

    printf("\n=== Forensic USB Audit Tap -- SD card bring-up ===\n");
    printf("[note]  The tap is NOT running in this build: no PIO, no DMA, no core1, no capture.\n");
    print_clock();
    printf("[spi]   SPI0: CS GPIO%u (pin 22), SCK GPIO%u (pin 24), MOSI GPIO%u (pin 25),"
           " MISO GPIO%u (pin 21)\n", SD_PIN_CS, SD_PIN_SCK, SD_PIN_MOSI, SD_PIN_MISO);

    /* What the lines say before any clock, then the card's answer to one command by hand. */
    const bool pins_ok = probe_pins();
    if (!g_driven_short) {
        raw_cmd0_probe();
    }
    if (!pins_ok) {
        printf("\n[stop]  not going on to the clock ladder: fix the line above first. Nothing was\n"
               "        written to the card.\n");
        /* The watch, for a board whose state is not yet known. */
        printf("\n[menu]  w = watch MISO 45 s;  other = stop\n");
        const int k = wait_key();
        if (k == 'w') {
            watch_miso(45u);
        }
        printf("\n[done]  Nothing was written to any card.\n");
        for (;;) { sleep_ms(1000); }
    }

    /* The clock ladder: everything after runs at the fastest clock the card passes. */
    static const uint sd_clk_hz[] = { 24000000u, 16000000u, 12000000u, 8000000u, 4000000u };
    bool up = false;

    for (uint32_t i = 0; i < sizeof(sd_clk_hz) / sizeof(sd_clk_hz[0]); i++) {
        uint32_t init_ms = 0;
        printf("\n[card]  trying %lu kHz (init always runs at %lu kHz first)...\n",
               (unsigned long)(sd_clk_hz[i] / 1000u), (unsigned long)(SD_CLK_SLOW_HZ / 1000u));
        if (!card_init(sd_clk_hz[i], &init_ms)) {
            continue;
        }
        DWORD sectors = 0, erase_blk = 0;
        const bool have_count = disk_ioctl(0, GET_SECTOR_COUNT, &sectors) == RES_OK;
        const bool have_erase = disk_ioctl(0, GET_BLOCK_SIZE, &erase_blk) == RES_OK;
        printf("[card]  up in %lu ms at %.2f MHz actual (init clock %.0f kHz actual)\n",
               (unsigned long)init_ms, (double)pico_fatfs_get_clk_fast_freq() / 1e6,
               (double)pico_fatfs_get_clk_slow_freq() / 1e3);
        if (have_count) {
            printf("[card]  %lu sectors of 512 bytes = %.2f GB\n",
                   (unsigned long)sectors, (double)sectors * 512.0 / 1e9);
        } else {
            printf("[card]  sector count unavailable (GET_SECTOR_COUNT failed)\n");
        }
        if (have_erase) {
            printf("[card]  erase block %lu sectors (%.1f KB) -- writes that cross one are where\n"
                   "        a long internal pause comes from\n",
                   (unsigned long)erase_blk, (double)erase_blk / 2.0);
        }

        /* Init runs at 400 kHz: the CSD read is the first real transfer at the fast clock. */
        if (!have_count) {
            printf("[card]  REJECTING this speed: the first real transfer at it (the CSD read)\n"
                   "        failed, so the fast clock is not sound here however well the 400 kHz\n"
                   "        handshake went. Stepping down.\n");
            continue;
        }

        up = true;
        break;
    }

    if (!up) {
        /* The watch only when MISO is held low; otherwise the card is simply not answering. */
        if (probe_pin(SD_PIN_MISO) == PIN_HELD_LOW) {
            watch_miso(45u);
        } else {
            printf("\n[card]  No line is held low, so nothing is shorted and the header's order is\n"
                   "        not the puzzle: the card simply did not answer. In order --\n"
                   "        1. IS THE CARD IN THE SOCKET? Push it until it clicks.\n"
                   "        2. Is VCC connected, and on the right pin for this board? 3V3 (pin 36)\n"
                   "           for a bare breakout, VBUS (pin 40) only for one with a regulator.\n"
                   "           A powered board with a card in it usually pulls MISO high; floating\n"
                   "           fits either no card or no supply.\n"
                   "        3. Are MOSI (pin 25), SCK (pin 24) and CS (pin 22) all seated? The card\n"
                   "           cannot answer a command it never received, and those three carry it.\n");
        }
        printf("\n[card]  THE CARD DID NOT COME UP at any clock. Check: VCC on the right pin for\n"
               "        this board (3V3 pin 36 for a bare breakout, VBUS pin 40 for a regulator\n"
               "        module), GND on pin 23, the four SPI pins, and wire length.\n");
        for (;;) { sleep_ms(1000); }
    }

    printf("\n[!]     Everything after this WRITES to the card, destroying sectors %lu..%lu.\n"
           "        Press 'y' to go ahead, 't' for the read-only clock test (writes nothing),\n"
           "        any other key to stop here.\n",
           (unsigned long)TEST_BASE_LBA, (unsigned long)(TEST_BASE_LBA + TEST_BLOCKS - 1u));

    const int key = wait_key();
    if (key == 't') {
        read_clock_test();
        for (;;) { sleep_ms(1000); }
    }
    if (key != 'y') {
        printf("[stop]  nothing was written.\n");
        for (;;) { sleep_ms(1000); }
    }

    /* 32 blocks written and read back first: a pause measured at a failing clock means nothing. */
    if (!quick_verify(TEST_BASE_LBA + TEST_BLOCKS - 32u, 32u)) {
        printf("\n[card]  32-block write/read-back FAILED at %.2f MHz. Lower the clock ladder's\n"
               "        top entry, or shorten the wiring, before measuring anything.\n",
               (double)pico_fatfs_get_clk_fast_freq() / 1e6);
        for (;;) { sleep_ms(1000); }
    }

    step_00a();
    step_00b();
    step_bandwidth();

    printf("\n[done]  Bring-up finished. The worst write pause above is what sizes the\n"
           "        store_fifo_t in front of the card.\n");
    for (;;) { sleep_ms(1000); }
}
