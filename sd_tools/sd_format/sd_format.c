/*
 * A separate, one-job firmware: formats the SD card FAT32 after an 'F' typed at its prompt, then mounts it
 * and reports it. The tap's wiring and driver, SPI at 12 MHz; no PIO, DMA or core1.
 *   python tests/sd_run.py --uf2 build/sd_format.uf2 --prompt "Type F" --keys F --until "\[done\]"
 */

/* printf. */
#include <stdio.h>

/* The SDK: stdio, the timer, clocks, SPI. */
#include "pico/stdlib.h"
#include "hardware/clocks.h"
#include "hardware/spi.h"

/* FatFs, its disk layer and the vendored card driver. */
#include "ff.h"        /* before diskio.h: it defines BYTE, UINT, LBA_t */
#include "diskio.h"
#include "tf_card.h"

/* The card's pins on SPI0, as the tap wires them. */
#define SD_PIN_MISO 16u
#define SD_PIN_CS   17u
#define SD_PIN_SCK  18u
#define SD_PIN_MOSI 19u

/* f_mkfs's work buffer: one sector, so every write is a single block (multi-block writes failed on this wiring). */
static BYTE g_work[512u];

/* The driver's own disk calls, which FatFs reaches through the wrappers below (-Wl,--wrap in CMakeLists.txt). */
DRESULT __real_disk_write(BYTE drv, const BYTE *buff, LBA_t sector, UINT count);
DRESULT __real_disk_read(BYTE drv, BYTE *buff, LBA_t sector, UINT count);
DRESULT __real_disk_ioctl(BYTE drv, BYTE cmd, void *buff);

/* Writes, sectors written and failed writes, for the closing line. */
static unsigned long g_writes, g_write_sectors, g_write_fails;

/* Writes through the driver, counting, and retries a failed write with a line saying where. */
DRESULT __wrap_disk_write(BYTE drv, const BYTE *buff, LBA_t sector, UINT count)
{
    DRESULT r = __real_disk_write(drv, buff, sector, count);
    g_writes++;
    g_write_sectors += count;
    /* Re-sent up to four times, as the tap's sd_log does. */
    for (unsigned attempt = 1; r != RES_OK && attempt <= 4u; attempt++) {
        g_write_fails++;
        printf("[disk]  disk_write(LBA %lu, %u sectors) = %d after %lu writes (%lu failed so far); retry %u\n",
               (unsigned long)sector, (unsigned)count, (int)r, g_writes - 1u, g_write_fails, attempt);
        r = __real_disk_write(drv, buff, sector, count);
    }
    return r;
}

/* Reads through the driver, and prints a line if the read failed. */
DRESULT __wrap_disk_read(BYTE drv, BYTE *buff, LBA_t sector, UINT count)
{
    const DRESULT r = __real_disk_read(drv, buff, sector, count);
    if (r != RES_OK) {
        printf("[disk]  disk_read(LBA %lu, %u sectors) = %d\n", (unsigned long)sector, (unsigned)count, (int)r);
    }
    return r;
}

/* Passes a control call to the driver, and prints a line if it failed. */
DRESULT __wrap_disk_ioctl(BYTE drv, BYTE cmd, void *buff)
{
    const DRESULT r = __real_disk_ioctl(drv, cmd, buff);
    if (r != RES_OK) {
        printf("[disk]  disk_ioctl(cmd %u) = %d\n", (unsigned)cmd, (int)r);
    }
    return r;
}

/* Starts the card, shows what is on it, and formats it FAT32 only after an F. */
int main(void)
{
    stdio_init_all();
    while (!stdio_usb_connected()) {
        sleep_ms(50);
    }
    sleep_ms(300);
    printf("\n=== Forensic USB Audit Tap -- SD card format (FAT32) ===\n");
    printf("[note]  The tap is NOT running in this build.\n");

    /* clk_peri at 48 MHz from the USB PLL, as the tap has it (at 150 MHz the card stops initialising). */
    clock_configure(clk_peri, 0, CLOCKS_CLK_PERI_CTRL_AUXSRC_VALUE_CLKSRC_PLL_USB, 48u * MHZ, 48u * MHZ);
    printf("[clock] clk_peri %.1f MHz\n", (double)clock_get_hz(clk_peri) / 1e6);
    pico_fatfs_spi_config_t cfg = {
        spi0, 400u * 1000u, 12u * 1000u * 1000u, SD_PIN_MISO, SD_PIN_CS, SD_PIN_SCK, SD_PIN_MOSI, true,
    };
    if (!pico_fatfs_set_config(&cfg)) {
        printf("[done]  REFUSED: the pins do not map to hardware SPI0.\n");
        while (true) {
            sleep_ms(1000);
        }
    }
    DSTATUS st = STA_NOINIT;
    for (unsigned attempt = 1; attempt <= 5u && (st & STA_NOINIT); attempt++) {
        st = disk_initialize(0);
        printf("[card]  init attempt %u: %s (status 0x%02x)\n", attempt,
               (st & STA_NOINIT) ? "failed" : "OK", (unsigned)st);
        if (st & STA_NOINIT) {
            sleep_ms(200);
        }
    }
    if (st & STA_NOINIT) {
        printf("[done]  the card did not initialise: nothing done.\n");
        while (true) {
            sleep_ms(1000);
        }
    }
    DWORD sectors = 0;
    (void)disk_ioctl(0, GET_SECTOR_COUNT, &sectors);
    printf("[card]  %lu sectors = %.2f GB, SPI %.1f MHz\n", (unsigned long)sectors,
           (double)sectors * 512.0 / 1e9, (double)pico_fatfs_get_clk_fast_freq() / 1e6);
    {
        FATFS fs;
        const FRESULT fr = f_mount(&fs, "", 1);
        printf("[card]  as it is now: %s\n", fr == FR_OK ? (fs.fs_type == FS_EXFAT ? "exFAT" : "FAT")
                                                      : fr == FR_NO_FILESYSTEM ? "no filesystem" : "unreadable");
        f_unmount("");
    }

    printf("Type F to format the card FAT32 -- EVERYTHING ON IT IS LOST. Any other key: stop.\n");
    int c;
    do {
        c = getchar_timeout_us(100000);
    } while (c == PICO_ERROR_TIMEOUT);
    if (c != 'F') {
        printf("[done]  not formatted.\n");
        while (true) {
            sleep_ms(1000);
        }
    }

    /* Two FATs and 32 KB clusters, as Windows formats a 32 GB card. */
    const MKFS_PARM opt = { FM_FAT32, 2, 0, 0, 32768 };
    printf("[fmt]   formatting...\n");
    const uint64_t t0 = time_us_64();
    FRESULT fr = f_mkfs("", &opt, g_work, sizeof(g_work));
    printf("[fmt]   f_mkfs: %s (FatFs %d) in %.1f s\n", fr == FR_OK ? "OK" : "FAILED", (int)fr,
           (double)(time_us_64() - t0) / 1e6);
    if (fr == FR_OK) {
        FATFS fs;
        fr = f_mount(&fs, "", 1);
        DWORD free_clst = 0;
        FATFS *pfs = &fs;
        if (fr == FR_OK && f_getfree("", &free_clst, &pfs) == FR_OK) {
            printf("[fmt]   mounted: %s, %u sectors per cluster, data at LBA %lu, %.2f GB free\n",
                   fs.fs_type == FS_FAT32 ? "FAT32" : "not FAT32?", (unsigned)fs.csize,
                   (unsigned long)fs.database, (double)free_clst * fs.csize * 512.0 / 1e9);
        } else {
            printf("[fmt]   the new filesystem does not mount (FatFs %d)\n", (int)fr);
        }
        f_unmount("");
    }
    printf("[fmt]   %lu writes (%lu sectors), %lu failed and were re-sent\n", g_writes, g_write_sectors,
           g_write_fails);
    printf("[done]  format finished.\n");
    while (true) {
        sleep_ms(1000);
    }
}
