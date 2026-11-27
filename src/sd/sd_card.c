/*
 * The SD card on SPI0: started, the log's parts found or created with FatFs at boot, then a one-block
 * device for sd_log.
 */

/* va_list for fail(), vsnprintf, memset. */
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

/* The SDK: GPIO, the timer and the SPI block. */
#include "pico/stdlib.h"
#include "hardware/spi.h"

/* FatFs and the vendored card driver (third_party/pico_fatfs). */
#include "ff.h"        /* before diskio.h: it defines BYTE, UINT, LBA_t */
#include "diskio.h"
#include "tf_card.h"

/* What this file defines. */
#include "sd_card.h"

/* The card's pins (SPI0) and the start-up clock. */
#define SD_PIN_MISO 16u   /* physical pin 21 */
#define SD_PIN_CS   17u   /* physical pin 22 */
#define SD_PIN_SCK  18u   /* physical pin 24 */
#define SD_PIN_MOSI 19u   /* physical pin 25 */
#define SD_INIT_HZ  (400u * 1000u)   /* a card is initialised at <= 400 kHz */
#define SD_INIT_TRIES 5u  /* start-ups tried before giving up */

/* Deselects the card (CS high), so a stray SCK edge at boot cannot reach it. */
void sd_card_park(void)
{
    gpio_init(SD_PIN_CS);
    gpio_put(SD_PIN_CS, 1);
    gpio_set_dir(SD_PIN_CS, GPIO_OUT);
}

/* Clocks out any transfer a reboot cut off (the card stays powered through it), then gives a
 * start-up's 80 clocks. */
static void finish_any_transfer(void)
{
    sd_card_park();   /* deselected before SCK is touched (see sd_card_park) */
    spi_init(spi0, SD_INIT_HZ);
    gpio_set_function(SD_PIN_SCK, GPIO_FUNC_SPI);
    gpio_set_function(SD_PIN_MOSI, GPIO_FUNC_SPI);
    gpio_set_function(SD_PIN_MISO, GPIO_FUNC_SPI);
    gpio_pull_up(SD_PIN_MISO);
    const uint8_t ff = 0xFF;
    uint8_t in = 0;
    gpio_put(SD_PIN_CS, 0);
    for (uint32_t i = 0; i < 1100u; i++) {   /* two blocks and their CRCs, at 400 kHz ~22 ms */
        spi_write_read_blocking(spi0, &ff, &in, 1);
    }
    const uint64_t t0 = time_us_64();
    do {
        spi_write_read_blocking(spi0, &ff, &in, 1);
    } while (in != 0xFF && time_us_64() - t0 < 500000u);
    gpio_put(SD_PIN_CS, 1);
    for (uint32_t i = 0; i < 10u; i++) {
        spi_write_read_blocking(spi0, &ff, &in, 1);
    }
}

/* ---- the one-block device sd_log writes through ---------------------- */

/* Reads one 512-byte block from the card. */
static bool dev_read(void *ctx, uint32_t lba, uint8_t *buf)
{
    (void)ctx;
    return disk_read(0, buf, lba, 1) == RES_OK;
}

/* Writes one 512-byte block to the card, and times it for the [sd] line. */
static bool dev_write(void *ctx, uint32_t lba, const uint8_t *buf)
{
    sd_card_info_t *const info = ctx;
    const uint64_t t0 = time_us_64();
    const bool ok = disk_write(0, buf, lba, 1) == RES_OK;
    const uint64_t us = time_us_64() - t0;
    info->write_us_total += us;
    if (us > info->write_us_max) {
        info->write_us_max = us;
    }
    return ok;
}

/* When a busy period began (0: idle), to time the card's longest busy spell. */
static uint64_t g_busy_since_us;

/* Asks the card whether it is idle (~2 us, never waits): a busy card holds DO low. Counts and times
 * the busy ones. */
static bool dev_ready(void *ctx)
{
    sd_card_info_t *const info = ctx;
    uint8_t b = 0xFFu;
    gpio_put(SD_PIN_CS, 0);
    spi_write_read_blocking(spi0, &b, &b, 1);
    gpio_put(SD_PIN_CS, 1);
    const uint8_t release = 0xFFu;
    spi_write_blocking(spi0, &release, 1);   /* as the driver's deselect: lets DO go */

    const uint64_t now = time_us_64();
    if (b == 0xFFu) {
        if (g_busy_since_us != 0u) {
            if (now - g_busy_since_us > info->busy_us_max) {
                info->busy_us_max = now - g_busy_since_us;
            }
            g_busy_since_us = 0u;
        }
        return true;
    }
    if (g_busy_since_us == 0u) {
        g_busy_since_us = now;
    }
    info->busy_probes++;
    return false;
}

/* Waits until the card has finished what it was given. */
static bool dev_sync(void *ctx)
{
    (void)ctx;
    return disk_ioctl(0, CTRL_SYNC, NULL) == RES_OK;
}

/* ---- opening --------------------------------------------------------- */

/* Records why the card cannot be used, turns the card log off, and returns false. */
static bool fail(sd_card_info_t *info, sd_log_t *log, uint64_t t0, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(info->why, sizeof(info->why), fmt, ap);
    va_end(ap);
    f_unmount("");   /* harmless when nothing is mounted */
    info->ok = false;
    info->open_ms = (uint32_t)((time_us_64() - t0) / 1000u);
    sd_log_set_off(log);
    return false;
}

/* Reads card_password.txt into `info`, overwrites its bytes with zeros and deletes it (reuses the
 * caller's FIL). */
static void take_card_password_file(sd_card_info_t *info, FIL *f)
{
    static const uint8_t zeros[64];
    if (f_open(f, SD_CARD_PASSWORD_FILE, FA_READ | FA_WRITE) != FR_OK) {
        if (f_stat(SD_CARD_PASSWORD_FILE, NULL) == FR_OK) {
            info->password_found = true;   /* there, but not writable (read-only): left, and so never used */
        }
        return;
    }
    info->password_found = true;
    const FSIZE_t size = f_size(f);
    UINT n = 0;
    if (size <= SD_CARD_PASSWORD_MAX && f_read(f, info->password, (UINT)size, &n) == FR_OK && n == size) {
        info->password_len = (uint32_t)n;
    }
    bool wiped = f_lseek(f, 0) == FR_OK;
    const FSIZE_t wipe = size < SD_CARD_PASSWORD_MAX ? size : SD_CARD_PASSWORD_MAX;
    for (FSIZE_t done = 0; wiped && done < wipe; done += n) {
        const UINT want = (UINT)(wipe - done < sizeof(zeros) ? wipe - done : sizeof(zeros));
        wiped = f_write(f, zeros, want, &n) == FR_OK && n == want;
    }
    wiped = f_close(f) == FR_OK && wiped;   /* the zeros reach the card before the delete */
    info->password_removed = f_unlink(SD_CARD_PASSWORD_FILE) == FR_OK && wiped;
}

/* Names part k: AUDIT.BIN, then AUDIT001.BIN on. */
static void part_name(char name[16], uint32_t k)
{
    if (k == 0u) {
        snprintf(name, 16, "%s", SD_LOG_FILE);
    } else {
        snprintf(name, 16, "AUDIT%03lu.BIN", (unsigned long)k);
    }
}

/* Finds an open part's first LBA; false unless it is `blocks` long and contiguous. */
static bool part_place(const FATFS *fs, FIL *fil, uint32_t blocks, uint32_t *lba)
{
    const bool contiguous = fs->fs_type != FS_EXFAT || (fil->obj.stat & 2u) != 0u;   /* exFAT records it */
    if (fil->obj.sclust < 2u || (uint64_t)f_size(fil) != (uint64_t)blocks * SD_LOG_BLOCK_BYTES || !contiguous) {
        return false;
    }
    *lba = (uint32_t)(fs->database + (LBA_t)(fil->obj.sclust - 2u) * fs->csize);
    return true;
}

/* Adds part `log->parts` as a new file: allocated contiguously, its header written before its entry is
 * committed. */
static void grow(sd_card_info_t *info, sd_log_t *log, FATFS *fs, FIL *fil, const sd_dev_t *dev)
{
    char name[16];
    part_name(name, log->parts);
    if (f_open(fil, name, FA_READ | FA_WRITE | FA_CREATE_NEW) != FR_OK) {
        info->grow_why = "a new part could not be created";
        return;
    }
    uint32_t lba = 0;
    const FRESULT fr = f_expand(fil, (FSIZE_t)info->blocks * SD_LOG_BLOCK_BYTES, 1);
    const bool headed = fr == FR_OK && part_place(fs, fil, info->blocks, &lba) &&
                        sd_log_create_part(dev, log->file_id, log->parts, lba, info->blocks);
    if (f_close(fil) != FR_OK || !headed) {
        (void)f_unlink(name);
        info->grow_why = fr == FR_DENIED ? "no contiguous 256 MB left on the card" : "allocating a new part failed";
        return;
    }
    if (sd_log_add_part(log, lba) != SD_ATTACH_OK) {
        info->grow_why = "the new part did not read back";
        return;
    }
    info->grew = true;
    info->parts = log->parts;
}

/* Starts the card, mounts it, finds or creates the log's parts and opens the log in them. */
bool sd_card_open(sd_card_info_t *info, sd_log_t *log, uint64_t new_file_id)
{
    memset(info, 0, sizeof(*info));
    const uint64_t t0 = time_us_64();

    pico_fatfs_spi_config_t cfg = {
        spi0, SD_INIT_HZ, SD_SPI_HZ, SD_PIN_MISO, SD_PIN_CS, SD_PIN_SCK, SD_PIN_MOSI,
        true,   /* pull-ups on MISO/MOSI */
    };
    if (!pico_fatfs_set_config(&cfg)) {
        /* It would fall back to a PIO SPI, and PIO0 belongs to the capture. */
        return fail(info, log, t0, "pins do not map to hardware SPI0 (the driver wanted a PIO SPI): not used");
    }

    /* FatFs is used only here: its objects live on this stack frame and the volume is unmounted
     * before returning. */
    FATFS fs;
    FIL   fil;
    FRESULT fr;
    do {
        finish_any_transfer();
        info->init_tries++;
        fr = f_mount(&fs, "", 1);
    } while ((fr == FR_NOT_READY || fr == FR_DISK_ERR) && info->init_tries < SD_INIT_TRIES);
    if (fr == FR_NOT_READY || fr == FR_DISK_ERR) {
        return fail(info, log, t0, "no card answered (FatFs %d): not inserted, not powered, or wiring", (int)fr);
    }
    if (fr == FR_NO_FILESYSTEM) {
        f_unmount("");
        return fail(info, log, t0, "the card has no FAT32 or exFAT filesystem: format it on a PC"
                    " (the tap never formats a card)");
    }
    if (fr != FR_OK) {
        f_unmount("");
        return fail(info, log, t0, "mount failed (FatFs %d)", (int)fr);
    }
    info->spi_hz = pico_fatfs_get_clk_fast_freq();
    info->exfat  = fs.fs_type == FS_EXFAT;
    take_card_password_file(info, &fil);
    {
        DWORD n = 0;
        if (disk_ioctl(0, GET_SECTOR_COUNT, &n) == RES_OK) {
            info->sectors = (uint32_t)n;
        }
    }

    fr = f_open(&fil, SD_LOG_FILE, FA_READ | FA_WRITE | FA_OPEN_ALWAYS);
    if (fr != FR_OK) {
        f_unmount("");
        return fail(info, log, t0, "cannot open or create " SD_LOG_FILE " (FatFs %d)", (int)fr);
    }
    if (f_size(&fil) == 0u) {
        /* Contiguous, so the session can write it by LBA with no FAT updates. */
        fr = f_expand(&fil, SD_LOG_FILE_BYTES, 1);
        if (fr != FR_OK) {
            f_close(&fil);
            f_unmount("");
            return fail(info, log, t0, fr == FR_DENIED
                        ? "no contiguous %u MB free on the card for " SD_LOG_FILE
                        : "allocating %u MB for " SD_LOG_FILE " failed", SD_LOG_FILE_BYTES >> 20);
        }
        info->created = true;
    }
    const uint64_t size = (uint64_t)f_size(&fil);
    if (size % SD_LOG_BLOCK_BYTES != 0u || size / SD_LOG_BLOCK_BYTES > UINT32_MAX ||
        !part_place(&fs, &fil, (uint32_t)(size / SD_LOG_BLOCK_BYTES), &info->first_lba)) {
        f_close(&fil);
        f_unmount("");
        return fail(info, log, t0, SD_LOG_FILE " exists but is not a contiguous whole number of blocks:"
                    " not the tap's file, left untouched");
    }
    info->blocks    = (uint32_t)(size / SD_LOG_BLOCK_BYTES);

    const sd_dev_t dev = { dev_read, dev_write, dev_ready, dev_sync, info };
    /* The header goes down before the directory entry is committed: a power cut leaves no file
     * without a header. */
    if (info->created && !sd_log_create(&dev, new_file_id, info->first_lba, info->blocks)) {
        f_close(&fil);
        f_unmount("");
        return fail(info, log, t0, "writing the header of a new " SD_LOG_FILE " failed");
    }
    fr = f_close(&fil);
    if (fr != FR_OK) {
        return fail(info, log, t0, "closing " SD_LOG_FILE " failed (FatFs %d)", (int)fr);
    }

    switch (sd_log_attach(log, &dev, info->first_lba, info->blocks)) {
    case SD_ATTACH_OK:
        break;
    case SD_ATTACH_READ_ERROR:
        return fail(info, log, t0, "reading " SD_LOG_FILE " back failed");
    case SD_ATTACH_NOT_OURS:
        return fail(info, log, t0, SD_LOG_FILE " exists but its first block is not the tap's header (or is"
                    " damaged): left untouched");
    case SD_ATTACH_TOO_SMALL:
        return fail(info, log, t0, SD_LOG_FILE " is too small to hold a log");
    }

    /* The later parts, in order; one left empty by a power cut while it was being made is deleted. */
    char name[16];
    for (uint32_t k = 1; k < SD_LOG_MAX_PARTS; k++) {
        part_name(name, k);
        fr = f_open(&fil, name, FA_READ);
        if (fr == FR_NO_FILE) {
            break;
        }
        if (fr != FR_OK) {
            return fail(info, log, t0, "cannot open %s (FatFs %d)", name, (int)fr);
        }
        uint32_t lba = 0;
        const bool empty = f_size(&fil) == 0u;
        const bool placed = part_place(&fs, &fil, info->blocks, &lba);
        f_close(&fil);
        if (empty) {
            (void)f_unlink(name);
            break;
        }
        if (!placed) {
            return fail(info, log, t0, "%s is not a contiguous part of the log's length: left untouched", name);
        }
        const sd_attach_result_t added = sd_log_add_part(log, lba);
        if (added != SD_ATTACH_OK) {
            return fail(info, log, t0, added == SD_ATTACH_READ_ERROR ? "reading %s back failed"
                        : "%s is not the next part of this log (or is damaged): left untouched", name);
        }
    }
    info->parts = log->parts;

    /* One part more once the log is running out, while the drive is off: a session never touches FatFs. */
    if ((log->state == SD_LOG_OPEN || log->state == SD_LOG_FULL) &&
        sd_log_blocks_free(log) < info->blocks / SD_LOG_GROW_WHEN) {
        if (log->parts < SD_LOG_MAX_PARTS) {
            grow(info, log, &fs, &fil, &dev);
        } else {
            info->grow_why = "the log has the most parts it can have";
        }
    }
    f_unmount("");

    info->resume_block = log->next;
    info->ok      = true;
    info->open_ms = (uint32_t)((time_us_64() - t0) / 1000u);
    snprintf(info->why, sizeof(info->why), "%s %s, %s, %lu part(s) of %lu blocks%s, %s at block %lu, %lu free%s%s",
             SD_LOG_FILE, info->created ? "created" : "found", info->exfat ? "exFAT" : "FAT",
             (unsigned long)log->parts, (unsigned long)info->blocks, info->grew ? " (one added now)" : "",
             log->state == SD_LOG_FULL ? "FULL" : "writing", (unsigned long)log->next,
             (unsigned long)sd_log_blocks_free(log), info->grow_why != NULL ? "; cannot grow: " : "",
             info->grow_why != NULL ? info->grow_why : "");
    return true;
}
