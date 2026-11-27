/*
 * The SD card on SPI0 (core0 only): opened at boot, the log's parts found or created through FatFs, then
 * written block by block by LBA, FatFs unused. Driver: third_party/pico_fatfs, no DMA, no interrupts.
 */
#ifndef SD_CARD_H
#define SD_CARD_H

/* bool and the fixed-width integers. */
#include <stdbool.h>
#include <stdint.h>

/* The card's log (sd_log_t) that opening the card attaches. */
#include "sd_log.h"

/* The log's first part on the card; later ones are AUDIT001.BIN, AUDIT002.BIN, ... */
#define SD_LOG_FILE       "AUDIT.BIN"
/* 256 MB (~2.6 million records) per part, each allocated contiguously. */
#define SD_LOG_FILE_BYTES (256u * 1024u * 1024u)
/* A part is added at boot once the log has less than 1/SD_LOG_GROW_WHEN of a part free. */
#define SD_LOG_GROW_WHEN  4u
/* A new card's password file, and the most of it read; a longer one is wiped and deleted unread. */
#define SD_CARD_PASSWORD_FILE "card_password.txt"
#define SD_CARD_PASSWORD_MAX  128u   /* bytes */
/* The SPI clock: 12 MHz is what clk_peri (48 MHz) gives; 24 MHz fails on this wiring. */
#define SD_SPI_HZ         (12u * 1000u * 1000u)

/* What opening the card found and did, and its write timings, for the banner and the stats. */
typedef struct {
    bool     ok;            /* the log is open on the card */
    char     why[160];      /* one line: what happened, for the banner */
    uint32_t open_ms;       /* time core0 spent opening it */
    uint32_t init_tries;    /* card start-ups it took (1 normally; more after a reboot mid-transfer) */
    uint32_t sectors;       /* card size (0: unknown) */
    uint32_t spi_hz;        /* actual SPI clock */
    bool     exfat;         /* else FAT12/16/32 */
    bool     created;       /* AUDIT.BIN was made by this boot */
    uint32_t first_lba;
    uint32_t blocks;        /* blocks per part */
    uint32_t parts;         /* parts found, and added by this boot */
    bool     grew;          /* this boot added a part */
    const char *grow_why;   /* why a part was needed and could not be added (NULL: none) */
    uint32_t resume_block;  /* where this boot started writing */

    /* card_password.txt, read at the opening then wiped and deleted, whatever the card's check
     * finds. */
    bool     password_found;    /* the card had one */
    bool     password_removed;  /* its bytes were overwritten with zeros, and it is deleted */
    uint32_t password_len;      /* its bytes held in `password` (0: empty, or too long to be one) */
    uint8_t  password[SD_CARD_PASSWORD_MAX];   /* the caller zeroes it once checked */

    /* Runtime, for the stats line. */
    uint64_t write_us_max;      /* longest single-block write call (core0 blocked) */
    uint64_t write_us_total;
    uint64_t busy_us_max;       /* longest the card stayed busy, seen by the ready probe */
    uint64_t busy_probes;       /* ready probes that found the card busy */
} sd_card_info_t;

/* Deselects the card; call first thing at boot, or a stray SCK edge while it is selected shifts its
 * bytes. */
void sd_card_park(void);

/* Brings the card up and opens the log on it, attaching `log`; on failure `info->why` says why.
 * A card_password.txt is read into `info->password`, then wiped and deleted. Blocks core0 (~50 ms). */
bool sd_card_open(sd_card_info_t *info, sd_log_t *log, uint64_t new_file_id);

#endif /* SD_CARD_H */
