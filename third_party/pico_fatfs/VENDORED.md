# pico_fatfs -- vendored, not ours

Upstream: https://github.com/elehobica/pico_fatfs
Commit:   417fca7fa519a915a7a697e3edf7b9a183243eaa (2026-08-26)
Licence:  BSD 2-clause (`LICENSE`), Elehobica 2020-2021.
          FatFs itself is ChaN's, under its own licence in `fatfs/ff.h`.

Copied verbatim except for what is noted under "Local changes". Its files
are listed by path in the project's CMakeLists (the tap and the bring-up
firmware), not copied into `src/`, so it stays separable and updatable.

## Why this library, and what it gives us

The user's decision (2026-09-20) was to use a third-party dependency if a
simple one exists, and to fall back to raw blocks and our own driver if not.
This one fits the constraints the tap puts on anything sharing the chip:

- **Pure C.** The project stays in C (a decided point); carlk3's
  no-OS-FatFS-SD is the other well-known choice and has a C++ API layer.
- **Hardware SPI0 on our exact wiring.** `tf_card.c` validates the pins
  against the RP2350's SPI0 function table and only falls back to a PIO SPI
  if they do not fit. MISO 16 / SCK 18 / MOSI 19 are in that table and CS 17
  is a plain GPIO, so **PIO0 -- which the capture owns -- is never touched**.
  `pico_fatfs_set_config()` returns false if it chose PIO: the bring-up
  treats that as a wiring error rather than running.
- **No interrupts and no DMA.** Every transfer is `spi_write_blocking` /
  `spi_read_blocking`, so it cannot take an IRQ that belongs to core0's
  scheduling, cannot claim a DMA channel the capture needs, and cannot run
  anywhere except the core that called it. Blocking is acceptable because
  `store_fifo_t` already buffers in front of slow sinks; it is also why the
  card's worst write pause (next step 00-b) is the number that sizes that
  buffer.
- **CMD17/CMD24 single-block and CMD18/CMD25 multi-block** -- the multi-block
  path is what the spill path's ~2.2 MB/s needs.
- **Two layers, separable.** `tf_card.c` alone is a block driver
  (`disk_initialize` / `disk_read` / `disk_write` / `disk_ioctl`), which is
  all raw-block logging needs; `fatfs/ff.c` on top is what makes the card
  readable on a PC. The bring-up build compiles only the block layer. **The
  tap (step 111) compiles both**, but uses FatFs only at boot, to find or
  create one preallocated, contiguous file (AUDIT.BIN, `f_expand`); the session
  then writes that file's blocks by LBA through `tf_card.c`, so no FAT or
  directory sector is written during a session (see `src/sd/sd_card.c`).

## Local changes

- `fatfs/conf/ffconf.h`: `FF_CODE_PAGE` 932 (Japanese) -> 437 (US). The
  932 tables are ~180 KB of flash we have no use for. The tap compiles `ff.c`
  since step 111, so this now matters.
- `fatfs/conf/ffconf.h`: `FF_USE_MKFS` 0 -> 1 (step 112), for
  `sd_tools/sd_format` only. The tap never calls `f_mkfs`, and the linker drops it
  from its image (`nm build/USBLogger.elf | grep f_mkfs` is empty).
- `tf_card.c`, `_select()` (2026-10-13, marked `LOCAL CHANGE` in the code):
  while `STA_NOINIT` is set it proceeds even if MISO does not read 0xFF. On a
  module that buffers DO (74LVC125) MISO idles low before the card has been
  spoken to, so the first `send_cmd(CMD0)` timed out and init failed on good
  hardware. After init the original wait-for-ready applies unchanged.

## Known upstream defect (we do not use the path)

`disk_ioctl(CTRL_TRIM)` calls `disk_ioctl(drv, MMC_GET_CSD, csd)`, but
`MMC_GET_CSD` has no case in that switch and falls through to
`default: res = RES_PARERR`, so CTRL_TRIM can never succeed. FatFs only
issues it when `FF_USE_TRIM` is 1, which it is not. Do not turn that on
without fixing this first.

## Updating

Re-copy `fatfs/`, `pio/`, `tf_card.c`, `tf_card.h`, `CMakeLists.txt` and
`LICENSE` from a fresh clone, re-apply the local changes above, and re-run the
bring-up (`sd_bringup`) before trusting the tap with it.
