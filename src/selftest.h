/*
 * The boot self-test: a known Full Speed packet stream written into the capture ring and run through
 * the real decoder, parser and audit log, so a bench failure can be blamed on wiring, not code.
 */
#ifndef SELFTEST_H
#define SELFTEST_H

/* bool, and the capture whose ring the self-test writes into. */
#include <stdbool.h>

#include "usb_capture.h"

/* True if every check passed. Call after usb_capture_init() and before usb_capture_start(). */
bool usb_selftest_run(usb_capture_t *cap, bool verbose);

/* The decode benchmark: a 32-transaction WRITE stream decoded with core1's code, timed in DWT
 * cycles. */
#define BENCH_TRANSACTIONS  32u
/* Times the stream is decoded; the fastest run counts. */
#define BENCH_RUNS          5u
#define DECODE_BENCH_BATCH  2048u   /* core1's DECODE_BATCH_WORDS */

/* The benchmark's result: whether it decoded as it must, and its cycle counts. */
typedef struct {
    bool     ok;                    /* every run skipped all 32 packets, paired CBW and CSW, no errors */
    uint32_t words;
    uint32_t skipped;
    uint32_t min_cycles;
    uint32_t runs[BENCH_RUNS];
} usb_selftest_bench_t;

/* Runs the benchmark; false if a run did not decode as it must. */
bool usb_selftest_bench(usb_capture_t *cap, usb_selftest_bench_t *out);

#endif /* SELFTEST_H */
