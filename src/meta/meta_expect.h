/*
 * Checks that every directory command's sectors reached the exFAT model whole (core0). The command and
 * its decoded sectors arrive by separate paths, matched by CBW time and tag; a result that never comes,
 * or comes incomplete, is reported, never passed silently. No SDK headers.
 */
#ifndef META_EXPECT_H
#define META_EXPECT_H

/* bool and the fixed-width integers. */
#include <stdbool.h>
#include <stdint.h>

/* Commands, and early results, held at once while they wait for each other. */
#define META_EXPECT_SLOTS 32u

/* Why a directory command is reported: no result came, or only part of one. */
typedef enum {
    META_EXPECT_MISSING = 1,     /* no result for the command */
    META_EXPECT_INCOMPLETE,      /* a result, not complete */
} meta_expect_outcome_t;

/* A directory command, or a decoded result, waiting for the other half. */
typedef struct {
    bool     used;
    bool     write;
    bool     complete;           /* results: META_COMPLETE */
    uint64_t ts_ns;              /* the CBW's time: the key, with the tag */
    uint32_t tag;
    uint64_t lba;
    uint32_t blocks;
    uint32_t bytes;              /* results: data bytes reassembled */
    uint64_t at_us;              /* commands: when it was noted */
} meta_expect_item_t;

/* Told about a command that failed; `result` is NULL for META_EXPECT_MISSING. */
typedef void (*meta_expect_cb_t)(meta_expect_outcome_t outcome, const meta_expect_item_t *cmd,
                                 const meta_expect_item_t *result, void *ctx);

/* The check itself: what is waiting on each side, and the counts. */
typedef struct {
    meta_expect_item_t cmds[META_EXPECT_SLOTS];     /* waiting for their result */
    meta_expect_item_t results[META_EXPECT_SLOTS];  /* arrived before their command */
    uint32_t           next_result;
    meta_expect_cb_t   cb;
    void              *ctx;

    uint64_t expected;           /* commands noted */
    uint64_t complete;
    uint64_t missing;
    uint64_t incomplete;
    uint64_t evicted;            /* of `missing`: reported because the table was full */
} meta_expect_t;

/* Starts an empty check that reports through `cb`. */
void meta_expect_init(meta_expect_t *e, meta_expect_cb_t cb, void *ctx);

/* A command that must have a complete result. */
void meta_expect_command(meta_expect_t *e, uint64_t ts_ns, uint32_t tag, bool write, uint64_t lba,
                         uint32_t blocks, uint64_t now_us);

/* Every result meta_rx reports, complete or not. */
void meta_expect_result(meta_expect_t *e, uint64_t ts_ns, uint32_t tag, bool write, uint64_t lba,
                        uint32_t blocks, bool complete, uint32_t bytes);

/* Reports commands noted at least `timeout_us` ago with no result as MISSING, oldest first. */
void meta_expect_tick(meta_expect_t *e, uint64_t now_us, uint64_t timeout_us);

#endif /* META_EXPECT_H */
