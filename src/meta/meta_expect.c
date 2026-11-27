/*
 * Matches each directory command with its decoded sectors, and reports the ones missing or
 * incomplete.
 */

/* memset. */
#include <string.h>

/* The table of commands and results this file matches. */
#include "meta_expect.h"

/* Empties both tables and sets the function told about each failure. */
void meta_expect_init(meta_expect_t *e, meta_expect_cb_t cb, void *ctx)
{
    memset(e, 0, sizeof(*e));
    e->cb  = cb;
    e->ctx = ctx;
}

/* A command and its result (or none) have met. */
static void settle(meta_expect_t *e, const meta_expect_item_t *cmd, const meta_expect_item_t *result)
{
    if (result != NULL && result->complete) {
        e->complete++;
        return;
    }
    if (result != NULL) {
        e->incomplete++;
    } else {
        e->missing++;
    }
    if (e->cb) {
        e->cb(result != NULL ? META_EXPECT_INCOMPLETE : META_EXPECT_MISSING, cmd, result, e->ctx);
    }
}

/* Notes a directory command; settles it at once if its result already came. */
void meta_expect_command(meta_expect_t *e, uint64_t ts_ns, uint32_t tag, bool write, uint64_t lba,
                         uint32_t blocks, uint64_t now_us)
{
    meta_expect_item_t c;
    memset(&c, 0, sizeof(c));
    c.used   = true;
    c.write  = write;
    c.ts_ns  = ts_ns;
    c.tag    = tag;
    c.lba    = lba;
    c.blocks = blocks;
    c.at_us  = now_us;
    e->expected++;

    for (uint32_t i = 0; i < META_EXPECT_SLOTS; i++) {
        meta_expect_item_t *const r = &e->results[i];
        if (r->used && r->ts_ns == ts_ns && r->tag == tag) {
            const meta_expect_item_t result = *r;
            r->used = false;
            settle(e, &c, &result);
            return;
        }
    }
    meta_expect_item_t *slot = NULL;
    meta_expect_item_t *oldest = NULL;
    for (uint32_t i = 0; i < META_EXPECT_SLOTS && slot == NULL; i++) {
        if (!e->cmds[i].used) {
            slot = &e->cmds[i];
        } else if (oldest == NULL || e->cmds[i].ts_ns < oldest->ts_ns) {
            oldest = &e->cmds[i];
        }
    }
    if (slot == NULL) {
        /* Full: the oldest waiting command's transfer can no longer be in the link. */
        const meta_expect_item_t old = *oldest;
        oldest->used = false;
        e->evicted++;
        settle(e, &old, NULL);
        slot = oldest;
    }
    *slot = c;
}

/* Results come in bus order: commands waiting from before `ts_ns` will get none. Reported oldest
 * first. */
static void settle_overtaken(meta_expect_t *e, uint64_t ts_ns)
{
    for (;;) {
        meta_expect_item_t *oldest = NULL;
        for (uint32_t i = 0; i < META_EXPECT_SLOTS; i++) {
            meta_expect_item_t *const c = &e->cmds[i];
            if (c->used && c->ts_ns < ts_ns && (oldest == NULL || c->ts_ns < oldest->ts_ns)) {
                oldest = c;
            }
        }
        if (oldest == NULL) {
            return;
        }
        const meta_expect_item_t cmd = *oldest;
        oldest->used = false;
        settle(e, &cmd, NULL);
    }
}

/* Notes a decoded transfer; settles the command waiting for it, or keeps it until one comes. */
void meta_expect_result(meta_expect_t *e, uint64_t ts_ns, uint32_t tag, bool write, uint64_t lba,
                        uint32_t blocks, bool complete, uint32_t bytes)
{
    meta_expect_item_t r;
    memset(&r, 0, sizeof(r));
    r.used     = true;
    r.write    = write;
    r.complete = complete;
    r.ts_ns    = ts_ns;
    r.tag      = tag;
    r.lba      = lba;
    r.blocks   = blocks;
    r.bytes    = bytes;

    settle_overtaken(e, ts_ns);
    for (uint32_t i = 0; i < META_EXPECT_SLOTS; i++) {
        meta_expect_item_t *const c = &e->cmds[i];
        if (c->used && c->ts_ns == ts_ns && c->tag == tag) {
            const meta_expect_item_t cmd = *c;
            c->used = false;
            settle(e, &cmd, &r);
            return;
        }
    }
    /* Most results are for commands nobody expects; they wait here until pushed out. */
    e->results[e->next_result] = r;
    e->next_result = (e->next_result + 1u) % META_EXPECT_SLOTS;
}

/* Reports as missing every command that has waited longer than timeout_us, oldest first. */
void meta_expect_tick(meta_expect_t *e, uint64_t now_us, uint64_t timeout_us)
{
    for (;;) {
        meta_expect_item_t *oldest = NULL;
        for (uint32_t i = 0; i < META_EXPECT_SLOTS; i++) {
            meta_expect_item_t *const c = &e->cmds[i];
            if (c->used && now_us >= c->at_us && now_us - c->at_us >= timeout_us &&
                (oldest == NULL || c->at_us < oldest->at_us)) {
                oldest = c;
            }
        }
        if (oldest == NULL) {
            return;
        }
        const meta_expect_item_t cmd = *oldest;
        oldest->used = false;
        settle(e, &cmd, NULL);
    }
}
