/*
 * The one path every persistent output goes through: audit records and metadata sectors.
 * Each item goes to every attached backend (the console, the card); callers say what they store, never where.
 */
#ifndef STORE_H
#define STORE_H

/* bool and the fixed-width integers. */
#include <stdbool.h>
#include <stdint.h>

/* What an item is, stored with it so a backend can give back one kind. Values are only ever
 * appended. */
typedef enum {
    STORE_ITEM_AUDIT_RECORD    = 1,   /* one audit_record_t (audit_log.h) */
    STORE_ITEM_METADATA_SECTOR = 2,   /* a raw directory sector: its LBA (8 bytes), then its bytes */
    STORE_ITEM_MODEL_SNAPSHOT  = 3,   /* unused: snapshots go to the card as blobs (sd_log.h) */
} store_item_t;

/* Most backends one store can feed. */
#define STORE_MAX_BACKENDS 4u

/* Called for each stored item of the requested kind, oldest first; false stops the walk. */
typedef bool (*store_visit_t)(void *vctx, const uint8_t *data, uint32_t len);

/* One place output goes (the console, the card, a RAM buffer), and what it has been given. */
typedef struct {
    const char *name;   /* for the stats line */

    /* Stores the whole item or nothing. False if it could not. */
    bool (*write)(void *ctx, store_item_t kind, const uint8_t *data, uint32_t len);
    /* Commits what was written to durable storage. NULL: nothing to commit. */
    bool (*sync)(void *ctx);
    /* Walks the stored items of one kind. NULL: this backend cannot read back. False: a corrupt
     * length. */
    bool (*for_each)(void *ctx, store_item_t kind, store_visit_t visit, void *vctx);
    void *ctx;

    /* Counted by store.c; a failure is output that may be missing from this backend. */
    uint64_t items;
    uint64_t bytes;
    uint64_t failures;
} store_backend_t;

/* A store: the backends every item is written to, in attach order. */
typedef struct {
    store_backend_t *backend[STORE_MAX_BACKENDS];
    uint32_t         count;
} store_t;

/* Starts a store with no backends. */
void store_init(store_t *s);

/* False if STORE_MAX_BACKENDS are already attached. */
bool store_attach(store_t *s, store_backend_t *b);

/* Writes one item to every backend, in attach order; false if any failed (the others still have
 * it). */
bool store_write(store_t *s, store_item_t kind, const uint8_t *data, uint32_t len);

/* Syncs every backend that has something to commit. False if any failed. */
bool store_sync(store_t *s);

/* Walks one kind's items from the first backend that can read back; false if none can. */
bool store_for_each(const store_t *s, store_item_t kind, store_visit_t visit, void *vctx);

/* ---- RAM backend ----------------------------------------------------- */

/* Items appended to a caller's buffer, each after an 8-byte header; an item that does not fit is
 * refused whole. */
typedef struct {
    uint8_t *buf;
    uint32_t size;
    uint32_t used;
} store_ram_t;

/* Bytes in front of each item in a RAM buffer: length (4), kind (1), zeros (3). */
#define STORE_RAM_HEADER_BYTES 8u

/* Sets up `ram` over buf[0..size) and fills `b` to use it. */
void store_ram_init(store_ram_t *ram, store_backend_t *b, const char *name,
                    uint8_t *buf, uint32_t size);

/* ---- FIFO backend: a RAM buffer in front of a slower backend --------- */

/* Holds items in RAM and forwards them, oldest first, when the target is ready, so a busy SD card never
 * stalls core0. An item that does not fit is a FIFO failure; one the target rejects is dropped and counted. */
typedef struct {
    uint8_t         *buf;
    uint32_t         size;
    uint32_t         start;        /* first held byte */
    uint32_t         end;          /* one past the last held byte */
    uint32_t         high_water;   /* most bytes ever held */
    store_backend_t *target;
    bool           (*ready)(void *ready_ctx);   /* NULL: always ready */
    void            *ready_ctx;
} store_fifo_t;

/* Sets up `fifo` over buf[0..size) in front of `target` and fills `b` (attach `b`, not `target`). */
void store_fifo_init(store_fifo_t *fifo, store_backend_t *b, const char *name,
                     uint8_t *buf, uint32_t size, store_backend_t *target,
                     bool (*ready)(void *ready_ctx), void *ready_ctx);

/* Forwards up to `max_items` held items while the target is ready; returns how many. */
uint32_t store_fifo_pump(store_fifo_t *fifo, uint32_t max_items);

/* Bytes held now, headers included. */
static inline uint32_t store_fifo_held(const store_fifo_t *fifo)
{
    return fifo->end - fifo->start;
}

#endif /* STORE_H */
