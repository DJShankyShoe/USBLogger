/*
 * The storage interface every persistent output goes through, with a RAM backend and a FIFO
 * backend.
 */

/* memset, memcpy, memmove. */
#include <string.h>

/* What this file defines. */
#include "store.h"

/* Starts a store with no backends. */
void store_init(store_t *s)
{
    memset(s, 0, sizeof(*s));
}

/* Adds a backend; false when STORE_MAX_BACKENDS are already attached. */
bool store_attach(store_t *s, store_backend_t *b)
{
    if (s->count >= STORE_MAX_BACKENDS) {
        return false;
    }
    s->backend[s->count++] = b;
    return true;
}

/* One write to one backend, counted. */
static bool backend_write(store_backend_t *b, store_item_t kind, const uint8_t *data,
                          uint32_t len)
{
    if (b->write(b->ctx, kind, data, len)) {
        b->items++;
        b->bytes += len;
        return true;
    }
    b->failures++;
    return false;
}

/* Gives one item to every backend; false if any refused it. */
bool store_write(store_t *s, store_item_t kind, const uint8_t *data, uint32_t len)
{
    bool ok = true;
    for (uint32_t i = 0; i < s->count; i++) {
        if (!backend_write(s->backend[i], kind, data, len)) {
            ok = false;
        }
    }
    return ok;
}

/* Asks every backend to make what it holds durable; false if any failed. */
bool store_sync(store_t *s)
{
    bool ok = true;
    for (uint32_t i = 0; i < s->count; i++) {
        store_backend_t *const b = s->backend[i];
        if (b->sync != NULL && !b->sync(b->ctx)) {
            b->failures++;
            ok = false;
        }
    }
    return ok;
}

/* Walks the items of one kind in the first backend that can be read back. */
bool store_for_each(const store_t *s, store_item_t kind, store_visit_t visit, void *vctx)
{
    for (uint32_t i = 0; i < s->count; i++) {
        const store_backend_t *const b = s->backend[i];
        if (b->for_each != NULL) {
            return b->for_each(b->ctx, kind, visit, vctx);
        }
    }
    return false;
}

/* ---- RAM backend ----------------------------------------------------- */

/* Writes one framed item (header + data) at p. */
static void put_item(uint8_t *p, store_item_t kind, const uint8_t *data, uint32_t len)
{
    p[0] = (uint8_t)len;
    p[1] = (uint8_t)(len >> 8);
    p[2] = (uint8_t)(len >> 16);
    p[3] = (uint8_t)(len >> 24);
    p[4] = (uint8_t)kind;
    p[5] = p[6] = p[7] = 0u;
    if (len != 0u) {
        memcpy(p + STORE_RAM_HEADER_BYTES, data, len);
    }
}

/* Reads a framed item's length (the first four bytes of its header, little-endian). */
static uint32_t item_len(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

/* Appends one framed item to the RAM area; false when it does not fit. */
static bool ram_write(void *ctx, store_item_t kind, const uint8_t *data, uint32_t len)
{
    store_ram_t *const r = ctx;
    const uint32_t room = r->size - r->used;
    if (room < STORE_RAM_HEADER_BYTES || len > room - STORE_RAM_HEADER_BYTES) {
        return false;
    }
    put_item(r->buf + r->used, kind, data, len);
    r->used += STORE_RAM_HEADER_BYTES + len;
    return true;
}

/* Walks the RAM area's items of one kind; false if a header is damaged. */
static bool ram_for_each(void *ctx, store_item_t kind, store_visit_t visit, void *vctx)
{
    const store_ram_t *const r = ctx;
    uint32_t off = 0;
    while (off < r->used) {
        if (r->used - off < STORE_RAM_HEADER_BYTES) {
            return false;
        }
        const uint8_t *const p = r->buf + off;
        const uint32_t len = item_len(p);
        if (len > r->used - off - STORE_RAM_HEADER_BYTES) {
            return false;
        }
        if (p[4] == (uint8_t)kind && !visit(vctx, p + STORE_RAM_HEADER_BYTES, len)) {
            return true;
        }
        off += STORE_RAM_HEADER_BYTES + len;
    }
    return true;
}

/* Makes `b` a RAM backend over `buf`, empty. */
void store_ram_init(store_ram_t *ram, store_backend_t *b, const char *name,
                    uint8_t *buf, uint32_t size)
{
    ram->buf  = buf;
    ram->size = size;
    ram->used = 0;

    memset(b, 0, sizeof(*b));
    b->name     = name;
    b->write    = ram_write;
    b->for_each = ram_for_each;
    b->ctx      = ram;
}

/* ---- FIFO backend ---------------------------------------------------- */

/* Appends one item; when it does not fit after the end, the held bytes move down first, so items
 * stay contiguous. */
static bool fifo_write(void *ctx, store_item_t kind, const uint8_t *data, uint32_t len)
{
    store_fifo_t *const f = ctx;
    const uint32_t held = f->end - f->start;
    const uint32_t free_total = f->size - held;
    if (free_total < STORE_RAM_HEADER_BYTES || len > free_total - STORE_RAM_HEADER_BYTES) {
        return false;
    }
    const uint32_t need = STORE_RAM_HEADER_BYTES + len;
    if (f->size - f->end < need) {
        memmove(f->buf, f->buf + f->start, held);
        f->start = 0;
        f->end   = held;
    }
    put_item(f->buf + f->end, kind, data, len);
    f->end += need;
    if (f->end - f->start > f->high_water) {
        f->high_water = f->end - f->start;
    }
    return true;
}

/* Passes up to max_items held items to the target while it is ready; returns how many. */
uint32_t store_fifo_pump(store_fifo_t *f, uint32_t max_items)
{
    uint32_t forwarded = 0;
    while (forwarded < max_items && f->end != f->start &&
           (f->ready == NULL || f->ready(f->ready_ctx))) {
        const uint8_t *const p = f->buf + f->start;
        const uint32_t len = item_len(p);
        /* Rejected items are counted by backend_write and dropped. */
        (void)backend_write(f->target, (store_item_t)p[4], p + STORE_RAM_HEADER_BYTES, len);
        f->start += STORE_RAM_HEADER_BYTES + len;
        forwarded++;
    }
    if (f->start == f->end) {
        f->start = f->end = 0;
    }
    return forwarded;
}

/* Empties the FIFO into the target and syncs the target; false if anything is left. */
static bool fifo_sync(void *ctx)
{
    store_fifo_t *const f = ctx;
    while (store_fifo_pump(f, UINT32_MAX) != 0u) {
    }
    if (f->end != f->start) {
        return false;
    }
    if (f->target->sync != NULL && !f->target->sync(f->target->ctx)) {
        f->target->failures++;
        return false;
    }
    return true;
}

/* Makes `b` a FIFO backend over `buf` in front of `target`, with `ready` saying when it can take more. */
void store_fifo_init(store_fifo_t *fifo, store_backend_t *b, const char *name,
                     uint8_t *buf, uint32_t size, store_backend_t *target,
                     bool (*ready)(void *ready_ctx), void *ready_ctx)
{
    memset(fifo, 0, sizeof(*fifo));
    fifo->buf       = buf;
    fifo->size      = size;
    fifo->target    = target;
    fifo->ready     = ready;
    fifo->ready_ctx = ready_ctx;

    memset(b, 0, sizeof(*b));
    b->name  = name;
    b->write = fifo_write;
    b->sync  = fifo_sync;
    b->ctx   = fifo;
}
