/*
 * The exFAT name model: learns the volume from its boot sector, keeps the directory sectors it has seen,
 * and compares each new version with the old to report files created, renamed, modified and deleted.
 * Also saves and loads the model as a SHA-256-sealed snapshot.
 */

/* memset, memcpy, memcmp, strlen. */
#include <string.h>

/* What this file defines, and SHA-256 for the snapshot's seal. */
#include "exfat_model.h"
#include "../log/sha256.h"

/* A directory entry's size, and how many fit in a sector. */
#define ENTRY_BYTES      32u
#define ENTRIES_PER_SEC  (EXFAT_SECTOR_BYTES / ENTRY_BYTES)

/* Entry types (the high bit is InUse). */
#define TYPE_IN_USE      0x80u
#define TYPE_FILE        0x05u   /* primary: file or directory */
#define TYPE_STREAM      0x40u   /* secondary: stream extension */
#define TYPE_NAME        0x41u   /* secondary: file name */
#define ATTR_DIRECTORY   0x0010u

/* Read little-endian fields (every exFAT field is little-endian). */
static uint16_t le16(const uint8_t *p) { return (uint16_t)(p[0] | (p[1] << 8)); }
static uint32_t le32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}
static uint64_t le64(const uint8_t *p) { return (uint64_t)le32(p) | ((uint64_t)le32(p + 4) << 32); }

/* Starts an empty model: no volume, nothing cached, events to `cb`. */
void exfat_model_init(exfat_model_t *m, exfat_event_cb_t cb, void *ctx)
{
    memset(m, 0, sizeof(*m));
    for (uint32_t i = 0; i < EXFAT_EMPTY_SECTORS; i++) {
        m->empty[i] = EXFAT_EMPTY_NONE;
    }
    m->cb  = cb;
    m->ctx = ctx;
}

/* Counts the event in m->ev and hands it to the callback. */
static void emit(exfat_model_t *m)
{
    m->events++;
    if (m->cb) {
        m->cb(&m->ev, m->ctx);
    }
}

/* True once the volume is known and this insertion's boot sector confirmed it: only then are
 * directories used. */
static bool known(const exfat_model_t *m)
{
    return m->have_volume && m->volume_confirmed;
}

/* Marks a loaded model unconfirmed until this insertion's boot sector arrives. */
void exfat_model_unconfirm(exfat_model_t *m)
{
    m->volume_confirmed = false;
}

/* ---- boot sector ----------------------------------------------------- */

/* Checks for an exFAT boot sector: "EXFAT   " at byte 3 and the 55 AA signature. */
static bool is_boot_sector(const uint8_t *b)
{
    return memcmp(&b[3], "EXFAT   ", 8) == 0 && b[510] == 0x55u && b[511] == 0xAAu;
}

/* The boot checksum over sectors 0-10, skipping VolumeFlags (bytes 106-107) and PercentInUse (112);
 * sector 11 holds it. */
static bool boot_checksum_ok(const uint8_t *region)
{
    uint32_t sum = 0;
    for (uint32_t i = 0; i < 11u * EXFAT_SECTOR_BYTES; i++) {
        if (i == 106u || i == 107u || i == 112u) {
            continue;
        }
        sum = ((sum & 1u) ? 0x80000000u : 0u) + (sum >> 1) + region[i];
    }
    const uint8_t *const s11 = &region[11u * EXFAT_SECTOR_BYTES];
    for (uint32_t k = 0; k < EXFAT_SECTOR_BYTES; k += 4u) {
        if (le32(&s11[k]) != sum) {
            return false;
        }
    }
    return true;
}

/* Tracks a directory extent; returns its index, or -1 (not a cluster, or the table is full). */
static int add_directory(exfat_model_t *m, uint32_t first, uint32_t clusters)
{
    if (first < 2u || clusters == 0u) {
        return -1;
    }
    for (uint32_t i = 0; i < m->ndirs; i++) {
        if (m->dirs[i].first == first) {
            if (clusters > m->dirs[i].clusters) {
                m->dirs[i].clusters = clusters;
                m->dirs_version++;
            }
            return (int)i;
        }
    }
    if (m->ndirs >= EXFAT_MAX_DIRS) {
        m->dirs_full++;
        return -1;
    }
    exfat_dir_extent_t *const d = &m->dirs[m->ndirs];
    memset(d, 0, sizeof(*d));
    d->first    = first;
    d->clusters = clusters;
    m->dirs_version++;
    return (int)m->ndirs++;
}

/* Drops a deleted directory's extent and its cached sectors, so the next directory in its cluster
 * inherits nothing. */
static void drop_extent(exfat_model_t *m, uint32_t i)
{
    const exfat_dir_extent_t *const d = &m->dirs[i];
    const uint64_t start = m->heap_lba + ((uint64_t)(d->first - 2u) << m->cluster_shift);
    const uint64_t end   = start + ((uint64_t)d->clusters << m->cluster_shift);
    for (uint32_t k = 0; k < EXFAT_CACHE_SECTORS; k++) {
        if (m->cache[k].valid && m->cache[k].lba >= start && m->cache[k].lba < end) {
            m->cache[k].valid = false;
        }
    }
    for (uint32_t k = 0; k < EXFAT_EMPTY_SECTORS; k++) {
        if (m->empty[k] != EXFAT_EMPTY_NONE && m->heap_lba + m->empty[k] >= start && m->heap_lba + m->empty[k] < end) {
            m->empty[k] = EXFAT_EMPTY_NONE;
        }
    }
    m->dirs[i] = m->dirs[m->ndirs - 1u];
    m->ndirs--;
    m->dirs_forgotten++;
    m->dirs_version++;
}

/* Forgets a deleted directory and every directory inside it, even ones whose own DELETE was lost. */
static void forget_directory(exfat_model_t *m, uint32_t first, uint32_t holder_first)
{
    if (first == m->root_cluster) {
        return;
    }
    int found = -1;
    for (uint32_t i = 0; i < m->ndirs; i++) {
        if (m->dirs[i].first == first) {
            found = (int)i;
            break;
        }
    }
    if (found < 0 || (m->dirs[found].named && m->dirs[found].parent != holder_first)) {
        return;
    }
    uint32_t gone[EXFAT_MAX_DIRS];
    uint32_t n = 0;
    gone[n++] = first;
    drop_extent(m, (uint32_t)found);
    for (uint32_t g = 0; g < n; g++) {
        for (uint32_t k = 0; k < m->ndirs;) {
            const exfat_dir_extent_t *const d = &m->dirs[k];
            if (d->named && d->parent == gone[g] && d->first != m->root_cluster) {
                if (n < EXFAT_MAX_DIRS) {
                    gone[n++] = d->first;
                }
                m->dirs_forgotten_inside++;
                drop_extent(m, k);          /* the last extent moves to k: look at k again */
            } else {
                k++;
            }
        }
    }
}

/* True for the volume's main boot sector at `lba`, not the backup 12 sectors on (by
 * PartitionOffset, else the serial). */
static bool main_boot_sector(const exfat_model_t *m, uint64_t lba, const uint8_t *b)
{
    if (!is_boot_sector(b)) {
        return false;
    }
    const uint64_t partition = le64(&b[64]);
    if (partition != 0u) {
        return lba == partition;
    }
    return !(m->have_volume && le32(&b[100]) == m->serial && lba == m->boot_lba + 12u);
}

/* Gives the volume serial of a main boot sector the model would take, without taking it. */
bool exfat_boot_sector_serial(const exfat_model_t *m, uint64_t lba, const uint8_t *sector, uint32_t *serial)
{
    /* The same tests boot_sector applies before it takes a volume. */
    if (!main_boot_sector(m, lba, sector) || sector[108] != 9u || sector[109] > 16u || le32(&sector[88]) == 0u) {
        return false;
    }
    *serial = le32(&sector[100]);
    return true;
}

/* Takes a boot sector: `region` starts at it, `sectors` of it came in this transfer (12 or more:
 * checksum verified). */
static void boot_sector(exfat_model_t *m, uint64_t lba, const uint8_t *region, uint32_t sectors,
                        bool from_write)
{
    const uint8_t *const b = region;
    const uint32_t heap_offset = le32(&b[88]);
    const uint32_t shift       = b[109];
    if (b[108] != 9u || shift > 16u || heap_offset == 0u) {
        return;                                /* not 512-byte sectors, or nonsense */
    }
    const uint64_t heap   = lba + heap_offset;
    const uint32_t root   = le32(&b[96]);
    const uint32_t serial = le32(&b[100]);

    const bool same = m->have_volume && m->boot_lba == lba && m->heap_lba == heap &&
                      m->cluster_shift == shift && m->root_cluster == root && m->serial == serial;
    const bool checked = sectors >= 12u;
    const bool ok = checked && boot_checksum_ok(region);
    if (same && !checked && m->volume_confirmed) {
        return;                                /* the same volume, nothing new to say */
    }
    if (!same) {
        /* A new (or reformatted) volume: nothing remembered applies. */
        m->ndirs = 0;
        m->dirs_version++;
        m->bitmap_first = m->bitmap_clusters = 0;
        m->upcase_first = m->upcase_clusters = 0;
        for (uint32_t i = 0; i < EXFAT_CACHE_SECTORS; i++) {
            m->cache[i].valid = false;
        }
        for (uint32_t i = 0; i < EXFAT_EMPTY_SECTORS; i++) {
            m->empty[i] = EXFAT_EMPTY_NONE;
        }
        for (uint32_t i = 0; i < EXFAT_PENDING; i++) {
            m->pending[i].used = false;
            m->fresh[i].used   = false;
        }
    }
    m->have_volume   = true;
    m->volume_confirmed = true;
    m->boot_lba      = lba;
    m->heap_lba      = heap;
    m->cluster_shift = shift;
    m->cluster_count = le32(&b[92]);
    m->root_cluster  = root;
    m->serial        = serial;
    m->fat_offset    = le32(&b[80]);
    m->fat_length    = le32(&b[84]);
    add_directory(m, root, 1u);

    memset(&m->ev, 0, sizeof(m->ev));
    m->ev.type                  = EXFAT_EV_VOLUME;
    m->ev.from_write            = from_write;
    m->ev.lba                   = lba;
    m->ev.boot_lba              = lba;
    m->ev.heap_lba              = heap;
    m->ev.sectors_per_cluster   = 1u << shift;
    m->ev.root_cluster          = root;
    m->ev.serial                = serial;
    m->ev.boot_checksum_checked = checked;
    m->ev.boot_checksum_ok      = ok;
    emit(m);
}

/* ---- directory extents and the sector cache -------------------------- */

/* The directory extent holding `lba`, or -1. */
static int directory_index(const exfat_model_t *m, uint64_t lba)
{
    if (!known(m) || lba < m->heap_lba) {
        return -1;
    }
    const uint64_t cluster = 2u + ((lba - m->heap_lba) >> m->cluster_shift);
    for (uint32_t i = 0; i < m->ndirs; i++) {
        if (cluster >= m->dirs[i].first &&
            cluster < (uint64_t)m->dirs[i].first + m->dirs[i].clusters) {
            return (int)i;
        }
    }
    return -1;
}

/* Checks whether a sector belongs to a directory the model tracks. */
bool exfat_model_is_directory(const exfat_model_t *m, uint64_t lba)
{
    return directory_index(m, lba) >= 0;
}

/* Checks whether a transfer touches any tracked directory. */
bool exfat_model_overlaps_directory(const exfat_model_t *m, uint64_t lba, uint32_t blocks)
{
    for (uint32_t i = 0; known(m) && i < m->ndirs; i++) {
        const uint64_t start = m->heap_lba + ((uint64_t)(m->dirs[i].first - 2u) << m->cluster_shift);
        const uint64_t end   = start + ((uint64_t)m->dirs[i].clusters << m->cluster_shift);
        if (lba < end && start < lba + blocks) {
            return true;
        }
    }
    return false;
}

/* Appends a string to `out` at *o, cut to fit, always terminated. */
static void put_str(char *out, uint32_t size, uint32_t *o, const char *s)
{
    while (*s != '\0' && *o + 1u < size) {
        out[(*o)++] = *s++;
    }
    out[*o] = '\0';
}

/* The deepest path walked: each directory keeps its name and its parent's cluster; an unknown top
 * starts with "?". */
#define PATH_DEPTH 16u

/* Writes the path of the directory holding a sector ("\test\rip"), "?" first if its top is unknown. */
bool exfat_model_directory_path(const exfat_model_t *m, uint64_t lba, char *out, uint32_t size)
{
    if (size == 0u) {
        return false;
    }
    out[0] = '\0';
    int i = directory_index(m, lba);
    if (i < 0) {
        return false;
    }
    uint32_t chain[PATH_DEPTH];
    uint32_t depth  = 0;
    bool     rooted = false;
    for (;;) {
        const exfat_dir_extent_t *const d = &m->dirs[i];
        if (d->first == m->root_cluster) {
            rooted = true;
            break;
        }
        if (depth == PATH_DEPTH) {
            break;
        }
        chain[depth++] = (uint32_t)i;
        if (!d->named) {
            break;
        }
        int p = -1;
        for (uint32_t k = 0; k < m->ndirs; k++) {
            if (m->dirs[k].first == d->parent) {
                p = (int)k;
                break;
            }
        }
        if (p < 0 || p == i) {
            break;
        }
        i = p;
    }
    uint32_t o = 0;
    if (!rooted) {
        put_str(out, size, &o, "?");
    }
    for (uint32_t k = depth; k-- > 0u;) {
        const exfat_dir_extent_t *const d = &m->dirs[chain[k]];
        put_str(out, size, &o, "\\");
        put_str(out, size, &o, d->named ? d->name : "?");
    }
    return true;
}

/* The path of the directory holding `lba`, a backslash, and `name`, into `out`
 * (EXFAT_PATH_UTF8 bytes). */
static void path_join(const exfat_model_t *m, uint64_t lba, const char *name, char *out)
{
    (void)exfat_model_directory_path(m, lba, out, EXFAT_PATH_UTF8);
    uint32_t o = (uint32_t)strlen(out);
    put_str(out, EXFAT_PATH_UTF8, &o, "\\");
    put_str(out, EXFAT_PATH_UTF8, &o, name);
}

/* Lists the tracked directories as LBA ranges, for core1's interest table; returns how many. */
uint32_t exfat_model_directory_ranges(const exfat_model_t *m, uint64_t *lba, uint32_t *sectors,
                                      uint32_t max)
{
    uint32_t n = 0;
    for (uint32_t i = 0; known(m) && i < m->ndirs && n < max; i++, n++) {
        lba[n]     = m->heap_lba + ((uint64_t)(m->dirs[i].first - 2u) << m->cluster_shift);
        sectors[n] = m->dirs[i].clusters << m->cluster_shift;
    }
    return n;
}

/* Finds a sector in the cache; NULL if it is not held. */
static const exfat_cached_sector_t *cache_find(const exfat_model_t *m, uint64_t lba)
{
    for (uint32_t i = 0; i < EXFAT_CACHE_SECTORS; i++) {
        if (m->cache[i].valid && m->cache[i].lba == lba) {
            return &m->cache[i];
        }
    }
    return NULL;
}

/* The slot of the empty-sector list holding `lba`, or -1. */
static int empty_find(const exfat_model_t *m, uint64_t lba)
{
    if (lba < m->heap_lba || lba - m->heap_lba >= EXFAT_EMPTY_NONE) {
        return -1;
    }
    const uint32_t offset = (uint32_t)(lba - m->heap_lba);
    for (uint32_t i = 0; i < EXFAT_EMPTY_SECTORS; i++) {
        if (m->empty[i] == offset) {
            return (int)i;
        }
    }
    return -1;
}

/* Remembers that `lba` holds no entry in use: a free slot, or the oldest one's when the list is
 * full. */
static void empty_add(exfat_model_t *m, uint64_t lba)
{
    if (lba < m->heap_lba || lba - m->heap_lba >= EXFAT_EMPTY_NONE || empty_find(m, lba) >= 0) {
        return;
    }
    uint32_t slot = EXFAT_EMPTY_SECTORS;
    for (uint32_t i = 0; i < EXFAT_EMPTY_SECTORS && slot == EXFAT_EMPTY_SECTORS; i++) {
        if (m->empty[i] == EXFAT_EMPTY_NONE) {
            slot = i;
        }
    }
    if (slot == EXFAT_EMPTY_SECTORS) {
        slot = m->empty_next;
        m->empty_next = (m->empty_next + 1u) % EXFAT_EMPTY_SECTORS;
        m->empty_full++;
    }
    m->empty[slot] = (uint32_t)(lba - m->heap_lba);
}

/* True if every sector of the run equals the cached copy (most directory sectors seen are repeats);
 * refreshes the stamps. */
static bool run_is_cached(exfat_model_t *m, uint64_t first, const uint8_t *data, uint32_t n)
{
    for (uint32_t s = 0; s < n; s++) {
        const exfat_cached_sector_t *const c = cache_find(m, first + s);
        if (c == NULL ||
            memcmp(c->data, &data[s * EXFAT_SECTOR_BYTES], EXFAT_SECTOR_BYTES) != 0) {
            return false;
        }
    }
    for (uint32_t s = 0; s < n; s++) {   /* keep the eviction order the parse would have left */
        for (uint32_t i = 0; i < EXFAT_CACHE_SECTORS; i++) {
            if (m->cache[i].valid && m->cache[i].lba == first + s) {
                m->cache[i].stamp = ++m->stamp;
                break;
            }
        }
    }
    return true;
}

/* Any entry in use (file sets, and the root's bitmap, up-case and label entries). */
static bool sector_has_live_entry(const uint8_t *data)
{
    for (uint32_t e = 0; e < ENTRIES_PER_SEC; e++) {
        if (data[e * ENTRY_BYTES] & TYPE_IN_USE) {
            return true;
        }
    }
    return false;
}

/* Caches a directory sector; when full, an empty sector goes first (its LBA goes on the empty
 * list), then the oldest. */
static void cache_store(exfat_model_t *m, uint64_t lba, const uint8_t *data)
{
    const int was_empty = empty_find(m, lba);   /* in the cache from now: off the list */
    if (was_empty >= 0) {
        m->empty[was_empty] = EXFAT_EMPTY_NONE;
    }
    exfat_cached_sector_t *slot = NULL;
    for (uint32_t i = 0; i < EXFAT_CACHE_SECTORS && slot == NULL; i++) {
        if (m->cache[i].valid && m->cache[i].lba == lba) {
            slot = &m->cache[i];
        }
    }
    for (uint32_t i = 0; i < EXFAT_CACHE_SECTORS && slot == NULL; i++) {
        if (!m->cache[i].valid) {
            slot = &m->cache[i];
        }
    }
    if (slot == NULL) {
        exfat_cached_sector_t *lru = NULL, *lru_empty = NULL;
        for (uint32_t i = 0; i < EXFAT_CACHE_SECTORS; i++) {
            exfat_cached_sector_t *const c = &m->cache[i];
            if (lru == NULL || c->stamp < lru->stamp) {
                lru = c;
            }
            if (!sector_has_live_entry(c->data) && (lru_empty == NULL || c->stamp < lru_empty->stamp)) {
                lru_empty = c;
            }
        }
        slot = lru_empty != NULL ? lru_empty : lru;
        m->evictions++;
        if (slot == lru_empty) {
            empty_add(m, slot->lba);
        }
    }
    slot->valid = true;
    slot->lba   = lba;
    slot->stamp = ++m->stamp;
    memcpy(slot->data, data, EXFAT_SECTOR_BYTES);
}

/* ---- entry sets ------------------------------------------------------ */

/* The checksum over a whole entry set, skipping its own field, with InUse forced on (a deleted set
 * still checks). */
static uint16_t set_checksum(const uint8_t *entries, uint32_t count)
{
    uint16_t sum = 0;
    for (uint32_t i = 0; i < count * ENTRY_BYTES; i++) {
        if (i == 2u || i == 3u) {
            continue;
        }
        uint8_t v = entries[i];
        if (i % ENTRY_BYTES == 0u) {
            v |= TYPE_IN_USE;
        }
        sum = (uint16_t)(((sum & 1u) ? 0x8000u : 0u) + (sum >> 1) + v);
    }
    return sum;
}

/* Finds the file entry sets in a view of `nsec` sectors; a set needing a sector the view lacks is
 * left out. */
static uint32_t parse_sets(const uint8_t *view, const bool *known, uint32_t nsec,
                           exfat_set_t *out, uint32_t max)
{
    const uint32_t total = nsec * ENTRIES_PER_SEC;
    uint32_t n = 0;
    uint32_t e = 0;
    while (e < total && n < max) {
        if (!known[e / ENTRIES_PER_SEC]) {
            e = (e / ENTRIES_PER_SEC + 1u) * ENTRIES_PER_SEC;
            continue;
        }
        const uint8_t *const p = &view[e * ENTRY_BYTES];
        /* 0x00 (end of directory) is skipped, not obeyed: a stale cached neighbour's end marker
         * must not hide later sets. */
        if ((p[0] & 0x7Fu) != TYPE_FILE) {
            e++;
            continue;
        }
        const uint32_t count = 1u + p[1];
        bool all_known = count >= 3u && e + count <= total;
        for (uint32_t k = 0; all_known && k < count; k++) {
            all_known = known[(e + k) / ENTRIES_PER_SEC];
        }
        if (!all_known) {
            e++;
            continue;
        }

        const uint8_t in_use = p[0] & TYPE_IN_USE;
        const uint8_t *const stream = p + ENTRY_BYTES;
        exfat_set_t s;
        memset(&s, 0, sizeof(s));
        s.pos           = e;
        s.count         = count;
        s.in_use        = in_use != 0u;
        s.directory     = (le16(&p[4]) & ATTR_DIRECTORY) != 0u;
        s.contiguous    = (stream[1] & 0x02u) != 0u;
        s.name_units    = stream[3];
        s.first_cluster = le32(&stream[20]);
        s.size          = le64(&stream[24]);

        const uint32_t name_entries = (s.name_units + 14u) / 15u;
        bool valid = stream[0] == (TYPE_STREAM | in_use) && name_entries >= 1u &&
                     2u + name_entries <= count;
        for (uint32_t k = 0; valid && k < name_entries; k++) {
            valid = p[(2u + k) * ENTRY_BYTES] == (TYPE_NAME | in_use);
        }
        s.valid = valid && set_checksum(p, count) == le16(&p[2]);
        out[n++] = s;
        e += s.valid ? count : 1u;
    }
    return n;
}

/* Finds the entry set that starts at entry `pos` of a view; NULL if none does. */
static const exfat_set_t *find_at(const exfat_set_t *sets, uint32_t n, uint32_t pos)
{
    for (uint32_t i = 0; i < n; i++) {
        if (sets[i].pos == pos) {
            return &sets[i];
        }
    }
    return NULL;
}

/* Copies a set's name, in UTF-16 code units, out of its name entries. */
static void set_units(const uint8_t *view, const exfat_set_t *s, uint16_t *units)
{
    for (uint32_t i = 0; i < s->name_units; i++) {
        const uint32_t entry = s->pos + 2u + i / 15u;
        units[i] = le16(&view[entry * ENTRY_BYTES + 2u + 2u * (i % 15u)]);
    }
}

/* Fills a state with what a set says: where it is, its file, size, flags and name. */
static void load_state(const uint8_t *view, const exfat_set_t *s, uint64_t base, exfat_state_t *st)
{
    const uint8_t *const p = &view[s->pos * ENTRY_BYTES];
    st->used          = true;
    st->fresh         = false;
    st->created       = le32(&p[8]);
    st->created_10ms  = p[20];
    st->lba           = base + s->pos / ENTRIES_PER_SEC;
    st->index         = s->pos % ENTRIES_PER_SEC;
    st->first_cluster = s->first_cluster;
    st->size          = s->size;
    st->directory     = s->directory;
    st->in_use        = s->in_use;
    st->name_units    = s->name_units;
    set_units(view, s, st->units);
}

/* A new-view set has the same name as a kept state. */
static bool same_name(exfat_model_t *m, const exfat_state_t *st, const exfat_set_t *ns)
{
    if (st->name_units != ns->name_units) {
        return false;
    }
    set_units(m->new_view, ns, m->units);
    return memcmp(st->units, m->units, st->name_units * sizeof(uint16_t)) == 0;
}

/* UTF-16 to UTF-8; an unpaired surrogate becomes U+FFFD. */
static void units_to_utf8(const uint16_t *u, uint32_t n, char *out)
{
    uint32_t o = 0;
    for (uint32_t i = 0; i < n && o < EXFAT_NAME_UTF8 - 5u; i++) {
        uint32_t c = u[i];
        if (c >= 0xD800u && c <= 0xDBFFu && i + 1u < n && u[i + 1u] >= 0xDC00u && u[i + 1u] <= 0xDFFFu) {
            c = 0x10000u + ((c - 0xD800u) << 10) + (u[i + 1u] - 0xDC00u);
            i++;
        } else if (c >= 0xD800u && c <= 0xDFFFu) {
            c = 0xFFFDu;
        }
        if (c < 0x80u) {
            out[o++] = (char)c;
        } else if (c < 0x800u) {
            out[o++] = (char)(0xC0u | (c >> 6));
            out[o++] = (char)(0x80u | (c & 0x3Fu));
        } else if (c < 0x10000u) {
            out[o++] = (char)(0xE0u | (c >> 12));
            out[o++] = (char)(0x80u | ((c >> 6) & 0x3Fu));
            out[o++] = (char)(0x80u | (c & 0x3Fu));
        } else {
            out[o++] = (char)(0xF0u | (c >> 18));
            out[o++] = (char)(0x80u | ((c >> 12) & 0x3Fu));
            out[o++] = (char)(0x80u | ((c >> 6) & 0x3Fu));
            out[o++] = (char)(0x80u | (c & 0x3Fu));
        }
    }
    out[o] = '\0';
}

/* Reports an event: `now` is a set in the new view, `before` a kept state; either may be NULL. */
static void report(exfat_model_t *m, exfat_event_type_t type, uint64_t base,
                   const exfat_set_t *now, const exfat_state_t *before, bool from_write)
{
    memset(&m->ev, 0, sizeof(m->ev));
    m->ev.type       = type;
    m->ev.from_write = from_write;
    if (now) {
        m->ev.lba           = base + now->pos / ENTRIES_PER_SEC;
        m->ev.index         = now->pos % ENTRIES_PER_SEC;
        m->ev.directory     = now->directory;
        m->ev.first_cluster = now->first_cluster;
        m->ev.size          = now->size;
        set_units(m->new_view, now, m->units);
        units_to_utf8(m->units, now->name_units, m->lookup_name);
        path_join(m, m->ev.lba, m->lookup_name, m->ev.name);
    }
    if (before) {
        if (!now) {
            m->ev.lba       = before->lba;
            m->ev.index     = before->index;
            m->ev.directory = before->directory;
        }
        m->ev.old_first_cluster = before->first_cluster;
        m->ev.old_size          = before->size;
        units_to_utf8(before->units, before->name_units, m->lookup_name);
        path_join(m, before->lba, m->lookup_name, m->ev.old_name);
        if (!now) {
            memcpy(m->ev.name, m->ev.old_name, sizeof(m->ev.name));
        }
    }
    emit(m);
}

/* ---- pending: slots whose set is being rewritten --------------------- */

/* Finds the pending state for the set at (lba, index); NULL if none. */
static exfat_state_t *pending_find(exfat_model_t *m, uint64_t lba, uint32_t index)
{
    for (uint32_t i = 0; i < EXFAT_PENDING; i++) {
        if (m->pending[i].used && m->pending[i].lba == lba && m->pending[i].index == index) {
            return &m->pending[i];
        }
    }
    return NULL;
}

/* Keeps a set's old state while it is rewritten, replacing its slot or the oldest. */
static void pending_keep(exfat_model_t *m, const exfat_state_t *st)
{
    exfat_state_t *slot = pending_find(m, st->lba, st->index);
    if (slot == NULL) {
        slot = &m->pending[m->pending_next];
        m->pending_next = (m->pending_next + 1u) % EXFAT_PENDING;
    }
    *slot = *st;
}

/* Takes the pending state for (lba, index) out of the table; false if there is none. */
static bool pending_take(exfat_model_t *m, uint64_t lba, uint32_t index, exfat_state_t *out)
{
    exfat_state_t *const slot = pending_find(m, lba, index);
    if (slot == NULL) {
        return false;
    }
    if (out) {
        *out = *slot;
    }
    slot->used = false;
    return true;
}

/* ---- fresh: files created empty, waiting for their data -------------- */

/* Notes a file created empty at (lba, index), replacing the oldest note when full. */
static void fresh_add(exfat_model_t *m, uint64_t lba, uint32_t index)
{
    m->fresh[m->fresh_next].used  = true;
    m->fresh[m->fresh_next].lba   = lba;
    m->fresh[m->fresh_next].index = index;
    m->fresh_next = (m->fresh_next + 1u) % EXFAT_PENDING;
}

/* Removes the note for (lba, index); true if there was one. */
static bool fresh_take(exfat_model_t *m, uint64_t lba, uint32_t index)
{
    for (uint32_t i = 0; i < EXFAT_PENDING; i++) {
        if (m->fresh[i].used && m->fresh[i].lba == lba && m->fresh[i].index == index) {
            m->fresh[i].used = false;
            return true;
        }
    }
    return false;
}

/* ---- comparing a directory sector's versions ------------------------- */

/* Gives the clusters a file of `size` bytes takes (at least 1, at most 0xFFFF). */
static uint32_t clusters_for(const exfat_model_t *m, uint64_t size)
{
    const uint64_t bytes = (uint64_t)EXFAT_SECTOR_BYTES << m->cluster_shift;
    const uint64_t c = (size + bytes - 1u) / bytes;
    return c == 0u ? 1u : (c > 0xFFFFu ? 0xFFFFu : (uint32_t)c);
}

/* Tracks a directory's set (its clusters, name and parent) for paths; a rename updates the name. */
static void note_directory(exfat_model_t *m, const exfat_set_t *s, uint64_t base)
{
    if (!(s->valid && s->in_use && s->directory)) {
        return;
    }
    const int i = add_directory(m, s->first_cluster, s->contiguous ? clusters_for(m, s->size) : 1u);
    if (i < 0 || m->dirs[i].first == m->root_cluster) {
        return;
    }
    exfat_dir_extent_t *const d = &m->dirs[i];
    const int holder = directory_index(m, base + s->pos / ENTRIES_PER_SEC);
    d->parent = holder >= 0 ? m->dirs[holder].first : 0u;
    set_units(m->new_view, s, m->units);
    units_to_utf8(m->units, s->name_units, m->lookup_name);
    size_t len = strlen(m->lookup_name);
    if (len >= EXFAT_DIR_NAME_BYTES) {
        len = EXFAT_DIR_NAME_BYTES - 1u;
    }
    memcpy(d->name, m->lookup_name, len);
    d->name[len] = '\0';
    d->named = true;
}

/* Adds a set to this update's deleted list, counting it when the list is full. */
static void add_deleted(exfat_model_t *m, uint32_t *n, const exfat_state_t *st)
{
    if (*n < EXFAT_MAX_CHANGES) {
        m->deleted[(*n)++] = *st;
    } else {
        m->changes_full++;
    }
}

/* Adds a set to this update's created list, counting it when the list is full. */
static void add_created(exfat_model_t *m, uint32_t *n, const exfat_set_t *s)
{
    if (*n < EXFAT_MAX_CHANGES) {
        m->created[(*n)++] = s;
    } else {
        m->changes_full++;
    }
}

/* Compares `n` new directory sectors from `first` with their cached versions, one sector either
 * side for whole sets. */
static void directory_update(exfat_model_t *m, uint64_t first, const uint8_t *data, uint32_t n,
                             bool from_write)
{
    const uint64_t base = first - 1u;
    const uint32_t nsec = n + 2u;
    for (uint32_t s = 0; s < nsec; s++) {
        const uint64_t lba = base + s;
        const exfat_cached_sector_t *const c = cache_find(m, lba);
        const uint8_t *const old_at = &m->old_view[s * EXFAT_SECTOR_BYTES];
        m->old_known[s] = c != NULL || empty_find(m, lba) >= 0;   /* an empty one: all zero below */
        if (c) {
            memcpy(&m->old_view[s * EXFAT_SECTOR_BYTES], c->data, EXFAT_SECTOR_BYTES);
        } else {
            memset(&m->old_view[s * EXFAT_SECTOR_BYTES], 0, EXFAT_SECTOR_BYTES);
        }
        if (s >= 1u && s <= n) {
            memcpy(&m->new_view[s * EXFAT_SECTOR_BYTES], &data[(s - 1u) * EXFAT_SECTOR_BYTES],
                   EXFAT_SECTOR_BYTES);
            m->new_known[s] = true;
        } else {
            memcpy(&m->new_view[s * EXFAT_SECTOR_BYTES], old_at, EXFAT_SECTOR_BYTES);
            m->new_known[s] = m->old_known[s];
        }
    }

    /* The bitmap (0x81) and up-case (0x82) entries say where those structures are, so their sectors
     * can be named. */
    for (uint32_t s = 1u; s <= n; s++) {
        for (uint32_t k = 0; k < ENTRIES_PER_SEC; k++) {
            const uint8_t *const p = &m->new_view[(s * ENTRIES_PER_SEC + k) * ENTRY_BYTES];
            if (p[0] == 0x81u || p[0] == 0x82u) {
                const uint32_t first    = le32(&p[20]);
                const uint32_t clusters = clusters_for(m, le64(&p[24]));
                if (p[0] == 0x81u) {
                    m->bitmap_first    = first;
                    m->bitmap_clusters = clusters;
                } else {
                    m->upcase_first    = first;
                    m->upcase_clusters = clusters;
                }
            }
        }
    }

    const uint32_t n_old = parse_sets(m->old_view, m->old_known, nsec, m->old_sets, EXFAT_MAX_SETS);
    const uint32_t n_new = parse_sets(m->new_view, m->new_known, nsec, m->new_sets, EXFAT_MAX_SETS);
    const uint32_t compare_below = (n + 1u) * ENTRIES_PER_SEC;   /* first entries in sectors 0..n */
    uint32_t n_deleted = 0, n_created = 0;

    for (uint32_t i = 0; i < n_new; i++) {
        const exfat_set_t *const ns = &m->new_sets[i];
        if (ns->pos >= compare_below) {
            continue;
        }
        const uint64_t lba   = base + ns->pos / ENTRIES_PER_SEC;
        const uint32_t index = ns->pos % ENTRIES_PER_SEC;
        const exfat_set_t *const os = find_at(m->old_sets, n_old, ns->pos);

        if (!ns->valid) {
            /* Being rewritten, or half outside this transfer: keep the last good state and wait for
             * a good one. */
            if (os && os->valid && os->in_use) {
                load_state(m->old_view, os, base, &m->before);
                pending_keep(m, &m->before);
            }
            m->bad_sets++;
            continue;
        }
        note_directory(m, ns, base);

        if (!m->old_known[ns->pos / ENTRIES_PER_SEC]) {
            (void)pending_take(m, lba, index, NULL);
            if (ns->in_use) {
                report(m, EXFAT_EV_EXISTING, base, ns, NULL, from_write);
            }
            continue;
        }

        bool have_before;
        if (os && os->valid) {
            load_state(m->old_view, os, base, &m->before);
            (void)pending_take(m, lba, index, NULL);   /* superseded */
            have_before = true;
        } else {
            have_before = pending_take(m, lba, index, &m->before);
        }

        if (!have_before || !m->before.in_use) {
            if (ns->in_use) {
                add_created(m, &n_created, ns);
            }
        } else if (!ns->in_use) {
            m->before.fresh = fresh_take(m, lba, index);
            add_deleted(m, &n_deleted, &m->before);
        } else if (!same_name(m, &m->before, ns)) {
            /* The same file renamed in place: the same data, or for an empty file the same creation time. */
            const uint8_t *const np = &m->new_view[ns->pos * ENTRY_BYTES];
            const bool same_file = m->before.first_cluster == ns->first_cluster &&
                                   (ns->first_cluster != 0u || m->before.created == 0u ||
                                    (m->before.created == le32(&np[8]) && m->before.created_10ms == np[20]));
            if (same_file) {
                const bool was_fresh = fresh_take(m, lba, index);
                report(m, EXFAT_EV_RENAME, base, ns, &m->before, from_write);
                if (was_fresh) {
                    fresh_add(m, lba, index);   /* renamed while empty: still waiting for its data */
                }
            } else {
                m->before.fresh = fresh_take(m, lba, index);
                /* A different file in the slot: the old one is gone. */
                add_deleted(m, &n_deleted, &m->before);
                add_created(m, &n_created, ns);
            }
        } else if (m->before.first_cluster != ns->first_cluster || m->before.size != ns->size) {
            /* A file seen created empty getting data, or growing from the same cluster in whole
             * clusters, is still being created. */
            const uint64_t cluster_bytes = (uint64_t)EXFAT_SECTOR_BYTES << m->cluster_shift;
            const bool was_fresh  = fresh_take(m, lba, index);
            const bool first_data = m->before.first_cluster == 0u && m->before.size == 0u && ns->size != 0u;
            const bool more_data  = m->before.first_cluster != 0u &&
                                    m->before.first_cluster == ns->first_cluster &&
                                    m->before.size < ns->size && m->before.size % cluster_bytes == 0u;
            const bool filled = was_fresh && (first_data || more_data);
            if (filled && ns->size % cluster_bytes == 0u) {
                fresh_add(m, lba, index);   /* may still be growing */
            }
            report(m, filled ? EXFAT_EV_CREATE_FILLED : EXFAT_EV_MODIFY, base, ns, &m->before,
                   from_write);
        }
    }

    /* In use before, and no set starts at that slot now. */
    for (uint32_t i = 0; i < n_old; i++) {
        const exfat_set_t *const os = &m->old_sets[i];
        if (os->pos >= compare_below || !os->valid || !os->in_use ||
            !m->new_known[os->pos / ENTRIES_PER_SEC] ||
            find_at(m->new_sets, n_new, os->pos) != NULL) {
            continue;
        }
        load_state(m->old_view, os, base, &m->before);
        (void)pending_take(m, m->before.lba, m->before.index, NULL);
        m->before.fresh = fresh_take(m, m->before.lba, m->before.index);
        add_deleted(m, &n_deleted, &m->before);
    }

    /* A creation with the same data as a deletion is a rename (with the same name, a move inside
     * the directory: not reported); an empty file, with no data, by its creation timestamp. */
    for (uint32_t c = 0; c < n_created; c++) {
        const exfat_set_t *const ns = m->created[c];
        const uint8_t *const np = &m->new_view[ns->pos * ENTRY_BYTES];
        const bool empty = ns->first_cluster == 0u && ns->size == 0u;
        bool paired = false;
        for (uint32_t d = 0; d < n_deleted && !paired; d++) {
            exfat_state_t *const st = &m->deleted[d];
            const bool same_data = !empty && st->first_cluster == ns->first_cluster && st->size == ns->size;
            const bool same_empty = empty && st->first_cluster == 0u && st->size == 0u && le32(&np[8]) != 0u &&
                                    st->created == le32(&np[8]) && st->created_10ms == np[20];
            if (st->used && (same_data || same_empty) && st->directory == ns->directory) {
                if (!same_name(m, st, ns)) {
                    report(m, EXFAT_EV_RENAME, base, ns, st, from_write);
                }
                if (st->fresh) {
                    fresh_add(m, base + ns->pos / ENTRIES_PER_SEC, ns->pos % ENTRIES_PER_SEC);
                }
                st->used = false;
                paired = true;
            }
        }
        if (!paired) {
            report(m, EXFAT_EV_CREATE, base, ns, NULL, from_write);
            if (ns->first_cluster == 0u && ns->size == 0u && !ns->directory) {
                fresh_add(m, base + ns->pos / ENTRIES_PER_SEC, ns->pos % ENTRIES_PER_SEC);
            }
        }
    }
    for (uint32_t d = 0; d < n_deleted; d++) {
        const exfat_state_t *const st = &m->deleted[d];
        if (st->used) {
            report(m, EXFAT_EV_DELETE, base, NULL, st, from_write);
            const int holder = directory_index(m, st->lba);
            if (st->directory && holder >= 0) {
                forget_directory(m, st->first_cluster, m->dirs[holder].first);
            }
        }
    }

    for (uint32_t s = 1u; s <= n; s++) {
        cache_store(m, base + s, &data[(s - 1u) * EXFAT_SECTOR_BYTES]);
    }
}

/* Says which part of the volume a sector is in: boot region, FAT, bitmap, up-case table, directory or none. */
exfat_area_t exfat_model_area_at(const exfat_model_t *m, uint64_t lba)
{
    if (!known(m) || lba < m->boot_lba) {
        return EXFAT_AREA_NONE;
    }
    if (lba < m->boot_lba + 24u) {
        return EXFAT_AREA_BOOT;
    }
    if (m->fat_length != 0u && lba >= m->boot_lba + m->fat_offset &&
        lba < (uint64_t)m->boot_lba + m->fat_offset + m->fat_length) {
        return EXFAT_AREA_FAT;
    }
    if (lba < m->heap_lba) {
        return EXFAT_AREA_NONE;
    }
    const uint64_t cluster = 2u + ((lba - m->heap_lba) >> m->cluster_shift);
    if (m->bitmap_clusters != 0u && cluster >= m->bitmap_first &&
        cluster < (uint64_t)m->bitmap_first + m->bitmap_clusters) {
        return EXFAT_AREA_BITMAP;
    }
    if (m->upcase_clusters != 0u && cluster >= m->upcase_first &&
        cluster < (uint64_t)m->upcase_first + m->upcase_clusters) {
        return EXFAT_AREA_UPCASE;
    }
    return exfat_model_is_directory(m, lba) ? EXFAT_AREA_DIRECTORY : EXFAT_AREA_NONE;
}

/* Gives an area's name as the console prints it. */
const char *exfat_model_area_name(exfat_area_t area)
{
    switch (area) {
    case EXFAT_AREA_BOOT:      return "boot region";
    case EXFAT_AREA_FAT:       return "FAT";
    case EXFAT_AREA_BITMAP:    return "allocation bitmap";
    case EXFAT_AREA_UPCASE:    return "up-case table";
    case EXFAT_AREA_DIRECTORY: return "directory";
    case EXFAT_AREA_NONE:
    default:                   return "none";
    }
}

/* Finds the file whose clusters hold a sector, from the cached directory sectors: its path, size
 * and kind. */
bool exfat_model_file_at(exfat_model_t *m, uint64_t lba, char *name, uint32_t name_size,
                         uint64_t *size, bool *directory)
{
    if (!known(m) || lba < m->heap_lba || name_size == 0u) {
        return false;
    }
    const uint64_t cluster = 2u + ((lba - m->heap_lba) >> m->cluster_shift);
    for (uint32_t i = 0; i < EXFAT_CACHE_SECTORS; i++) {
        const exfat_cached_sector_t *const c = &m->cache[i];
        if (!c->valid) {
            continue;
        }
        /* This sector and the next, so a set starting here is whole. */
        const exfat_cached_sector_t *const next = cache_find(m, c->lba + 1u);
        memcpy(m->new_view, c->data, EXFAT_SECTOR_BYTES);
        m->new_known[0] = true;
        if (next) {
            memcpy(&m->new_view[EXFAT_SECTOR_BYTES], next->data, EXFAT_SECTOR_BYTES);
        }
        m->new_known[1] = next != NULL;
        const uint32_t n = parse_sets(m->new_view, m->new_known, 2u, m->new_sets, EXFAT_MAX_SETS);
        for (uint32_t k = 0; k < n; k++) {
            const exfat_set_t *const s = &m->new_sets[k];
            if (s->pos >= ENTRIES_PER_SEC || !s->valid || !s->in_use || s->first_cluster < 2u) {
                continue;
            }
            const uint64_t clusters = s->contiguous ? clusters_for(m, s->size) : 1u;
            if (cluster >= s->first_cluster && cluster < (uint64_t)s->first_cluster + clusters) {
                set_units(m->new_view, s, m->units);
                units_to_utf8(m->units, s->name_units, m->lookup_name);
                path_join(m, c->lba, m->lookup_name, m->joined);
                size_t len = strlen(m->joined);
                if (len >= name_size) {
                    len = name_size - 1u;
                }
                memcpy(name, m->joined, len);
                name[len] = '\0';
                *size = s->size;
                *directory = s->directory;
                return true;
            }
        }
    }
    return false;
}

/* Takes one decoded transfer: a boot sector sets the volume, directory sectors are compared and cached. */
void exfat_model_feed(exfat_model_t *m, uint64_t lba, const uint8_t *data, uint32_t blocks,
                      bool from_write)
{
    if (blocks > EXFAT_MAX_BLOCKS) {
        blocks = EXFAT_MAX_BLOCKS;
    }
    m->sectors += blocks;

    for (uint32_t i = 0; i < blocks; i++) {
        const uint8_t *const sec = &data[i * EXFAT_SECTOR_BYTES];
        if (main_boot_sector(m, lba + i, sec)) {
            boot_sector(m, lba + i, sec, blocks - i, from_write);
        }
    }
    if (!known(m)) {
        return;   /* no volume, or one not confirmed by this insertion's boot sector */
    }
    uint32_t i = 0;
    while (i < blocks) {
        if (!exfat_model_is_directory(m, lba + i)) {
            i++;
            continue;
        }
        uint32_t j = i;
        while (j < blocks && exfat_model_is_directory(m, lba + j)) {
            j++;
        }
        m->dir_sectors += j - i;
        if (run_is_cached(m, lba + i, &data[i * EXFAT_SECTOR_BYTES], j - i)) {
            m->dir_sectors_same += j - i;   /* nothing can have changed */
        } else {
            directory_update(m, lba + i, &data[i * EXFAT_SECTOR_BYTES], j - i, from_write);
        }
        i = j;
    }
}

/* ---- snapshots ------------------------------------------------------- */

/* The snapshot's layout (all little-endian; see exfat_model.h):
 *   header  "EXFS" | version u16 | reserved u16 | body length u32
 *   volume  have_volume u8 | boot_lba u64 | heap_lba u64 | cluster_shift u8 |
 *           cluster_count, root_cluster, serial, fat_offset, fat_length,
 *           bitmap_first, bitmap_clusters, upcase_first, upcase_clusters u32 |
 *           stamp, pending_next, fresh_next u32                     (66 bytes)
 *   dirs    count u32, then each: first, clusters, parent u32 | named u8 |
 *           name[EXFAT_DIR_NAME_BYTES]
 *   cache   count u32, then each valid slot: slot u32 | lba u64 | stamp u32 |
 *           data[512]
 *   pending count u32, then each used slot: slot u32 | lba u64 | index,
 *           first_cluster u32 | size u64 | directory, in_use, name_units u8 |
 *           units[EXFAT_NAME_UNITS] u16
 *   fresh   count u32, then each used slot: slot u32 | lba u64 | index u32
 *   empty   next u32 | count u32, then each used slot: slot u32 | offset u32
 *           (version 2 on; a version 1 snapshot ends after fresh)
 *   SHA-256 of everything above                                           */

/* The snapshot's header: "EXFS", the format version and the body's length. */
#define SNAP_HEADER_BYTES 12u

/* A snapshot being written: bytes go to the sink as they are made, and into the digest. */
typedef struct {
    exfat_snapshot_sink_t sink;
    void                 *ctx;
    sha256_ctx_t          sha;
    uint32_t              n;
} snap_writer_t;

/* Sends bytes to the snapshot's sink and adds them to its digest. */
static void put_bytes(snap_writer_t *w, const void *src, uint32_t len)
{
    sha256_update(&w->sha, src, len);
    w->sink(w->ctx, src, len);
    w->n += len;
}

/* Writes a field of `bytes` bytes, little-endian. */
static void put_le(snap_writer_t *w, uint64_t v, uint32_t bytes)
{
    uint8_t b[8];
    for (uint32_t i = 0; i < bytes; i++) {
        b[i] = (uint8_t)(v >> (8u * i));
    }
    put_bytes(w, b, bytes);
}

/* A snapshot being read: bytes asked of the source as needed, into the digest; nothing past `left`
 * is read. */
typedef struct {
    exfat_snapshot_source_t source;
    void                   *ctx;
    sha256_ctx_t            sha;
    uint32_t                left;
    bool                    ok;
} snap_reader_t;

/* Reads bytes from the snapshot's source into the digest; false once anything is short. */
static bool get_bytes(snap_reader_t *r, void *dst, uint32_t len)
{
    if (!r->ok || r->left < len || !r->source(r->ctx, dst, len)) {
        r->ok = false;
        return false;
    }
    sha256_update(&r->sha, dst, len);
    r->left -= len;
    return true;
}

/* Reads a little-endian field of `bytes` bytes (0 if the read failed). */
static uint64_t get_le(snap_reader_t *r, uint32_t bytes)
{
    uint8_t b[8];
    uint64_t v = 0;
    if (get_bytes(r, b, bytes)) {
        for (uint32_t i = 0; i < bytes; i++) {
            v |= (uint64_t)b[i] << (8u * i);
        }
    }
    return v;
}

/* A flag byte: 0 or 1, anything else makes the snapshot malformed. */
static bool get_flag(snap_reader_t *r)
{
    const uint64_t v = get_le(r, 1u);
    if (v > 1u) {
        r->ok = false;
    }
    return v == 1u;
}

/* Counts the cached sectors in use. */
static uint32_t used_cache(const exfat_model_t *m)
{
    uint32_t n = 0;
    for (uint32_t i = 0; i < EXFAT_CACHE_SECTORS; i++) {
        n += m->cache[i].valid ? 1u : 0u;
    }
    return n;
}

/* Counts the pending states in use. */
static uint32_t used_pending(const exfat_model_t *m)
{
    uint32_t n = 0;
    for (uint32_t i = 0; i < EXFAT_PENDING; i++) {
        n += m->pending[i].used ? 1u : 0u;
    }
    return n;
}

/* Counts the fresh-file notes in use. */
static uint32_t used_fresh(const exfat_model_t *m)
{
    uint32_t n = 0;
    for (uint32_t i = 0; i < EXFAT_PENDING; i++) {
        n += m->fresh[i].used ? 1u : 0u;
    }
    return n;
}

/* Counts the empty sectors remembered. */
static uint32_t used_empty(const exfat_model_t *m)
{
    uint32_t n = 0;
    for (uint32_t i = 0; i < EXFAT_EMPTY_SECTORS; i++) {
        n += m->empty[i] != EXFAT_EMPTY_NONE ? 1u : 0u;
    }
    return n;
}

/* Gives the snapshot body's length for the model as it is now. */
static uint32_t snapshot_body_bytes(const exfat_model_t *m)
{
    return 66u + 4u + m->ndirs * (13u + EXFAT_DIR_NAME_BYTES) + 4u + used_cache(m) * (16u + EXFAT_SECTOR_BYTES) +
           4u + used_pending(m) * (31u + 2u * EXFAT_NAME_UNITS) + 4u + used_fresh(m) * 16u +
           8u + used_empty(m) * 8u;
}

/* Gives the whole snapshot's length: header, body and digest. */
uint32_t exfat_model_snapshot_bytes(const exfat_model_t *m)
{
    return SNAP_HEADER_BYTES + snapshot_body_bytes(m) + SHA256_DIGEST_SIZE;
}

/* Streams the model to `sink` as a snapshot and gives its digest; returns the bytes written. */
uint32_t exfat_model_snapshot_write(const exfat_model_t *m, exfat_snapshot_sink_t sink, void *ctx,
                                    uint8_t digest[SHA256_DIGEST_SIZE])
{
    static snap_writer_t w;   /* static: the SHA-256 state is ~100 bytes, and core0's stack is small */
    w.sink = sink;
    w.ctx  = ctx;
    w.n    = 0u;
    sha256_init(&w.sha);
    put_bytes(&w, "EXFS", 4u);
    put_le(&w, EXFAT_SNAPSHOT_VERSION, 2u);
    put_le(&w, 0u, 2u);
    put_le(&w, snapshot_body_bytes(m), 4u);

    put_le(&w, m->have_volume ? 1u : 0u, 1u);
    put_le(&w, m->boot_lba, 8u);
    put_le(&w, m->heap_lba, 8u);
    put_le(&w, m->cluster_shift, 1u);
    put_le(&w, m->cluster_count, 4u);
    put_le(&w, m->root_cluster, 4u);
    put_le(&w, m->serial, 4u);
    put_le(&w, m->fat_offset, 4u);
    put_le(&w, m->fat_length, 4u);
    put_le(&w, m->bitmap_first, 4u);
    put_le(&w, m->bitmap_clusters, 4u);
    put_le(&w, m->upcase_first, 4u);
    put_le(&w, m->upcase_clusters, 4u);
    put_le(&w, m->stamp, 4u);
    put_le(&w, m->pending_next, 4u);
    put_le(&w, m->fresh_next, 4u);

    put_le(&w, m->ndirs, 4u);
    for (uint32_t i = 0; i < m->ndirs; i++) {
        const exfat_dir_extent_t *const d = &m->dirs[i];
        put_le(&w, d->first, 4u);
        put_le(&w, d->clusters, 4u);
        put_le(&w, d->parent, 4u);
        put_le(&w, d->named ? 1u : 0u, 1u);
        put_bytes(&w, d->name, EXFAT_DIR_NAME_BYTES);
    }

    put_le(&w, used_cache(m), 4u);
    for (uint32_t i = 0; i < EXFAT_CACHE_SECTORS; i++) {
        const exfat_cached_sector_t *const c = &m->cache[i];
        if (c->valid) {
            put_le(&w, i, 4u);
            put_le(&w, c->lba, 8u);
            put_le(&w, c->stamp, 4u);
            put_bytes(&w, c->data, EXFAT_SECTOR_BYTES);
        }
    }

    put_le(&w, used_pending(m), 4u);
    for (uint32_t i = 0; i < EXFAT_PENDING; i++) {
        const exfat_state_t *const st = &m->pending[i];
        if (st->used) {
            put_le(&w, i, 4u);
            put_le(&w, st->lba, 8u);
            put_le(&w, st->index, 4u);
            put_le(&w, st->first_cluster, 4u);
            put_le(&w, st->size, 8u);
            put_le(&w, st->directory ? 1u : 0u, 1u);
            put_le(&w, st->in_use ? 1u : 0u, 1u);
            put_le(&w, st->name_units, 1u);
            for (uint32_t k = 0; k < EXFAT_NAME_UNITS; k++) {
                put_le(&w, st->units[k], 2u);
            }
        }
    }

    put_le(&w, used_fresh(m), 4u);
    for (uint32_t i = 0; i < EXFAT_PENDING; i++) {
        if (m->fresh[i].used) {
            put_le(&w, i, 4u);
            put_le(&w, m->fresh[i].lba, 8u);
            put_le(&w, m->fresh[i].index, 4u);
        }
    }

    put_le(&w, m->empty_next, 4u);
    put_le(&w, used_empty(m), 4u);
    for (uint32_t i = 0; i < EXFAT_EMPTY_SECTORS; i++) {
        if (m->empty[i] != EXFAT_EMPTY_NONE) {
            put_le(&w, i, 4u);
            put_le(&w, m->empty[i], 4u);
        }
    }

    sha256_final(&w.sha, digest);
    sink(ctx, digest, SHA256_DIGEST_SIZE);
    return w.n + SHA256_DIGEST_SIZE;
}

/* The buffer form: a sink that copies, refusing (and remembering it) past `cap`. */
typedef struct {
    uint8_t *p;
    uint32_t n, cap;
    bool     ok;
} snap_buffer_t;

/* A sink that copies into a buffer, failing when it is full. */
static void buffer_sink(void *ctx, const uint8_t *bytes, uint32_t len)
{
    snap_buffer_t *const b = ctx;
    if (!b->ok || b->cap - b->n < len) {
        b->ok = false;
        return;
    }
    memcpy(&b->p[b->n], bytes, len);
    b->n += len;
}

/* A source that reads from a buffer, failing at its end. */
static bool buffer_source(void *ctx, uint8_t *bytes, uint32_t len)
{
    snap_buffer_t *const b = ctx;
    if (b->cap - b->n < len) {
        return false;
    }
    memcpy(bytes, &b->p[b->n], len);
    b->n += len;
    return true;
}

/* Saves the model into a buffer; returns the bytes, or 0 if it does not fit. */
uint32_t exfat_model_snapshot_save(const exfat_model_t *m, uint8_t *out, uint32_t cap)
{
    if (exfat_model_snapshot_bytes(m) > cap) {
        return 0u;
    }
    snap_buffer_t b = { out, 0u, cap, true };
    uint8_t digest[SHA256_DIGEST_SIZE];
    const uint32_t n = exfat_model_snapshot_write(m, buffer_sink, &b, digest);
    return b.ok && b.n == n ? n : 0u;
}

/* Fills a fresh model from a snapshot's body; false if anything is out of place (the caller checks
 * the digest). */
static bool snapshot_parse(exfat_model_t *m, snap_reader_t *r)
{
    uint8_t head[SNAP_HEADER_BYTES];
    r->left = SNAP_HEADER_BYTES;
    if (!get_bytes(r, head, SNAP_HEADER_BYTES) || memcmp(head, "EXFS", 4u) != 0 ||
        (le16(&head[4]) != 1u && le16(&head[4]) != EXFAT_SNAPSHOT_VERSION) || le16(&head[6]) != 0u ||
        le32(&head[8]) > EXFAT_SNAPSHOT_MAX_BYTES - SNAP_HEADER_BYTES - SHA256_DIGEST_SIZE) {
        return false;
    }
    r->left = le32(&head[8]);

    m->have_volume     = get_flag(r);
    m->boot_lba        = get_le(r, 8u);
    m->heap_lba        = get_le(r, 8u);
    m->cluster_shift   = (uint32_t)get_le(r, 1u);
    m->cluster_count   = (uint32_t)get_le(r, 4u);
    m->root_cluster    = (uint32_t)get_le(r, 4u);
    m->serial          = (uint32_t)get_le(r, 4u);
    m->fat_offset      = (uint32_t)get_le(r, 4u);
    m->fat_length      = (uint32_t)get_le(r, 4u);
    m->bitmap_first    = (uint32_t)get_le(r, 4u);
    m->bitmap_clusters = (uint32_t)get_le(r, 4u);
    m->upcase_first    = (uint32_t)get_le(r, 4u);
    m->upcase_clusters = (uint32_t)get_le(r, 4u);
    m->stamp           = (uint32_t)get_le(r, 4u);
    m->pending_next    = (uint32_t)get_le(r, 4u);
    m->fresh_next      = (uint32_t)get_le(r, 4u);
    if (!r->ok || m->cluster_shift > 16u || m->pending_next >= EXFAT_PENDING ||
        m->fresh_next >= EXFAT_PENDING) {
        return false;
    }

    const uint64_t ndirs = get_le(r, 4u);
    if (ndirs > EXFAT_MAX_DIRS) {
        return false;
    }
    for (uint32_t i = 0; r->ok && i < ndirs; i++) {
        exfat_dir_extent_t *const d = &m->dirs[i];
        d->first    = (uint32_t)get_le(r, 4u);
        d->clusters = (uint32_t)get_le(r, 4u);
        d->parent   = (uint32_t)get_le(r, 4u);
        d->named    = get_flag(r);
        if (!get_bytes(r, d->name, EXFAT_DIR_NAME_BYTES) || memchr(d->name, 0, EXFAT_DIR_NAME_BYTES) == NULL ||
            d->first < 2u || d->clusters == 0u) {
            return false;
        }
        for (uint32_t k = 0; k < i; k++) {
            if (m->dirs[k].first == d->first) {
                return false;
            }
        }
    }
    m->ndirs = (uint32_t)ndirs;

    uint64_t count = get_le(r, 4u);
    if (count > EXFAT_CACHE_SECTORS) {
        return false;
    }
    for (uint32_t i = 0; r->ok && i < count; i++) {
        const uint64_t slot = get_le(r, 4u);
        const uint64_t lba  = get_le(r, 8u);
        const uint64_t st   = get_le(r, 4u);
        if (!r->ok || slot >= EXFAT_CACHE_SECTORS || m->cache[slot].valid || cache_find(m, lba) != NULL ||
            st > m->stamp) {
            return false;
        }
        exfat_cached_sector_t *const c = &m->cache[slot];
        if (!get_bytes(r, c->data, EXFAT_SECTOR_BYTES)) {
            return false;
        }
        c->valid = true;
        c->lba   = lba;
        c->stamp = (uint32_t)st;
    }

    count = get_le(r, 4u);
    if (count > EXFAT_PENDING) {
        return false;
    }
    exfat_state_t *const st = &m->before;   /* scratch: 0.5 KB kept off core0's stack */
    for (uint32_t i = 0; r->ok && i < count; i++) {
        const uint64_t slot = get_le(r, 4u);
        memset(st, 0, sizeof(*st));
        st->used          = true;
        st->lba           = get_le(r, 8u);
        st->index         = (uint32_t)get_le(r, 4u);
        st->first_cluster = (uint32_t)get_le(r, 4u);
        st->size          = get_le(r, 8u);
        st->directory     = get_flag(r);
        st->in_use        = get_flag(r);
        st->name_units    = (uint8_t)get_le(r, 1u);
        for (uint32_t k = 0; k < EXFAT_NAME_UNITS; k++) {
            st->units[k] = (uint16_t)get_le(r, 2u);
        }
        if (!r->ok || slot >= EXFAT_PENDING || m->pending[slot].used ||
            st->index >= ENTRIES_PER_SEC || pending_find(m, st->lba, st->index) != NULL) {
            return false;
        }
        m->pending[slot] = *st;
    }
    memset(st, 0, sizeof(*st));

    count = get_le(r, 4u);
    if (count > EXFAT_PENDING) {
        return false;
    }
    for (uint32_t i = 0; r->ok && i < count; i++) {
        const uint64_t slot  = get_le(r, 4u);
        const uint64_t lba   = get_le(r, 8u);
        const uint64_t index = get_le(r, 4u);
        if (!r->ok || slot >= EXFAT_PENDING || m->fresh[slot].used || index >= ENTRIES_PER_SEC) {
            return false;
        }
        for (uint32_t k = 0; k < EXFAT_PENDING; k++) {
            if (m->fresh[k].used && m->fresh[k].lba == lba && m->fresh[k].index == index) {
                return false;
            }
        }
        m->fresh[slot].used  = true;
        m->fresh[slot].lba   = lba;
        m->fresh[slot].index = (uint32_t)index;
    }

    if (le16(&head[4]) == 1u) {
        return r->ok && r->left == 0u;   /* version 1: no empty sectors known */
    }
    m->empty_next = (uint32_t)get_le(r, 4u);
    count = get_le(r, 4u);
    if (!r->ok || m->empty_next >= EXFAT_EMPTY_SECTORS || count > EXFAT_EMPTY_SECTORS) {
        return false;
    }
    for (uint32_t i = 0; r->ok && i < count; i++) {
        const uint64_t slot   = get_le(r, 4u);
        const uint64_t offset = get_le(r, 4u);
        if (!r->ok || slot >= EXFAT_EMPTY_SECTORS || m->empty[slot] != EXFAT_EMPTY_NONE ||
            offset == EXFAT_EMPTY_NONE || empty_find(m, m->heap_lba + offset) >= 0 ||
            cache_find(m, m->heap_lba + offset) != NULL) {
            return false;
        }
        m->empty[slot] = (uint32_t)offset;
    }
    return r->ok && r->left == 0u;
}

/* Loads the model from a snapshot stream if its digest matches; otherwise leaves it empty. */
bool exfat_model_snapshot_read(exfat_model_t *m, exfat_snapshot_source_t source, void *ctx,
                               uint8_t digest[SHA256_DIGEST_SIZE])
{
    const exfat_event_cb_t cb   = m->cb;
    void *const            cctx = m->ctx;
    exfat_model_init(m, cb, cctx);
    m->dirs_version = 1u;   /* differs from a fresh model's 0 */
    static snap_reader_t r;   /* static, as the writer's */
    r.source = source;
    r.ctx    = ctx;
    r.ok     = true;
    sha256_init(&r.sha);
    if (snapshot_parse(m, &r)) {
        uint8_t stored[SHA256_DIGEST_SIZE];
        sha256_final(&r.sha, digest);
        if (source(ctx, stored, SHA256_DIGEST_SIZE) && memcmp(stored, digest, SHA256_DIGEST_SIZE) == 0) {
            return true;
        }
    }
    exfat_model_init(m, cb, cctx);
    memset(digest, 0, SHA256_DIGEST_SIZE);
    return false;
}

/* Loads the model from a buffer holding exactly one snapshot; otherwise leaves it empty. */
bool exfat_model_snapshot_load(exfat_model_t *m, const uint8_t *in, uint32_t len)
{
    snap_buffer_t b = { (uint8_t *)in, 0u, len, true };
    uint8_t digest[SHA256_DIGEST_SIZE];
    if (exfat_model_snapshot_read(m, buffer_source, &b, digest) && b.n == len) {
        return true;
    }
    exfat_model_init(m, m->cb, m->ctx);   /* a byte left over: refused too */
    return false;
}
