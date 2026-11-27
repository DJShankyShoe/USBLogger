/*
 * File names from exFAT metadata sectors (core0): fed the boot sector and every directory sector seen on
 * the bus, it keeps the volume layout, the directories and the last version of each directory sector, and
 * reports what changed (create, delete, rename, modify) with each file's path, e.g. \test\rip\rot.txt.
 * An entry set counts only if its SetChecksum matches; one that stops matching is being rewritten, not
 * deleted. A sector seen for the first time gives EXISTING, never CREATE. No SDK headers.
 */
#ifndef EXFAT_MODEL_H
#define EXFAT_MODEL_H

/* bool and the fixed-width integers. */
#include <stdbool.h>
#include <stdint.h>

#define EXFAT_SECTOR_BYTES   512u    /* exFAT sectors are 512 bytes on this drive */
#define EXFAT_MAX_BLOCKS     16u     /* the largest transfer fed at once */
#define EXFAT_CACHE_SECTORS  32u     /* directory sectors remembered (those with entries kept longest) */
#define EXFAT_EMPTY_SECTORS  64u     /* directory sectors with no entry in use, remembered by LBA alone */
#define EXFAT_MAX_DIRS       32u     /* directory extents tracked */
#define EXFAT_PENDING        16u     /* slots whose set is being rewritten */
#define EXFAT_MAX_CHANGES    16u     /* creations and deletions paired per transfer */
#define EXFAT_NAME_UNITS     255u    /* UTF-16 units in a name */
#define EXFAT_NAME_UTF8      (EXFAT_NAME_UNITS * 3u + 1u)   /* a name as UTF-8, with its 0 */
#define EXFAT_DIR_NAME_BYTES 128u    /* a tracked directory's own name (UTF-8, truncated), for paths */
#define EXFAT_PATH_UTF8      (EXFAT_NAME_UTF8 + 256u)   /* a name with its directory path */
#define EXFAT_VIEW_SECTORS   (EXFAT_MAX_BLOCKS + 2u)   /* a transfer and a sector either side */
#define EXFAT_MAX_SETS       (EXFAT_VIEW_SECTORS * 16u / 3u)   /* entry sets a view can hold */

/* What changed, as the model reports it. */
typedef enum {
    EXFAT_EV_VOLUME = 1,   /* a boot sector: layout known (or changed) */
    EXFAT_EV_EXISTING,     /* an entry set in a directory sector seen for the first time */
    EXFAT_EV_CREATE,       /* a set in use where none was */
    EXFAT_EV_DELETE,       /* a set's InUse bits cleared, or its slot now holds none */
    EXFAT_EV_RENAME,       /* new name, same data (same slot, or moved to another) */
    EXFAT_EV_MODIFY,       /* same name, new size or first cluster */
    EXFAT_EV_CREATE_FILLED,/* a file seen created empty got its first data: the rest of a creation, not an edit */
} exfat_event_type_t;

/* One change, with everything the audit records about it. */
typedef struct {
    exfat_event_type_t type;
    bool     from_write;         /* from a WRITE; else a READ, so the change happened where the tap did not see it */
    uint64_t lba;                /* sector holding the set's first entry */
    uint32_t index;              /* entry number within that sector */
    bool     directory;
    uint32_t first_cluster;
    uint64_t size;
    uint32_t old_first_cluster;  /* RENAME, MODIFY, DELETE: before */
    uint64_t old_size;
    char     name[EXFAT_PATH_UTF8];      /* with its directory path: \test\rot.txt */
    char     old_name[EXFAT_PATH_UTF8];

    /* EXFAT_EV_VOLUME */
    uint64_t boot_lba;
    uint64_t heap_lba;
    uint32_t sectors_per_cluster;
    uint32_t root_cluster;
    uint32_t serial;
    bool     boot_checksum_checked;
    bool     boot_checksum_ok;
} exfat_event_t;

/* Called with each event as the model finds it. */
typedef void (*exfat_event_cb_t)(const exfat_event_t *ev, void *ctx);

/* What part of the volume a sector is in. */
typedef enum {
    EXFAT_AREA_NONE = 0,     /* not known to be filesystem structure (file data, or unknown) */
    EXFAT_AREA_BOOT,         /* main and backup boot regions (24 sectors) */
    EXFAT_AREA_FAT,
    EXFAT_AREA_BITMAP,       /* allocation bitmap (from the root directory's 0x81 entry) */
    EXFAT_AREA_UPCASE,       /* up-case table (0x82 entry) */
    EXFAT_AREA_DIRECTORY,
} exfat_area_t;

/* A directory sector as last seen, kept to compare the next version with. */
typedef struct {
    uint64_t lba;
    uint32_t stamp;      /* last use, for eviction */
    bool     valid;
    uint8_t  data[EXFAT_SECTOR_BYTES];
} exfat_cached_sector_t;

/* A tracked directory: its clusters, its name and the directory holding it. */
typedef struct {
    uint32_t first;      /* cluster */
    uint32_t clusters;
    uint32_t parent;     /* first cluster of the directory holding its entry (0: not known) */
    bool     named;      /* its entry set was seen: name and parent are known */
    char     name[EXFAT_DIR_NAME_BYTES];
} exfat_dir_extent_t;

/* One entry set found in a view of sectors (see exfat_model.c). */
typedef struct {
    uint32_t pos;            /* entry number from the start of the view */
    uint32_t count;          /* entries in the set */
    uint32_t first_cluster;
    uint64_t size;
    uint8_t  name_units;
    bool     in_use;
    bool     valid;
    bool     directory;
    bool     contiguous;
} exfat_set_t;

/* A set's state, with its name, kept apart from any sector. */
typedef struct {
    bool     used;
    bool     fresh;          /* created empty and still waiting for data (deleted states only) */
    uint8_t  created_10ms;   /* the creation time's 10 ms part */
    uint32_t created;        /* the creation timestamp: an empty file keeps it when renamed */
    uint64_t lba;
    uint32_t index;
    uint32_t first_cluster;
    uint64_t size;
    bool     directory;
    bool     in_use;
    uint8_t  name_units;
    uint16_t units[EXFAT_NAME_UNITS];
} exfat_state_t;

/* The model: the volume's layout, the directories, the cached sectors, the sets
 * being rewritten, scratch space, and the counts. */
typedef struct {
    bool     have_volume;
    bool     volume_confirmed;   /* a boot sector fed since it was made, loaded or unconfirmed (until then: no directory use) */
    uint64_t boot_lba;
    uint64_t heap_lba;
    uint32_t cluster_shift;      /* sectors per cluster = 1 << cluster_shift */
    uint32_t cluster_count;
    uint32_t root_cluster;
    uint32_t serial;
    uint32_t fat_offset;         /* sectors from the boot sector */
    uint32_t fat_length;
    uint32_t bitmap_first, bitmap_clusters;   /* 0: not seen yet */
    uint32_t upcase_first, upcase_clusters;

    exfat_dir_extent_t dirs[EXFAT_MAX_DIRS];
    uint32_t           ndirs;
    uint32_t           dirs_version;   /* changes whenever an extent is added, grown or forgotten (not in snapshots) */

    exfat_cached_sector_t cache[EXFAT_CACHE_SECTORS];
    uint32_t              stamp;

    /* Directory sectors pushed out of the cache with no entry in use, by offset from heap_lba
     * (EXFAT_EMPTY_NONE: free). */
    uint32_t empty[EXFAT_EMPTY_SECTORS];
    uint32_t empty_next;         /* the slot taken when none is free */

    exfat_state_t pending[EXFAT_PENDING];
    uint32_t      pending_next;

    /* Slots reported CREATE with no cluster and size 0, until they get data. */
    struct {
        bool     used;
        uint64_t lba;
        uint32_t index;
    } fresh[EXFAT_PENDING];
    uint32_t fresh_next;

    /* Scratch, kept here rather than on core0's small stack. */
    uint8_t            old_view[EXFAT_VIEW_SECTORS * EXFAT_SECTOR_BYTES];
    uint8_t            new_view[EXFAT_VIEW_SECTORS * EXFAT_SECTOR_BYTES];
    bool               old_known[EXFAT_VIEW_SECTORS];
    bool               new_known[EXFAT_VIEW_SECTORS];
    exfat_set_t        old_sets[EXFAT_MAX_SETS];
    exfat_set_t        new_sets[EXFAT_MAX_SETS];
    exfat_state_t      before;
    exfat_state_t      deleted[EXFAT_MAX_CHANGES];
    const exfat_set_t *created[EXFAT_MAX_CHANGES];
    uint16_t           units[EXFAT_NAME_UNITS];
    char               lookup_name[EXFAT_NAME_UTF8];
    char               joined[EXFAT_PATH_UTF8];
    exfat_event_t      ev;

    exfat_event_cb_t cb;
    void            *ctx;

    uint64_t sectors;            /* sectors fed */
    uint64_t dir_sectors;        /* of those, directory sectors */
    uint64_t events;
    uint64_t bad_sets;           /* sets not matching their checksum or layout (most are being rewritten) */
    uint64_t dirs_full;          /* directories not tracked: table full */
    uint64_t dirs_forgotten;     /* extents dropped because their directory was deleted */
    uint64_t dirs_forgotten_inside; /* of those, inside a deleted directory (own DELETE not seen) */
    uint64_t evictions;          /* cached sectors pushed out */
    uint64_t empty_full;         /* empty sectors forgotten: the list of them was full */
    uint64_t dir_sectors_same;   /* directory sectors identical to the cached copy, not parsed again */
    uint64_t changes_full;       /* creations or deletions beyond EXFAT_MAX_CHANGES */
} exfat_model_t;

/* Starts an empty model that reports events through `cb`. */
void exfat_model_init(exfat_model_t *m, exfat_event_cb_t cb, void *ctx);

/* Feeds one complete transfer: `blocks` sectors from `lba`; only boot and directory sectors are
 * used. */
void exfat_model_feed(exfat_model_t *m, uint64_t lba, const uint8_t *data, uint32_t blocks,
                      bool from_write);

/* The drive went away: the model keeps what it knows but uses nothing until a boot sector confirms
 * the volume. */
void exfat_model_unconfirm(exfat_model_t *m);

/* True if `sector` at `lba` is a boot sector the model would take as the volume's (not the backup);
 * gives its serial. */
bool exfat_boot_sector_serial(const exfat_model_t *m, uint64_t lba, const uint8_t *sector, uint32_t *serial);

/* The sector is in a cluster the model knows to be a directory. */
bool exfat_model_is_directory(const exfat_model_t *m, uint64_t lba);

/* The in-use file covering `lba`, with its path, name and size; false if none is known. Not from an
 * event callback. */
bool exfat_model_file_at(exfat_model_t *m, uint64_t lba, char *name, uint32_t name_size,
                         uint64_t *size, bool *directory);

/* Which filesystem structure `lba` belongs to, if any. */
exfat_area_t exfat_model_area_at(const exfat_model_t *m, uint64_t lba);
/* An area's name, for the console. */
const char  *exfat_model_area_name(exfat_area_t area);

/* The path of the tracked directory holding `lba` ("" for the root, "?" when the top is not known).
 * Safe in callbacks. */
bool exfat_model_directory_path(const exfat_model_t *m, uint64_t lba, char *out, uint32_t size);

/* Any of `blocks` sectors from `lba` is in a tracked directory. */
bool exfat_model_overlaps_directory(const exfat_model_t *m, uint64_t lba, uint32_t blocks);

/* ---- snapshots ------------------------------------------------------- */

/* Everything the model knows except counters, so it can be reloaded at the volume's next insertion:
 *   "EXFS" | version u16 | reserved u16 | body length u32 | body | SHA-256 of everything before it. */
#define EXFAT_SNAPSHOT_VERSION 2u   /* version 1 (no empty sectors) still loads */
/* A free slot in the model's list of empty sectors. */
#define EXFAT_EMPTY_NONE       0xFFFFFFFFu
/* The largest snapshot: every table full. */
#define EXFAT_SNAPSHOT_MAX_BYTES                                            \
    (12u +                                              /* header */       \
     66u +                                              /* volume */       \
     4u + EXFAT_MAX_DIRS * (13u + EXFAT_DIR_NAME_BYTES) +                  \
     4u + EXFAT_CACHE_SECTORS * (16u + EXFAT_SECTOR_BYTES) +               \
     4u + EXFAT_PENDING * (31u + 2u * EXFAT_NAME_UNITS) +                  \
     4u + EXFAT_PENDING * 16u +                         /* fresh */        \
     8u + EXFAT_EMPTY_SECTORS * 8u +                    /* empty */        \
     32u)                                              /* SHA-256 */

/* The snapshot's size in bytes, as it would be written now. */
uint32_t exfat_model_snapshot_bytes(const exfat_model_t *m);

/* Takes the snapshot a few bytes at a time as it is made (it goes straight into card blocks). */
typedef void (*exfat_snapshot_sink_t)(void *ctx, const uint8_t *bytes, uint32_t len);
/* Writes the snapshot through `sink`; returns its size and digest. */
uint32_t exfat_model_snapshot_write(const exfat_model_t *m, exfat_snapshot_sink_t sink, void *ctx,
                                    uint8_t digest[32]);

/* Gives exactly `len` bytes of a snapshot; false if it has no more. */
typedef bool (*exfat_snapshot_source_t)(void *ctx, uint8_t *bytes, uint32_t len);
/* Replaces the model with a snapshot (left unconfirmed); false, and the model fresh, if it is
 * malformed or does not match its digest. */
bool exfat_model_snapshot_read(exfat_model_t *m, exfat_snapshot_source_t source, void *ctx,
                               uint8_t digest[32]);

/* Saves the snapshot into a buffer; returns its size, or 0 if `cap` is too small. */
uint32_t exfat_model_snapshot_save(const exfat_model_t *m, uint8_t *out, uint32_t cap);
/* Loads a snapshot, trusting nothing before the digest and every bound check pass; refuses bytes after
 * the digest. */
bool exfat_model_snapshot_load(exfat_model_t *m, const uint8_t *in, uint32_t len);

/* The directory extents as LBA ranges; returns how many were written. */
uint32_t exfat_model_directory_ranges(const exfat_model_t *m, uint64_t *lba, uint32_t *sectors,
                                      uint32_t max);

#endif /* EXFAT_MODEL_H */
