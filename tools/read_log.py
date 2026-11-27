"""The tap's log reader: a window that opens the card's AUDIT.BIN, checks it with the log key, and
shows what happened to the drive in each session.

    python tools/read_log.py
"""
# The hashes, paths, the record and block layouts, and the CRC.
import hashlib
import hmac
import os
import shutil
import struct
import time
import zlib
from collections import Counter
from datetime import datetime, timedelta

# The C ChaCha20 from the `cryptography` package when it is installed (a full card in seconds, not minutes).
try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
except ImportError:
    Cipher = None


# A log the reader cannot take at all: not an AUDIT.BIN, or a format it does not know.
class LogError(Exception):
    """Raised with a message saying why the log cannot be read."""


# ---- the keys, derived as the firmware does ---------------------------

# The record version chained with HMAC-SHA256 (version 1 is plain SHA-256 from zero).
VERSION_KEYED = 2


def parse_log_key(text):
    """The 32-byte log key from its 64 hex digits (white space around them dropped); None if it is not one."""
    try:
        key = bytes.fromhex(text.strip())
    except ValueError:
        return None
    return key if len(key) == 32 else None


def chain_key(log_key):
    """The audit chain's HMAC key: HMAC-SHA256(log key, "usbtap chain v1") (audit_chain_key in audit_log.c)."""
    return hmac.new(log_key, b"usbtap chain v1", hashlib.sha256).digest()


def cipher_key(log_key):
    """The card's ChaCha20 key: HMAC-SHA256(log key, "usbtap card v1")."""
    return hmac.new(log_key, b"usbtap card v1", hashlib.sha256).digest()


def record_hash(ckey, version, prev, body_bytes):
    """A record's hash: HMAC-SHA256 with the chain key (version 2) or SHA-256 (1)."""
    if version == VERSION_KEYED:
        return hmac.new(ckey, prev + body_bytes, hashlib.sha256).digest()
    return hashlib.sha256(prev + body_bytes).digest()


def genesis_tag(head):
    """The first 8 bytes of a hash as a number: a keyed SESSION_START's lba."""
    return int.from_bytes(head[:8], "little")


def _rotl(v, n):
    """Rotates a 32-bit word left by n bits."""
    return ((v << n) | (v >> (32 - n))) & 0xFFFFFFFF


def chacha20_block(key, nonce, counter):
    """One 64-byte ChaCha20 keystream block (RFC 8439 section 2.3)."""
    s = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574] + list(struct.unpack("<8I", key)) + \
        [counter & 0xFFFFFFFF] + list(struct.unpack("<3I", nonce))
    x = list(s)

    def qr(a, b, c, d):
        """The quarter round on words a, b, c and d of the state."""
        x[a] = (x[a] + x[b]) & 0xFFFFFFFF; x[d] = _rotl(x[d] ^ x[a], 16)
        x[c] = (x[c] + x[d]) & 0xFFFFFFFF; x[b] = _rotl(x[b] ^ x[c], 12)
        x[a] = (x[a] + x[b]) & 0xFFFFFFFF; x[d] = _rotl(x[d] ^ x[a], 8)
        x[c] = (x[c] + x[d]) & 0xFFFFFFFF; x[b] = _rotl(x[b] ^ x[c], 7)

    for _ in range(10):
        qr(0, 4, 8, 12); qr(1, 5, 9, 13); qr(2, 6, 10, 14); qr(3, 7, 11, 15)
        qr(0, 5, 10, 15); qr(1, 6, 11, 12); qr(2, 7, 8, 13); qr(3, 4, 9, 14)
    return struct.pack("<16I", *[(x[i] + s[i]) & 0xFFFFFFFF for i in range(16)])


def chacha20_xor_python(key, nonce, counter, data):
    """Encrypts or decrypts data in pure Python: XORs it with keystream from block `counter` on."""
    out = bytearray(data)
    for off in range(0, len(out), 64):
        ks = chacha20_block(key, nonce, counter + off // 64)
        for i in range(min(64, len(out) - off)):
            out[off + i] ^= ks[i]
    return bytes(out)


def chacha20_xor(key, nonce, counter, data):
    """Encrypts or decrypts data: with `cryptography` when installed (counter LE, then nonce), else in Python."""
    if Cipher is not None:
        return Cipher(algorithms.ChaCha20(key, struct.pack("<I", counter) + nonce), mode=None).encryptor().update(data)
    return chacha20_xor_python(key, nonce, counter, data)


def open_block(ckey, blk):
    """A version 3 block with its payload decrypted: nonce = index then file id, counter = boot tag x 8."""
    nonce = blk[16:20] + blk[8:16]
    return blk[:32] + chacha20_xor(ckey, nonce, blk[23] * 8, blk[32:])


# ---- the record ----------------------------------------------------------

# Record type names (audit_log.h) to their numbers, and back.
TYPES = {"SESSION_START": 1, "SCSI": 2, "BUS_EVENT": 3, "GAP": 4, "SESSION_END": 5,
         "FILE": 6, "FILE_BEFORE": 7, "FILE_NAME": 8,
         "DRIVE_POWER": 9, "CARD_CHECK": 10, "SECTOR": 11, "MODEL": 12, "HOST_POWER": 13}
# Record type numbers to their names.
TYPE_NAMES = {v: k for k, v in TYPES.items()}
# FILE events' op numbers to their names.
EVENTS = {1: "VOLUME", 2: "EXISTING", 3: "CREATE", 4: "DELETE", 5: "RENAME", 6: "MODIFY",
          7: "CREATE completed", 8: "UNRELIABLE"}
# A record body's first four bytes ("UDIT"), and the record flags the file events read.
MAGIC = 0x54494455
FLAG_FROM_WRITE, FLAG_DIRECTORY, FLAG_OLD_NAME = 16, 32, 256


def unpack(raw):
    """A 96-byte record from the card as a dict of its fields, its hash and its raw bytes."""
    (magic, version, typ, flags, seq, session, ts, lba, blocks, dlen, residue, tag, dev, ep, lun, opcode,
     op, status, aux, reserved) = struct.unpack_from("<IBBHQQQQIIIIBBBBBBBB", raw, 0)
    return {"magic": magic, "version": version, "type": typ, "flags": flags, "seq": seq, "session": session,
            "ts": ts, "lba": lba, "blocks": blocks, "dlen": dlen, "residue": residue, "tag": tag, "dev": dev,
            "ep": ep, "lun": lun, "opcode": opcode, "op": op, "status": status, "aux": aux,
            "reserved": reserved, "sha": raw[64:96].hex(), "raw": raw}


# ---- file events ---------------------------------------------------------

def file_events(recs):
    """The FILE events of a session's records, each with its FILE_BEFORE and its names reassembled."""
    events, current = [], None
    for r in recs:
        if r["type"] == TYPES["FILE"]:
            current = {"seq": r["seq"], "ts": r["ts"], "tag": r["tag"], "event": r["op"],
                       "flags": r["flags"], "lba": r["lba"], "index": r["dev"], "cluster": r["blocks"],
                       "size": r["dlen"] | (r["residue"] << 32), "blocks": r["blocks"],
                       "dlen": r["dlen"], "residue": r["residue"],
                       "name": b"", "old_name": b"", "before": None}
            if r["op"] == 1:
                current.update(serial=r["blocks"], heap_offset=r["dlen"], root=r["residue"], shift=r["dev"])
            events.append(current)
        elif r["type"] == TYPES["FILE_BEFORE"] and current is not None:
            current["before"] = (r["blocks"], r["dlen"] | (r["residue"] << 32))
        elif r["type"] == TYPES["FILE_NAME"] and current is not None:
            raw = struct.pack("<QIIII", r["lba"], r["blocks"], r["dlen"], r["residue"], r["tag"])[:r["lun"]]
            key = "old_name" if r["flags"] & FLAG_OLD_NAME else "name"
            current[key] += raw
    return events


# ---- the PC's own times, from the directory sectors on the card ----------

# A File entry's (0x85) three times: its 32-bit time, its 10 ms byte (none for last access), its UTC byte.
PC_TIMES = {"created": (8, 20, 22), "modified": (12, 21, 23), "accessed": (16, None, 24)}


def exfat_time(entry, at, ms_at, utc_at):
    """One time of an exFAT File entry as text, 2026-11-08 14:03:21 (UTC+8), or None if it is empty."""
    v = struct.unpack_from("<I", entry, at)[0]
    if v == 0:
        return None
    year, month, day = 1980 + (v >> 25), (v >> 21) & 15, (v >> 16) & 31
    hour, minute, sec = (v >> 11) & 31, (v >> 5) & 63, (v & 31) * 2
    sec += entry[ms_at] // 100 if ms_at is not None else 0
    text = f"{year}-{month:02d}-{day:02d} {hour:02d}:{minute:02d}:{sec:02d}"
    utc = entry[utc_at]
    if utc & 0x80:
        q = (utc & 0x7F) - (0x80 if utc & 0x40 else 0)    # signed, in quarter hours
        h, m = divmod(abs(q) * 15, 60)
        text += f" (UTC{'+' if q >= 0 else '-'}{h}" + (f":{m:02d})" if m else ")")
    return text


def entry_times(sector, index, e):
    """The PC's times in the File entry at `index` of a directory sector, if that entry is the event's file."""
    if sector is None or index > 15:
        return None
    entry = sector[index * 32:index * 32 + 32]
    if entry[0] & 0x7F != 0x05 or (e["event"] != 4) != bool(entry[0] & 0x80):
        return None
    if index < 15:   # its Stream Extension in the same sector: the same first cluster and size (a delete's: before)
        stream = sector[index * 32 + 32:index * 32 + 64]
        want = e["before"] if e["event"] == 4 and e["before"] else (e["cluster"], e["size"])
        if stream[0] & 0x7F != 0x40 or struct.unpack_from("<IQ", stream, 20) != tuple(want):
            return None
    return {k: exfat_time(entry, *at) for k, at in PC_TIMES.items()}


def pc_times(events, secs, vouched, sid):
    """{event seq: {"at": the PC's times, "last": the same entry's times as last stored}} for a session's file
    events, from the sectors its SECTOR records vouch for. "at" is from the first one logged after the event (its
    own transfer), else the latest before it; "last" catches times the PC set later with no other change (a
    copy's modified time)."""
    by_lba = {}
    for k, seq in vouched.items():
        if secs[k][3] == sid:
            by_lba.setdefault(secs[k][1], []).append((seq, secs[k][2]))
    out = {}
    for e in events:
        if e["event"] in (1, 8):
            continue
        cands = by_lba.get(e["lba"], [])
        after = sorted((c for c in cands if c[0] > e["seq"]), key=lambda c: c[0])
        before = sorted((c for c in cands if c[0] < e["seq"]), key=lambda c: -c[0])
        for k, (_seq, sector) in enumerate(after[:1] + before):
            t = entry_times(sector, e["index"], e)
            if t:
                out[e["seq"]] = {"at": t, "last": t}
                break
        if after and e["seq"] in out and k == 0:
            for _seq, sector in after[1:]:
                t = entry_times(sector, e["index"], e)
                if not t:
                    break   # the entry changed: a later event's
                out[e["seq"]]["last"] = t
    return out


def pc_clock(events, times):
    """The PC's clock against the tap's in a session, from the files it created (stamped as they were made):
    a function from a tap time to an estimated PC time as text, or None when nothing was created."""
    anchors = []
    for e in events:
        t = times.get(e["seq"], {}).get("at", {})
        if e["event"] == 3 and t.get("created"):
            pc = datetime.strptime(t["created"][:19], "%Y-%m-%d %H:%M:%S")
            anchors.append((pc - timedelta(microseconds=e["ts"] // 1000), t["created"][19:]))
    if not anchors:
        return None
    anchors.sort()
    base, zone = anchors[len(anchors) // 2]   # the median: one late stamp does not move it
    return lambda ts: "≈ " + (base + timedelta(microseconds=ts // 1000)).strftime("%Y-%m-%d %H:%M:%S") + zone


# ---- records in words ----------------------------------------------------

# The names the firmware gives SCSI operations, bus events and drive-power reasons.
MSC_OPS = ["OTHER", "READ", "WRITE", "QUERY", "FLUSH", "LOCK", "UNLOCK", "EJECT", "LOAD", "STOP", "START",
           "VERIFY", "TRIM", "FORMAT", "SETTINGS"]
# Bus event codes (usb_bus_event_t) and DRIVE_POWER reasons (AUDIT_POWER_*), in words.
BUS_EVENTS = ["BUS-RESET", "HS-CHIRP", "HIGH-SPEED-SUSPECTED", "SE1", "CAPTURE-OVERRUN", "NO-DEVICE",
              "SUSPEND", "SUSPEND-END", "DETACH", "ATTACH"]
POWER_REASONS = {1: "checks passed", 2: "by key", 3: "session ended", 4: "PC unplugged", 5: "card full"}
# CARD_CHECK aux flags: how the card compared with the checkpoint in the Pico's flash.
CHECKPOINT_FLAGS = [(1, "first use"), (8, "not this tap's card")]
# ---- what happened: the activity timeline and the files ------------------

# Activity rows by kind: the tap and its power, the drive, file changes, file reads and writes, and warnings.
SESSION, DRIVE, CHANGE, READ, WRITE, WARN = "session", "drive", "change", "read", "write", "warn"
# The colour of each group a row is shown in, and the key's words for it, in the key's order.
TONES = [("read", "#1967d2", "Read"), ("made", "#188038", "Created / wrote"),
         ("edited", "#c26401", "Edited / deleted"), ("moved", "#8430ce", "Renamed / moved"),
         ("warn", "#b3261e", "Warning"), ("drive", "#202124", "Drive"), ("session", "#80868b", "Tap and power")]
# The group of a read or a file change, by its first word.
VERB_TONES = {"Read": "read", "Created": "made", "Wrote": "made", "Edited": "edited", "Overwrote": "edited",
              "Deleted": "edited", "Renamed": "moved", "Moved": "moved"}
# The group of a file in the Files tab, by the last thing that happened to it.
WHAT_TONES = {"created": "made", "written": "made", "edited": "edited", "overwritten": "edited",
              "deleted": "edited", "read": "read"}


def tone(row):
    """A row's colour group: reads and file changes by their first word, anything else by its kind."""
    if row["kind"] in (CHANGE, READ, WRITE):
        return VERB_TONES.get(row["text"].split(" ", 1)[0], row["kind"])
    return row["kind"]


def file_tone(what):
    """A file's colour group in the Files tab, from what happened to it (the last thing counts)."""
    last = what[-1] if what else "read"
    if last.startswith(("renamed", "moved")):
        return "moved"
    return WHAT_TONES.get(last, "")
# How long after a read or write the file events that name it may come (a new file's entry follows its data),
# and the quiet gap that ends a run of accesses to one file.
NAME_DELAY_NS, RUN_GAP_NS = 5_000_000_000, 3_000_000_000
# How soon after a run's last command a command to a sector no file held still continues that run.
CONTINUE_NS = 500_000_000
# How long a sequential stream of commands may pause and still be one stream.
STREAM_GAP_NS = 3_000_000_000
# The least commands on both sides of a jump for it to count as a file's next piece (big copies, not small files).
PIECE_CMDS = 8
# What each bus event means to someone reading the log; None: noise, not shown.
BUS_TEXT = {"ATTACH": (DRIVE, "Drive connected"), "DETACH": (DRIVE, "Drive disconnected"),
            "NO-DEVICE": (DRIVE, "No drive"),
            "SUSPEND": None, "SUSPEND-END": None,   # the PC idling the drive: a safe removal shows as its EJECT
            "HIGH-SPEED-SUSPECTED": (WARN, "Drive may be running at High Speed (unreadable)"),
            "CAPTURE-OVERRUN": (WARN, "Tap fell behind"),
            "BUS-RESET": None, "HS-CHIRP": None, "SE1": None}


def fmt_bytes(n):
    """A byte count for people: 512 B, 4 KB, 15.4 MB."""
    for unit, size in (("GB", 1 << 30), ("MB", 1 << 20), ("KB", 1 << 10)):
        if n >= size:
            return f"{n // size} {unit}" if n % size == 0 else f"{n / size:.1f} {unit}"
    return f"{n} B"


def size_change(now, was):
    """A file's new size against its old: "now 4.9 KB, was 2.9 KB", in bytes when rounding would hide it."""
    if was is None:
        return f"now {fmt_bytes(now)}"
    if now == was:
        return f"same size, {fmt_bytes(now)}"
    if fmt_bytes(now) == fmt_bytes(was):
        return f"now {now:,} B, was {was:,} B"
    return f"now {fmt_bytes(now)}, was {fmt_bytes(was)}"


def fmt_span(ns):
    """A duration for people: 850 ms, 12.3 s, 4 min 05 s, 4 h 39 min."""
    s = ns / 1e9
    if s < 1:
        return f"{s * 1000:.0f} ms"
    if s < 60:
        return f"{s:.1f} s"
    if s < 3600:
        return f"{int(s // 60)} min {int(s % 60):02d} s"
    return f"{int(s // 3600)} h {int(s % 3600 // 60):02d} min"


class DriveMap:
    """One volume's files over time, as the log has shown them, so a sector number can be named."""

    def __init__(self, e):
        """Starts the map from a VOLUME event: the volume's geometry, and no files yet."""
        self.serial = e["serial"]
        self.heap = e["lba"] + e["heap_offset"]
        self.shift = e["shift"]
        self.boot = e["lba"]
        self.root = e["root"]
        self.spans = []      # every placement: {"lo", "hi", "path", "dir", "from", "to"} (times in this session)
        self.live = {}       # first cluster -> the placement holding it now

    def cluster_lba(self, c):
        """The first sector of cluster c."""
        return self.heap + ((c - 2) << self.shift)

    def new_session(self):
        """Carries the files still on the drive into a new session, as there from its start."""
        self.spans = []
        for c, s in list(self.live.items()):
            self.live[c] = dict(s, **{"from": -1, "to": None})
            self.spans.append(self.live[c])

    def place(self, cluster, path, size, is_dir, ts):
        """A file or folder holds the clusters from `cluster` from time ts (contiguous, as copies are)."""
        if cluster < 2:
            return
        self.remove(cluster, ts)
        n = max(1, (size + (512 << self.shift) - 1) // (512 << self.shift))
        lo = self.cluster_lba(cluster)
        s = {"lo": lo, "hi": lo + (n << self.shift), "path": path, "dir": is_dir, "from": ts, "to": None}
        self.live[cluster] = s
        self.spans.append(s)

    def made_before(self, cluster, ts):
        """True if this session placed a file at `cluster` before ts (it was made here, not found)."""
        lo = self.cluster_lba(cluster)
        return any(s["lo"] == lo and 0 <= s["from"] < ts for s in self.spans)

    def remove(self, cluster, ts):
        """The file at `cluster` left it at time ts (deleted, truncated or moved)."""
        s = self.live.pop(cluster, None)
        if s:
            s["to"] = ts

    def owner(self, lba, ts, write=False):
        """What a sector belonged to at time ts, as (kind, name, held): the file holding it then, else the next
        or last one to hold it (held False)."""
        if lba < self.boot:
            return "fs", "the partition table", True
        if lba < self.heap:
            return "fs", "the file system's tables (boot region, FAT)", True
        root = self.cluster_lba(self.root)
        if root <= lba < root + (1 << self.shift):
            return "dir", "\\", True
        now = later = before = None
        for s in self.spans:
            if not s["lo"] <= lba < s["hi"]:
                continue
            if s["from"] <= ts and (s["to"] is None or ts < s["to"]):
                now = s if now is None or (s["lo"], s["from"]) > (now["lo"], now["from"]) else now
            elif s["from"] > ts:
                later = s if later is None or s["from"] < later["from"] else later
            elif before is None or s["to"] > before["to"]:
                before = s
        s = now or later or before
        if s is not None and s is before and write:
            return "free", "free space", False
        if s is None:
            if lba < root:
                return "fs", "the file system's tables (allocation bitmap, up-case table)", True
            return "unknown", "unknown data", False
        name = s["path"] + (" (no longer there)" if s is before else "")
        return ("dir" if s["dir"] else "file"), (name or "\\"), s is now


def name_streams(recs, volume_at, start_map):
    """Names what every READ and WRITE touched, as {seq: (kind, name)}, joining commands into sequential
    streams named by the file that held their sectors."""
    current = start_map
    first = next(iter(volume_at.values()), None)   # names the mount's reads before its boot sector
    streams, open_ = [], []
    for r in recs:
        if r["type"] == TYPES["FILE"] and r["seq"] in volume_at:
            current = volume_at[r["seq"]]
        if r["type"] != TYPES["SCSI"] or r["op"] not in (1, 2) or not r["flags"] & 2:
            continue
        m = current or first
        owner = m.owner(r["lba"], r["ts"], r["op"] == 2) if m else ("unknown", "data on an unknown drive", False)
        st = next((s for s in open_ if s["op"] == r["op"] and s["end"] == r["lba"]
                   and r["ts"] - s["last"] < STREAM_GAP_NS), None)
        if st is None:
            st = {"op": r["op"], "cmds": [], "owners": [], "start": r["ts"]}
            streams.append(st)
            open_.append(st)
        st["cmds"].append(r["seq"])
        st["owners"].append(owner)
        st["end"], st["last"] = r["lba"] + max(r["blocks"], 1), r["ts"]
    for st in streams:
        held = [o for o in st["owners"] if o[2]]
        if held:
            st["name"] = Counter(o[:2] for o in held).most_common(1)[0][0]   # ties: the first seen
        else:
            st["name"] = Counter(o[:2] for o in st["owners"]).most_common(1)[0][0]
            st["unheld"] = True
    for k, st in enumerate(streams):
        if not st.get("unheld"):
            continue
        prev = [p for p in streams[:k] if p["op"] == st["op"] and p["name"][0] == "file"
                and 0 <= st["start"] - p["last"] < CONTINUE_NS
                and len(p["cmds"]) >= PIECE_CMDS and len(st["cmds"]) >= PIECE_CMDS]
        if prev:
            st["name"] = prev[-1]["name"]
    return {seq: st["name"] for st in streams for seq in st["cmds"]}


def pair_empty_renames(events):
    """Pairs an empty file's DELETE and CREATE in one command and folder (older firmware's rename), as
    ({create seq: old name}, {delete seq})."""
    def empty_file(e):
        """An empty file's event, not a folder's."""
        return not e["flags"] & FLAG_DIRECTORY and e["cluster"] == 0 and e["size"] == 0

    def folder(e):
        """The folder an event's file is in."""
        return e["name"].decode("utf-8", errors="replace").rsplit("\\", 1)[0]

    renamed, gone = {}, set()
    by_command = {}
    for e in events.values():
        by_command.setdefault((e["ts"], e["tag"]), []).append(e)
    for group in by_command.values():
        deletes = [e for e in group if e["event"] == 4 and empty_file(e) and (e["before"] in (None, (0, 0)))]
        for c in [e for e in group if e["event"] == 3 and empty_file(e)]:
            d = next((d for d in deletes if d["seq"] not in gone and folder(d) == folder(c)), None)
            if d is not None:
                renamed[c["seq"]] = d["name"].decode("utf-8", errors="replace")
                gone.add(d["seq"])
    return renamed, gone


MOVE_NS = 2_000_000_000   # a move's delete and create are two directory writes, milliseconds apart


def pair_moves(events):
    """Pairs a DELETE in one folder with a CREATE in another, by cluster and size (or name within MOVE_NS
    for an empty file), as ({create seq: (old path, how)}, {delete seq})."""
    def folder(name):
        """The folder part of a path."""
        return name.rsplit("\\", 1)[0]

    def base(name):
        """The name part of a path."""
        return name.rsplit("\\", 1)[-1]

    moved, gone = {}, set()
    deletes = [e for e in events.values() if e["event"] == 4 and e["before"] is not None]
    for c in sorted((e for e in events.values() if e["event"] == 3), key=lambda e: e["seq"]):
        new = c["name"].decode("utf-8", errors="replace")
        for d in deletes:
            old = d["name"].decode("utf-8", errors="replace")
            if (d["seq"] in gone or abs(c["ts"] - d["ts"]) > MOVE_NS or folder(old) == folder(new)
                    or bool(c["flags"] & FLAG_DIRECTORY) != bool(d["flags"] & FLAG_DIRECTORY)):
                continue
            cluster, size = d["before"]
            if cluster != 0 and (cluster, size) == (c["cluster"], c["size"]):
                how = ""
            elif cluster == 0 and size == 0 and c["cluster"] == 0 and c["size"] == 0 and base(old) == base(new):
                how = "matched by name"
            else:
                continue
            moved[c["seq"]] = (old, how)
            gone.add(d["seq"])
            break
    return moved, gone


def found_tree(existing):
    """The files and folders found at a mount as nested rows: each folder holds what is in it, folders first."""
    rows = {"": {"children": []}}
    for r, name, is_dir, size in sorted(existing, key=lambda x: (x[1].count("\\"), x[1].lower())):
        folder = name.rsplit("\\", 1)[0]
        parent = rows.get(folder, rows[""])
        base = name.rsplit("\\", 1)[-1]
        row = {"ts": r["ts"], "kind": DRIVE, "seq": r["seq"], "unverified": False, "path": name, "notime": True,
               "text": (f"{base} (folder)" if is_dir else base) if folder in rows or not folder else name,
               "detail": "" if is_dir else fmt_bytes(size),
               "children": [], "_dir": is_dir}
        parent["children"].append(row)
        if is_dir:
            rows[name] = row
    for row in rows.values():
        row["children"].sort(key=lambda c: (not c.get("_dir"), c["text"].lower()))
        if row.get("_dir"):
            n = len(row["children"])
            row["detail"] = f"{n} item{'s' if n != 1 else ''}" if n else "empty"
    return rows[""]["children"]


def fold_writes(rows):
    """Folds the writes that make a file's change (a copy's data, an overwrite) into that change's row."""
    changes = [r for r in rows if r["kind"] == CHANGE and r.get("path")]
    kept = []
    for r in rows:
        if r["kind"] == WRITE and r.get("path"):
            near = [c for c in changes if c["path"] == r["path"] and not c["text"].startswith("Deleted")
                    and (abs(c["ts"] - r["ts"]) < 3 * NAME_DELAY_NS
                         or 0 <= r["ts"] - c.get("_end", c["ts"]) < 2 * RUN_GAP_NS)]
            if near:
                c = min(near, key=lambda c: abs(c["ts"] - r["ts"]))
                c["unverified"] = c["unverified"] or r["unverified"]
                c["_end"] = max(c.get("_end", c["ts"]), r["_last"])
                continue
        kept.append(r)
    return kept


def group_bursts(rows):
    """Collapses a burst of the same change in one folder (50 files created at once) into one row with children."""
    def key(r):
        """A change row's verb and folder, or None."""
        if r["kind"] != CHANGE or not r.get("path"):
            return None
        return r["text"].split(" ")[0], r["path"].rsplit("\\", 1)[0] or "\\"

    out, i = [], 0
    while i < len(rows):
        k = key(rows[i])
        if k is None:
            out.append(rows[i])
            i += 1
            continue
        j, members, last = i + 1, [rows[i]], rows[i]["ts"]
        while j < len(rows) and rows[j]["ts"] - last < RUN_GAP_NS:
            r = rows[j]
            folder_warn = r["kind"] == WARN and r.get("path") in (k[1], k[1].lstrip("\\") and k[1])
            if key(r) == k or folder_warn or (r["kind"] in (READ, WRITE) and (r.get("path") or "").startswith(k[1])):
                members.append(r)
                last = r["ts"]
                j += 1
            else:
                break
        changes = [m for m in members if m["kind"] == CHANGE]
        if len(changes) < 4:
            out.append(rows[i])
            i += 1
            continue
        warns = [m for m in members if m["kind"] == WARN]
        kinds = {("folder" if " folder " in c["text"] else "file") for c in changes}
        noun = "files and folders" if len(kinds) > 1 else ("folders" if kinds == {"folder"} else "files")
        detail = f"over {fmt_span(members[-1]['ts'] - members[0]['ts'])}"
        if warns:
            detail += f"; {len(warns)} folder writes missed"
        out.append({"ts": members[0]["ts"], "kind": WARN if warns else CHANGE, "seq": members[0]["seq"],
                    "text": f"{k[0]} {len(changes)} {noun} in {k[1]}", "detail": detail, "path": k[1],
                    "unverified": any(m["unverified"] for m in members),
                    "children": [m for m in members if m["kind"] != WARN]})
        i = j
    return out


def session_list(numbers):
    """Session numbers in short: 1, 3-6."""
    out, start = [], None
    for k, n in enumerate(numbers):
        start = n if start is None else start
        if k + 1 == len(numbers) or numbers[k + 1] != n + 1:
            out.append(str(n) if n == start else f"{start}-{n}")
            start = None
    return ", ".join(out)


def serial_text(serial):
    """A volume serial as Windows shows it: 30EF-6102."""
    return f"{serial >> 16:04X}-{serial & 0xFFFF:04X}"


def drive_facts(sessions, chosen, activity):
    """The drive in the chosen sessions, as (label, value) rows: its volume, its USB link and what was done."""
    volumes, known = {}, {}
    for i, s in enumerate(sessions):
        if i <= max(chosen):
            known.update(s.get("volumes", {}))   # the newest snapshot of each volume up to these sessions
    facts, seen, read, where = [], [], 0, {}
    written, cmds, failed, speed, address, changes = 0, 0, 0, None, None, 0
    for i in chosen:
        recs = sorted(sessions[i]["recs"], key=lambda r: r["seq"])
        for e in file_events(recs):
            if e["event"] == 1 and e["serial"] not in seen:
                seen.append(e["serial"])
                volumes[e["serial"]] = e
            if e["event"] == 1 and i + 1 not in where.setdefault(e["serial"], []):
                where[e["serial"]].append(i + 1)
        for r in recs:
            if r["type"] == TYPES["SESSION_START"]:
                speed = r["aux"]
            elif r["type"] == TYPES["SCSI"] and MSC_OPS[r["op"]] in ("READ", "WRITE") and r["flags"] & 2:
                cmds += 1
                failed += 0 if (r["flags"] & 1 and r["status"] == 0) else 1
                if MSC_OPS[r["op"]] == "READ":
                    read += r["blocks"] * 512
                else:
                    written += r["blocks"] * 512
                address = r["dev"] if address is None else address
        changes += sum(1 for row in activity[i]["rows"] if row["kind"] == CHANGE)
    if len(seen) > 1:
        facts.append(("Drives", f"{len(seen)} different"))
        facts.append(("", ""))
    for serial in seen:
        e, v = volumes[serial], known.get(serial)
        facts.append(("Volume", serial_text(serial)))
        if len(chosen) > 1:
            facts.append(("In sessions", session_list(where[serial])))
        facts.append(("File system", "exFAT"))
        cluster = 512 << e["shift"]
        facts.append(("Size", fmt_bytes(v["clusters"] * cluster) if v else "unknown"))
        facts.append(("Sector size", "512 B"))
        facts.append(("Cluster size", fmt_bytes(cluster)))
        facts.append(("Partition starts at", f"sector {e['lba']}"))
        if v:
            facts.append(("Folders", str(v["folders"])))
        facts.append(("", ""))
    if not seen:
        facts.append(("Volume", "none mounted"))
        facts.append(("", ""))
    facts.append(("USB speed", {0: "Low Speed (1.5 Mbit/s)", 1: "Full Speed (12 Mbit/s)"}.get(speed, "unknown")))
    if address is not None and len(chosen) == 1:   # a new address each time the drive is plugged in
        facts.append(("USB address", str(address)))
    facts.append(("Read", fmt_bytes(read)))
    facts.append(("Written", fmt_bytes(written)))
    facts.append(("Reads and writes", f"{cmds}" + (f" ({failed} failed)" if failed else "")))
    facts.append(("File changes", str(changes)))
    return facts


def build_activity(sessions):
    """Turns every session's records into a timeline in words and a per-file summary, one {"rows", "files",
    "length"} per session, carrying the drive's files from session to session."""
    maps = {}
    last_volume = None
    pc_known = {}        # path -> the PC's times for it as last stored, across sessions
    out = []
    for s in sessions:
        recs = sorted(s["recs"], key=lambda r: r["seq"])
        brk = s.get("break_seq")
        events = {e["seq"]: e for e in file_events(recs)}
        times = s.get("pc_times", {})
        pc_last = {}         # path -> the PC's times for it as last stored
        length = max((r["ts"] for r in recs), default=0)
        for m in maps.values():
            m.new_session()

        # Pass 1: where every file was, and when, from the file events.
        start_volume = last_volume
        current = maps.get(last_volume)
        volume_at = {}       # seq of each VOLUME record -> its map
        for r in recs:
            e = events.get(r["seq"]) if r["type"] == TYPES["FILE"] else None
            if e is None:
                continue
            if e["event"] == 1:
                current = maps.get(e["serial"])
                if current is None:
                    current = maps[e["serial"]] = DriveMap(e)
                volume_at[r["seq"]] = current
                last_volume = e["serial"]
                continue
            if current is None or e["event"] == 8:
                continue
            name = e["name"].decode("utf-8", errors="replace")
            if e["before"] and e["before"][0] != e["cluster"]:
                current.remove(e["before"][0], r["ts"])
            if e["event"] == 4:
                current.remove(e["cluster"], r["ts"])
            else:
                current.place(e["cluster"], name, e["size"], bool(e["flags"] & FLAG_DIRECTORY), r["ts"])

        # Pass 2: the rows.
        prev_volume = start_volume   # the volume mounted last, to see a different drive come
        renamed, gone = pair_empty_renames(events)
        moved, moved_from = pair_moves(events)
        rows, files, runs = [], {}, {}
        open_rows = {}       # path -> its last change row, to fold create/finish and truncate/refill into one

        def add(r, kind, text, detail="", path=None, ts=None, pc=""):
            """Adds one row, marked unverified when it comes after the chain's break."""
            rows.append({"ts": r["ts"] if ts is None else ts, "kind": kind, "text": text, "detail": detail,
                         "seq": r["seq"], "path": path, "unverified": brk is not None and r["seq"] >= brk, "pc": pc})
            return rows[-1]

        def entry(path, ts):
            """The file's summary entry, noting when it was first and last seen."""
            f = files.setdefault(path, {"path": path, "what": [], "read": 0, "written": 0, "reads": 0,
                                        "writes": 0, "first": ts, "last": ts})
            f["first"], f["last"] = min(f["first"], ts), max(f["last"], ts)
            return f

        def close_run(key):
            """Writes out a finished run of reads or writes to one thing."""
            run = runs.pop(key)
            kind, owner_kind, name = key
            verb = "Read" if kind == READ else "Wrote"
            detail = fmt_bytes(run["bytes"])
            detail += f", {run['failed']} failed" if run["failed"] else ""
            if run["last"] - run["first"] >= 1_000_000_000:
                detail += f", over {fmt_span(run['last'] - run['first'])}"
            row = {"ts": run["first"], "detail": detail, "seq": run["seq"], "unverified": run["unverified"],
                   "_bytes": run["bytes"], "_last": run["last"]}
            if owner_kind == "file":
                path = name.replace(" (no longer there)", "")
                f = entry(path, run["first"])
                f["read" if kind == READ else "written"] += run["bytes"]
                f["reads" if kind == READ else "writes"] += run["cmds"]
                row.update(kind=kind, text=f"{verb} {name}", path=path)
            elif owner_kind == "unknown":
                row.update(kind=WARN if kind == WRITE else kind, text=f"{verb} {name}", path=None,
                           detail=f"{detail}, LBA {run['lo']}-{run['hi']}")
            elif owner_kind == "free":
                row.update(kind=WRITE, text="Wrote to free space", path=None,
                           detail=f"{detail}, LBA {run['lo']}-{run['hi']}")
            else:
                return              # the file system's own tables and folders: their changes are the file rows
            rows.append(row)

        def access(r, owner_kind, name):
            """Adds a READ or WRITE command to the run of accesses to what it touched."""
            kind = READ if r["op"] == 1 else WRITE
            key = (kind, owner_kind, name)
            for k in [k for k, run in runs.items() if r["ts"] - run["last"] > RUN_GAP_NS]:
                close_run(k)
            run = runs.get(key)
            if run is None:
                run = runs[key] = {"first": r["ts"], "last": r["ts"], "cmds": 0, "bytes": 0, "failed": 0,
                                   "seq": r["seq"], "lo": r["lba"], "hi": r["lba"], "unverified": False}
            run["last"] = r["ts"]
            run["cmds"] += 1
            run["bytes"] += r["blocks"] * 512
            run["failed"] += 0 if (r["flags"] & 1 and r["status"] == 0) else 1
            run["lo"], run["hi"] = min(run["lo"], r["lba"]), max(run["hi"], r["lba"] + max(r["blocks"], 1) - 1)
            run["unverified"] = run["unverified"] or (brk is not None and r["seq"] >= brk)

        owners = name_streams(recs, volume_at, maps.get(start_volume))

        existing = []
        # "No drive" while one is still to connect is just the drive getting power.
        attached = [r["ts"] for r in recs if r["type"] == TYPES["BUS_EVENT"] and r["opcode"] < len(BUS_EVENTS)
                    and BUS_EVENTS[r["opcode"]] == "ATTACH"]
        for r in recs:
            t = TYPE_NAMES.get(r["type"])
            if t == "SESSION_START":
                add(r, SESSION, "Tap started")
            elif t == "SESSION_END":
                add(r, SESSION, "Session closed", ts=length)
            elif t == "CARD_CHECK":
                flags = ", ".join(txt for bit, txt in CHECKPOINT_FLAGS if r["aux"] & bit)
                full = bool(r["aux"] & 32)
                text = ("Card full: drive kept off" if full and r["op"] in (1, 2) else
                        {1: "Card checked: OK", 2: "New card accepted"}.get(r["op"], "Card check FAILED: drive kept off"))
                add(r, SESSION if r["op"] in (1, 2) and not full else WARN, text, flags)
            elif t == "DRIVE_POWER":
                add(r, WARN if r["aux"] == 5 else SESSION, "Drive powered on" if r["op"] else "Drive powered off",
                    POWER_REASONS.get(r["aux"], ""))
            elif t == "HOST_POWER":
                add(r, SESSION, "PC connected" if r["op"] else "PC disconnected")
            elif t == "GAP":
                add(r, WARN, "Missed bus traffic", f"{r['dlen'] / 1000:.1f} ms")
            elif t == "BUS_EVENT":
                name = BUS_EVENTS[r["opcode"]] if r["opcode"] < len(BUS_EVENTS) else "?"
                said = BUS_TEXT.get(name)
                if said and (name != "NO-DEVICE" or not any(t > r["ts"] for t in attached)):
                    add(r, said[0], said[1])
            elif t == "MODEL":
                if r["op"] not in (1, 2):
                    add(r, WARN, "Saved file list rejected", "existing files show as found")
            elif t == "SCSI":
                op = MSC_OPS[r["op"]] if r["op"] < len(MSC_OPS) else "?"
                if op in ("READ", "WRITE") and r["flags"] & 2:
                    access(r, *owners[r["seq"]])
                elif op == "EJECT":
                    add(r, DRIVE, "Drive ejected")
                elif op == "FORMAT":
                    add(r, WARN, "Format command sent")
                elif op == "TRIM":
                    add(r, WRITE, "Sectors discarded (TRIM)")
                # Other commands (TEST UNIT READY, INQUIRY, ...) only ask the drive about itself.
            elif t == "FILE" and r["seq"] in events:
                e = events[r["seq"]]
                ev, name = e["event"], e["name"].decode("utf-8", errors="replace")
                if ev == 1:
                    current = volume_at.get(r["seq"], current)
                    other = prev_volume is not None and e["serial"] != prev_volume
                    add(r, WARN if other else DRIVE, "Drive mounted",
                        f"volume {serial_text(e['serial'])}" + (", different drive" if other else ""))
                    prev_volume = e["serial"]
                    continue
                is_dir = bool(e["flags"] & FLAG_DIRECTORY)
                what = "folder" if is_dir else "file"
                if ev == 8:
                    add(r, WARN, f"Missed a change in folder {name or chr(92)}", "", path=name)
                    continue
                at = times.get(r["seq"], {}).get("at", {})
                if r["seq"] in times:
                    pc_last[name] = times[r["seq"]]["last"]
                if ev == 2:
                    if not (current and current.made_before(e["cluster"], r["ts"])):
                        existing.append((r, name, is_dir, e["size"]))
                        entry(name, r["ts"])["what"].append("found")
                    continue
                if r["seq"] in gone or r["seq"] in moved_from:
                    continue                # the old entry of a file renamed or moved (the CREATE says it)
                if r["seq"] in moved:
                    old, how = moved[r["seq"]]
                    to = name.rsplit("\\", 1)[0] or "\\"
                    same = old.rsplit("\\", 1)[-1] == name.rsplit("\\", 1)[-1]
                    row = add(r, CHANGE, f"Moved {what} {old} to {to if same else name}", how, path=name)
                    row.update(_ev=5, _size=e["size"], _was=e["size"])
                    open_rows[name] = row
                    entry(name, r["ts"])["what"].append(f"moved from {old}")
                    entry(old, r["ts"])["what"].append(f"moved to {name}")
                    if old in files:
                        files[name]["read"] += files[old]["read"]
                        files[name]["written"] += files[old]["written"]
                    continue
                if r["seq"] in renamed:
                    old = renamed[r["seq"]]
                    row = add(r, CHANGE, f"Renamed file {old} to {name}", "", path=name)
                    row.update(_ev=5, _size=0, _was=0)
                    open_rows[name] = row
                    entry(name, r["ts"])["what"].append(f"renamed from {old}")
                    entry(old, r["ts"])["what"].append(f"renamed to {name}")
                    continue
                for k in [k for k in runs if k[2] == name]:
                    close_run(k)            # the file's data before this change is its own row
                f = entry(name, r["ts"])
                old = e["old_name"].decode("utf-8", errors="replace")
                was = e["before"][1] if e["before"] else None
                unseen = "" if e["flags"] & FLAG_FROM_WRITE else " (while the tap was off)"
                prev = open_rows.get(name)
                if ev == 7 and prev and prev["_ev"] == 3:
                    prev["detail"] = fmt_bytes(e["size"]) + unseen
                    prev["_size"] = e["size"]
                    continue
                if ev == 6 and prev and prev["_ev"] == 6 and prev["_size"] == 0 and e["size"] > 0:
                    prev.update(text=f"Overwrote {what} {name}",
                                detail=size_change(e["size"], prev["_was"]) + unseen,
                                _size=e["size"], pc=at.get("modified") or prev["pc"])
                    f["what"].append("overwritten")
                    continue
                text, detail, summary = {
                    3: (f"Created {what} {name}", "" if is_dir else fmt_bytes(e["size"]), "created"),
                    7: (f"Wrote {what} {name}", fmt_bytes(e["size"]), "written"),
                    4: (f"Deleted {what} {name}", "" if is_dir or was is None else f"was {fmt_bytes(was)}", "deleted"),
                    5: (f"Renamed {what} {old} to {name}", "", f"renamed from {old}"),
                    6: (f"Edited {what} {name}",
                        size_change(e["size"], was),
                        "edited"),
                }.get(ev, (f"{EVENTS.get(ev, '?')} {what} {name}", "", EVENTS.get(ev, "?")))
                pc = at.get({3: "created", 6: "modified", 7: "modified"}.get(ev, ""), "") or ""
                row = add(r, CHANGE, text, detail + unseen, path=name, pc=pc)
                row.update(_ev=ev, _size=e["size"], _was=was or 0)
                open_rows[name] = row
                f["what"].append(summary)
                if ev == 5:
                    entry(old, r["ts"])["what"].append(f"renamed to {name}")
                    f["read"] += files[old]["read"]
                    f["written"] += files[old]["written"]
        for k in list(runs):
            close_run(k)
        pc_known.update(pc_last)
        for path, f in files.items():
            t = pc_known.get(path)
            if t:
                f.update(pc_created=t["created"] or "", pc_modified=t["modified"] or "")
        if existing:
            nf = sum(1 for x in existing if not x[2])
            total = sum(x[3] for x in existing if not x[2])
            nd = len(existing) - nf
            row = add(existing[0][0], DRIVE, f"Already on the drive: {nf} file{'s' if nf != 1 else ''}, "
                      f"{nd} folder{'s' if nd != 1 else ''}", fmt_bytes(total))
            row["children"] = found_tree(existing)
        rows.sort(key=lambda x: (x["ts"], x["seq"]))
        rows = group_bursts(fold_writes(rows))
        # Repeated warnings close together become one row with a count.
        merged = []
        for row in rows:
            last = merged[-1] if merged else None
            if (last and row["kind"] == WARN and last["kind"] == WARN and last["text"] == row["text"]
                    and row["ts"] - last.get("_end", last["ts"]) < RUN_GAP_NS):
                last["_n"] = last.get("_n", 1) + 1
                last["_end"] = row["ts"]
                last["detail"] = f"{last['_n']} times; " + row["detail"]
                continue
            merged.append(row)
        estimate = pc_clock(events.values(), times)

        def strip(r):
            """Drops the builder's own keys from a row and its children, and gives a row with no time of the
            PC's own an estimate from the PC's clock (marked ~)."""
            for k in [k for k in r if k.startswith("_")]:
                del r[k]
            if not r.get("pc") and estimate and not r.get("notime"):
                r["pc"] = estimate(r["ts"])
            for c in r.get("children", []):
                strip(c)

        for row in merged:
            strip(row)
        out.append({"rows": merged, "files": files, "length": length})
    return out


# ---- the card ------------------------------------------------------------

# The card's layout (src/log/sd_log.h): sizes, magic and version, block kinds, stream constants.
BLOCK, HEADER, RECORD, PER_BLOCK = 512, 32, 96, 5
CARD_MAGIC, CARD_VERSION = b"USBTAPLG", 2      # version 1 blocks are records only
KIND_RECORDS, KIND_SECTOR_1, KIND_SECTOR_2, KIND_ZERO, KIND_SHORT, KIND_STREAM, KIND_BLOB = 0, 1, 2, 3, 4, 5, 6
STREAM_PAYLOAD, NONE = 480, 0xFFFF   # a stream block's payload bytes; no item starts here
PART1 = 472                          # a sector's bytes in the block it starts in


def crc_ok(blk):
    """Checks a block's CRC-32: over the whole block with the CRC field as zeros."""
    stored = struct.unpack_from("<I", blk, 28)[0]
    return zlib.crc32(blk[:28] + b"\0\0\0\0" + blk[32:]) == stored


def first_part(path):
    """The log's first part for any part of it: AUDIT.BIN beside an AUDIT001.BIN; None if it is not there."""
    name = os.path.basename(path).upper()
    if not (len(name) == 12 and name.startswith("AUDIT") and name.endswith(".BIN") and name[5:8].isdigit()):
        return path
    folder = os.path.dirname(os.path.abspath(path))
    return next((os.path.join(folder, n) for n in os.listdir(folder) if n.upper() == "AUDIT.BIN"), None)


def part_paths(path):
    """The log's parts beside the first: AUDIT001.BIN, AUDIT002.BIN, ... up to the first missing one."""
    folder = os.path.dirname(os.path.abspath(path))
    names = {n.upper(): n for n in os.listdir(folder)}
    out = []
    while f"AUDIT{len(out) + 1:03d}.BIN" in names:
        out.append(os.path.join(folder, names[f"AUDIT{len(out) + 1:03d}.BIN"]))
    return out


class Parts:
    """The log's parts as one run of blocks: block i is in part i // blocks, a part's first block its header."""

    def __init__(self, path, hdr, first):
        """Opens AUDIT.BIN's parts beside it, stopping at the first that is not the next part of this log."""
        self.blocks, self.data, self.names, self.notes = hdr["blocks"], [first], [os.path.basename(path)], []
        for p in part_paths(path):
            k = len(self.data)
            with open(p, "rb") as f:
                d = f.read()
            h = d[:BLOCK]
            if (len(d) < BLOCK or h[:8] != CARD_MAGIC or not crc_ok(h) or struct.unpack_from("<Q", h, 8)[0] != hdr["file_id"]
                    or struct.unpack_from("<I", h, 16)[0] != k * self.blocks
                    or struct.unpack_from("<I", h, 24)[0] != self.blocks):
                self.notes.append(f"note: {os.path.basename(p)} is not part {k} of this log: it and any after it"
                                  f" are not read")
                break
            self.data.append(d)
            self.names.append(os.path.basename(p))

    def __len__(self):
        """Blocks in all the parts, as indexes."""
        return len(self.data) * self.blocks

    def block(self, i):
        """Block i's 512 bytes (short or empty past what a part's copy holds)."""
        d = self.data[i // self.blocks]
        o = (i % self.blocks) * BLOCK
        return d[o:o + BLOCK]


def read_header(path, h):
    """The header block's fields; raises LogError if it is not the tap's header or not a known format."""
    if h[:8] != CARD_MAGIC or not crc_ok(h) or struct.unpack_from("<I", h, 16)[0] != 0:
        raise LogError(f"{path}: block 0 is not the tap's header (magic {h[:8]!r}, CRC "
                       f"{'ok' if crc_ok(h) else 'BAD'}): not an AUDIT.BIN copied off the tap's card")
    hdr = {"file_id": struct.unpack_from("<Q", h, 8)[0], "version": h[21], "blocks": struct.unpack_from("<I", h, 24)[0],
           "first_lba": struct.unpack_from("<I", h, 32)[0], "record": h[36], "per_block": h[37], "notes": []}
    if hdr["version"] not in (1, CARD_VERSION) or hdr["record"] != RECORD or hdr["per_block"] != PER_BLOCK:
        raise LogError(f"{path}: header describes format version {hdr['version']}, {hdr['record']}-byte records,"
                       f" {hdr['per_block']} per block -- this reader knows version {CARD_VERSION}, {RECORD}, {PER_BLOCK}")
    return hdr


def read_card(path, ckey=None, progress=None):
    """Walks the card's blocks, as (header, [(index, kind, payload)], end index, why it stopped), telling
    `progress(fraction, text)` how far it is."""
    data = open(path, "rb").read()
    if len(data) < 2 * BLOCK:
        raise LogError(f"{path}: {len(data)} bytes, too short for a log")
    hdr = read_header(path, data[:BLOCK])
    file_id = hdr["file_id"]
    have = len(data) // BLOCK
    if have != hdr["blocks"]:
        hdr["notes"].append(f"note: the header says {hdr['blocks']} blocks, the file holds {have} "
                            f"(a partial copy or image is fine as long as it includes the end of the log)")
    card = Parts(path, hdr, data) if have >= hdr["blocks"] else None
    if card is None:
        card = Parts.__new__(Parts)
        card.blocks, card.data, card.names, card.notes = hdr["blocks"], [data], [os.path.basename(path)], []
    hdr["notes"] += card.notes
    hdr["parts"] = card.names
    hdr["tags"] = {}      # each block's boot tag (its session id's low byte; 0 before encryption)

    blocks = []
    i = 1
    limit = (len(card.data) - 1) * card.blocks + min(len(card.data[-1]) // BLOCK, card.blocks)
    why = "end of the last part: every block is in use (the log is FULL)"
    if len(card.data) < 128:
        why += (f" -- if the card has AUDIT{len(card.data):03d}.BIN, copy it beside this file: the log may go on"
                f" there")
    while i < limit:
        if i % card.blocks == 0:
            i += 1            # a part's header
            continue
        if progress and i % 512 == 0:
            progress(0.9 * i / limit, f"reading block {i}")
        b = card.block(i)
        if len(b) < BLOCK:
            why = f"the copy of {card.names[i // card.blocks]} ends here: copy the whole file off the card"
            break
        idx = struct.unpack_from("<I", b, 16)[0]
        fid = struct.unpack_from("<Q", b, 8)[0]
        n = b[20]
        if b[:8] != CARD_MAGIC:
            why = "next block has no tap magic (never written)"
            break
        if fid != file_id:
            why = f"next block belongs to another file (id {fid:016x}): left from before this file was made"
            break
        if idx != i:
            why = f"next block says it is index {idx}: stale, never written in this file's order"
            break
        if not crc_ok(b):
            why = "next block is TORN: this file's magic, id and index but a bad CRC (a write cut short)"
            break
        kind = b[22]
        if b[21] == 3:   # encrypted: the payload opened with the cipher key
            if ckey is None:
                why = "next block is encrypted (version 3) and there is no key (--log-key): cannot read on"
                break
            b = open_block(ckey, b)
            # Opened with the right key, a record block starts with a record's magic.
            if kind == KIND_RECORDS and struct.unpack_from("<I", b, HEADER)[0] != MAGIC:
                why = ("next block does not open with this key: WRONG LOG KEY (not the key this card was"
                       " written with) -- cannot read on")
                break
            kind_ok = kind in (KIND_RECORDS, KIND_STREAM, KIND_BLOB)
        else:
            kind_ok = kind == KIND_RECORDS if b[21] == 1 else (b[21] == CARD_VERSION and kind <= KIND_BLOB)
        if kind == KIND_RECORDS:
            count_ok = 1 <= n <= PER_BLOCK
        elif kind == KIND_BLOB:
            number, used = struct.unpack_from("<HH", b, 24)
            count_ok = 1 <= used <= STREAM_PAYLOAD and n == (1 if number == 0 else 0)
        elif kind == KIND_STREAM:
            first, used = struct.unpack_from("<HH", b, 24)
            count_ok = 1 <= used <= STREAM_PAYLOAD and n <= 48 and (first == NONE if n == 0 else first < used)
        else:
            count_ok = n == 1
        if not kind_ok or not count_ok or (b[23] != 0 and b[21] != 3):
            why = f"next block has version {b[21]}, kind {kind} and {n} items: not valid"
            break
        hdr["tags"][i] = b[23]
        if kind == KIND_RECORDS:
            blocks.append((i, kind, [b[HEADER + r * RECORD:HEADER + (r + 1) * RECORD] for r in range(n)]))
        elif kind == KIND_STREAM:
            first, used = struct.unpack_from("<HH", b, 24)
            blocks.append((i, kind, (used, first, n, b[HEADER:HEADER + used])))
        elif kind == KIND_BLOB:
            number, used = struct.unpack_from("<HH", b, 24)
            blocks.append((i, kind, (number, used, b[HEADER:HEADER + used])))
        else:
            blocks.append((i, kind, b[HEADER:]))
        i += 1
    # Blocks are written in order, so a valid one past the end means the log was damaged in the middle.
    if progress:
        progress(0.9, "looking for blocks past the end of the log")
    after = []
    for j in range(i + 1, limit):
        if j % card.blocks == 0:
            continue
        b = card.block(j)
        if (b[:8] == CARD_MAGIC and struct.unpack_from("<Q", b, 8)[0] == file_id
                and struct.unpack_from("<I", b, 16)[0] == j and crc_ok(b)):
            after.append(j)
    if after and "cannot read on" not in why:   # encrypted, not damaged: there is just no (right) key
        why += (f" -- BUT {len(after)} valid blocks of this file follow it (blocks {after[0]}..{after[-1]}):"
                f" the log is DAMAGED at block {i}, not ended there")
    return hdr, blocks, i, why


def check_key(path, log_key):
    """Tries the log key on the card's first records: (True, False or None, why). None: nothing to try it on."""
    ckey, xkey = chain_key(log_key), cipher_key(log_key)
    with open(path, "rb") as f:
        hdr = read_header(path, f.read(BLOCK))
        for i in range(1, min(hdr["blocks"], 4096)):
            b = f.read(BLOCK)
            if len(b) < BLOCK or b[:8] != CARD_MAGIC or struct.unpack_from("<Q", b, 8)[0] != hdr["file_id"] \
                    or struct.unpack_from("<I", b, 16)[0] != i or not crc_ok(b):
                break
            if b[22] != KIND_RECORDS:
                continue
            if b[21] == 3:
                b = open_block(xkey, b)
                if struct.unpack_from("<I", b, HEADER)[0] != MAGIC:
                    return False, "this key does not open the card's blocks: it is not the key this card was written with"
            r = unpack(b[HEADER:HEADER + RECORD])
            if r["version"] == VERSION_KEYED and r["seq"] == 0 and i == 1:
                if record_hash(ckey, VERSION_KEYED, bytes(32), r["raw"][:64]).hex() != r["sha"]:
                    return False, "this key opens the blocks but does not re-derive the first record's hash"
                return True, "the key opens the card's blocks and re-derives its first record"
            if b[21] == 3:
                return True, "the key opens the card's blocks"
    return None, "the card's first blocks are not encrypted: the key is checked with the chains"


def card_sessions(blocks):
    """The card's records split into sessions (a new id, or a SESSION_START at seq 0), and partial blocks."""
    sessions = []
    partial = 0
    for idx, kind, recs in blocks:
        if kind != KIND_RECORDS:
            continue
        if len(recs) < PER_BLOCK:
            partial += 1
        for raw in recs:
            r = unpack(raw)
            r["block"] = idx
            if (not sessions or sessions[-1][0] != r["session"] or
                    (r["type"] == TYPES["SESSION_START"] and r["seq"] == 0)):
                sessions.append((r["session"], []))
            sessions[-1][1].append(r)
    return sessions, partial


def stored_elsewhere(secs, card_by_lba, lba, n, dig):
    """True if some contents stored anywhere on the card for LBAs lba..lba+n-1 give the digest."""
    tries = [0]

    def walk(h, at):
        """Extends the digest one LBA at a time, over each distinct contents stored for it."""
        if at == lba + n:
            return h.digest()[:16] == dig
        for data in {secs[k][2] for k in card_by_lba.get(at, [])}:
            tries[0] += 1
            if tries[0] > 20000:
                return False
            g = h.copy()
            g.update(struct.pack("<Q", at) + (data if data is not None else bytes(512)))
            if walk(g, at + 1):
                return True
        return False

    return walk(hashlib.sha256(), lba)


def sectors_of(blocks, tags=None):
    """The metadata sectors on the card, [(block, lba, bytes or None, session)], and the blocks cut short."""
    out, cut = [], []
    buf, need = bytearray(), 10
    k = 0
    while k < len(blocks):
        idx, kind, pay = blocks[k]
        if kind == KIND_STREAM:
            used, first, starts, data = pay
            n_starts, n_first = 0, NONE
            for pos in range(used):
                if not buf:
                    n_starts += 1
                    n_first = pos if n_first == NONE else n_first
                buf.append(data[pos])
                if len(buf) == 2:
                    need = 10 + struct.unpack_from("<H", buf, 0)[0]
                    if need > 10 + 512:   # not an item: the stream is damaged from here
                        cut.append(idx)
                        buf, need = bytearray(), 10
                        break
                if len(buf) == need:
                    n = need - 10
                    lba = struct.unpack_from("<Q", buf, 2)[0]
                    out.append([idx, lba, None if n == 0 else bytes(buf[10:]) + bytes(512 - n)])
                    buf, need = bytearray(), 10
            if n_starts != starts or n_first != first:
                cut.append(idx)
            k += 1
            continue
        if kind == KIND_BLOB:   # a model snapshot: no sectors in it
            k += 1
            continue
        if kind == KIND_ZERO:
            out.append([idx, struct.unpack_from("<Q", pay, 0)[0], None])
        elif kind == KIND_SHORT:   # bytes 472..511 are zero
            out.append([idx, struct.unpack_from("<Q", pay, 0)[0], pay[8:8 + PART1] + bytes(512 - PART1)])
        elif kind == KIND_SECTOR_1:
            lba = struct.unpack_from("<Q", pay, 0)[0]
            nxt = blocks[k + 1] if k + 1 < len(blocks) else None
            if nxt and nxt[0] == idx + 1 and nxt[1] == KIND_SECTOR_2 and struct.unpack_from("<Q", nxt[2], 0)[0] == lba:
                out.append([idx, lba, pay[8:8 + PART1] + nxt[2][8:8 + 512 - PART1]])
                k += 1
            else:
                cut.append(idx)
        elif kind == KIND_SECTOR_2:
            cut.append(idx)
        k += 1
    if buf:
        cut.append(blocks[-1][0])   # the stream ends inside an item
    # A sector belongs to the session whose boot wrote its block: the record block before or after it with
    # the block's boot tag (the session id's low byte); without one, the next record block's session.
    session_after, session_before = {}, {}
    sid = None
    for idx, kind, pay in reversed(blocks):
        if kind == KIND_RECORDS:
            sid = struct.unpack_from("<Q", pay[0], 16)[0]
        session_after[idx] = sid
    sid = None
    for idx, kind, pay in blocks:
        if kind == KIND_RECORDS:
            sid = struct.unpack_from("<Q", pay[0], 16)[0]
        session_before[idx] = sid
    for sec in out:
        after, before = session_after[sec[0]], session_before[sec[0]]
        tag = (tags or {}).get(sec[0], 0)
        if tag and before is not None and before & 0xFF == tag and (after is None or after & 0xFF != tag):
            sec.append(before)
        else:
            sec.append(after if after is not None else before)
    return out, cut


def model_snapshot(blocks, first):
    """The model snapshot starting at block `first`, put back together; None if it is not whole and sound."""
    at = {idx: k for k, (idx, _kind, _pay) in enumerate(blocks)}
    data = bytearray()
    k, number = at.get(first, len(blocks)), 0
    while True:
        _idx, kind, pay = blocks[k] if k < len(blocks) else (None, None, None)
        if kind != KIND_BLOB or pay[0] != number:
            return None
        data += pay[2]
        if pay[1] < STREAM_PAYLOAD:
            break
        if len(data) >= 12 and len(data) >= 12 + struct.unpack_from("<I", data, 8)[0] + 32:
            break
        k, number = k + 1, number + 1
    if len(data) < 44 or data[:4] != b"EXFS":
        return None
    total = 12 + struct.unpack_from("<I", data, 8)[0] + 32
    if len(data) != total or hashlib.sha256(bytes(data[:-32])).digest() != bytes(data[-32:]):
        return None
    return bytes(data)


def snapshot_volume(snap):
    """The volume a sound model snapshot describes: its layout and the folders known (src/fs/exfat_model.c)."""
    (have, boot, heap, shift, clusters, root, serial, fat_offset, fat_length, _bf, _bc, _uf, _uc, _stamp, _pn, _fn,
     ndirs) = struct.unpack_from("<BQQBIIIIIIIIIIIII", snap, 12)
    return {"have": bool(have), "boot": boot, "heap": heap, "shift": shift, "clusters": clusters, "root": root,
            "serial": serial, "fat_offset": fat_offset, "fat_length": fat_length, "folders": ndirs}


def verify_card(path, log_key, progress=None):
    """Reads AUDIT.BIN and checks its blocks, chains, sectors and models, returning the report and each
    session's records, events and verdicts."""
    ckey = chain_key(log_key) if log_key else None
    hdr, blocks, end, why = read_card(path, cipher_key(log_key) if log_key else None, progress)
    if progress:
        progress(0.93, "checking the chains")
    damaged = "DAMAGED" in why
    sessions, partial = card_sessions(blocks)
    secs, cut = sectors_of(blocks, hdr["tags"])
    damaged = damaged or any(blocks_kind == KIND_STREAM for blocks_kind in
                             (kd for ix, kd, _ in blocks if ix in set(cut)))

    bad = 0
    report_sessions = []
    card_by_lba = None      # LBA -> positions of the card's sectors with it, built on first use
    used_secs = set()       # positions already vouched for by a record
    vouched = {}            # position -> the seq of the SECTOR record vouching for it
    last_head = bytes(32)   # the previous session's last hash: what a keyed session follows
    prev_end = -1           # the last block of the session before, to count each one's sectors
    for sid, recs in sessions:
        keyed = recs[0]["version"] == VERSION_KEYED
        prev = last_head if keyed else bytes(32)
        problems = []
        break_seq = None    # the record where the chain stops re-deriving (0: the session's first)
        if keyed and ckey is not None and "WRONG LOG KEY" in why:
            problems.append("keyed session and the log key is not this card's: not checked")
        elif keyed and ckey is None:
            problems.append("keyed session and no key (--log-key): not checked")
        elif keyed and recs[0]["lba"] != genesis_tag(prev):
            problems.append("does not follow the session before it on the card (a session missing, reordered "
                            "or replaced) -- chain BROKEN here")
            break_seq = 0
        for k, r in enumerate(recs):
            if problems:
                break
            if r["magic"] != MAGIC or r["version"] != recs[0]["version"]:
                problems.append(f"seq {r['seq']}: record magic/version wrong")
            if r["seq"] != k:
                problems.append(f"record {k} has seq {r['seq']} (a gap or a repeat)")
                break_seq = r["seq"]
                break
            h = record_hash(ckey, r["version"], prev, r["raw"][:64])
            if h.hex() != r["sha"]:
                problems.append(f"seq {r['seq']} (block {r['block']}): hash does not re-derive -- chain BROKEN here")
                break_seq = r["seq"]
                break
            prev = h
        last_head = prev
        nsec = sum(1 for x in secs if x[3] == sid and prev_end < x[0] <= recs[-1]["block"])
        prev_end = recs[-1]["block"]
        session_bad = bool(problems)

        # Each SECTOR record vouches for `aux` sectors from `lba` (aux 0: an early one-sector form, or
        # none when its status, the new sectors the card refused, is not 0).
        runs = [(r["lba"], r["aux"] or (0 if r["status"] else 1), r["raw"][40:56], r["aux"] != 0, r["status"], r["block"],
                 r["seq"]) for r in recs if r["type"] == TYPES["SECTOR"]]
        sectors = None
        if runs:
            if card_by_lba is None:
                card_by_lba = {}
                for k, x in enumerate(secs):
                    card_by_lba.setdefault(x[1], []).append(k)
            missing, elsewhere = [], 0
            for lba, n, dig, with_lba, _, block, seq in runs:
                if n == 0:
                    continue
                found = False
                # Its own session's sectors, the nearest to it on the card first.
                for k in sorted(card_by_lba.get(lba, []), key=lambda k: abs(secs[k][0] - block)):
                    if k in used_secs or k + n > len(secs) or secs[k][3] != sid:
                        continue
                    h = hashlib.sha256()
                    for x in secs[k:k + n]:
                        h.update((struct.pack("<Q", x[1]) if with_lba else b"") +
                                 (x[2] if x[2] is not None else bytes(512)))
                    if h.digest()[:16] == dig:
                        used_secs.update(range(k, k + n))
                        vouched.update((j, seq) for j in range(k, k + n))
                        found = True
                        break
                if not found and with_lba and stored_elsewhere(secs, card_by_lba, lba, n, dig):
                    elsewhere += 1
                    found = True
                if not found:
                    missing.append(lba)
            sectors = {"records": sum(1 for run in runs if run[1]), "sectors": sum(run[1] for run in runs),
                       "missing": missing, "elsewhere": elsewhere, "refused": sum(run[4] for run in runs),
                       "loose": sum(1 for k, x in enumerate(secs) if x[3] == sid and k not in used_secs)}
            session_bad = session_bad or bool(missing)

        # Each MODEL SAVED record vouches for a snapshot: its first block, serial and digest.
        models = [r for r in recs if r["type"] == TYPES["MODEL"]]
        volumes = {}        # serial -> the volume as the last sound snapshot of this session gives it
        model_check = None
        if models:
            saved = []
            for r in models:
                if r["op"] != 1:
                    continue
                snap = model_snapshot(blocks, r["lba"])
                serial = struct.unpack_from("<I", r["raw"], 56)[0]
                good = snap is not None and snap[-32:-16] == r["raw"][40:56]
                if good:
                    volumes[serial] = snapshot_volume(snap)
                saved.append({"serial": serial, "block": r["lba"], "bytes": len(snap) if snap else 0, "good": good})
            model_check = {"saved": saved, "loaded": sum(1 for r in models if r["op"] == 2),
                           "refused": [(r["lba"], r["status"]) for r in models if r["op"] == 3]}
            session_bad = session_bad or not all(m["good"] for m in saved)

        # The session's file events, from a chain that checked out.
        events = file_events(recs) if not problems else []
        times = pc_times(events, secs, vouched, sid)
        bad += 1 if session_bad else 0
        report_sessions.append({"sid": sid, "recs": recs, "events": events, "problems": problems, "keyed": keyed,
                                "ok": not session_bad, "ended": recs[-1]["type"] == TYPES["SESSION_END"],
                                "sectors": nsec, "head": prev, "break_seq": break_seq, "volumes": volumes,
                                "sector_check": sectors, "model_check": model_check, "pc_times": times})

    if "cannot read on" in why:
        status = 2   # encrypted and no (right) key: nothing was checked
    else:
        status = 1 if bad or damaged else 0
    if progress:
        progress(1.0, "done")
    return {"hdr": hdr, "end": end, "why": why, "damaged": damaged, "sessions": report_sessions,
            "partial": partial, "zero": sum(1 for x in secs if x[2] is None), "secs": len(secs), "cut": cut,
            "exit": status}


# ---- card care: a long log is cleared now and then ------------------------

# The tap's start-up check, per block of log (measured: 21.5 s for 23,706 blocks).
CHECK_MS_PER_BLOCK = 0.9
# Start-up checks shorter than these are "Good", then "Clean up soon"; longer ones "Clean up now".
GOOD_CHECK_S, SOON_CHECK_S = 30, 90
# The most of a card password the tap reads.
PASSWORD_MAX_BYTES = 128


def card_health(report):
    """The card's state from its log's size: ("good" | "soon" | "now", the words for it)."""
    hdr, end = report["hdr"], report["end"]
    used = (end - 1) - (end - 1) // hdr["blocks"]
    seconds = used * CHECK_MS_PER_BLOCK / 1000
    level = "good" if seconds < GOOD_CHECK_S else "soon" if seconds < SOON_CHECK_S else "now"
    head = {"good": "Good", "soon": "Clean up soon", "now": "Clean up now"}[level]
    return level, f"Card: {head} ({fmt_bytes(used * BLOCK)} of log)"


def removable_drives():
    """The removable drives with a card in them, as [(root, label)]; [] off Windows."""
    try:
        import ctypes
        kernel = ctypes.windll.kernel32
    except (ImportError, AttributeError):
        return []
    out = []
    mask = kernel.GetLogicalDrives()
    for i in range(26):
        root = f"{chr(65 + i)}:\\"
        if mask >> i & 1 and kernel.GetDriveTypeW(root) == 2 and os.path.isdir(root):   # 2: removable
            name = ctypes.create_unicode_buffer(261)
            kernel.GetVolumeInformationW(root, name, 261, None, None, None, None, 0)
            out.append((root, name.value))
    return out


def log_files(folder):
    """The tap's log in a folder: AUDIT.BIN and its parts, in order; [] if there is none."""
    first = next((os.path.join(folder, n) for n in os.listdir(folder) if n.upper() == "AUDIT.BIN"), None)
    return [first] + part_paths(first) if first else []


def back_up(files, folder, progress=None):
    """Copies the files into folder, then checks each copy against what was read from the card."""
    total, done = sum(os.path.getsize(f) for f in files), 0
    for f in files:
        copy, digest = os.path.join(folder, os.path.basename(f)), hashlib.sha256()
        with open(f, "rb") as src, open(copy, "xb") as dst:
            while chunk := src.read(4 << 20):
                digest.update(chunk)
                dst.write(chunk)
                done += len(chunk)
                if progress:
                    progress(0.9 * done / total, f"Copying {os.path.basename(f)}")
            dst.flush()
            os.fsync(dst.fileno())
        check = hashlib.sha256()
        with open(copy, "rb") as back:
            while chunk := back.read(4 << 20):
                check.update(chunk)
        if check.digest() != digest.digest():
            raise OSError(f"the copy of {os.path.basename(f)} does not match the card")


def clean_card(card, backups, password, progress=None):
    """Backs the card's log up into a new folder in `backups`, deletes it and leaves card_password.txt, so
    the tap takes the card as new; returns the folder, or None with no log."""
    files = log_files(card)
    folder = None
    if files:
        folder = os.path.join(backups, time.strftime("Tap log %Y-%m-%d %H.%M.%S"))
        os.makedirs(folder)
        back_up(files, folder, progress)
        for f in reversed(files):   # AUDIT.BIN last: a log cut short is refused, never extended
            os.remove(f)
    with open(os.path.join(card, "card_password.txt"), "w", encoding="utf-8", newline="") as f:
        f.write(password)
        f.flush()
        os.fsync(f.fileno())
    return folder


# ---- the window ----------------------------------------------------------

def fmt_clock(ns):
    """A time into a session: 03:21.209, or 4:17:28.7 past an hour."""
    s = max(ns, 0) / 1e9
    if s >= 3600:
        return f"{int(s // 3600)}:{int(s % 3600 // 60):02d}:{s % 60:04.1f}"
    return f"{int(s // 60):02d}:{s % 60:06.3f}"


def problem_text(report):
    """What is wrong with a card that failed its check, in a few words."""
    for i, s in enumerate(report["sessions"]):
        if s["break_seq"] is not None:
            return f"session {i + 1} was altered or damaged (record {s['break_seq']})"
        if s["problems"]:
            return f"session {i + 1} could not be checked"
        if not s["ok"]:
            return f"session {i + 1}: stored data does not match the log"
    return "the log file is damaged"


def run_gui(path=None):
    """Opens the window: choose AUDIT.BIN, give the log key, verify, then read what happened to the drive."""
    # tkinter only here, so the text check needs no display.
    import queue
    import threading
    import tkinter as tk
    from tkinter import filedialog, font, ttk

    # Sharp text on a scaled Windows display, instead of a blurred bitmap stretch.
    try:
        import ctypes
        ctypes.windll.shcore.SetProcessDpiAwareness(1)
    except (AttributeError, OSError):
        pass
    root = tk.Tk()
    root.title("Tap Log Reader")
    root.geometry("1400x860")
    root.minsize(960, 600)
    style = ttk.Style(root)
    if "vista" in style.theme_names():
        style.theme_use("vista")
    style.configure("Treeview", rowheight=24)

    path_var = tk.StringVar(value=path or "")
    key_var = tk.StringVar()
    show_var = tk.BooleanVar(value=False)
    status_var = tk.StringVar(value="")
    search_var = tk.StringVar()
    state = {"report": None, "activity": None, "sel": None, "busy": False}
    work = queue.Queue()

    # The file and the key.
    top = ttk.Frame(root, padding=(10, 10, 10, 4))
    top.pack(fill="x")
    ttk.Label(top, text="AUDIT.BIN").grid(row=0, column=0, sticky="w")
    path_entry = ttk.Entry(top, textvariable=path_var, width=90)
    path_entry.grid(row=0, column=1, sticky="we", padx=6)

    def browse():
        """Asks for the AUDIT.BIN to read."""
        chosen = filedialog.askopenfilename(title="AUDIT.BIN copied off the tap's card",
                                            filetypes=[("Tap log", "AUDIT.BIN *.BIN *.bin"), ("All files", "*.*")])
        if chosen:
            path_var.set(chosen)

    ttk.Button(top, text="Browse...", command=browse).grid(row=0, column=2, sticky="w")
    ttk.Label(top, text="Log key").grid(row=1, column=0, sticky="w", pady=(6, 0))
    key_entry = ttk.Entry(top, textvariable=key_var, width=90, show="•")
    key_entry.grid(row=1, column=1, sticky="we", padx=6, pady=(6, 0))

    def toggle_show():
        """Shows or hides the key as it is typed."""
        key_entry.configure(show="" if show_var.get() else "•")

    ttk.Checkbutton(top, text="Show", variable=show_var, command=toggle_show).grid(row=1, column=2, sticky="w",
                                                                                   pady=(6, 0))
    verify_button = ttk.Button(top, text="Verify", width=12)
    verify_button.grid(row=0, column=3, rowspan=2, sticky="ns", padx=(10, 0))
    top.columnconfigure(1, weight=1)

    # A banner only when something is wrong; progress and a short status line.
    banner = tk.Label(root, text="", font=("Segoe UI", 12, "bold"), anchor="w", justify="left", padx=12, pady=6,
                      foreground="#b3261e", background="#fce8e6")
    banner.bind("<Configure>", lambda e: banner.configure(wraplength=max(200, e.width - 24)))
    bar = ttk.Progressbar(root, mode="determinate", maximum=1.0)
    bar.pack(fill="x", padx=10, pady=(2, 0))
    status = ttk.Label(root, textvariable=status_var, padding=(12, 2))
    status.pack(fill="x")
    care = ttk.Frame(root, padding=(12, 2))
    care.pack(fill="x")
    health = ttk.Label(care, text="", font=("Segoe UI", 10, "bold"))
    health.pack(side="left")
    clean_button = ttk.Button(care, text="Clean up card")
    clean_button.pack(side="left", padx=(12, 0))

    def show_banner(text):
        """Shows the red banner with `text`, or hides it when text is empty."""
        if text:
            banner.configure(text=text)
            banner.pack(fill="x", padx=10, before=bar)
        else:
            banner.pack_forget()

    # Sessions on the left; what happened on the right.
    panes = ttk.PanedWindow(root, orient="horizontal")
    panes.pack(fill="both", expand=True, padx=10, pady=(4, 10))
    left = ttk.Frame(panes)
    panes.add(left, weight=1)
    ttk.Label(left, text="Sessions", font=("Segoe UI", 10, "bold")).pack(anchor="w")
    s_cols = ("length", "changes", "integrity")
    sessions_tree = ttk.Treeview(left, columns=s_cols, selectmode="browse")
    sessions_tree.heading("#0", text="Session")
    sessions_tree.column("#0", width=110, stretch=True)
    for col, text, width in zip(s_cols, ("Length", "Changes", "Check"), (80, 70, 80)):
        sessions_tree.heading(col, text=text)
        sessions_tree.column(col, width=width, anchor="w", stretch=False)
    sessions_tree.tag_configure("bad", background="#fce8e6")
    sessions_tree.tag_configure("all", font=("Segoe UI", 9, "bold"))
    sessions_tree.pack(fill="both", expand=True)

    right = ttk.Frame(panes)
    panes.add(right, weight=4)
    tabs = ttk.Notebook(right)
    tabs.pack(fill="both", expand=True)

    def tree_with_scroll(parent, columns, headings, widths, stretch, show="headings"):
        """A Treeview with a vertical scrollbar, its columns set up."""
        frame = ttk.Frame(parent)
        frame.pack(fill="both", expand=True)
        tree = ttk.Treeview(frame, columns=columns, show=show, selectmode="browse")
        for col, text, width in zip(columns, headings, widths):
            tree.heading(col, text=text)
            tree.column(col, width=width, anchor="w", stretch=col in stretch)
        scroll = ttk.Scrollbar(frame, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=scroll.set)
        scroll.pack(side="right", fill="y")
        tree.pack(fill="both", expand=True)
        return tree

    # Activity: what happened, in words.
    act_tab = ttk.Frame(tabs, padding=4)
    tabs.add(act_tab, text="Activity")
    act_bar = ttk.Frame(act_tab)
    act_bar.pack(fill="x", pady=(0, 4))
    ttk.Label(act_bar, text="Search").pack(side="left")
    ttk.Entry(act_bar, textvariable=search_var, width=40).pack(side="left", padx=6)
    act_count = ttk.Label(act_bar, text="")
    act_count.pack(side="right")
    key_bar = ttk.Frame(act_tab)
    key_bar.pack(fill="x", pady=(0, 4))
    for _tag, colour, words in TONES:
        ttk.Label(key_bar, text="\u25a0 " + words, foreground=colour, font=("Segoe UI", 9, "bold")).pack(
            side="left", padx=(0, 14))
    approx_key = ttk.Label(key_bar, text="\u2248 PC time estimated")
    approx_key.pack(side="right")
    # PC time first (an estimate's sign before it), then the tap's time, then the event, which carries the
    # open/close sign of a row with rows inside (a click on it toggles them).
    act_tree = tree_with_scroll(act_tab, ("pc", "time", "event", "details"),
                                ("PC time", "Tap time", "Event", "Details"),
                                (230, 90, 440, 280), {"event", "details"})
    for tag, colour, _words in TONES:
        act_tree.tag_configure(tag, foreground=colour)
    act_tree.tag_configure("unverified", foreground="#9aa0a6", font=("Segoe UI", 9, "italic"))
    act_tree.tag_configure("header", background="#e8eaed", font=("Segoe UI", 9, "bold"))

    # Files: everything that happened to each file.
    file_tab = ttk.Frame(tabs, padding=4)
    tabs.add(file_tab, text="Files")
    ttk.Label(file_tab, text="Double-click a file to see its activity. PC times are what the PC wrote on the "
                             "drive, from its own clock, which can be set to anything.").pack(anchor="w", pady=(0, 4))
    files_tree = tree_with_scroll(file_tab, ("file", "what", "read", "written", "first", "last", "created", "modified"),
                                  ("File or folder", "Events", "Read", "Written", "First seen", "Last seen",
                                   "PC created", "PC modified"),
                                  (300, 200, 70, 70, 90, 90, 190, 190), {"file", "what"})
    for tag, colour, _words in TONES:
        files_tree.tag_configure(tag, foreground=colour)

    # Drive: what the log knows of the drive in the chosen session(s).
    drive_tab = ttk.Frame(tabs, padding=4)
    tabs.add(drive_tab, text="Drive")
    drive_tree = tree_with_scroll(drive_tab, ("what", "value"), ("", ""), (220, 400), {"value"}, show="")

    def chosen_sessions():
        """The sessions picked on the left: all of them, or one."""
        report, sel = state["report"], state["sel"]
        if report is None or sel is None:
            return []
        return list(range(len(report["sessions"]))) if sel == "all" else [sel]

    def matches(row, needle):
        """True if a row (or one of its children) contains the search text."""
        text = f"{row['text']} {row['detail']} {row.get('path') or ''}".lower()
        return needle in text or any(matches(c, needle) for c in row.get("children", []))

    def pad_like(text):
        """Spaces as wide as `text` in the window's font, so an exact PC time starts where an estimate's digits do."""
        f = font.nametofont("TkDefaultFont")
        target = f.measure(text)
        pads = (" " * a + " " * b + " " * c for a in range(4) for b in range(5) for c in range(4))
        return min(pads, key=lambda p: (abs(f.measure(p) - target), len(p)))

    approx_pad = pad_like("≈ ")
    CLOSED, OPENED = "▶  ", "▼  "    # the sign of a row with rows inside, shut and open
    sign_pad = pad_like(CLOSED)
    events_text = {}     # iid -> (indent, event text), to redraw a row's sign

    def show_sign(iid):
        """Writes a row's event with its open/close sign, or the sign's width of space when it has no rows inside."""
        indent, text = events_text[iid]
        sign = (OPENED if act_tree.item(iid, "open") else CLOSED) if act_tree.get_children(iid) else sign_pad
        act_tree.set(iid, "event", indent + sign + text)

    def act_insert(parent, row, detail, depth, tags, is_open):
        """Adds a row: the PC time (an estimate's sign before it, an exact one padded as wide), the tap time, the
        event (indented by depth), details."""
        pc = row.get("pc", "")
        iid = act_tree.insert(parent, "end", values=(pc if pc.startswith("≈ ") or not pc else approx_pad + pc,
                                                     "" if row.get("notime") else fmt_clock(row["ts"]), "", detail),
                              tags=tags, open=is_open)
        events_text[iid] = (sign_pad * depth, row["text"])
        return iid

    def insert_children(iid, row, needle, depth=1):
        """Adds a row's children under it, and theirs under them; a search opens the branches it matches."""
        for c in row.get("children", []):
            cid = act_insert(iid, c, c["detail"], depth, ("unverified",) if c["unverified"] else (tone(c),),
                             bool(needle) and matches(c, needle))
            insert_children(cid, c, needle, depth + 1)
        if needle and matches(row, needle) and needle not in f"{row['text']} {row['detail']} {row.get('path') or ''}".lower():
            act_tree.item(iid, open=True)
        show_sign(iid)

    def toggle(event):
        """Opens or shuts the rows inside the row clicked."""
        iid = act_tree.identify_row(event.y)
        if iid and act_tree.get_children(iid) and act_tree.identify_region(event.x, event.y) == "cell":
            act_tree.item(iid, open=not act_tree.item(iid, "open"))
            show_sign(iid)

    act_tree.bind("<ButtonRelease-1>", toggle)
    for opened in ("<<TreeviewOpen>>", "<<TreeviewClose>>"):    # the arrow keys: sent before the change
        act_tree.bind(opened, lambda _e: act_tree.after_idle(lambda: act_tree.focus() and show_sign(act_tree.focus())))

    def show_activity():
        """Fills the Activity tab for the chosen session(s), filtered and searched."""
        act_tree.delete(*act_tree.get_children())
        events_text.clear()
        needle = search_var.get().strip().lower()
        shown = 0
        many = state["sel"] == "all"
        with_pc = any(r.get("pc") for i in chosen_sessions() for r in state["activity"][i]["rows"])
        shown_pc = act_tree["displaycolumns"][0] in ("pc", "#all")
        if with_pc != shown_pc:   # the PC time column shown or hidden: Details gives or takes its room
            room = act_tree.column("pc", "width")
            act_tree.column("details", width=max(100, act_tree.column("details", "width") + (-room if with_pc else room)))
        act_tree["displaycolumns"] = ("pc", "time", "event", "details") if with_pc else ("time", "event", "details")
        approx_key.configure(text="≈ PC time estimated" if with_pc else "")
        for i in chosen_sessions():
            a = state["activity"][i]
            if many:
                s = state["report"]["sessions"][i]
                act_tree.insert("", "end", values=("", "", f"Session {i + 1}", f"{fmt_span(a['length'])}; "
                                                   + ("OK" if s["ok"] else "ALTERED")),
                                tags=("header",), open=True)
            for row in a["rows"]:
                if needle and not matches(row, needle):
                    continue
                tags = ("unverified",) if row["unverified"] else (tone(row),)
                detail = ("Unverified: " if row["unverified"] else "") + row["detail"]
                iid = act_insert("", row, detail, 0, tags, False)
                insert_children(iid, row, needle)
                shown += 1
        act_count.configure(text=f"{shown} event(s)")

    def show_files():
        """Fills the Files tab: every file and folder of the chosen session(s), what happened and how much moved."""
        files_tree.delete(*files_tree.get_children())
        merged = {}
        for i in chosen_sessions():
            for path, f in state["activity"][i]["files"].items():
                m = merged.setdefault(path, {"what": [], "read": 0, "written": 0, "first": None, "last": None,
                                             "sessions": []})
                for w in f["what"]:
                    if w not in m["what"]:
                        m["what"].append(w)
                m["read"] += f["read"]
                m["written"] += f["written"]
                m["sessions"].append(i)
                first = (i, f["first"])
                m["first"] = m["first"] or first
                m["last"] = (i, f["last"])
                if f.get("pc_created") or f.get("pc_modified"):
                    m["pc"] = (f.get("pc_created", ""), f.get("pc_modified", ""))
        many = state["sel"] == "all"
        for path in sorted(merged, key=str.lower):
            m = merged[path]
            when = (lambda p: f"S{p[0] + 1} {fmt_clock(p[1])}") if many else (lambda p: fmt_clock(p[1]))
            files_tree.insert("", "end", values=(path, ", ".join(m["what"]) or "read",
                                                 fmt_bytes(m["read"]) if m["read"] else "",
                                                 fmt_bytes(m["written"]) if m["written"] else "",
                                                 when(m["first"]), when(m["last"])) + m.get("pc", ("", "")),
                              tags=(file_tone(m["what"]),))

    def show_drive():
        """Fills the Drive tab for the chosen session(s)."""
        drive_tree.delete(*drive_tree.get_children())
        chosen = chosen_sessions()
        if chosen:
            for label, value in drive_facts(state["report"]["sessions"], chosen, state["activity"]):
                drive_tree.insert("", "end", values=(label, value))

    def show_session(_event=None):
        """Shows the session(s) chosen on the left in every tab."""
        chosen = sessions_tree.selection()
        if not chosen or state["report"] is None:
            return
        state["sel"] = "all" if chosen[0] == "all" else int(chosen[0])
        show_activity()
        show_files()
        show_drive()

    def show_file_activity(_event=None):
        """Shows the Activity tab searched for the file double-clicked."""
        chosen = files_tree.selection()
        if chosen:
            search_var.set(files_tree.item(chosen[0], "values")[0])
            tabs.select(0)

    def fill(report, activity):
        """Shows a finished verification: the sessions, and the most recent (or the first broken) one."""
        state["report"], state["activity"] = report, activity
        sessions = report["sessions"]
        if report["exit"] == 2:
            show_banner("Wrong log key")
        elif report["exit"] != 0:
            show_banner("Problem: " + problem_text(report))
        sessions_tree.delete(*sessions_tree.get_children())
        total = sum(sum(1 for r in a["rows"] if r["kind"] == CHANGE) for a in activity)
        sessions_tree.insert("", "end", iid="all", text="All sessions", tags=("all",),
                             values=(fmt_span(sum(a["length"] for a in activity)), total,
                                     "OK" if report["exit"] == 0 else "PROBLEM"))
        for i, (s, a) in enumerate(zip(sessions, activity)):
            changes = sum(1 for r in a["rows"] if r["kind"] == CHANGE)
            integrity = "OK" if s["ok"] else "ALTERED"
            sessions_tree.insert("", "end", iid=str(i), text=f"Session {i + 1}", tags=() if s["ok"] else ("bad",),
                                 values=(fmt_span(a["length"]), changes, integrity))
        first_bad = next((str(i) for i, s in enumerate(sessions) if not s["ok"]), None)
        pick = first_bad or (str(len(sessions) - 1) if sessions else "all")
        sessions_tree.selection_set(pick)
        sessions_tree.see(pick)
        status_var.set(f"{len(sessions)} session{'s' if len(sessions) != 1 else ''}")
        level, words = card_health(report)
        health.configure(text=words, foreground={"good": "#188038", "soon": "#c26401", "now": "#b3261e"}[level])

    def ask_cleanup():
        """Asks for the card, where to keep the backup and the card password, then starts the cleanup."""
        if state["busy"]:
            return
        from tkinter import messagebox
        win = tk.Toplevel(root)
        win.title("Clean up card")
        win.transient(root)
        win.grab_set()
        form = ttk.Frame(win, padding=14)
        form.pack(fill="both", expand=True)
        ttk.Label(form, text="Backs up the log, then clears the card.", justify="left").grid(row=0, column=0, columnspan=3, sticky="w", pady=(0, 10))
        card_var, dest_var = tk.StringVar(), tk.StringVar(value=os.path.join(os.path.expanduser("~"), "Documents"))
        pw_var, again_var, pw_show = tk.StringVar(), tk.StringVar(), tk.BooleanVar(value=False)

        def drives():
            """The removable drives, each with whether it holds a log."""
            out = []
            for root_, label in removable_drives():
                has = bool(log_files(root_))
                out.append(f"{root_[:2]}" + (" (has log)" if has else ""))
            return out

        ttk.Label(form, text="SD card").grid(row=1, column=0, sticky="w")
        card_box = ttk.Combobox(form, textvariable=card_var, state="readonly", width=40, values=drives())
        card_box.grid(row=1, column=1, sticky="we", padx=6)
        ttk.Button(form, text="Refresh", command=lambda: card_box.configure(values=drives())).grid(row=1, column=2)
        ttk.Label(form, text="Back up to").grid(row=2, column=0, sticky="w", pady=(6, 0))
        ttk.Entry(form, textvariable=dest_var, width=40).grid(row=2, column=1, sticky="we", padx=6, pady=(6, 0))
        ttk.Button(form, text="Browse...",
                   command=lambda: dest_var.set(filedialog.askdirectory(parent=win, title="Where to keep the backup")
                                                or dest_var.get())).grid(row=2, column=2, pady=(6, 0))
        ttk.Label(form, text="Card password").grid(row=3, column=0, sticky="w", pady=(6, 0))
        pw_entry = ttk.Entry(form, textvariable=pw_var, width=40, show="\u2022")
        pw_entry.grid(row=3, column=1, sticky="we", padx=6, pady=(6, 0))
        ttk.Label(form, text="Again").grid(row=4, column=0, sticky="w", pady=(6, 0))
        again_entry = ttk.Entry(form, textvariable=again_var, width=40, show="\u2022")
        again_entry.grid(row=4, column=1, sticky="we", padx=6, pady=(6, 0))
        ttk.Checkbutton(form, text="Show", variable=pw_show,
                        command=lambda: [e.configure(show="" if pw_show.get() else "\u2022")
                                         for e in (pw_entry, again_entry)]).grid(row=3, column=2, sticky="w")
        form.columnconfigure(1, weight=1)

        def start():
            """Checks what was given, confirms, and runs the cleanup off the window's thread."""
            card = card_var.get()[:2] + "\\" if card_var.get() else ""
            dest = dest_var.get().strip().strip('"')
            password = pw_var.get()
            problem = ("Choose the SD card" if not card or not os.path.isdir(card) else
                       "Choose a backup folder" if not os.path.isdir(dest) else
                       "The backup can't go on the card" if os.path.splitdrive(os.path.abspath(dest))[0].upper()
                       == card[:2].upper() else
                       "Type the password" if not password else
                       "The passwords differ" if password != again_var.get() else
                       "Password too long"
                       if len(password.encode("utf-8")) > PASSWORD_MAX_BYTES else None)
            files = log_files(card) if not problem else []
            if not problem and files and shutil.disk_usage(dest).free < sum(os.path.getsize(f) for f in files):
                problem = "Not enough space for the backup"
            if problem:
                messagebox.showerror("Clean up card", problem, parent=win)
                return
            ask = (f"Back up the log to {dest} and clear {card[:2]}?" if files else
                   f"No log on {card[:2]}. Just save the password?")
            if not messagebox.askyesno("Clean up card", ask, parent=win):
                return
            win.destroy()
            state["busy"] = True
            verify_button.configure(state="disabled")
            clean_button.configure(state="disabled")
            bar["value"] = 0.0
            status_var.set("Cleaning up...")
            threading.Thread(target=clean_worker, args=(card, dest, password), daemon=True).start()

        buttons = ttk.Frame(form)
        buttons.grid(row=5, column=0, columnspan=3, sticky="e", pady=(12, 0))
        ttk.Button(buttons, text="Cancel", command=win.destroy).pack(side="right")
        ttk.Button(buttons, text="Clean up", command=start).pack(side="right", padx=6)

    def clean_worker(card, dest, password):
        """Backs up and clears the card, off the window's thread."""
        try:
            folder = clean_card(card, dest, password, lambda f, t: work.put(("progress", f, t)))
            work.put(("cleaned", folder))
        except OSError as exc:
            work.put(("clean_error", str(exc)))

    def worker(path, log_key):
        """Checks the key, verifies the whole file and builds the activity, off the window's thread."""
        try:
            ok, why = check_key(path, log_key)
            work.put(("key", ok, why))
            if ok is False:
                return
            report = verify_card(path, log_key, lambda f, t: work.put(("progress", f, t)))
            work.put(("progress", 0.98, "reading what happened"))
            work.put(("done", report, build_activity(report["sessions"])))
        except (LogError, OSError) as exc:
            work.put(("error", str(exc)))

    def poll():
        """Takes the worker's news into the window."""
        try:
            while True:
                item = work.get_nowait()
                if item[0] == "progress":
                    bar["value"] = item[1]
                    status_var.set("Checking...")
                elif item[0] == "key":
                    if item[1] is False:
                        show_banner("Wrong log key")
                        status_var.set("")
                        finish()
                    else:
                        status_var.set("Checking...")
                elif item[0] == "done":
                    fill(item[1], item[2])
                    finish()
                elif item[0] == "error":
                    show_banner("Not a tap log file")
                    status_var.set("")
                    finish()
                elif item[0] == "cleaned":
                    from tkinter import messagebox
                    status_var.set("Card cleaned up")
                    finish()
                    messagebox.showinfo("Clean up card", f"Done. Backup: {item[1]}" if item[1] else "Done.",
                                        parent=root)
                elif item[0] == "clean_error":
                    from tkinter import messagebox
                    status_var.set("")
                    finish()
                    messagebox.showerror("Clean up card", f"Stopped: {item[1]}", parent=root)
        except queue.Empty:
            pass
        root.after(100, poll)

    def finish():
        """Lets the window be used again, and forgets the key."""
        state["busy"] = False
        key_var.set("")
        verify_button.configure(state="normal")
        clean_button.configure(state="normal")
        bar["value"] = 1.0 if state["report"] else 0.0

    def verify(_event=None):
        """Starts a verification of the chosen file with the typed key."""
        if state["busy"]:
            return
        path = path_var.get().strip().strip('"')
        if not os.path.isfile(path):
            show_banner("Choose a file")
            return
        if first_part(path) is None:
            show_banner(f"{os.path.basename(path)} is a later part of the log: put AUDIT.BIN beside it")
            return
        path = first_part(path)
        path_var.set(path)
        log_key = parse_log_key(key_var.get())
        if log_key is None:
            show_banner("The key is 64 hex digits")
            key_entry.focus_set()
            return
        show_banner("")
        state.update(busy=True, report=None, activity=None, sel=None)
        verify_button.configure(state="disabled")
        for tree in (sessions_tree, act_tree, files_tree, drive_tree):
            tree.delete(*tree.get_children())
        bar["value"] = 0.0
        status_var.set("Checking...")
        threading.Thread(target=worker, args=(path, log_key), daemon=True).start()

    verify_button.configure(command=verify)
    clean_button.configure(command=ask_cleanup)
    key_entry.bind("<Return>", verify)
    sessions_tree.bind("<<TreeviewSelect>>", show_session)
    files_tree.bind("<Double-1>", show_file_activity)
    search_var.trace_add("write", lambda *_a: show_activity() if state["report"] else None)
    (key_entry if path else path_entry).focus_set()
    root.after(100, poll)
    root.mainloop()


if __name__ == "__main__":
    run_gui()
