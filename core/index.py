#!/usr/bin/env python

"""
Copyright (c) 2014-2026 Maltrail developers (https://github.com/stamparm/maltrail/)
See the file 'LICENSE' for copying permission
"""

"""
Per-day sidecar index over the daily event logs (`LOG_DIR/YYYY-MM-DD.log`), so `/counts` and
`/hunt` answer from a compact SQLite table instead of re-reading, decoding and lower-casing
every line of every log on each request.

Shape: one `<LOG_DIR>/index/YYYY-MM-DD.sqlite` per day (WAL journal), holding one row per log
line - the byte offset it starts at, the eleven event fields split the way `core/log.py`'s
`safe_value()` wrote them, and the whole line lower-cased. Nothing is deleted from the log and
nothing else reads the index: it is a derived cache, rebuilt from scratch at any time.

Correctness contract: `search()` returns EXACTLY the offsets whose line contains the query -
`instr(line_l, ?)` over a Python-lower-cased copy of the line is the same substring test the
linear scan performs (`query.lower() in line.lower()`), so results are identical by
construction, not by tolerance. Session scope, masking and sample rendering stay in `httpd`,
which fetches the actual line bytes through the offsets and re-runs its own filters on them.

Freshness is offset-based: the index remembers how far into the log it has parsed, and
`prepare()` appends everything written since. Sensors append-only, so steady state costs one
`stat()` per request; a shrunk or rotated log (offset beyond EOF) falls back to a full rebuild;
a missing log removes the sidecar. A crash mid-write costs at most the uncommitted tail.
"""

import os
import sqlite3
import threading

from core import logfmt
from core.compat import xrange
from core.settings import config

SCHEMA_VERSION = 1

_SCHEMA = """
CREATE TABLE IF NOT EXISTS meta(k TEXT PRIMARY KEY, v);
CREATE TABLE IF NOT EXISTS lines(
                   off INTEGER PRIMARY KEY,   -- byte offset of the line start in the .log
                   src TEXT, sport TEXT, dst TEXT, dport TEXT,
                   proto TEXT, ttype TEXT, trail TEXT, info TEXT, ref TEXT,
                   line_l TEXT NOT NULL       -- whole line, lower-cased (the match column)
);
CREATE INDEX IF NOT EXISTS lines_trail ON lines(trail);
"""

_BATCH = 4096           # lines per INSERT batch while catching up
_READ_CHUNK = 1 << 20   # catch-up read size
_MAX_PENDING = 64 << 20 # a newline-less tail this big means the file is not an event log

_locks = {}
_locks_guard = threading.Lock()


def enabled():
    # Default on (see core/settings.py); only an explicit `USE_EVENT_INDEX false` disables.
    # Tolerating a missing/None value keeps the module usable before read_config() has run.
    return getattr(config, "USE_EVENT_INDEX", None) is not False


def _day_lock(day):
    with _locks_guard:
        lock = _locks.get(day)
        if lock is None:
            lock = _locks[day] = threading.RLock()
        return lock


def _db_path(day):
    return os.path.join(config.LOG_DIR, "index", "%s.sqlite" % day)


def _remove_db(path):
    for suffix in ("", "-wal", "-shm"):
        try:
            os.remove(path + suffix)
        except OSError:
            pass


def _connect_write(path):
    conn = sqlite3.connect(path, timeout=30)
    conn.execute("PRAGMA journal_mode=WAL")
    # It is a rebuildable cache: NORMAL under WAL risks losing only the last commits on power
    # loss, never the database itself, and keeps intake off the write path's critical section.
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.executescript(_SCHEMA)
    version = conn.execute("PRAGMA user_version").fetchone()[0]
    if version != SCHEMA_VERSION:
        conn.execute("DELETE FROM lines")
        conn.execute("PRAGMA user_version = %d" % SCHEMA_VERSION)
    return conn


def split_event_line(line):
    """Split one event-log line the way `safe_value()` quoted it (see the Rust twin
    `testkit::split_quoted`). Returns up to 11 fields; malformed lines yield fewer."""
    fields = []
    parts = []          # joined per field: `current += ch` is quadratic on a corrupted line
    quoted = False
    i = 0
    while i < len(line):
        ch = line[i]
        if quoted:
            if ch == u'"':
                if line[i + 1:i + 2] == u'"':
                    parts.append(u'"')
                    i += 2
                    continue
                quoted = False
            else:
                parts.append(ch)
        elif ch == u'"':
            quoted = True
        elif ch == u' ':
            fields.append(u"".join(parts))
            parts = []
        else:
            parts.append(ch)
        i += 1
    fields.append(u"".join(parts))
    return fields


def prepare(day):
    """Bring `day`'s sidecar up to date with its log. False means "not usable" (disabled,
    no such log, storage refused) - callers must fall back to the linear scan."""
    if not enabled():
        return False

    log_path = os.path.join(config.LOG_DIR, "%s.log" % day)
    if not os.path.isfile(log_path):
        _remove_db(_db_path(day))   # day dropped -> drop the sidecar with it
        return False

    with _day_lock(day):
        return _catch_up(day, log_path)


def _catch_up(day, log_path):
    path = _db_path(day)
    try:
        os.makedirs(os.path.dirname(path), 0o755)
    except OSError:
        pass

    try:
        size = os.path.getsize(log_path)
        conn = _connect_write(path)
    except (OSError, sqlite3.Error):
        _remove_db(path)    # unreadable sidecar (e.g. corrupt): rebuild from scratch next call
        try:
            conn = _connect_write(path)
        except (OSError, sqlite3.Error):
            return False

    try:
        row = conn.execute("SELECT v FROM meta WHERE k='offset'").fetchone()
        offset = int(row[0]) if row else 0
        if offset > size:   # truncated/rotated/shrunk -> nothing reusable
            conn.execute("DELETE FROM lines")
            offset = 0

        if offset < size:
            with open(log_path, "rb") as f:
                f.seek(offset)
                offset = _index_lines(conn, f, offset)

        conn.execute("INSERT OR REPLACE INTO meta VALUES('offset',?)", (offset,))
        conn.commit()
        return True
    except (OSError, sqlite3.Error):
        try:
            conn.rollback()
        except sqlite3.Error:
            pass
        return False
    finally:
        conn.close()


def _index_lines(conn, f, offset):
    """Index complete lines from `f`'s position; returns the offset just past the LAST
    COMPLETE newline (a partial trailing line belongs to a writer mid-append, not to us)."""

    def row_for(off, raw):
        line = raw.decode("utf8", "ignore")
        # Format is decided per line, not from the configuration: a LOG_DIR holds whatever was
        # written on the day, so after a LOCAL_LOG_FORMAT change one file is text and the next is
        # JSON, and both have to index or the history stops being searchable.
        fields = logfmt.fields(line) if logfmt.is_json_line(line) else split_event_line(line)
        # Malformed lines keep their text (substring matching must see them too) but carry
        # no structured columns.
        if fields is None:
            fields = []
        cols = tuple(fields[_] if len(fields) == 11 else None for _ in xrange(2, 11))
        return (off,) + cols + (line.lower(),)

    pending = b""
    done = offset      # absolute offset of the first unparsed byte in `pending`
    batch = []
    while True:
        chunk = f.read(_READ_CHUNK)
        if not chunk:
            break
        if len(pending) > _MAX_PENDING:   # no newline in ~64MB: not an event log; leave the rest unindexed
            break
        pending += chunk
        start = 0
        while True:
            nl = pending.find(b"\n", start)
            if nl < 0:
                break
            raw = pending[start:nl]
            if raw.endswith(b"\r"):
                raw = raw[:-1]
            batch.append(row_for(done + start, raw))
            start = nl + 1
            if len(batch) >= _BATCH:
                conn.executemany("INSERT OR REPLACE INTO lines VALUES(?,?,?,?,?,?,?,?,?,?,?)", batch)
                batch = []
        done += start
        pending = pending[start:]
    if batch:
        conn.executemany("INSERT OR REPLACE INTO lines VALUES(?,?,?,?,?,?,?,?,?,?,?)", batch)
    return done


def search(day, needle_lower):
    """Offsets of lines containing `needle_lower`, ascending - identical to filtering the
    log with `needle_lower in line.lower()`. Call only after `prepare(day)` returned True."""
    try:
        conn = sqlite3.connect("file:%s?mode=ro" % _db_path(day), uri=True, timeout=30)
    except sqlite3.Error:
        return
    try:
        for (off,) in conn.execute("SELECT off FROM lines WHERE instr(line_l,?) ORDER BY off", (needle_lower,)):
            yield off
    except sqlite3.Error:
        return                  # sidecar removed mid-iteration -> caller falls back on next request
    finally:
        conn.close()


def count(day):
    """Exact number of indexed lines, or None when the index is disabled/unavailable."""
    if not prepare(day):
        return None
    conn = sqlite3.connect("file:%s?mode=ro" % _db_path(day), uri=True, timeout=30)
    try:
        return conn.execute("SELECT COUNT(*) FROM lines").fetchone()[0]
    except sqlite3.Error:
        return None
    finally:
        conn.close()
