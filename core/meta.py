#!/usr/bin/env python

"""
Copyright (c) 2014-2026 Maltrail developers (https://github.com/stamparm/maltrail/)
See the file 'LICENSE' for copying permission
"""

from __future__ import print_function

import math
import os
import re
import socket
import sqlite3
import threading
import time
import traceback

from core.common import is_local
from core.common import get_text
from core.settings import DEFAULT_EVENT_LOG_PERMISSIONS

# Condensed "observable" store (LOG_DIR/meta.sqlite): one cumulative aggregate row per distinct
# thing seen on the wire - a domain OR an IP - with first_seen / last_seen / count. It answers
# "have I EVER seen this, since when, how often" (novelty + retro-hunt of newly-known IOCs against
# pre-detection traffic) WITHOUT storing raw traffic. Design goals: cheap enough for 2x10G (per
# packet == one dict bump; junk-filter + scope run insert-only), tiny on disk (WITHOUT ROWID +
# packed flags + IPs as 4/16-byte BLOBs), and self-bounding (per-window key cap + smart score-prune).
#
# Concurrency model: each sensor worker is a separate PROCESS with its own in-RAM aggregate dict.
# The hot path is LOCK-FREE - a background flush thread atomically swaps the dict out and drains it
# via a batched, portable (works on ancient SQLite) INSERT-OR-IGNORE + UPDATE merge. Under a race a
# bump may be lost; counts are therefore best-effort (as is the sensor's own per-bucket log throttling).
# The DB uses rollback-journal (NOT WAL) mode and is chmod'd world-readable: the sensor writes it as
# root, the server typically reads it as a non-root user, and WAL would force that reader to write the
# -shm sidecar (which it can't) -> the read-side must open truly read-only (URI mode=ro).

# flags byte: bit0 = kind (0=ip, 1=dns); bits1-2 = scope (0=n/a, 1=local, 2=remote)
FLAG_DNS = 0x1
SCOPE_LOCAL = 0x1
SCOPE_REMOTE = 0x2
_SCOPE_NAME = {0: "", SCOPE_LOCAL: "local", SCOPE_REMOTE: "remote"}

# never worth an observable row
_JUNK_IPS = frozenset(("0.0.0.0", "255.255.255.255", "::"))
_V4_RE = re.compile(r"\A\d{1,3}(?:\.\d{1,3}){3}\Z")

try:
    _TEXT_TYPES = (str, unicode)   # py2: TEXT comes back as unicode/str; py3: str
except NameError:
    _TEXT_TYPES = (str,)

_WITHOUT_ROWID = " WITHOUT ROWID" if sqlite3.sqlite_version_info >= (3, 8, 2) else ""

# module state (set by configure())
_db_path = None
_enabled = False
_max_window_keys = 200000
_flush_period = 60
_agg = {}                        # observable(str) -> [flags, first_seen, last_seen, count]
_flusher = None
_flush_lock = threading.Lock()   # guards the flush->SQLite section (not the hot path)


def configure(db_path, enabled=True, max_window_keys=200000, flush_period=60):
    global _db_path, _enabled, _max_window_keys, _flush_period
    _db_path = db_path
    _enabled = bool(enabled)
    _max_window_keys = max_window_keys or 200000
    _flush_period = flush_period or 60


def is_enabled():
    return _enabled and _db_path is not None


def _is_mcast(value):
    # v4 224.0.0.0/4 (224-239), v6 ff00::/8
    if ":" in value:
        return value[:2].lower() == "ff"
    dot = value.find(".")
    if dot > 0:
        head = value[:dot]
        if head.isdigit():
            return 224 <= int(head) <= 239
    return False


def _flags_ip(value, is6):
    if is6:
        local = value == "::1" or value[:2].lower() in ("fe", "fc", "fd")
    else:
        local = is_local(value)
    return (SCOPE_LOCAL if local else SCOPE_REMOTE) << 1     # kind bit stays 0 (== ip)


def observe_conn(src, dst, is6, sec):
    """Hot path: record BOTH endpoints of a connection. Lock-free; junk-filter+scope+flusher-start insert-only."""
    if not _enabled:
        return
    d = _agg
    r = d.get(dst)
    if r is None:
        if len(d) < _max_window_keys and dst not in _JUNK_IPS and not _is_mcast(dst):
            d[dst] = [_flags_ip(dst, is6), sec, sec, 1]
            if _flusher is None:
                _ensure_flusher()
    else:
        r[2] = sec
        r[3] += 1
    r = d.get(src)
    if r is None:
        if len(d) < _max_window_keys and src not in _JUNK_IPS and not _is_mcast(src):
            d[src] = [_flags_ip(src, is6), sec, sec, 1]
    else:
        r[2] = sec
        r[3] += 1


def observe_dns(name, sec):
    """Hot path: record a queried domain name as an observable."""
    if not _enabled or not name:
        return
    d = _agg
    r = d.get(name)
    if r is None:
        if len(d) < _max_window_keys:
            d[name] = [FLAG_DNS, sec, sec, 1]
            if _flusher is None:
                _ensure_flusher()
    else:
        r[2] = sec
        r[3] += 1


def _pack(flags, value):
    """observable -> storage key: IPs to 4/16-byte BLOB, domains stay TEXT."""
    if flags & FLAG_DNS:
        return value
    try:
        if ":" in value:
            return sqlite3.Binary(socket.inet_pton(socket.AF_INET6, value))
        return sqlite3.Binary(socket.inet_aton(value))
    except Exception:
        return value


def _unpack(key):
    """storage key -> printable observable. TEXT == domain; BLOB (bytes/bytearray/memoryview/py2 buffer) == IP."""
    if isinstance(key, _TEXT_TYPES):
        return key
    b = bytes(key)                 # memoryview (py3) / buffer (py2) / bytearray -> bytes
    try:
        if len(b) == 4:
            return socket.inet_ntoa(b)
        if len(b) == 16:
            return socket.inet_ntop(socket.AF_INET6, b)
    except Exception:
        pass
    return get_text(b)


def _pack_lookup(observable):
    """A user-supplied observable string -> (storage key, kind). IP if it parses, else domain TEXT."""
    if ":" in observable:
        try:
            return sqlite3.Binary(socket.inet_pton(socket.AF_INET6, observable)), "ip"
        except Exception:
            pass
    elif _V4_RE.match(observable):
        try:
            return sqlite3.Binary(socket.inet_aton(observable)), "ip"
        except Exception:
            pass
    return observable, "dns"


def _ro_uri(path):
    return "file:" + os.path.abspath(path).replace("?", "%3F").replace("#", "%23") + "?mode=ro"


def _connect(create=True, readonly=False):
    if _db_path is None:
        return None
    if (readonly or not create) and not os.path.exists(_db_path):
        return None
    if readonly:
        # The sensor writes this as root; the server usually reads it as a NON-root user. A truly read-only
        # open (URI mode=ro) needs no write access to the DB or any journal sidecar -> works across that uid
        # split. Fall back to a plain open (same-user / world-writable case).
        for opener in (lambda: sqlite3.connect(_ro_uri(_db_path), uri=True, timeout=5),
                       lambda: sqlite3.connect(_db_path, timeout=5)):
            try:
                return opener()
            except Exception:
                continue
        return None
    con = sqlite3.connect(_db_path, timeout=10)
    # NOT WAL: WAL requires every reader to write the -shm/-wal sidecars, which the non-root server can't do
    # against a root-owned DB (it silently fell back to {}). Rollback journal is still fully ACID/crash-safe;
    # our ~per-minute flush rate doesn't need WAL's concurrency.
    con.execute("PRAGMA journal_mode=DELETE")
    con.execute("PRAGMA synchronous=NORMAL")
    con.execute("PRAGMA busy_timeout=8000")
    if create:
        con.execute("CREATE TABLE IF NOT EXISTS observables (observable, flags INTEGER, first_seen INTEGER, last_seen INTEGER, count INTEGER, PRIMARY KEY(observable))%s" % _WITHOUT_ROWID)
        con.execute("CREATE TABLE IF NOT EXISTS meta_info (key TEXT PRIMARY KEY, value)")
        con.execute("INSERT OR IGNORE INTO meta_info (key, value) VALUES ('schema_version', 1)")
        con.commit()
        try:   # world-readable like the daily event logs, so a non-root server can read a root-written store
            os.chmod(_db_path, DEFAULT_EVENT_LOG_PERMISSIONS)
        except OSError:
            pass
    return con


def flush():
    """Drain this process's aggregate into SQLite. Atomic swap keeps the hot path lock-free."""
    global _agg
    if not _agg:
        return 0
    old = _agg
    _agg = {}
    with _flush_lock:
        con = None
        try:
            con = _connect(create=True)
            if con is None:
                return 0
            cur = con.cursor()
            # portable merge (no ON CONFLICT / no SQLite 3.24 needed): ensure row, then bump.
            for value, r in old.items():
                flags, fs, ls, cnt = r[0], r[1], r[2], r[3]
                key = _pack(flags, value)
                cur.execute("INSERT OR IGNORE INTO observables (observable, flags, first_seen, last_seen, count) VALUES (?, ?, ?, ?, 0)", (key, flags, fs, ls))
                # first_seen = MIN too: concurrent workers can flush windows out of time order (up to ~1 window apart)
                cur.execute("UPDATE observables SET first_seen = MIN(first_seen, ?), last_seen = MAX(last_seen, ?), count = count + ? WHERE observable = ?", (fs, ls, cnt, key))
            con.commit()
            return len(old)
        except Exception:
            traceback.print_exc()
            return 0
        finally:
            if con is not None:
                try:
                    con.close()
                except Exception:
                    pass


def _flush_loop(period):
    while True:
        time.sleep(period)
        try:
            flush()
        except Exception:
            traceback.print_exc()


def _ensure_flusher():
    """Lazily start this process's background flush thread on its first observed insert. Idempotent.
    (Threads don't survive fork, so each worker process starts its own the first time it records something.)"""
    global _flusher
    if _flusher is not None or not is_enabled():
        return
    with _flush_lock:
        if _flusher is not None:
            return
        _flusher = threading.Thread(target=_flush_loop, args=(_flush_period,))
        _flusher.daemon = True
        _flusher.start()


def _score(count, first_seen, last_seen):
    # keep-worthiness: recurrence + longevity + mild recency. Higher == keep.
    span_days = max(last_seen - first_seen, 0) / 86400.0
    return math.log(1 + count, 2) + math.log(1 + span_days, 2) + (last_seen / (30.0 * 86400.0))


def prune(max_rows):
    """Smart, budget-triggered eviction: over budget -> delete the LOWEST-score rows first.
    (Age-cutoff can't touch a recent DGA burst; score-prune sheds count=1/zero-span junk and
    protects established low-and-slow observables.) Returns number of rows deleted."""
    con = _connect(create=False)
    if con is None:
        return 0
    try:
        n = con.execute("SELECT COUNT(*) FROM observables").fetchone()[0]
        if n <= max_rows:
            return 0
        overflow = n - max_rows
        con.create_function("meta_score", 3, _score)
        # WITHOUT ROWID tables have no rowid, so evict by PK (works for both table shapes)
        con.execute("DELETE FROM observables WHERE observable IN (SELECT observable FROM observables ORDER BY meta_score(count, first_seen, last_seen) ASC LIMIT ?)", (overflow,))
        con.commit()
        con.execute("VACUUM")
        con.commit()
        return overflow
    except Exception:
        traceback.print_exc()
        return 0
    finally:
        try:
            con.close()
        except Exception:
            pass


def lookup(observable):
    """Read side (/meta): O(1) PK lookup. Returns dict or None."""
    if not observable:
        return None
    con = _connect(create=False, readonly=True)
    if con is None:
        return None
    try:
        key, _ = _pack_lookup(observable)
        row = con.execute("SELECT flags, first_seen, last_seen, count FROM observables WHERE observable = ?", (key,)).fetchone()
        if row is None:
            return None
        flags, fs, ls, cnt = row
        return {
            "observable": observable,
            "kind": "dns" if (flags & FLAG_DNS) else "ip",
            "scope": _SCOPE_NAME.get((flags >> 1) & 0x3, ""),
            "first_seen": fs,
            "last_seen": ls,
            "count": cnt,
        }
    except Exception:
        traceback.print_exc()
        return None
    finally:
        try:
            con.close()
        except Exception:
            pass
