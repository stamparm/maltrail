#!/usr/bin/env python

"""
Copyright (c) 2014-present Maltrail developers (https://github.com/stamparm/maltrail/)
See the file 'LICENSE' for copying permission
"""


import os
import re
import socket
import sqlite3
import traceback

# Condensed "observable" store (LOG_DIR/meta.sqlite): one cumulative aggregate row per distinct
# thing seen on the wire - a domain OR an IP - with first_seen / last_seen / count. It answers
# "have I EVER seen this, since when, how often" (novelty + retro-hunt of newly-known IOCs against
# pre-detection traffic) WITHOUT storing raw traffic.
#
# This is the READ side only. The sensor (sensor/src/meta.rs) writes and prunes the store; the
# server serves /meta from it with lookup(). The file's shape is the contract between the two: WITHOUT ROWID, IPs as 4/16-byte BLOBs and domains as TEXT, a rollback journal rather
# than WAL, world-readable - the sensor writes it as root and the server usually reads it as a
# non-root user, so the read side opens it truly read-only (URI mode=ro).

# flags byte: bit0 = kind (0=ip, 1=dns); bits1-2 = scope (0=n/a, 1=local, 2=remote)
FLAG_DNS = 0x1
SCOPE_LOCAL = 0x1
SCOPE_REMOTE = 0x2
_SCOPE_NAME = {0: "", SCOPE_LOCAL: "local", SCOPE_REMOTE: "remote"}

_V4_RE = re.compile(r"\A\d{1,3}(?:\.\d{1,3}){3}\Z")

# module state (set by configure())
_db_path = None


def configure(db_path, enabled=False):
    """Point lookup() at the store. `enabled` is accepted for compatibility and ignored: there is
    nothing here to enable, the sensor is the writer."""
    global _db_path
    _db_path = db_path


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


def _connect():
    if _db_path is None or not os.path.exists(_db_path):
        return None
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


def lookup(observable):
    """Read side (/meta): O(1) PK lookup. Returns dict or None."""
    if not observable:
        return None
    con = _connect()
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
