#!/usr/bin/env python

"""
Copyright (c) 2014-present Maltrail developers (https://github.com/stamparm/maltrail/)
See the file 'LICENSE' for copying permission
"""

import os
import sqlite3

class DiskTrailsDict(object):
    """
    The build-time trail dict of update_trails(), kept in a SQLite file instead of the heap.

    update_trails() merges ~1.9M trails before it writes trails.csv, and as an ordinary dict that is
    ~250 MB of Python objects on a 64-bit host - more than a small box (a Raspberry Pi, a 256 MB VPS)
    can give it next to a running sensor. This class is a drop-in for the handful of dict operations that
    function uses, with the SAME semantics, insertion order included: overwriting a key keeps its
    position, deleting and re-adding one moves it to the end. update_trails() iterates and rewrites
    keys while it post-processes, and which of two colliding keys wins depends on that order, so it
    is reproduced rather than approximated - the merge code stays one code path whichever store
    holds it.

    Memory is bounded by SQLite's page cache plus the interned (info, reference) pairs - a few
    thousand distinct ones for 1.9M trails, which is also why a row stores only a pair index.

    >>> import tempfile
    >>> path = os.path.join(tempfile.mkdtemp(), "build.sqlite")
    >>> trails = DiskTrailsDict(path)
    >>> trails["b.example"] = ("malware", "(static)")
    >>> trails["a.example"] = ("phishing", "(custom)")
    >>> trails["b.example"] = ("c2", "(static)")      # overwrite keeps the position
    >>> "a.example" in trails, "nope.example" in trails, len(trails)
    (True, False, 2)
    >>> list(trails.snapshot_keys())
    ['b.example', 'a.example']
    >>> del trails["b.example"]; trails["b.example"] = ("c2", "(static)")   # re-added moves to the end
    >>> list(trails.snapshot_keys())
    ['a.example', 'b.example']
    >>> list(trails.sorted_items())
    [('a.example', ('phishing', '(custom)')), ('b.example', ('c2', '(static)'))]
    >>> trails.close(); os.path.exists(path)
    False
    """

    CHUNK = 10000

    def __init__(self, path):
        self._path = path
        self._remove()
        self._db = sqlite3.connect(path, isolation_level=None)
        self._db.text_factory = str
        for pragma in ("journal_mode=OFF", "synchronous=OFF", "temp_store=FILE", "cache_size=-8192", "locking_mode=EXCLUSIVE"):
            self._db.execute("PRAGMA %s" % pragma)
        # pos is the insertion order. AUTOINCREMENT, because a plain rowid may be reused after the
        # highest row is deleted, and a reused position would put a new key inside an iteration
        # snapshot that must not see it.
        self._db.execute("CREATE TABLE t (pos INTEGER PRIMARY KEY AUTOINCREMENT, key TEXT NOT NULL UNIQUE, pair INTEGER NOT NULL)")
        self._db.execute("BEGIN")
        self._pair_index = {}
        self._pair_list = []
        self._len = 0

    def _remove(self):
        for _ in (self._path, "%s-journal" % self._path):
            try:
                os.remove(_)
            except OSError:
                pass

    def _pair(self, value):
        pair = (value[0], value[1])
        index = self._pair_index.get(pair)
        if index is None:
            index = len(self._pair_list)
            self._pair_index[pair] = index
            self._pair_list.append(pair)
        return index

    def __contains__(self, key):
        return self._db.execute("SELECT 1 FROM t WHERE key=?", (key,)).fetchone() is not None

    def __getitem__(self, key):
        row = self._db.execute("SELECT pair FROM t WHERE key=?", (key,)).fetchone()
        if row is None:
            raise KeyError(key)
        return self._pair_list[row[0]]

    def get(self, key, default=None):
        row = self._db.execute("SELECT pair FROM t WHERE key=?", (key,)).fetchone()
        return default if row is None else self._pair_list[row[0]]

    def __setitem__(self, key, value):
        if not isinstance(value, (tuple, list)):
            raise Exception("unsupported type '%s'" % type(value))
        pair = self._pair(value)
        if self._db.execute("UPDATE t SET pair=? WHERE key=?", (pair, key)).rowcount == 0:
            self._db.execute("INSERT INTO t (key, pair) VALUES (?, ?)", (key, pair))
            self._len += 1

    def __delitem__(self, key):
        if self._db.execute("DELETE FROM t WHERE key=?", (key,)).rowcount == 0:
            raise KeyError(key)
        self._len -= 1

    def __len__(self):
        return self._len

    def __bool__(self):
        return self._len > 0

    __nonzero__ = __bool__

    def snapshot_keys(self):
        """
        The keys present right now, in insertion order - what `list(d.keys())` gives a dict, but
        streamed. A key added after the call is not yielded (it was not in the list), one deleted
        after it is (the caller re-checks membership, exactly as it has to with a list).
        """

        last = self._db.execute("SELECT MAX(pos) FROM t").fetchone()[0]
        pos = 0
        while last is not None and pos < last:
            rows = self._db.execute("SELECT pos, key FROM t WHERE pos > ? AND pos <= ? ORDER BY pos LIMIT ?", (pos, last, self.CHUNK)).fetchall()
            if not rows:
                break
            for _, key in rows:
                yield key
            pos = rows[-1][0]

    def items(self):
        """(key, (info, reference)) in insertion order. The store must not be modified meanwhile."""

        for key, pair in self._db.execute("SELECT key, pair FROM t ORDER BY pos"):
            yield key, self._pair_list[pair]

    def sorted_items(self):
        # SQLite's BINARY collation compares UTF-8 bytes, which orders exactly like Python's
        # code-point comparison of the same strings - so this is sorted(d.keys()).
        for key, pair in self._db.execute("SELECT key, pair FROM t ORDER BY key"):
            yield key, self._pair_list[pair]

    def close(self):
        try:
            self._db.close()
        finally:
            self._remove()
