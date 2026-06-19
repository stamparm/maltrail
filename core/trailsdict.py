#!/usr/bin/env python

"""
Copyright (c) 2014-2026 Maltrail developers (https://github.com/stamparm/maltrail/)
See the file 'LICENSE' for copying permission
"""

import sys

from array import array
from bisect import bisect_left

try:
    _TEXT_TYPE = unicode             # Python 2
except NameError:
    _TEXT_TYPE = str                 # Python 3

_HASH_MASK = (1 << 63) - 1          # keep hashes non-negative so they pack into a signed 'q' array

def _key_hash(key):
    """
    Process-stable 64-bit hash of a trail key. The store is always built and queried inside the same process
    (each sensor/worker process loads its own copy), so the builtin (per-process randomized) hash() is consistent
    between build time and lookup time. The key is normalised to UTF-8 bytes first so the str/unicode/bytes forms
    of the same trail hash identically across Python 2/3 (e.g. IDN domains).
    """

    if isinstance(key, bytes):
        data = key
    elif isinstance(key, _TEXT_TYPE):
        data = key.encode("utf-8", "replace")
    else:
        data = str(key).encode("utf-8", "replace")

    return hash(data) & _HASH_MASK

class TrailsDict(dict):
    """
    Memory-efficient store for threat trails.

    During build it behaves as an ordinary (mutable) dict that interns the (info, reference) pairs so that the
    millions of trails sharing one of only a few thousand distinct pairs all point at a single tuple object.

    Once a process holds its final, read-only set (the sensor/worker hot path only ever does membership tests and
    value lookups - never key iteration), finalize() compacts it: every key is replaced by its 64-bit hash packed
    into a contiguous array, and the key strings themselves - by far the largest cost (~90 MB for ~1.6M trails) -
    are dropped entirely. Lookups become a bisect over the sorted hash array. The rare possibility of a hash
    collision (none observed across 1.6M real trails) is handled exactly: any colliding keys are kept verbatim in
    a small side dict, so a collision can never produce a wrong match.

    >>> trails = TrailsDict()
    >>> trails["1.2.3.4"] = ("malware", "(static)")
    >>> "1.2.3.4" in trails
    True
    >>> trails["1.2.3.4"]
    ('malware', '(static)')
    >>> trails.get("missing.example") is None
    True
    >>> len(trails)
    1
    >>> trails.update({"evil.example": ("phishing", "(custom)")})
    >>> sorted(trails.keys())
    ['1.2.3.4', 'evil.example']
    >>> del trails["1.2.3.4"]
    >>> "1.2.3.4" in trails
    False
    >>> len(trails)
    1

    Lookups keep working identically after finalize(), but the store becomes read-only:

    >>> trails["a.example"] = ("malware", "(static)")
    >>> trails["b.example"] = ("phishing", "(static)")
    >>> trails.finalize()
    >>> "a.example" in trails, "evil.example" in trails, "nope.example" in trails
    (True, True, False)
    >>> trails["b.example"]
    ('phishing', '(static)')
    >>> trails.get("nope.example") is None
    True
    >>> len(trails)
    3
    """

    def __init__(self):
        self._trails = {}           # key -> the shared (info, reference) tuple (build mode only)
        self._pairs = {}            # (info, reference) -> the one shared tuple instance (build mode only)
        self._regex = ""
        self._frozen = None         # set by finalize() to (hashes, values, pair_list, collisions, length); None => build mode

    def finalize(self):
        """
        Compacts the build-mode dict into the frozen hash-array representation and drops the key strings. Idempotent.
        Must run after build_trails_regex() (which needs the real key strings to find wildcard trails).
        """

        if self._frozen is not None:
            return

        # group keys by hash to detect collisions; the common case is one key per hash (a bare key, not a list)
        groups = {}
        for key in self._trails:
            h = _key_hash(key)
            existing = groups.get(h)
            if existing is None:
                groups[h] = key
            elif type(existing) is list:
                existing.append(key)
            else:
                groups[h] = [existing, key]

        pair_index = {}
        pair_list = []
        collisions = {}
        clean = []

        for h, entry in groups.items():
            if type(entry) is list:             # genuine hash collision: keep these few keys verbatim, exclude from arrays
                for key in entry:
                    collisions[key] = self._trails[key]
            else:
                pair = self._trails[entry]
                pi = pair_index.get(pair)
                if pi is None:
                    pi = len(pair_list)
                    pair_index[pair] = pi
                    pair_list.append(pair)
                clean.append((h, pi))

        clean.sort()
        hashes = array('q', [h for h, pi in clean])
        values = array('H' if len(pair_list) <= 0xFFFF else 'i', [pi for h, pi in clean])
        length = len(self._trails)

        # single attribute swapped in last: the read path reads self._frozen once, so it sees a fully consistent snapshot
        self._frozen = (hashes, values, pair_list, collisions, length)
        self._trails = None
        self._pairs = None

    def adopt(self, other):
        """
        Atomically replaces this dict's contents with another TrailsDict's. The read path reads either self._trails
        (build mode) or self._frozen (frozen mode) as a single attribute, so a live reload swaps it in one assignment
        - readers see the old or the new table, never the empty/half-built window that clear()+update() exposed.
        """

        # The read path branches on self._frozen, so that discriminator is assigned LAST and the alternate-mode
        # field is left in place (the old contents are unreferenced afterwards and GC'd) - a concurrent worker
        # reader therefore sees a fully consistent old-or-new snapshot through the frozen<->build transition too.
        self._regex = other._regex
        if other._frozen is not None:
            self._frozen = other._frozen        # single atomic swap for the read path (done last)
        else:
            self._pairs = other._pairs
            self._trails = other._trails
            self._frozen = None                 # single atomic swap for the read path (done last)

    def __contains__(self, key):
        frozen = self._frozen
        if frozen is None:
            return key in self._trails

        hashes, values, pair_list, collisions, length = frozen
        if collisions and key in collisions:
            return True
        h = _key_hash(key)
        i = bisect_left(hashes, h)
        return i < len(hashes) and hashes[i] == h

    def has_key(self, key):
        return self.__contains__(key)

    def __getitem__(self, key):
        frozen = self._frozen
        if frozen is None:
            return self._trails[key]

        hashes, values, pair_list, collisions, length = frozen
        if collisions and key in collisions:
            return collisions[key]
        h = _key_hash(key)
        i = bisect_left(hashes, h)
        if i < len(hashes) and hashes[i] == h:
            return pair_list[values[i]]
        raise KeyError(key)

    def get(self, key, default=None):
        frozen = self._frozen
        if frozen is None:
            return self._trails.get(key, default)

        hashes, values, pair_list, collisions, length = frozen
        if collisions and key in collisions:
            return collisions[key]
        h = _key_hash(key)
        i = bisect_left(hashes, h)
        if i < len(hashes) and hashes[i] == h:
            return pair_list[values[i]]
        return default

    def __len__(self):
        frozen = self._frozen
        return frozen[4] if frozen is not None else len(self._trails)

    def clear(self):
        self.__init__()

    def __setitem__(self, key, value):
        if self._frozen is not None:
            raise Exception("cannot modify a finalized TrailsDict")
        if not isinstance(value, (tuple, list)):
            raise Exception("unsupported type '%s'" % type(value))

        pair = (value[0], value[1])
        shared = self._pairs.get(pair)
        if shared is None:
            shared = pair
            self._pairs[pair] = pair
        self._trails[key] = shared

    def __delitem__(self, key):
        if self._frozen is not None:
            raise Exception("cannot modify a finalized TrailsDict")
        del self._trails[key]

    def update(self, value):
        if self._frozen is not None:
            raise Exception("cannot modify a finalized TrailsDict")
        if isinstance(value, (TrailsDict, dict)):
            for key in value:
                self[key] = value[key]
        else:
            raise Exception("unsupported type '%s'" % type(value))

    def keys(self):
        if self._frozen is not None:
            raise Exception("cannot iterate a finalized TrailsDict (keys are not retained)")
        return self._trails.keys()

    def iterkeys(self):
        if self._frozen is not None:
            raise Exception("cannot iterate a finalized TrailsDict (keys are not retained)")
        for key in self._trails:
            yield key

    def __iter__(self):
        if self._frozen is not None:
            raise Exception("cannot iterate a finalized TrailsDict (keys are not retained)")
        for key in self._trails:
            yield key
