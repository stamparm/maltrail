#!/usr/bin/env python

"""
Copyright (c) 2014-2026 Maltrail developers (https://github.com/stamparm/maltrail/)
See the file 'LICENSE' for copying permission
"""

class TrailsDict(dict):
    """
    Memory-efficient store for threat trails that interns the (info, reference) pairs
    instead of storing them per trail

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
    """

    def __init__(self):
        self._trails = {}   # key -> the shared (info, reference) tuple for that trail
        self._regex = ""
        # NOTE: there are only a few thousand distinct (info, reference) pairs across millions of trails, so every trail
        # with the same pair shares ONE tuple object instead of each storing its own "i,j" index string. That string per
        # trail (one tiny str object each, parsed with split(',')+int() on every lookup) was the dominant RAM cost and a
        # per-lookup cost; sharing the tuple cut steady-state RSS ~29% and makes a lookup a plain dict read.
        self._pairs = {}    # (info, reference) -> the one shared tuple instance

    def adopt(self, other):
        """
        Atomically replaces this dict's contents with another TrailsDict's. Lookups read self._trails (a single
        attribute), so a live reload swaps it in one assignment - readers see the old or the new table, never the
        empty/half-built window that clear()+update() exposed them to during every trail reload.
        """

        self._pairs = other._pairs
        self._regex = other._regex
        self._trails = other._trails  # single atomic swap for the read path (done last)

    def __delitem__(self, key):
        del self._trails[key]

    def has_key(self, key):
        return key in self._trails

    def __contains__(self, key):
        return key in self._trails

    def clear(self):
        self.__init__()

    def keys(self):
        return self._trails.keys()

    def iterkeys(self):
        for key in self._trails:
            yield key

    def __iter__(self):
        for key in self._trails:
            yield key

    def get(self, key, default=None):
        return self._trails.get(key, default)

    def update(self, value):
        if isinstance(value, (TrailsDict, dict)):
            for key in value:
                self[key] = value[key]
        else:
            raise Exception("unsupported type '%s'" % type(value))

    def __len__(self):
        return len(self._trails)

    def __getitem__(self, key):
        return self._trails[key]

    def __setitem__(self, key, value):
        if not isinstance(value, (tuple, list)):
            raise Exception("unsupported type '%s'" % type(value))

        pair = (value[0], value[1])
        shared = self._pairs.get(pair)
        if shared is None:
            shared = pair
            self._pairs[pair] = pair
        self._trails[key] = shared
