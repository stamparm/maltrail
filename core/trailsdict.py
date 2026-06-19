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
        self._trails = {}
        self._regex = ""
        self._infos = []
        self._reverse_infos = {}
        self._references = []
        self._reverse_references = {}
        # NOTE: lookups read this single tuple (one atomic attribute access) instead of self._trails/_infos/_references
        # separately, so a live reload via adopt() can never expose them to a half-swapped (inconsistent) state.
        # _read[0] IS self._trails (same objects), so in-place writes stay visible; it is only rebound here and in adopt().
        self._read = (self._trails, self._infos, self._references)

    def adopt(self, other):
        """
        Atomically replaces this dict's contents with another TrailsDict's. Readers see the old contents or the new
        contents - never the empty/half-populated window that clear()+update() left exposed during every trail reload.
        """

        self._trails = other._trails
        self._infos = other._infos
        self._reverse_infos = other._reverse_infos
        self._references = other._references
        self._reverse_references = other._reverse_references
        self._read = (self._trails, self._infos, self._references)  # single atomic swap for the read path
        self._regex = other._regex

    def __delitem__(self, key):
        del self._trails[key]  # _read[0] is the same dict object, so the deletion is visible to readers

    def has_key(self, key):
        return key in self._read[0]

    def __contains__(self, key):
        return key in self._read[0]

    def clear(self):
        self.__init__()

    def keys(self):
        return self._read[0].keys()

    def iterkeys(self):
        for key in self._read[0].keys():
            yield key

    def __iter__(self):
        for key in self._read[0].keys():
            yield key

    def get(self, key, default=None):
        trails, infos, references = self._read  # consistent snapshot
        if key in trails:
            _ = trails[key].split(',')
            if len(_) == 2:
                return (infos[int(_[0])], references[int(_[1])])

        return default

    def update(self, value):
        if isinstance(value, TrailsDict):
            for key in value:  # per-key merge (was a by-reference attribute copy that silently aliased internal state)
                self[key] = value[key]
        elif isinstance(value, dict):
            for key in value:
                info, reference = value[key]
                if info not in self._reverse_infos:
                    self._reverse_infos[info] = len(self._infos)
                    self._infos.append(info)
                if reference not in self._reverse_references:
                    self._reverse_references[reference] = len(self._references)
                    self._references.append(reference)
                self._trails[key] = "%d,%d" % (self._reverse_infos[info], self._reverse_references[reference])
        else:
            raise Exception("unsupported type '%s'" % type(value))

    def __len__(self):
        return len(self._read[0])

    def __getitem__(self, key):
        trails, infos, references = self._read  # consistent snapshot
        if key in trails:
            _ = trails[key].split(',')
            if len(_) == 2:
                return (infos[int(_[0])], references[int(_[1])])

        raise KeyError(key)

    def __setitem__(self, key, value):
        if isinstance(value, (tuple, list)):
            info, reference = value
            if info not in self._reverse_infos:
                self._reverse_infos[info] = len(self._infos)
                self._infos.append(info)
            if reference not in self._reverse_references:
                self._reverse_references[reference] = len(self._references)
                self._references.append(reference)
            self._trails[key] = "%d,%d" % (self._reverse_infos[info], self._reverse_references[reference])
        else:
            raise Exception("unsupported type '%s'" % type(value))
