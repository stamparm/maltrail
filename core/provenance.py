#!/usr/bin/env python

"""
Copyright (c) 2014-present Maltrail developers (https://github.com/stamparm/maltrail/)
See the file 'LICENSE' for copying permission
"""

# Where a static trail came from: the file it sits in and the '# Reference:' header above it.
#
# The dashboard's trail drawer answers "why was this flagged" with that citation, and it used to
# get it by grepping trails/static/** on demand. Static content lives in its own repository now, so
# there is nothing to grep - and a blank citation reads as "this indicator has no source" rather
# than "provenance is not installed here".
#
# So it ships as a sidecar. 1.6M trails resolve to ~105k distinct (file, reference) pairs, which is
# what makes this affordable: the index is a sorted array of (trail hash, pair id) searched by
# bisect over an mmap, and the pairs themselves are a small JSON table. An open-addressing table
# like core/trailsbin.py's would be ~80 MB of mostly-empty slots; sorted is ~20 MB and the lookup
# is a handful of page touches either way, because this is an analyst clicking one row, not a
# packet path.
#
# The SERVER fetches this, not the sensor: it exists only to render a citation. One host, not every
# deployed sensor, which is what makes the download affordable at all.

import hashlib
import json
import mmap
import os
import struct

_MAGIC = b"MTPROV1"                    # 7 bytes; bump on any format change
_HEADER = struct.Struct("<7sQQ")       # magic, entry count, pair-table byte length
_ENTRY = struct.Struct("<QI")          # trail hash (u64), pair index (u32)
_ENTRY_SIZE = _ENTRY.size              # 12


def trail_hash(trail):
    """Stable 64-bit hash of a trail key.

    md5 prefix rather than the builtin hash(): that is randomised per process, so a file built by
    the publisher would be unreadable by the server that downloads it.
    """

    if not isinstance(trail, bytes):
        trail = trail.encode("utf8", "replace")
    return struct.unpack("<Q", hashlib.md5(trail).digest()[:8])[0]


def build(entries, pairs, path):
    """Write the sidecar.

    `entries` is an iterable of (trail, pair_index); `pairs` a list of (source_path, reference).
    """

    rows = sorted((trail_hash(trail), index) for trail, index in entries)

    table = json.dumps(pairs, separators=(',', ':')).encode("utf8")
    tmp = "%s.new" % path
    with open(tmp, "wb") as f:
        f.write(_HEADER.pack(_MAGIC, len(rows), len(table)))
        f.write(table)
        # struct.pack per row would be 1.6M Python calls; one join is the difference between
        # ~4 seconds and well under one.
        f.write(b"".join(_ENTRY.pack(h, i) for h, i in rows))
    os.replace(tmp, path)
    return len(rows), len(pairs)


class Provenance(object):
    """An opened sidecar. Read-only, mmap'd, safe to share between request threads."""

    def __init__(self, path):
        self._file = open(path, "rb")
        try:
            self._map = mmap.mmap(self._file.fileno(), 0, access=mmap.ACCESS_READ)
        except Exception:
            self._file.close()
            raise

        magic, count, table_len = _HEADER.unpack_from(self._map, 0)
        if magic != _MAGIC:
            self.close()
            raise ValueError("not a Maltrail provenance sidecar (bad magic)")

        self.count = count
        self._pairs = json.loads(self._map[_HEADER.size:_HEADER.size + table_len].decode("utf8"))
        self._base = _HEADER.size + table_len

        if self._base + count * _ENTRY_SIZE > len(self._map):
            self.close()
            raise ValueError("provenance sidecar is truncated")

    def _hash_at(self, i):
        offset = self._base + i * _ENTRY_SIZE
        return struct.unpack_from("<Q", self._map, offset)[0]

    def lookup(self, trail):
        """(reference, source_path) for `trail`, or None.

        The order matches what core/httpd.py's on-demand scan returned, so the caller does not care
        which of the two answered.
        """

        target = trail_hash(trail)
        lo, hi = 0, self.count
        while lo < hi:
            mid = (lo + hi) // 2
            if self._hash_at(mid) < target:
                lo = mid + 1
            else:
                hi = mid
        if lo >= self.count or self._hash_at(lo) != target:
            return None
        index = struct.unpack_from("<I", self._map, self._base + lo * _ENTRY_SIZE + 8)[0]
        try:
            source, reference = self._pairs[index]
        except (IndexError, ValueError):
            return None
        return (reference, source)

    def close(self):
        try:
            self._map.close()
        except Exception:
            pass
        try:
            self._file.close()
        except Exception:
            pass
