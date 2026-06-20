#!/usr/bin/env python

"""
Copyright (c) 2014-2026 Maltrail developers (https://github.com/stamparm/maltrail/)
See the file 'LICENSE' for copying permission
"""

# Shared, memory-mapped representation of the (read-only) trail set.
#
# The trail set is built ONCE (by the process that owns the build peak) into a compact binary file. Every sensor
# worker then mmap()s that file read-only, so the kernel keeps a SINGLE physical copy shared across all of them
# (like a shared library) instead of each worker carrying its own ~150+ MB heap copy. The file is an open-addressing
# (linear-probing) hash table, so a lookup is just a couple of slot probes into the memory-mapped arrays.
#
# Keys are NOT stored - only a 64-bit hash of each. The hash is a stable md5 prefix (NOT the builtin, per-process
# randomised hash()), so the file built by one process is valid in any other process and across restarts. The rare
# possibility of a 64-bit hash collision between two distinct trails is handled exactly (the colliding keys are
# kept verbatim in a small side dict), so a collision can never cause a wrong match.

import hashlib
import mmap
import os
import struct
import sys

from array import array

try:
    import cPickle as pickle
except ImportError:
    import pickle

try:
    _TEXT_TYPE = unicode            # Python 2
except NameError:
    _TEXT_TYPE = str                # Python 3

_PY2 = sys.version_info[0] == 2

_MAGIC = b"MTRAILB2"               # 8 bytes; bump the trailing digit on any format change
_HEADER = struct.Struct("<8sQQQ") # magic, cap (slot count, power of two), n (occupied entries), blob_len
_HEADER_SIZE = _HEADER.size
_EMPTY = 0xFFFFFFFF                # value-slot sentinel for an empty bucket (pair indices are always far smaller)

def stable_hash(key):
    """
    Cross-process-stable 64-bit hash of a trail key (md5 prefix). The key is normalised to UTF-8 bytes first so the
    str/unicode/bytes forms of the same trail hash identically across Python 2/3 (e.g. IDN domains).

    >>> stable_hash("1.2.3.4") == stable_hash(b"1.2.3.4")
    True
    >>> 0 <= stable_hash("evil.example") < (1 << 64)
    True
    """

    if isinstance(key, bytes):
        data = key
    elif isinstance(key, _TEXT_TYPE):
        data = key.encode("utf-8", "replace")
    else:
        data = str(key).encode("utf-8", "replace")

    return struct.unpack("<Q", hashlib.md5(data).digest()[:8])[0]

def write_bin(path, entries, pair_list, collisions, regex):
    """
    Writes the binary trail file as an open-addressing (linear-probing) hash table. 'entries' is an iterable of
    (hash64, pair_index) for every non-colliding trail. 'pair_list' maps a pair_index to its (info, reference)
    tuple. 'collisions' maps the few keys whose hash collided to their (info, reference) tuple. 'regex' is the
    wildcard alternation string.

    The table is sized to a power-of-two capacity at load factor < 0.5, so a lookup is ~1-2 slot probes (vs the ~21
    of a bisect over a sorted array) - which matters most on Python 2, whose ctypes-array indexing is slow.
    """

    entries = list(entries)
    n = len(entries)

    cap = 1
    while cap < n * 2:              # power of two, load factor < 0.5 (fast &mask, short probe chains)
        cap <<= 1
    mask = cap - 1

    hi = array('I', b"\x00\x00\x00\x00" * cap)       # zero-filled (b"\x00"*N is portable; bytes(N) differs on Py2)
    lo = array('I', b"\x00\x00\x00\x00" * cap)
    val = array('I', b"\xff\xff\xff\xff" * cap)      # every slot initially _EMPTY
    for h, pi in entries:
        slot = h & mask
        while val[slot] != _EMPTY:                   # linear probe to the next free slot
            slot = (slot + 1) & mask
        hi[slot] = (h >> 32) & 0xFFFFFFFF
        lo[slot] = h & 0xFFFFFFFF
        val[slot] = pi

    blob = pickle.dumps((pair_list, collisions, regex), 2)

    to_bytes = (lambda a: a.tobytes()) if hasattr(hi, "tobytes") else (lambda a: a.tostring())  # tobytes: Py3.2+, tostring: Py2 (removed in Py3.9)

    with open(path, "wb") as f:
        f.write(_HEADER.pack(_MAGIC, cap, n, len(blob)))
        f.write(to_bytes(hi))
        f.write(to_bytes(lo))
        f.write(to_bytes(val))
        f.write(blob)

def _u32_view(buf, offset, n):
    """
    Returns a zero-copy, read-only view of a contiguous little-endian uint32 region of an mmap, indexable like a
    list so bisect() and direct indexing work over it WITHOUT any per-element wrapper overhead (the hot path). On
    Python 3 a casted memoryview is returned; on Python 2 (no memoryview.cast) a ctypes array overlaid on the
    buffer. Either way nothing is copied out of the shared mapping.
    """

    if _PY2:
        import ctypes
        return (ctypes.c_uint32 * n).from_buffer(buf, offset)   # buf must be writable (ACCESS_COPY); pages stay shared (COW) while only read
    return memoryview(buf)[offset:offset + 4 * n].cast("I")

def open_bin(path):
    """
    Memory-maps a binary trail file and returns a dict of read handles:
    {mmap, hi, lo, val, pair_list, collisions, regex, length}. The 'hi'/'lo'/'val' views read directly from the
    shared mapping. Raises ValueError on a bad/truncated/foreign file.
    """

    f = open(path, "rb")
    try:
        # Python 2 needs a writable (ACCESS_COPY / MAP_PRIVATE) mapping for the ctypes overlay; the pages remain
        # shared with the page cache via copy-on-write as long as nothing writes to them (we never do).
        access = mmap.ACCESS_COPY if _PY2 else mmap.ACCESS_READ
        mm = mmap.mmap(f.fileno(), 0, access=access)
    finally:
        f.close()

    if mm.size() < _HEADER_SIZE:
        mm.close()
        raise ValueError("trail bin too small")

    magic, cap, n, blob_len = _HEADER.unpack(mm[:_HEADER_SIZE])
    if magic != _MAGIC:
        mm.close()
        raise ValueError("bad trail bin magic")

    off = _HEADER_SIZE
    expected = off + 12 * cap + blob_len
    if mm.size() < expected:
        mm.close()
        raise ValueError("truncated trail bin (have %d, need %d)" % (mm.size(), expected))

    hi = _u32_view(mm, off, cap); off += 4 * cap
    lo = _u32_view(mm, off, cap); off += 4 * cap
    val = _u32_view(mm, off, cap); off += 4 * cap
    pair_list, collisions, regex = pickle.loads(mm[off:off + blob_len])

    return {"mmap": mm, "hi": hi, "lo": lo, "val": val, "mask": cap - 1,
            "pair_list": pair_list, "collisions": collisions, "regex": regex, "length": n + len(collisions)}

def lookup(handles, key, default=None):
    """
    Looks up a key in the opened handles, returning its (info, reference) tuple or 'default'. This is the read hot
    path: a tiny side-dict check (empty in practice) then a linear-probe of the open-addressing table starting at
    (hash & mask) - terminating at the matching slot or the first empty one (a couple of probes at load < 0.5).

    >>> import os, tempfile
    >>> p = os.path.join(tempfile.mkdtemp(), "t.bin")
    >>> e = [(stable_hash("a.example"), 0), (stable_hash("b.example"), 1)]
    >>> write_bin(p, e, [("malware", "(x)"), ("phishing", "(y)")], {}, "")
    >>> h = open_bin(p)
    >>> lookup(h, "a.example")
    ('malware', '(x)')
    >>> lookup(h, "b.example")
    ('phishing', '(y)')
    >>> lookup(h, "missing.example") is None
    True
    """

    collisions = handles["collisions"]
    if collisions and key in collisions:
        return collisions[key]

    h = stable_hash(key)
    target_hi = (h >> 32) & 0xFFFFFFFF
    target_lo = h & 0xFFFFFFFF
    hi = handles["hi"]
    lo = handles["lo"]
    val = handles["val"]
    mask = handles["mask"]
    slot = h & mask
    while True:
        v = val[slot]
        if v == _EMPTY:
            return default
        if hi[slot] == target_hi and lo[slot] == target_lo:
            return handles["pair_list"][v]
        slot = (slot + 1) & mask
