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
import json
import mmap
import os
import struct
import sys
import tempfile

from array import array

try:
    _TEXT_TYPE = unicode            # Python 2
except NameError:
    _TEXT_TYPE = str                # Python 3

_PY2 = sys.version_info[0] == 2

_MAGIC = b"MTRAILB3"               # 8 bytes; bump the trailing digit on any format change
_HEADER = struct.Struct("<8sQQQ") # magic, cap (slot count, power of two), n (occupied entries), blob_len
_HEADER_SIZE = _HEADER.size
_EMPTY = 0xFFFFFFFF                # value-slot sentinel for an empty bucket (pair indices are always far smaller)

assert array("I").itemsize == 4   # the binary format hardcodes 4-byte slots (true on every platform Maltrail runs on)

def _native_str(value):
    # json.loads yields unicode on Python 2; the rest of the sensor handles trail info/reference as native str there
    if _PY2 and isinstance(value, _TEXT_TYPE):
        return value.encode("utf-8")
    return value

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

def new_table(n_hint):
    """
    Allocates an empty open-addressing table sized to a power-of-two capacity at load factor < 0.5 (so lookups are
    ~1-2 probes and there is always a free slot). 'n_hint' is an upper bound on the number of entries. Returns
    (hi, lo, val, mask, cap). The table is filled by streaming table_insert() calls - no intermediate list of all
    entries (nor any retained key strings) is built, which keeps the builder's peak RSS an order of magnitude
    below materialising the whole set first.
    """

    cap = 1
    while cap < n_hint * 2:         # power of two, load factor < 0.5 (fast &mask, short probe chains)
        cap <<= 1
    hi = array('I', b"\x00\x00\x00\x00" * cap)       # zero-filled (b"\x00"*N is portable; bytes(N) differs on Py2)
    lo = array('I', b"\x00\x00\x00\x00" * cap)
    val = array('I', b"\xff\xff\xff\xff" * cap)      # every slot initially _EMPTY
    return hi, lo, val, cap - 1, cap

def table_insert(hi, lo, val, mask, h, pidx):
    """
    Inserts (h -> pidx) into the table. Returns True on success, or False WITHOUT inserting if the same 64-bit hash
    is already present - i.e. a genuine collision between two distinct trails (the CSV has unique keys, so a repeat
    hash is never a duplicate row). The caller handles the (astronomically rare) collision exactly, out of band.
    """

    target_hi = (h >> 32) & 0xFFFFFFFF
    target_lo = h & 0xFFFFFFFF
    slot = h & mask
    while val[slot] != _EMPTY:
        if hi[slot] == target_hi and lo[slot] == target_lo:
            return False
        slot = (slot + 1) & mask
    hi[slot] = target_hi
    lo[slot] = target_lo
    val[slot] = pidx
    return True

def write_table(path, cap, n, hi, lo, val, pair_list, collisions, regex):
    """
    Atomically writes a filled table to 'path'. 'pair_list' maps a pair_index to its (info, reference) tuple;
    'collisions' maps the few keys whose hash collided to their (info, reference) tuple; 'regex' is the wildcard
    alternation string.
    """

    assert len(pair_list) < _EMPTY, "too many distinct (info, reference) pairs for a uint32 value slot"

    # NOTE: the blob is JSON, not pickle - this file is read back by the (root) sensor, and pickle.loads on a file
    # an attacker might tamper with would be an arbitrary-code-execution sink. JSON of plain strings cannot execute.
    blob = json.dumps([pair_list, collisions, regex]).encode("utf-8")

    to_bytes = (lambda a: a.tobytes()) if hasattr(hi, "tobytes") else (lambda a: a.tostring())  # tobytes: Py3.2+, tostring: Py2 (removed in Py3.9)

    # write to a randomly-named, O_EXCL, 0600 temp file in the same dir, then atomically rename over the target -
    # mkstemp defeats symlink / predictable-name races a world-writable trails dir would otherwise expose
    directory = os.path.dirname(path) or "."
    fd, tmp_path = tempfile.mkstemp(prefix=".trailsbin-", dir=directory)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(_HEADER.pack(_MAGIC, cap, n, len(blob)))
            f.write(to_bytes(hi))
            f.write(to_bytes(lo))
            f.write(to_bytes(val))
            f.write(blob)
        (os.replace if hasattr(os, "replace") else os.rename)(tmp_path, path)  # atomic publish
    except Exception:
        try:
            os.remove(tmp_path)
        except OSError:
            pass
        raise

def write_bin(path, entries, pair_list, collisions, regex):
    """
    Convenience builder from a materialised (hash64, pair_index) iterable. Used by tests; the sensor's real builder
    (core.common) streams via new_table()/table_insert()/write_table() so it never materialises 'entries'.
    """

    entries = list(entries)
    hi, lo, val, mask, cap = new_table(len(entries))
    n = 0
    for h, pidx in entries:
        if table_insert(hi, lo, val, mask, h, pidx):
            n += 1
    write_table(path, cap, n, hi, lo, val, pair_list, collisions, regex)

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

    raw_pairs, raw_collisions, regex = json.loads(mm[off:off + blob_len].decode("utf-8"))
    pair_list = [(_native_str(p[0]), _native_str(p[1])) for p in raw_pairs]   # JSON lists -> the (info, reference) tuples the rest of the code expects
    collisions = dict((_native_str(k), (_native_str(v[0]), _native_str(v[1]))) for k, v in raw_collisions.items())
    regex = _native_str(regex)

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
    pl = handles["pair_list"]
    slot = h & mask
    while True:
        v = val[slot]
        if v == _EMPTY:
            return default
        if hi[slot] == target_hi and lo[slot] == target_lo:
            return pl[v] if v < len(pl) else default   # bounds-check: a corrupted/truncated/tampered bin must miss, not IndexError-crash the sensor on every lookup
        slot = (slot + 1) & mask
