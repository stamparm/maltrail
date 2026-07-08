#!/usr/bin/env python

"""
Copyright (c) 2014-2026 Maltrail developers (https://github.com/stamparm/maltrail/)
See the file 'LICENSE' for copying permission
"""

from __future__ import print_function

import bisect
import gzip
import os
import socket
import struct
import threading

from core.settings import GEO_IP2CC_BUNDLED_FILE
from core.settings import GEO_IP2CC_FILE
from core.settings import GEO_IP2CC6_FILE

# IP -> ISO country, built from the public-domain RIR delegation statistics. Two tables (IPv4 + IPv6); each is rows of
# "range_start_int,CC" sorted by start, with empty-CC gap rows marking unallocated space so private/reserved/unassigned
# addresses resolve to None. IPv4 ships a bundled seed (data/) with a runtime refresh (USERS_DIR); IPv6 is runtime-only
# (its table is large and IPv6 is comparatively rare) -> air-gapped IPv6 simply reads as "unmapped". All lookups are
# server-side, so the frontend never needs the tables and stays IP-version agnostic.

_tables = {}  # path -> (starts, ccs, mtime); mtime-keyed so an updated table is picked up without a restart
_lock = threading.Lock()


def _load(path):
    try:
        mtime = os.path.getmtime(path)
    except Exception:
        return ([], [])

    cached = _tables.get(path)
    if cached is not None and cached[2] == mtime:
        return (cached[0], cached[1])

    with _lock:
        cached = _tables.get(path)
        if cached is not None and cached[2] == mtime:
            return (cached[0], cached[1])

        starts, ccs = [], []
        try:
            with gzip.open(path, "rb") as f:  # binary + manual decode -> py2/py3 safe
                for line in f.read().decode("latin-1").split("\n"):
                    comma = line.find(",")
                    if comma > 0:
                        starts.append(int(line[:comma]))
                        ccs.append(line[comma + 1:].strip())
        except Exception:
            pass

        _tables[path] = (starts, ccs, mtime)
        return (starts, ccs)


def _lookup(path, value):
    starts, ccs = _load(path)
    if not starts:
        return None
    index = bisect.bisect_right(starts, value) - 1
    if index < 0:
        return None
    return ccs[index] or None


def _v4_path():
    try:
        if os.path.isfile(GEO_IP2CC_FILE) and os.path.getsize(GEO_IP2CC_FILE) > 0:  # runtime refresh
            return GEO_IP2CC_FILE
    except Exception:
        pass
    return GEO_IP2CC_BUNDLED_FILE  # bundled seed (first run / air-gapped)


def ip_to_country(ip):
    """
    ISO country code for a public IP address, or None for private/reserved/unallocated/unknown addresses. Handles both
    IPv4 and IPv6 (IPv6 only when its runtime table exists, i.e. after an online update; otherwise -> None).
    """

    if not ip:
        return None

    if ":" in ip:  # IPv6 -> 128-bit int (needs inet_pton; unavailable on some old/Windows py -> None)
        try:
            value = 0
            for byte in bytearray(socket.inet_pton(socket.AF_INET6, ip)):
                value = (value << 8) | byte
        except Exception:
            return None
        return _lookup(GEO_IP2CC6_FILE, value)

    try:
        value = struct.unpack(">I", socket.inet_aton(ip))[0]
    except (OSError, socket.error, TypeError):
        return None
    return _lookup(_v4_path(), value)
