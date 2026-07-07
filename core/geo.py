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

from core.settings import ROOT_DIR

# Compact IPv4 -> ISO country table, built from the public-domain RIR delegation statistics (see data/). Country-level
# allocations drift only slightly over months, so the bundled snapshot stays useful offline (air-gapped installs keep
# working off it); when online it can be refreshed on the update cycle. Rows are "range_start_int,CC" sorted by start,
# with empty-CC gap rows marking unallocated space, so private/reserved/unassigned IPs correctly resolve to None.
GEO_IP2CC_FILE = os.path.join(ROOT_DIR, "data", "ip2cc.csv.gz")

_starts = None  # sorted range-start integers
_ccs = None     # parallel ISO country codes ("" == unallocated gap)
_lock = threading.Lock()


def _load():
    global _starts, _ccs

    if _starts is not None:
        return

    with _lock:
        if _starts is not None:
            return

        starts, ccs = [], []
        try:
            with gzip.open(GEO_IP2CC_FILE, "rb") as f:  # binary + manual decode -> py2/py3 safe
                for line in f.read().decode("latin-1").split("\n"):
                    comma = line.find(",")
                    if comma > 0:
                        starts.append(int(line[:comma]))
                        ccs.append(line[comma + 1:].strip())
        except Exception:
            pass

        _starts, _ccs = starts, ccs


def ip_to_country(ip):
    """
    ISO country code for a public IPv4 address, or None for private/reserved/unallocated addresses, non-IPv4 values
    (e.g. a domain or IPv6 trail), or anything the table doesn't cover. Returning None == "not placed on the map".
    """

    _load()

    if not _starts or not ip:
        return None

    try:
        value = struct.unpack(">I", socket.inet_aton(ip))[0]
    except (OSError, socket.error, TypeError):
        return None

    index = bisect.bisect_right(_starts, value) - 1
    if index < 0:
        return None

    return _ccs[index] or None
