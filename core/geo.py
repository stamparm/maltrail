#!/usr/bin/env python

"""
Copyright (c) 2014-2026 Maltrail developers (https://github.com/stamparm/maltrail/)
See the file 'LICENSE' for copying permission
"""


import bisect
import gzip
import os
import re
import socket
import struct
import threading
import time

from core.settings import GEO_IP2CC_BUNDLED_FILE
from core.settings import GEO_IP2CC_FILE
from core.settings import GEO_IP2CC6_BUNDLED_FILE
from core.settings import GEO_IP2CC6_FILE

# IP -> ISO country, built from the public-domain RIR delegation statistics. Two tables (IPv4 + IPv6), each rows of
# "range_start,CC" sorted by start, with empty-CC gap rows marking unallocated space so private/reserved/unassigned
# addresses resolve to None. Both ship a bundled seed (data/) with a runtime refresh (USERS_DIR), so an air-gapped or
# first-run install geolocates both address families. All lookups are server-side, so the frontend never needs the
# tables and stays IP-version agnostic.
#
# STORAGE. A row's start is written as a HEX DELTA from the previous row (GEO_DELTA_MAGIC on the first line), and an
# IPv6 start as the delta of its /64 prefix - every RIR IPv6 allocation is coarser than a /64, so the low 64 bits are
# always zero and carrying them costs 20 decimal digits a row. The absolute-decimal format that came before is still
# read, because an existing install has one in USERS_DIR until its next refresh. The encoding is what makes bundling
# IPv6 defensible at all: 2,283 KB of absolute decimals, 81 KB as hex deltas, measured on the same table.

GEO_DELTA_MAGIC = "#hexdelta1"

_RESTAT_INTERVAL = 1.0  # seconds between mtime checks of a loaded table (see _load)

_tables = {}  # path -> (starts, ccs, mtime, checked_at); mtime-keyed so a refreshed table is picked up without a restart
_paths = {}   # (runtime, bundled) -> (resolved, checked_at)
_lock = threading.Lock()


def _parse(text):
    """Rows of either storage format -> (starts, ccs). Deltas accumulate; the IPv6 shift is applied by the caller."""

    starts, ccs = [], []
    lines = text.split("\n")
    delta = lines and lines[0].startswith(GEO_DELTA_MAGIC)
    shift = 64 if delta and lines[0].strip().endswith(":6") else 0
    previous = 0

    for line in lines[1:] if delta else lines:
        comma = line.find(",")
        if comma <= 0:
            continue
        if delta:
            previous += int(line[:comma], 16)
            starts.append(previous << shift)
        else:
            starts.append(int(line[:comma]))
        ccs.append(line[comma + 1:].strip())

    return (starts, ccs)


def _load(path):
    # Re-stat at most once a second. The tables refresh on a FRESH_GEO_DELTA_DAYS cadence, and this is called once per
    # event on /geo, where three stat() calls per lookup (two of them in _resolve) were 96% of the 4.4 us it took.
    now = time.time()
    cached = _tables.get(path)
    if cached is not None and now - cached[3] < _RESTAT_INTERVAL:
        return (cached[0], cached[1])

    try:
        mtime = os.path.getmtime(path)
    except Exception:
        return ([], [])

    if cached is not None and cached[2] == mtime:
        _tables[path] = (cached[0], cached[1], mtime, now)
        return (cached[0], cached[1])

    with _lock:
        cached = _tables.get(path)
        if cached is not None and cached[2] == mtime:
            return (cached[0], cached[1])

        starts, ccs = [], []
        try:
            with gzip.open(path, "rb") as f:  # binary + manual decode -> py2/py3 safe
                starts, ccs = _parse(f.read().decode("latin-1"))
        except Exception:
            pass

        _tables[path] = (starts, ccs, mtime, now)
        return (starts, ccs)


def _lookup(path, value):
    starts, ccs = _load(path)
    if not starts:
        return None
    index = bisect.bisect_right(starts, value) - 1
    if index < 0:
        return None
    return ccs[index] or None


def _resolve(runtime, bundled):
    """The runtime refresh in USERS_DIR when there is one, else the bundled seed (first run / air-gapped)."""

    key = (runtime, bundled)
    now = time.time()
    cached = _paths.get(key)
    if cached is not None and now - cached[1] < _RESTAT_INTERVAL:
        return cached[0]

    path = bundled
    try:
        if os.path.isfile(runtime) and os.path.getsize(runtime) > 0:
            path = runtime
    except Exception:
        pass

    _paths[key] = (path, now)
    return path


def _v4_path():
    return _resolve(GEO_IP2CC_FILE, GEO_IP2CC_BUNDLED_FILE)


def _v6_path():
    return _resolve(GEO_IP2CC6_FILE, GEO_IP2CC6_BUNDLED_FILE)


def ip_to_country(ip):
    """
    ISO country code for a public IP address, or None for private/reserved/unallocated/unknown addresses. Handles both
    IPv4 and IPv6; both families have a bundled seed, so neither depends on an online update having run.
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
        return _lookup(_v6_path(), value)

    try:
        value = struct.unpack(">I", socket.inet_aton(ip))[0]
    except (OSError, socket.error, TypeError):
        return None
    return _lookup(_v4_path(), value)


# leading IPv4 of a trail, up to an IP/port/path/space boundary: matches a bare IP, "IP:port", "IP/path",
# "IP (query)". A digit-leading DOMAIN (e.g. "1.2.3.4.evil.com") is rejected by requiring that boundary.
_LEADING_IPV4 = re.compile(r"(\d{1,3}(?:\.\d{1,3}){3})(?:[:/ ]|\Z)")


def event_country(trail_type, src, dst, trail):
    """
    Country to plot for one event on the attack-origins map, or None when it can't be honestly placed.

    The map should show WHERE the malicious external party is. That endpoint depends on the trail type
    (see the sensor), so this is an explicit decision tree rather than "geolocate the trail string":

      1. The IOC itself carries a public IP - a bare IP trail, or the host of an "IP:port" / "IP/path" /
         "IP (query)" trail (types IP / IPORT / IP-based URL|HTTP). Place that IP. It is already the exact
         malicious endpoint, whichever side (src or dst) of the flow it was.
      2. DNS: the IOC is a domain and the packet's dst is only the RESOLVER (e.g. 8.8.8.8) - the malicious
         host's IP is unknown at log time. Return None (honestly unmapped) rather than plotting the resolver.
      3. Inbound-attack heuristics (PATH web-scanning, PORT infection): the external party is the SOURCE.
         Place src, falling back to dst.
      4. Everything else - a domain-host URL|HTTP, a suspicious UA, etc. - is outbound: our host reached out
         to the malicious server, so place the DESTINATION we contacted, falling back to src.

    ip_to_country() returns None for private/loopback IPs and for non-IPs (domains), so a local host or a
    benign resolver can never be mis-plotted: it is both the "is this a routable public IP" test and the lookup.
    """
    tip = trail or ""
    m = _LEADING_IPV4.match(tip) if tip[:1].isdigit() else None
    cc = ip_to_country(m.group(1) if m else tip)
    if cc:
        return cc
    if trail_type == "DNS":
        return None
    if trail_type in ("PATH", "PORT"):
        return ip_to_country(src) or ip_to_country(dst) or None
    return ip_to_country(dst) or ip_to_country(src) or None
