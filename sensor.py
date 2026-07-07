#!/usr/bin/env python

"""
Copyright (c) 2014-2026 Maltrail developers (https://github.com/stamparm/maltrail/)
See the file 'LICENSE' for copying permission
"""

from __future__ import print_function  # Requires: Python >= 2.6
from collections import deque

import sys
from typing import Any

sys.dont_write_bytecode = True

import cProfile
import inspect
import math
import mmap
import optparse
import os
import re
import socket
import subprocess
import struct
import threading
import time
import traceback
import warnings

from core.addr import inet_ntoa6
from core.addr import addr_port
from core.addr import parse_host_port
from core.attribdict import AttribDict
from core.common import build_trails_regex
from core.common import check_connection
from core.common import check_sudo
from core.common import check_whitelisted
from core.common import get_ex_message
from core.common import get_text
from core.common import is_local
from core.common import load_trails
from core.common import load_trails_mmap
from core.common import patch_parser
from core.common import USE_MMAP_TRAILS
from core.compat import xrange
from core.datatype import LRUDict
from core.enums import BLOCK_MARKER
from core.enums import CACHE_TYPE
from core.enums import PROTO
from core.enums import TRAIL
from core.log import create_log_directory
from core.log import flush_condensed_events
from core.log import get_error_log_handle
from core.log import log_error
from core.log import log_event
from core.parallel import worker
from core.parallel import write_block
from core.settings import config
from core.settings import CAPTURE_TIMEOUT
from core.settings import CHECK_CONNECTION_MAX_RETRIES
from core import fastfilter
from core.settings import CONFIG_FILE
from core.settings import CONSONANTS
from core.settings import DLT_OFFSETS
from core.settings import DNS_EXHAUSTION_THRESHOLD
from core.settings import GENERIC_SINKHOLE_REGEX
from core.settings import HOMEPAGE
from core.settings import HOURLY_SECS
from core.settings import HTTP_TIME_FORMAT
from core.settings import IGNORE_DNS_QUERY_SUFFIXES
from core.settings import IPPROTO_LUT
from core.settings import IS_WIN
from core.settings import LOCALHOST_IP
from core.settings import LOCAL_SUBDOMAIN_LOOKUPS
from core.settings import MAX_CACHE_ENTRIES
from core.settings import MMAP_ZFILL_CHUNK_LENGTH
from core.settings import NAME
from core.settings import NO_SUCH_NAME_COUNTERS
from core.settings import NO_SUCH_NAME_PER_HOUR_THRESHOLD
from core.settings import INFECTION_SCANNING_THRESHOLD
from core.settings import PORT_SCANNING_THRESHOLD
from core.settings import POTENTIAL_INFECTION_PORTS
from core.settings import read_config
from core.settings import REGULAR_SENSOR_SLEEP_TIME
from core.settings import SNAP_LEN
from core.settings import SUSPICIOUS_CONTENT_TYPES
from core.settings import SUSPICIOUS_DIRECT_DOWNLOAD_EXTENSIONS
from core.settings import SUSPICIOUS_DIRECT_IP_URL_REGEX
from core.settings import SUSPICIOUS_DOMAIN_CONSONANT_THRESHOLD
from core.settings import SUSPICIOUS_DOMAIN_ENTROPY_THRESHOLD
from core.settings import SUSPICIOUS_DOMAIN_LENGTH_THRESHOLD
from core.settings import SUSPICIOUS_HTTP_PATH_REGEXES
from core.settings import SUSPICIOUS_HTTP_REQUEST_PRE_CONDITION
from core.settings import SUSPICIOUS_HTTP_REQUEST_REGEXES
from core.settings import SUSPICIOUS_HTTP_REQUEST_FORCE_ENCODE_CHARS
from core.settings import SUSPICIOUS_PROXY_PROBE_PRE_CONDITION
from core.settings import SUSPICIOUS_UA_REGEX
from core.settings import VALID_DNS_NAME_REGEX
from core.settings import trails
from core.settings import VERSION
from core.settings import WEB_SCANNING_THRESHOLD
from core.settings import WHITELIST
from core.settings import WHITELIST_DIRECT_DOWNLOAD_KEYWORDS
from core.settings import WHITELIST_LONG_DOMAIN_NAME_KEYWORDS
from core.settings import WHITELIST_HTTP_REQUEST_PATHS
from core.settings import WHITELIST_UA_REGEX
from core.update import update_ipcat
from core.update import update_trails
from core.icmp_packet import IcmpDestination
from thirdparty import six
from thirdparty.six.moves import urllib as _urllib

warnings.filterwarnings(action="ignore", category=DeprecationWarning)       # NOTE: https://github.com/helpsystems/pcapy/pull/67/files

_buffer = None
_caps = []
_connect_sec = 0


def _fanout_count():
    """Number of PACKET_FANOUT capture sockets to open per live interface (CAPTURE_FANOUT).
    Lets the kernel flow-hash one interface's traffic across N capture threads instead of one,
    scaling capture past a single thread. <=1 / unset / 'false' = off; 'true'/'auto' = CPU count.
    Linux + a pcapy-ng that exposes set_fanout only; otherwise it falls back to a single socket."""
    val = getattr(config, "CAPTURE_FANOUT", None)
    if val is None or val == "":
        return 0
    try:
        n = int(val)
    except (TypeError, ValueError):
        n = _cpu_count() if str(val).strip().lower() in ("true", "auto", "yes", "on") else 0
    return n if n > 1 else 0


def _cpu_count():
    """Logical CPU count, Py2 + Py3 safe (os.cpu_count is Py3.4+)."""
    try:
        return os.cpu_count() or 1
    except AttributeError:
        try:
            import multiprocessing
            return multiprocessing.cpu_count()
        except Exception:
            return 1


def _src_hash(packet, ip_offset):
    """Deterministic hash of a packet's source IP (v4 or v6), for source-affinity worker routing.
    Same source -> same value (so its whole flow/scan lands on one worker); a polynomial roll gives
    an even spread across sources for load balance. Returns a non-negative int (0 if not IP)."""
    try:
        ver = bytearray(packet[ip_offset:ip_offset + 1])[0] >> 4
    except IndexError:
        return 0
    if ver == 4:
        src = packet[ip_offset + 12:ip_offset + 16]
    elif ver == 6:
        src = packet[ip_offset + 8:ip_offset + 24]
    else:
        return 0
    h = 0
    for b in bytearray(src):
        h = (h * 131 + b) & 0xffffffff
    return h


def _cfg_bool(value):
    """True iff a config value is an affirmative switch. Robust whether read_config gave us a real
    bool (USE_/CHECK_/... prefixes) or a raw string (e.g. FAST_ADMIT_ADAPTIVE, which has no boolean
    prefix) -- bool('false') is True, so a plain bool() cast would wrongly enable a 'false' switch."""
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in ("1", "true", "yes", "on")


_HEURISTIC_NAMES = ("port_scanning", "udp_scanning", "infection", "web_scanning", "dns_exhaustion", "long_domain")
_disabled_heuristics_cache = [None]

def _heuristic_enabled(name):
    """Whether a named (low-value/noisy) heuristic should emit events. Lets an operator mute the
    annoying ones (e.g. `DISABLED_HEURISTICS port_scanning, dns_exhaustion`) without turning off
    USE_HEURISTICS wholesale. Unset => all enabled (no behavior change). Names: %s.""" % ", ".join(_HEURISTIC_NAMES)
    cached = _disabled_heuristics_cache[0]
    if cached is None:
        raw = getattr(config, "DISABLED_HEURISTICS", None) or ""
        if not isinstance(raw, str):
            raw = ",".join(raw)                         # tolerate a list from read_config
        cached = frozenset(_.strip().lower() for _ in re.split(r"[,\s]+", raw) if _.strip())
        _disabled_heuristics_cache[0] = cached
    return name not in cached


# Sliding-window scan detection: instead of clearing the accumulators every ~1s (which let any
# sub-threshold-rate scan evade), keep state for _scan_window() seconds and alert once per key per
# window. Memory is bounded by a per-key item cap and a total-key cap (so a 60k-port scan or a busy
# network can't balloon the dicts).
_SCAN_TRACK_PER_KEY = 1024     # plenty above any threshold; once hit, the scan is already detected
_SCAN_MAX_KEYS = 50000         # cap distinct (src,dst) pairs tracked at once
_STEALTH_FLAGS = frozenset((0x00, 0x01, 0x29))   # NULL / bare-FIN / XMAS scans (nmap -sN/-sF/-sX)

def _scan_window():
    """Sliding-window length in seconds for the scan heuristics (default 30). Longer = catches
    slower scans but retains more state; bounded to a sane range."""
    try:
        return max(1, min(3600, int(getattr(config, "SCAN_WINDOW", 30) or 30)))
    except (TypeError, ValueError):
        return 30

def _scan_track(store, details, key, item, detail):
    """Add item/detail to a sliding-window scan accumulator with BOUNDED memory: cap the number of
    distinct keys (_SCAN_MAX_KEYS) and items-per-key (_SCAN_TRACK_PER_KEY). Once a key is over its
    threshold the scan is already detected, so refusing further growth loses no detection while
    keeping RAM bounded even on a busy network or against a 65k-port sweep."""
    s = store.get(key)
    if s is None:
        if len(store) >= _SCAN_MAX_KEYS:
            return                                  # at capacity -> don't start new keys
        s = store[key] = set()
        details[key] = set()
    if len(s) < _SCAN_TRACK_PER_KEY:
        s.add(item)
        details[key].add(detail)

_connect_src_dst = {}
_connect_src_details = {}
_path_src_dst = {}
_path_src_dst_details = {}
_udp_scan = {}                 # (src,dst_ip) -> set of UDP dst ports (UDP scan detection)
_udp_scan_details = {}
_scan_window_start = 0
_scan_alerted = set()          # keys that already alerted this window (avoids per-second re-log flood)
_path_alerted = set()
_udp_alerted = set()
_count = 0
_locks = AttribDict()
_multiprocessing = None
_n = None
_result_cache = LRUDict(MAX_CACHE_ENTRIES)
_local_cache = LRUDict(MAX_CACHE_ENTRIES)
_valid_dns_name_regex = re.compile(VALID_DNS_NAME_REGEX)  # NOTE: precompiled (used per DNS query); ~2x vs re.search(string, ...)
_last_syn = None
_last_logged_syn = None
_last_udp = None
_last_logged_udp = None
_done_count = 0
_done_lock = threading.Lock()
_subdomains = {}
_subdomains_sec = None
_no_such_name_hour = None   # last hour-bucket for which NO_SUCH_NAME_COUNTERS was pruned (bounds the per-worker dict)
_dns_exhausted_domains = set()
_last_icmp4_destinations = {}
_last_icmp4_order = deque()
_icmp4_exfiltration_baseline = 0
_icmp4_exfiltration_baseline_startup_time = time.time()
_icmp4_large_payload_size_treshold = 0
_icmp4_large_package_size_startup_time = time.time()

_last_icmp6_destinations = {}
_last_icmp6_order = deque()
_icmp6_exfiltration_baseline = 0
_icmp6_exfiltration_baseline_startup_time = time.time()
_icmp6_large_payload_size_treshold = 0
_icmp6_large_package_size_startup_time = time.time()

class _set(set):
    pass

try:
    import __builtin__
except ImportError:
    # Python 3
    import builtins as __builtin__


def print(*args, **kwargs):
    ret = __builtin__.print(*args, **kwargs)
    sys.stdout.flush()
    return ret


try:
    import pcapy
except ImportError:
    if IS_WIN:
        sys.exit("[!] please install 'WinPcap' (e.g. 'http://www.winpcap.org/install/') and Pcapy (e.g. 'https://breakingcode.wordpress.com/?s=pcapy')")
    else:
        msg = "[!] please install 'pcapy or pcapy-ng' (e.g. 'sudo pip%s install pcapy-ng')" % ('3' if six.PY3 else '2')

        sys.exit(msg)

def _check_domain_member(query, domains):
    """
    Checks whether the query (or any of its parent domains) is contained in the given set of domains

    >>> _check_domain_member("www.evil.com", set(["evil.com"]))
    True
    >>> _check_domain_member("a.b.example.com", set(["example.com"]))
    True
    >>> _check_domain_member("good.com", set(["evil.com"]))
    False
    """

    parts = query.lower().split('.')

    for i in xrange(0, len(parts)):
        domain = '.'.join(parts[i:])
        if domain in domains:
            return True

    return False

def _check_domain_whitelisted(query):
    result = _result_cache.get((CACHE_TYPE.DOMAIN_WHITELISTED, query))

    if result is None:
        result = _check_domain_member(re.split(r"(?i)[^A-Z0-9._-]", query or "")[0], WHITELIST)
        _result_cache[(CACHE_TYPE.DOMAIN_WHITELISTED, query)] = result

    return result

def _check_domain(query, sec, usec, src_ip, src_port, dst_ip, dst_port, proto, packet=None):
    if query:
        query = query.lower()
        if ':' in query:
            query = query.split(':', 1)[0]

    if query.replace('.', "").isdigit():  # IP address
        return

    if _result_cache.get((CACHE_TYPE.DOMAIN, query)) is False:
        return

    result = False
    if _valid_dns_name_regex.search(query) is not None and not _check_domain_whitelisted(query):
        parts = query.split('.')

        if query.endswith(".ip-adress.com"):  # Reference: https://www.virustotal.com/gui/domain/ip-adress.com/relations
            _ = '.'.join(parts[:-2])
            trail = "%s(.ip-adress.com)" % _
            if _ in trails:
                result = True
                log_event((sec, usec, src_ip, src_port, dst_ip, dst_port, proto, TRAIL.DNS, trail, trails[_][0], trails[_][1]), packet)

        if not result:
            for i in xrange(0, len(parts)):
                domain = '.'.join(parts[i:])
                if domain in trails:
                    if domain == query:
                        trail = domain
                    else:
                        _ = ".%s" % domain
                        trail = "(%s)%s" % (query[:-len(_)], _)

                    if not (re.search(r"(?i)\A([rd]?ns|nf|mx|nic)\d*\.", query) and any(_ in trails.get(domain, " ")[0] for _ in ("suspicious", "sinkhole"))):  # e.g. ns2.nobel.su
                        if not ((query == trail or parts[0] == "www") and any(_ in trails.get(domain, " ")[0] for _ in ("dynamic", "free web"))):  # e.g. noip.com
                            result = True
                            log_event((sec, usec, src_ip, src_port, dst_ip, dst_port, proto, TRAIL.DNS, trail, trails[domain][0], trails[domain][1]), packet)
                            break

        if not result and config.USE_HEURISTICS and _heuristic_enabled("long_domain"):
            if len(parts[0]) > SUSPICIOUS_DOMAIN_LENGTH_THRESHOLD and '-' not in parts[0]:
                trail = None

                if len(parts) > 2:
                    trail = "(%s).%s" % ('.'.join(parts[:-2]), '.'.join(parts[-2:]))
                elif len(parts) == 2:
                    trail = "(%s).%s" % (parts[0], parts[1])
                else:
                    trail = query

                if trail and not any(_ in trail for _ in WHITELIST_LONG_DOMAIN_NAME_KEYWORDS):
                    result = True
                    log_event((sec, usec, src_ip, src_port, dst_ip, dst_port, proto, TRAIL.DNS, trail, "long domain (suspicious)", "(heuristic)"), packet)

        if not result and trails._regex:
            match = re.search(trails._regex, query)
            if match:
                group, trail = [_ for _ in match.groupdict().items() if _[1] is not None][0]
                candidate = trails._regex.split("(?P<")[int(group[1:]) + 1]
                candidate = candidate.split('>', 1)[-1].rstrip('|')[:-1]
                if candidate in trails:
                    result = True
                    trail = match.group(0)

                    prefix, suffix = query[:match.start()], query[match.end():]
                    if prefix:
                        trail = "(%s)%s" % (prefix, trail)
                    if suffix:
                        trail = "%s(%s)" % (trail, suffix)

                    trail = trail.replace(".)", ").")

                    log_event((sec, usec, src_ip, src_port, dst_ip, dst_port, proto, TRAIL.DNS, trail, trails[candidate][0], trails[candidate][1]), packet)

        if not result and ".onion." in query:
            trail = re.sub(r"(\.onion)(\..*)", r"\1(\2)", query)
            _ = trail.split('(')[0]
            if _ in trails:
                result = True
                log_event((sec, usec, src_ip, src_port, dst_ip, dst_port, proto, TRAIL.DNS, trail, trails[_][0], trails[_][1]), packet)

    if result is False:
        _result_cache[(CACHE_TYPE.DOMAIN, query)] = False

def _get_local_prefix():
    _sources = set(_[0] for _ in list(_connect_src_dst.keys()))  # NOTE: tuple keys (src, dst); list() snapshots atomically to avoid "dictionary changed size" when another capture thread mutates _connect_src_dst (multi-interface mode)
    _candidates = [re.sub(r"\d+\.\d+\Z", "", _) for _ in _sources]
    _ = sorted(((_candidates.count(_), _) for _ in set(_candidates)), reverse=True)
    result = _[0][1] if _ else ""

    if result:
        _result_cache[(CACHE_TYPE.LOCAL_PREFIX, "")] = result
    else:
        result = _result_cache.get((CACHE_TYPE.LOCAL_PREFIX, ""))

    return result or '_'

def _process_packet(packet, sec, usec, ip_offset):
    """
    Processes single (raw) IP layer data
    """

    global _connect_sec
    global _last_syn
    global _last_logged_syn
    global _last_udp
    global _last_logged_udp
    global _subdomains_sec
    global _no_such_name_hour
    global _scan_window_start

    try:
        if config.USE_HEURISTICS:
            if _locks.connect_sec:
                _locks.connect_sec.acquire()

            connect_sec = _connect_sec
            _connect_sec = sec

            if _locks.connect_sec:
                _locks.connect_sec.release()

            if sec > connect_sec:
                if getattr(_locks, "heuristics", None):
                    _locks.heuristics.acquire()

                try:
                    for key in _connect_src_dst:
                        if key in _scan_alerted:                 # already alerted this window -> no per-second re-log
                            continue
                        _src_ip, _dst = key
                        if not isinstance(_dst, int) and len(_connect_src_dst[key]) > PORT_SCANNING_THRESHOLD:  # str _dst => per-IP key (port scan); int _dst => per-port key (infection)
                            _dst_ip = _dst
                            # port-scan is the noisiest, lowest-value heuristic, BUT it is NOT locality-
                            # suppressed: the battle-test lab showed a both-local guard silently kills
                            # internal->internal lateral recon (a real TP). So it stays whitelist-gated
                            # and mutable via DISABLED_HEURISTICS (the right lever for noise-averse ops).
                            if not check_whitelisted(_src_ip) and _heuristic_enabled("port_scanning"):
                                # log ONCE per (scanner, target) per window. The old `for _ in details`
                                # emitted one event PER probed port -> a 1000-port scan = 1000 lines.
                                _ = next(iter(_connect_src_details[key]))
                                log_event((sec, usec, _src_ip, _[2], _dst_ip, _[3], PROTO.TCP, TRAIL.IP, _src_ip, "potential port scanning", "(heuristic)"), packet)
                                _scan_alerted.add(key)
                        elif len(_connect_src_dst[key]) > INFECTION_SCANNING_THRESHOLD:
                            # _connect_src_dst[key] is already a SET of distinct dst IPs, so exceeding the
                            # threshold == "this local host hit >N distinct hosts on one infection port".
                            _dst_port = _dst
                            if _src_ip.startswith(_get_local_prefix()) and _heuristic_enabled("infection"):
                                _ = next(iter(_connect_src_details[key]))
                                log_event((sec, usec, _src_ip, _[-2], _[-1], _dst_port, PROTO.TCP, TRAIL.PORT, _dst_port, "potential infection", "(heuristic)"), packet)
                                _scan_alerted.add(key)
                finally:
                    if getattr(_locks, "heuristics", None):
                        _locks.heuristics.release()

                for key in list(_path_src_dst):   # snapshot keys: _path_src_dst is written lock-free by other capture threads, so a bare `for key in _path_src_dst` races into "dictionary changed size during iteration" in multi-interface mode (mirrors the list() snapshot at line 277). On that throw the analysis aborted and _path_src_dst was never cleared -> missed web-scan detection + unbounded growth.
                    if key in _path_alerted:
                        continue
                    details = _path_src_dst_details.get(key)
                    if len(_path_src_dst[key]) > WEB_SCANNING_THRESHOLD and details:   # `details` may briefly be missing/empty (its entry is created a few statements after _path_src_dst's, lock-free) -> guard the .pop()
                        _src_ip, _dst_ip = key
                        # FP guard (this heuristic alone had NONE, unlike port-scan's whitelist check
                        # and infection's local-source check): skip whitelisted sources, and skip
                        # internal<->internal traffic. Reverse proxies, service meshes, health checks
                        # and docker/k8s networks routinely hit many distinct paths on an internal
                        # host -> that is not web scanning. External<->internal scans are still flagged.
                        if not check_whitelisted(_src_ip) and not (is_local(_src_ip) and is_local(_dst_ip)) and _heuristic_enabled("web_scanning"):
                            _sec, _usec, _src_port, _dst_port, _path = details.pop()
                            log_event((_sec, _usec, _src_ip, _src_port, _dst_ip, _dst_port, PROTO.TCP, TRAIL.PATH, "*", "potential web scanning", "(heuristic)"), packet)
                            _path_alerted.add(key)

                for key in list(_udp_scan):                  # UDP scan (nmap -sU): many UDP dst ports, one host
                    if key in _udp_alerted:
                        continue
                    details = _udp_scan_details.get(key)
                    if len(_udp_scan[key]) > PORT_SCANNING_THRESHOLD and details:
                        _src_ip, _dst_ip = key
                        if not check_whitelisted(_src_ip) and _heuristic_enabled("udp_scanning"):
                            _ = next(iter(details))
                            log_event((sec, usec, _src_ip, _[2], _dst_ip, _[3], PROTO.UDP, TRAIL.IP, _src_ip, "potential udp scanning", "(heuristic)"), packet)
                            _udp_alerted.add(key)

                # SLIDING WINDOW: clear only at the window boundary (not every second), so a scan spread
                # over up to _scan_window() seconds still accumulates -> slow scans no longer slip under
                # the old ~1s clear. Between boundaries state is kept and each key alerts at most once
                # (via _scan_alerted / _path_alerted / _udp_alerted), so there is no per-second re-log flood.
                if sec - _scan_window_start >= _scan_window():
                    _connect_src_dst.clear()
                    _connect_src_details.clear()
                    _scan_alerted.clear()
                    _path_src_dst.clear()
                    _path_src_dst_details.clear()
                    _udp_scan.clear()
                    _udp_scan_details.clear()
                    _udp_alerted.clear()
                    _path_alerted.clear()
                    _scan_window_start = sec

        ip_data = packet[ip_offset:]
        ip_version = ord(ip_data[0:1]) >> 4

        if ip_version == 0x04:  # IPv4
            ip_header = struct.unpack("!BBHHHBBH4s4s", ip_data[:20])
            fragment_offset = ip_header[4] & 0x1fff
            if fragment_offset != 0:
                return
            iph_length = (ip_header[0] & 0xf) << 2
            protocol = ip_header[6]
            src_ip = socket.inet_ntoa(ip_header[8])
            dst_ip = socket.inet_ntoa(ip_header[9])
        elif ip_version == 0x06:  # IPv6
            # Reference: http://chrisgrundemann.com/index.php/2012/introducing-ipv6-understanding-ipv6-addresses/
            ip_header = struct.unpack("!BBHHBB16s16s", ip_data[:40])
            iph_length = 40
            protocol = ip_header[4]
            src_ip = inet_ntoa6(ip_header[6])
            dst_ip = inet_ntoa6(ip_header[7])
        else:
            return   # not IPv4/IPv6 (e.g. a misaligned offset from the DLT heuristic) -> drop before the LOCALHOST_IP lookup below would KeyError

        localhost_ip = LOCALHOST_IP[ip_version]

        if protocol == socket.IPPROTO_TCP:  # TCP
            src_port, dst_port, _, _, doff_reserved, flags = struct.unpack("!HHLLBB", ip_data[iph_length:iph_length + 14])

            if flags != 2 and config.plugin_functions:
                if dst_ip in trails:
                    log_event((sec, usec, src_ip, src_port, dst_ip, dst_port, PROTO.TCP, TRAIL.IP, dst_ip, trails[dst_ip][0], trails[dst_ip][1]), packet, skip_write=True)
                elif src_ip in trails and dst_ip != localhost_ip:
                    log_event((sec, usec, src_ip, src_port, dst_ip, dst_port, PROTO.TCP, TRAIL.IP, src_ip, trails[src_ip][0], trails[src_ip][1]), packet, skip_write=True)

            if flags == 2:  # SYN set (only)
                _ = _last_syn
                _last_syn = (sec, src_ip, src_port, dst_ip, dst_port)
                if _ == _last_syn:  # skip bursts
                    return

                if dst_ip in trails or addr_port(dst_ip, dst_port) in trails:
                    _ = _last_logged_syn
                    _last_logged_syn = _last_syn
                    if _ != _last_logged_syn:
                        trail = addr_port(dst_ip, dst_port)
                        if trail not in trails:
                            trail = dst_ip
                        if not any(_ in trails[trail][0] for _ in ("attacker",)) and not ("parking site" in trails[trail][0] and dst_port not in (80, 443)):
                            # IPORT iff the matched key is the addr_port form (not the bare IP). The old
                            # `':' not in trail` check mis-typed EVERY IPv6 IP-trail as IPORT (v6 addrs contain ':').
                            log_event((sec, usec, src_ip, src_port, dst_ip, dst_port, PROTO.TCP, TRAIL.IPORT if trail != dst_ip else TRAIL.IP, trail, trails[trail][0], trails[trail][1]), packet)

                elif (src_ip in trails or addr_port(src_ip, src_port) in trails) and dst_ip != localhost_ip:
                    _ = _last_logged_syn
                    _last_logged_syn = _last_syn
                    if _ != _last_logged_syn:
                        trail = addr_port(src_ip, src_port)
                        if trail not in trails:
                            trail = src_ip
                        if not any(_ in trails[trail][0] for _ in ("malware",)):
                            log_event((sec, usec, src_ip, src_port, dst_ip, dst_port, PROTO.TCP, TRAIL.IPORT if trail != src_ip else TRAIL.IP, trail, trails[trail][0], trails[trail][1]), packet)

                if config.USE_HEURISTICS:
                    if dst_ip != localhost_ip:
                        if getattr(_locks, "heuristics", None):
                            _locks.heuristics.acquire()

                        try:
                            # tuple keys (IPv6-safe); bounded sliding-window accumulators (see _scan_track)
                            _scan_track(_connect_src_dst, _connect_src_details, (src_ip, dst_ip), dst_port, (sec, usec, src_port, dst_port))
                            if dst_port in POTENTIAL_INFECTION_PORTS:
                                _scan_track(_connect_src_dst, _connect_src_details, (src_ip, dst_port), dst_ip, (sec, usec, src_port, dst_ip))
                        finally:
                            if getattr(_locks, "heuristics", None):
                                _locks.heuristics.release()

            elif config.USE_HEURISTICS and flags in _STEALTH_FLAGS and dst_ip != localhost_ip and _heuristic_enabled("port_scanning"):
                # Stealth scan coverage: NULL (0x00), bare-FIN (0x01) and XMAS (FIN|PSH|URG=0x29) are
                # flag combos no legitimate TCP stack sends (a real FIN carries ACK), so they are scan
                # probes -- nmap -sN / -sF / -sX. Feed them into the SAME port-scan accumulator the SYN
                # path uses, so these (previously invisible -- only flags==2 was counted) scans are
                # caught too. ACK/Maimon scans are deliberately NOT included: a bare ACK is normal mid-
                # connection traffic, so counting it would be a false-positive cannon.
                if getattr(_locks, "heuristics", None):
                    _locks.heuristics.acquire()
                try:
                    _scan_track(_connect_src_dst, _connect_src_details, (src_ip, dst_ip), dst_port, (sec, usec, src_port, dst_port))
                finally:
                    if getattr(_locks, "heuristics", None):
                        _locks.heuristics.release()

            else:
                tcph_length = doff_reserved >> 4
                h_size = iph_length + (tcph_length << 2)
                tcp_payload = ip_data[h_size:]
                # NOTE: the whole block below only acts on HTTP (response starting with "HTTP/" or request containing " HTTP/"),
                # so skip the (costly) full-payload decode for non-HTTP TCP (e.g. the bulk of line-rate traffic: TLS/443)
                tcp_data = get_text(tcp_payload) if b"HTTP/" in tcp_payload else ""

                if tcp_data.startswith("HTTP/"):
                    match = re.search(GENERIC_SINKHOLE_REGEX, tcp_data[:2000])
                    if match:
                        trail = match.group(0)
                        log_event((sec, usec, src_ip, src_port, dst_ip, dst_port, PROTO.TCP, TRAIL.HTTP, trail, "sinkhole response (malware)", "(heuristic)"), packet)
                    else:
                        index = tcp_data.find("<title>")
                        if index >= 0:
                            end = tcp_data.find("</title>", index)   # only extract when the closing tag is in the captured bytes; otherwise find()==-1 -> tcp_data[start:-1] grabs ~the whole response body as a bogus multi-KB trail (the Content-Type/Host parses below already guard this way)
                            if end >= 0:
                                title = tcp_data[index + len("<title>"):end]
                                if re.search(r"domain name has been seized by|Domain Seized|Domain Seizure", title):
                                    log_event((sec, usec, src_ip, src_port, dst_ip, dst_port, PROTO.TCP, TRAIL.HTTP, title, "seized domain (suspicious)", "(heuristic)"), packet)

                    content_type = None
                    first_index = tcp_data.find("\r\nContent-Type:")
                    if first_index >= 0:
                        first_index = first_index + len("\r\nContent-Type:")
                        last_index = tcp_data.find("\r\n", first_index)
                        if last_index >= 0:
                            content_type = tcp_data[first_index:last_index].strip().lower()

                    if content_type and content_type in SUSPICIOUS_CONTENT_TYPES:
                        log_event((sec, usec, src_ip, src_port, dst_ip, dst_port, PROTO.TCP, TRAIL.HTTP, content_type, "content type (suspicious)", "(heuristic)"), packet)

                method, path = None, None

                if " HTTP/" in tcp_data:
                    index = tcp_data.find("\r\n")
                    if index >= 0:
                        line = tcp_data[:index]
                        if line.count(' ') == 2 and " HTTP/" in line:
                            method, path, _ = line.split(' ')

                if method and path:
                    post_data = None
                    host = dst_ip
                    first_index = tcp_data.find("\r\nHost:")
                    path = path.lower()

                    if first_index >= 0:
                        first_index = first_index + len("\r\nHost:")
                        last_index = tcp_data.find("\r\n", first_index)
                        if last_index >= 0:
                            host = tcp_data[first_index:last_index]
                            host = host.strip().lower()
                            if host.endswith(":80"):
                                host = host[:-3]
                            if host and host[0].isalpha() and dst_ip in trails:
                                log_event((sec, usec, src_ip, src_port, dst_ip, dst_port, PROTO.TCP, TRAIL.IP, "%s (%s)" % (dst_ip, host.split(':')[0]), trails[dst_ip][0], trails[dst_ip][1]), packet)
                            elif re.search(r"\A\d+\.[0-9.]+\Z", host or "") and re.search(SUSPICIOUS_DIRECT_IP_URL_REGEX, "%s%s" % (host, path)):
                                if not dst_ip.startswith(_get_local_prefix()):
                                    trail = "(%s)%s" % (host, path)
                                    log_event((sec, usec, src_ip, src_port, dst_ip, dst_port, PROTO.TCP, TRAIL.HTTP, trail, "potential iot-malware download (suspicious)", "(heuristic)"), packet)
                                    return
                            elif config.CHECK_HOST_DOMAINS:
                                _check_domain(host, sec, usec, src_ip, src_port, dst_ip, dst_port, PROTO.TCP, packet)
                    elif config.USE_HEURISTICS and config.CHECK_MISSING_HOST:
                        log_event((sec, usec, src_ip, src_port, dst_ip, dst_port, PROTO.TCP, TRAIL.HTTP, "%s%s" % (host, path), "missing host header (suspicious)", "(heuristic)"), packet)

                    index = tcp_data.find("\r\n\r\n")
                    if index >= 0:
                        post_data = tcp_data[index + 4:]

                    url = None
                    if config.USE_HEURISTICS and path.startswith('/'):
                        _path = path.split('/')[1]
                        _scan_track(_path_src_dst, _path_src_dst_details, (src_ip, dst_ip), _path, (sec, usec, src_port, dst_port, path))

                    elif config.USE_HEURISTICS and dst_port == 80 and path.startswith("http://") and any(_ in path for _ in SUSPICIOUS_PROXY_PROBE_PRE_CONDITION) and not _check_domain_whitelisted(path.split('/')[2]):
                        trail = re.sub(r"(http://[^/]+/)(.+)", r"\g<1>(\g<2>)", path)
                        trail = re.sub(r"(http://)([^/(]+)", lambda match: "%s%s" % (match.group(1), match.group(2).split(':')[0].rstrip('.')), trail)
                        log_event((sec, usec, src_ip, src_port, dst_ip, dst_port, PROTO.TCP, TRAIL.HTTP, trail, "potential proxy probe (suspicious)", "(heuristic)"), packet)
                        return
                    elif "://" in path:
                        unquoted_path = _urllib.parse.unquote(path)

                        key = "code execution"
                        if key not in _local_cache:
                            _local_cache[key] = next(_[1] for _ in SUSPICIOUS_HTTP_REQUEST_REGEXES if "code execution" in _[0])

                        if re.search(_local_cache[key], unquoted_path, re.I) is None:    # NOTE: to prevent malware domain FPs in case of outside scanners
                            url = path.split("://", 1)[1]

                            if '/' not in url:
                                url = "%s/" % url

                            host, path = url.split('/', 1)
                            if host.endswith(":80"):
                                host = host[:-3]
                            path = "/%s" % path
                            proxy_domain = host.split(':')[0]
                            _check_domain(proxy_domain, sec, usec, src_ip, src_port, dst_ip, dst_port, PROTO.TCP, packet)
                    elif method == "CONNECT":
                        if '/' in path:
                            host, path = path.split('/', 1)
                            path = "/%s" % path
                        else:
                            host, path = path, '/'
                        if host.endswith(":80"):
                            host = host[:-3]
                        url = "%s%s" % (host, path)
                        proxy_domain = host.split(':')[0]
                        _check_domain(proxy_domain, sec, usec, src_ip, src_port, dst_ip, dst_port, PROTO.TCP, packet)

                    if url is None:
                        url = "%s%s" % (host, path)

                    if config.USE_HEURISTICS:
                        user_agent, result = None, None

                        first_index = tcp_data.find("\r\nUser-Agent:")
                        if first_index >= 0:
                            first_index = first_index + len("\r\nUser-Agent:")
                            last_index = tcp_data.find("\r\n", first_index)
                            if last_index >= 0:
                                user_agent = tcp_data[first_index:last_index]
                                user_agent = _urllib.parse.unquote(user_agent).strip()

                        if user_agent:
                            result = _result_cache.get((CACHE_TYPE.USER_AGENT, user_agent))
                            if result is None:
                                if re.search(WHITELIST_UA_REGEX, user_agent, re.I) is None:
                                    match = re.search(SUSPICIOUS_UA_REGEX, user_agent)
                                    if match and match.group(0):
                                        def _(value):
                                            return value.rstrip('\\').replace('(', "\\(").replace(')', "\\)")

                                        parts = user_agent.split(match.group(0), 1)

                                        if len(parts) > 1 and parts[0] and parts[-1]:
                                            result = _result_cache[(CACHE_TYPE.USER_AGENT, user_agent)] = "%s (%s)" % (_(match.group(0)), _(user_agent))
                                        else:
                                            result = _result_cache[(CACHE_TYPE.USER_AGENT, user_agent)] = _(match.group(0)).join(("(%s)" if part else "%s") % _(part) for part in parts)
                                if not result:
                                    _result_cache[(CACHE_TYPE.USER_AGENT, user_agent)] = False

                            if result:
                                log_event((sec, usec, src_ip, src_port, dst_ip, dst_port, PROTO.TCP, TRAIL.UA, result, "user agent (suspicious)", "(heuristic)"), packet)

                    if not _check_domain_whitelisted(host):
                        path = path.replace("//", '/')

                        unquoted_path = _urllib.parse.unquote(path)
                        unquoted_post_data = _urllib.parse.unquote(post_data or "")

                        checks = [path.rstrip('/')]

                        if '?' in path:
                            checks.append(path.split('?')[0].rstrip('/'))

                            if '=' in path:
                                checks.append(path[:path.index('=') + 1])

                            _ = re.sub(r"(\w+=)[^&=]+", r"\g<1>", path)
                            if _ not in checks:
                                checks.append(_)
                                if _.count('/') > 1:
                                    checks.append("/%s" % _.split('/')[-1])
                        elif post_data:
                            checks.append("%s?%s" % (path, unquoted_post_data.lower()))

                        if checks[-1].count('/') > 1:
                            checks.append(checks[-1][:checks[-1].rfind('/')])
                            checks.append(checks[0][checks[0].rfind('/'):].split('?')[0])

                        for check in filter(None, checks):
                            for _ in ("", host):
                                check = "%s%s" % (_, check)
                                if check in trails:
                                    if '?' not in path and '?' in check and post_data:
                                        trail = "%s(%s \\(%s %s\\))" % (host, path, method, post_data.strip())
                                        log_event((sec, usec, src_ip, src_port, dst_ip, dst_port, PROTO.TCP, TRAIL.HTTP, trail, trails[check][0], trails[check][1]))
                                    else:
                                        parts = url.split(check)
                                        other = ("(%s)" % _ if _ else _ for _ in parts)
                                        trail = check.join(other)
                                        log_event((sec, usec, src_ip, src_port, dst_ip, dst_port, PROTO.TCP, TRAIL.URL, trail, trails[check][0], trails[check][1]))

                                    return

                        if "%s/" % host in trails:
                            trail = "%s/" % host
                            log_event((sec, usec, src_ip, src_port, dst_ip, dst_port, PROTO.TCP, TRAIL.URL, trail, trails[trail][0], trails[trail][1]))
                            return

                        if config.USE_HEURISTICS:
                            match = re.search(r"\b(CF-Connecting-IP|True-Client-IP|X-Forwarded-For):\s*([0-9.]+)".encode(), packet, re.I)
                            if match:
                                forwarded_ip = get_text(match.group(2))
                                src_ip = "%s,%s" % (src_ip, forwarded_ip)

                            for char in SUSPICIOUS_HTTP_REQUEST_FORCE_ENCODE_CHARS:
                                replacement = SUSPICIOUS_HTTP_REQUEST_FORCE_ENCODE_CHARS[char]
                                path = path.replace(char, replacement)
                                if post_data:
                                    post_data = post_data.replace(char, replacement)

                            if not any(_ in unquoted_path.lower() for _ in WHITELIST_HTTP_REQUEST_PATHS):
                                if any(_ in unquoted_path for _ in SUSPICIOUS_HTTP_REQUEST_PRE_CONDITION):
                                    found = _result_cache.get((CACHE_TYPE.PATH, unquoted_path))
                                    if found is None:
                                        for desc, regex in SUSPICIOUS_HTTP_REQUEST_REGEXES:
                                            if re.search(regex, unquoted_path, re.I | re.DOTALL):
                                                found = desc
                                                break
                                        _result_cache[(CACHE_TYPE.PATH, unquoted_path)] = found or ""
                                    if found and not ("data leakage" in found and is_local(dst_ip)):
                                        trail = "%s(%s)" % (host, path)
                                        log_event((sec, usec, src_ip, src_port, dst_ip, dst_port, PROTO.TCP, TRAIL.URL, trail, "%s (suspicious)" % found, "(heuristic)"), packet)
                                        return

                                if any(_ in unquoted_post_data for _ in SUSPICIOUS_HTTP_REQUEST_PRE_CONDITION):
                                    found = _result_cache.get((CACHE_TYPE.POST_DATA, unquoted_post_data))
                                    if found is None:
                                        for desc, regex in SUSPICIOUS_HTTP_REQUEST_REGEXES:
                                            if re.search(regex, unquoted_post_data, re.I | re.DOTALL):
                                                found = desc
                                                break
                                        _result_cache[(CACHE_TYPE.POST_DATA, unquoted_post_data)] = found or ""
                                    if found:
                                        trail = "%s(%s \\(%s %s\\))" % (host, path, method, post_data.strip())
                                        log_event((sec, usec, src_ip, src_port, dst_ip, dst_port, PROTO.TCP, TRAIL.HTTP, trail, "%s (suspicious)" % found, "(heuristic)"), packet)
                                        return

                            if '.' in path:
                                _ = _urllib.parse.urlparse("http://%s" % url)  # dummy scheme
                                path = path.lower()
                                filename = _.path.split('/')[-1]
                                name, extension = os.path.splitext(filename)
                                trail = "%s(%s)" % (host, path)
                                if extension in SUSPICIOUS_DIRECT_DOWNLOAD_EXTENSIONS and not is_local(dst_ip) and not any(_ in path for _ in WHITELIST_DIRECT_DOWNLOAD_KEYWORDS) and '=' not in _.query and len(name) < 10:
                                    log_event((sec, usec, src_ip, src_port, dst_ip, dst_port, PROTO.TCP, TRAIL.URL, trail, "direct %s download (suspicious)" % extension, "(heuristic)"), packet)
                                else:
                                    for desc, regex in SUSPICIOUS_HTTP_PATH_REGEXES:
                                        if re.search(regex, filename, re.I):
                                            log_event((sec, usec, src_ip, src_port, dst_ip, dst_port, PROTO.TCP, TRAIL.URL, trail, "%s (suspicious)" % desc, "(heuristic)"), packet)
                                            break

        elif protocol == socket.IPPROTO_UDP:  # UDP
            _ = ip_data[iph_length:iph_length + 4]
            if len(_) < 4:
                return

            src_port, dst_port = struct.unpack("!HH", _)

            _ = _last_udp
            _last_udp = (sec, src_ip, src_port, dst_ip, dst_port)
            if _ == _last_udp:  # skip bursts
                return

            if src_port != 53 and dst_port != 53:  # not DNS
                if dst_ip in trails:
                    trail = dst_ip
                elif src_ip in trails:
                    trail = src_ip
                else:
                    trail = None

                if trail:
                    _ = _last_logged_udp
                    _last_logged_udp = _last_udp
                    if _ != _last_logged_udp:
                        if not any(_ in trails[trail][0] for _ in ("malware",)):
                            log_event((sec, usec, src_ip, src_port, dst_ip, dst_port, PROTO.UDP, TRAIL.IP, trail, trails[trail][0], trails[trail][1]), packet)

                # UDP scan coverage (nmap -sU): one src hitting many distinct UDP ports on one host.
                # The TCP scan heuristics never saw this. Benign UDP rarely fans many ports at one
                # host (a client uses ~1 port per service; QUIC/DNS/mDNS are single-port), so distinct
                # UDP dst-port count is a reasonable signal. Sliding-window + bounded like the rest.
                if config.USE_HEURISTICS and dst_ip != localhost_ip:
                    if getattr(_locks, "heuristics", None):
                        _locks.heuristics.acquire()
                    try:
                        _scan_track(_udp_scan, _udp_scan_details, (src_ip, dst_ip), dst_port, (sec, usec, src_port, dst_port))
                    finally:
                        if getattr(_locks, "heuristics", None):
                            _locks.heuristics.release()

            else:
                dns_data = ip_data[iph_length + 8:]

                # Reference: http://www.ccs.neu.edu/home/amislove/teaching/cs4700/fall09/handouts/project1-primer.pdf
                if len(dns_data) > 6:
                    qdcount = struct.unpack("!H", dns_data[4:6])[0]
                    if qdcount > 0:
                        offset = 12
                        query = ""

                        while len(dns_data) > offset:
                            length = ord(dns_data[offset:offset + 1])
                            if not length:
                                query = query[:-1]
                                break
                            query += get_text(dns_data[offset + 1:offset + length + 1]) + '.'
                            offset += length + 1

                        query = query.lower()
                        parts = query.split('.')  # NOTE: computed once (was split twice per DNS query: guard + below)

                        if not query or _valid_dns_name_regex.search(query) is None or any(_ in query for _ in (".intranet.",)) or parts[-1] in IGNORE_DNS_QUERY_SUFFIXES:
                            return

                        if ord(dns_data[2:3]) & 0xfa == 0x00:  # standard query (both recursive and non-recursive)
                            type_, class_ = struct.unpack("!HH", dns_data[offset + 1:offset + 5])

                            if len(parts) > 2:
                                if len(parts) > 3 and len(parts[-2]) <= 3:
                                    domain = '.'.join(parts[-3:])
                                else:
                                    domain = '.'.join(parts[-2:])

                                if not _check_domain_whitelisted(domain):  # e.g. <hash>.hashserver.cs.trendmicro.com
                                    if (sec - (_subdomains_sec or 0)) > HOURLY_SECS:
                                        _subdomains.clear()
                                        _dns_exhausted_domains.clear()
                                        _subdomains_sec = sec

                                    if domain not in _subdomains:  # NOTE: membership test, not truthiness; an existing-but-empty set (just cleared at the 60s boundary) must keep its window _start, else the exhaustion window keeps resetting and detection is evaded
                                        subdomains = _subdomains[domain] = _set()
                                        subdomains._start = sec
                                    else:
                                        subdomains = _subdomains[domain]

                                    if not re.search(r"\A\d+\-\d+\-\d+\-\d+\Z", parts[0]):
                                        if sec - subdomains._start > 60:
                                            subdomains._start = sec
                                            subdomains.clear()
                                        elif len(subdomains) < DNS_EXHAUSTION_THRESHOLD:
                                            subdomains.add('.'.join(parts[:-2]))
                                        elif domain not in _dns_exhausted_domains:   # alert ONCE per domain per window; otherwise EVERY subdomain query past the threshold re-logs -> a self-inflicted log flood during the very attack this detects (the set was populated at 767 but never checked here)
                                            trail = "(%s).%s" % ('.'.join(parts[:-2]), '.'.join(parts[-2:]))
                                            if re.search(r"bl\b", trail) is None:                                               # generic check for DNSBLs
                                                if not any(_ in subdomains for _ in LOCAL_SUBDOMAIN_LOOKUPS) and _heuristic_enabled("dns_exhaustion"):   # generic check for local DNS resolutions
                                                    log_event((sec, usec, src_ip, src_port, dst_ip, dst_port, PROTO.UDP, TRAIL.DNS, trail, "potential dns exhaustion (suspicious)", "(heuristic)"), packet)
                                                    _dns_exhausted_domains.add(domain)

                                            return
                                        else:
                                            return   # already alerted this domain this window -> suppress repeat logs

                            # Reference: http://en.wikipedia.org/wiki/List_of_DNS_record_types
                            if type_ not in (12, 28) and class_ == 1:  # Type not in (PTR, AAAA), Class IN
                                if addr_port(dst_ip, dst_port) in trails:
                                    trail = addr_port(dst_ip, dst_port)
                                    log_event((sec, usec, src_ip, src_port, dst_ip, dst_port, PROTO.UDP, TRAIL.IPORT, "%s (%s)" % (dst_ip, query), trails[trail][0], trails[trail][1]), packet)
                                elif dst_ip in trails:
                                    log_event((sec, usec, src_ip, src_port, dst_ip, dst_port, PROTO.UDP, TRAIL.IP, "%s (%s)" % (dst_ip, query), trails[dst_ip][0], trails[dst_ip][1]), packet)
                                elif src_ip in trails:
                                    log_event((sec, usec, src_ip, src_port, dst_ip, dst_port, PROTO.UDP, TRAIL.IP, src_ip, trails[src_ip][0], trails[src_ip][1]), packet)

                                _check_domain(query, sec, usec, src_ip, src_port, dst_ip, dst_port, PROTO.UDP, packet)

                        elif config.USE_HEURISTICS:
                            if ord(dns_data[2:3]) & 0x80:  # standard response
                                if ord(dns_data[3:4]) == 0x80:  # recursion available, no error
                                    _ = offset + 5
                                    try:
                                        ptr = _   # NOTE: define ptr up-front - a response with an empty/truncated answer section (offset+5 >= len) skips the loop below, and the later dns_data[ptr+10:...] read would raise UnboundLocalError (NOT caught by the IndexError handler -> surfaces as an "unhandled exception")

                                        while _ < len(dns_data):
                                            ptr = _
                                            while ptr < len(dns_data):
                                                lbl_len = ord(dns_data[ptr:ptr+1])
                                                if lbl_len & 0xc0: # Compressed pointer
                                                    ptr += 2
                                                    break
                                                if lbl_len == 0: # End of labels
                                                    ptr += 1
                                                    break
                                                ptr += lbl_len + 1

                                            # check if we have enough data for Type(2)+Class(2)+TTL(4)+RdLen(2) = 10 bytes
                                            if ptr + 10 > len(dns_data):
                                                break

                                            # check for Type A (0x0001)
                                            if dns_data[ptr:ptr+2] == b"\x00\x01":
                                                # found the record, _ is pointing to start of Name.
                                                break
                                            else:
                                                # skip this record
                                                rd_len = struct.unpack("!H", dns_data[ptr + 8: ptr + 10])[0]
                                                _ = ptr + 10 + rd_len

                                        _ = dns_data[ptr + 10:ptr + 14]   # A RDATA = name-end(ptr) + type(2)+class(2)+ttl(4)+rdlen(2); was `_+12`, which only held when the answer name was a 2-byte compression pointer and mis-read uncompressed answer names (-> missed sinkhole/parking detection / evasion)
                                        if len(_) == 4:
                                            answer = socket.inet_ntoa(_)
                                            if answer in trails and not _check_domain_whitelisted(query):
                                                _ = trails[answer]
                                                if "sinkhole" in _[0]:
                                                    trail = "(%s).%s" % ('.'.join(parts[:-1]), '.'.join(parts[-1:]))
                                                    log_event((sec, usec, src_ip, src_port, dst_ip, dst_port, PROTO.UDP, TRAIL.DNS, trail, "sinkholed by %s (malware)" % _[0].split(" ")[1], "(heuristic)"), packet)  # (e.g. kitro.pl, devomchart.com, jebena.ananikolic.su, vuvet.cn)
                                                elif "parking" in _[0]:
                                                    trail = "(%s).%s" % ('.'.join(parts[:-1]), '.'.join(parts[-1:]))
                                                    log_event((sec, usec, src_ip, src_port, dst_ip, dst_port, PROTO.UDP, TRAIL.DNS, trail, "parked site (suspicious)", "(heuristic)"), packet)
                                    except IndexError:
                                        pass

                                elif ord(dns_data[3:4]) == 0x83:  # recursion available, no such name
                                    if '.'.join(parts[-2:]) not in _dns_exhausted_domains and not _check_domain_whitelisted(query) and not _check_domain_member(query, trails):
                                        if parts[-1].isdigit():
                                            return

                                        if not (len(parts) > 4 and all(_.isdigit() and int(_) < 256 for _ in parts[:4])):  # generic check for DNSBL IP lookups
                                            if not is_local(dst_ip):  # prevent FPs caused by local queries
                                                # prune stale (previous-hour) entries once per hour: keys are hour-bucketed but were never
                                                # dropped when unseen in a later hour, so DGA/scan traffic (many unique NXDOMAINs) grew the
                                                # per-worker dict without bound (slow OOM on long-running sensors)
                                                _cur_hour = sec // 3600
                                                if _no_such_name_hour != _cur_hour:
                                                    _no_such_name_hour = _cur_hour
                                                    for _stale in [_k for _k in NO_SUCH_NAME_COUNTERS if NO_SUCH_NAME_COUNTERS[_k][0] != _cur_hour]:
                                                        del NO_SUCH_NAME_COUNTERS[_stale]

                                                for _ in filter(None, (query, "*.%s" % '.'.join(parts[-2:]) if query.count('.') > 1 else None)):
                                                    if _ not in NO_SUCH_NAME_COUNTERS or NO_SUCH_NAME_COUNTERS[_][0] != sec // 3600:
                                                        NO_SUCH_NAME_COUNTERS[_] = [sec // 3600, 1, set()]
                                                    else:
                                                        NO_SUCH_NAME_COUNTERS[_][1] += 1
                                                        NO_SUCH_NAME_COUNTERS[_][2].add(query)

                                                        if NO_SUCH_NAME_COUNTERS[_][1] > NO_SUCH_NAME_PER_HOUR_THRESHOLD:
                                                            if _.startswith("*."):
                                                                trail = "%s%s" % ("(%s)" % ','.join(item.replace(_[1:], "") for item in NO_SUCH_NAME_COUNTERS[_][2]), _[1:])
                                                                if not any(subdomain in trail for subdomain in LOCAL_SUBDOMAIN_LOOKUPS):  # generic check for local DNS resolutions
                                                                    log_event((sec, usec, src_ip, src_port, dst_ip, dst_port, PROTO.UDP, TRAIL.DNS, trail, "excessive no such domain (suspicious)", "(heuristic)"), packet)
                                                                for item in NO_SUCH_NAME_COUNTERS[_][2]:
                                                                    try:
                                                                        del NO_SUCH_NAME_COUNTERS[item]
                                                                    except KeyError:
                                                                        pass
                                                            else:
                                                                log_event((sec, usec, src_ip, src_port, dst_ip, dst_port, PROTO.UDP, TRAIL.DNS, _, "excessive no such domain (suspicious)", "(heuristic)"), packet)

                                                            try:
                                                                del NO_SUCH_NAME_COUNTERS[_]
                                                            except KeyError:
                                                                pass

                                                            break

                                            if len(parts) == 2 and parts[0] and '-' not in parts[0]:
                                                part = parts[0]
                                                trail = "(%s).%s" % (parts[0], parts[1])

                                                result = _result_cache.get(part)

                                                if result is None:
                                                    # Reference: https://github.com/exp0se/dga_detector
                                                    probabilities = (float(part.count(c)) / len(part) for c in set(_ for _ in part))
                                                    entropy = -sum(p * math.log(p) / math.log(2.0) for p in probabilities)
                                                    if entropy > SUSPICIOUS_DOMAIN_ENTROPY_THRESHOLD:
                                                        result = "entropy threshold no such domain (suspicious)"

                                                    if not result:
                                                        if sum(_ in CONSONANTS for _ in part) > SUSPICIOUS_DOMAIN_CONSONANT_THRESHOLD:
                                                            result = "consonant threshold no such domain (suspicious)"

                                                    _result_cache[part] = result or False

                                                if result:
                                                    log_event((sec, usec, src_ip, src_port, dst_ip, dst_port, PROTO.UDP, TRAIL.DNS, trail, result, "(heuristic)"), packet)

        elif protocol in IPPROTO_LUT:  # non-TCP/UDP (e.g. ICMP)
            if config.USE_HEURISTICS:
                icmp_offset = ip_offset + iph_length
                if protocol == socket.IPPROTO_ICMP:
                    treatable_packet = is_icmpv4_packet(packet, icmp_offset)
                    treat_icmp4_packet(packet, icmp_offset, dst_ip, ip_offset, src_ip)

                    exfiltration, destination = detect_icmpv4_exfiltration_by_destination(dst_ip)
                    if exfiltration and treatable_packet:
                        log_event((sec, usec, destination.get_largest_src_ip(), '-', dst_ip, '-', PROTO.ICMP, TRAIL.ICMP, '-', "ICMPv4 exfiltration by anomalous traffic to destination (suspicious)", "(heuristic)"), packet)
                    
                    exfiltration, src_ip = detect_icmpv4_exfiltration_by_src_dst_ips(src_ip, dst_ip)
                    if exfiltration and treatable_packet:
                        log_event((sec, usec, src_ip, '-', dst_ip, '-', PROTO.ICMP, TRAIL.ICMP, '-', "ICMPv4 exfiltration by src/dst ips pair (suspicious)", "(heuristic)"), packet)
                    
                    exfiltration = detect_icmpv4_exfiltration_by_multiple_sources_to_destination(dst_ip)
                    if exfiltration and treatable_packet:
                        log_event((sec, usec, src_ip, '-', dst_ip, '-', PROTO.ICMP, TRAIL.ICMP, '-', "ICMPv4 exfiltration by multiple sources to destination (suspicious)", "(heuristic)"), packet)
                    
                    if detect_icmpv4_large_package_size(packet, ip_data, dst_ip, iph_length) and treatable_packet:
                        log_event((sec, usec, src_ip, '-', dst_ip, '-', PROTO.ICMP, TRAIL.ICMP, '-', "ICMPv4 large package size (suspicious)", "(heuristic)"), packet)
        
                elif protocol == socket.IPPROTO_ICMPV6:
                    treatable_packet = is_icmpv6_packet(packet, icmp_offset)
                    treat_icmp6_packet(packet, icmp_offset, dst_ip, ip_offset, src_ip)
                    
                    exfiltration, destination = detect_icmpv6_exfiltration_by_destination(dst_ip)
                    if exfiltration and treatable_packet:
                        log_event((sec, usec, src_ip, '-', dst_ip, '-', PROTO.ICMP, TRAIL.ICMP, '-', "ICMPv6 exfiltration by anomalous traffic to destination (suspicious)", "(heuristic)"), packet)
                    
                    exfiltration, src_ip = detect_icmpv6_exfiltration_by_src_dst_ips(src_ip, dst_ip)
                    if exfiltration and treatable_packet:
                        log_event((sec, usec, src_ip, '-', dst_ip, '-', PROTO.ICMP, TRAIL.ICMP, '-', "ICMPv6 exfiltration by src/dst ips pair (suspicious)", "(heuristic)"), packet)
                    
                    if detect_icmpv6_exfiltration_by_multiple_sources_to_destination(dst_ip) and treatable_packet:
                        log_event((sec, usec, src_ip, '-', dst_ip, '-', PROTO.ICMP, TRAIL.ICMP, '-', "ICMPv6 exfiltration by multiple sources to destination (suspicious)", "(heuristic)"), packet)
                    
                    if detect_icmpv6_large_package_size(packet, ip_data, dst_ip, icmp_offset) and treatable_packet:
                        log_event((sec, usec, src_ip, '-', dst_ip, '-', PROTO.ICMP, TRAIL.ICMP, '-', "ICMPv6 large package size (suspicious)", "(heuristic)"), packet)

            if dst_ip in trails:
                log_event((sec, usec, src_ip, '-', dst_ip, '-', IPPROTO_LUT[protocol], TRAIL.IP, dst_ip, trails[dst_ip][0], trails[dst_ip][1]), packet)
            elif src_ip in trails:
                log_event((sec, usec, src_ip, '-', dst_ip, '-', IPPROTO_LUT[protocol], TRAIL.IP, src_ip, trails[src_ip][0], trails[src_ip][1]), packet)

    except struct.error:
        pass  # truncated/garbage packet headers are expected and high-volume

    except Exception:
        # NOTE: never let a packet-processing bug fail SILENTLY - an IDS that quietly stops detecting a whole traffic
        # class looks perfectly healthy while it's blind. Surface it (single=True dedups identical tracebacks, so a
        # recurring bug can't flood the error log) instead of only printing under SHOW_DEBUG.
        log_error("unhandled exception in _process_packet:\n%s" % traceback.format_exc(), single=True)
        if config.SHOW_DEBUG:
            traceback.print_exc()

def is_icmpv6_packet(packet, iph_length):
    return ord(packet[iph_length:iph_length + 1]) == 0x80 or ord(packet[iph_length:iph_length + 1]) == 0x81

def is_icmpv4_packet(packet, iph_length):
    return ord(packet[iph_length:iph_length + 1]) == 0x08 or ord(packet[iph_length:iph_length + 1]) == 0x00

def treat_icmp6_packet(packet, icmp_offset, dst_ip, ip_offset, src_ip):
    global _icmp6_exfiltration_baseline
    global _icmp6_exfiltration_baseline_startup_time
    global _last_icmp6_destinations
    global _last_icmp6_order

    if dst_ip in _last_icmp6_destinations:
        destination = _last_icmp6_destinations[dst_ip]

        destination.package_size_accumulator += len(packet[icmp_offset+8:len(packet) + 1])
        destination.add_src_ip(src_ip)
        destination.update_last_seen(time.time())

        # Move last destination IP to the end of the line
        _last_icmp6_order.remove(dst_ip)
        _last_icmp6_order.append(dst_ip)
        
        if (time.time() - _icmp6_exfiltration_baseline_startup_time) > config.ICMP_DESTINATION_TRAFFIC_AUTO_DETECT_BASELINE_WINDOW and _icmp6_exfiltration_baseline == 0:
            if config.ICMP_DESTINATION_TRAFFIC_AUTO_DETECT_BASELINE:
                if (len(_last_icmp6_destinations.values()) == 0):
                    return False
                sumOfCalls = 0
                for dest in _last_icmp6_destinations.values():
                    _icmp6_exfiltration_baseline += dest.get_average_traffic()*dest.count
                    sumOfCalls += dest.count
                _icmp6_exfiltration_baseline /= sumOfCalls
                if _icmp6_exfiltration_baseline != 0:
                    print("[i] ICMPv6 exfiltration baseline: %s" % _icmp6_exfiltration_baseline)
            
    else:
        icmp_destination = IcmpDestination(dst_ip, len(packet[icmp_offset:len(packet) + 1]), time.time(), time.time())
        icmp_destination.add_src_ip(src_ip)
        _last_icmp6_destinations[dst_ip] = icmp_destination
        _last_icmp6_order.append(dst_ip)

        if len(_last_icmp6_destinations) > config.ICMP_DESTINATION_HISTORY_MAX_SIZE:
            oldest_ip = _last_icmp6_order.popleft()

            if oldest_ip in _last_icmp6_destinations:
                del _last_icmp6_destinations[oldest_ip]

def detect_icmpv6_exfiltration_by_multiple_sources_to_destination(dst_ip):
    global _last_icmp6_destinations
    destination = _last_icmp6_destinations[dst_ip]

    count = 0
    for src_ip in destination.src_ips:
        if destination.get_src_ip_average_traffic(src_ip) > _icmp6_exfiltration_baseline + config.ICMP_DESTINATION_TRAFFIC_AUTO_DETECT_BASELINE_TOLERANCE:
            count += 1
        if destination.get_src_ip_average_traffic(src_ip) > config.ICMP_DESTINATION_AVERAGE_EXFILTRATION_DETECTION_THRESHOLD:
            count += 1
    if count > 2:
        return True
    return False

def detect_icmpv6_exfiltration_by_destination(dst_ip):
    global _last_icmp6_destinations
    destination = _last_icmp6_destinations[dst_ip]

    if destination.get_average_traffic() > _icmp6_exfiltration_baseline + config.ICMP_DESTINATION_TRAFFIC_AUTO_DETECT_BASELINE_TOLERANCE:
        return True, destination
    if destination.get_average_traffic() > config.ICMP_DESTINATION_AVERAGE_EXFILTRATION_DETECTION_THRESHOLD:
        return True, destination

    return False, None

#detects exfiltration by src ips to destination - matches src/dst ips as a pair
def detect_icmpv6_exfiltration_by_src_dst_ips(src_ip, dst_ip):
    global _last_icmp6_destinations
    destination = _last_icmp6_destinations[dst_ip]

    if destination.get_src_ip_average_traffic(src_ip) > _icmp6_exfiltration_baseline + config.ICMP_SRC_DEST_PAIR_EXFILTRATION_DETECTION_TOLERANCE:
        return True, src_ip

    if destination.get_src_ip_average_traffic(src_ip) > config.ICMP_DESTINATION_AVERAGE_EXFILTRATION_DETECTION_THRESHOLD:
        return True, src_ip
    return False, None

def detect_icmpv6_large_package_size(packet, ip_data, dst_ip, icmp_offset):
    global _icmp6_large_payload_size_treshold
    global _icmp6_large_package_size_startup_time
    global _icmp6_exfiltration_baseline_startup_time

    if config.ICMP_AUTO_DETECT_LARGE_PACKAGE_SIZE and len(_last_icmp6_destinations.values()) != 0:
        if (time.time() - _icmp6_large_package_size_startup_time) > config.ICMP_DESTINATION_TRAFFIC_AUTO_DETECT_BASELINE_WINDOW and _icmp6_large_payload_size_treshold == 0:
            packets = 0
            for destination in _last_icmp6_destinations.values():
                _icmp6_large_payload_size_treshold += destination.package_size_accumulator
                packets += destination.count
            if packets == 0 or _icmp6_large_payload_size_treshold == 0:
                _icmp6_large_payload_size_treshold = 0
                return False
            _icmp6_large_payload_size_treshold /= packets
            print("[i] ICMPv6 large payload size threshold: %s" % _icmp6_large_payload_size_treshold)
        
        if _icmp6_large_payload_size_treshold != 0 and len(packet[icmp_offset+4:len(packet) + 1]) > _icmp6_large_payload_size_treshold + config.ICMP_LARGE_PACKAGE_SIZE_TOLERANCE:
            return True

    if config.ICMP_LARGE_PACKAGE_ABSOLUTE_THRESHOLD < len(packet[icmp_offset+4:len(packet) + 1]):
        return True
    return False

def treat_icmp4_packet(packet, icmp_offset, dst_ip, ip_offset, src_ip):
    global _icmp4_exfiltration_baseline
    global _icmp4_exfiltration_baseline_startup_time
    global _last_icmp4_destinations
    global _last_icmp4_order

    if dst_ip in _last_icmp4_destinations:
        destination = _last_icmp4_destinations[dst_ip]
        destination.package_size_accumulator += len(packet[icmp_offset+8:len(packet) + 1])
        destination.add_src_ip(src_ip)
        destination.update_last_seen(time.time())

        # Move last destination IP to the end of the line
        _last_icmp4_order.remove(dst_ip)
        _last_icmp4_order.append(dst_ip)
        
        if config.ICMP_DESTINATION_TRAFFIC_AUTO_DETECT_BASELINE and (time.time() - _icmp4_exfiltration_baseline_startup_time) > config.ICMP_DESTINATION_TRAFFIC_AUTO_DETECT_BASELINE_WINDOW:
            if _icmp4_exfiltration_baseline == 0 and len(_last_icmp4_destinations.values()) != 0:
                if (len(_last_icmp4_destinations.values()) == 0):
                    return
                sumOfCalls = 0
                for dest in _last_icmp4_destinations.values():
                    _icmp4_exfiltration_baseline += dest.get_average_traffic()*dest.count
                    sumOfCalls += dest.count
                _icmp4_exfiltration_baseline /= sumOfCalls
                if _icmp4_exfiltration_baseline != 0:
                    print("[i] ICMPv4 exfiltration baseline: %s" % _icmp4_exfiltration_baseline)

    else:
        icmp_destination = IcmpDestination(dst_ip, len(packet[icmp_offset:len(packet) + 1]), time.time(), time.time())
        icmp_destination.add_src_ip(src_ip)
        _last_icmp4_destinations[dst_ip] = icmp_destination
        _last_icmp4_order.append(dst_ip)

        if len(_last_icmp4_destinations.values()) > config.ICMP_DESTINATION_HISTORY_MAX_SIZE:
            oldest_ip = _last_icmp4_order.popleft()

            if oldest_ip in _last_icmp4_destinations:
                del _last_icmp4_destinations[oldest_ip]

def detect_icmpv4_exfiltration_by_multiple_sources_to_destination(dst_ip):
    global _last_icmp4_destinations
    destination = _last_icmp4_destinations[dst_ip]

    count = 0
    for src_ip in destination.src_ips:
        if destination.get_src_ip_average_traffic(src_ip) > _icmp4_exfiltration_baseline + config.ICMP_DESTINATION_TRAFFIC_AUTO_DETECT_BASELINE_TOLERANCE:
            count += 1
        if destination.get_src_ip_average_traffic(src_ip) > config.ICMP_DESTINATION_AVERAGE_EXFILTRATION_DETECTION_THRESHOLD:
            count += 1
    if count > 2:
        return True
    return False   

def detect_icmpv4_exfiltration_by_destination(dst_ip):
    global _last_icmp4_destinations
    destination = _last_icmp4_destinations[dst_ip]

    if destination.get_average_traffic() > _icmp4_exfiltration_baseline + config.ICMP_DESTINATION_TRAFFIC_AUTO_DETECT_BASELINE_TOLERANCE:
        return True, destination
    if destination.get_average_traffic() > config.ICMP_DESTINATION_AVERAGE_EXFILTRATION_DETECTION_THRESHOLD:
        return True, destination
    return False, None

#detects exfiltration by src ips to destination - matches src/dst ips as a pair
def detect_icmpv4_exfiltration_by_src_dst_ips(src_ip, dst_ip):
    global _last_icmp4_destinations
    destination = _last_icmp4_destinations[dst_ip]

    if destination.get_src_ip_average_traffic(src_ip) > _icmp4_exfiltration_baseline + config.ICMP_SRC_DEST_PAIR_EXFILTRATION_DETECTION_TOLERANCE:
        return True, src_ip

    if destination.get_src_ip_average_traffic(src_ip) > config.ICMP_DESTINATION_AVERAGE_EXFILTRATION_DETECTION_THRESHOLD:
        return True, src_ip
    return False, None

def detect_icmpv4_large_package_size(packet, ip_data, dst_ip, icmp_offset):
    global _icmp4_large_payload_size_treshold
    global _icmp4_large_package_size_startup_time
    global _icmp4_exfiltration_baseline_startup_time

    if config.ICMP_AUTO_DETECT_LARGE_PACKAGE_SIZE and len(_last_icmp4_destinations.values()) != 0:
        if (time.time() - _icmp4_large_package_size_startup_time) > config.ICMP_DESTINATION_TRAFFIC_AUTO_DETECT_BASELINE_WINDOW and _icmp4_large_payload_size_treshold == 0:
            packets = 0
            for destination in _last_icmp4_destinations.values():
                _icmp4_large_payload_size_treshold += destination.package_size_accumulator
                packets += destination.count
            if packets == 0:
                _icmp4_large_payload_size_treshold = 0
                return False
            _icmp4_large_payload_size_treshold /= packets
            print("[i] ICMPv4 large payload size threshold: %s" % _icmp4_large_payload_size_treshold)
        
        if _icmp4_large_payload_size_treshold != 0 and len(packet[icmp_offset+8:len(packet) + 1]) > _icmp4_large_payload_size_treshold + config.ICMP_LARGE_PACKAGE_SIZE_TOLERANCE:
            return True

    if config.ICMP_LARGE_PACKAGE_ABSOLUTE_THRESHOLD < len(packet[icmp_offset+8:len(packet) + 1]):
        return True
    return False

def init():
    """
    Performs sensor initialization
    """

    global _multiprocessing

    try:
        import multiprocessing

        if config.PROCESS_COUNT > 1 and not config.profile:
            _multiprocessing = multiprocessing
    except (ImportError, OSError, NotImplementedError):
        pass

    def update_timer():
        retries = 0
        if not config.offline:
            while retries < CHECK_CONNECTION_MAX_RETRIES and not check_connection():
                sys.stdout.write("[!] can't update because of lack of Internet connection (waiting..." if not retries else '.')
                sys.stdout.flush()
                time.sleep(10)
                retries += 1

            if retries:
                print(")")

        if config.offline or retries == CHECK_CONNECTION_MAX_RETRIES:
            if retries == CHECK_CONNECTION_MAX_RETRIES:
                print("[x] going to continue without online update")
            _ = update_trails(offline=True)
        else:
            _ = update_trails()
            update_ipcat()

        if USE_MMAP_TRAILS:
            # the trail set (just refreshed into the CSV by update_trails) is built once into a shared, memory-mapped
            # binary store; this process maps it and every worker process forked afterwards shares that one mapping
            # instead of carrying its own ~150 MB heap copy
            trails.adopt(load_trails_mmap(quiet=True))
        else:
            if _:
                trails.adopt(_)  # atomic swap (was clear()+update(), which exposed the hot path to an empty/half-built table)
            elif not trails:
                trails.adopt(load_trails())

            build_trails_regex(trails)
            trails.finalize()   # compact the resident set to the hash-array form (read-only hot path); drops key strings

        thread = threading.Timer(config.UPDATE_PERIOD, update_timer)
        thread.daemon = True
        thread.start()

    create_log_directory()
    get_error_log_handle()

    msg = "[i] using '%s' for trail storage" % config.TRAILS_FILE
    if os.path.isfile(config.TRAILS_FILE):
        mtime = time.gmtime(os.path.getmtime(config.TRAILS_FILE))
        msg += " (last modification: '%s')" % time.strftime(HTTP_TIME_FORMAT, mtime)

    print(msg)

    update_timer()

    if not config.DISABLE_CHECK_SUDO and check_sudo() is False:
        sys.exit("[!] please run '%s' with root privileges" % __file__)

    if config.plugins:
        config.plugin_functions = []
        for plugin in re.split(r"[,;]", config.plugins):
            plugin = plugin.strip()
            found = False

            for _ in (plugin, os.path.join("plugins", plugin), os.path.join("plugins", "%s.py" % plugin)):
                if os.path.isfile(_):
                    plugin = _
                    found = True
                    break

            if not found:
                sys.exit("[!] plugin script '%s' not found" % plugin)
            else:
                dirname, filename = os.path.split(plugin)
                dirname = os.path.abspath(dirname)
                if not os.path.exists(os.path.join(dirname, '__init__.py')):
                    sys.exit("[!] empty file '__init__.py' required inside directory '%s'" % dirname)

                if not filename.endswith(".py"):
                    sys.exit("[!] plugin script '%s' should have an extension '.py'" % filename)

                if dirname not in sys.path:
                    sys.path.insert(0, dirname)

                try:
                    module = __import__(filename[:-3])
                except (ImportError, SyntaxError) as msg:
                    sys.exit("[!] unable to import plugin script '%s' (%s)" % (filename, msg))

                found = False
                for name, function in inspect.getmembers(module, inspect.isfunction):
                    try:
                        args = inspect.getfullargspec(function).args
                    except AttributeError:
                        args = inspect.getargspec(function).args

                    if name == "plugin" and set(("event_tuple", "packet")).issubset(set(args)):
                        found = True
                        config.plugin_functions.append(function)
                        function.__name__ = module.__name__

                if not found:
                    sys.exit("[!] missing function 'plugin(event_tuple, packet)' in plugin script '%s'" % filename)

    if config.pcap_file:
        for _ in config.pcap_file.split(','):
            _caps.append(pcapy.open_offline(_))
    else:
        interfaces = set(_.strip() for _ in config.MONITOR_INTERFACE.split(','))

        try:
            devices = pcapy.findalldevs()
        except Exception:
            devices = []

        if (config.MONITOR_INTERFACE or "").lower() == "any":
            if devices and (IS_WIN or "any" not in devices):
                print("[x] virtual interface 'any' missing. Replacing it with all interface names")
                interfaces = devices
            else:
                print("[?] in case of any problems with packet capture on virtual interface 'any', please put all monitoring interfaces to promiscuous mode manually (e.g. 'sudo ifconfig eth0 promisc')")

        fanout_n = 0 if IS_WIN else _fanout_count()

        for interface_idx, interface in enumerate(interfaces):
            if interface.lower() != "any" and devices and re.sub(r"(?i)\Anetmap:", "", interface) not in devices:
                hint = "[?] available interfaces: '%s'" % ",".join(devices)
                sys.exit("[!] interface '%s' not found\n%s" % (interface, hint))

            print("[i] opening interface '%s'" % interface)
            try:
                if fanout_n:
                    # PACKET_FANOUT: open N sockets on this interface, all joined to one kernel
                    # fanout group (unique per interface + per process), so the kernel flow-hashes
                    # the interface's traffic across N capture threads. Each flow stays on a single
                    # socket (HASH), so no packet is captured twice. Falls back to one socket if the
                    # installed pcapy/kernel lacks PACKET_FANOUT (opening N plain sockets would
                    # otherwise DUPLICATE every packet across them).
                    group = (os.getpid() + interface_idx) & 0xffff
                    joined, fanout_err = [], None
                    for _ in xrange(fanout_n):
                        _cap = pcapy.open_live(interface, SNAP_LEN, True, CAPTURE_TIMEOUT)
                        try:
                            _cap.set_fanout(group, getattr(pcapy, "PACKET_FANOUT_HASH", 0))
                        except Exception as ex:
                            fanout_err = ex
                            try: _cap.close()
                            except Exception: pass
                            break
                        joined.append(_cap)
                    if joined:
                        print("[i] CAPTURE_FANOUT active: %d kernel-balanced capture socket(s) on '%s' (PACKET_FANOUT group %d)" % (len(joined), interface, group))
                        _caps.extend(joined)
                    else:
                        # visible on the operational console (NOT just the error log) - a requested
                        # knob that silently no-ops is exactly the misconfig the operator must see.
                        print("[!] CAPTURE_FANOUT requested but PACKET_FANOUT is unavailable (%s); using a SINGLE capture socket on '%s' (need Linux + pcapy-ng >= 2.0 with set_fanout)" % (fanout_err, interface))
                        log_error("CAPTURE_FANOUT is set but PACKET_FANOUT is unavailable (%s); "
                                  "using a single capture socket on '%s'" % (fanout_err, interface), single=True)
                        _caps.append(pcapy.open_live(interface, SNAP_LEN, True, CAPTURE_TIMEOUT))
                else:
                    _caps.append(pcapy.open_live(interface, SNAP_LEN, True, CAPTURE_TIMEOUT))
            except (socket.error, pcapy.PcapError):
                if "permitted" in str(sys.exc_info()[1]):
                    sys.exit("[!] permission problem occurred ('%s')" % sys.exc_info()[1])
                elif "No such device" in str(sys.exc_info()[1]):
                    sys.exit("[!] no such device '%s'" % interface)
                else:
                    raise

    if config.LOG_SERVER and ':' not in config.LOG_SERVER:
        sys.exit("[!] invalid configuration value for 'LOG_SERVER' ('%s')" % config.LOG_SERVER)

    # NOTE: validate via parse_host_port (requires a numeric port) instead of `len(split(':')) == 2` - the latter
    # rejected every IPv6 literal (e.g. '[2001:db8::1]:514' has many colons) even though the send path
    # (_endpoint_address -> parse_host_port) handles IPv6 fine; this matches LOG_SERVER accepting IPv6
    if config.SYSLOG_SERVER and parse_host_port(config.SYSLOG_SERVER)[1] is None:
        sys.exit("[!] invalid configuration value for 'SYSLOG_SERVER' ('%s')" % config.SYSLOG_SERVER)

    if config.LOGSTASH_SERVER and parse_host_port(config.LOGSTASH_SERVER)[1] is None:
        sys.exit("[!] invalid configuration value for 'LOGSTASH_SERVER' ('%s')" % config.LOGSTASH_SERVER)

    if config.REMOTE_SEVERITY_REGEX:
        try:
            re.compile(config.REMOTE_SEVERITY_REGEX)
        except re.error:
            sys.exit("[!] invalid configuration value for 'REMOTE_SEVERITY_REGEX' ('%s')" % config.REMOTE_SEVERITY_REGEX)

    if config.CAPTURE_FILTER and not config.pcap_file:
        print("[i] setting capture filter '%s'" % config.CAPTURE_FILTER)
        for _cap in _caps:
            try:
                _cap.setfilter(config.CAPTURE_FILTER)
            except Exception as ex:
                # surface a bad/unsupported BPF filter instead of swallowing it: a silent failure leaves the sensor
                # capturing EVERYTHING with the admin none the wiser that their filter (capture scope) was never applied
                print("[!] unable to set capture filter '%s' ('%s')" % (config.CAPTURE_FILTER, ex))

    if _multiprocessing:
        _init_multiprocessing()

    if not IS_WIN and not config.DISABLE_CPU_AFFINITY:
        msg = "[?] please install 'schedtool' for better CPU scheduling"

        try:
            affinity = 1

            try:
                with open("/proc/cpuinfo", "r") as f:
                    mod = sum(1 for line in f if line.startswith("processor"))

                if mod < 1:
                    mod = 1

                output = subprocess.check_output(["ps", "aux"], stderr=subprocess.STDOUT)
                if not isinstance(output, str):
                    output = output.decode("utf-8", "ignore")

                pids = []
                for line in output.splitlines():
                    parts = line.split(None, 10)
                    if len(parts) > 1 and parts[0] == "root" and "python" in line and "sensor.py" in line:
                        try:
                            pids.append(int(parts[1]))
                        except ValueError:
                            pass

                used = []
                for pid in pids:
                    try:
                        output = subprocess.check_output(["schedtool", str(pid)], stderr=subprocess.STDOUT)
                        if not isinstance(output, str):
                            output = output.decode("utf-8", "ignore")

                        index = output.find("AFFINITY")
                        if index >= 0:
                            parts = output[index:].split()
                            if len(parts) > 1 and parts[1] != "0xf":
                                used.append(parts[1])
                    except (OSError, subprocess.CalledProcessError, ValueError):
                        pass

                if used:
                    max_used = max(int(_, 16) for _ in used)
                    affinity = max(1, (max_used << 1) % 2 ** mod)
            except (IOError, OSError, subprocess.CalledProcessError, ValueError):
                affinity = 1

            try:
                p = subprocess.Popen(
                    [
                        "schedtool",
                        "-n", "-2",
                        "-M", "2",
                        "-p", "10",
                        "-a", "0x%02x" % affinity,
                        str(os.getpid())
                    ],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE
                )
                _, stderr = p.communicate()
                if not isinstance(stderr, str):
                    stderr = stderr.decode("utf-8", "ignore")

                if "not found" in stderr:
                    print(msg)
            except OSError:
                print(msg)
        except Exception:
            pass

def _init_multiprocessing():
    """
    Inits worker processes used in multiprocessing mode
    """

    global _buffer
    global _multiprocessing
    global _n

    if _multiprocessing:
        print("[i] preparing capture buffer...")
        try:
            _buffer = mmap.mmap(-1, config.CAPTURE_BUFFER)  # http://www.alexonlinux.com/direct-io-in-python

            _ = b"\x00" * MMAP_ZFILL_CHUNK_LENGTH
            for i in xrange(config.CAPTURE_BUFFER // MMAP_ZFILL_CHUNK_LENGTH):
                _buffer.write(_)
            _buffer.seek(0)
        except KeyboardInterrupt:
            raise
        except Exception:
            sys.exit("[!] unable to allocate network capture buffer. Please adjust value of 'CAPTURE_BUFFER'")

        _n = _multiprocessing.Value('L', lock=False)

        try:
            for i in xrange(config.PROCESS_COUNT - 1):
                process = _multiprocessing.Process(target=worker, name=str(i), args=(_buffer, _n, i, config.PROCESS_COUNT - 1, _process_packet))
                process.daemon = True
                process.start()
        except TypeError:   # Note: https://github.com/stamparm/maltrail/issues/11823
            _buffer = None
            _multiprocessing = None
        else:
            print("[i] created %d more processes (out of total %d)" % (config.PROCESS_COUNT - 1, config.PROCESS_COUNT))

_ioc_set_cache = None

def _get_ioc_set():
    """Packed IPv4 IOC set (all IPv4 / IPv4:port trail keys) for the in-C prefilter, built once.
    Best-effort: if the trails store can't be enumerated, returns b'' (IP-trail packets then rely
    on the normal admit classes / are shed as low-priority noise under load)."""
    global _ioc_set_cache
    if _ioc_set_cache is None:
        try:
            _ioc_set_cache = fastfilter.ioc_set_from_trails(trails)
        except Exception:
            _ioc_set_cache = b""
    return _ioc_set_cache

_dlt_learn = {}

def _guess_dlt_ip_offset(datalink, packet):
    """For a datalink that is NOT in DLT_OFFSETS, infer where the IP header begins by heuristic
    (instead of dropping every packet). Learned + cached per datalink, locked once two packets
    agree on the same offset; uses the provisional guess in the meantime, so nothing is dropped
    while learning. Returns the offset or None."""
    cached = _dlt_learn.get(datalink)
    if isinstance(cached, int):
        return cached
    if cached is False:
        return None
    off = fastfilter.guess_ip_offset(packet)
    if off is None:
        return None
    if _dlt_learn.get(("p", datalink)) == off:          # two packets agree -> lock it in
        _dlt_learn[datalink] = off
        try:
            print("[i] datalink %d missing from offset table; inferred IP offset %d by heuristic" % (datalink, off))
        except Exception:
            pass
        return off
    _dlt_learn[("p", datalink)] = off                    # provisional; still usable this packet
    return off

def monitor():
    """
    Sniffs/monitors given capturing interface
    """
    print("[^] running...")

    def packet_handler(datalink, header, packet):
        global _count

        ip_offset = None
        dlt_offset = DLT_OFFSETS.get(datalink)

        if dlt_offset is None:
            # Datalink not in the table: instead of dropping every packet, infer the IP-header
            # offset heuristically (and remember it for this datalink). Still surface it once per
            # datalink (the classic path used to log_error here) so an unsupported link is visible.
            log_error("Received unexpected datalink (%d); attempting IP-offset heuristic" % datalink, single=True)
            ip_offset = _guess_dlt_ip_offset(datalink, packet)
        else:
            try:
                if datalink == pcapy.DLT_RAW:
                    ip_offset = dlt_offset

                elif datalink == pcapy.DLT_PPP:
                    if packet[2:4] in (b"\x00\x21", b"\x00\x57"):  # (IPv4, IPv6)
                        ip_offset = dlt_offset

                elif datalink == pcapy.DLT_NULL:
                    if packet[0:4] in (b"\x02\x00\x00\x00", b"\x23\x00\x00\x00"):  # (IPv4, IPv6)
                        ip_offset = dlt_offset

                elif dlt_offset >= 2:
                    if packet[dlt_offset - 2:dlt_offset] == b"\x81\x00":  # VLAN
                        dlt_offset += 4
                    if packet[dlt_offset - 2:dlt_offset] in (b"\x08\x00", b"\x86\xdd"):  # (IPv4, IPv6)
                        ip_offset = dlt_offset

            except IndexError:
                pass

        if ip_offset is None:
            return

        # NOTE: pcapy.open_live() caps packets at SNAP_LEN, but pcapy.open_offline() (used in offline mode) applies no
        # snaplen, so a pcap recorded with e.g. `tcpdump -s 0` can yield packets larger than SNAP_LEN. In multiprocessing
        # mode such a packet would overflow its fixed-size slot in the shared capture buffer (BLOCK_LENGTH), corrupting
        # adjacent slots (resulting in a hung/early-exiting worker) or raising in struct.pack ("=H" caps at 65535). Truncating
        # to SNAP_LEN here matches what live capture already enforces at capture time (the parser only inspects headers and a
        # limited amount of payload, so it already operates on SNAP_LEN-truncated packets in production).
        if len(packet) > SNAP_LEN:
            packet = packet[:SNAP_LEN]

        try:
            if six.PY3:  # https://github.com/helpsystems/pcapy/issues/37#issuecomment-530795813
                sec, usec = [int(_) for _ in ("%.6f" % time.time()).split('.')]
            else:
                sec, usec = header.getts()

            if _multiprocessing:
                block = struct.pack("=III", sec, usec, ip_offset) + packet

                if _locks.count:
                    _locks.count.acquire()

                # Optional source-affinity (USE_CAPTURE_AFFINITY): pin all packets of a source IP to
                # one worker so cross-packet heuristic state (port/web/infection scan, DNS exhaustion)
                # is COMPLETE on that worker instead of fragmented across the round-robin pool -- which
                # otherwise needs a scan ~PROCESS_COUNT x larger to trip and emits one duplicate event
                # per worker. Routing is done by padding the ring to the target worker's lane with
                # empty (skipped) blocks, so the worker/ring code is unchanged. Off by default.
                if config.USE_CAPTURE_AFFINITY and config.PROCESS_COUNT > 2:
                    mod = config.PROCESS_COUNT - 1
                    target = _src_hash(packet, ip_offset) % mod
                    while _count % mod != target:
                        write_block(_buffer, _count, b"")          # filler; consumed and ignored (len < 12) by worker _count%mod
                        _n.value = _count = _count + 1

                write_block(_buffer, _count, block)
                _n.value = _count = _count + 1

                if _locks.count:
                    _locks.count.release()
            else:
                _process_packet(packet, sec, usec, ip_offset)

        except socket.timeout:
            pass

    def _run_fast_prefilter(_cap, datalink):
        # In-C prefilter (pcapy-ng loop_filtered): classify + admit in C, dropping provably-inert
        # noise; only DNS/DPI/IOC/HEAD/SYN packets cross into Python, where they go through the
        # unchanged packet_handler (offset/VLAN/write_block/_process_packet). The IOC set keeps
        # known-bad-IP packets (any protocol) even when they'd otherwise be shed as bulk noise.
        global _done_count

        ioc = _get_ioc_set()
        l2_offset = DLT_OFFSETS[datalink]
        flow_cutoff = int(getattr(config, "FAST_FLOW_CUTOFF", 4) or 0)   # >0 => capture TLS/QUIC handshake heads
        # Severity-aware admission: 0=normal .. 3=overload. DNS + IOC always admitted (never go
        # blind on DNS / known-bad IPs); higher levels shed SYN, then HEAD, then DPI under load.
        # FAST_ADMIT_ADAPTIVE auto-tunes the level from the live capture drop-rate (live only).
        adaptive = _cfg_bool(getattr(config, "FAST_ADMIT_ADAPTIVE", False)) and not config.pcap_file
        admit_level = 0 if adaptive else int(getattr(config, "FAST_ADMIT_LEVEL", 0) or 0)
        admit_mask = fastfilter.admit_mask_for_load(admit_level)
        _prev_stats = [None]   # (recv, drop) for the adaptive controller

        def fast_cb(header, packet, cls):
            # Additive: on a TLS/QUIC handshake head, extract the SNI and run it through the
            # normal domain check -> surfaces malicious domains on ENCRYPTED traffic that the
            # classic path can't see. The packet still goes through packet_handler for its
            # usual IP/heuristic processing.
            try:
                if cls == fastfilter.CLS_HEAD:
                    info = fastfilter.head_sni(packet, l2_offset)
                    if info:
                        sni, src_ip, src_port, dst_ip, dst_port, ipproto = info
                        if six.PY3:
                            sec, usec = [int(_) for _ in ("%.6f" % time.time()).split('.')]
                        else:
                            sec, usec = header.getts()
                        _check_domain(sni, sec, usec, src_ip, src_port, dst_ip, dst_port,
                                      PROTO.TCP if ipproto == 6 else PROTO.UDP, packet)
            except Exception:
                pass   # sniffer-safe: one malformed handshake never aborts the C loop (and so the
                       # only error that can escape loop_filtered is a genuine signature mismatch)
            packet_handler(datalink, header, packet)
            return None

        # Adaptive mode processes in bounded chunks so the admit level can be re-evaluated from
        # the drop-rate between chunks; otherwise one unbounded loop (offline EOF / live forever).
        chunk = 100000 if adaptive else -1

        while True:
            try:
                _cap.loop_filtered(chunk, fast_cb, admit_mask, ioc, flow_cutoff, None, None, 53, l2_offset, fastfilter.PROFILE)
            except (pcapy.PcapError, socket.timeout):
                pass
            except SystemError as ex:
                if "PY_SSIZE_T_CLEAN" in str(ex):
                    sys.exit("[!] seems that you are not using pcapy-ng (https://pypi.org/project/pcapy-ng/)")
                raise

            if config.pcap_file:                  # offline: EOF reached -> mark done and stop
                with _done_lock:
                    _done_count += 1
                return

            if adaptive:                          # re-tune the admit level from the capture drop-rate
                try:
                    recv, drop, _ = _cap.stats()
                    prev = _prev_stats[0]
                    if prev is not None:
                        admit_level = fastfilter.next_admit_level(admit_level, recv - prev[0], drop - prev[1])
                        admit_mask = fastfilter.admit_mask_for_load(admit_level)
                    _prev_stats[0] = (recv, drop)
                except Exception:
                    pass
            else:
                time.sleep(REGULAR_SENSOR_SLEEP_TIME)  # live: re-enter capture (e.g. after a transient error)

    try:
        def _(_cap):
            global _done_count

            datalink = _cap.datalink()

            _stats_iter = 0
            _stats_last = time.time()

            # Fast in-C prefilter path (opt-in via USE_FAST_PREFILTER, requires pcapy-ng built with
            # loop_filtered). Falls through to the classic next() loop below when off or unsupported,
            # but says WHY so a turned-on flag that can't take effect isn't silently ignored.
            if getattr(config, "USE_FAST_PREFILTER", False):
                if not fastfilter.has_fast_prefilter(_cap):
                    log_error("USE_FAST_PREFILTER is set but the installed pcapy has no loop_filtered "
                              "(needs pcapy-ng with the fast prefilter, https://pypi.org/project/pcapy-ng/); "
                              "using the classic capture path", single=True)
                elif datalink not in DLT_OFFSETS:
                    log_error("USE_FAST_PREFILTER: datalink %d not in offset table; using the classic "
                              "capture path" % datalink, single=True)
                else:
                    try:
                        _run_fast_prefilter(_cap, datalink)
                        return
                    except (TypeError, AttributeError) as ex:
                        # loop_filtered exists but its signature isn't the profile-aware form this
                        # build expects (older pcapy-ng) -> fall back instead of killing capture.
                        log_error("USE_FAST_PREFILTER: incompatible loop_filtered (%s); the installed "
                                  "pcapy-ng is too old, using the classic capture path" % ex, single=True)


#
# NOTE: currently an issue with pcapy-png and loop()
#
#            if six.PY3 and not config.pcap_file:  # https://github.com/helpsystems/pcapy/issues/37#issuecomment-530795813
#                def _loop_handler(header, packet):
#                    packet_handler(datalink, header, packet)
#
#                _cap.loop(-1, _loop_handler)
#            else:

            while True:
                success = False
                try:
                    (header, packet) = _cap.next()
                    if header is not None:
                        success = True
                        packet_handler(datalink, header, packet)
                    elif config.pcap_file:
                        with _done_lock:
                            _done_count += 1
                        break
                except (pcapy.PcapError, socket.timeout):
                    pass
                except SystemError as ex:
                    if "PY_SSIZE_T_CLEAN" in str(ex):
                        sys.exit("[!] seems that you are not using pcapy-ng (https://pypi.org/project/pcapy-ng/)")
                    else:
                        raise

                if not success:
                    time.sleep(REGULAR_SENSOR_SLEEP_TIME)

                # NOTE: periodic capture-drop visibility for live interfaces. Output goes to stdout via print() (operational
                # channel) - deliberately NOT log_event(), so it never pollutes the event log/feed. Counter-gated so the hot
                # path pays only a cheap increment per packet (no per-packet clock call), and fully sealed so a stats() quirk
                # can never disrupt capture. ps_drop is the kernel/libpcap ring shedding under load (drop-old by design).
                _stats_iter += 1
                if _stats_iter >= 1000000:
                    _stats_iter = 0
                    if not config.pcap_file and time.time() - _stats_last >= 3600:
                        _stats_last = time.time()
                        try:
                            recv, drop, ifdrop = _cap.stats()
                            print("[i] capture stats (cumulative): received=%d dropped=%d ifdropped=%d" % (recv, drop, ifdrop))
                        except Exception:
                            pass

        # One-time capture-topology summary on the operational console, so a turned-on fast-path
        # knob that silently no-ops (e.g. installed pcapy lacks the feature) is visible -- not
        # something the operator only discovers by reading source or measuring throughput.
        if not config.pcap_file and _caps:
            if getattr(config, "USE_FAST_PREFILTER", False):
                if fastfilter.has_fast_prefilter(_caps[0]):
                    _lvl = int(getattr(config, "FAST_ADMIT_LEVEL", 0) or 0)
                    _ad = _cfg_bool(getattr(config, "FAST_ADMIT_ADAPTIVE", False))
                    print("[i] fast prefilter ACTIVE: pcapy-ng loop_filtered (noise dropped in C; SNI surfaced on TLS/QUIC); admit level %d%s" % (_lvl, ", adaptive" if _ad else ""))
                else:
                    print("[!] USE_FAST_PREFILTER requested but the installed pcapy has no loop_filtered; using the CLASSIC capture path (install pcapy-ng >= 2.0)")
            print("[i] capture topology: %d capture socket(s) -> %d worker process(es)" % (len(_caps), config.PROCESS_COUNT))

        if config.profile and len(_caps) == 1:
            print("[=] will store profiling results to '%s'..." % config.profile)
            _(_caps[0])
        else:
            if len(_caps) > 1:
                if _multiprocessing:
                    _locks.count = threading.Lock()
                _locks.connect_sec = threading.Lock()
                _locks.heuristics = threading.Lock()

            for _cap in _caps:
                threading.Thread(target=_, args=(_cap,)).start()

            while _caps and not _done_count == (config.pcap_file or "").count(',') + 1:
                time.sleep(1)

        if not config.pcap_file:
            print("[i] all capturing interfaces closed")
    except SystemError as ex:
        if "error return without" in str(ex):
            print("\r[x] stopping (Ctrl-C pressed)")
        else:
            raise
    except KeyboardInterrupt:
        print("\r[x] stopping (Ctrl-C pressed)")
    finally:
        print("\r[i] cleaning up...")

        if _multiprocessing:
            try:
                for _ in xrange(config.PROCESS_COUNT - 1):
                    write_block(_buffer, _n.value, b"", BLOCK_MARKER.END)
                    _n.value = _n.value + 1
                while _multiprocessing.active_children():
                    time.sleep(REGULAR_SENSOR_SLEEP_TIME)
            except KeyboardInterrupt:
                pass

        if config.pcap_file:
            flush_condensed_events(True)

def main():
    for i in xrange(1, len(sys.argv)):
        if sys.argv[i] == "-q":
            sys.stdout = open(os.devnull, 'w')
        if sys.argv[i] == "-i":
            for j in xrange(i + 2, len(sys.argv)):
                value = sys.argv[j]
                if os.path.isfile(value):
                    sys.argv[i + 1] += ",%s" % value
                    sys.argv[j] = ''
                else:
                    break

    print("%s (sensor) #v%s {%s}\n" % (NAME, VERSION, HOMEPAGE))

    if "--version" in sys.argv:
        raise SystemExit

    parser = optparse.OptionParser(version=VERSION)
    parser.add_option("-c", dest="config_file", default=CONFIG_FILE, help="configuration file (default: '%s')" % os.path.split(CONFIG_FILE)[-1])
    parser.add_option("-r", dest="pcap_file", help="pcap file for offline analysis")
    parser.add_option("-p", dest="plugins", help="plugin(s) to be used per event")
    parser.add_option("-q", "--quiet", dest="quiet", action="store_true", help="turn off regular output")
    parser.add_option("--console", dest="console", action="store_true", help="print events to console")
    parser.add_option("--offline", dest="offline", action="store_true", help="disable (online) trail updates")
    parser.add_option("--debug", dest="debug", action="store_true", help=optparse.SUPPRESS_HELP)
    parser.add_option("--profile", dest="profile", help=optparse.SUPPRESS_HELP)
    parser.add_option("--smoke-test", dest="smoke_test", action="store_true", help=optparse.SUPPRESS_HELP)
    parser.add_option("--detect-test", dest="detect_test", action="store_true", help=optparse.SUPPRESS_HELP)

    patch_parser(parser)

    options, _ = parser.parse_args()

    if options.smoke_test:
        from core.testing import smoke_test
        raise SystemExit(0 if smoke_test() else 1)

    if options.detect_test:
        from core.testing import detect_test
        raise SystemExit(0 if detect_test() else 1)

    print("[*] starting @ %s\n" % time.strftime("%X /%Y-%m-%d/"))

    read_config(options.config_file)

    for option in dir(options):
        if isinstance(getattr(options, option), (six.string_types, bool)) and not option.startswith('_'):
            config[option] = getattr(options, option)

    if options.debug:
        config.console = True
        config.PROCESS_COUNT = 1
        config.SHOW_DEBUG = True

    if options.pcap_file:
        if options.pcap_file == '-':
            print("[i] using STDIN")
        else:
            for _ in options.pcap_file.split(','):
                if not os.path.isfile(_):
                    sys.exit("[!] missing pcap file '%s'" % _)

            print("[i] using pcap file(s) '%s'" % options.pcap_file)

    if not config.DISABLE_CHECK_SUDO and not check_sudo():
        sys.exit("[!] please run '%s' with root privileges" % __file__)

    try:
        init()
        if config.profile:
            open(config.profile, "w+b").write("")
            cProfile.run("monitor()", config.profile)
        else:
            monitor()
    except KeyboardInterrupt:
        print("\r[x] stopping (Ctrl-C pressed)")

if __name__ == "__main__":
    code = 0

    try:
        main()
    except SystemExit as ex:
        if isinstance(get_ex_message(ex), six.string_types) and get_ex_message(ex).strip('0'):
            print(get_ex_message(ex))
            code = 1
    except IOError:
        log_error("\n\n[!] session abruptly terminated\n[?] (hint: \"https://stackoverflow.com/a/20997655\")")
        code = 1
    except Exception:
        msg = "\r[!] unhandled exception occurred ('%s')" % sys.exc_info()[1]
        msg += "\n[x] please report the following details at 'https://github.com/stamparm/maltrail/issues':\n---\n'%s'\n---" % traceback.format_exc()
        log_error("\n\n%s" % msg.replace("\r", ""))

        print(msg)
        code = 1
    finally:
        if not any(_ in sys.argv for _ in ("--version", "-h", "--help")):
            print("\n[*] ending @ %s" % time.strftime("%X /%Y-%m-%d/"))

        os._exit(code)
