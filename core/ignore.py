#!/usr/bin/env python

"""
Copyright (c) 2014-present Maltrail developers (https://github.com/stamparm/maltrail/)
See the file 'LICENSE' for copying permission
"""

# simple ignore rule mechanism configured by file 'data/ignore_events.txt' and/or user defined `USER_IGNORELIST`
#
# Address and port fields take a network or a range as well as a literal. The literal-only form was
# unusable at the scale people actually hit: issue #19142 is an operator with 5-10k events a day
# whose only way to silence their own subnet was to write out every address in it. A CIDR and a
# dash range are the same containment test, so both compile to one inclusive interval and the
# matcher never has to know which spelling produced it.
#
# Anything that is not a valid network or range stays an exact string comparison, so every rule
# written before this existed keeps meaning exactly what it meant. This mirrors sensor/src/ignore.rs
# and the two are pinned against each other by tests/test_ignore.py.

import re
import socket
import struct

from core.addr import addr_to_int
from core.addr import make_mask
from core.settings import config
from core.settings import IGNORE_EVENTS

ANY = "*"

_IPV4_REGEX = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")

def _parse_ipv4(value):
    """IPv4 text -> int, or None.

    core.addr.addr_to_int() raises on anything that is not a dotted quad, and every caller here is
    parsing operator-written text where "not an address" is an ordinary answer, not an error.
    """

    if not _IPV4_REGEX.match(value):
        return None
    try:
        octets = [int(_) for _ in value.split('.')]
    except ValueError:
        return None
    if any(_ > 255 for _ in octets):
        return None
    return addr_to_int(value)

def _parse_ipv6(value):
    """IPv6 text -> int, or None."""

    try:
        return int.from_bytes(socket.inet_pton(socket.AF_INET6, value), "big")
    except (OSError, ValueError, AttributeError):
        return None

def _compile_host(token):
    """(kind, lo, hi) for an address field.

    kind is 'any', 'exact', 4 or 6. A CIDR and a dash range both become an inclusive interval.
    """

    if token == ANY:
        return ("any", None, None)

    if '/' in token:
        prefix, _, bits = token.partition('/')
        try:
            bits = int(bits)
        except ValueError:
            return ("exact", token, None)
        value = _parse_ipv4(prefix)
        if value is not None and 0 <= bits <= 32:
            mask = make_mask(bits)
            return (4, value & mask, (value & mask) | (0xffffffff ^ mask))
        value = _parse_ipv6(prefix)
        if value is not None and 0 <= bits <= 128:
            mask = ((1 << 128) - 1) ^ ((1 << (128 - bits)) - 1)
            return (6, value & mask, (value & mask) | (((1 << 128) - 1) ^ mask))
        return ("exact", token, None)

    if '-' in token:
        lo, _, hi = token.partition('-')
        start = _parse_ipv4(lo)
        if start is not None:
            end = _parse_ipv4(hi)
            if end is None:
                # "192.168.1.10-20" is the shorthand people write: the last octet only
                try:
                    last = int(hi)
                except ValueError:
                    return ("exact", token, None)
                if not 0 <= last <= 255:
                    return ("exact", token, None)
                end = (start & 0xffffff00) | last
            return (4, start, end) if end >= start else ("exact", token, None)
        start = _parse_ipv6(lo)
        end = _parse_ipv6(hi)
        if start is not None and end is not None and end >= start:
            return (6, start, end)
        return ("exact", token, None)

    return ("exact", token, None)

def _compile_port(token):
    if token == ANY:
        return ("any", None, None)
    if '-' in token:
        lo, _, hi = token.partition('-')
        try:
            lo, hi = int(lo), int(hi)
        except ValueError:
            return ("exact", token, None)
        if 0 <= lo <= 65535 and 0 <= hi <= 65535 and hi >= lo:
            return ("range", lo, hi)
    return ("exact", token, None)

def _host_matches(rule, text):
    kind, lo, hi = rule
    if kind == "any":
        return True
    if kind == "exact":
        return lo == text
    value = _parse_ipv4(text) if kind == 4 else _parse_ipv6(text)
    return value is not None and lo <= value <= hi

def _port_matches(rule, text):
    kind, lo, hi = rule
    if kind == "any":
        return True
    if kind == "exact":
        return lo == text
    try:
        value = int(text)
    except (TypeError, ValueError):
        return False    # a non-port protocol writes "-" here; a range must not match it
    return lo <= value <= hi

_compiled = None            # IGNORE_EVENTS compiled to matchers
_compiled_src = None        # a COPY of the rule set it was compiled from

def _rules():
    """Compile IGNORE_EVENTS once, and again whenever it changes.

    Compared by value against a copy, not by identity: read_ignorelist() clears and refills the
    SAME set object, so an identity check would keep serving rules from the previous configuration
    after a reload - silently ignoring traffic the operator had just stopped ignoring, or the
    reverse. The comparison is a set equality over a handful of tuples, once per EVENT rather than
    per packet, which is nothing beside writing the event out.
    """

    global _compiled, _compiled_src

    if _compiled is None or _compiled_src != IGNORE_EVENTS:
        _compiled = [
            (_compile_host(a), _compile_port(b), _compile_host(c), _compile_port(d))
            for (a, b, c, d) in IGNORE_EVENTS
        ]
        _compiled_src = set(IGNORE_EVENTS)
    return _compiled

_ignore_events_regex = None         # compiled form of config.IGNORE_EVENTS_REGEX, cached across events
_ignore_events_regex_src = None     # source string it was compiled from (recompiled only when it changes)

def ignore_event(event_tuple):
    global _ignore_events_regex, _ignore_events_regex_src

    retval = False
    _, _, src_ip, src_port, dst_ip, dst_port, _, _, _, _, _ = event_tuple

    regex_src = config.IGNORE_EVENTS_REGEX
    if regex_src:
        if regex_src != _ignore_events_regex_src:   # (re)compile once instead of re-hashing the pattern on every event
            try:
                _ignore_events_regex = re.compile(regex_src, re.I)
            except re.error as ex:
                # an invalid IGNORE_EVENTS_REGEX must NOT raise out of this per-event hot path: log_event only catches
                # (OSError, IOError), so the re.error would propagate and drop EVERY event -> the sensor silently goes
                # blind on a single config typo. Disable the rule (warn once) and keep logging, like FAIL2BAN_REGEX does.
                _ignore_events_regex = None
                print("[!] invalid regular expression in option 'IGNORE_EVENTS_REGEX' ('%s'): %s" % (regex_src, ex))
            _ignore_events_regex_src = regex_src    # NOTE: set even on failure so the bad pattern isn't recompiled (nor re-warned) on every subsequent event
        if _ignore_events_regex is not None and _ignore_events_regex.search(repr(event_tuple)):
            retval = True

    if not retval and IGNORE_EVENTS:
        src_port_str = str(src_port)    # computed once here rather than per ignore rule below
        dst_port_str = str(dst_port)
        for r_src_ip, r_src_port, r_dst_ip, r_dst_port in _rules():
            if not _host_matches(r_src_ip, src_ip):
                continue
            if not _port_matches(r_src_port, src_port_str):
                continue
            if not _host_matches(r_dst_ip, dst_ip):
                continue
            if not _port_matches(r_dst_port, dst_port_str):
                continue
            retval = True
            break

    if retval and config.SHOW_DEBUG:
        print("[i] ignore_event src_ip=%s, src_port=%s, dst_ip=%s, dst_port=%s" % (src_ip, src_port, dst_ip, dst_port))

    return retval
