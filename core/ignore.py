#!/usr/bin/env python

"""
Copyright (c) 2014-2026 Maltrail developers (https://github.com/stamparm/maltrail/)
See the file 'LICENSE' for copying permission
"""
from __future__ import print_function

# simple ignore rule mechanism configured by file 'misc/ignore_event.txt' and/or user defined `USER_IGNORELIST`

import re

from core.settings import config
from core.settings import IGNORE_EVENTS

_ignore_events_regex = None         # compiled form of config.IGNORE_EVENTS_REGEX, cached across events
_ignore_events_regex_src = None     # source string it was compiled from (recompiled only when it changes)

def ignore_event(event_tuple):
    global _ignore_events_regex, _ignore_events_regex_src

    retval = False
    _, _, src_ip, src_port, dst_ip, dst_port, _, _, _, _, _ = event_tuple

    regex_src = config.IGNORE_EVENTS_REGEX
    if regex_src:
        if regex_src != _ignore_events_regex_src:   # (re)compile once instead of re-hashing the pattern on every event
            _ignore_events_regex = re.compile(regex_src, re.I)
            _ignore_events_regex_src = regex_src
        if _ignore_events_regex.search(repr(event_tuple)):
            retval = True

    if not retval and IGNORE_EVENTS:
        src_port_str = str(src_port)    # computed once here rather than per ignore rule below
        dst_port_str = str(dst_port)
        for ignore_src_ip, ignore_src_port, ignore_dst_ip, ignore_dst_port in IGNORE_EVENTS:
            if ignore_src_ip != '*' and ignore_src_ip != src_ip:
                continue
            if ignore_src_port != '*' and ignore_src_port != src_port_str:
                continue
            if ignore_dst_ip != '*' and ignore_dst_ip != dst_ip:
                continue
            if ignore_dst_port != '*' and ignore_dst_port != dst_port_str:
                continue
            retval = True
            break

    if retval and config.SHOW_DEBUG:
        print("[i] ignore_event src_ip=%s, src_port=%s, dst_ip=%s, dst_port=%s" % (src_ip, src_port, dst_ip, dst_port))

    return retval
