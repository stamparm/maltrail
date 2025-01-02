#!/usr/bin/env python

"""
Copyright (c) 2014-2025 Maltrail developers (https://github.com/stamparm/maltrail/)
See the file 'LICENSE' for copying permission
"""
from __future__ import print_function

# simple ignore rule mechanism configured by file 'misc/ignore_event.txt' and/or user defined `USER_IGNORELIST`

import re

from core.settings import config
from core.settings import IGNORE_EVENTS

def ignore_event(event_tuple):
    retval = False
    _, _, src_ip, src_port, dst_ip, dst_port, _, _, _, _, _ = event_tuple

    if config.IGNORE_EVENTS_REGEX and re.search(config.IGNORE_EVENTS_REGEX, repr(event_tuple), re.I):
        retval = True

    for ignore_src_ip, ignore_src_port, ignore_dst_ip, ignore_dst_port in IGNORE_EVENTS:
        if ignore_src_ip != '*' and ignore_src_ip != src_ip:
            continue
        if ignore_src_port != '*' and ignore_src_port != str(src_port):
            continue
        if ignore_dst_ip != '*' and ignore_dst_ip != dst_ip:
            continue
        if ignore_dst_port != '*' and ignore_dst_port != str(dst_port):
            continue
        retval = True
        break

    if retval and config.SHOW_DEBUG:
        print("[i] ignore_event src_ip=%s, src_port=%s, dst_ip=%s, dst_port=%s" % (src_ip, src_port, dst_ip, dst_port))

    return retval
