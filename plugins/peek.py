#!/usr/bin/env python

"""
Copyright (c) 2014-2025 Maltrail developers (https://github.com/stamparm/maltrail/)
See the file 'LICENSE' for copying permission
"""

import sys
import string
import time

TIME_FORMAT = "%Y-%m-%d %H:%M:%S"

def plugin(event_tuple, packet=None):
    sec, usec, src_ip, src_port, dst_ip, dst_port, proto, type, trail, info, reference = event_tuple
    if packet:
        localtime = time.strftime(TIME_FORMAT, time.localtime(int(sec)))
        output = "\n[%s] %s:%s -> %s:%s:\n" % (localtime, src_ip, src_port, dst_ip, dst_port)
        output += "%s\n" % "".join(chr(_) if chr(_) in string.printable else '.' for _ in packet)
        sys.stderr.write(output)
        sys.stderr.flush()
