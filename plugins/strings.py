#!/usr/bin/env python2

"""
Copyright (c) 2014-2019 Maltrail developers (https://github.com/stamparm/maltrail/)
See the file 'LICENSE' for copying permission
"""

import re
import sys
import time

TIME_FORMAT = "%Y-%m-%d %H:%M:%S"


def plugin(event_tuple, packet=None):
    sec, usec, src_ip, src_port, dst_ip, dst_port, proto, type, trail, info, reference = event_tuple
    if packet:
        localtime = time.strftime(TIME_FORMAT, time.localtime(int(sec)))
        output = "\n[%s] %s:%s -> %s:%s:\n" % (localtime, src_ip, src_port, dst_ip, dst_port)
        output += "%s\n" % "\n".join(re.findall(r"[ -~]{4,}", packet))
        sys.stderr.write(output)
        sys.stderr.flush()
