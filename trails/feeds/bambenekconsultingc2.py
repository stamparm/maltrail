#!/usr/bin/env python

"""
Copyright (c) 2014-2016 Miroslav Stampar (@stamparm)
See the file 'LICENSE' for copying permission
"""

import re

from core.common import retrieve_content

__url__ = "http://osint.bambenekconsulting.com/feeds/c2-ipmasterlist.txt"
__check__ = "Master Feed"
__reference__ = "bambenekconsulting.com"

def fetch():
    retval = {}
    content = retrieve_content(__url__)

    if __check__ in content:
        for match in re.finditer(r"(?m)^([\d.]+),IP used by ([^,]+) C&C", content):
            retval[match.group(1)] = ("%s (malware)" % match.group(2).lower(), __reference__)

    return retval
