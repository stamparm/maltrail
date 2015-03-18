#!/usr/bin/env python

"""
Copyright (c) 2014-2015 Miroslav Stampar (@stamparm)
See the file 'LICENSE' for copying permission
"""

import re

from core.common import retrieve_content
from core.enums import TRAIL

__type__ = (TRAIL.DNS, TRAIL.IP)
__url__ = "https://zeustracker.abuse.ch/monitor.php?filter=all"
__check__ = "ZeuS Tracker"
__reference__ = "zeustracker.abuse.ch"

def fetch():
    retval = dict((_, {}) for _ in __type__)
    content = retrieve_content(__url__)

    if __check__ in content:
        for match in re.finditer(r'<td>([^<]+)</td><td><a href="/monitor.php\?host=([^"]+)', content):
            retval[TRAIL.IP if re.search(r"\A\d+\.\d+\.\d+\.\d+\Z", match.group(2)) else TRAIL.DNS][match.group(1)] = (match.group(2).lower() + " (malware)", __reference__)

    return retval
