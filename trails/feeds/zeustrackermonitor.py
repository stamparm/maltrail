#!/usr/bin/env python

"""
Copyright (c) 2014-2025 Maltrail developers (https://github.com/stamparm/maltrail/)
See the file 'LICENSE' for copying permission
"""

import re

from core.common import retrieve_content

__url__ = "https://zeustracker.abuse.ch/monitor.php?filter=all"
__check__ = "ZeuS Tracker"
__reference__ = "abuse.ch"

def fetch():
    retval = {}
    content = retrieve_content(__url__)

    if __check__ in content:
        for match in re.finditer(r'<td>([^<]+)</td><td><a href="/monitor.php\?host=([^"]+)', content):
            retval[match.group(2)] = (match.group(1).lower() + " (malware)", __reference__)

    return retval
