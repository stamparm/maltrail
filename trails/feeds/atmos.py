#!/usr/bin/env python

"""
Copyright (c) 2014-2025 Maltrail developers (https://github.com/stamparm/maltrail/)
See the file 'LICENSE' for copying permission
"""

import re

from core.common import retrieve_content

__url__ = "https://cybercrime-tracker.net/ccam.php"
__check__ = "Atmos Strategic Monitoring"
__info__ = "atmos (malware)"
__reference__ = "cybercrime-tracker.net"

def fetch():
    retval = {}
    content = retrieve_content(__url__)

    if __check__ in content:
        for match in re.finditer(r">([^<]+\.[a-zA-Z]+)</td>\s*<td style=\"background-color: rgb\(11, 11, 11\);\"><a href=\"ccamdetail\.php\?hash=", content):
            retval[match.group(1)] = (__info__, __reference__)

    return retval
