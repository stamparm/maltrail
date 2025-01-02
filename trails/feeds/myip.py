#!/usr/bin/env python

"""
Copyright (c) 2014-2025 Maltrail developers (https://github.com/stamparm/maltrail/)
See the file 'LICENSE' for copying permission
"""

import re

from core.common import retrieve_content

__url__ = "https://myip.ms/files/blacklist/htaccess/latest_blacklist.txt"
__check__ = "ADDRESSES DATABASE"
__info__ = "crawler"
__reference__ = "myip.ms"

def fetch():
    retval = {}
    content = retrieve_content(__url__)

    if __check__ in content:
        for match in re.finditer(r"deny from (\d+\.\d+\.\d+\.\d+)", content):
            retval[match.group(1)] = (__info__, __reference__)

    return retval
