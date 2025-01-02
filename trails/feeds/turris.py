#!/usr/bin/env python

"""
Copyright (c) 2014-2025 Maltrail developers (https://github.com/stamparm/maltrail/)
See the file 'LICENSE' for copying permission
"""

from core.common import retrieve_content

__url__ = "https://view.sentinel.turris.cz/greylist-data/greylist-latest.csv"
__check__ = ".1"
__info__ = "bad reputation"
__reference__ = "turris.cz"

def fetch():
    retval = {}
    content = retrieve_content(__url__)

    if __check__ in content:
        for line in content.split('\n'):
            line = line.strip()
            if not line or line.startswith('#') or '.' not in line:
                continue
            retval[line.split(',')[0].strip()] = (__info__, __reference__)

    return retval
