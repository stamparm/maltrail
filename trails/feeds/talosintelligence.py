#!/usr/bin/env python

"""
Copyright (c) 2014-2024 Maltrail developers (https://github.com/stamparm/maltrail/)
See the file 'LICENSE' for copying permission
"""

from core.common import retrieve_content

__url__ = "https://www.talosintelligence.com/documents/ip-blacklist"
__check__ = ".1"
__info__ = "bad reputation"
__reference__ = "talosintelligence.com"

def fetch():
    retval = {}
    content = retrieve_content(__url__)

    if __check__ in content:
        for line in content.split('\n'):
            line = line.strip()
            if not line or line.startswith('#') or '.' not in line:
                continue
            retval[line] = (__info__, __reference__)

    return retval
