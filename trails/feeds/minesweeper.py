#!/usr/bin/env python

"""
Copyright (c) 2014-2020 Maltrail developers (https://github.com/stamparm/maltrail/)
See the file 'LICENSE' for copying permission
"""

from core.common import retrieve_content

__url__ = "https://raw.githubusercontent.com/PortSwigger/mine-sweeper/master/lib/sources.txt"
__check__ = ".com"
__info__ = "crypto jacking (suspicious)"
__reference__ = "github.com/portswigger"

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
