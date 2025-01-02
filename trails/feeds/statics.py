#!/usr/bin/env python

"""
Copyright (c) 2014-2025 Maltrail developers (https://github.com/stamparm/maltrail/)
See the file 'LICENSE' for copying permission
"""

from core.common import retrieve_content

__url__ = "https://raw.githubusercontent.com/stamparm/aux/master/maltrail-static-trails.txt"
__check__ = "morphed.ru"

def fetch():
    retval = {}
    content = retrieve_content(__url__)

    if __check__ in content:
        for line in content.split('\n'):
            line = line.strip()
            if not line or line.startswith('#') or line.count(',') != 2:
                continue
            trail, __info__, __reference__ = line.split(',')
            retval[trail] = (__info__, __reference__)

    return retval
