#!/usr/bin/env python

"""
Copyright (c) 2014-2016 Miroslav Stampar (@stamparm)
See the file 'LICENSE' for copying permission
"""

from core.common import retrieve_content

__url__ = "https://www.autoshun.org/files/shunlist.csv"
__check__ = "Shunlist"
__reference__ = "autoshun.org"

def fetch():
    retval = {}
    content = retrieve_content(__url__)

    if __check__ in content:
        for line in content.split('\n'):
            line = line.strip()
            if not line or line.startswith('#') or '.' not in line or "Shunlist" in line:
                continue
            retval[line.split(",")[0]] = ("%s (attacker)" % line.split(",", 2)[-1].lower().strip("'\""), __reference__)

    return retval
