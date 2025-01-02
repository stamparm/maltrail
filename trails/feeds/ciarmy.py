#!/usr/bin/env python

"""
Copyright (c) 2014-2025 Maltrail developers (https://github.com/stamparm/maltrail/)
See the file 'LICENSE' for copying permission
"""

from core.common import retrieve_content

__url__ = "http://cinsscore.com/list/ci-badguys.txt"
__info__ = "known attacker"
__reference__ = "cinsscore.com"

def fetch():
    retval = {}
    content = retrieve_content(__url__)

    for line in content.split('\n'):
        line = line.strip()
        if not line or line.startswith('#') or '.' not in line:
            continue
        retval[line] = (__info__, __reference__)

    return retval
