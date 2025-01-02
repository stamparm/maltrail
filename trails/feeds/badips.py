#!/usr/bin/env python

"""
Copyright (c) 2014-2025 Maltrail developers (https://github.com/stamparm/maltrail/)
See the file 'LICENSE' for copying permission
"""

from core.common import retrieve_content

__url__ = "https://www.badips.com/get/list/any/2?age=7d"
__backup__ = "https://iplists.firehol.org/files/bi_any_2_7d.ipset"
__check__ = ".1"
__info__ = "known attacker"
__reference__ = "badips.com"

def fetch():
    retval = {}
    content = retrieve_content(__url__)

    if __check__ not in content:
        content = retrieve_content(__backup__)

    if __check__ in content:
        for line in content.split('\n'):
            line = line.strip()
            if not line or line.startswith('#') or '.' not in line:
                continue
            retval[line] = (__info__, __reference__)

    return retval
