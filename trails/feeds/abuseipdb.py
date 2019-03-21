#!/usr/bin/env python2

"""
Copyright (c) 2014-2019 Maltrail developers (https://github.com/stamparm/maltrail/)
See the file 'LICENSE' for copying permission
"""

import re

from core.common import retrieve_content

__url__ = "https://www.abuseipdb.com/statistics"
__check__ = "distinct users"
__info__ = "known attacker"
__reference__ = "abuseipdb.com"

def fetch():
    retval = {}
    content = retrieve_content(__url__)

    if __check__ in content:
        for ip in re.findall(r">(\d+\.\d+\.\d+\.\d+)</a></b> \(\d+ reports from \d+ distinct users\)", content):
            retval[ip] = (__info__, __reference__)

    return retval
