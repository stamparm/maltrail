#!/usr/bin/env python

"""
Copyright (c) 2014-2026 Maltrail developers (https://github.com/stamparm/maltrail/)
See the file 'LICENSE' for copying permission
"""

from core.common import retrieve_content
from core.settings import NAME

__url__ = "https://bl.ipwhois.net/feed.txt"
__check__ = "IPWhois.net Blacklist"
__info__ = "known attacker"
__reference__ = "ipwhois.net"

def fetch():
    retval = {}
    content = retrieve_content(__url__, headers={"User-agent": NAME})

    if __check__ in content:
        for line in content.split('\n'):
            line = line.strip()
            if not line or line.startswith('#') or '.' not in line:
                continue
            retval[line] = (__info__, __reference__)

    return retval
