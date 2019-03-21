#!/usr/bin/env python2

"""
Copyright (c) 2014-2019 Maltrail developers (https://github.com/stamparm/maltrail/)
See the file 'LICENSE' for copying permission
"""

from core.common import retrieve_content

__url__ = "https://www.talosintelligence.com/feeds/ip-filter.blf"
__check__ = ".1"
__info__ = "bad reputation"
__reference__ = "talosintelligence.com"

# Reference: http://blog.snort.org/2015/09/ip-blacklist-feed-has-moved-locations.html
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
