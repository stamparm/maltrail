#!/usr/bin/env python

"""
Copyright (c) 2014-2015 Miroslav Stampar (@stamparm)
See the file 'LICENSE' for copying permission
"""

import re

from core.common import retrieve_content

__url__ = "http://www.botscout.com/last_caught_cache.htm"
__check__ = "Bot Name"
__info__ = "spammer"
__reference__ = "botscout.com"

def fetch():
    retval = {}
    content = retrieve_content(__url__)

    if __check__ in content:
        for match in re.finditer(r'ipcheck.htm\?ip=([\d.]+)"', content):
            retval[match.group(1)] = (__info__, __reference__)

    return retval
