#!/usr/bin/env python

"""
Copyright (c) 2014-2015 Miroslav Stampar (@stamparm)
See the file 'LICENSE' for copying permission
"""

import re

from core.common import retrieve_content

__url__ = "https://www.maxmind.com/en/anonymous_proxies"
__check__ = "Anonymous Proxies "
__info__ = "anonymous proxy (suspicious)"
__reference__ = "maxmind.com"

def fetch():
    retval = {}
    content = retrieve_content(__url__)

    if __check__ in content:
        for match in re.finditer(r"proxy/([\d.]+)", content):
            retval[match.group(1)] = (__info__, __reference__)

    return retval
