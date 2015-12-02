#!/usr/bin/env python

"""
Copyright (c) 2014-2015 Miroslav Stampar (@stamparm)
See the file 'LICENSE' for copying permission
"""

import re

from core.common import retrieve_content

__url__ = "https://reputation.alienvault.com/reputation.generic"
__check__ = " # Malicious"
__info__ = "bad reputation"
__reference__ = "alienvault.com"

def fetch():
    retval = {}
    content = retrieve_content(__url__)

    if __check__ in content:
        for line in content.split('\n'):
            line = line.strip()
            if not line or line.startswith('#') or '.' not in line:
                continue
            if " # " in line:
                retval[line.split(" # ")[0]] = ("%s (%s)" % (__info__, line.split(" # ")[1].split()[0].lower()), __reference__)

    return retval
