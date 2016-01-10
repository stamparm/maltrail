#!/usr/bin/env python

"""
Copyright (c) 2014-2016 Miroslav Stampar (@stamparm)
See the file 'LICENSE' for copying permission
"""

import re

from core.common import retrieve_content

__url__ = "http://osint.bambenekconsulting.com/feeds/dga-feed.txt"
__check__ = "Domain used by"
__reference__ = "bambenekconsulting.com"

def fetch():
    retval = {}
    content = retrieve_content(__url__)

    if __check__ in content:
        for match in re.finditer(r"(?m)^([^,\s]+),Domain used by ([^ ]+)", content):
            retval[match.group(1)] = ("%s dga (malware)" % match.group(2).lower(), __reference__)

    return retval
