#!/usr/bin/env python

"""
Copyright (c) 2014-2016 Miroslav Stampar (@stamparm)
See the file 'LICENSE' for copying permission
"""

import re

from core.common import retrieve_content

__url__ = "http://security-research.dyndns.org/pub/botnet/ponmocup/ponmocup-finder/ponmocup-infected-domains-latest.txt"
__check__ = "DNS: "
__info__ = "ponmocup (malware)"
__reference__ = "security-research.dyndns.org"

def fetch():
    retval = {}
    content = retrieve_content(__url__)

    if __check__ in content:
        for domain in re.findall(r" DNS: ([^ ]+)", content):
            retval[domain] = (__info__, __reference__)

    return retval
