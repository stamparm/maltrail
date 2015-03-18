#!/usr/bin/env python

"""
Copyright (c) 2014-2015 Miroslav Stampar (@stamparm)
See the file 'LICENSE' for copying permission
"""

import re

from core.common import retrieve_content
from core.enums import TRAIL

__type__ = (TRAIL.IP,)
__url__ = "http://atrack.h3x.eu/c2"
__check__ = "ASPROX Tracker"
__info__ = "asprox (malware)"
__reference__ = "atrack.h3x.eu"

def fetch():
    retval = dict((_, {}) for _ in __type__)
    content = retrieve_content(__url__)

    if __check__ in content:
        for match in re.finditer(r'<div class="?code"?>(\d+\.\d+\.\d+\.\d+)</div>', content):
            retval[TRAIL.IP][match.group(1)] = (__info__, __reference__)

    return retval
