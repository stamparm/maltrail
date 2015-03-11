#!/usr/bin/env python

"""
Copyright (c) 2014-2015 Miroslav Stampar (@stamparm)
See the file 'LICENSE' for copying permission
"""

import re

from core.common import retrieve_content
from core.enums import TRAIL

__type__ = (TRAIL.IP,)
__url__ = "http://rules.emergingthreats.net/open/suricata/rules/botcc.rules"
__check__ = "CnC Server"
__info__ = "c&c"
__reference__ = "emergingthreats.net"

def fetch():
    retval = dict((_, {}) for _ in __type__)
    content = retrieve_content(__url__)

    if __check__ in content:
        for match in re.finditer(r"\d+\.\d+\.\d+\.\d+", content):
            retval[TRAIL.IP][match.group(0)] = (__info__, __reference__)

    return retval
