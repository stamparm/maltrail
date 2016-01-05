#!/usr/bin/env python

"""
Copyright (c) 2014-2016 Miroslav Stampar (@stamparm)
See the file 'LICENSE' for copying permission
"""

import re

from core.common import retrieve_content

__url__ = "http://rules.emergingthreats.net/open/suricata/rules/botcc.rules"
__check__ = "CnC Server"
__info__ = "malware"
__reference__ = "emergingthreats.net"

def fetch():
    retval = {}
    content = retrieve_content(__url__)

    if __check__ in content:
        for match in re.finditer(r"\d+\.\d+\.\d+\.\d+", content):
            retval[match.group(0)] = (__info__, __reference__)

    return retval
