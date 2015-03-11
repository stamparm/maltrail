#!/usr/bin/env python

"""
Copyright (c) 2014-2015 Miroslav Stampar (@stamparm)
See the file 'LICENSE' for copying permission
"""

import re

from core.common import retrieve_content
from core.enums import TRAIL

__type__ = (TRAIL.DNS,)
__url__ = "https://rules.emergingthreats.net/open/suricata/rules/emerging-dns.rules"
__check__ = "Emerging Threats"
__info__ = "c&c"
__reference__ = "emergingthreats.net"

def fetch():
    retval = dict((_, {}) for _ in __type__)
    content = retrieve_content(__url__)

    if __check__ in content:
        #for match in re.finditer(r"(?i)Suspicious \*?\.([^\s]+) domain", content):
        #    retval[TRAIL.DNS][match.group(1)] = ("suspicious", __reference__)

        for match in re.finditer(r"(?i)C2 Domain \.?([^\s\"]+)", content):
            retval[TRAIL.DNS][match.group(1)] = (__info__, __reference__)

    return retval
