#!/usr/bin/env python

"""
Copyright (c) 2014-2015 Miroslav Stampar (@stamparm)
See the file 'LICENSE' for copying permission
"""

import re

from core.common import retrieve_content
from core.common import BLACKLIST

__type__ = (BLACKLIST.DNS,)
__url__ = "https://rules.emergingthreats.net/open/suricata/rules/emerging-dns.rules"
__check__ = "Emerging Threats"
__reference__ = "emergingthreats.net"

def fetch():
    retval = dict((_, {}) for _ in __type__)
    content = retrieve_content(__url__)

    if __check__ in content:
        for match in re.finditer(r"(?i)Suspicious \*?\.([^\s]+) domain", content):
            retval[BLACKLIST.DNS][match.group(1)] = ("suspicious", __reference__)

        for match in re.finditer(r"(?i)C2 Domain \.?([^\s\"]+)", content):
            retval[BLACKLIST.DNS][match.group(1)] = ("C&C", __reference__)

    return retval
