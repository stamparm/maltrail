#!/usr/bin/env python

"""
Copyright (c) 2014-2015 Miroslav Stampar (@stamparm)
See the file 'LICENSE' for copying permission
"""

import re

from core.common import retrieve_content
from core.enums import TRAIL

__type__ = (TRAIL.IP, TRAIL.DNS)
__url__ = "https://palevotracker.abuse.ch/blocklists.php?download=combinedblocklist"
__check__ = "Palevo"
__info__ = "palevo"
__reference__ = "palevotracker.abuse.ch"

def fetch():
    retval = dict((_, {}) for _ in __type__)
    content = retrieve_content(__url__)

    if __check__ in content:
        for line in content.split('\n'):
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            if re.search(r"\A\d+\.\d+\.\d+\.\d+\Z", line):
                retval[TRAIL.IP][line] = (__info__, __reference__)
            else:
                retval[TRAIL.DNS][line] = (__info__, __reference__)

    return retval
