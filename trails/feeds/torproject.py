#!/usr/bin/env python

"""
Copyright (c) 2014-2015 Miroslav Stampar (@stamparm)
See the file 'LICENSE' for copying permission
"""

from core.common import retrieve_content
from core.enums import TRAIL

__type__ = (TRAIL.IP,)
__url__ = "https://check.torproject.org/cgi-bin/TorBulkExitList.py?ip=1.1.1.1"
__check__ = "Tor exit nodes"
__info__ = "tor exit node"
__reference__ = "torproject.org"

def fetch():
    retval = dict((_, {}) for _ in __type__)
    content = retrieve_content(__url__)

    if __check__ in content:
        for line in content.split('\n'):
            line = line.strip()
            if not line or line.startswith('#') or '.' not in line:
                continue
            retval[TRAIL.IP][line] = (__info__, __reference__)

    return retval
