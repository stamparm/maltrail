#!/usr/bin/env python

from core.common import retrieve_content
from core.common import BLACKLIST

__type__ = (BLACKLIST.IP,)
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
            retval[BLACKLIST.IP][line] = (__info__, __reference__)

    return retval
