#!/usr/bin/env python

from core.common import retrieve_content
from core.common import BLACKLIST

__type__ = (BLACKLIST.IP,)
__url__ = "http://lists.blocklist.de/lists/all.txt"
__info__ = "attacker"
__reference__ = "blocklist.de"

def fetch():
    retval = dict((_, {}) for _ in __type__)
    content = retrieve_content(__url__)

    for line in content.split('\n'):
        line = line.strip()
        if not line or line.startswith('#') or '.' not in line:
            continue
        retval[BLACKLIST.IP][line] = (__info__, __reference__)

    return retval
