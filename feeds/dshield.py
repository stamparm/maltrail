#!/usr/bin/env python

from core.common import retrieve_content
from core.common import BLACKLIST

__type__ = (BLACKLIST.DNS,)
__url__ = "http://www.dshield.org/feeds/suspiciousdomains_High.txt"
__check__ = "DShield.org"
__info__ = "suspicious"
__reference__ = "dshield.org"

def fetch():
    retval = dict((_, {}) for _ in __type__)
    content = retrieve_content(__url__)

    if __check__ in content:
        for line in content.split('\n'):
            line = line.strip()
            if not line or line.startswith('#') or '.' not in line:
                continue
            retval[BLACKLIST.DNS][line] = (__info__, __reference__)

    return retval
