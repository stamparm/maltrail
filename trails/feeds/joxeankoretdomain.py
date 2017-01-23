#!/usr/bin/env python

"""

Yunus YILDIRIM (@Th3Gundy)

"""

from core.common import retrieve_content

__url__ = "http://malwareurls.joxeankoret.com/domains.txt"
__check__ = "joxeankoret"
__info__ = "domain (suspicious)"
__reference__ = "joxeankoret.com"

def fetch():
    retval = {}
    content = retrieve_content(__url__)

    if __check__ in content:
        for line in content.split('\n'):
            line = line.strip()
            if not line or line.startswith('#') or line.startswith('['):
                continue
            retval[line] = (__info__, __reference__)

    return retval
