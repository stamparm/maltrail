#!/usr/bin/env python

"""

Yunus YILDIRIM (@Th3Gundy)

"""

import re

from core.common import retrieve_content

__url__ = "http://malwareurls.joxeankoret.com/normal.txt"
__check__ = "joxeankoret"
__info__ = "malware"
__reference__ = "joxeankoret.com"

def fetch():
    retval = {}
    content = retrieve_content(__url__)

    if __check__ in content:
        for line in content.split('\n'):
            line = line.strip()
            if not line or line.startswith('#') or line.startswith('['):
                continue
            if '://' in line:
                line = re.search(r"://(.*)", line).group(1)
                retval[line] = (__info__, __reference__)

    return retval
