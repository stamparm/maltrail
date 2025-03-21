#!/usr/bin/env python

"""
Copyright (c) 2014-2025 Maltrail developers (https://github.com/stamparm/maltrail/)
See the file 'LICENSE' for copying permission
"""

from core.common import retrieve_content
from core.settings import NAME
__url__ = "https://blackhole.s-e-r-v-e-r.pw/blackhole-today"
__info__ = "known attacker"
__reference__ = "ip.blackhole.monster"

def fetch():
    retval = {}
    content = retrieve_content(__url__, headers={"User-agent": NAME}) # having problems with database (appending error messages to the end of gzip stream)

    for line in content.split('\n'):
        line = line.strip()
        if not line or line.startswith('#') or '.' not in line:
            continue
        retval[line] = (__info__, __reference__)

    return retval
