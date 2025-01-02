#!/usr/bin/env python

"""
Copyright (c) 2014-2025 Maltrail developers (https://github.com/stamparm/maltrail/)
See the file 'LICENSE' for copying permission
"""

from core.common import retrieve_content

__url__ = "https://rules.emergingthreats.net/open/suricata/rules/compromised-ips.txt"
__info__ = "compromised (suspicious)"
__reference__ = "emergingthreats.net"

def fetch():
    retval = {}
    content = retrieve_content(__url__)

    for line in content.split('\n'):
        line = line.strip()
        if not line or line.startswith('#') or '.' not in line:
            continue
        retval[line] = (__info__, __reference__)

    return retval
