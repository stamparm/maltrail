#!/usr/bin/env python

"""
Copyright (c) 2014-2025 Maltrail developers (https://github.com/stamparm/maltrail/)
See the file 'LICENSE' for copying permission
"""

import re

from core.common import retrieve_content

__url__ = "https://sslbl.abuse.ch/blacklist/sslipblacklist.rules"
__check__ = "abuse.ch SSLBL"
__reference__ = "abuse.ch"

def fetch():
    retval = {}
    content = retrieve_content(__url__)

    if __check__ in content:
        for line in content.split('\n'):
            line = line.strip()
            if not line or line.startswith('#') or '.' not in line:
                continue
            match = re.search(r"any -> \[([\d.]+)\] (\d+) .+likely ([^)]+) C&C", line)
            if match:
                retval["%s:%s" % (match.group(1), match.group(2))] = ("%s (malware)" % (match.group(3).lower() if match.group(3).lower() != "malware" else "generic"), __reference__)

    return retval
