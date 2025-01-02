#!/usr/bin/env python

"""
Copyright (c) 2014-2025 Maltrail developers (https://github.com/stamparm/maltrail/)
See the file 'LICENSE' for copying permission
"""

from core.common import retrieve_content

__url__ = "https://reputation.alienvault.com/reputation.generic"
__check__ = " # Malicious"
__info__ = "bad reputation"
__reference__ = "alienvault.com"

def fetch():
    retval = {}
    content = retrieve_content(__url__)

    if __check__ in content:
        for line in content.split('\n'):
            line = line.strip()
            if not line or line.startswith('#') or '.' not in line:
                continue
            if " # " in line:
                reason = line.split(" # ")[1].split()[0].lower()
                if reason == "scanning":  # too many false positives
                    continue
                retval[line.split(" # ")[0]] = (__info__, __reference__)

    return retval
