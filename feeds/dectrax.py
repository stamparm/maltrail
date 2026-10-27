#!/usr/bin/env python

"""
Copyright (c) 2014-present Maltrail developers (https://github.com/stamparm/maltrail/)
See the file 'LICENSE' for copying permission
"""

from core.common import retrieve_content

__url__ = "https://raw.githubusercontent.com/Sadman-TheDentian/dectrax-threat-intel/main/feeds/attackers.txt"
__check__ = "DECTRAX"
__info__ = "known attacker (deception telemetry)"
__reference__ = "dectrax.com"

def fetch():
    retval = {}
    content = retrieve_content(__url__)

    if content and __check__ in content:
        for line in content.split('\n'):
            line = line.strip()
            if not line or line.startswith('#') or line.count('.') != 3:
                continue
            retval[line] = (__info__, __reference__)

    return retval
