#!/usr/bin/env python

"""
Copyright (c) 2014-2016 Miroslav Stampar (@stamparm)
See the file 'LICENSE' for copying permission
"""

from core.common import retrieve_content

__url__ = "https://dragonresearchgroup.org/insight/vncprobe.txt"
__check__ = "DRG"
__info__ = "known attacker"
__reference__ = "dragonresearchgroup.org"

def fetch():
    retval = {}
    content = retrieve_content(__url__)

    if __check__ in content:
        for line in content.split('\n'):
            line = line.strip()
            if not line or line.startswith('#') or '.' not in line or '|' not in line:
                continue
            retval[line.split('|')[2].strip()] = (__info__, __reference__)

    return retval
