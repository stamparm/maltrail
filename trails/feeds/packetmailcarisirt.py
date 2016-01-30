#!/usr/bin/env python

"""
Copyright (c) 2014-2016 Miroslav Stampar (@stamparm)
See the file 'LICENSE' for copying permission
"""

from core.common import retrieve_content

__url__ = "https://www.packetmail.net/iprep_CARISIRT.txt"
__check__ = ".1"
__info__ = "known attacker"
__reference__ = "packetmail.net"

def fetch():
    retval = {}
    content = retrieve_content(__url__)

    if __check__ in content:
        for line in content.split('\n'):
            line = line.strip()
            if not line or line.startswith('#') or '.' not in line:
                continue
            retval[line.split(';')[0].strip()] = (__info__, __reference__)

    return retval
