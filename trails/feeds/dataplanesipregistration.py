#!/usr/bin/env python

"""
See the file 'LICENSE' for copying permission
"""

from core.common import retrieve_content

__url__ = "https://dataplane.org/sipregistration.txt"
__check__ = "DataPlane.org"
__info__ = "known SIP REGISTER operation"
__reference__ = "dataplane.org"

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
