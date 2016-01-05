#!/usr/bin/env python

"""
Copyright (c) 2014-2016 Miroslav Stampar (@stamparm)
See the file 'LICENSE' for copying permission
"""

import re

from core.common import retrieve_content

__url__ = "http://vxvault.siri-urz.net/URL_List.php"
__check__ = "VX Vault"
__info__ = "malware"
__reference__ = "siri-urz.net"

def fetch():
    retval = {}
    content = retrieve_content(__url__)

    if __check__ in content:
        for line in content.split('\n'):
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            if '://' in line:
                line = re.search(r"://(.*)", line).group(1)
                retval[line] = (__info__, __reference__)

    return retval
