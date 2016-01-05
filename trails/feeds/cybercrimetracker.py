#!/usr/bin/env python

"""
Copyright (c) 2014-2016 Miroslav Stampar (@stamparm)
See the file 'LICENSE' for copying permission
"""

import re

from core.common import retrieve_content

__url__ = "http://cybercrime-tracker.net/all.php"
__check__ = "admin.php"
__info__ = "malware"
__reference__ = "cybercrime-tracker.net"

def fetch():
    retval = {}
    content = retrieve_content(__url__)

    if __check__ in content:
        content = content.replace("<br />", '\n')
        for line in content.split('\n'):
            line = line.strip()
            if not line or line.startswith('#') or '(SSL)' in line:
                continue
            if '://' in line:
                line = re.search(r"://(.*)", line).group(1)
            line = line.rstrip('/')
            if '/' in line:
                retval[line] = (__info__, __reference__)
                line = line.split('/')[0]
            if ':' in line:
                line = line.split(':')[0]
            if re.search(r"\A\d+\.\d+\.\d+\.\d+\Z", line):
                retval[line] = (__info__, __reference__)
            else:
                retval[line] = (__info__, __reference__)

    return retval
