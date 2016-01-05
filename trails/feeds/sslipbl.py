#!/usr/bin/env python

"""
Copyright (c) 2014-2016 Miroslav Stampar (@stamparm)
See the file 'LICENSE' for copying permission
"""

from core.common import retrieve_content

__url__ = "https://sslbl.abuse.ch/blacklist/sslipblacklist.csv"
__check__ = "abuse.ch SSL IPBL "
__reference__ = "abuse.ch"

def fetch():
    retval = {}
    content = retrieve_content(__url__)

    if __check__ in content:
        for line in content.split('\n'):
            line = line.strip()
            if not line or line.startswith('#') or '.' not in line:
                continue
            retval[line.split(',')[0]] = ("%s (malware)" % line.split(',')[2].lower().split()[0], __reference__)

    return retval
