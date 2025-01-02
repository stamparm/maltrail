#!/usr/bin/env python

"""
Copyright (c) 2014-2025 Maltrail developers (https://github.com/stamparm/maltrail/)
See the file 'LICENSE' for copying permission
"""

from core.common import retrieve_content

__url__ = "https://raw.githubusercontent.com/futpib/policeman-rulesets/master/examples/simple_domains_blacklist.txt"
__check__ = "malwaredomains.com"
__info__ = "malware"
__reference__ = "malwaredomains.com"

def fetch():
    retval = {}
    content = retrieve_content(__url__)

    if __check__ in content:
        for line in content.split('\n'):
            line = line.strip().lower()
            if not line or line.startswith('#') or '.' not in line or line in ("api.ipify.org",):
                continue
            retval[line] = (__info__, __reference__)

    return retval
