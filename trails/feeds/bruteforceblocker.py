#!/usr/bin/env python

"""
Copyright (c) 2014-2025 Maltrail developers (https://github.com/stamparm/maltrail/)
See the file 'LICENSE' for copying permission
"""

from core.common import retrieve_content

__url__ = "http://danger.rulez.sk/projects/bruteforceblocker/blist.php"
__check__ = "Last Reported"
__info__ = "known attacker"
__reference__ = "rulez.sk"

def fetch():
    retval = {}
    content = retrieve_content(__url__)

    if __check__ in content:
        for line in content.split('\n'):
            line = line.strip()
            if not line or line.startswith('#') or '.' not in line:
                continue
            retval[line.split('\t')[0]] = (__info__, __reference__)

    return retval
