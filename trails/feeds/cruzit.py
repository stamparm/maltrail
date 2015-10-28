#!/usr/bin/env python

"""
Copyright (c) 2014-2015 Miroslav Stampar (@stamparm)
See the file 'LICENSE' for copying permission
"""

from core.common import retrieve_content

__url__ = "http://www.cruzit.com/xwbl2txt.php"
__check__ = "ipaddress"
__info__ = "attacker"
__reference__ = "cruzit.com"

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
