#!/usr/bin/env python

"""
Copyright (c) 2014-2015 Miroslav Stampar (@stamparm)
See the file 'LICENSE' for copying permission
"""

from core.common import retrieve_content
from core.enums import TRAIL

__type__ = (TRAIL.IP,)
__url__ = "http://danger.rulez.sk/projects/bruteforceblocker/blist.php"
__check__ = "Last Reported"
__info__ = "brute forcer"
__reference__ = "danger.rulez.sk"

def fetch():
    retval = dict((_, {}) for _ in __type__)
    content = retrieve_content(__url__)

    if __check__ in content:
        for line in content.split('\n'):
            line = line.strip()
            if not line or line.startswith('#') or '.' not in line:
                continue
            retval[TRAIL.IP][line.split('\t')[0]] = (__info__, __reference__)

    return retval
