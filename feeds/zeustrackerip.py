#!/usr/bin/env python

"""
Copyright (c) 2014-2015 Miroslav Stampar (@stamparm)
See the file 'LICENSE' for copying permission
"""

import re

from core.common import retrieve_content
from core.common import BLACKLIST

__type__ = (BLACKLIST.IP,)
__url__ = "https://zeustracker.abuse.ch/blocklist.php?download=badips"
__check__ = "ZeuS"
__info__ = "ZeuS C&C"
__reference__ = "zeustracker.abuse.ch"

def fetch():
    retval = dict((_, {}) for _ in __type__)
    content = retrieve_content(__url__)

    if __check__ in content:
        for line in content.split('\n'):
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            retval[BLACKLIST.IP][line] = (__info__, __reference__)

    return retval
