#!/usr/bin/env python

"""
Copyright (c) 2014-2015 Miroslav Stampar (@stamparm)
See the file 'LICENSE' for copying permission
"""

import re

from core.common import addr_to_int
from core.common import int_to_addr
from core.common import make_mask
from core.common import retrieve_content
from core.settings import MIN_BLACKLIST_MASK
from core.settings import MAX_BLACKLIST_MASK

__url__ = "http://www.voipbl.org/update/"
__check__ = "TOTAL NETBLOCK"
__info__ = "attacker"
__reference__ = "voipbl.org"

def fetch():
    retval = {}
    content = retrieve_content(__url__)

    if __check__ in content:
        for match in re.finditer(r"(\d+\.\d+\.\d+\.\d+)/(\d+)", content):
            prefix, mask = match.groups()
            mask = int(mask)
            if MIN_BLACKLIST_MASK <= mask <= MAX_BLACKLIST_MASK:
                start_int = addr_to_int(prefix) & make_mask(mask)
                end_int = start_int | ((1 << 32 - mask) - 1)
                for address in xrange(start_int, end_int + 1):
                    retval[int_to_addr(address)] = (__info__, __reference__)

    return retval
