#!/usr/bin/env python

"""
Copyright (c) 2014-2016 Miroslav Stampar (@stamparm)
See the file 'LICENSE' for copying permission
"""

import re

from core.addr import addr_to_int
from core.addr import int_to_addr
from core.addr import make_mask
from core.common import retrieve_content

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
            start_int = addr_to_int(prefix) & make_mask(mask)
            end_int = start_int | ((1 << 32 - mask) - 1)
            if 0 <= end_int - start_int <= 1024:
                address = start_int
                while start_int <= address <= end_int:
                    retval[int_to_addr(address)] = (__info__, __reference__)
                    address += 1

    return retval
