#!/usr/bin/env python

import re

from core.common import retrieve_content
from core.common import BLACKLIST

__type__ = (BLACKLIST.URL,)
__url__ = "http://vxvault.siri-urz.net/URL_List.php"
__check__ = "VX Vault"
__info__ = "malware"
__reference__ = "vxvault.siri-urz.net"

def fetch():
    retval = dict((_, {}) for _ in __type__)
    content = retrieve_content(__url__)

    if __check__ in content:
        for line in content.split('\n'):
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            if '://' in line:
                line = re.search(r"://(.*)", line).group(1)
                retval[BLACKLIST.URL][line] = (__info__, __reference__)

    return retval
