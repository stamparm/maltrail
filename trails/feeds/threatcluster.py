#!/usr/bin/env python

"""
Copyright (c) 2014-2026 Maltrail developers (https://github.com/stamparm/maltrail/)
See the file 'LICENSE' for copying permission
"""

from core.common import retrieve_content

__url__ = "https://threatcluster.io/api/iocs/public/domains.txt#https://threatcluster.io/api/iocs/public/ips.txt"
__check__ = "ThreatCluster public IOC feed"
__info__ = "malicious"
__reference__ = "threatcluster.io"

def fetch():
    retval = {}

    for url in __url__.split('#'):
        content = retrieve_content(url)

        if __check__ in content:
            for line in content.split('\n'):
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                retval[line] = (__info__, __reference__)

    return retval
