#!/usr/bin/env python

"""
Copyright (c) 2014-2025 Maltrail developers (https://github.com/stamparm/maltrail/)
See the file 'LICENSE' for copying permission
"""

import binascii
import re

from core.common import retrieve_content

__url__ = "https://rules.emergingthreats.net/open/suricata/rules/emerging-malware.rules"
__check__ = "Emerging Threats"
__info__ = "malware"
__reference__ = "emergingthreats.net"

def fetch():
    retval = {}
    content = retrieve_content(__url__)

    if __check__ in content:
        for match in re.finditer(r'(?i)(CnC DNS Query|C2 Domain|CnC Domain)[^\n]+(dns.query|tls.sni); content:"([^"]+)', content):
            candidate = match.group(3).lower().strip('.').split("//")[-1]
            candidate = re.sub(r"\|([^|]+)\|", lambda match: binascii.unhexlify(match.group(1).replace(" ", "")).decode(), candidate)
            if '.' in candidate:
                retval[candidate] = (__info__, __reference__)

    return retval
