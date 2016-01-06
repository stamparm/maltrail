#!/usr/bin/env python

"""
Copyright (c) 2014-2016 Miroslav Stampar (@stamparm)
See the file 'LICENSE' for copying permission
"""

import re

from core.common import retrieve_content

__url__ = "https://intel.deepviz.com/recap_network.php?tw=7d&active=network_domains"
__check__ = "Deepviz Threat Intel"
__reference__ = "deepviz.com"

def fetch():
    retval = {}
    content = retrieve_content(__url__)

    if __check__ in content:
        for match in re.finditer(r"(?m)^([\d.]+),IP used by ([^,]+) C&C", content):
            retval[match.group(1)] = ("%s (malware)" % match.group(2).lower(), __reference__)

    for row in re.finditer(r"(?s)<tr>(.+?)</tr>", content):
        if "<span>100%</span>" in row.group(1):
            domain = re.search(r"get_data_domain\('([^']+)", row.group(1))
            if domain:
                tag = re.search(r">(trojan|spyware|adware)\.([^<]+)", row.group(1))
                retval[domain.group(1)] = (("%s (malware)" % tag.group(2)) if tag else "malware", __reference__)

    return retval
