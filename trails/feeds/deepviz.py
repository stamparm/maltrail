#!/usr/bin/env python

"""
Copyright (c) 2014-2017 Miroslav Stampar (@stamparm)
See the file 'LICENSE' for copying permission
"""

import re

from core.common import retrieve_content

#__url__ = "https://intel.deepviz.com/recap_network.php?tw=7d&active=network_domains"
__url__ = "https://intel.deepviz.com/recap/network/"
__check__ = "Deepviz"
__reference__ = "deepviz.com"

def fetch():
    retval = {}
    content = retrieve_content(__url__)

    if __check__ in content:
        for row in re.finditer(r"(?s)<tr>(.+?)</tr>", content):
            if "MalwareConnection" in row.group(1):
                match = re.search(r"<strong>([^<]+)</strong></td><td><div class='max-200'>", row.group(1))
                if match:
                    retval[match.group(1)] = ("malware", __reference__)

    return retval
