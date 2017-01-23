#!/usr/bin/env python

import re

from core.common import retrieve_content

__url__ = "https://www.maxmind.com/en/high-risk-ip-sample-list"
__check__ = "Sample List of Higher Risk IP Addresses"
__info__ = "high risk ip (suspicious)"
__reference__ = "maxmind.com"

def fetch():
    retval = {}
    content = retrieve_content(__url__)

    if __check__ in content:
        for match in re.finditer(r"high-risk-ip-sample/([\d.]+)", content):
            retval[match.group(1)] = (__info__, __reference__)

    return retval
