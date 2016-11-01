#!/usr/bin/env python

"""

Yunus YILDIRIM (@Th3Gundy)

"""

import json
from core.common import retrieve_content

__url__ = "http://data.phishtank.com/data/online-valid.json"
__check__ = "phishtank"
__info__ = "phishing"
__reference__ = "phishtank.com"

def fetch():
    retval = {}
    content = retrieve_content(__url__)

    if __check__ in content:
        data = json.loads(content)
        for line in data:
            line = line["url"].strip().rstrip('/')
            retval[line] = (__info__, __reference__)

    return retval
