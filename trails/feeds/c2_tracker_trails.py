#!/usr/bin/env python3
# C2-Tracker Feed (https://github.com/montysecurity/C2-Tracker)
# c2tracker.com live chart

from core.common import retrieve_content

__url__ = "https://raw.githubusercontent.com/montysecurity/C2-Tracker/main/data/all.txt"
__info__ = "C2-Tracker #malicious C2 IP"
__reference__ = "github.com/montysecurity/C2-Tracker"

def fetch():
    retval = {}
    content = retrieve_content(__url__)

    if content:
        for line in content.split('\n'):
            line = line.strip()
            if not line or line.startswith('#') or line.count('.') != 3:
                continue
            retval[line] = (__info__, __reference__)

    return retval
