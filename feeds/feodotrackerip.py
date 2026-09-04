#!/usr/bin/env python

"""
Copyright (c) 2014-present Maltrail developers (https://github.com/stamparm/maltrail/)
See the file 'LICENSE' for copying permission
"""

from core.common import retrieve_content

# The 'ipblocklist_recommended.txt' this used to read now returns a header and nothing else, so
# the feed had been contributing zero indicators. The CSV is the one Feodo Tracker still fills.
__url__ = "https://feodotracker.abuse.ch/downloads/ipblocklist.csv"
__check__ = "dst_ip"
__reference__ = "abuse.ch"

# Only currently-online C2s. The CSV also carries offline history, and an address that stopped
# serving a botnet years ago has usually been reassigned to something innocent since - listing
# those trades a dead detection for a live false positive.
def fetch():
    retval = {}
    content = retrieve_content(__url__)

    if __check__ in content:
        for line in content.split('\n'):
            line = line.strip()
            if not line or line.startswith('#'):
                continue

            parts = [_.strip().strip('"') for _ in line.split(',')]
            if len(parts) < 6 or parts[1] == "dst_ip":
                continue

            ip, status, malware = parts[1], parts[3].lower(), parts[5].lower()
            if status != "online" or not ip:
                continue

            retval[ip] = ("%s (malware)" % (malware or "feodo"), __reference__)

    return retval
