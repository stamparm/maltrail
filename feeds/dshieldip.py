#!/usr/bin/env python

"""
Copyright (c) 2014-2026 Maltrail developers (https://github.com/stamparm/maltrail/)
See the file 'LICENSE' for copying permission
"""

from core.addr import expand_range
from core.common import retrieve_content

# dshield_top_1000 froze in June 2021. The 1d netset is the list DShield actually still
# publishes - the /24s its sensors saw attacking in the last day - and it updates daily. The
# ranges are expanded into addresses when the trail set is merged; see core/update.py.
__url__ = "https://iplists.firehol.org/files/dshield_1d.netset"
__check__ = ".1"
# NOT "known attacker". The feed publishes SUBNETS, and expanding a /24 means 255 of its 256
# addresses were never seen attacking anything - the observation is about the network, not about
# the host. "bad reputation (attacking subnet)" is the claim the data actually supports, and it
# matches how the tor and bitcoin node feeds qualify the same word.
__info__ = "bad reputation (attacking subnet)"
__reference__ = "dshield.org"

# Narrowest prefix expanded: /22 is 1,024 addresses. DShield publishes /24s; this is the guard for
# the day it does not.
MAX_PREFIX = 22

def fetch():
    retval = {}
    content = retrieve_content(__url__)

    if __check__ in content:
        for line in content.split('\n'):
            line = line.strip()
            if not line or line.startswith('#') or '.' not in line:
                continue
            entry = line.split()[0]

            # The netset is networks, and a trail is matched by exact string: a "1.2.3.0/24" key
            # is never what a packet's address renders as, so it would sit in the set matching
            # nothing. Expanded here, where blocking the whole network is what DShield means by
            # publishing it - these are the subnets its sensors saw attacking in the last day.
            #
            # Bounded on purpose. A /24 is 256 addresses; anything wider than MAX_PREFIX would
            # put thousands of never-observed addresses in the set under "known attacker", which
            # is a false-positive surface rather than a detection. If the feed ever widens, this
            # says so instead of silently ingesting it.
            if '/' in entry:
                try:
                    width = int(entry.split('/')[1])
                except ValueError:
                    continue
                if width < MAX_PREFIX:
                    print("[!] '%s' skipped: /%d is wider than the /%d this feed expands" % (entry, width, MAX_PREFIX))
                    continue
                for address in expand_range(entry):
                    retval[address] = (__info__, __reference__)
            else:
                retval[entry] = (__info__, __reference__)

    return retval
