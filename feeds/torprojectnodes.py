#!/usr/bin/env python

"""
Copyright (c) 2014-2026 Maltrail developers (https://github.com/stamparm/maltrail/)
See the file 'LICENSE' for copying permission
"""

import json

from core.common import retrieve_content

# ALL running relays, not just exits. A Tor client connects to a GUARD relay and never to an exit,
# so an exit-only list cannot see a host on your own network using Tor - which is the case an
# office cares about, and the gap reported in issue #19163. Exits remain a separate feed
# (torproject.py) because they carry a different meaning: traffic arriving FROM one.
#
# Onionoo is the Tor Project's own metrics API, served from onionoo-backend-*.torproject.org, so
# unlike the community mirrors suggested on that issue it sits behind no CDN interstitial.
__url__ = "https://onionoo.torproject.org/details?type=relay&running=true&fields=or_addresses"
__check__ = "or_addresses"
__info__ = "bad reputation (tor node)"
__reference__ = "torproject.org"

# "bad reputation (...)" follows the convention the other infrastructure feeds use (compare
# bitcoinnodes.py). It also makes the merge order-independent: "reputation" is a
# LOW_PRIORITY_INFO_KEYWORD, so for an address that is BOTH a relay and an exit, the more specific
# "tor exit node (suspicious)" wins whichever of the two feeds is processed first. Being a relay is
# informational rather than an accusation, so low severity is the honest rating.


def fetch():
    retval = {}
    content = retrieve_content(__url__)

    if __check__ not in content:
        return retval

    try:
        relays = json.loads(content).get("relays") or []
    except ValueError:
        return retval

    for relay in relays:
        for address in relay.get("or_addresses") or []:
            address = address.strip()
            if not address:
                continue

            # "1.2.3.4:9001" or "[2001:db8::1]:9001"
            if address.startswith('['):
                host = address[1:address.find(']')] if ']' in address else ""
            else:
                host = address.rsplit(':', 1)[0]

            if host:
                retval[host] = (__info__, __reference__)

    return retval
