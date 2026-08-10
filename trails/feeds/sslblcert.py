#!/usr/bin/env python

"""
Copyright (c) 2014-2026 Maltrail developers (https://github.com/stamparm/maltrail/)
See the file 'LICENSE' for copying permission
"""

import re

from core.common import retrieve_content

__url__ = "https://sslbl.abuse.ch/blacklist/sslblacklist.csv"
__check__ = "SSL Certificate Blacklist"
__reference__ = "abuse.ch"

# Trails here are SHA-1 fingerprints of TLS *server certificates*, matched by the sensor against
# the certificate a server presents (CHECK_TLS_CERTIFICATES). They are worth carrying because a
# certificate outlives the address and the domain: re-keying costs a C2 operator more than
# re-registering, so a fingerprint keeps matching after the other indicators have rotated away.
#
# Deliberately classified BELOW the malware families they belong to. A fingerprint identifies one
# specific certificate, so a match is exact and cannot be a near-miss -- but a handful of listings
# are dual-use remote-administration tooling (ConnectWise, NetSupport, MeshAgent), where the same
# certificate can legitimately appear in an estate that runs that software. Rating the whole feed
# as "suspicious" keeps those from producing high-severity alerts in a managed environment.
_SHA1_REGEX = re.compile(r"\A[0-9a-f]{40}\Z")


def fetch():
    retval = {}
    content = retrieve_content(__url__)

    if __check__ in content:
        for line in content.split('\n'):
            line = line.strip()
            if not line or line.startswith('#'):
                continue

            parts = line.split(',')
            if len(parts) < 3:
                continue

            fingerprint = parts[1].strip().lower()
            if not _SHA1_REGEX.match(fingerprint):
                continue

            # "AsyncRAT C&C" -> "asyncrat"
            family = re.sub(r"(?i)\s*(C&C|malware distribution)\s*\Z", "", parts[2].strip()).strip()
            family = family.lower() or "unknown"

            # The family name carries the dual-use warning by itself: an analyst reading
            # "connectwise c2 certificate" knows why it might be a legitimate estate.
            retval[fingerprint] = ("%s c2 certificate (suspicious)" % family, __reference__)

    return retval
