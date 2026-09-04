#!/usr/bin/env python

"""
Copyright (c) 2014-present Maltrail developers (https://github.com/stamparm/maltrail/)
See the file 'LICENSE' for copying permission
"""

import re

from core.common import retrieve_content

__url__ = "https://sslbl.abuse.ch/blacklist/ja3_fingerprints.csv"
__check__ = "JA3 Fingerprint Blacklist"
__reference__ = "abuse.ch"

# Trails here are JA3 fingerprints of TLS *client* hellos, matched by the sensor against the
# hello a CLIENT sends - the counterpart of sslblcert.py, where the certificate identifies the
# server that survives moving. An implant's TLS stack is what survives everything: the same
# binary phones home from every address it lands on with byte-identical hello fields, so the
# hash keeps matching after domains and IPs have rotated away.
#
# Deliberately classified BELOW malware severity, like sslblcert.py: a JA3 identifies one TLS
# stack configuration, not one binary - a listing means "a client that behaves like this
# implant's client", which is exact on the hash but not proof of the implant.
_MD5_REGEX = re.compile(r"\A[0-9a-f]{32}\Z")


def fetch():
    retval = {}
    content = retrieve_content(__url__)

    if __check__ in content:
        for line in content.split('\n'):
            line = line.strip()
            if not line or line.startswith('#'):
                continue

            parts = line.split(',')
            if len(parts) < 4:
                continue

            fingerprint = parts[0].strip().lower()
            if not _MD5_REGEX.match(fingerprint):
                continue

            # "Dridex" / "Possible Cobalt Strike" -> "dridex" / "cobalt strike"
            family = re.sub(r"(?i)\s*possible\s+", "", parts[3].strip()).strip()
            family = family.lower() or "unknown"

            # "ja3", not "fingerprint": this string is a column in the reporting table.
            retval[fingerprint] = ("%s tls client (suspicious)" % family, __reference__)

    return retval
