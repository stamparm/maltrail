#!/usr/bin/env python

"""
Copyright (c) 2014-present Maltrail developers (https://github.com/stamparm/maltrail/)
See the file 'LICENSE' for copying permission
"""

import csv
import re

from core.common import retrieve_content
from core.settings import config

# abuse.ch put every URLhaus download behind an Auth-Key in October 2026 (the old
# https://urlhaus.abuse.ch/downloads/text/ and its siblings answer "410 Gone"). The key goes in the
# path; it is substituted in fetch() only, so it never appears where __url__ is printed.
__url__ = "https://urlhaus-api.abuse.ch/v2/files/exports/<ABUSE_CH_AUTH_KEY>/recent.csv"
__check__ = "URLhaus"
__info__ = "malware"
__reference__ = "abuse.ch"
# Without the option this feed is skipped, with one line saying how to enable it (core/update.py)
__requires__ = "ABUSE_CH_AUTH_KEY"
__requires_hint__ = "a free Auth-Key from https://auth.abuse.ch/"

def fetch():
    retval = {}
    key = (config.ABUSE_CH_AUTH_KEY or "").strip()
    if not key:
        return retval

    content = retrieve_content(__url__.replace("<%s>" % __requires__, key))

    # case-insensitively: every row's urlhaus_link column says "urlhaus", whatever the header
    # does, and the 401 an invalid key gets ('{"status":401,"message":"Invalid auth token"}') does not
    if __check__.lower() in content.lower():
        # A '#' comment header naming the columns ("# id,dateadded,url,url_status,last_online,threat,
        # tags,urlhaus_link,reporter"), then quoted CSV rows. The url column is found by that name,
        # position 2 failing that - never "the first field that looks like a URL", which on a row
        # whose url is not http would take urlhaus_link and make abuse.ch itself a trail.
        column = 2
        for line in content.split('\n'):
            if line.startswith('#') and ",url," in line:
                column = [_.strip("# \r") for _ in line.split(',')].index("url")
                break
        for row in csv.reader(line for line in content.split('\n') if line.strip() and not line.startswith('#')):
            value = row[column].strip() if len(row) > column else ""
            if value.startswith("http") and "://" in value:
                retval[re.search(r"://(.*)", value).group(1)] = (__info__, __reference__)

    return retval
