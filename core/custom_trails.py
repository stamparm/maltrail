#!/usr/bin/env python

"""
Copyright (c) 2014-present Maltrail developers (https://github.com/stamparm/maltrail/)
See the file 'LICENSE' for copying permission
"""

import glob
import os
import re

from core.settings import config
from core.settings import ROOT_DIR
from core.settings import UNICODE_ENCODING

__url__ = "(custom)"
__reference__ = "(custom)"

# An operator's own indicators, from CUSTOM_TRAILS_DIR.
#
# This used to be a directory inside the checkout (trails/custom/) that pretended to be a feed: an
# __init__.py with a fetch(), discovered by globbing and imported by basename, so that
# update_trails() could run one loop over "feeds". The interface bought exactly one thing - a
# progress line - and cost two: the operator's private files lived inside a git tree (which is why
# install.sh must never run `git clean`), and because the directory was appended to the feed list,
# `DISABLED_FEEDS custom` silently disabled it. Both are gone; this is a plain function now.
#
# CUSTOM_TRAILS_URL is deliberately NOT merged in here. It looks like the same thing but it is not:
# it writes straight into the merged set, skipping keys already covered by a custom/static source,
# and it expands small CIDR ranges. Those are merge-time rules, not fetch-time ones, so it stays in
# core/update.py until something proves the two can be unified without moving an indicator.


def fetch():
    """Every trail under CUSTOM_TRAILS_DIR, as {trail: (info, reference)}.

    Unset CUSTOM_TRAILS_DIR means the operator has no custom trails. It used to mean "read the
    directory this module lives in", which is how user data ended up inside the repository.
    """

    retval = {}

    if not config.CUSTOM_TRAILS_DIR:
        return retval

    directory = os.path.abspath(os.path.join(ROOT_DIR, os.path.expanduser(config.CUSTOM_TRAILS_DIR)))

    if not os.path.isdir(directory):
        # Say so. A typo here used to be indistinguishable from "no custom trails configured", and
        # the operator's own indicators - the ones they trust most - would just never load.
        print("[!] 'CUSTOM_TRAILS_DIR' is set to '%s', which is not a directory (no custom trails loaded)" % directory)
        return retval

    for filename in sorted(glob.glob(os.path.join(directory, "*.txt"))):
        info = os.path.splitext(os.path.basename(filename))[0].replace('_', " ")
        with open(filename, "rb") as f:
            for line in f:
                line = line.decode(UNICODE_ENCODING)
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                line = re.sub(r"\s*#.*", "", line)
                if '://' in line:
                    line = re.search(r"://(.*)", line).group(1)
                line = line.rstrip('/')
                if '/' in line:
                    retval[line] = (info, __reference__)
                    line = line.split('/')[0]
                elif re.search(r"\A\d+\.\d+\.\d+\.\d+\Z", line):
                    retval[line] = (info, __reference__)
                else:
                    retval[line.strip('.')] = (info, __reference__)

    return retval
