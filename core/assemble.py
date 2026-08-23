#!/usr/bin/env python

"""
Copyright (c) 2014-2026 Maltrail developers (https://github.com/stamparm/maltrail/)
See the file 'LICENSE' for copying permission
"""

import glob
import os
import re

from core.settings import UNICODE_ENCODING

__url__ = "(static)"

def fetch():
    retval = {}

    # glob() hands back DIRECTORY ORDER, and both sorts below are stable, so within a group the
    # order was whatever the filesystem happened to hold. An indicator listed in two piles is
    # labelled by whichever file is read LAST, so that arbitrary order decided the label - and it
    # changes when files are rewritten or the tree is re-checked out. Found by rebuilding the set
    # before and after a commit that only edited comment lines: same 1,632,336 keys, 5,950 of them
    # differently attributed (metamorfo vs latentbot, cobaltstrike-1 vs -2, ...). Sort by name
    # first, so the same checkout builds the same trails.csv on every machine.
    directories = [os.path.dirname(__file__)] + sorted(glob.glob(os.path.join(os.path.dirname(__file__), "*")))
    directories = sorted(directories, key=lambda _: -1 if any(__ in _ for __ in ("suspicious", "malicious")) else int("custom" in _))

    for directory in directories:
        if not os.path.isdir(directory):
            continue

        category = os.path.split(directory)[-1]
        if category == "static":
            category = None

        for filename in sorted(glob.glob(os.path.join(directory, "*.csv"))):
            __reference__ = "%s (static)" % os.path.splitext(os.path.basename(filename))[0]
            with open(filename, "rb") as f:
                for line in f:
                    line = line.decode(UNICODE_ENCODING)
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    value, __info__ = line.split(',', 1)
                    __info__ = __info__.strip('"')
                    if category:
                        __info__ = "%s (%s)" % (__info__, category)
                    if '://' in value:
                        value = re.search(r"://(.*)", value).group(1)
                    value = value.rstrip('/')
                    if '/' in value:
                        retval[value] = (__info__, __reference__)
                        value = value.split('/')[0]
                    elif re.search(r"\A\d+\.\d+\.\d+\.\d+\Z", value):
                        retval[value] = (__info__, __reference__)
                    else:
                        retval[value.strip('.')] = (__info__, __reference__)

        filenames = sorted(glob.glob(os.path.join(directory, "*.txt")))
        filenames = sorted(filenames, key=lambda _: "history" in _)

        __reference__ = "(static)"
        for filename in filenames:
            __info__ = os.path.splitext(os.path.basename(filename))[0].replace('_', " ")
            if category:
                __info__ = "%s (%s)" % (__info__, category)

            with open(filename, "rb") as f:
                for line in f:
                    line = line.decode(UNICODE_ENCODING)
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    line = re.sub(r"\s*#.*", "", line)
                    if '://' in line:
                        line = re.search(r"://(.*)", line).group(1)
                        if '/' not in line:
                            line = "%s/" % line
                    if '/' in line:
                        if line.count('/') > 1:
                            line = line.rstrip('/')
                        retval[line] = (__info__, __reference__)
                        line = line.split('/')[0]
                    elif re.search(r"\A\d+\.\d+\.\d+\.\d+\Z", line):
                        retval[line] = (__info__, __reference__)
                    else:
                        retval[line.strip('.')] = (__info__, __reference__)

    return retval
