#!/usr/bin/env python

"""
Copyright (c) 2014-2016 Miroslav Stampar (@stamparm)
See the file 'LICENSE' for copying permission
"""

import glob
import os
import re

__url__ = "(static)"

def fetch():
    retval = {}

    for directory in [os.path.dirname(__file__)] + glob.glob(os.path.join(os.path.dirname(__file__), "*")):
        if not os.path.isdir(directory):
            continue

        category = os.path.split(directory)[-1]
        if category == "static":
            category = None

        __reference__ = "(static)"
        for filename in glob.glob(os.path.join(directory, "*.txt")):
            __info__ = os.path.splitext(os.path.basename(filename))[0].replace('_', " ")
            if category:
                __info__ = "%s (%s)" % (__info__, category)

            content = open(filename, "rb").read()
            for line in content.split('\n'):
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                line = re.sub(r"\s*#.+", "", line)
                if '://' in line:
                    line = re.search(r"://(.*)", line).group(1)
                line = line.rstrip('/')
                if '/' in line:
                    retval[line] = (__info__, __reference__)
                    line = line.split('/')[0]
                elif re.search(r"\A\d+\.\d+\.\d+\.\d+\Z", line):
                    retval[line] = (__info__, __reference__)
                else:
                    retval[line.strip('.')] = (__info__, __reference__)

        for filename in glob.glob(os.path.join(directory, "*.csv")):
            __reference__ = "%s (static)" % os.path.splitext(os.path.basename(filename))[0]
            content = open(filename, "rb").read()
            for line in content.split('\n'):
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

    return retval
