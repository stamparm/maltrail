#!/usr/bin/env python

"""
Copyright (c) 2014-2025 Maltrail developers (https://github.com/stamparm/maltrail/)
See the file 'LICENSE' for copying permission
"""

import glob
import os
import re

from core.settings import UNICODE_ENCODING
from thirdparty import six

__url__ = "(static)"

def fetch():
    retval = {}

    directories = [os.path.dirname(__file__)] + glob.glob(os.path.join(os.path.dirname(__file__), "*"))
    directories = sorted(directories, key=lambda _: -1 if any(__ in _ for __ in ("suspicious", "malicious")) else int("custom" in _))

    for directory in directories:
        if not os.path.isdir(directory):
            continue

        category = os.path.split(directory)[-1]
        if category == "static":
            category = None

        for filename in glob.glob(os.path.join(directory, "*.csv")):
            __reference__ = "%s (static)" % os.path.splitext(os.path.basename(filename))[0]
            with open(filename, "rb") as f:
                for line in f:
                    if six.PY3:
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

        filenames = glob.glob(os.path.join(directory, "*.txt"))
        filenames = sorted(filenames, key=lambda _: "history" in _)

        __reference__ = "(static)"
        for filename in filenames:
            __info__ = os.path.splitext(os.path.basename(filename))[0].replace('_', " ")
            if category:
                __info__ = "%s (%s)" % (__info__, category)

            with open(filename, "rb") as f:
                for line in f:
                    if six.PY3:
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
