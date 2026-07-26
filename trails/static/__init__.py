#!/usr/bin/env python

"""
Copyright (c) 2014-2026 Maltrail developers (https://github.com/stamparm/maltrail/)
See the file 'LICENSE' for copying permission
"""

import glob
import os
import re

from core.settings import UNICODE_ENCODING
from thirdparty import six

__url__ = "(static)"

_non_domains = set()

def _is_domain(value):
    if not value or '.' not in value or len(value) > 255:
        return False

    labels = value.split('.')
    if re.search(r"\A\d+\Z", labels[-1]):
        return False

    for label in labels:
        if not label or len(label) > 63 or label[0] == '-' or label[-1] == '-':
            return False
        if not re.search(r"\A[a-zA-Z0-9-]+\Z", label):
            return False

    return True

def fetch():
    retval = {}
    _non_domains.clear()

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
                        value = value.strip('.')
                        if _is_domain(value):
                            retval[value] = (__info__, __reference__)
                        elif value:
                            _non_domains.add(value)

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
                        line = line.strip('.')
                        if _is_domain(line):
                            retval[line] = (__info__, __reference__)
                        elif line:
                            _non_domains.add(line)

    return retval
