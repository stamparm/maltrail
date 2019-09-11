#!/usr/bin/env python

"""
Copyright (c) 2014-2019 Maltrail developers (https://github.com/stamparm/maltrail/)
See the file 'LICENSE' for copying permission
"""

import sre_compile
import sys

from sre_compile import _code
from sre_compile import isstring
from sre_compile import _sre
from sre_compile import sre_parse

if sys.version_info >= (3, 0):
    xrange = range
else:
    xrange = xrange
