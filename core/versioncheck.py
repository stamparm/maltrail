#!/usr/bin/env python

"""
Copyright (c) 2014-2020 Maltrail developers (https://github.com/stamparm/maltrail/)
See the file 'LICENSE' for copying permission
"""

import sys

PYVERSION = sys.version.split()[0]

if PYVERSION < "2.6":
    sys.exit("[%s] [CRITICAL] incompatible Python version detected ('%s'). To successfully run Maltrail you'll have to use version 2.6, 2.7 or 3.x (visit 'https://www.python.org/downloads/')" % PYVERSION)
