#!/usr/bin/env python

"""
Copyright (c) 2014-2018 Miroslav Stampar (@stamparm)
See the file 'LICENSE' for copying permission
"""

import sys

def plugin(event_tuple, packet=None):
    sys.stdout.write("TEST PLUGIN")
