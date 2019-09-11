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

def dirty_patch():
    def _compile(p, flags=0):
        # internal: convert pattern list to internal format

        if isstring(p):
            pattern = p
            p = sre_parse.parse(p, flags)
        else:
            pattern = None

        code = _code(p, flags)

        # print code

        ## XXX: <fl> get rid of this limitation!
        #if p.pattern.groups > 100:
            #raise AssertionError(
                #"sorry, but this version only supports 100 named groups"
                #)

        # map in either direction
        groupindex = p.pattern.groupdict
        indexgroup = [None] * p.pattern.groups
        for k, i in groupindex.items():
            indexgroup[i] = k

        return _sre.compile(
            pattern, flags | p.pattern.flags, code,
            p.pattern.groups-1,
            groupindex, indexgroup
            )

    sre_compile.compile = _compile

dirty_patch()