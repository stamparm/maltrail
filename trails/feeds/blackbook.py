#!/usr/bin/env python

"""
Copyright (c) 2014-2025 Maltrail developers (https://github.com/stamparm/maltrail/)
See the file 'LICENSE' for copying permission
"""

from core.common import retrieve_content

__url__ = "https://raw.githubusercontent.com/stamparm/blackbook/master/blackbook.csv"
__check__ = "Malware"
__reference__ = "github.com/stamparm/blackbook"

def fetch():
    retval = {}
    content = retrieve_content(__url__)

    if __check__ in content:
        for line in content.split('\n'):
            line = line.strip()
            if not line or line.startswith('#') or '.' not in line:
                continue
            retval[line.split(',')[0].strip()] = ("%s (malware)" % line.split(',')[1].strip(), __reference__)

    return retval
