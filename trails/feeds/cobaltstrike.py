#!/usr/bin/env python

"""
Copyright (c) 2014-2025 Maltrail developers (https://github.com/stamparm/maltrail/)
See the file 'LICENSE' for copying permission
"""

import datetime

from core.common import retrieve_content

__url__ = "https://raw.githubusercontent.com/fox-it/cobaltstrike-extraneous-space/master/cobaltstrike-servers.csv"
__check__ = "last_seen"
__info__ = "cobalt strike (adversary)"
__reference__ = "github.com/fox-it"

def fetch():
    retval = {}
    content = retrieve_content(__url__)

    if __check__ in content:
        for line in content.split('\n'):
            line = line.strip()
            if not line or line.startswith('#') or not all(_ in line for _ in ('.', ',')):
                continue
            parts = line.split(',')
            if (datetime.datetime.now() - datetime.datetime.strptime(parts[-1], "%Y-%M-%d")).days < 120:
                retval["%s:%s" % (parts[0], parts[1])] = (__info__, __reference__)

    return retval
