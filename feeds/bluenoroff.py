#!/usr/bin/env python

"""
Copyright (c) 2014-2026 Maltrail developers (https://github.com/stamparm/maltrail/)
See the file 'LICENSE' for copying permission
"""

from core.common import retrieve_content

__url__ = "https://raw.githubusercontent.com/farbodghasemlu/bluenoroff-fake-meeting-kit/main/iocs/indicators.csv"
__check__ = "microteam"
__info__ = "bluenoroff fake meeting kit"
__reference__ = "github.com/farbodghasemlu/bluenoroff-fake-meeting-kit"

def fetch():
    retval = {}
    content = retrieve_content(__url__)

    if __check__ in content:
        for line in content.split('\n'):
            line = line.strip()
            if not line or line.startswith('type,') or line.startswith('#'):
                continue
            parts = line.split(',')
            if len(parts) < 2:
                continue
            kind, value = parts[0].strip(), parts[1].strip()
            if kind not in ("domain", "ip"):
                continue
            if not value or '.' not in value:
                continue
            retval[value] = (__info__, __reference__)

    return retval
