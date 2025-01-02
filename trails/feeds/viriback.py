#!/usr/bin/env python

"""
Copyright (c) 2014-2025 Maltrail developers (https://github.com/stamparm/maltrail/)
See the file 'LICENSE' for copying permission
"""

import re

from core.common import retrieve_content

__url__ = "http://tracker.viriback.com/dump.php"
__check__ = "Family,URL,IP,FirstSeen"
__info__ = "malware"
__reference__ = "viriback.com"

def fetch():
    retval = {}
    content = retrieve_content(__url__)

    if __check__ in content:
        for line in content.split('\n'):
            line = line.strip()
            if not line or line.startswith(__check__):
                continue
            if "://" in line:
                parts = line.lower().split(',')
                trail = parts[1].split("://")[-1].split('?')[0].split('#')[0]
                trail = re.sub("/[^/]+$", "", trail)
                trail = re.sub(r"/(web)?panel.*", "", trail)
                if re.search(r"\A\d[\d.]*\d\Z", trail):
                    trail = "%s/" % trail
                trail = trail.replace(".xsph.ru.xsph.ru", ".xsph.ru")
                retval[trail] = (parts[0], __reference__)

    return retval
