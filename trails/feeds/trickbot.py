#!/usr/bin/env python

"""
Copyright (c) 2014-2019 Miroslav Stampar (@stamparm)
See the file 'LICENSE' for copying permission
"""

import re

from core.addr import addr_to_int
from core.addr import int_to_addr
from core.addr import make_mask
from core.common import retrieve_content

__url__ = "https://github.com/JR0driguezB/malware_configs"
__check__ = "mcconf"
__info__ = "trickbot (malware)"
__reference__ = "github.com/JR0driguezB"

def fetch():
    retval = {}
    content = retrieve_content("https://github.com/JR0driguezB/malware_configs/tree/master/TrickBot/mcconf_files")

    if __check__ in content:
        last = re.findall(r"config.conf_\d+.xml", content)[-1]
        content = retrieve_content("https://raw.githubusercontent.com/JR0driguezB/malware_configs/master/TrickBot/mcconf_files/%s" % last)
        if __check__ in content:
            for match in re.finditer(r"<srv>([\d.]+)", content):
                retval[match.group(1)] = (__info__, __reference__)

    return retval
