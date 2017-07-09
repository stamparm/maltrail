#!/usr/bin/env python

"""
Copyright (c) 2014-2017 Miroslav Stampar (@stamparm)
See the file 'LICENSE' for copying permission
"""

# simple ignore rule mechanism configured by file 'misc/ignore_event.txt' and/or user defined `USER_IGNORELIST`

import csv
import gzip
import os
import re
import sqlite3
import StringIO
import subprocess
import urllib2
import zipfile
import zlib
       
from core.settings import config
from core.settings import INGORE_EVENTS

def ignore_event(event_tuple):
    retval = False
    _, _, src_ip, src_port, dst_ip, dst_port, _, _, _, _, _ = event_tuple

    for ignore_src_ip, ignore_src_port, ignore_dst_ip, ignore_dst_port in INGORE_EVENTS:
        if ignore_src_ip != "*" and ignore_src_ip != src_ip :
            continue
        if ignore_src_port != "*" and ignore_src_port != str(src_port) :
            continue
        if ignore_dst_ip != "*" and ignore_dst_ip != dst_ip :
            continue
        if ignore_dst_port != "*" and ignore_dst_port != str(dst_port) :
            continue
        retval = True
        break
    
    if config.SHOW_DEBUG:
        print("[i] ignore_event src_ip=%s, src_port=%s, dst_ip=%s, dst_port=%s, retval=%s" % (src_ip, src_port, dst_ip, dst_port, retval)) 
    return retval
