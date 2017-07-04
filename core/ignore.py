#!/usr/bin/env python
"""
simple ignore rule configured by file misc/ignore_event.txt

example:

#sintax:
#src_ip;src_port;dst_ip;dst_port
#
#  '*' is use for any
#
# ignore all events from source ip 192.168.0.3
# 192.168.0.3;*;*;*
#
# ignore all events to ssh port 22
# *;*;*;22

"""

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
        if ignore_src_port != "*" and ignore_src_port != src_port :
            continue
        if ignore_dst_ip != "*" and ignore_dst_ip != dst_ip :
            continue
        if ignore_dst_port != "*" and ignore_dst_port != dst_port :
            continue
        retval = True
        break
    
    if config.SHOW_DEBUG:
        print("[i] ignore_event src_ip=%s, src_port=%s, dst_ip=%s, dst_port=%s, retval=%s" % (src_ip, src_port, dst_ip, dst_port, retval)) 
    return retval
