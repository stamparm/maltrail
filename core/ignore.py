#!/usr/bin/env python
"""
Copyright (c) 2014-2017 Miroslav Stampar (@stamparm)
See the file 'LICENSE' for copying permission
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


ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
INGORE_EVENT = set()

def init_ignore():
    INGORE_EVENT.clear()


    _ = os.path.abspath(os.path.join(ROOT_DIR, "misc", "ignore_event.txt"))
    if os.path.isfile(_):
        with open(_, "r") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                else:
                    try:
                        src_ip, src_port, dst_ip, dst_port = line.split(';')
                        INGORE_EVENT.add(  (src_ip, src_port, dst_ip, dst_port)  )
                    except (IndexError, ValueError):
                        INGORE_EVENT.add(line)
             



def ignore_event(event_tuple):
    sec, usec, src_ip, src_port, dst_ip, dst_port, proto, trail_type, trail, info, reference = event_tuple
    
    for I_src_ip, I_src_port, I_dst_ip, I_dst_port in INGORE_EVENT:
        if I_src_ip != '*' and I_src_ip != src_ip :
            continue
        if I_src_port != '*' and I_src_port != src_port :
            continue
        if I_dst_ip != '*' and I_dst_ip != dst_ip :
            continue
        if I_dst_port != '*' and I_dst_port != dst_port :
            continue
        
        return True
    return False