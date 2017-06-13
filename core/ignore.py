#!/usr/bin/env python
"""
simple ignore rule configured by file misc/ignore_event.txt

example:

#sintax:
#src_ip;src_port;dst_ip;dst_port
#
#
#this is a comment
#
# ignore all from source ip 192.168.0.3
192.168.0.3;*;*;*
#
# ignore all request to ssh port 22
*;*;22;*

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
                print("[i] IGNORE parse line: %s " % (line))
                if not line or line.startswith('#'):
                    continue
                else:
                    try:
                        src_ip, src_port, dst_ip, dst_port = line.split(';')
                        print("[i] IGNORE add src_ip=%s, src_port=%s, dst_ip=%s, dst_port=%s " % (src_ip, src_port, dst_ip, dst_port)) 
                        INGORE_EVENT.add(  (src_ip, src_port, dst_ip, dst_port)  )
                    except (IndexError, ValueError):
                        print("[i] IGNORE ERROR, skil config line %s" % line)
             



def ignore_event(event_tuple):
    sec, usec, src_ip, src_port, dst_ip, dst_port, proto, trail_type, trail, info, reference = event_tuple
    #print("[i] ignore_event")
    for I_src_ip, I_src_port, I_dst_ip, I_dst_port in INGORE_EVENT:
        if I_src_ip != "*" and I_src_ip != src_ip :
            continue
        if I_src_port != "*" and I_src_port != src_port :
            continue
        if I_dst_ip != "*" and I_dst_ip != dst_ip :
            continue
        if I_dst_port != "*" and I_dst_port != dst_port :
            continue
        #print("[i] IGNORE src_ip=%s, src_port=%s, dst_ip=%s, dst_port=%s " % (src_ip, src_port, dst_ip, dst_port))
        return True
    return False
