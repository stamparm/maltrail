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
192.168.0.3;*;*;*
#
# ignore all events to ssh port 22
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
             
from core.settings import INGORE_EVENT


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
