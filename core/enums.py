#!/usr/bin/env python

"""
Copyright (c) 2014-2015 Miroslav Stampar (@stamparm)
See the file 'LICENSE' for copying permission
"""

class TRAIL:
    DNS = "DNS"
    IP = "IP"
    HTTP = "HTTP"

class BLOCK_MARKER:
    NOP = chr(0x00)
    READ = chr(0x01)
    WRITE = chr(0x02)
    END = chr(0xFF)
