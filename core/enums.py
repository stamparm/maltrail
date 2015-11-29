#!/usr/bin/env python

"""
Copyright (c) 2014-2015 Miroslav Stampar (@stamparm)
See the file 'LICENSE' for copying permission
"""

class _(type):
   def __getattr__(self, attr):
     return attr

class TRAIL(object):
   __metaclass__ = _

class BLOCK_MARKER:
    NOP = chr(0x00)
    READ = chr(0x01)
    WRITE = chr(0x02)
    END = chr(0xFF)
