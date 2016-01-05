#!/usr/bin/env python

"""
Copyright (c) 2014-2016 Miroslav Stampar (@stamparm)
See the file 'LICENSE' for copying permission
"""

class AttribDict(dict):
    def __getattr__(self, name):
        return self[name] if name in self else None

    def __setattr__(self, name, value):
        self[name] = value