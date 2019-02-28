#!/usr/bin/env python

"""
Copyright (c) 2014-2019 Miroslav Stampar (@stamparm)
See the file 'LICENSE' for copying permission
"""

class AttribDict(dict):
    def __getattr__(self, name):
        return self.get(name)

    def __setattr__(self, name, value):
        self[name] = value