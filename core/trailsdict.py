#!/usr/bin/env python

"""
Copyright (c) 2014-2025 Maltrail developers (https://github.com/stamparm/maltrail/)
See the file 'LICENSE' for copying permission
"""

import re

class TrailsDict(dict):
    def __init__(self):
        self._trails = {}
        self._regex = ""
        self._infos = []
        self._reverse_infos = {}
        self._references = []
        self._reverse_references = {}

    def __delitem__(self, key):
        del self._trails[key]

    def has_key(self, key):
        return key in self._trails

    def __contains__(self, key):
        return key in self._trails

    def clear(self):
        self.__init__()

    def keys(self):
        return self._trails.keys()

    def iterkeys(self):
        for key in self._trails.keys():
            yield key

    def __iter__(self):
        for key in self._trails.keys():
            yield key

    def get(self, key, default=None):
        if key in self._trails:
            _ = self._trails[key].split(',')
            if len(_) == 2:
                return (self._infos[int(_[0])], self._references[int(_[1])])

        return default

    def update(self, value):
        if isinstance(value, TrailsDict):
            if not self._trails:
                for attr in dir(self):
                    if re.search(r"\A_[a-z]", attr):
                        setattr(self, attr, getattr(value, attr))
            else:
                for key in value:
                    self[key] = value[key]
        elif isinstance(value, dict):
            for key in value:
                info, reference = value[key]
                if info not in self._reverse_infos:
                    self._reverse_infos[info] = len(self._infos)
                    self._infos.append(info)
                if reference not in self._reverse_references:
                    self._reverse_references[reference] = len(self._references)
                    self._references.append(reference)
                self._trails[key] = "%d,%d" % (self._reverse_infos[info], self._reverse_references[reference])
        else:
            raise Exception("unsupported type '%s'" % type(value))

    def __len__(self):
        return len(self._trails)

    def __getitem__(self, key):
        if key in self._trails:
            _ = self._trails[key].split(',')
            if len(_) == 2:
                return (self._infos[int(_[0])], self._references[int(_[1])])

        raise KeyError(key)

    def __setitem__(self, key, value):
        if isinstance(value, (tuple, list)):
            info, reference = value
            if info not in self._reverse_infos:
                self._reverse_infos[info] = len(self._infos)
                self._infos.append(info)
            if reference not in self._reverse_references:
                self._reverse_references[reference] = len(self._references)
                self._references.append(reference)
            self._trails[key] = "%d,%d" % (self._reverse_infos[info], self._reverse_references[reference])
        else:
            raise Exception("unsupported type '%s'" % type(value))
