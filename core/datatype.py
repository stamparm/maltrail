#!/usr/bin/env python

from thirdparty.odict import OrderedDict

# Reference: https://www.kunxi.org/2014/05/lru-cache-in-python
class LRUDict(object):
    """
    This class defines the LRU dictionary

    >>> foo = LRUDict(capacity=2)
    >>> foo["first"] = 1
    >>> foo["second"] = 2
    >>> foo["third"] = 3
    >>> "first" in foo
    False
    >>> "third" in foo
    True
    """

    def __init__(self, capacity):
        self.capacity = capacity
        self.cache = OrderedDict()

    def __len__(self):
        return len(self.cache)

    def __contains__(self, key):
        return key in self.cache

    def __getitem__(self, key):
        try:
            value = self.cache.pop(key)
            self.cache[key] = value
        except:
            value = None

        return value

    def get(self, key):
        return self.__getitem__(key)

    def __setitem__(self, key, value):
        try:
            self.cache.pop(key)
        except KeyError:
            if len(self.cache) >= self.capacity:
                self.cache.popitem(last=False)
        self.cache[key] = value

    def set(self, key, value):
        self.__setitem__(key, value)

    def keys(self):
        return self.cache.keys()
