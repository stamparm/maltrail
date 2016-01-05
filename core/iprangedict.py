#!/usr/bin/env python

"""
Copyright (c) 2014-2016 Miroslav Stampar (@stamparm)
See the file 'LICENSE' for copying permission
"""

from core.addr import addr_to_int

class IPRangeDict(dict):
    def __init__(self):
        self.store = {}

    def _get_key(self, ip_address):
        if ip_address.isdigit():
            retval = int(ip_address) >> 16
        elif isinstance(ip_address, int):
            retval = ip_address >> 16
        else:
            _ = ip_address.split('.')
            retval = (int(_[0]) << 8) + int(_[1])

        return retval

    def __getitem__(self, ip_address):
        retval = None
        addr = addr_to_int(ip_address)
        key = self._get_key(ip_address)

        for item in self.store.get(key, []):
            start_int, end_int, value = item
            if start_int <= addr <= end_int:
                retval = value
                break

        return retval

    def __setitem__(self, ip_range, value):
        start, end = ip_range
        entry = (addr_to_int(start), addr_to_int(end), value)
        key = self._get_key(start)
        last_key = self._get_key(end)

        while key <= last_key:
            self.store.setdefault(key, [])
            self.store[key].append(entry)
            key += 1

    def __contains__(self, ip_address):
        return self[ip_address] is not None
