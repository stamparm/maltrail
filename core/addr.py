#!/usr/bin/env python

"""
Copyright (c) 2014-2025 Maltrail developers (https://github.com/stamparm/maltrail/)
See the file 'LICENSE' for copying permission
"""

import re

from core.compat import xrange

def addr_to_int(value):
    _ = value.split('.')
    return (int(_[0]) << 24) + (int(_[1]) << 16) + (int(_[2]) << 8) + int(_[3])

def int_to_addr(value):
    return '.'.join(str(value >> n & 0xff) for n in (24, 16, 8, 0))

def make_mask(bits):
    return 0xffffffff ^ (1 << 32 - bits) - 1

def compress_ipv6(address):
    zeros = re.findall("(?:0000:)+", address)
    if zeros:
        address = address.replace(sorted(zeros, key=lambda _: len(_))[-1], ":", 1)
        address = re.sub(r"(\A|:)0+(\w)", r"\g<1>\g<2>", address)
        if address == ":1":
            address = "::1"
    return address

# Note: socket.inet_ntop not available everywhere (Reference: https://docs.python.org/2/library/socket.html#socket.inet_ntop)
def inet_ntoa6(packed_ip):
    _ = packed_ip.hex() if hasattr(packed_ip, "hex") else packed_ip.encode("hex")
    return compress_ipv6(':'.join(_[i:i + 4] for i in xrange(0, len(_), 4)))

def expand_range(value):
    retval = []
    value = value.strip()

    match = re.match(r"(\d+\.\d+\.\d+\.\d+)/(\d+)", value)
    if match:
        prefix, mask = match.groups()
        mask = int(mask)
        assert(mask <= 32)

        start_int = addr_to_int(prefix) & make_mask(mask)
        end_int = start_int | ((1 << 32 - mask) - 1)
        if 0 <= end_int - start_int <= 65536:
            address = start_int
            while start_int <= address <= end_int:
                retval.append(int_to_addr(address))
                address += 1

    elif '-' in value:
        start, end = value.split('-')
        start_int, end_int = addr_to_int(start), addr_to_int(end)
        current = start_int
        while start_int <= current <= end_int:
            retval.append(int_to_addr(current))
            current += 1

    else:
        retval.append(value)

    return retval

def addr_port(addr, port):
    if ':' in addr and '.' not in addr:
        retval = "[%s]:%s" % (addr.strip("[]"), port)
    else:
        retval = "%s:%s" % (addr, port)

    return retval
