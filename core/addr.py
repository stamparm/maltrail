#!/usr/bin/env python

"""
Copyright (c) 2014-2026 Maltrail developers (https://github.com/stamparm/maltrail/)
See the file 'LICENSE' for copying permission
"""

import re

from core.compat import xrange

def addr_to_int(value):
    """
    Converts an IPv4 address into its integer representation

    >>> addr_to_int("1.2.3.4")
    16909060
    """

    _ = value.split('.')
    return (int(_[0]) << 24) + (int(_[1]) << 16) + (int(_[2]) << 8) + int(_[3])

def int_to_addr(value):
    """
    Converts an integer into its IPv4 address representation

    >>> int_to_addr(16909060)
    '1.2.3.4'
    """

    return '.'.join(str(value >> n & 0xff) for n in (24, 16, 8, 0))

def make_mask(bits):
    """
    Returns the integer netmask for a given number of network bits

    >>> int_to_addr(make_mask(24))
    '255.255.255.0'
    >>> int_to_addr(make_mask(32))
    '255.255.255.255'
    """

    return 0xffffffff ^ (1 << 32 - bits) - 1

def compress_ipv6(address):
    r"""
    Compresses a fully expanded IPv6 address (collapsing the longest zero-run to '::')

    >>> compress_ipv6("0000:0000:0000:0000:0000:0000:0000:0001")
    '::1'
    """

    zeros = re.findall("(?:0000:)+", address)
    if zeros:
        address = address.replace(sorted(zeros, key=lambda _: len(_))[-1], ":", 1)
        address = re.sub(r"(\A|:)0+(\w)", r"\g<1>\g<2>", address)
        if address.startswith(':') and not address.startswith('::'):
            address = ":%s" % address  # NOTE: a zero-run at the start collapses to a single leading ':' (e.g. ':1', ':1234:...'); prefix it to form a valid '::...' (also covers loopback ':1' -> '::1')
    return address

# Note: socket.inet_ntop not available everywhere (Reference: https://docs.python.org/2/library/socket.html#socket.inet_ntop)
def inet_ntoa6(packed_ip):
    r"""
    Converts a packed (16-byte) IPv6 address into its compressed string form

    >>> inet_ntoa6(b'\x00' * 15 + b'\x01')
    '::1'
    """

    _ = packed_ip.hex() if hasattr(packed_ip, "hex") else packed_ip.encode("hex")
    return compress_ipv6(':'.join(_[i:i + 4] for i in xrange(0, len(_), 4)))

def expand_range(value):
    r"""
    Expands a CIDR ('192.168.1.0/30') or dash range ('10.0.0.1-10.0.0.3') into a list of addresses.
    Oversized ranges (> 65536 addresses) are refused (returning []) to bound memory usage.

    >>> expand_range("192.168.1.0/30")
    ['192.168.1.0', '192.168.1.1', '192.168.1.2', '192.168.1.3']
    >>> expand_range("10.0.0.1-10.0.0.3")
    ['10.0.0.1', '10.0.0.2', '10.0.0.3']
    >>> expand_range("1.0.0.0-200.0.0.0")
    []
    >>> expand_range("10.0.0.0/8")
    []
    >>> expand_range("evil.com")
    ['evil.com']
    """

    retval = []
    value = value.strip()

    match = re.match(r"(\d+\.\d+\.\d+\.\d+)/(\d+)", value)
    if match:
        prefix, mask = match.groups()
        mask = int(mask)
        if mask > 32:
            return retval

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
        if 0 <= end_int - start_int <= 65536:
            current = start_int
            while start_int <= current <= end_int:
                retval.append(int_to_addr(current))
                current += 1

    else:
        retval.append(value)

    return retval

def addr_port(addr, port):
    """
    Formats an address:port pair, bracketing IPv6 literals

    >>> addr_port("1.2.3.4", 80)
    '1.2.3.4:80'
    >>> addr_port("dead::beef", 53)
    '[dead::beef]:53'
    """

    if ':' in addr and '.' not in addr:
        retval = "[%s]:%s" % (addr.strip("[]"), port)
    else:
        retval = "%s:%s" % (addr, port)

    return retval
