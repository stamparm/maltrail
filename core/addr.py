#!/usr/bin/env python

"""
Copyright (c) 2014-2026 Maltrail developers (https://github.com/stamparm/maltrail/)
See the file 'LICENSE' for copying permission
"""

import re
import socket

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
    >>> expand_range("my-host.com")
    ['my-host.com']
    >>> expand_range("10.0.0.1-10.0.0.2-10.0.0.3")
    ['10.0.0.1-10.0.0.2-10.0.0.3']
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
        # Only a clean two-endpoint IPv4 range expands. Anything else with a '-' (a hostname like
        # "my-host.com", a malformed multi-dash value) is kept as a literal instead of crashing
        # addr_to_int()/the tuple-unpack - which previously aborted config (IP_ALIASES) parsing entirely.
        parts = [_.strip() for _ in value.split('-')]
        if len(parts) == 2 and all(re.match(r"\A\d+\.\d+\.\d+\.\d+\Z", _) for _ in parts):
            start_int, end_int = addr_to_int(parts[0]), addr_to_int(parts[1])
            if 0 <= end_int - start_int <= 65536:
                current = start_int
                while start_int <= current <= end_int:
                    retval.append(int_to_addr(current))
                    current += 1
        else:
            retval.append(value)

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

def parse_host_port(value):
    """
    Splits a 'host:port' endpoint into (host, port), where port is an int (or None if absent).
    Handles IPv6 literals - bracketed ('[::1]:514') or bare with a trailing port ('fe80::1:514').

    >>> parse_host_port("1.2.3.4:8080")
    ('1.2.3.4', 8080)
    >>> parse_host_port("[fe80::1]:514")
    ('fe80::1', 514)
    >>> parse_host_port("example.com:53")
    ('example.com', 53)
    >>> parse_host_port("example.com")
    ('example.com', None)
    """

    value = (value or "").strip()

    if value.startswith('[') and ']' in value:    # bracketed IPv6: [host] or [host]:port
        host, _, rest = value[1:].partition(']')
        port = rest[1:] if rest.startswith(':') else ""
    elif value.count(':') == 1:                    # host:port (IPv4 / hostname)
        host, _, port = value.partition(':')
    elif value.count(':') > 1:                     # bare IPv6 with a trailing :port
        host, _, port = value.rpartition(':')
    else:                                          # host only, no port
        host, port = value, ""

    return host, (int(port) if port.isdigit() else None)

def resolve_address(host, port):
    """
    Resolves (host, port) into a numeric sockaddr tuple suitable for sendto()/bind(), IPv4/IPv6-safe
    (numeric only - no DNS). Returns a 2-tuple for IPv4, a 4-tuple for IPv6.
    """

    _AI_NUMERICSERV = getattr(socket, "AI_NUMERICSERV", 0)
    flags = socket.AI_NUMERICHOST | _AI_NUMERICSERV
    return socket.getaddrinfo(host, int(port) if str(port or "").isdigit() else 0, 0, 0, 0, flags)[0][4]
