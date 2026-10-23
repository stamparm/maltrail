# coding: utf-8
"""Unit tests for core/addr.py address helpers (pure functions)."""
import os
import sys
import socket
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from core.addr import (addr_to_int, int_to_addr, make_mask, compress_ipv6,
                       inet_ntoa6, expand_range, addr_port, parse_host_port,
                       canonical_ip_trail)


class TestAddr(unittest.TestCase):
    def test_addr_int_roundtrip(self):
        self.assertEqual(addr_to_int("1.2.3.4"), 16909060)
        self.assertEqual(int_to_addr(16909060), "1.2.3.4")
        for ip in ("0.0.0.0", "255.255.255.255", "192.168.1.1", "8.8.8.8"):
            self.assertEqual(int_to_addr(addr_to_int(ip)), ip)

    def test_make_mask(self):
        self.assertEqual(make_mask(24), 0xFFFFFF00)
        self.assertEqual(make_mask(32), 0xFFFFFFFF)
        self.assertEqual(make_mask(0), 0)

    def test_compress_ipv6(self):
        self.assertEqual(compress_ipv6("2001:0db8:0000:0000:0000:0000:0000:0001"), "2001:db8::1")

    def test_inet_ntoa6(self):
        self.assertEqual(inet_ntoa6(socket.inet_pton(socket.AF_INET6, "::1")), "::1")
        self.assertEqual(inet_ntoa6(socket.inet_pton(socket.AF_INET6, "2001:db8::1")), "2001:db8::1")

    def test_addr_port(self):
        self.assertEqual(addr_port("1.2.3.4", 80), "1.2.3.4:80")
        self.assertEqual(addr_port("dead::beef", 53), "[dead::beef]:53")   # IPv6 bracketed

    def test_parse_host_port(self):
        self.assertEqual(parse_host_port("1.2.3.4:80"), ("1.2.3.4", 80))

    def test_expand_range(self):
        self.assertEqual(list(expand_range("1.2.3.4-1.2.3.6")), ["1.2.3.4", "1.2.3.5", "1.2.3.6"])
        self.assertEqual(list(expand_range("192.168.1.0/30")),
                         ["192.168.1.0", "192.168.1.1", "192.168.1.2", "192.168.1.3"])


class TestAddrEdges(unittest.TestCase):
    def test_parse_host_port_ipv6_bracketed(self):
        self.assertEqual(parse_host_port("[dead::beef]:53"), ("dead::beef", 53))

    def test_parse_host_port_no_port(self):
        self.assertEqual(parse_host_port("1.2.3.4"), ("1.2.3.4", None))

    def test_addr_port_ipv6_brackets(self):
        self.assertEqual(addr_port("dead::beef", 53), "[dead::beef]:53")

    def test_canonical_ip_trail_collapses_spellings_and_keeps_rendered_text(self):
        import random
        rnd = random.Random(19)
        changed = 0
        for _ in range(20000):
            # addresses with and without zero groups, so both renderer branches are exercised
            groups = [rnd.choice((0, 0, rnd.randint(1, 0xff), rnd.randint(0, 0xffff))) for _ in range(8)]
            packed = b"".join(g.to_bytes(2, "big") for g in groups)
            rendered = inet_ntoa6(packed)
            full = ":".join("%x" % g for g in groups)
            padded = ":".join("%04X" % g for g in groups)
            # what the sensor renders is a fixed point: an existing trail never changes
            self.assertEqual(canonical_ip_trail(rendered), rendered)
            self.assertEqual(canonical_ip_trail(addr_port(rendered, 443)), addr_port(rendered, 443))
            for spelling in (full, padded, socket.inet_ntop(socket.AF_INET6, packed)):
                self.assertEqual(canonical_ip_trail(spelling), rendered, spelling)
                self.assertEqual(canonical_ip_trail("[%s]:8080" % spelling), "[%s]:8080" % rendered, spelling)
                changed += spelling != rendered
        self.assertGreater(changed, 10000)      # not vacuous: most spellings differed from the rendering

    def test_canonical_ip_trail_leaves_everything_else_alone(self):
        for trail in ("evil.com", "evil.com:8080", "evil.com:8080/a:b", "1.2.3.4", "1.2.3.4:80", "010.1.1.1",
                      "2001:db8::/32", "fe80::1%eth0", "[dead::beef]", "[dead::beef]:99999", "a:b",
                      "deadbeef::cafe::1", "/wp-admin:x", "http://[dead::beef]/"):
            self.assertEqual(canonical_ip_trail(trail), trail)
        # the case that started it: MythicRatatoskr's C&C as ESET published it
        self.assertEqual(canonical_ip_trail("[201:b479:2771:8df4:b5eb:d007:63b0:2838]:8080"),
                         "[0201:b479:2771:8df4:b5eb:d007:63b0:2838]:8080")

    def test_expand_range_single_and_cidr(self):
        self.assertEqual(list(expand_range("1.2.3.4")), ["1.2.3.4"])           # non-range -> passthrough
        self.assertEqual(list(expand_range("192.168.1.0/30")),
                         ["192.168.1.0", "192.168.1.1", "192.168.1.2", "192.168.1.3"])

    def test_make_mask_edges(self):
        self.assertEqual(make_mask(0), 0)
        self.assertEqual(make_mask(32), 0xFFFFFFFF)



class TestUnicodeDigitPorts(unittest.TestCase):
    """A port that passes str.isdigit() but not int() must be refused, not raised on.

    parse_host_port and resolve_address both took config strings (LOG_SERVER, SYSLOG_SERVER,
    HTTP_ADDRESS) and guarded int() with isdigit(), which admits 128 characters int() rejects.
    """

    def test_parse_host_port_refuses_them(self):
        self.assertEqual(parse_host_port(u"1.2.3.4:\xb2"), ("1.2.3.4", None))
        self.assertEqual(parse_host_port(u"1.2.3.4:5\xb3"), ("1.2.3.4", None))
        self.assertEqual(parse_host_port("1.2.3.4:53"), ("1.2.3.4", 53))   # positive control

    def test_resolve_address_refuses_them(self):
        from core.addr import resolve_address
        self.assertEqual(resolve_address("1.2.3.4", u"\xb2"), ("1.2.3.4", 0))
        self.assertEqual(resolve_address("1.2.3.4", "53"), ("1.2.3.4", 53))   # positive control


if __name__ == "__main__":
    unittest.main()
