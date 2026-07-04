# coding: utf-8
"""Unit tests for core/addr.py address helpers (pure functions)."""
import os
import sys
import socket
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from core.addr import (addr_to_int, int_to_addr, make_mask, compress_ipv6,
                       inet_ntoa6, expand_range, addr_port, parse_host_port)


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


if __name__ == "__main__":
    unittest.main()
