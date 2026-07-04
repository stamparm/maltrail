# coding: utf-8
"""Unit tests for core/enums (TRAIL metaclass, PROTO/SEVERITY constants) and core/attribdict.AttribDict.

The TRAIL metaclass returns any attribute name AS its own string (TRAIL.IP == "IP"); the sensor's
event typing (and the IPv6 IP-vs-IPORT fixes) depend on that identity. AttribDict backs `config`:
a missing key must be None (never AttributeError), or config.MISSING checks would crash."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from core.enums import TRAIL, PROTO, SEVERITY
from core.attribdict import AttribDict


class TestTrailMetaclass(unittest.TestCase):
    def test_attr_is_its_own_name(self):
        self.assertEqual(TRAIL.IP, "IP")
        self.assertEqual(TRAIL.IPORT, "IPORT")
        self.assertEqual(TRAIL.DNS, "DNS")
        self.assertEqual(TRAIL.PATH, "PATH")
        self.assertEqual(TRAIL.PORT, "PORT")
        self.assertEqual(TRAIL.HTTP, "HTTP")

    def test_ip_and_iport_are_distinct(self):
        # the IPv6 typing fixes hinge on this distinction
        self.assertNotEqual(TRAIL.IP, TRAIL.IPORT)


class TestProtoSeverity(unittest.TestCase):
    def test_proto(self):
        self.assertEqual((PROTO.TCP, PROTO.UDP, PROTO.ICMP), ("TCP", "UDP", "ICMP"))

    def test_severity_order(self):
        self.assertEqual(SEVERITY.LOW, "low")
        self.assertEqual(SEVERITY.HIGH, "high")


class TestAttribDict(unittest.TestCase):
    def test_missing_key_is_none(self):
        d = AttribDict()
        self.assertIsNone(d.NONEXISTENT)                  # must NOT raise (config.MISSING checks rely on this)

    def test_attr_set_get_roundtrip(self):
        d = AttribDict()
        d.foo = 42
        self.assertEqual(d.foo, 42)
        self.assertEqual(d["foo"], 42)                    # attribute and item views agree
        d["bar"] = "x"
        self.assertEqual(d.bar, "x")


if __name__ == "__main__":
    unittest.main()
