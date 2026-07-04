# coding: utf-8
"""PACKET_FANOUT integration tests that DON'T need root: the pcapy-ng C API surface, the
offline-handle guard, and sensor._fanout_count() parsing. The live kernel load-balancing itself
is proven by tests/manual_fanout_check.py (needs CAP_NET_RAW + traffic)."""
import os
import sys
import struct
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pcapy


def _tiny_pcap():
    fd, path = tempfile.mkstemp(suffix=".pcap")
    os.close(fd)
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        pkt = b"\x00" * 14 + b"\x45" + b"\x00" * 19
        f.write(struct.pack("<IIII", 0, 0, len(pkt), len(pkt)) + pkt)
    return path


class TestFanoutAPI(unittest.TestCase):
    def test_constants_present(self):
        if not hasattr(pcapy, "PACKET_FANOUT_HASH"):
            self.skipTest("pcapy build without PACKET_FANOUT (not the fast build / non-Linux)")
        self.assertEqual(pcapy.PACKET_FANOUT_HASH, 0)
        self.assertEqual(pcapy.PACKET_FANOUT_LB, 1)
        self.assertEqual(pcapy.PACKET_FANOUT_CPU, 2)

    def test_method_present_and_offline_raises(self):
        path = _tiny_pcap()
        try:
            r = pcapy.open_offline(path)
        finally:
            pass
        if not hasattr(r, "set_fanout"):
            os.unlink(path)
            self.skipTest("pcapy build without set_fanout (not the fast build)")
        # an offline handle has no live socket fd -> must raise cleanly, never crash
        with self.assertRaises(Exception):
            r.set_fanout(1234, getattr(pcapy, "PACKET_FANOUT_HASH", 0))
        os.unlink(path)


class TestFanoutCount(unittest.TestCase):
    def setUp(self):
        sys.argv = ["x"]
        import sensor
        self.sensor = sensor
        from core.settings import config
        self.config = config

    def test_parsing(self):
        cpu = self.sensor._cpu_count()
        cases = [(None, 0), ("", 0), ("0", 0), ("1", 0), ("4", 4), ("8", 8),
                 ("true", cpu), ("auto", cpu), ("false", 0), ("garbage", 0)]
        for val, exp in cases:
            self.config["CAPTURE_FANOUT"] = val
            self.assertEqual(self.sensor._fanout_count(), exp, "CAPTURE_FANOUT=%r" % val)


if __name__ == "__main__":
    unittest.main()
