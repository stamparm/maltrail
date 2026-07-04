# coding: utf-8
"""Unit tests for core/fastfilter.py: IOC set building, severity admission tiers, the adaptive
controller, and the DLT-offset heuristic (for datalinks missing from DLT_OFFSETS)."""
import os
import sys
import socket
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from core import fastfilter as F
import _pcapgen as G


class TestIOCSet(unittest.TestCase):
    def test_extracts_ipv4_and_ipport(self):
        keys = ["45.95.202.106", "2.200.107.168:4444", "evil.com", "evil.com/p",
                "dead::beef", "[dead::beef]:53", "8.8.8.8", "45.95.202.106", "999.1.1.1", ""]
        s = F.build_ioc_set(keys)
        ips = set(s[i:i + 4] for i in range(0, len(s), 4))
        self.assertEqual(ips, set(socket.inet_aton(x) for x in ["45.95.202.106", "2.200.107.168", "8.8.8.8"]))

    def test_empty_and_dedup(self):
        self.assertEqual(F.build_ioc_set([]), b"")
        self.assertEqual(len(F.build_ioc_set(["1.2.3.4", "1.2.3.4:80", "1.2.3.4:443"])), 4)

    def test_from_trails_mapping(self):
        s = F.ioc_set_from_trails({"1.2.3.4": ("x", "y"), "evil.com": ("a", "b"), "9.9.9.9:53": ("c", "d")})
        ips = set(s[i:i + 4] for i in range(0, len(s), 4))
        self.assertEqual(ips, set(socket.inet_aton(x) for x in ["1.2.3.4", "9.9.9.9"]))


class TestAdmitTiers(unittest.TestCase):
    def test_dns_and_ipset_never_shed(self):
        for lvl in range(4):
            m = F.admit_mask_for_load(lvl)
            self.assertTrue(m & (1 << F.IDX_DNS), "DNS shed at level %d" % lvl)
            self.assertTrue(m & (1 << F.IDX_IPSET), "IPSET shed at level %d" % lvl)
            self.assertFalse(m & (1 << F.IDX_NOISE), "noise admitted at level %d" % lvl)

    def test_progressive_shedding(self):
        self.assertTrue(F.admit_mask_for_load(0) & (1 << F.IDX_SYN))        # SYN at normal
        self.assertFalse(F.admit_mask_for_load(1) & (1 << F.IDX_SYN))       # dropped at busy
        self.assertFalse(F.admit_mask_for_load(2) & (1 << F.IDX_HEAD))      # head dropped at strained
        self.assertFalse(F.admit_mask_for_load(3) & (1 << F.IDX_HTTP))      # http dropped at overload

    def test_default_mask(self):
        self.assertEqual(F.ADMIT_DEFAULT, 59)


class TestAdaptive(unittest.TestCase):
    def test_rises_then_recovers(self):
        lvl = 0
        for _ in range(5):
            lvl = F.next_admit_level(lvl, 100000, 10000)   # 10% drops -> climb
        self.assertEqual(lvl, 3)
        for _ in range(5):
            lvl = F.next_admit_level(lvl, 100000, 0)        # recover -> descend
        self.assertEqual(lvl, 0)

    def test_hysteresis_and_caps(self):
        self.assertEqual(F.next_admit_level(1, 100000, 1000), 1)            # 1% -> hold
        self.assertEqual(F.next_admit_level(2, 0, 0), 2)                    # no traffic -> hold
        lvl = 0
        for _ in range(9):
            lvl = F.next_admit_level(lvl, 100000, 50000, max_level=1)
        self.assertEqual(lvl, 1)                                           # capped


class TestCapabilityProbe(unittest.TestCase):
    """has_fast_prefilter must gate the fast path: True only when the reader exposes loop_filtered."""

    def test_probe(self):
        class _Old(object):
            pass
        class _Fast(object):
            def loop_filtered(self, *a):
                pass
        self.assertFalse(F.has_fast_prefilter(_Old()))
        self.assertTrue(F.has_fast_prefilter(_Fast()))

    def test_stock_pcapy_reader_has_no_fast(self):
        # Documents reality: a stock pcapy reader has no loop_filtered, so the fast path stays off.
        import pcapy, os, struct, tempfile
        fd, path = tempfile.mkstemp(suffix=".pcap")
        os.close(fd)
        try:
            with open(path, "wb") as f:
                f.write(struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
                pkt = b"\x00" * 14 + b"\x45" + b"\x00" * 19
                f.write(struct.pack("<IIII", 0, 0, len(pkt), len(pkt)) + pkt)
            r = pcapy.open_offline(path)
            # Either it's the fast build (has it) or stock (doesn't) -- the probe must agree with hasattr.
            self.assertEqual(F.has_fast_prefilter(r), hasattr(r, "loop_filtered"))
        finally:
            os.unlink(path)


class TestDLTHeuristic(unittest.TestCase):
    """The DLT-offset heuristic: infer where the IP header begins for an unknown datalink."""

    def _ip(self):
        return G.ipv4(17, "10.0.0.5", "8.8.8.8", G.udp(1, 53, b"\x00" * 8))

    def test_known_layouts(self):
        ip = self._ip()
        self.assertEqual(F.guess_ip_offset(G.eth() + ip), 14)              # Ethernet
        self.assertEqual(F.guess_ip_offset(G.sll() + ip), 16)             # Linux cooked
        self.assertEqual(F.guess_ip_offset(ip), 0)                        # raw IP
        self.assertEqual(F.guess_ip_offset(G.eth_vlan() + ip), 18)        # 802.1Q

    def test_unknown_l2_and_ipv6(self):
        ip = self._ip()
        self.assertEqual(F.guess_ip_offset(b"\xde\xad\xbe\xef\xca\xfe\x00\x00" + ip), 8)   # odd 8-byte L2
        v6 = G.eth(0x86DD) + G.ipv6(17, "::1", "::2", G.udp(1, 53, b"\x00" * 8))
        self.assertEqual(F.guess_ip_offset(v6), 14)

    def test_rejects_non_ip(self):
        self.assertIsNone(F.guess_ip_offset(b"\x00" * 60))
        self.assertIsNone(F.guess_ip_offset(b"\x45\x00"))                 # too short
        self.assertIsNone(F.guess_ip_offset(G.eth(0x0806) + b"\x00" * 28))  # ARP


if __name__ == "__main__":
    unittest.main()
