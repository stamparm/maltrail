# coding: utf-8
"""Unit tests for core/meta.py (the condensed observable store). Pure stdlib, py2/py3, no network.
Locks: pack/unpack roundtrip (v4/v6/domain), the batched merge summing counts across flushes/workers
(MIN first_seen / MAX last_seen), the broadcast/multicast junk filter, scope tagging, smart
score-prune (evict lowest-value to budget), and lookup."""
import os
import sys
import shutil
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from core import meta as M


class MetaTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.db = os.path.join(self.tmp, "meta.sqlite")
        M._agg = {}
        M.configure(self.db, enabled=True, max_window_keys=1000)

    def tearDown(self):
        M._agg = {}
        M.configure(None, enabled=False)
        shutil.rmtree(self.tmp, ignore_errors=True)


class TestPackUnpack(MetaTestCase):
    def test_ipv4_roundtrip(self):
        key = M._pack(0, "8.8.4.4")
        self.assertEqual(len(bytes(key)), 4)
        self.assertEqual(M._unpack(key), "8.8.4.4")

    def test_ipv6_roundtrip(self):
        key = M._pack(0, "2001:db8::1")
        self.assertEqual(len(bytes(key)), 16)
        self.assertEqual(M._unpack(key), "2001:db8::1")

    def test_domain_stays_text(self):
        key = M._pack(M.FLAG_DNS, "evil.com")
        self.assertEqual(key, "evil.com")
        self.assertEqual(M._unpack(key), "evil.com")

    def test_pack_lookup_classifies(self):
        self.assertEqual(M._pack_lookup("1.2.3.4")[1], "ip")
        self.assertEqual(M._pack_lookup("2001:db8::5")[1], "ip")
        self.assertEqual(M._pack_lookup("example.org")[1], "dns")
        # an all-digit-but-not-4-octet string is NOT a v4 address -> domain
        self.assertEqual(M._pack_lookup("12345")[1], "dns")


class TestObserveAndMerge(MetaTestCase):
    def test_both_endpoints_recorded(self):
        M.observe_conn("192.168.0.5", "8.8.8.8", False, 100)
        M.flush()
        self.assertIsNotNone(M.lookup("192.168.0.5"))
        self.assertIsNotNone(M.lookup("8.8.8.8"))

    def test_scope_tagging(self):
        M.observe_conn("192.168.0.5", "8.8.8.8", False, 100)
        M.flush()
        self.assertEqual(M.lookup("192.168.0.5")["scope"], "local")
        self.assertEqual(M.lookup("8.8.8.8")["scope"], "remote")

    def test_dns_kind(self):
        M.observe_dns("evil.com", 100)
        M.flush()
        row = M.lookup("evil.com")
        self.assertEqual(row["kind"], "dns")
        self.assertEqual(row["count"], 1)

    def test_counts_sum_across_flushes(self):
        # two flushes = two windows / two "workers" merging into the same DB
        M.observe_conn("192.168.0.5", "8.8.8.8", False, 200)
        M.observe_conn("192.168.0.5", "8.8.8.8", False, 250)
        M.flush()
        M.observe_conn("192.168.0.5", "8.8.8.8", False, 50)   # an EARLIER window, flushed later
        M.flush()
        row = M.lookup("8.8.8.8")
        self.assertEqual(row["count"], 3)
        self.assertEqual(row["first_seen"], 50)     # MIN across flushes even out-of-order
        self.assertEqual(row["last_seen"], 250)     # MAX

    def test_flush_clears_and_is_lockfree_swap(self):
        M.observe_dns("a.com", 1)
        self.assertEqual(len(M._agg), 1)
        M.flush()
        self.assertEqual(len(M._agg), 0)            # atomic swap emptied it


class TestJunkFilter(MetaTestCase):
    def test_broadcast_multicast_unspecified_dropped(self):
        M.observe_conn("0.0.0.0", "255.255.255.255", False, 10)
        M.observe_conn("192.168.0.9", "239.255.255.250", False, 10)   # SSDP multicast dst
        M.flush()
        for junk in ("0.0.0.0", "255.255.255.255", "239.255.255.250"):
            self.assertIsNone(M.lookup(junk), "%s should be filtered" % junk)
        self.assertIsNotNone(M.lookup("192.168.0.9"))                 # the real endpoint survives

    def test_window_cap_blocks_new_keys(self):
        M.configure(self.db, enabled=True, max_window_keys=2)
        M._agg = {}
        M.observe_dns("a.com", 1)
        M.observe_dns("b.com", 1)
        M.observe_dns("c.com", 1)      # over cap -> dropped
        self.assertEqual(len(M._agg), 2)
        M.observe_dns("a.com", 2)      # existing key still bumps despite cap
        self.assertEqual(M._agg["a.com"][3], 2)


class TestSmartPrune(MetaTestCase):
    def test_keeps_established_evicts_junk(self):
        # 20 established (old-but-recurring, high count/long span) + 200 DGA one-hits (recent, count=1)
        for i in range(20):
            M._agg["good-%d.net" % i] = [M.FLAG_DNS, 1000, 1000 + 20 * 86400, 500]
        for i in range(200):
            t = 100000 + i
            M._agg["dga-%d.xyz" % i] = [M.FLAG_DNS, t, t, 1]
        M.flush()
        deleted = M.prune(50)          # budget 50 of 220
        self.assertEqual(deleted, 170)
        # all established survive; survivors are dominated by the established set
        good = sum(1 for i in range(20) if M.lookup("good-%d.net" % i))
        self.assertEqual(good, 20)


class TestDisabled(MetaTestCase):
    def test_noop_when_disabled(self):
        M.configure(self.db, enabled=False)
        M._agg = {}
        M.observe_dns("x.com", 1)
        M.observe_conn("1.1.1.1", "2.2.2.2", False, 1)
        self.assertEqual(len(M._agg), 0)


if __name__ == "__main__":
    unittest.main()
