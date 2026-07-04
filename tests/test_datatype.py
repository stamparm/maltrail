# coding: utf-8
"""Unit tests for core/datatype.LRUDict — backs the sensor/server bounded caches (_result_cache,
DISPOSED_NONCES, ipcat cache). A capacity/eviction bug = cache corruption or unbounded memory."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from core.datatype import LRUDict


class TestLRUDict(unittest.TestCase):
    def test_capacity_and_lru_eviction(self):
        d = LRUDict(3)
        d["a"], d["b"], d["c"] = 1, 2, 3
        self.assertEqual(len(d), 3)
        d["d"] = 4                       # overflow -> evict LRU ("a")
        self.assertEqual(len(d), 3)
        self.assertNotIn("a", d)
        self.assertIn("d", d)

    def test_access_refreshes_recency(self):
        d = LRUDict(3)
        d["a"], d["b"], d["c"] = 1, 2, 3
        _ = d["a"]                       # touch "a" -> now most-recent; "b" is LRU
        d["d"] = 4                       # evicts "b", keeps "a"
        self.assertIn("a", d)
        self.assertNotIn("b", d)

    def test_get_missing_returns_none_and_default(self):
        d = LRUDict(2)
        d["x"] = 1
        self.assertEqual(d.get("x"), 1)
        self.assertIsNone(d.get("missing"))            # single-arg: None (unchanged behavior)
        self.assertEqual(d.get("missing", "DEF"), "DEF")  # dict-compatible default (footgun fix)

    def test_reassign_does_not_grow(self):
        d = LRUDict(2)
        d["a"] = 1; d["a"] = 2
        self.assertEqual(len(d), 1)
        self.assertEqual(d["a"], 2)


if __name__ == "__main__":
    unittest.main()
