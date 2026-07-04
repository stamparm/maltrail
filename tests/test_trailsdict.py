# coding: utf-8
"""Unit tests for core/trailsdict.TrailsDict. This is the detection-critical trail store: the sensor
does `ip in trails` / `trails[key]` on every packet, and production FINALIZES it (load_trails
freeze=True) into a compact hash-based frozen form that does NOT retain key strings. A lookup
divergence between build-mode and frozen-mode = silently missed detections. These tests pin that
build == frozen for membership, values, and length, and that a finalized store is immutable."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from core.trailsdict import TrailsDict


def _populate(n=600):
    td = TrailsDict()
    keys = ["evil.com", "66.66.66.66", "8.8.8.8:53", "a.b.c.example.org", "sub.dom.io"]
    keys += ["k%d.test" % i for i in range(n)]
    vals = {}
    for i, k in enumerate(keys):
        v = ("info%d (malware)" % i, "ref%d" % i)
        td[k] = v
        vals[k] = v
    return td, keys, vals


class TestTrailsDict(unittest.TestCase):
    def test_build_mode_lookup(self):
        td, keys, vals = _populate(50)
        for k in keys:
            self.assertIn(k, td)
            self.assertEqual(td[k], vals[k])
            self.assertEqual(td.get(k), vals[k])
        self.assertEqual(len(td), len(keys))
        self.assertNotIn("not-a-trail", td)
        self.assertIsNone(td.get("not-a-trail"))

    def test_frozen_matches_build(self):
        td, keys, vals = _populate(600)
        blen = len(td)
        bmembers = {k: (k in td, td[k], td.get(k)) for k in keys}
        td.finalize()
        self.assertEqual(len(td), blen, "len changed after finalize")
        for k in keys:
            self.assertIn(k, td, "key vanished after finalize: %s" % k)
            self.assertEqual(td[k], bmembers[k][1], "value changed after finalize: %s" % k)
            self.assertEqual(td.get(k), bmembers[k][2])
        # non-keys must stay absent (128-bit hash -> collisions negligible)
        for nk in ("definitely-not-a-trail", "0.0.0.0", "zzz.zzz", "9.9.9.9:1"):
            self.assertNotIn(nk, td, nk)
            self.assertIsNone(td.get(nk))

    def test_frozen_is_immutable(self):
        td, _, _ = _populate(10)
        td.finalize()
        with self.assertRaises(Exception):
            td["new"] = ("x", "y")
        with self.assertRaises(Exception):   # iterating a frozen store (keys not retained) must refuse, not lie
            list(td.items())

    def test_empty(self):
        td = TrailsDict()
        self.assertEqual(len(td), 0)
        self.assertNotIn("x", td)
        td.finalize()
        self.assertEqual(len(td), 0)
        self.assertNotIn("x", td)


if __name__ == "__main__":
    unittest.main()
