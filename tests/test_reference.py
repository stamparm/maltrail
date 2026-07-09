# coding: utf-8
"""Unit tests for the on-demand trail source-citation lookup (core.httpd._lookup_trail_reference).
Uses a temp static-trails dir so it's deterministic (no coupling to real trail content). Locks: per-PILE
precision (the nearest preceding '# Reference:'), URL-host matching, line-anchoring (no substring hits), miss."""
import os
import sys
import shutil
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import core.httpd as H


class ReferenceLookupTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self._saved = H._STATIC_TRAILS_DIR
        H._STATIC_TRAILS_DIR = self.tmp
        H._reference_cache.clear()
        os.makedirs(os.path.join(self.tmp, "malware"))
        with open(os.path.join(self.tmp, "malware", "fake.txt"), "w") as f:
            f.write("# Copyright\n\n"
                    "# Reference: https://example.com/feedA\n"
                    "bad1.example\nbad2.example\n\n"
                    "# Reference: https://example.com/feedB\n"
                    "9.9.9.9\nevil.example/path\n")

    def tearDown(self):
        H._STATIC_TRAILS_DIR = self._saved
        H._reference_cache.clear()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_first_pile(self):
        ref, src = H._lookup_trail_reference("bad1.example")
        self.assertEqual(ref, "https://example.com/feedA")
        self.assertTrue(src.endswith("fake.txt"))

    def test_per_pile_precision(self):
        # 9.9.9.9 sits under the SECOND '# Reference:' -> must resolve to feedB, not the file's first header
        self.assertEqual(H._lookup_trail_reference("9.9.9.9")[0], "https://example.com/feedB")

    def test_url_host_match(self):
        # trail is the host of "evil.example/path"
        self.assertEqual(H._lookup_trail_reference("evil.example")[0], "https://example.com/feedB")

    def test_no_substring_false_positive(self):
        # "ad1.example" is a substring of "bad1.example" but the match is line-anchored -> no hit
        self.assertEqual(H._lookup_trail_reference("ad1.example"), ("", ""))

    def test_miss(self):
        self.assertEqual(H._lookup_trail_reference("nope.invalid"), ("", ""))

    def test_cached(self):
        H._lookup_trail_reference("bad2.example")
        self.assertIn("bad2.example", H._reference_cache)


if __name__ == "__main__":
    unittest.main()
