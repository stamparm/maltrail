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
        # Static content is its own repository now, so the lookup resolves its directory per call
        # (STATIC_TRAILS_DIR, a sibling checkout, or a pre-split tree) instead of reading a module
        # global fixed at import. Point it at the fixture the same way an operator would.
        self._saved = H.config.STATIC_TRAILS_DIR
        H.config.STATIC_TRAILS_DIR = self.tmp
        H._reference_cache.clear()
        os.makedirs(os.path.join(self.tmp, "malware"))
        with open(os.path.join(self.tmp, "malware", "fake.txt"), "w") as f:
            f.write("# Copyright\n\n"
                    "# Reference: https://example.com/feedA\n"
                    "bad1.example\nbad2.example\n\n"
                    "# Reference: https://example.com/feedB\n"
                    "9.9.9.9\nevil.example/path\n")

    def tearDown(self):
        H.config.STATIC_TRAILS_DIR = self._saved
        H._reference_cache.clear()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_first_pile(self):
        ref, src = H._lookup_trail_reference("bad1.example")
        self.assertEqual(ref, "https://example.com/feedA")
        self.assertTrue(src.endswith("fake.txt"))

    def test_per_pile_precision(self):
        # 9.9.9.9 sits under the SECOND '# Reference:' -> must resolve to feedB, not the file's first header
        self.assertEqual(H._lookup_trail_reference("9.9.9.9")[0], "https://example.com/feedB")

    def test_no_checkout_says_so(self):
        # Without a content checkout there is nothing to cite. It must not come back as an empty
        # citation, which renders as "this trail has no source" rather than "provenance is not
        # configured here".
        H.config.STATIC_TRAILS_DIR = os.path.join(self.tmp, "nonexistent")
        H._reference_cache.clear()
        ref, src = H._lookup_trail_reference("bad1.example")
        self.assertEqual(ref, "")
        self.assertIn("STATIC_TRAILS_DIR", src)

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



class ProvenanceSidecar(unittest.TestCase):
    """The sidecar is how a deployment cites a detection's source now that the content tree is a
    separate repository. Nobody clones it, so without this the trail drawer says nothing."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self._saved = dict(H.config)
        self.addCleanup(self._restore)
        H.config.TRAILS_FILE = os.path.join(self.tmp, "trails.csv")
        H.config.STATIC_TRAILS_DIR = None
        H._reference_cache.clear()
        H._provenance_key = None

        from core import provenance
        self.path = "%s.provenance" % H.config.TRAILS_FILE
        provenance.build(
            [("evil.example", 0), ("9.9.9.9", 1)],
            [["malware/fake.txt", "https://example.com/feedA"],
             ["suspicious/other.txt", "https://example.com/feedB"]],
            self.path)

    def _restore(self):
        if H._provenance_handle:
            H._provenance_handle.close()
        H._provenance_handle = False
        H.config.clear()
        H.config.update(self._saved)
        H._reference_cache.clear()
        H._provenance_key = None

    def test_cites_the_source(self):
        self.assertEqual(H._lookup_trail_reference("evil.example"),
                         ("https://example.com/feedA", "malware/fake.txt"))
        self.assertEqual(H._lookup_trail_reference("9.9.9.9"),
                         ("https://example.com/feedB", "suspicious/other.txt"))

    def test_a_trail_with_no_citation_is_not_reported_as_missing_provenance(self):
        # Present sidecar, absent trail. Saying "provenance is not installed" here would send an
        # operator to fix configuration that is already correct.
        self.assertEqual(H._lookup_trail_reference("absent.example"), ("", ""))

    def test_no_sidecar_names_what_restores_it(self):
        os.remove(self.path)
        H._reference_cache.clear()
        H._provenance_key = None
        reference, note = H._lookup_trail_reference("evil.example")
        self.assertEqual(reference, "")
        self.assertIn("STATIC_TRAILS_PROVENANCE", note)

    def test_a_corrupt_sidecar_does_not_take_the_endpoint_down(self):
        with open(self.path, "wb") as f:
            f.write(b"not a sidecar at all")
        H._reference_cache.clear()
        H._provenance_key = None
        reference, note = H._lookup_trail_reference("evil.example")
        self.assertEqual(reference, "")
        self.assertIn("STATIC_TRAILS_PROVENANCE", note)

    def test_it_reopens_when_the_sidecar_changes(self):
        # update_trails() replaces the file whenever the content moves; an mmap of the old inode
        # would keep citing a trail set nobody is running.
        self.assertEqual(H._lookup_trail_reference("evil.example")[1], "malware/fake.txt")
        from core import provenance
        provenance.build([("evil.example", 0)], [["malware/renamed.txt", "https://example.com/feedC"]], self.path)
        os.utime(self.path, (0, 0))
        H._reference_cache.clear()
        self.assertEqual(H._lookup_trail_reference("evil.example"),
                         ("https://example.com/feedC", "malware/renamed.txt"))


if __name__ == "__main__":
    unittest.main()
