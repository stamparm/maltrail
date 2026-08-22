# coding: utf-8
"""Trail-confidence sidecar. Scores come from feed agreement (how many distinct feeds listed the
same trail), are written by update_trails() into a sorted TSV next to trails.csv, and are read by
the /check endpoint through an mmap binary search that must never load the file onto the heap.
Covers the scorer, the writer's on-disk contract, and the lookup's hit/miss/staleness paths."""
import os
import sys
import tempfile
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

from core.update import confidence_score, write_confidence_file
from core.httpd import _confidence_lookup


class ConfidenceScore(unittest.TestCase):
    def test_single_source_scores_the_floor(self):
        self.assertEqual(confidence_score("http://somefeed.example/list", 0), 40)

    def test_agreement_climbs_and_caps_at_four_extra_feeds(self):
        self.assertEqual(confidence_score("feed-a", 1), 55)
        self.assertEqual(confidence_score("feed-a", 2), 70)
        self.assertEqual(confidence_score("feed-a", 4), 100)
        self.assertEqual(confidence_score("feed-a", 40), 100)

    def test_custom_and_static_score_full_marks(self):
        self.assertEqual(confidence_score("(custom) internal list", 0), 100)
        self.assertEqual(confidence_score("static", 0), 100)
        self.assertEqual(confidence_score(None, 0), 40)


class ConfidenceFile(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.mkdtemp()
        from core.settings import config
        self._saved_trails_file = config.TRAILS_FILE
        config.TRAILS_FILE = os.path.join(self._tmp, "trails.csv")

    def tearDown(self):
        from core.settings import config
        config.TRAILS_FILE = self._saved_trails_file

    def test_written_sorted_as_key_tab_score_lines(self):
        trails = {"b.evil.example": ("malware", "feed-b"),
                  "a.evil.example": ("malware", "(custom) mine"),
                  "1.2.3.4": ("attack source", "feed-x (+feed-y)")}
        duplicates = {"b.evil.example": set(("feed-y", "feed-z"))}
        self.assertTrue(write_confidence_file(trails, duplicates))

        path = "%s.confidence" % __import__("core.settings", fromlist=["config"]).config.TRAILS_FILE
        with open(path) as f:
            lines = f.read().splitlines()
        self.assertEqual(lines, ["1.2.3.4\t40", "a.evil.example\t100", "b.evil.example\t70"])

    def test_lookup_hit_miss_and_between_lines(self):
        trails = {"aaa.example": ("malware", "feed-a"), "zzz.example": ("malware", "feed-b")}
        write_confidence_file(trails, {})
        self.assertEqual(_confidence_lookup("aaa.example"), 40)
        self.assertIsNone(_confidence_lookup("mmm.example"))  # sorts between records
        self.assertIsNone(_confidence_lookup("aa.example"))   # prefix, not equal

    def test_lookup_tracks_rewrites(self):
        write_confidence_file({"k.example": ("malware", "feed-a")}, {})
        self.assertEqual(_confidence_lookup("k.example"), 40)
        write_confidence_file({"k.example": ("malware", "feed-a")}, {"k.example": set(("b", "c", "d", "e"))})
        self.assertEqual(_confidence_lookup("k.example"), 100)

    def test_missing_sidecar_is_no_opinion_not_an_error(self):
        self.assertIsNone(_confidence_lookup("anything.example", path=os.path.join(self._tmp, "absent.confidence")))


if __name__ == "__main__":
    unittest.main()
