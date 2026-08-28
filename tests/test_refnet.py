# coding: utf-8
"""Unit tests for the reference network (sensor/tools/refnet.py).

The tool exists to turn "the heuristics are noisy" into a number, so its own arithmetic has to be
trustworthy: a scorer that miscounts produces confident nonsense, which is worse than no number.
Two bugs in the first version make the point, and both are pinned here.

  * The sensor BRACKETS the part of a URL that matched, so a request to `1.2.3.4/a/b.php` caught by
    a bare-path trail logs as `(1.2.3.4)/a/b.php`. Compared literally that scored as a miss AND a
    false positive - two wrong answers from one formatting rule.
  * A dotted quad has no colon and no slash, so it landed in the DOMAIN pool and was planted as a
    DNS query for "141.8.225.181". Nothing resolves that and no IP trail matches it, and the run
    reported a detection miss the generator had manufactured.
"""

import io
import os
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "sensor", "tools"))

import refnet as R


def meta(truth, hosts=500, minutes=60, benign=100000):
    return {"hosts": hosts, "minutes": minutes, "benign_packets": benign, "truth": truth}


class ScoringTest(unittest.TestCase):
    def test_an_exact_match_counts_once(self):
        m = meta([{"host": "10.0.0.1", "trail": "evil.example", "kind": "DNS"}])
        r = R.score(m, [("10.0.0.1", "evil.example", "malware")])
        self.assertEqual((r["detected"], r["false_positives"]), (1, 0))
        self.assertEqual(r["detection_rate"], 100.0)

    def test_a_bracketed_url_is_the_same_detection(self):
        m = meta([{"host": "10.0.0.1", "trail": "1.2.3.4/a/b.php", "kind": "URL"}])
        r = R.score(m, [("10.0.0.1", "(1.2.3.4)/a/b.php", "malware")])
        self.assertEqual(r["detected"], 1, "the brackets mark what matched, not a different trail")
        self.assertEqual(r["false_positives"], 0, "and it must not also be counted as invented")

    def test_a_path_only_match_credits_the_planted_url(self):
        # the listed trail was the bare path; the sensor renders host + path
        m = meta([{"host": "10.0.0.1", "trail": "1.2.3.4/gate.php", "kind": "URL"}])
        r = R.score(m, [("10.0.0.1", "(1.2.3.4)/gate.php", "malware")])
        self.assertEqual((r["detected"], r["false_positives"]), (1, 0))

    def test_the_same_trail_on_another_host_is_a_false_positive(self):
        m = meta([{"host": "10.0.0.1", "trail": "evil.example", "kind": "DNS"}])
        r = R.score(m, [("10.0.0.9", "evil.example", "malware")])
        self.assertEqual((r["detected"], r["false_positives"]), (0, 1))

    def test_a_missed_plant_is_reported(self):
        m = meta([{"host": "10.0.0.1", "trail": "evil.example", "kind": "DNS"}])
        r = R.score(m, [])
        self.assertEqual(r["detected"], 0)
        self.assertEqual(r["missed"], [("10.0.0.1", "evil.example")])

    def test_a_scan_is_credited_to_its_source_whatever_the_trail_says(self):
        # the heuristic writes the scanner's address as the trail; the point is that its SOURCE
        # was flagged, so anything from a planted scanner counts and never lands in false positives
        m = meta([{"host": "203.0.113.7", "trail": "203.0.113.7", "kind": "SCAN"}])
        r = R.score(m, [("203.0.113.7", "203.0.113.7", "potential port scanning")])
        self.assertEqual((r["scans_detected"], r["false_positives"]), (1, 0))

    def test_rates_are_computed_from_the_run_size(self):
        m = meta([], hosts=500, minutes=60, benign=200000)
        r = R.score(m, [("10.0.0.5", "x", "y")] * 10)
        self.assertAlmostEqual(r["events_per_day_per_1000_hosts"], 10 * 24 * 2, places=6)
        r2 = R.score(meta([], benign=200000), [("10.0.0.5", "x", "y")])
        self.assertAlmostEqual(r2["fp_per_100k_benign"], 0.5, places=6)


class TrailPoolTest(unittest.TestCase):
    """Each planted indicator has to be plantable AS the kind it is, or the miss is ours."""

    def _pools(self, rows):
        handle, path = tempfile.mkstemp(suffix=".csv")
        os.close(handle)
        self.addCleanup(os.unlink, path)
        with io.open(path, "w", encoding="utf8") as out:
            out.write(u"".join(u"%s,info,(static)\n" % _ for _ in rows))
        return R._trail_pools(path)

    def test_a_bare_address_is_not_a_domain(self):
        domains, ipports, urls = self._pools(["141.8.225.181", "evil.example"])
        self.assertEqual(domains, ["evil.example"], "a dotted quad cannot be planted as a DNS query")
        self.assertEqual((ipports, urls), ([], []))

    def test_the_kinds_are_separated(self):
        domains, ipports, urls = self._pools(
            ["evil.example", "1.2.3.4:8080", "5.6.7.8/gate.php", "9.9.9.9"])
        self.assertEqual(domains, ["evil.example"])
        self.assertEqual(ipports, ["1.2.3.4:8080"])
        self.assertEqual(urls, ["5.6.7.8/gate.php"])

    def test_a_url_with_no_real_path_is_skipped(self):
        # "1.2.3.4/" carries nothing to request; planting it would test the generator, not the sensor
        _, _, urls = self._pools(["1.2.3.4/", "1.2.3.4/ab"])
        self.assertEqual(urls, [])


class GenerationTest(unittest.TestCase):
    def test_a_seed_reproduces_the_same_network(self):
        # a number nobody can reproduce is an anecdote
        handle, trails = tempfile.mkstemp(suffix=".csv")
        os.close(handle)
        self.addCleanup(os.unlink, trails)
        with io.open(trails, "w", encoding="utf8") as out:
            out.write(u"evil.example,malware (test),(static)\n1.2.3.4:99,malware (test),(static)\n"
                      u"5.6.7.8/gate.php,malware (test),(static)\n")
        first = tempfile.mkdtemp()
        second = tempfile.mkdtemp()
        import shutil
        self.addCleanup(shutil.rmtree, first, True)
        self.addCleanup(shutil.rmtree, second, True)
        a_pcap, a = R.generate(first, hosts=5, minutes=2, seed=42, planted=1, scans=1, trails=trails)
        b_pcap, b = R.generate(second, hosts=5, minutes=2, seed=42, planted=1, scans=1, trails=trails)
        self.assertEqual(a["truth"], b["truth"])
        self.assertEqual(io.open(a_pcap, "rb").read(), io.open(b_pcap, "rb").read())

    def test_every_planted_indicator_is_recorded_as_truth(self):
        handle, trails = tempfile.mkstemp(suffix=".csv")
        os.close(handle)
        self.addCleanup(os.unlink, trails)
        with io.open(trails, "w", encoding="utf8") as out:
            out.write(u"evil.example,malware (test),(static)\n1.2.3.4:99,malware (test),(static)\n"
                      u"5.6.7.8/gate.php,malware (test),(static)\n")
        out_dir = tempfile.mkdtemp()
        import shutil
        self.addCleanup(shutil.rmtree, out_dir, True)
        _, m = R.generate(out_dir, hosts=4, minutes=2, seed=7, planted=1, scans=2, trails=trails)
        kinds = sorted(_["kind"] for _ in m["truth"])
        self.assertEqual(kinds, ["DNS", "IPORT", "SCAN", "SCAN", "URL"])
        self.assertGreater(m["benign_packets"], 0, "a network with no benign traffic measures nothing")


if __name__ == "__main__":
    unittest.main()
