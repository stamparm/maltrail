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

    def test_other_events_on_an_attacks_own_traffic_are_noise_not_false_positives(self):
        truth = [{"host": "10.0.0.5", "trail": None, "info": "dns tunneling", "kind": "DNS_TUNNEL",
                  "explains": "t1.exfil.example"}]
        logged = [("10.0.0.5", "(aaaa).t1.exfil.example", "potential dns tunneling (suspicious)"),
                  ("10.0.0.5", "(bbbb.t1).exfil.example", "long domain (suspicious)"),
                  ("10.0.0.5", "(cccc.t1).exfil.example", "long domain (suspicious)")]
        r = R.score(meta(truth), logged)
        self.assertEqual(r["heuristics"]["DNS_TUNNEL"], (1, 1))
        self.assertEqual((r["attack_noise"]["DNS_TUNNEL"], r["false_positives"]), (2, 0))

    def test_a_planted_heuristic_is_credited_only_by_its_own_event(self):
        truth = [{"host": "10.0.0.5", "trail": "198.51.100.9", "kind": "ICMP_TUNNEL"},
                 {"host": "10.0.0.6", "trail": "xn--pple-43d.com", "kind": "HOMOGRAPH"}]
        r = R.score(meta(truth), [("10.0.0.5", "198.51.100.9", "potential icmp tunneling (suspicious)"),
                                  ("10.0.0.6", "xn--pple-43d.com", "potential homograph of apple.com (suspicious)")])
        self.assertEqual(r["heuristics"], {"ICMP_TUNNEL": (1, 1), "HOMOGRAPH": (1, 1)})
        self.assertEqual(r["false_positives"], 0)
        # anything else the same host sets off is still charged to it
        r = R.score(meta(truth), [("10.0.0.5", "8.8.8.8", "potential icmp tunneling (suspicious)")])
        self.assertEqual((r["heuristics"]["ICMP_TUNNEL"], r["false_positives"]), ((0, 1), 1))

    def test_the_homograph_generator_swaps_exactly_one_letter(self):
        import random
        name = R._homograph("google.com", random.Random(1))
        self.assertTrue(name.startswith("xn--") and name.endswith(".com"), name)
        decoded = name.split(".")[0].encode("ascii").decode("idna")
        self.assertEqual(sum(1 for a, b in zip(decoded, "google") if a != b), 1, decoded)

    def test_rates_are_computed_from_the_run_size(self):
        m = meta([], hosts=500, minutes=60, benign=200000)
        r = R.score(m, [("10.0.0.5", "x", "y")] * 10)
        self.assertAlmostEqual(r["events_per_day_per_1000_hosts"], 10 * 24 * 2, places=6)
        r2 = R.score(meta([], benign=200000), [("10.0.0.5", "x", "y")])
        self.assertAlmostEqual(r2["fp_per_100k_benign"], 0.5, places=6)


class GateTest(unittest.TestCase):
    """CI runs this tool as a gate; a gate that cannot fail is not one."""

    def result(self, **overrides):
        r = {"detection_rate": 100.0, "false_positives": 0, "scans_detected": 3, "scans_planted": 3,
             "heuristics": {"BEACONING": (1, 1), "ICMP_TUNNEL": (2, 2)}}
        r.update(overrides)
        return r

    def test_a_clean_run_passes(self):
        self.assertEqual(R.gate(self.result(), 100, 0, True), [])

    def test_each_threshold_fails_on_its_own(self):
        self.assertTrue(R.gate(self.result(detection_rate=96.7), 100, 0, True))
        self.assertTrue(R.gate(self.result(false_positives=1), 100, 0, True))
        self.assertTrue(R.gate(self.result(scans_detected=2), 100, 0, True))
        self.assertEqual(R.gate(self.result(heuristics={"BEACONING": (0, 1)}), 100, 0, True),
                         ["BEACONING detected 0/1"])

    def test_a_missed_heuristic_only_fails_when_asked(self):
        self.assertEqual(R.gate(self.result(heuristics={"BEACONING": (0, 1)}), 100, 0, False), [])


class TrailPoolTest(unittest.TestCase):
    """Each planted indicator has to be plantable AS the kind it is, or the miss is ours."""

    def _pools(self, rows, info="info"):
        handle, path = tempfile.mkstemp(suffix=".csv")
        os.close(handle)
        self.addCleanup(os.unlink, path)
        with io.open(path, "w", encoding="utf8") as out:
            out.write(u"".join(u"%s,%s,(static)\n" % (_, info) for _ in rows))
        return R._trail_pools(path)

    def test_a_bare_dynamic_dns_domain_is_not_planted(self):
        # the sensor reports only subdomains of a dynamic-DNS provider; the bare name never fires
        domains, _, _ = self._pools(["flowergardendaycare.com"], info="dynamic domain (suspicious)")
        self.assertEqual(domains, [])

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

    def test_an_address_port_with_a_path_is_not_an_ipport(self):
        # "1.2.3.4:34283/i" planted as a SYN to port int("34283/i") crashed the whole run
        _, ipports, _ = self._pools(["1.2.3.4:34283/i", "1.2.3.4:8080"])
        self.assertEqual(ipports, ["1.2.3.4:8080"])

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
        # (the four encapsulation plants need four trail domains; this trail set has one)
        self.assertEqual(kinds, ["BEACONING", "CERT", "DGA", "DNS", "DNS_EXHAUSTION", "DNS_TUNNEL", "HOMOGRAPH", "HOMOGRAPH",
                                 "HOMOGRAPH", "ICMP_TUNNEL", "ICMP_TUNNEL", "IOT_DROPPER", "IPORT", "JA3", "JA4",
                                 "SCAN", "SCAN", "TAIL_SCAN", "URL"])
        # the planted fingerprints are in the run's own trail set, the given one untouched
        run_trails = io.open(m["trails"], encoding="utf8").read()
        for entry in m["truth"]:
            if entry["kind"] in ("JA3", "JA4", "CERT"):
                self.assertIn(entry["trail"] + ",", run_trails)
        self.assertNotIn("refnet", io.open(trails, encoding="utf8").read())
        self.assertGreater(m["benign_packets"], 0, "a network with no benign traffic measures nothing")

    def test_a_rerun_into_the_same_directory_starts_from_empty_logs(self):
        # the sensor appends to its daily log; scoring a second run used to count the first one too
        import shutil
        out_dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, out_dir, True)
        logs = os.path.join(out_dir, "logs")
        os.makedirs(logs)
        with io.open(os.path.join(logs, "2023-11-14.log"), "w", encoding="utf8") as stale:
            stale.write(u"stale line from a previous run\n")
        original = R.subprocess.check_call
        R.subprocess.check_call = lambda *a, **k: 0
        self.addCleanup(setattr, R.subprocess, "check_call", original)
        handle, sensor = tempfile.mkstemp()
        os.close(handle)
        self.addCleanup(os.unlink, sensor)
        R.replay("x.pcap", out_dir, "trails.csv", sensor=sensor)
        self.assertEqual(os.listdir(logs), [])


if __name__ == "__main__":
    unittest.main()
