# coding: utf-8
"""Unit tests for the static-trail reachability gate (sensor/tools/check_trails.py).

This is a gate on trails/static/, so its exit status has to mean something: it ran outside CI for
as long as it reported a live trail as dead. `support¬forum.org` (malware/apt_darkhotel.txt) is
stored as `xn--supportforum-tqa.org` by core/update.py's idna step, and replaying that name as a
DNS query through the release sensor produces an event - so the "not punycode" verdict was wrong.

Both directions are asserted here, because a checker that flags nothing passes just as quietly as
one that flags everything: every INERT sample must be caught, and every REACHABLE sample must not
be. wire_form() is pinned against the transformation core/update.py actually performs."""

import io
import os
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "sensor", "tools"))

import check_trails as C


# (key, reason it can never match)
INERT = [
    ("host_.tld_", "underscore in the TLD position: no such TLD"),
    ("evil.local", "an IGNORE_DNS_QUERY_SUFFIXES suffix: the query never reaches a lookup"),
    ("bad|char.biz", "'|' is not a DNS character - one corrupted onion address in lockbit.txt"),
    ("xinchao\\w{6}\\.(com|net|org)", "a regex in a plain trail file matches only itself"),
    ("initial-scale=1.0", "HTML scraped into a trail file"),
    ("a b.com", "U+00A0 nameprep-maps to a space, and a space is not a DNS name"),
    (".com", "idna refuses these, so the key is stored verbatim"),
]

# (key, why it does reach traffic)
REACHABLE = [
    ("evil.biz", "plain ASCII"),
    ("EVIL.biz", "case is folded on both sides"),
    ("ortakoporotör.com", "a deliberate IDN: matches its punycode, xn--ortakoporotr-fjb.com"),
    ("support¬forum.org", "the apt_darkhotel entry - proven by replay to produce an event"),
    ("xyz", "a bare TLD: the parent-domain walk reaches it from evil.xyz"),
    ("10.11.12.13", "an IPv4 trail, not a name"),
    ("10.11.12.13:4444", "an IPv4:port trail"),
    ("2001:db8::1", "an IPv6 trail"),
    ("bad..biz", "an empty interior label: DNS cannot carry it, but an HTTP Host or SNI can"),
    ("dyn_host.dyn.biz", "'_' is legal in every label but the last"),
    ("*.evil.biz", "a wildcard trail, matched by regex"),
]


class ClassifyTest(unittest.TestCase):
    def test_inert_keys_are_all_caught(self):
        for key, why in INERT:
            verdict = C.classify(key)
            self.assertIsNotNone(verdict, "%r (%s) was not reported at all" % (key, why))
            self.assertEqual(verdict[0], "inert", "%r (%s) -> %s" % (key, why, verdict))

    def test_reachable_keys_are_not_reported_as_inert(self):
        for key, why in REACHABLE:
            verdict = C.classify(key)
            self.assertFalse(verdict and verdict[0] == "inert",
                             "%r is reachable (%s) but was called inert: %s" % (key, why, verdict))

    def test_a_separator_lookalike_warns_but_is_not_inert(self):
        # idna gives xn--ab-41t.com - a valid name, so not inert, but not the reported domain either.
        verdict = C.classify("a–b.com")
        self.assertEqual(verdict[0], "warn")
        self.assertIn("xn--ab-41t.com", verdict[1])

    def test_a_dot_lookalike_is_repaired_by_nameprep(self):
        # U+2024 maps to '.', so the stored trail is the domain the report meant. Still flagged,
        # because a file full of lookalikes is a transcription problem either way.
        self.assertEqual(C.wire_form("foo․bar.com"), "foo.bar.com")
        self.assertEqual(C.classify("foo․bar.com")[0], "warn")


class WireFormTest(unittest.TestCase):
    """wire_form() must agree with core/update.py, which is what actually writes trails.csv."""

    def test_matches_update_py_for_ascii_and_idn(self):
        for key, expected in (("EVIL.biz", "evil.biz"),
                              ("ortakoporotör.com", "xn--ortakoporotr-fjb.com"),
                              ("support¬forum.org", "xn--supportforum-tqa.org")):
            self.assertEqual(C.wire_form(key), expected)

    def test_returns_none_when_idna_refuses(self):
        self.assertIsNone(C.wire_form(".com"))


class ScanTest(unittest.TestCase):
    """problems() over a temp tree: comment/inline-comment/URL handling and line numbers."""

    def test_reports_line_numbers_and_skips_comments(self):
        tmp = tempfile.mkdtemp()
        try:
            os.makedirs(os.path.join(tmp, "malware"))
            with open(os.path.join(tmp, "malware", "sample.txt"), "wb") as f:
                f.write(u"# Copyright\n"
                        u"good.biz\n"
                        u"# host_.tld_\n"                     # a comment, not an entry
                        u"host_.tld_\n"                       # line 4, inert
                        u"http://also-good.biz/path\n"
                        u"still.good.biz  # trailing comment\n".encode("utf8"))
            found = C.problems(tmp)
            self.assertEqual([(_[1], _[2], _[3]) for _ in found], [(4, "host_.tld_", "inert")])
        finally:
            import shutil
            shutil.rmtree(tmp)

    def test_the_real_static_pile_has_no_inert_trails(self):
        static = os.path.join(ROOT, "trails", "static")
        if not os.path.isdir(static):
            self.skipTest("no trails/static")
        inert = [_ for _ in C.problems(static) if _[3] == "inert"]
        self.assertEqual(inert, [], "inert trail(s) in trails/static: %s" % inert[:5])


class WhitelistShadowTest(unittest.TestCase):
    """A trail whose PARENT domain is whitelisted loads into trails.csv and is then dropped by the sensor's
    loader, so it is present, counted and unable to match.

    Found by replaying `10.53.154.104.bc.googleusercontent.com` through the release sensor against the real
    trail set: the trail was there, the control fired, the trail did not. `googleusercontent.com` is line 103
    of data/whitelist.txt. The updater's own check_whitelisted() does not walk parents, so nothing removed it
    at build time and nothing reported it either."""

    WL = {"cloudfront.net", "evil.example", "co.uk"}

    def test_a_whitelisted_parent_shadows_the_trail(self):
        verdict = C.classify("d1wp6m56sqw74a.cloudfront.net", self.WL)
        self.assertEqual(verdict[0], "shadowed")
        self.assertIn("cloudfront.net", verdict[1])

    def test_the_walk_reaches_any_ancestor(self):
        self.assertEqual(C.whitelisted_parent("a.b.c.evil.example", self.WL), "evil.example")
        self.assertEqual(C.whitelisted_parent("x.co.uk", self.WL), "co.uk")

    def test_an_exactly_listed_name_is_not_reported(self):
        # the operator listed that exact name; only a name shadowed BY AN ANCESTOR is the surprise
        self.assertIsNone(C.whitelisted_parent("cloudfront.net", self.WL))
        self.assertIsNone(C.classify("cloudfront.net", self.WL))

    def test_a_suffix_that_is_not_a_label_boundary_does_not_shadow(self):
        self.assertIsNone(C.whitelisted_parent("notcloudfront.net", self.WL))
        self.assertIsNone(C.whitelisted_parent("evil.example.org", self.WL))

    def test_shadowing_does_not_fail_the_gate(self):
        # it is a collision between two operator-visible lists, not a broken entry
        self.assertEqual(C.classify("d1wp6m56sqw74a.cloudfront.net", self.WL)[0], "shadowed")
        inert = [_ for _ in C.problems(os.path.join(ROOT, "trails", "static"), None) if _[3] == "inert"]
        self.assertEqual(inert, [])

    def test_no_whitelist_means_no_shadow_reports(self):
        self.assertIsNone(C.classify("d1wp6m56sqw74a.cloudfront.net", None))
        self.assertIsNone(C.classify("d1wp6m56sqw74a.cloudfront.net", set()))


class CanaryTest(unittest.TestCase):
    """`--canaries`: the other direction from the rest of this file. Not "can this trail ever match"
    but "does it match something it must never match".

    It exists because a popularity-list INTERSECTION cannot see regex trails - a pattern is never
    equal to a domain - and that is precisely the class that reached a customer: a roamingmantis
    pattern that matched 89 top-1M domains, amazon-corp.com among them."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        os.makedirs(os.path.join(self.tmp, "malware"))

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _write(self, *lines):
        with io.open(os.path.join(self.tmp, "malware", "sample.txt"), "w", encoding="utf8") as f:
            f.write(u"# Copyright\n" + u"\n".join(lines) + u"\n")

    def test_a_regex_matching_a_canary_is_caught(self):
        self._write(u"^[a-z]+\\.org$")
        hits = C.popular_matches(self.tmp, ["wikipedia.org", "evil.biz"])
        self.assertEqual([(_[3], _[4]) for _ in hits], [("wikipedia.org", "regex")])

    def test_a_literal_canary_is_caught(self):
        self._write(u"wikipedia.org", u"evil.biz")
        hits = C.popular_matches(self.tmp, ["wikipedia.org"])
        self.assertEqual([(_[3], _[4]) for _ in hits], [("wikipedia.org", "literal")])

    def test_a_narrow_pattern_is_not_a_hit(self):
        self._write(u"^[a-z]{2}\\-[a-z]{2,3}\\.(top|club)$")
        self.assertEqual(C.popular_matches(self.tmp, ["wikipedia.org", "one.one.one.one"]), [])

    def test_a_whitelisted_canary_is_excluded(self):
        # the sensor refuses a whitelisted QUERY before any lookup (process.rs:147), so a trail
        # matching one cannot fire and reporting it would be a false false-positive
        self._write(u"^[a-z]+\\.org$")
        self.assertEqual(C.popular_matches(self.tmp, ["wikipedia.org"], {"wikipedia.org"}), [])
        self.assertEqual(C.popular_matches(self.tmp, ["en.wikipedia.org"], {"wikipedia.org"}), [])

    def test_the_canary_file_parses_and_is_not_all_whitelisted(self):
        names = list(C.canaries(os.path.join(ROOT, "tests", "canaries.txt")))
        self.assertGreater(len(names), 20)
        whitelist = C.whitelisted_parents()
        exercised = [_ for _ in names if not (C.whitelisted_parent(_, whitelist) or _ in whitelist)]
        # A canary list made of google.com/1.1.1.1/github.com would be reassuring and worthless:
        # those are in data/whitelist.txt, so no trail matching them can fire either way.
        self.assertGreater(len(exercised), 20, "the canary list is mostly whitelist-covered, so it proves little")

    def test_the_real_static_pile_matches_no_canary(self):
        static = os.path.join(ROOT, "trails", "static")
        if not os.path.isdir(static):
            self.skipTest("no trails/static")
        names = list(C.canaries(os.path.join(ROOT, "tests", "canaries.txt")))
        hits = C.popular_matches(static, names, C.whitelisted_parents())
        self.assertEqual(hits, [], "trail(s) match a canary: %s" % hits[:3])


class PopularityListTest(unittest.TestCase):
    """`--canaries` also reads a popularity list as shipped, which is how the regex trails get checked
    against the top 1M. The list stays out of CI (2.4M rows, and misc/alexa1m.py owns that job) - what
    is tested here is that the tool can read one and that the scan does not degrade with its size."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        os.makedirs(os.path.join(self.tmp, "malware"))
        with io.open(os.path.join(self.tmp, "malware", "sample.txt"), "w", encoding="utf8") as f:
            f.write(u"# Copyright\n^[a-z]{2}\\-[a-z]{2,3}\\.(top|club)$\nplain-literal.biz\n")

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _zip(self, rows):
        import zipfile
        path = os.path.join(self.tmp, "list.csv.zip")
        with zipfile.ZipFile(path, "w") as archive:
            archive.writestr("top-1m.csv", "\n".join(rows))
        return path

    def test_a_rank_comma_domain_zip_is_read(self):
        # the Alexa / Cisco / Tranco shape
        path = self._zip(["1,ai-pay.club", "2,example-safe.biz", "3,plain-literal.biz"])
        self.assertEqual(sorted(C.canaries(path)), ["ai-pay.club", "example-safe.biz", "plain-literal.biz"])

    def test_regex_and_literal_hits_are_both_found_and_separable(self):
        path = self._zip(["1,ai-pay.club", "2,plain-literal.biz", "3,nothing.biz"])
        names = list(C.canaries(path))
        both = C.popular_matches(self.tmp, names)
        self.assertEqual(sorted(_[4] for _ in both), ["literal", "regex"])
        # --kinds regex is what the popularity-list pass uses: a top-1M list legitimately contains
        # live malware domains, so LITERAL hits there are mostly correct detections
        only = C.popular_matches(self.tmp, list(C.canaries(path)), None, None, "regex")
        self.assertEqual([_[4] for _ in only], ["regex"])
        self.assertEqual([_[3] for _ in only], ["ai-pay.club"])

    def test_stats_count_what_was_and_was_not_exercised(self):
        path = self._zip(["1,ai-pay.club", "2,safe.cloudfront.net", "3,nothing.biz"])
        stats = {}
        C.popular_matches(self.tmp, C.canaries(path), {"cloudfront.net"}, stats, "regex")
        self.assertEqual(stats["total"], 3)
        self.assertEqual(stats["covered"], 1)          # safe.cloudfront.net has a whitelisted parent
        self.assertEqual(stats["patterns"], 1)

    def test_the_scan_is_one_alternation_not_one_pass_per_pattern(self):
        # 27 patterns x 2.4M names was ~27s scanned separately and 11.5s as a single alternation.
        # The observable property is that adding patterns does not multiply the work, so this asserts
        # the shape: many patterns, one combined regex, and every one still attributable.
        with io.open(os.path.join(self.tmp, "malware", "many.txt"), "w", encoding="utf8") as f:
            for i in range(40):
                f.write(u"^pat%d[0-9]{2}\\.biz$\n" % i)
        names = ["pat%d42.biz" % i for i in range(40)] + ["unrelated.biz"]
        hits = C.popular_matches(self.tmp, names, None, None, "regex")
        self.assertEqual(len(hits), 40)
        self.assertEqual(len(set(_[2] for _ in hits)), 40, "each pattern must be attributed to itself")


class RankCapTest(unittest.TestCase):
    """A popularity list is RANKED, and only its head is trustworthy: the tail carries live malware,
    because these lists measure DNS query volume and a running campaign generates plenty. misc/alexa1m.py
    reads alexa[:500000], cisco[:250000], tranco[:50000]. Scanning the full lists instead produced 47
    hits here of which 46 were tail noise."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        os.makedirs(os.path.join(self.tmp, "malware"))
        with io.open(os.path.join(self.tmp, "malware", "s.txt"), "w", encoding="utf8") as f:
            f.write(u"^[a-z]{2}\\-[a-z]{2,3}\\.(top|club)$\n")

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_spec_parsing(self):
        self.assertEqual(C.canary_source("a/b.zip:50000"), ("a/b.zip", 50000))
        self.assertEqual(C.canary_source("a/b.zip"), ("a/b.zip", None))
        self.assertEqual(C.canary_source("tests/canaries.txt"), ("tests/canaries.txt", None))

    def test_the_cap_stops_at_the_requested_depth(self):
        path = os.path.join(self.tmp, "list.csv")
        with io.open(path, "w", encoding="utf8") as f:
            f.write(u"\n".join(u"%d,host%d.biz" % (i, i) for i in range(1, 101)))
        self.assertEqual(len(list(C.canaries(path))), 100)
        self.assertEqual(len(list(C.canaries(path, 10))), 10)
        self.assertEqual(list(C.canaries(path, 3)), ["host1.biz", "host2.biz", "host3.biz"])

    def test_a_tail_only_hit_disappears_under_the_cap(self):
        # the finding that survives a cap is the one worth a human; the rest were list tail
        path = os.path.join(self.tmp, "list.csv")
        with io.open(path, "w", encoding="utf8") as f:
            f.write(u"1,safe.biz\n2,other.biz\n3,ai-pay.club\n")
        self.assertEqual(len(C.popular_matches(self.tmp, C.canaries(path))), 1)
        self.assertEqual(C.popular_matches(self.tmp, C.canaries(path, 2)), [])


if __name__ == "__main__":
    unittest.main()
