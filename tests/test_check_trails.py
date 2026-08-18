# coding: utf-8
"""Unit tests for the static-trail reachability gate (sensor/tools/check_trails.py).

This is a gate on trails/static/, so its exit status has to mean something: it ran outside CI for
as long as it reported a live trail as dead. `support¬forum.org` (malware/apt_darkhotel.txt) is
stored as `xn--supportforum-tqa.org` by core/update.py's idna step, and replaying that name as a
DNS query through the release sensor produces an event - so the "not punycode" verdict was wrong.

Both directions are asserted here, because a checker that flags nothing passes just as quietly as
one that flags everything: every INERT sample must be caught, and every REACHABLE sample must not
be. wire_form() is pinned against the transformation core/update.py actually performs."""

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


if __name__ == "__main__":
    unittest.main()
