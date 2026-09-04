# coding: utf-8
"""Unit tests for the static-trail reachability gate (sensor/tools/check_trails.py).

This is a gate on the static trail pile, so its exit status has to mean something: it ran outside CI for
as long as it reported a live trail as dead. `support¬forum.org` (malware/apt_darkhotel.txt) is
stored as `xn--supportforum-tqa.org` by core/update.py's idna step, and replaying that name as a
DNS query through the release sensor produces an event - so the "not punycode" verdict was wrong.

Both directions are asserted here, because a checker that flags nothing passes just as quietly as
one that flags everything: every INERT sample must be caught, and every REACHABLE sample must not
be. wire_form() is pinned against the transformation core/update.py actually performs."""

import datetime
import io
import os
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "sensor", "tools"))

import check_trails as C


def trails_root():
    """The static-trail checkout, or None.

    The content moved to stamparm/trails in 3.2, so ROOT/trails/static will never exist again and
    a skip naming it can never stop being printed. These three assertions are OWNED by that
    repository's gate.yml, which runs this same checker on every commit - this runs them too when
    a checkout happens to be around, beside maltrail or wherever MALTRAIL_TRAILS_DIR points.
    """

    path = C._default_trails_path()      # MALTRAIL_TRAILS_DIR, then a sibling checkout
    return path if os.path.isdir(os.path.join(path, "malware")) else None


NO_CHECKOUT = "no stamparm/trails checkout (gate.yml in that repository runs this on every commit)"


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
    # Routable on purpose. These used to be 10.11.12.13, which is RFC1918 - and once classify()
    # started judging address trails, that was correctly reported inert, because update_trails()
    # drops bogons. The old pair asserted the blind spot, not the behaviour.
    ("45.83.220.17", "an IPv4 trail, not a name"),
    ("45.83.220.17:4444", "an IPv4:port trail"),
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
        static = trails_root()
        if not static:
            self.skipTest(NO_CHECKOUT)
        inert = [_ for _ in C.problems(static) if _[3] == "inert"]
        self.assertEqual(inert, [], "inert trail(s) in the static pile: %s" % inert[:5])


class HeaderTest(unittest.TestCase):
    """'# Reference:' / '# Aliases:' header hygiene (#19597).

    core/httpd.py finds a trail's source citation with a literal `rfind(b"\\n# Reference:")`, so a
    misspelled header is not a cosmetic problem: the lookup walks past it and the drawer shows the
    citation of an unrelated pile above. Both directions are asserted, because a checker that
    flags every comment line is as useless as one that flags nothing."""

    BAD = [
        ("# Referecne: https://example.invalid/a", "misspelled"),
        ("# Refernce: https://example.invalid/a", "misspelled"),
        ("# Referenced: https://example.invalid/a", "misspelled"),
        ("# Alises: foo, bar", "misspelled"),
        ("#Reference: https://example.invalid/a", "space"),
        ("#  Reference: https://example.invalid/a", "space"),
        ("## Reference: https://example.invalid/a", "'#'"),
        ("# reference: https://example.invalid/a", "case"),
        ("# Reference:: https://example.invalid/a", "colons"),
        ("# Reference:https://example.invalid/a", "space"),
        ("# Reference:  https://example.invalid/a", "space"),
        ("# Reference: https://example.invalid/a ", "trailing"),
        ("# Reference: ", "trailing"),
    ]

    GOOD = [
        "# Reference: https://example.invalid/a",
        "# Aliases: foo, bar",
        "# Reference:",                      # deliberate pile break: no citation for what follows
        "# Copyright (c) 2014-present Maltrail developers",
        "# Note: this pile came from a sandbox run",
        "# Generic trails:",
        "# TITLE-HOST/IP=airbot admin panel",
        "# evil.example",                    # a commented-out entry
    ]

    def test_every_malformed_header_is_caught(self):
        for line, hint in self.BAD:
            why = C.header_problem(line)
            self.assertTrue(why, "not caught: %r" % line)
            self.assertIn(hint, why, "%r reported as %r, expected something about %r" % (line, why, hint))

    def test_ordinary_comments_are_left_alone(self):
        for line in self.GOOD:
            self.assertIsNone(C.header_problem(line), "false positive on %r" % line)

    def test_line_numbers_come_back(self):
        tmp = tempfile.mkdtemp()
        try:
            os.makedirs(os.path.join(tmp, "malware"))
            with open(os.path.join(tmp, "malware", "sample.txt"), "wb") as f:
                f.write(u"# Reference: https://example.invalid/a\n"
                        u"good.biz\n"
                        u"# Referecne: https://example.invalid/b\n"
                        u"other.biz\n".encode("utf8"))
            found = C.header_problems(tmp)
            self.assertEqual([(_[1], "misspelled" in _[3]) for _ in found], [(3, True)])
        finally:
            import shutil
            shutil.rmtree(tmp)

    def test_the_real_static_pile_has_clean_headers(self):
        static = trails_root()
        if not static:
            self.skipTest(NO_CHECKOUT)
        found = C.header_problems(static)
        self.assertEqual(found, [], "malformed header(s): %s" % [(_[0], _[1], _[3]) for _ in found[:5]])


class WhitelistShadowTest(unittest.TestCase):
    """Which whitelist entries actually stop a trail, since 3.2 changed the answer.

    The retired Python sensor suppressed a name whenever ANY ancestor was whitelisted. The Rust sensor applies
    longest-match precedence: only an entry equal to the FULL name vetoes a trail hit, so a trail on
    `evil.cloudfront.net` fires even though `cloudfront.net` is whitelisted. That is asserted on the engine side
    by sensor/tests/detection.rs::trail_under_whitelisted_parent_fires and its three siblings; these tests exist
    so the CHECKER cannot drift away from it again.

    It had drifted. The report still applied the ancestor rule, and said "the sensor's loader drops this trail" -
    which the loader does not do, its check_whitelisted() being exact-match plus IPv4 ranges like the updater's.
    Measured against the current content that was 3,081 live trails on shared platforms called dead, against 11
    entries that really are."""

    # not ".example": that suffix is in IGNORE_DNS_QUERY_SUFFIXES, so a name under it is inert
    # for a different reason and would not exercise the whitelist rule at all
    WL = {"cloudfront.net", "evil.biz", "co.uk"}

    def test_a_whitelisted_ancestor_does_not_shadow_a_more_specific_trail(self):
        # the case the engine fires on; reporting it as dead is what this whole class is about
        self.assertIsNone(C.classify("d1wp6m56sqw74a.cloudfront.net", self.WL))
        self.assertIsNone(C.classify("a.b.c.evil.biz", self.WL))

    def test_an_exact_whitelist_entry_does_shadow(self):
        # a tie goes to the whitelist, and the build drops it before trails.csv
        verdict = C.classify("cloudfront.net", self.WL)
        self.assertEqual(verdict[0], "shadowed")
        self.assertIn("whitelist", verdict[1])

    def test_the_parent_walk_itself_still_works(self):
        # kept for the heuristics story and for wildcard trails, which do NOT earn the precedence
        self.assertEqual(C.whitelisted_parent("a.b.c.evil.biz", self.WL), "evil.biz")
        self.assertEqual(C.whitelisted_parent("x.co.uk", self.WL), "co.uk")
        self.assertIsNone(C.whitelisted_parent("cloudfront.net", self.WL))

    def test_a_suffix_that_is_not_a_label_boundary_does_not_shadow(self):
        self.assertIsNone(C.classify("notcloudfront.net", self.WL))
        self.assertIsNone(C.classify("evil.biz.org", self.WL))

    def test_shadowing_does_not_fail_the_gate(self):
        # it is a collision between two operator-visible lists, not a broken entry
        self.assertEqual(C.classify("cloudfront.net", self.WL)[0], "shadowed")

    def test_no_whitelist_means_no_shadow_reports(self):
        self.assertIsNone(C.classify("cloudfront.net", None))
        self.assertIsNone(C.classify("cloudfront.net", set()))

    def test_a_url_trail_on_a_cleared_host_is_reported_for_the_right_reason(self):
        # a bare-domain trail dies at BUILD time (its full key is the whitelisted name); a URL trail on
        # that host survives the build and the load, and is vetoed when the request arrives. Both are
        # dead, and a report naming the wrong mechanism sends the reader to the wrong file.
        bare = C.classify("cloudfront.net", self.WL, "", "cloudfront.net")
        url = C.classify("cloudfront.net", self.WL, "", "cloudfront.net/evil/loader.js")
        self.assertEqual((bare[0], url[0]), ("shadowed", "shadowed"))
        self.assertIn("build drops", bare[1])
        self.assertIn("never examines", url[1])

    def test_the_raw_key_travels_with_the_reduced_one(self):
        tmp = tempfile.mkdtemp()
        self.addCleanup(__import__("shutil").rmtree, tmp, True)
        os.mkdir(os.path.join(tmp, "malware"))
        with io.open(os.path.join(tmp, "malware", "s.txt"), "w", encoding="utf8") as handle:
            handle.write(u"host.example.biz/a/b.js\nbare.example.biz\n")
        got = [(key, raw) for _, key, raw in C.entries(os.path.join(tmp, "malware", "s.txt"))]
        self.assertEqual(got, [("host.example.biz", "host.example.biz/a/b.js"),
                               ("bare.example.biz", "bare.example.biz")])

    def test_the_real_pile_reports_only_exact_collisions(self):
        static = trails_root()
        if not static:
            self.skipTest(NO_CHECKOUT)
        whitelist = C.whitelisted_parents()
        shadowed = [_ for _ in C.problems(static, whitelist) if _[3] == "shadowed"]
        stale = [_ for _ in shadowed if _[2].lower() not in whitelist]
        self.assertEqual(stale[:3], [], "reported as shadowed without being in the whitelist itself")


class PublicSuffixTest(unittest.TestCase):
    """A trail equal to a public suffix names a REGISTRY, not a host.

    The sensor's parent-domain walk means a trail on `com.cn` matches every domain in China's commercial
    namespace - a false positive against millions of sites from one line. The rule for catching it existed,
    in a script on one workstation that read a gitignored copy of the list, so nothing in CI could apply it.

    suspicious/domain.txt lists whole namespaces on purpose and writes them with a LEADING DOT (`.tk`,
    `.xyz`). That dot is what separates "the entire namespace, deliberately" from "an ordinary trail nobody
    noticed was a registry", and it is free to write because the loader strips it - core/assemble.py does
    `line.strip('.')`, so `.co.cl` and `co.cl` build the identical trail."""

    SUF = {"com.cn", "co.uk", "tk", "augustow.pl"}

    def test_a_bare_public_suffix_is_reported(self):
        verdict = C.classify("com.cn", None, "", "com.cn", self.SUF)
        self.assertEqual(verdict[0], "overbroad")
        self.assertIn("every domain in that registry", verdict[1])

    def test_the_leading_dot_marks_it_deliberate(self):
        # written as ".tk" in suspicious/domain.txt: the whole namespace, on purpose
        self.assertIsNone(C.classify("tk", None, "", ".tk", self.SUF))

    def test_a_host_under_a_suffix_is_fine(self):
        self.assertIsNone(C.classify("evil.com.cn", None, "", "evil.com.cn", self.SUF))
        self.assertIsNone(C.classify("shop.co.uk", None, "", "shop.co.uk", self.SUF))

    def test_no_list_means_no_reports(self):
        # the vendored file is optional; without it the check must be silent, not wrong
        self.assertIsNone(C.classify("com.cn", None, "", "com.cn", None))
        self.assertIsNone(C.classify("com.cn", None, "", "com.cn", set()))

    def test_it_fails_the_gate(self):
        tmp = tempfile.mkdtemp()
        self.addCleanup(__import__("shutil").rmtree, tmp, True)
        os.mkdir(os.path.join(tmp, "malware"))
        with io.open(os.path.join(tmp, "malware", "x.txt"), "w", encoding="utf8") as handle:
            handle.write(u"com.cn\nevil.example.biz\n")
        found = C.problems(tmp, None, self.SUF)
        self.assertEqual([(_[2], _[3]) for _ in found], [("com.cn", "overbroad")])

    def test_the_shipped_list_is_icann_only_and_carries_both_idn_forms(self):
        suffixes = C.public_suffixes()
        self.assertGreater(len(suffixes), 6000)
        for known in ("com.cn", "co.uk", "xyz", "augustow.pl"):
            self.assertIn(known, suffixes, "%s should be an ICANN suffix" % known)
        # PRIVATE-section hosting slots must NOT be here: Maltrail tracks per-user subdomains on them
        for hosting in ("blogspot.com", "ply.gg", "duckdns.org", "s3.amazonaws.com"):
            self.assertNotIn(hosting, suffixes, "%s is a hosting suffix, not a registry" % hosting)
        # an IDN suffix in both spellings, because trails are stored punycoded
        self.assertIn("xn--p1ai", suffixes)

    def test_the_shipped_list_carries_a_refresh_stamp(self):
        path = os.path.join(ROOT, "data", "public_suffix_icann.txt")
        self.assertIsNotNone(C.refreshed_on(path), "public_suffix_icann.txt lost its '# Refreshed:' line")

    def test_the_real_pile_has_none(self):
        static = trails_root()
        if not static:
            self.skipTest(NO_CHECKOUT)
        found = [_ for _ in C.problems(static, None) if _[3] == "overbroad"]
        self.assertEqual([(_[2], _[0]) for _ in found][:5], [], "trail(s) that match a whole registry")


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

    def test_a_canary_under_a_whitelisted_parent_is_still_exercised(self):
        # since 3.2 a whitelisted ANCESTOR does not protect its children - an exact trail on the more
        # specific name fires - so skipping this canary would hide a real false positive
        self._write(u"en.wikipedia.org")
        hits = C.popular_matches(self.tmp, ["en.wikipedia.org"], {"wikipedia.org"})
        self.assertEqual([_[3] for _ in hits], ["en.wikipedia.org"])

    def test_the_canary_file_parses_and_is_not_all_whitelisted(self):
        names = list(C.canaries(os.path.join(ROOT, "tests", "canaries.txt")))
        self.assertGreater(len(names), 20)
        whitelist = C.whitelisted_parents()
        # exact entries only: a whitelisted ANCESTOR no longer protects its children, so a canary under
        # one is still exercised. On the top-100k list that is 197 names the old rule skipped.
        exercised = [_ for _ in names if _ not in whitelist]
        # A canary list made of google.com/1.1.1.1/github.com would be reassuring and worthless:
        # those are in data/whitelist.txt, so no trail matching them can fire either way.
        self.assertGreater(len(exercised), 20, "the canary list is mostly whitelist-covered, so it proves little")

    def test_the_real_static_pile_matches_no_canary(self):
        static = trails_root()
        if not static:
            self.skipTest(NO_CHECKOUT)
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
        path = self._zip(["1,ai-pay.club", "2,cloudfront.net", "3,safe.cloudfront.net", "4,nothing.biz"])
        stats = {}
        C.popular_matches(self.tmp, C.canaries(path), {"cloudfront.net"}, stats, "regex")
        self.assertEqual(stats["total"], 4)
        # only the EXACT entry is covered. safe.cloudfront.net merely has a whitelisted parent, which
        # stopped protecting it in 3.2, so it is exercised like any other name.
        self.assertEqual(stats["covered"], 1)
        self.assertEqual(stats["covered_examples"], ["cloudfront.net"])
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



class AddressTrailsAreJudgedToo(unittest.TestCase):
    """An address trail can be unreachable, and until this it was the one inert class nothing saw.

    update_trails() deletes any trail whose leading quad is a CDN edge or a bogon, so such an entry
    is added, reviewed, committed - and then dropped from every build. The report said "C2 at
    104.16.155.10:8888", somebody put it in, and no deployment ever matched it. That is worse than a
    false positive: it looks like detection. 451 entries in the content repository were in this
    state when the check was written.
    """

    def test_cdn_edge_is_inert(self):
        for key in ("104.16.155.10", "104.16.155.10:8888"):
            verdict = C.classify(key, set(), "")
            self.assertIsNotNone(verdict, key)
            self.assertEqual(verdict[0], "inert")
            self.assertIn("CDN edge", verdict[1])

    def test_bogon_is_inert(self):
        verdict = C.classify("10.0.0.5", set(), "")
        self.assertIsNotNone(verdict)
        self.assertEqual(verdict[0], "inert")
        self.assertIn("bogon", verdict[1])

    def test_a_routable_address_is_clean(self):
        # The check has to be able to stay quiet, or it is just noise with a reason attached.
        for key in ("45.83.220.17", "45.83.220.17:443"):
            self.assertIsNone(C.classify(key, set(), ""), key)

    def test_parking_and_sinkhole_are_exempt(self):
        # update_trails() spares them: naming shared infrastructure is the entire point of those
        # piles. Mirror it, or this reports deliberate entries as broken.
        for info in ("parking site", "sinkhole"):
            self.assertIsNone(C.classify("104.16.155.10", set(), info), info)


class UrlTrailsAreNotDomainTrails(unittest.TestCase):
    """A path under a popular host is not a trail on that host.

    entries() reduces `archive.org/download/x.hta` to `archive.org` because the reachability checks
    only care whether the HOST is a resolvable name. trail_index() reused that, so the literal index
    claimed a trail on archive.org and the top-10k canary run reported it - along with discord.com,
    codeberg.org and unwomen.org. Ten of eighty hits, every one a correct trail."""

    URL_TRAILS = [
        "archive.org/download/hbankers-latest/HBankers_Latest.hta",
        "https://telegra.ph/Functions-04-03",
        "discord.com/api/webhooks/1354279778441629867/",
        "unwomen.org/jquery-3.3.1.min.js",
    ]

    def _tree(self):
        tmp = tempfile.mkdtemp()
        os.mkdir(os.path.join(tmp, "malware"))
        with io.open(os.path.join(tmp, "malware", "sample.txt"), "w", encoding="utf8") as handle:
            handle.write(u"\n".join(self.URL_TRAILS) + u"\nevil.example\n")
        return tmp

    def test_the_host_of_a_url_trail_is_not_indexed_as_a_literal(self):
        tmp = self._tree()
        try:
            literals, _ = C.trail_index(tmp)
            for host in ("archive.org", "telegra.ph", "discord.com", "unwomen.org"):
                self.assertNotIn(host, literals, "%s indexed as a literal trail" % host)
            self.assertIn("evil.example", literals, "a bare domain trail must still be indexed")
        finally:
            import shutil
            shutil.rmtree(tmp)

    def test_a_popularity_list_does_not_match_a_url_trail(self):
        tmp = self._tree()
        try:
            hits = C.popular_matches(tmp, ["archive.org", "discord.com", "evil.example"])
            self.assertEqual([_[3] for _ in hits], ["evil.example"])
        finally:
            import shutil
            shutil.rmtree(tmp)

    def test_reachability_still_sees_only_the_host(self):
        # the other caller must NOT change: classify() judges names, and a path is not one
        tmp = self._tree()
        try:
            keys = [key for _, key, _raw in C.entries(os.path.join(tmp, "malware", "sample.txt"))]
            self.assertIn("archive.org", keys)
            self.assertIn("telegra.ph", keys)
        finally:
            import shutil
            shutil.rmtree(tmp)


class RefreshStampTest(unittest.TestCase):
    """The vendored top-10k list says when it was last regenerated, and the tool says it out loud.

    Never fatal. A stale canary list is wrong in the harmless direction - a domain that was popular
    a year ago is still one that must never be flagged - so all staleness costs is coverage of names
    that became popular since. This exists because the failure mode of a hand-maintained snapshot is
    that everybody forgets it is a snapshot."""

    def _stamped(self, body):
        handle, path = tempfile.mkstemp(suffix=".txt")
        os.close(handle)
        with io.open(path, "w", encoding="utf8") as out:
            out.write(body)
        self.addCleanup(os.unlink, path)
        return path

    def test_a_fresh_stamp_is_reported_not_flagged(self):
        today = datetime.date.today()
        note = C.staleness(self._stamped(u"# Refreshed: %s\nexample.com\n" % today))
        self.assertTrue(note.startswith("[i] "), note)
        self.assertIn("0 day(s) ago", note)

    def test_an_old_stamp_asks_to_be_regenerated(self):
        old = datetime.date.today() - datetime.timedelta(days=C.STALE_DAYS + 1)
        note = C.staleness(self._stamped(u"# Refreshed: %s\nexample.com\n" % old))
        self.assertTrue(note.startswith("[!] "), note)
        self.assertIn("regenerating", note)

    def test_a_file_with_no_stamp_says_nothing(self):
        # tests/canaries.txt is hand-picked rather than a snapshot, so it carries no stamp and must
        # not be nagged about
        self.assertIsNone(C.staleness(self._stamped(u"# hand-picked\nexample.com\n")))
        self.assertIsNone(C.staleness(self._stamped(u"# Refreshed: not-a-date\nexample.com\n")))

    def test_the_shipped_list_carries_a_stamp(self):
        # a regeneration that drops the stamp would silently disable the reminder
        path = os.path.join(ROOT, "tests", "canaries-top100k.txt")
        self.assertIsNotNone(C.refreshed_on(path), "tests/canaries-top100k.txt lost its '# Refreshed:' line")
        names = [_ for _ in C.canaries(path)]
        self.assertEqual(len(names), 100000, "the canary list is no longer 100,000 names")
        self.assertTrue(all(not _.startswith("#") for _ in names), "a comment leaked through as a canary")

    def test_the_literal_depth_is_the_head_of_the_same_file(self):
        # gate.yml reads this file twice: whole for regexes, ':30000' for literals. If canary_source
        # or canaries() stopped honouring the cap, the literal gate would quietly widen to 100k and
        # start failing on correct trails.
        path = os.path.join(ROOT, "tests", "canaries-top100k.txt")
        source, limit = C.canary_source("%s:30000" % path)
        self.assertEqual(limit, 30000)
        head = [_ for _ in C.canaries(source, limit)]
        self.assertEqual(len(head), 30000)
        self.assertEqual(head, [_ for _ in C.canaries(path)][:30000])


class AllowFileTest(unittest.TestCase):
    """Correct trails that happen to be ranked are written down, not deleted.

    trafficconverter.biz is Conficker's 2008 C2 at rank #28,676 - ranked because infected hosts
    still beacon at it. Quieting that by removing the trail would be the wrong repair, so the reason
    is recorded instead. Anything NOT in the file still fails, which is how lnkd.in, selcdn.ru and
    totalav.com were found and removed."""

    def test_reasons_and_blank_lines_are_stripped(self):
        handle, path = tempfile.mkstemp(suffix=".txt")
        os.close(handle)
        self.addCleanup(os.unlink, path)
        with io.open(path, "w", encoding="utf8") as out:
            out.write(u"# a header\n\nevil.example   # because\n  other.example\n\n")
        self.assertEqual(list(C.allow_file(path)), ["evil.example", "other.example"])

    def test_the_shipped_allow_file_only_names_trails_that_are_still_listed(self):
        # an allow entry outliving its trail is a stale exception nobody will notice
        allowed = list(C.allow_file(os.path.join(ROOT, "tests", "canaries-allow.txt")))
        self.assertTrue(allowed, "the allow file is empty")
        static = trails_root()
        if not static:
            self.skipTest(NO_CHECKOUT)
        literals = {}
        for pile in ("malware", "malicious"):
            literals.update(C.trail_index(os.path.join(static, pile))[0])
        stale = [_ for _ in allowed if _ not in literals]
        self.assertEqual(stale, [], "allow entries whose trail is gone: %s" % stale)


class EmptyPathIsNotAPass(unittest.TestCase):
    """Handed a path with no trails in it, the tool must refuse rather than report a clean run.

    _default_trails_path() falls back to a sibling checkout that need not exist. ci.yml gated on
    `check_trails.py` with no arguments, so after the split it walked a missing directory, found
    nothing, printed "0 entry(ies) that cannot match" and exited 0 - a green gate over no content
    at all, for months. Exit 2 keeps "could not run" apart from "ran and found problems"."""

    def test_a_missing_directory_is_not_scannable(self):
        self.assertFalse(C._has_trails(os.path.join(tempfile.gettempdir(), "no-such-trails-dir")))

    def test_a_directory_with_no_trail_files_is_not_scannable(self):
        tmp = tempfile.mkdtemp()
        self.addCleanup(__import__("shutil").rmtree, tmp)
        self.assertFalse(C._has_trails(tmp))
        with io.open(os.path.join(tmp, "notes.md"), "w", encoding="utf8") as handle:
            handle.write(u"not a trail file\n")
        self.assertFalse(C._has_trails(tmp))

    def test_one_trail_file_anywhere_beneath_is_enough(self):
        tmp = tempfile.mkdtemp()
        self.addCleanup(__import__("shutil").rmtree, tmp)
        os.makedirs(os.path.join(tmp, "malware"))
        with io.open(os.path.join(tmp, "malware", "x.txt"), "w", encoding="utf8") as handle:
            handle.write(u"evil.example\n")
        self.assertTrue(C._has_trails(tmp))


if __name__ == "__main__":
    unittest.main()
