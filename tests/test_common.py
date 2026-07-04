# coding: utf-8
"""Unit tests for core/common.py pure helpers (no network / no loaded trail DB). Locks the
behavior of the low-level utilities the sensor and server rely on -- especially is_local's RFC1918
ranges (a past bug missed 172.16-31) and get_text's defensive decoding."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from core import common as C


class TestGetText(unittest.TestCase):
    def test_bytes_and_str(self):
        self.assertEqual(C.get_text(b"abc"), "abc")
        self.assertEqual(C.get_text("abc"), "abc")

    def test_invalid_utf8_does_not_raise(self):
        # the exact replacement glyph differs across py2/py3; the CONTRACT is: never raise, return text
        out = C.get_text(b"\xff\xfe")
        self.assertTrue(isinstance(out, ("".__class__, u"".__class__)))
        self.assertIsNotNone(out)


class TestGetExMessage(unittest.TestCase):
    def test_message(self):
        try:
            raise ValueError("boom")
        except Exception as e:
            self.assertEqual(C.get_ex_message(e), "boom")


class TestIsLocal(unittest.TestCase):
    def test_rfc1918_and_loopback(self):
        for ip in ("10.0.0.1", "172.16.0.1", "172.20.5.5", "172.31.255.255", "192.168.1.1", "127.0.0.1"):
            self.assertTrue(C.is_local(ip), ip)

    def test_public_and_boundaries(self):
        for ip in ("8.8.8.8", "172.15.0.1", "172.32.0.1", "11.0.0.1", "193.168.0.1"):
            self.assertFalse(C.is_local(ip), ip)   # 172.15/172.32 are the off-by-one boundaries a past bug got wrong

    def test_none(self):
        self.assertFalse(C.is_local(None))


class TestBogon(unittest.TestCase):
    def test_bogon_vs_public(self):
        self.assertTrue(C.bogon_ip("0.0.0.0"))
        self.assertFalse(C.bogon_ip("8.8.8.8"))


class TestGetRegex(unittest.TestCase):
    def test_plain_alternation(self):
        self.assertEqual(C.get_regex(["a.com", "b.com"]), r"(?:a\.com|b\.com)")

    def test_empty(self):
        self.assertEqual(C.get_regex([]), "")

    def test_common_affix_factoring(self):
        # get_regex factors shared prefixes/suffixes into a trie-like alternation (compact matching)
        self.assertEqual(C.get_regex(["car", "cat"]), "ca(?:r|t)")

    def test_metachars_escaped_literally(self):
        # '*' and '?' in trails are LITERAL here (get_regex is not a wildcard expander) -> escaped
        self.assertEqual(C.get_regex(["*.evil.com"]), r"\*\.evil\.com")
        import re
        rx = C.get_regex(["a.com", "b.com"])
        self.assertIsNone(re.search(rx, "aXcomZ"))       # the '.' is escaped, not "any char"
        self.assertIsNotNone(re.search(rx, "a.com"))


class TestCheckWhitelisted(unittest.TestCase):
    def test_builtin_ranges_match(self):
        # WHITELIST_RANGES ships common infra (e.g. Google DNS); a bare IP in a whitelisted range -> True
        self.assertTrue(C.check_whitelisted("8.8.8.8"))
        # a random doc-range IP is not whitelisted
        self.assertFalse(C.check_whitelisted("203.0.113.7"))

    def test_domain_not_range_matched(self):
        # a domain that merely starts with digits must NOT be range-matched (whitelist-bypass guard)
        self.assertFalse(C.check_whitelisted("10.0.0.1.evil.com"))

    def test_exact_member_whitelisted(self):
        # an exact string in WHITELIST is whitelisted regardless of range logic
        saved = C.WHITELIST
        try:
            C.WHITELIST = set(["good.example.com"])
            self.assertTrue(C.check_whitelisted("good.example.com"))
            self.assertFalse(C.check_whitelisted("evil.example.com"))
        finally:
            C.WHITELIST = saved


class TestIpcatLookup(unittest.TestCase):
    """ipcat_lookup backs /check_ip. The static seed (STATIC_IPCAT_LOOKUPS) is checked before any SQLite
    fallback, so these are deterministic regardless of whether an ipcat DB file exists."""

    def test_none(self):
        self.assertIsNone(C.ipcat_lookup(None))

    def test_static_exact_hit(self):
        self.assertEqual(C.ipcat_lookup("66.240.192.138"), "shodan.io")   # exact IP in the static seed

    def test_static_range_hit(self):
        self.assertEqual(C.ipcat_lookup("71.6.216.40"), "labs.rapid7.com")  # inside 71.6.216.32-63


class TestWhitelistRangeCidr(unittest.TestCase):
    """read_whitelist stores CIDR ranges that check_whitelisted matches as `ip & mask == prefix`. A
    non-network-aligned CIDR in the whitelist file (e.g. 10.0.5.0/16) must still whitelist its whole
    subnet -- otherwise whitelisted traffic still alerts (false positives)."""

    def setUp(self):
        from core import settings
        self.settings = settings
        self._orig_uw = settings.config.USER_WHITELIST

    def tearDown(self):
        self.settings.config.USER_WHITELIST = self._orig_uw
        self.settings.read_whitelist()               # restore the real whitelist for other tests

    def test_non_aligned_cidr_whitelists_subnet(self):
        import tempfile
        fd, p = tempfile.mkstemp(suffix=".txt")
        os.write(fd, b"10.0.5.0/16\n"); os.close(fd)   # NOT network-aligned; means 10.0.0.0/16
        try:
            self.settings.config.USER_WHITELIST = p
            self.settings.read_whitelist()
            self.assertTrue(C.check_whitelisted("10.0.99.7"), "in-subnet IP must be whitelisted")
            self.assertFalse(C.check_whitelisted("11.0.0.1"), "out-of-subnet IP must NOT be whitelisted")
        finally:
            os.unlink(p)


class TestWorstAsns(unittest.TestCase):
    """worst_asns backs /check_ip (returns the 'worst ASN' name for an IP in a flagged range, else None).
    Prefixes are stored masked, so a non-aligned range still matches its whole subnet."""

    def test_none_and_non_ip(self):
        self.assertIsNone(C.worst_asns(None))
        self.assertIsNone(C.worst_asns("not.an.ip"))

    def test_range_match(self):
        from core.addr import addr_to_int, make_mask
        saved = C.WORST_ASNS
        try:
            m = make_mask(16)
            C.WORST_ASNS = {"5": [(addr_to_int("5.6.5.0") & m, m, "badasn")]}   # non-aligned 5.6.5.0/16 -> 5.6.0.0
            self.assertEqual(C.worst_asns("5.6.9.9"), "badasn")   # in-subnet
            self.assertIsNone(C.worst_asns("6.6.9.9"))            # different first octet -> no bucket
        finally:
            C.WORST_ASNS = saved


class TestCdnIp(unittest.TestCase):
    def test_none_and_empty(self):
        self.assertFalse(C.cdn_ip(None))
        self.assertFalse(C.cdn_ip(""))

    def test_non_ip_no_crash(self):
        self.assertFalse(C.cdn_ip("not.an.ip"))          # addr_to_int raises -> caught -> False

    def test_range_match(self):
        from core.addr import addr_to_int, make_mask
        saved = C.CDN_RANGES
        try:
            C.CDN_RANGES = {"1": [(addr_to_int("1.2.0.0") & make_mask(16), make_mask(16))]}
            self.assertTrue(C.cdn_ip("1.2.3.4"))          # inside 1.2.0.0/16
            self.assertFalse(C.cdn_ip("1.9.9.9"))         # same first octet, outside the range
            self.assertFalse(C.cdn_ip("2.2.3.4"))         # different first octet -> no bucket
        finally:
            C.CDN_RANGES = saved


if __name__ == "__main__":
    unittest.main()
