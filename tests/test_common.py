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


class TestUsesPublishedKey(unittest.TestCase):
    """The key Maltrail shipped in misc/server.pem is public, so the server must refuse it.

    Deleting the file from the tree rotated nothing: the blob is still in this repository's git
    history and in the /etc/maltrail of everyone who copied it once. Recognition is therefore by
    content, and it has to survive the two ways an operator's copy differs from the original file -
    a different filename, and a fresh certificate generated around the same key.

    The published key is deliberately NOT a fixture here (re-committing it would undo the point).
    The matching logic is exercised against a synthetic fingerprint set, and the shipped set is
    checked for the two digests separately - so nothing in this file depends on git history being
    present, which a shallow CI checkout does not guarantee.
    """

    def _pem(self, blocks, mangle=False):
        import base64
        import tempfile

        out = []
        for kind, der in blocks:
            body = base64.b64encode(der).decode("ascii")
            sep = "\r\n" if mangle else "\n"
            wrapped = sep.join(body[i:i + 64] for i in range(0, len(body), 64))
            out.append("-----BEGIN %s-----%s%s%s-----END %s-----%s" % (kind, sep, wrapped, sep, kind, sep))
            if mangle:
                out.append("\n   \n")   # stray whitespace between blocks
        handle = tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False)
        handle.write("".join(out))
        handle.close()
        self.addCleanup(os.unlink, handle.name)
        return handle.name

    def _sha256(self, der):
        import hashlib
        return hashlib.sha256(der).hexdigest()

    def test_a_pem_holding_a_known_bad_block_is_rejected(self):
        der = b"\x30\x82pretend this is the published private key"
        path = self._pem([("PRIVATE KEY", der), ("CERTIFICATE", b"\x30\x82some certificate")])
        self.assertTrue(C.uses_published_key(path, {self._sha256(der): "private key"}))

    def test_the_key_is_recognised_without_its_original_certificate(self):
        # A fresh self-signed certificate around the same key is still the same public key, and an
        # operator who renamed the file has not changed who holds it either.
        der = b"\x30\x82pretend this is the published private key"
        path = self._pem([("PRIVATE KEY", der), ("CERTIFICATE", b"\x30\x82a NEWLY generated cert")])
        self.assertTrue(C.uses_published_key(path, {self._sha256(der): "private key"}))

    def test_whitespace_and_block_order_do_not_matter(self):
        der = b"\x30\x82pretend this is the published private key"
        path = self._pem([("CERTIFICATE", b"\x30\x82unrelated"), ("PRIVATE KEY", der)], mangle=True)
        self.assertTrue(C.uses_published_key(path, {self._sha256(der): "private key"}))

    def test_an_unrelated_pem_is_accepted(self):
        path = self._pem([("PRIVATE KEY", b"\x30\x82a key nobody published")])
        self.assertFalse(C.uses_published_key(path))
        self.assertFalse(C.uses_published_key(path, {"0" * 64: "private key"}))

    def test_garbage_in_a_pem_block_is_not_a_crash(self):
        import tempfile
        handle = tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False)
        handle.write("-----BEGIN PRIVATE KEY-----\nnot base64 at all !!!\n-----END PRIVATE KEY-----\n")
        handle.close()
        self.addCleanup(os.unlink, handle.name)
        self.assertFalse(C.uses_published_key(handle.name))

    def test_an_unreadable_pem_is_neither_accepted_nor_rejected(self):
        # None, not False: "could not tell" must not read as "verified fine".
        self.assertIsNone(C.uses_published_key(os.path.join(os.sep, "nonexistent", "server.pem")))

    def test_the_shipped_fingerprint_set_still_names_both_blocks(self):
        # The whole check is these two constants; losing one silently would re-accept the key.
        # Reproduce them with: git show 0f876cfa^:misc/server.pem
        self.assertEqual(
            sorted(C.PUBLISHED_PEM_FINGERPRINTS),
            ["2905a63fd3399bda47f286dac449edf734cdbdbe51b5d7d5cf241d2f74ea58c1",
             "9395629637a4fc48290286313b60ae26fb6bdcd8018db45894ab54c273d1a2c3"])
        self.assertEqual(sorted(C.PUBLISHED_PEM_FINGERPRINTS.values()), ["certificate", "private key"])


class TestRipeLookup(unittest.TestCase):
    """The server-side half of the RIPEstat enrichment that used to be a JSONP <script> in the page.

    Nothing here talks to RIPEstat: urlopen is replaced, which is also how the call counts below
    prove the two cache behaviours - a hit costs no request, and a FAILED lookup is remembered
    briefly too (an air-gapped server would otherwise pay a connect timeout per visible IP, per
    page load, forever).
    """

    def setUp(self):
        self._saved_open = C._urllib.request.urlopen
        self._calls = []
        C._ripe_cache.clear()
        C.config.pop("DISABLE_RIPE_LOOKUPS", None)
        self.addCleanup(self._restore)

    def _restore(self):
        C._urllib.request.urlopen = self._saved_open
        C._ripe_cache.clear()
        C.config.pop("DISABLE_RIPE_LOOKUPS", None)

    def _answer(self, payload, fail=False):
        import json

        class _Resp(object):
            def __init__(self, body):
                self._body = body

            def read(self, n=None):
                return self._body[:n] if n else self._body

            def close(self):
                pass

        calls = self._calls

        def _urlopen(req, timeout=None):
            calls.append(getattr(req, "full_url", req))
            if fail:
                raise IOError("no route to host")
            return _Resp(json.dumps(payload).encode("utf8"))

        C._urllib.request.urlopen = _urlopen

    def test_geoloc_country_is_extracted_and_normalised(self):
        self._answer({"data": {"located_resources": [{"locations": [{"country": "US-CA"}]}]}})
        self.assertEqual(C.ripe_lookup("geo", "8.8.8.8"), {"cc": "us"})
        self.assertIn("8.8.8.8", self._calls[0])
        self.assertIn("geoloc", self._calls[0])

    def test_a_country_that_is_not_a_country_code_is_dropped(self):
        # Whatever comes back is third-party text rendered into the page as a flag; only a
        # two-letter code can be one.
        self._answer({"data": {"located_resources": [{"locations": [{"country": "<script>"}]}]}})
        self.assertEqual(C.ripe_lookup("geo", "8.8.8.8"), {"cc": ""})

    def test_network_info_asn(self):
        self._answer({"data": {"asns": [15169], "prefix": "8.8.8.0/24"}})
        self.assertEqual(C.ripe_lookup("asn", "8.8.8.8"), {"asn": "AS15169", "holder": ""})
        self.assertIn("network-info", self._calls[0])

    def test_missing_or_malformed_payload_is_a_non_answer_not_a_crash(self):
        self._answer({"data": {}})
        self.assertEqual(C.ripe_lookup("geo", "8.8.8.8"), {"cc": ""})
        C._ripe_cache.clear()
        self._answer({"nothing": "useful"})
        self.assertEqual(C.ripe_lookup("asn", "8.8.8.8"), {"asn": "", "holder": ""})

    def test_a_hit_costs_no_request(self):
        self._answer({"data": {"located_resources": [{"locations": [{"country": "de"}]}]}})
        self.assertEqual(C.ripe_lookup("geo", "1.2.3.4"), {"cc": "de"})
        self.assertEqual(C.ripe_lookup("geo", "1.2.3.4"), {"cc": "de"})
        self.assertEqual(len(self._calls), 1, "the second lookup must be served from the cache")

    def test_a_failure_is_cached_too(self):
        self._answer({}, fail=True)
        self.assertIsNone(C.ripe_lookup("geo", "1.2.3.4"))
        self.assertIsNone(C.ripe_lookup("geo", "1.2.3.4"))
        self.assertEqual(len(self._calls), 1, "an unreachable RIPEstat must not be re-dialled per request")

    def test_expiry_lets_a_lookup_retry(self):
        self._answer({}, fail=True)
        self.assertIsNone(C.ripe_lookup("geo", "1.2.3.4"))
        key = ("geo", "1.2.3.4")
        expires, payload = C._ripe_cache[key]
        C._ripe_cache[key] = (0, payload)                # pretend the negative entry aged out
        self._answer({"data": {"located_resources": [{"locations": [{"country": "fr"}]}]}})
        self.assertEqual(C.ripe_lookup("geo", "1.2.3.4"), {"cc": "fr"})
        self.assertGreater(expires, 0, "a negative entry must still have had an expiry")

    def test_the_cache_is_bounded(self):
        self._answer({"data": {"located_resources": [{"locations": [{"country": "nl"}]}]}})
        saved = C.RIPE_LOOKUP_MAX_ENTRIES
        try:
            C.RIPE_LOOKUP_MAX_ENTRIES = 8
            for i in range(40):
                C.ripe_lookup("geo", "1.2.3.%d" % i)
            self.assertLessEqual(len(C._ripe_cache), 8, "an unbounded cache is a memory leak per distinct IP")
        finally:
            C.RIPE_LOOKUP_MAX_ENTRIES = saved

    def test_disabled_means_no_request_at_all(self):
        self._answer({"data": {"located_resources": [{"locations": [{"country": "us"}]}]}})
        C.config.DISABLE_RIPE_LOOKUPS = True
        self.assertIsNone(C.ripe_lookup("geo", "8.8.8.8"))
        self.assertEqual(self._calls, [], "DISABLE_RIPE_LOOKUPS must be a kill switch, not a fallback")

    def test_an_unknown_kind_is_refused_before_any_request(self):
        self._answer({"data": {}})
        self.assertIsNone(C.ripe_lookup("whois", "8.8.8.8"))
        self.assertIsNone(C.ripe_lookup("geo", ""))
        self.assertEqual(self._calls, [], "only the two fixed RIPEstat endpoints may be reached")


if __name__ == "__main__":
    unittest.main()
