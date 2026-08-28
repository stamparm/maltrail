# coding: utf-8
"""core/update.py's ASCII test, which decides whether a trail key is punycoded.

`_is_ascii()` is not cosmetic: an ASCII key takes the fast lowercase path, and a non-ASCII one goes
through `encode("idna")` and becomes punycode. Get it wrong and IDN trails are stored under the
wrong key, which means they never match.

It used to be `str.isascii()` and nothing else - a 3.7+ method. On Python 3.6, still the stock
`python3` of RHEL 8, CentOS 7, openSUSE Leap 15 / SLE 15 and Amazon Linux 2, the whole update died
with "'str' object has no attribute 'isascii'", so the trail set stayed EMPTY and the sensor
detected nothing. One method call, four distribution families.

There are two implementations now, and this compares them against each other on whatever
interpreter the suite happens to be running - so the 3.6 path is covered on 3.13 as well.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.addr import leading_ipv4
from core.update import _NON_ASCII_REGEX, _is_ascii

# Both branches must agree here, character for character.
CASES = (
    "",                          # str.isascii() is True for the empty string
    "example.com",
    "EXAMPLE.COM",
    "1.2.3.4",
    "under_score.example",
    "a" * 300,
    "\x00\x1f\x7f",              # control characters and DEL are still ASCII
    "\x80",                      # first non-ASCII byte value
    "évil.com",             # Latin-1 supplement
    "сbербank.com",         # Cyrillic homoglyph - the phishing case idna exists for
    "xn--80ak6aa92e.com",        # already punycode, therefore ASCII
    "例え.テスト",
    "café",
    "\U0001f600.example",        # astral plane (surrogate pair on narrow builds)
)


class TestIsAscii(unittest.TestCase):
    def test_the_two_implementations_agree(self):
        for value in CASES:
            self.assertEqual(_NON_ASCII_REGEX.search(value) is None, _is_ascii(value),
                             "the 3.6 regex path and str.isascii() disagree on %r" % value)

    def test_it_answers_correctly(self):
        # Not just self-consistent: right. ord() < 128 is the definition.
        for value in CASES:
            self.assertEqual(all(ord(c) < 128 for c in value), _is_ascii(value), repr(value))

    def test_the_ascii_verdict_survives_punycoding(self):
        # What the verdict is FOR: a non-ASCII key becomes punycode, an ASCII one is only lowercased.
        for value, expected in (("Example.COM", "example.com"), ("сbербank.com", "xn--bank-b4dx1ff.com")):
            if _is_ascii(value):
                self.assertEqual(expected, value.lower())
            else:
                self.assertEqual(expected, value.encode("idna").decode("ascii"))

    def test_the_3_6_path_exists_at_all(self):
        # If someone deletes the fallback, 3.6 breaks again - and it breaks by building nothing,
        # which is the failure mode nobody notices until a detection is missed.
        with open(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "core", "update.py"), "rb") as f:
            source = f.read().decode("utf8")
        self.assertIn('hasattr(str, "isascii")', source,
                      "core/update.py no longer chooses an implementation, so it is 3.7+ only again")


class LeadingIPv4Test(unittest.TestCase):
    """The boundary that decides "address trail" from "name that starts with digits".

    The updater's bogon/CDN filter used a `\\b`-bounded prefix match, and `\\b` matches the dot in a
    digit-leading DOMAIN too - so a reverse-DNS style trail was judged by its first four labels. Two static
    trails were deleted from EVERY build as bogons (`10.53.154.104.bc.googleusercontent.com`,
    `224.185.60.34.bc.googleusercontent.com`) while their neighbours with a routable leading quad survived,
    which is why nobody noticed. The rule now lives once, in core.addr, shared with the geolocation path.
    """

    def test_address_shaped_trails_yield_their_address(self):
        for trail, address in (("1.2.3.4", "1.2.3.4"),
                               ("1.2.3.4:8080", "1.2.3.4"),
                               ("1.2.3.4/gate.php", "1.2.3.4"),
                               ("1.2.3.4 (evil.example)", "1.2.3.4"),
                               ("10.0.0.0/8", "10.0.0.0")):
            self.assertEqual(leading_ipv4(trail), address, trail)

    def test_digit_leading_names_are_not_addresses(self):
        for trail in ("10.53.154.104.bc.googleusercontent.com",
                      "224.185.60.34.bc.googleusercontent.com",
                      "1.2.3.4.evil.example",
                      "13.249.87.125.evil.example",     # a CDN range as the leading quad
                      "1.2.3.4-evil.example",
                      "evil.example",
                      "", None):
            self.assertIsNone(leading_ipv4(trail), trail)

    def test_the_two_googleusercontent_trails_would_now_survive_the_filter(self):
        # the exact predicate from update_trails()'s post-processing, on the entries it used to drop
        from core.common import bogon_ip, cdn_ip
        for trail in ("10.53.154.104.bc.googleusercontent.com", "224.185.60.34.bc.googleusercontent.com"):
            address = leading_ipv4(trail)
            self.assertIsNone(address, trail)
            self.assertFalse(address and (bogon_ip(address) or cdn_ip(address)))
        # and a real address trail in the same ranges must STILL be dropped - the filter has to keep working
        for trail in ("10.53.154.104", "224.185.60.34"):
            address = leading_ipv4(trail)
            self.assertIsNotNone(address, trail)
            self.assertTrue(bogon_ip(address), trail)


class StaticFileOrderTest(unittest.TestCase):
    """The same checkout must build the same trail set on every machine.

    An indicator listed in two piles is labelled by whichever file the loader reads LAST, and the
    file list came straight from glob() - directory order. So the label depended on the order the
    filesystem happened to hand back, which changes when files are rewritten or the tree is cloned
    again. Measured on the real pile: rebuilding after a commit that touched only comment lines
    moved 5,950 of 1,632,336 entries to a different family (metamorfo vs latentbot,
    cobaltstrike-1 vs -2). Sorting the globs fixes the winner; this pins it."""

    def _fetch_with(self, root, order):
        """Run the assembler with glob() forced into `order`, over two piles that share a key."""
        import glob as _glob
        from core import assemble as S

        real = _glob.glob

        def fake(pattern):
            hits = real(pattern)
            return order(hits) if pattern.endswith("*.txt") else hits

        S.glob.glob = fake
        try:
            return S.fetch(root)
        finally:
            S.glob.glob = real

    def test_the_label_does_not_depend_on_directory_order(self):
        # trails/static/__init__.py became core/assemble.py and the content became its own
        # repository, so this needs a checkout: beside maltrail, or MALTRAIL_TRAILS_DIR.
        static = os.environ.get("MALTRAIL_TRAILS_DIR") or os.path.join(
            os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "trails")
        if not os.path.isdir(os.path.join(static, "malware")):
            self.skipTest("no stamparm/trails checkout")
        forward = self._fetch_with(static, lambda hits: hits)
        backward = self._fetch_with(static, lambda hits: list(reversed(hits)))
        self.assertEqual(len(forward), len(backward))
        differing = [k for k in forward if forward[k] != backward.get(k)]
        self.assertEqual(differing[:5], [],
                         "%d trail(s) are labelled by whatever order the filesystem returns" % len(differing))


if __name__ == "__main__":
    unittest.main()
