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


if __name__ == "__main__":
    unittest.main()
