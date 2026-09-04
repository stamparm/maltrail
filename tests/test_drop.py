# coding: utf-8
"""Spamhaus DROP as an annotation, never as a trail (#19598).

DROP is ~1,700 netblocks covering millions of addresses. As trails they would be either inert - a
"1.2.3.0/24" key is never what a packet's address renders as, which is exactly how 1,093 entries of
mass_scanner_cidr.txt sat in the trail set matching nothing - or, expanded, a false-positive surface
vastly larger than anything anyone observed. So it is a lookup for /check_ip beside worst_asns(),
and these tests pin that shape as much as the matching.
"""

import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from core.common import spamhaus_drop                                       # noqa: E402
from core.settings import DROP6_RANGES, DROP_RANGES, read_drop             # noqa: E402


class DropLookup(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        read_drop()
        if not DROP_RANGES:
            raise unittest.SkipTest("no DROP netblocks loaded (data/drop.txt missing?)")

    def test_the_seed_actually_loaded(self):
        # A lookup over an empty table answers False for everything and looks like a clean pass.
        self.assertGreater(len(DROP_RANGES), 500, "data/drop.txt holds almost no IPv4 netblocks")
        self.assertGreater(len(DROP6_RANGES), 10, "data/drop.txt holds almost no IPv6 netblocks")

    def test_a_listed_netblock_matches_at_both_edges_and_stops(self):
        import ipaddress
        start, end = DROP_RANGES[0]
        first, last = str(ipaddress.ip_address(start)), str(ipaddress.ip_address(end))
        self.assertTrue(spamhaus_drop(first), "%s is the first address of a listed netblock" % first)
        self.assertTrue(spamhaus_drop(last), "%s is the last address of a listed netblock" % last)
        self.assertFalse(spamhaus_drop(str(ipaddress.ip_address(end + 1))),
                         "matching ran past the end of a netblock")

    def test_ipv6_is_matched_too(self):
        import ipaddress
        start, end = DROP6_RANGES[0]
        self.assertTrue(spamhaus_drop(str(ipaddress.ip_address(start))))
        self.assertTrue(spamhaus_drop(str(ipaddress.ip_address(end))))
        self.assertFalse(spamhaus_drop(str(ipaddress.ip_address(end + 1))))

    def test_ordinary_addresses_are_not_listed(self):
        for address in ("8.8.8.8", "1.1.1.1", "127.0.0.1", "10.0.0.1", "2001:db8::1"):
            self.assertFalse(spamhaus_drop(address), address)

    def test_junk_is_false_not_an_exception(self):
        # Called per address from a request handler; a raise here is a 500 on the dashboard.
        for value in ("", None, "not-an-ip", "999.999.999.999", "1.2.3", ":::", "::ffff:x"):
            self.assertFalse(spamhaus_drop(value), repr(value))

    def test_drop_is_not_merged_into_the_trail_set(self):
        """The whole design decision, asserted.

        Adding data/drop.txt to LOCAL_STATIC_TRAIL_FILES would put netblock keys in trails.csv,
        where they match nothing - or invite someone to "fix" that by expanding millions of
        addresses nobody observed. It is an annotation.
        """
        from core.settings import LOCAL_STATIC_TRAIL_FILES
        for name in LOCAL_STATIC_TRAIL_FILES:
            self.assertNotIn("drop", name.lower(),
                             "DROP was merged into the trail set; it is a /check_ip annotation, "
                             "like worst_asns.txt, and its netblocks cannot match as trails")


if __name__ == "__main__":
    unittest.main()
