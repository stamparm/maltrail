# coding: utf-8
"""Unit tests for sensor/tools/check_redistribution.py.

The tool answers a question the rest of the project does not ask: would something we PUBLISH hurt
somebody who redistributes it? Maltrail itself is unharmed by a trail on a shared CDN edge, because
update_trails() deletes it before any sensor sees it. FireHOL, oisd, NextDNS and the other
"trails only" consumers do not run update_trails(), so for them it is a live rule against an
address thousands of innocent sites sit behind.

No network here: the provider ranges are injected, so these test the judgement, not the internet.
"""
import ipaddress
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "sensor", "tools"))

import check_redistribution as R


def _index(shared, excluded=None):
    return R.index(shared), (R.index(excluded) if excluded else None)


class SharedVersusSingleTenant(unittest.TestCase):
    """The distinction the whole tool rests on, and the one it got wrong first."""

    def setUp(self):
        # A CDN edge (shared by thousands) and a customer compute range inside a provider
        # supernet (one tenant per address).
        self.shared = {"cdn": [ipaddress.ip_network(u"104.16.0.0/13")],
                       "google": [ipaddress.ip_network(u"34.64.0.0/10")]}
        self.excluded = {"google:exclude": [ipaddress.ip_network(u"34.102.128.0/17")]}

    def test_a_shared_edge_is_reported(self):
        b, e = _index(self.shared, self.excluded)
        self.assertEqual(R.match(b, ipaddress.ip_address(u"104.16.155.10"), e), "cdn")

    def test_customer_compute_inside_a_provider_supernet_is_not(self):
        # goog.json publishes 34.64.0.0/10, which swallows GCP customer ranges; cloud.json carves
        # them out. Without the exclusion this flagged 13,487 Gafgyt bots on rented instances -
        # single-tenant addresses that are entirely legitimate to list.
        b, e = _index(self.shared, self.excluded)
        self.assertIsNone(R.match(b, ipaddress.ip_address(u"34.102.233.188"), e))

    def test_the_rest_of_the_supernet_still_counts(self):
        # Inside 34.64.0.0/10 (34.64.0.0 - 34.127.255.255) but outside the carved-out customer
        # /17, so it is still Google's own frontend and still shared.
        b, e = _index(self.shared, self.excluded)
        self.assertEqual(R.match(b, ipaddress.ip_address(u"34.65.1.1"), e), "google")

    def test_an_unrelated_address_is_clean(self):
        b, e = _index(self.shared, self.excluded)
        self.assertIsNone(R.match(b, ipaddress.ip_address(u"45.83.220.17"), e))


class AddressParsing(unittest.TestCase):
    def test_forms_that_appear_in_trail_files(self):
        for key, expected in ((u"104.16.155.10", u"104.16.155.10"),
                              (u"104.16.155.10:8888", u"104.16.155.10"),
                              (u"104.16.0.0/13", u"104.16.0.0")):
            self.assertEqual(str(R._address(key)), expected, key)

    def test_names_and_urls_are_not_addresses(self):
        for key in (u"evil.example.com", u"evil.example.com/path", u"", u"not-an-ip"):
            self.assertIsNone(R._address(key), key)

    def test_ipv6(self):
        self.assertEqual(str(R._address(u"2606:4700::1")), u"2606:4700::1")


class SupernetsSpanningBuckets(unittest.TestCase):
    def test_a_prefix_shorter_than_the_bucket_is_found_in_every_bucket_it_spans(self):
        # Lookups bucket on the leading octet. A /10 spans 64 of them, and registering it in only
        # the first would silently miss most of its addresses - a false NEGATIVE, which for this
        # tool means shipping the harm.
        b, _ = _index({"big": [ipaddress.ip_network(u"34.64.0.0/10")]})
        for probe in (u"34.64.0.1", u"34.100.5.5", u"34.127.255.254"):
            self.assertEqual(R.match(b, ipaddress.ip_address(probe)), "big", probe)


class Exemptions(unittest.TestCase):
    def test_piles_that_exist_to_name_shared_infrastructure(self):
        # Reporting these would be reporting the intent; update_trails() spares them too.
        for info in ("parking site", "sinkhole", "mass scanner", "cdn"):
            self.assertTrue(any(_ in info.lower() for _ in R.EXEMPT_INFO), info)

    def test_an_ordinary_family_is_not_exempt(self):
        for info in ("asyncrat (malware)", "deimos c2", "cobaltstrike"):
            self.assertFalse(any(_ in info.lower() for _ in R.EXEMPT_INFO), info)


if __name__ == "__main__":
    unittest.main()
