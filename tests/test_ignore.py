# coding: utf-8
"""Unit tests for core/ignore.ignore_event — decides which events to suppress (IGNORE_EVENTS_REGEX
+ USER_IGNORELIST tuples). Runs on the sensor hot path, so a bad regex must NOT crash (which would
silently drop EVERY event). Tests match/miss/invalid-regex and ignorelist wildcard tuples."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import core.ignore as I
from core.settings import config

# (sec, usec, src_ip, src_port, dst_ip, dst_port, proto, type, trail, info, ref)
EV = (1, 0, "10.0.0.5", 4444, "66.66.66.66", 80, "TCP", "IP", "66.66.66.66", "malware", "(static)")


class TestIgnore(unittest.TestCase):
    def setUp(self):
        config.IGNORE_EVENTS_REGEX = None
        config.SHOW_DEBUG = False
        I.IGNORE_EVENTS = []
        I._ignore_events_regex = None
        I._ignore_events_regex_src = None

    def test_no_config_keeps_event(self):
        self.assertFalse(I.ignore_event(EV))

    def test_regex_match_and_miss(self):
        config.IGNORE_EVENTS_REGEX = r"66\.66\.66\.66"
        self.assertTrue(I.ignore_event(EV))
        self.setUp()
        config.IGNORE_EVENTS_REGEX = r"this-does-not-appear"
        self.assertFalse(I.ignore_event(EV))

    def test_invalid_regex_does_not_crash(self):
        config.IGNORE_EVENTS_REGEX = "[unclosed("      # invalid pattern
        # must NOT raise (would drop every event on the hot path); rule disabled -> event kept
        self.assertFalse(I.ignore_event(EV))
        self.assertFalse(I.ignore_event(EV))            # second call: cached-disabled, still no crash

    def test_ignorelist_src_wildcards(self):
        I.IGNORE_EVENTS = [("10.0.0.5", "*", "*", "*")]
        self.assertTrue(I.ignore_event(EV))

    def test_ignorelist_dst_port(self):
        I.IGNORE_EVENTS = [("*", "*", "66.66.66.66", "80")]
        self.assertTrue(I.ignore_event(EV))
        self.setUp()
        I.IGNORE_EVENTS = [("*", "*", "66.66.66.66", "443")]   # wrong port
        self.assertFalse(I.ignore_event(EV))

    def test_ignorelist_no_match(self):
        I.IGNORE_EVENTS = [("*", "*", "1.2.3.4", "*")]
        self.assertFalse(I.ignore_event(EV))




class TestIgnoreRanges(unittest.TestCase):
    """#19142: networks, ranges and port ranges in the ignore list.

    An operator with 5-10k events a day could previously only silence their own subnet by writing
    out every address in it. These pin the new spellings AND the ones that must stay literal.
    """

    def setUp(self):
        config.IGNORE_EVENTS_REGEX = None
        config.SHOW_DEBUG = False
        I.IGNORE_EVENTS = []
        I._compiled = None
        I._compiled_src = None
        I._ignore_events_regex = None
        I._ignore_events_regex_src = None

    def ev(self, src="10.0.0.5", sport=4444, dst="66.66.66.66", dport=80):
        return (1, 0, src, sport, dst, dport, "TCP", "IP", dst, "malware", "(static)")

    def ignores(self, rule, event):
        I.IGNORE_EVENTS = [rule]
        I._compiled = None
        return I.ignore_event(event)

    def test_cidr_covers_its_network_and_stops_at_the_edges(self):
        self.assertTrue(self.ignores(("192.168.1.0/24", "*", "*", "*"), self.ev(src="192.168.1.77")))
        self.assertFalse(self.ignores(("192.168.1.0/24", "*", "*", "*"), self.ev(src="192.168.0.255")))
        self.assertFalse(self.ignores(("192.168.1.0/24", "*", "*", "*"), self.ev(src="192.168.2.0")))
        self.assertTrue(self.ignores(("0.0.0.0/0", "*", "*", "*"), self.ev(src="8.8.8.8")))

    def test_dash_ranges_in_both_spellings(self):
        self.assertTrue(self.ignores(("10.0.0.1-10.0.0.15", "*", "*", "*"), self.ev(src="10.0.0.7")))
        self.assertTrue(self.ignores(("10.0.0.1-15", "*", "*", "*"), self.ev(src="10.0.0.7")))
        self.assertFalse(self.ignores(("10.0.0.1-15", "*", "*", "*"), self.ev(src="10.0.0.16")))

    def test_port_ranges(self):
        self.assertTrue(self.ignores(("*", "*", "*", "8000-8100"), self.ev(dport=8080)))
        self.assertFalse(self.ignores(("*", "*", "*", "8000-8100"), self.ev(dport=8101)))
        self.assertTrue(self.ignores(("*", "1024-65535", "*", "*"), self.ev(sport=50000)))

    def test_ipv6_networks(self):
        self.assertTrue(self.ignores(("2001:db8::/32", "*", "*", "*"), self.ev(src="2001:db8::5")))
        self.assertFalse(self.ignores(("2001:db9::/32", "*", "*", "*"), self.ev(src="2001:db8::5")))

    def test_malformed_rules_degrade_to_literals(self):
        # NOT widened into something matching more than the operator wrote
        self.assertFalse(self.ignores(("192.168.1.0/33", "*", "*", "*"), self.ev(src="192.168.1.5")))
        self.assertFalse(self.ignores(("10.0.0.20-10.0.0.1", "*", "*", "*"), self.ev(src="10.0.0.5")))
        # a hostname with a dash is not a range
        self.assertTrue(self.ignores(("my-host.com", "*", "*", "*"), self.ev(src="my-host.com")))

    def test_a_range_does_not_match_a_non_numeric_port(self):
        self.assertFalse(self.ignores(("*", "*", "*", "1-100"), self.ev(dport="-")))

    def test_reloading_the_ignore_list_in_place_takes_effect(self):
        # read_ignorelist() clears and refills the SAME set object, so a cache keyed on identity
        # would keep applying the previous configuration after a reload
        rules = set()
        I.IGNORE_EVENTS = rules
        I._compiled = None
        rules.add(("192.168.1.0/24", "*", "*", "*"))
        self.assertTrue(I.ignore_event(self.ev(src="192.168.1.5")))

        rules.clear()
        rules.add(("10.0.0.0/8", "*", "*", "*"))
        self.assertFalse(I.ignore_event(self.ev(src="192.168.1.5")), "stale compiled rules survived a reload")
        self.assertTrue(I.ignore_event(self.ev(src="10.1.2.3")))


if __name__ == "__main__":
    unittest.main()
