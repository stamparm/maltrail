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


if __name__ == "__main__":
    unittest.main()
