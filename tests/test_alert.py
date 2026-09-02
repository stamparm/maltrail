# coding: utf-8
"""Unit tests for core/alert.py -- the outbound webhook for events worth waking someone up for.

Two things it must not do: page on inbound scan noise, and page 2,880 times for one beacon. Both are
asserted against the REMOTE_SEVERITY_REGEX that maltrail.conf actually ships, because that regex is
the whole selector -- if it stops classifying `(malware)` as high, this feature silently stops
mattering, and nothing else in the suite would notice."""

import os
import sys
import time
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from core import alert
from core.log import severity_of
from core.settings import config, read_config

LINE = ('"2026-08-18 10:00:00.000000" box 10.0.0.5 4421 8.8.8.8 53 UDP DNS %s "%s" (static)')


def event_line(trail, info):
    return LINE % (trail, info)


class SeverityTest(unittest.TestCase):
    """The shipped REMOTE_SEVERITY_REGEX, not a copy of it."""

    @classmethod
    def setUpClass(cls):
        read_config(os.path.join(ROOT, "maltrail.conf"))

    def test_named_malware_is_high(self):
        for info in ("apt darkhotel (malware)", "interlock (malware)", "asyncrat (malware)",
                     "ransomware (malware)", "iot-malware download"):
            self.assertEqual(severity_of(info), "high", info)

    def test_inbound_noise_is_low(self):
        # the whole point: this is what FAIL2BAN_REGEX wants and an operator does not
        for info in ("known attacker", "bad reputation", "spammer", "crawler", "mass scanner",
                     "potential port scanning"):
            self.assertEqual(severity_of(info), "low", info)

    def test_web_compromise_is_medium(self):
        # exploit kits, skimmers and browser lockers are a dashboard row, not a page
        for info in ("ek clearfake (malicious)", "browser locker (malicious)", "magentocore (malicious)",
                     "potential malware site", "malware distribution"):
            self.assertEqual(severity_of(info), "medium", info)

    def test_the_default_threshold_takes_high_only(self):
        config.ALERT_SEVERITY = "high"
        self.assertTrue(alert.wanted({"severity": "high"}))
        self.assertFalse(alert.wanted({"severity": "medium"}))
        self.assertFalse(alert.wanted({"severity": "low"}))

    def test_a_lower_threshold_includes_everything_above_it(self):
        config.ALERT_SEVERITY = "medium"
        self.assertTrue(alert.wanted({"severity": "high"}))
        self.assertTrue(alert.wanted({"severity": "medium"}))
        self.assertFalse(alert.wanted({"severity": "low"}))

    def test_a_junk_threshold_falls_back_to_high(self):
        config.ALERT_SEVERITY = "URGENT!!"
        self.assertTrue(alert.wanted({"severity": "high"}))
        self.assertFalse(alert.wanted({"severity": "low"}))


class ParseTest(unittest.TestCase):
    def test_a_quoted_info_with_spaces_survives(self):
        event = alert.parse_event_line(event_line("evil.biz", "apt darkhotel (malware)"))
        self.assertEqual(event["src_ip"], "10.0.0.5")
        self.assertEqual(event["dst_ip"], "8.8.8.8")
        self.assertEqual(event["proto"], "UDP")
        self.assertEqual(event["type"], "DNS")
        self.assertEqual(event["trail"], "evil.biz")
        self.assertEqual(event["info"], "apt darkhotel (malware)")
        self.assertEqual(event["reference"], "(static)")

    def test_garbage_is_not_an_event(self):
        for line in ("", "\n", "garbage", '"2026-08-18 10:00:00.000000" box 10.0.0.5'):
            self.assertIsNone(alert.parse_event_line(line), line)


class ThrottleTest(unittest.TestCase):
    def setUp(self):
        alert._throttle.clear()
        config.ALERT_THROTTLE = 300

    def test_the_same_source_and_trail_is_suppressed(self):
        event = {"src_ip": "10.0.0.5", "trail": "evil.biz"}
        self.assertFalse(alert.throttled(event, now=1000))
        self.assertTrue(alert.throttled(event, now=1100))
        self.assertFalse(alert.throttled(event, now=1400))   # the window has passed

    def test_a_different_source_or_trail_is_not(self):
        self.assertFalse(alert.throttled({"src_ip": "10.0.0.5", "trail": "evil.biz"}, now=1000))
        self.assertFalse(alert.throttled({"src_ip": "10.0.0.6", "trail": "evil.biz"}, now=1000))
        self.assertFalse(alert.throttled({"src_ip": "10.0.0.5", "trail": "other.biz"}, now=1000))

    def test_zero_disables_it(self):
        config.ALERT_THROTTLE = 0
        event = {"src_ip": "10.0.0.5", "trail": "evil.biz"}
        self.assertFalse(alert.throttled(event, now=1000))
        self.assertFalse(alert.throttled(event, now=1000))

    def test_the_table_is_bounded(self):
        from core.settings import MAX_ALERT_THROTTLE_KEYS
        for i in range(MAX_ALERT_THROTTLE_KEYS + 200):
            alert.throttled({"src_ip": "10.0.0.%d" % (i % 256), "trail": "t%d" % i}, now=1000 + i)
        self.assertLessEqual(len(alert._throttle), MAX_ALERT_THROTTLE_KEYS)


class BodyTest(unittest.TestCase):
    def setUp(self):
        self.event = alert.parse_event_line(event_line("evil.biz", "apt darkhotel (malware)"))

    def test_the_shipped_slack_template(self):
        config.ALERT_FORMAT = '{"text": "%(severity)s: %(src_ip)s -> %(trail)s (%(info)s) [%(type)s]"}'
        self.assertIn('10.0.0.5 -> evil.biz (apt darkhotel (malware)) [DNS]', alert.body(self.event))

    def test_json_is_the_logstash_payload(self):
        import json
        config.ALERT_FORMAT = "%(json)s"
        payload = json.loads(alert.body(self.event))
        self.assertEqual(list(payload), ["timestamp", "sensor", "severity", "src_ip", "src_port",
                                         "dst_ip", "dst_port", "proto", "type", "trail", "info", "reference"])
        self.assertEqual(payload["trail"], "evil.biz")

    def test_a_broken_template_returns_none_instead_of_raising(self):
        config.ALERT_FORMAT = "%(nosuchfield)s"
        self.assertIsNone(alert.body(self.event))


class TailTest(unittest.TestCase):
    """The tailer, against a real file: it must start at the END (a restart is not a replay), pick up
    appended lines, and follow the day rollover."""

    def setUp(self):
        import tempfile
        self.tmp = tempfile.mkdtemp()
        config.LOG_DIR = self.tmp
        config.ALERT_FORMAT = "%(json)s"
        config.ALERT_SEVERITY = "high"
        config.ALERT_THROTTLE = 0
        alert._throttle.clear()
        self.sent = []
        self._saved = alert.send
        alert.send = lambda event: (self.sent.append(event), True)[1]
        self.path = alert._log_path()

    def tearDown(self):
        import shutil
        alert.send = self._saved
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _append(self, *lines):
        with open(self.path, "a") as f:
            for line in lines:
                f.write(line + "\n")

    def test_a_restart_does_not_replay_the_day(self):
        self._append(event_line("old.biz", "apt x (malware)"))
        state = {"path": None, "offset": 0}
        alert._tail_once(state)                              # first pass: seek to the end
        self.assertEqual(self.sent, [])
        self._append(event_line("new.biz", "apt y (malware)"))
        alert._tail_once(state)
        self.assertEqual([_["trail"] for _ in self.sent], ["new.biz"])

    def test_only_events_above_the_threshold_are_sent(self):
        state = {"path": None, "offset": 0}
        alert._tail_once(state)
        self._append(event_line("noise.biz", "known attacker"),
                     event_line("kit.biz", "ek clearfake (malicious)"),
                     event_line("bad.biz", "interlock (malware)"))
        alert._tail_once(state)
        self.assertEqual([_["trail"] for _ in self.sent], ["bad.biz"])

    def test_a_partial_line_waits_for_the_rest(self):
        state = {"path": None, "offset": 0}
        alert._tail_once(state)
        with open(self.path, "a") as f:
            f.write(event_line("half.biz", "apt z (malware)")[:40])
        alert._tail_once(state)
        self.assertEqual(self.sent, [])
        with open(self.path, "a") as f:
            f.write(event_line("half.biz", "apt z (malware)")[40:] + "\n")
        alert._tail_once(state)
        self.assertEqual([_["trail"] for _ in self.sent], ["half.biz"])

    def test_truncation_in_place_is_not_an_error(self):
        state = {"path": None, "offset": 0}
        self._append(event_line("a-longer-name.biz", "apt a (malware)"))
        alert._tail_once(state)
        open(self.path, "w").close()                         # truncated in place: inode kept, size shrinks
        self._append(event_line("b.biz", "apt b (malware)"))
        alert._tail_once(state)
        self.assertEqual([_["trail"] for _ in self.sent], ["b.biz"])

    def test_rotation_to_a_new_file_is_not_an_error(self):
        # `mv log log.1 && touch log` keeps the size but changes the inode, so a size check alone
        # would sit at the old offset and drop everything written to the new file.
        state = {"path": None, "offset": 0}
        self._append(event_line("a.biz", "apt a (malware)"))
        alert._tail_once(state)
        os.rename(self.path, self.path + ".1")
        self._append(event_line("b.biz", "apt b (malware)"))
        alert._tail_once(state)
        self.assertEqual([_["trail"] for _ in self.sent], ["b.biz"])


class DisabledTest(unittest.TestCase):
    def test_start_is_a_no_op_without_a_url(self):
        config.ALERT_WEBHOOK_URL = ""
        self.assertFalse(alert.start())



class TestCorruptTimestamp(unittest.TestCase):
    """parse_event_line's contract is "-> dict, or None when it is not one" - never raise.

    A time field that does not start with a digit already fell back to timestamp 0. One that
    starts with a digit but does not parse raised ValueError instead, which the tail loop then
    swallowed as a blanket "Exception" and reported as a traceback under SHOW_DEBUG.
    """

    def _line(self, when):
        return ('"%s" box 10.0.0.5 4421 8.8.8.8 53 UDP DNS evil.biz "apt x (malware)" (static)'
                % when)

    def test_impossible_times_parse_to_zero(self):
        for when in ("2026-13-45 10:00:00.000000", "2026-01-01 99:99:99.000000",
                     "2026-02-30 10:00:00.000000", "0000-00-00 00:00:00.000000"):
            event = alert.parse_event_line(self._line(when))
            self.assertIsNotNone(event, "%r is still a well-formed event line" % when)
            self.assertEqual(event["timestamp"], 0, "%r must fall back, not raise" % when)

    def test_a_real_time_still_parses(self):
        event = alert.parse_event_line(self._line("2026-01-01 10:00:00.000000"))
        self.assertGreater(event["timestamp"], 0, "positive control: a real time still converts")


if __name__ == "__main__":
    unittest.main()
