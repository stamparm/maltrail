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
                     "ransomware (malware)"):
            self.assertEqual(severity_of(info), "high", info)

    def test_a_sensor_guess_is_not_a_page(self):
        # The dashboard has ranked the sensor's own verdicts below anything a feed listed since
        # 307e0e8, and this regex could not express that until it was given the reference: "long
        # domain (suspicious)" showed LOW and alerted MEDIUM. The noisiest heuristic in the
        # product must not page anybody (#19621, #19622).
        for info in ("long domain (suspicious)", "user agent (suspicious)",
                     "excessive no such domain (suspicious)", "potential dns tunneling (suspicious)",
                     "potential sql injection (suspicious)", "parked site (suspicious)"):
            self.assertEqual(severity_of(info, "(heuristic)"), "low", info)

    def test_the_same_class_from_a_feed_is_not_demoted(self):
        # ... and the reverse: a feed saying "(suspicious)" keeps the legacy MEDIUM. Demoting these
        # too would have been the easy way to make the two agree, and the wrong one.
        for info in ("ipinfo (suspicious)", "pua (suspicious)", "crypto mining (suspicious)"):
            self.assertEqual(severity_of(info, "(static)"), "medium", info)

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

    def test_the_iot_dropper_is_medium_not_high(self):
        # It contains "malware", which made it HIGH - level with a proven C2 callback - for a URL
        # that merely looks like an architecture-tagged dropper (#19622).
        for ref in ("(heuristic)", ""):
            self.assertEqual(severity_of("potential iot-malware download (suspicious)", ref),
                             "medium", ref)

    def test_an_infection_sweep_stays_medium(self):
        # One host spraying 445 across the network is not noise, so it must not fall to LOW with
        # the rest of the heuristics.
        self.assertEqual(severity_of("potential infection (suspicious)", "(heuristic)"), "medium")

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

    def test_one_threat_is_one_message_whatever_its_spelling(self):
        # The dashboard folds every "(label).com" long-domain hit from one host into one threat;
        # keyed on the raw trail, each spelling was a message of its own.
        first = {"time": "2026-11-05 10:00:00", "src_ip": "10.0.0.5", "trail": "(a8f3k).com",
                 "info": "long domain (suspicious)", "reference": "(heuristic)"}
        second = dict(first, trail="(b91xq2).com")
        self.assertFalse(alert.throttled(first, now=1000))
        self.assertTrue(alert.throttled(second, now=1001))
        # ...but a different detection on the same name is a different threat
        self.assertFalse(alert.throttled(dict(second, info="potential dga (suspicious)"), now=1002))

    def test_a_scanning_tool_is_one_threat_whatever_test_it_ran(self):
        # same rule as engine.js:normTrail - a user agent's own parentheses are escaped
        nikto = {"src_ip": "10.0.0.5", "info": "user agent (suspicious)", "reference": "(heuristic)",
                 "trail": r"Nikto (Mozilla/5.00 \(Nikto/2.1.5\) \(Evasions:None\) \(Test:map_codes\))"}
        self.assertEqual(alert.threat_key(nikto), alert.threat_key(dict(nikto, trail="Nikto (*)")))
        traversal = {"src_ip": "10.0.0.5", "info": "potential directory traversal (suspicious)", "reference": "(heuristic)"}
        self.assertEqual(alert.threat_key(dict(traversal, trail="198.51.100.7(/x?|dir%20..\\\\..\\\\)")),
                         alert.threat_key(dict(traversal, trail="198.51.100.7(/../etc/passwd)")))

    def test_a_new_day_is_a_new_threat(self):
        config.ALERT_THROTTLE = 86400
        event = {"time": "2026-11-05 23:59:00", "src_ip": "10.0.0.5", "trail": "evil.biz", "info": "x (malware)", "reference": "(static)"}
        self.assertFalse(alert.throttled(event, now=1000))
        self.assertTrue(alert.throttled(dict(event, time="2026-11-05 23:59:30"), now=1030))
        self.assertFalse(alert.throttled(dict(event, time="2026-11-06 00:00:30"), now=1090))

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

    def test_threat_is_the_id_the_dashboard_shows(self):
        # expected values computed by html/js/engine.js:threatUID, not by the code under test
        config.ALERT_FORMAT = "%(threat)s"
        self.assertEqual(alert.body(self.event), "86905c1d")
        heuristic = {"src_ip": "10.0.0.5", "trail": "(a8f3k).com", "info": "long domain (suspicious)", "reference": "(heuristic)"}
        self.assertEqual(alert.threat_uid(heuristic), "6b007af1")

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


class DeliveryTest(unittest.TestCase):
    """A webhook that answers 4xx/5xx or times out must count as a failure, and the alert must be
    retried rather than lost. retrieve_content() returned empty bytes for every error, so each of
    those used to be reported as a delivered alert."""

    def setUp(self):
        import http.server
        import threading as _threading
        self.answers, self.received = [], []
        test = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                test.received.append(self.rfile.read(int(self.headers.get("Content-Length", 0))))
                self.send_response(test.answers.pop(0) if test.answers else 200)
                self.send_header("Content-Length", "0")
                self.end_headers()

            def log_message(self, *args):
                pass

        self.server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
        _threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self._saved = (config.ALERT_WEBHOOK_URL, alert.RETRY_MIN, alert.RETRY_MAX)
        config.ALERT_WEBHOOK_URL = "http://127.0.0.1:%d/hook" % self.server.server_address[1]
        alert.RETRY_MIN, alert.RETRY_MAX = 0.05, 0.1

    def tearDown(self):
        self.server.shutdown()
        config.ALERT_WEBHOOK_URL, alert.RETRY_MIN, alert.RETRY_MAX = self._saved

    def test_an_error_status_is_a_failure(self):
        self.answers = [500, 404]
        self.assertEqual(alert.post("{}"), "HTTP 500")
        self.assertEqual(alert.post("{}"), "HTTP 404")
        self.assertIsNone(alert.post("{}"), "the control: a 200 is a delivery")

    def test_a_failed_alert_is_retried_until_it_is_delivered(self):
        config.ALERT_FORMAT = "%(json)s"
        self.answers = [503, 503]
        event = alert.parse_event_line(event_line("retried.biz", "apt r (malware)"))
        self.assertTrue(alert.send(event))
        deadline = time.time() + 10
        while time.time() < deadline and alert.delivery_status()["queued"]:
            time.sleep(0.05)
        self.assertEqual(alert.delivery_status()["queued"], 0, "the alert was never delivered")
        self.assertEqual(len(self.received), 3, "two refusals and one delivery, not one silent loss")
        self.assertIn(b"retried.biz", self.received[-1])


class SensorSilenceTest(unittest.TestCase):
    """A sensor that stops sending heartbeats is reported once, and once more when it is back -
    never per check, never again after a restart, never for a sensor retired long ago. Time is
    the `now` argument; rows go straight into core/log.py's table with the last_seen wanted."""

    def setUp(self):
        import shutil
        import tempfile
        import core.log as L
        self.L = L
        self.tmp = tempfile.mkdtemp(prefix="mt_silence_")
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self._saved = (config.LOG_DIR, config.ALERT_WEBHOOK_URL, config.ALERT_FORMAT, alert.send, alert.log_error)
        self._table = (dict(L._sensor_status), dict(L._receiver_status))
        config.LOG_DIR, config.ALERT_WEBHOOK_URL = self.tmp, "http://127.0.0.1:9/hook"
        self.sent, self.errors = [], []
        alert.send = self.sent.append
        alert.log_error = lambda msg, single=False: self.errors.append(msg)
        self._restart()

    def tearDown(self):
        config.LOG_DIR, config.ALERT_WEBHOOK_URL, config.ALERT_FORMAT, alert.send, alert.log_error = self._saved
        self.L._sensor_status.clear(); self.L._sensor_status.update(self._table[0])
        self.L._receiver_status.clear(); self.L._receiver_status.update(self._table[1])
        alert._silent.clear()
        alert._drops.clear(); alert._dropping.clear()

    def _restart(self):
        """What a server restart leaves: an empty table and alert state, then start()'s load."""
        self.L._sensor_status.clear()
        self.L._receiver_status.clear()
        alert._silent.clear()
        alert._drops.clear(); alert._dropping.clear()
        alert._liveness.update(saved=0, known=set())
        alert._silent.update(self.L.load_sensor_status())

    def _seen(self, name, sec):
        self.L._sensor_status[name] = {"sensor": name, "version": "1.0", "uptime": 5, "address": "10.0.0.9", "last_seen": sec}

    def test_silent_is_reported_once_and_back_once(self):
        self._seen("box", 1000)
        self.assertEqual(alert.check_sensors(now=1000), 0, "a fresh sensor is not news")
        self.assertEqual(alert.check_sensors(now=1000 + 900), 0, "exactly at the threshold is not yet silent")
        self.assertEqual(alert.check_sensors(now=1000 + 901), 1, "the control: past the threshold it is")
        self.assertEqual(self.sent[0]["sensor"], "box")
        self.assertEqual(self.sent[0]["severity"], "high")
        self.assertIn("silent since", self.sent[0]["info"])
        for now in (2000, 5000, 50000):
            self.assertEqual(alert.check_sensors(now=now), 0, "still silent must not repeat")
        self._seen("box", 60000)
        self.assertEqual(alert.check_sensors(now=60000), 1)
        self.assertEqual(self.sent[1]["info"], "sensor reporting again")
        self.assertEqual(alert.check_sensors(now=60030), 0)
        self.assertEqual(len(self.sent), 2)
        self.assertEqual(len(self.errors), 2, "both facts also go to error.log")
        self.assertIn("sensor 'box' (10.0.0.9): sensor silent since", self.errors[0])

    def test_a_dropping_capture_is_reported_once_and_its_end_once(self):
        def beat(sec, captured, dropped):
            self._seen("box", sec)
            self.L._sensor_status["box"].update(captured=captured, dropped=dropped)
            return alert.check_sensors(now=sec)

        self.assertEqual(beat(1000, 0, 0), 0)
        self.assertEqual(beat(1000 + 3600, 100000, 1000), 0, "exactly 1% is not over the threshold")
        self.assertEqual(beat(1000 + 7200, 200000, 3000), 1, "the control: 2% in the hour is")
        self.assertIn("dropped 2.0% of packets (2000 of 100000)", self.sent[-1]["info"])
        self.assertEqual(self.sent[-1]["severity"], "high")
        self.assertEqual(beat(1000 + 10800, 300000, 6000), 0, "still dropping must not repeat")
        self.assertEqual(beat(1000 + 14400, 400000, 6000), 1)
        self.assertEqual(self.sent[-1]["info"], "capture no longer dropping packets")
        self.assertEqual(beat(1000 + 15000, 5, 0), 0, "counters going down are a restart, not a recovery")
        self.assertEqual(len(self.errors), 2)

    def test_a_silent_sensor_is_not_reported_as_no_longer_dropping(self):
        self._seen("box", 1000)
        self.L._sensor_status["box"].update(captured=0, dropped=0)
        alert.check_sensors(now=1000)
        self.L._sensor_status["box"].update(last_seen=4600, captured=100, dropped=50)
        self.assertEqual(alert.check_sensors(now=4600), 1)
        self.assertEqual(alert.check_sensors(now=9000), 1, "only the silence is news")
        self.assertIn("silent since", self.sent[-1]["info"])

    def test_a_restart_while_silent_does_not_report_it_again(self):
        self._seen("box", 1000)
        self.assertEqual(alert.check_sensors(now=2000), 1)
        self._restart()
        self.assertEqual([_["sensor"] for _ in self.L.sensor_status()], ["box"], "the restart forgot the sensor")
        self.assertEqual(alert.check_sensors(now=3000), 0, "re-alerted after a restart")
        self._seen("box", 4000)
        self.assertEqual(alert.check_sensors(now=4000), 1, "and its return is still reported")

    def test_a_sensor_that_died_while_the_server_was_down_is_reported(self):
        self._seen("box", 1000)
        alert.check_sensors(now=1000)       # persisted while it was alive
        self._restart()
        self.assertEqual(alert.check_sensors(now=1000 + 3600), 1)

    def test_nothing_for_a_sensor_never_seen_or_long_retired(self):
        self.assertEqual(alert.check_sensors(now=10 ** 9), 0)
        self.assertFalse(os.path.exists(os.path.join(self.tmp, "sensors.json")), "nothing to remember, nothing written")
        self._seen("old", 1000)
        self.assertEqual(alert.check_sensors(now=1000 + 8 * 86400), 0, "a sensor gone for a week is retired")
        self._seen("box", 1000 + 2 * 86400)
        self.assertEqual(alert.check_sensors(now=1000 + 8 * 86400), 1, "the control: six days silent is reported")
        self.assertEqual(self.sent[0]["sensor"], "box")

    def test_without_a_webhook_it_is_still_in_error_log(self):
        config.ALERT_WEBHOOK_URL = ""
        self._seen("box", 1000)
        self.assertEqual(alert.check_sensors(now=5000), 1)
        self.assertEqual(self.sent, [])
        self.assertEqual(len(self.errors), 1)

    def test_the_alert_renders_with_the_shipped_and_a_custom_format(self):
        # Through read_config, not the raw line: the shipped value once held a '#', which the
        # reader takes for a comment, so every alert body was cut short into invalid JSON.
        read_config(os.path.join(ROOT, "maltrail.conf"))
        shipped = config.ALERT_FORMAT
        config.LOG_DIR, config.ALERT_WEBHOOK_URL = self.tmp, "http://127.0.0.1:9/hook"
        self._seen("box", 1000)
        event = {}
        alert.send = lambda e: event.update(e)
        alert.check_sensors(now=5000)
        config.ALERT_FORMAT = shipped
        text = alert.body(event)
        self.assertRegex(__import__("json").loads(text)["text"], r'^high: 10\.0\.0\.9 -> box \(sensor silent since [-0-9: ]+ \(no heartbeat for 66 min\)\) \[SENSOR\] threat [0-9a-f]{8}$')
        config.ALERT_FORMAT = "%(sensor)s|%(severity)s|%(dst_ip)s|%(reference)s"
        self.assertEqual(alert.body(event), "box|high|-|(liveness)")
        config.ALERT_FORMAT = "%(json)s"
        self.assertEqual(__import__("json").loads(alert.body(event))["type"], "SENSOR")



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



class CustomSeverityRegexTest(unittest.TestCase):
    """A REMOTE_SEVERITY_REGEX an operator wrote with only some of the low/medium/high groups."""

    def setUp(self):
        self._saved = config.REMOTE_SEVERITY_REGEX

    def tearDown(self):
        config.REMOTE_SEVERITY_REGEX = self._saved

    def test_a_regex_without_every_group_does_not_raise(self):
        config.REMOTE_SEVERITY_REGEX = r"(?P<high>malware)"
        self.assertEqual(severity_of("malware", "(static)"), "high")       # match.group("low") raised once
        self.assertEqual(severity_of("harmless info", "(static)"), "medium", "no match falls back to medium")


class CefEscapeTest(unittest.TestCase):
    """core/log.py:_cef_escape(), which the server's SYSLOG_SERVER auth events go through."""

    def test_special_characters_are_escaped(self):
        from core.log import _cef_escape
        self.assertEqual(_cef_escape("host.com/?a=b", extension=True), r"host.com/?a\=b")
        self.assertEqual(_cef_escape("evil|marker"), r"evil\|marker")
        self.assertEqual(_cef_escape("a\nb\rc"), "a b c")

    def test_plain_values_are_unchanged(self):
        from core.log import _cef_escape
        self.assertEqual(_cef_escape("plain.example.com"), "plain.example.com")
        self.assertEqual(_cef_escape("1.2.3.4", extension=True), "1.2.3.4")


class _QueueIsolation(unittest.TestCase):
    """A private queue, condition and no delivery thread: a deliverer left running by an earlier
    test waits on the OLD condition, so it cannot race these tests for the queue or the counters."""

    def setUp(self):
        import collections
        import shutil
        import tempfile
        import threading as _threading
        self._saved = (alert._queue, alert._queue_cond, alert._deliverer, dict(alert._delivery), dict(alert._outage),
                       alert.MAX_ALERT_QUEUE, alert.log_error, config.ALERT_FORMAT, config.LOG_DIR, dict(alert._tail_saved))
        alert._queue, alert._queue_cond, alert._deliverer = collections.deque(), _threading.Condition(), [None]
        alert._delivery.update(sent=0, dropped=0, failures=0, last_error=None, last_sent=None)
        alert._outage.update(since=None, reported=0, dropped=0, told=0)
        alert._tail_saved.update(at=0, sig=None)
        self.errors = []
        alert.log_error = lambda msg, single=False: self.errors.append(msg)
        config.ALERT_FORMAT = "%(json)s"
        self.tmp = config.LOG_DIR = tempfile.mkdtemp(prefix="mt_alertq_")
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def tearDown(self):
        (alert._queue, alert._queue_cond, alert._deliverer, delivery, outage, alert.MAX_ALERT_QUEUE, alert.log_error,
         config.ALERT_FORMAT, config.LOG_DIR, tail_saved) = self._saved
        alert._delivery.update(delivery); alert._outage.update(outage); alert._tail_saved.update(tail_saved)


class DropReportTest(_QueueIsolation):
    """With a dead webhook the queue drops its oldest alerts. That was counted, and nowhere said:
    1,100 alerts went in, 1,000 came out, and error.log spoke only of failures and retries."""

    def test_the_drop_count_is_in_the_error_log(self):
        alert.MAX_ALERT_QUEUE = 3
        alert._failed("HTTP 503", now=1000)
        self.assertEqual(len(self.errors), 1)
        self.assertIn("0 dropped", self.errors[0], "the control: nothing dropped yet")
        for i in range(5):
            alert.send(alert.parse_event_line(event_line("d%d.biz" % i, "apt d (malware)")))
        self.assertEqual(alert.delivery_status()["dropped"], 2)
        self.assertEqual(alert.delivery_status()["queued"], 3)
        self.assertIn(b"d2.biz", alert._queue[0].encode(), "the oldest go first")
        alert._failed("HTTP 503", now=1010)
        self.assertEqual(len(self.errors), 2, "the first drop is told at the next retry, not an hour later")
        self.assertIn("3 alert(s) waiting, 2 dropped", self.errors[1])
        alert._failed("HTTP 503", now=1020)
        self.assertEqual(len(self.errors), 2, "and then paced")
        alert._recovered()
        self.assertIn("2 alert(s) were dropped", self.errors[2])

    def test_a_recovery_without_drops_says_nothing_of_them(self):
        alert._failed("HTTP 503", now=1000)
        alert._recovered()
        self.assertNotIn("dropped", self.errors[1])


class ResumeTest(_QueueIsolation):
    """A restart started the tailer at the end of today's log, so a high event written while the
    server was down (a local sensor writes the log itself) was never alerted, and the in-memory
    queue was lost. alerts.json keeps the position and the queue; a resume needs today's file with
    the same inode, and alerts on at most MAX_ALERT_QUEUE events."""

    @classmethod
    def setUpClass(cls):
        read_config(os.path.join(ROOT, "maltrail.conf"))   # the shipped severity regex: "(malware)" is high

    def setUp(self):
        _QueueIsolation.setUp(self)
        config.ALERT_SEVERITY, config.ALERT_THROTTLE = "high", 0
        alert._throttle.clear()
        self.sent = []
        self._send = alert.send
        alert.send = lambda event: (self.sent.append(event["trail"]), True)[1]
        self.path = alert._log_path()

    def tearDown(self):
        alert.send = self._send
        _QueueIsolation.tearDown(self)

    def _append(self, *trails):
        with open(self.path, "a") as f:
            for trail in trails:
                f.write(event_line(trail, "apt r (malware)") + "\n")

    def _run_then_stop(self):
        """A server run: start, see `before.biz` alerted, persist, stop."""
        state = alert._load_tail()
        alert._tail_once(state)
        self._append("before.biz")
        alert._tail_once(state)
        self.assertEqual(self.sent, ["before.biz"], "the control: the live tail alerts")
        self.assertTrue(alert._save_tail(state, now=10 ** 9))
        del self.sent[:]
        return state

    def test_an_event_written_while_down_is_alerted_once(self):
        self._run_then_stop()
        self._append("while-down.biz")
        state = alert._load_tail()
        alert._tail_once(state)
        self.assertEqual(self.sent, ["while-down.biz"], "the event written while the server was down")
        self.assertTrue(any("resuming" in _ for _ in self.errors))

    def test_without_a_saved_position_it_still_starts_at_the_end(self):
        self._append("old.biz")
        state = alert._load_tail()
        alert._tail_once(state)
        self.assertEqual(self.sent, [])

    def test_another_inode_is_not_resumed(self):
        self._run_then_stop()
        os.rename(self.path, self.path + ".1")
        self._append("x.biz", "y.biz")
        state = alert._load_tail()
        alert._tail_once(state)
        self.assertEqual(self.sent, [], "a rotated file was replayed")

    def test_another_day_is_not_resumed(self):
        state = self._run_then_stop()
        yesterday = alert._log_path(time.time() - 86400)
        os.rename(self.path, yesterday)
        import json as _json
        with open(os.path.join(self.tmp, alert.TAIL_STATE_FILE), "w") as f:
            _json.dump({"path": yesterday, "inode": state["inode"], "offset": 0, "queue": []}, f)
        self._append("today.biz")
        state = alert._load_tail()
        alert._tail_once(state)
        self.assertEqual(self.sent, [], "a resume replayed another day")

    def test_the_resume_is_capped(self):
        self._run_then_stop()
        alert.MAX_ALERT_QUEUE = 3
        self._append(*("r%d.biz" % i for i in range(10)))
        state = alert._load_tail()
        alert._tail_once(state)
        self.assertEqual(self.sent, ["r0.biz", "r1.biz", "r2.biz"])
        self.assertTrue(any("stopped at 3 alert(s)" in _ for _ in self.errors))
        self._append("live.biz")
        alert._tail_once(state)
        self.assertEqual(self.sent[3:], ["live.biz"], "after the cap the live tail goes on")

    def test_the_pending_queue_survives_a_restart(self):
        alert.send = self._send
        state = alert._load_tail()
        alert._tail_once(state)
        self._append("pending.biz")
        alert._tail_once(state)
        self.assertEqual(len(alert._queue), 1)
        alert._save_tail(state, now=10 ** 9)
        alert._queue.clear()
        alert._load_tail()
        self.assertEqual(len(alert._queue), 1, "the waiting alert was lost with the process")
        self.assertIn("pending.biz", alert._queue[0])

    def test_saving_is_throttled(self):
        state = alert._load_tail()
        self.assertTrue(alert._save_tail(state, now=1000))
        state["offset"] = 1
        self.assertFalse(alert._save_tail(state, now=1001))
        self.assertTrue(alert._save_tail(state, now=1000 + alert.TAIL_SAVE_PERIOD))
        self.assertFalse(alert._save_tail(state, now=2000), "nothing changed, nothing written")


if __name__ == "__main__":
    unittest.main()
