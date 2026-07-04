# coding: utf-8
"""Unit tests for core/log.flush_condensed_events — the server-side event condenser.

Events sharing a (src_ip, trail) key that carry a CONDENSE_ON_INFO_KEYWORDS info string are
buffered and flushed as ONE event, with the differing fields (src_port, dst_ip, dst_port, proto)
merged into a sorted comma-joined string. A regression here means either lost events (over-merge)
or log spam (under-merge). flush runs on a daemon thread; we drive it synchronously via single=True
and capture what it hands to log_event."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import core.log as L

# (sec, usec, src_ip, src_port, dst_ip, dst_port, proto, type, trail, info, ref)
def _ev(src_port, dst_ip, dst_port, proto="TCP"):
    return (1, 0, "10.0.0.5", src_port, dst_ip, dst_port, proto, "IP", "evil.trail", "malware", "(ref)")


class TestFlushCondensedEvents(unittest.TestCase):
    def setUp(self):
        self._orig = L.log_event
        self._captured = []
        L.log_event = lambda ev, **kw: self._captured.append((ev, kw))
        L._condensed_events = {}

    def tearDown(self):
        L.log_event = self._orig
        L._condensed_events = {}

    def test_single_event_passes_through_unmerged(self):
        L._condensed_events = {("10.0.0.5", "evil.trail"): [_ev(4444, "66.66.66.66", 80)]}
        L.flush_condensed_events(single=True)
        self.assertEqual(len(self._captured), 1)
        ev, kw = self._captured[0]
        self.assertTrue(kw.get("skip_condensing"))          # must not re-condense (infinite loop otherwise)
        self.assertEqual(ev[3], 4444)                        # scalar, not a set-string
        self.assertEqual(ev[4], "66.66.66.66")

    def test_differing_ports_merged_sorted(self):
        key = ("10.0.0.5", "evil.trail")
        L._condensed_events = {key: [_ev(1111, "66.66.66.66", 80),
                                     _ev(3333, "66.66.66.66", 80),
                                     _ev(2222, "66.66.66.66", 80)]}
        L.flush_condensed_events(single=True)
        self.assertEqual(len(self._captured), 1)
        ev = self._captured[0][0]
        self.assertEqual(ev[3], "1111,2222,3333")            # merged + sorted
        self.assertEqual(ev[4], "66.66.66.66")               # identical field stays scalar
        self.assertEqual(ev[5], 80)

    def test_multiple_fields_merge_independently(self):
        key = ("10.0.0.5", "evil.trail")
        L._condensed_events = {key: [_ev(1000, "1.1.1.1", 80, "TCP"),
                                     _ev(1000, "2.2.2.2", 443, "UDP")]}
        L.flush_condensed_events(single=True)
        ev = self._captured[0][0]
        self.assertEqual(ev[3], 1000)                        # src_port identical -> scalar
        self.assertEqual(ev[4], "1.1.1.1,2.2.2.2")           # dst_ip merged
        self.assertEqual(ev[5], "80,443")                    # dst_port merged (sorted numerically as ints)
        self.assertEqual(ev[6], "TCP,UDP")                   # proto merged

    def test_flush_clears_buffer(self):
        L._condensed_events = {("10.0.0.5", "evil.trail"): [_ev(4444, "66.66.66.66", 80)]}
        L.flush_condensed_events(single=True)
        self.assertEqual(L._condensed_events, {})            # buffer drained so events aren't re-emitted next flush


class TestRemoteSeverity(unittest.TestCase):
    """The SYSLOG/CEF path derives severity from REMOTE_SEVERITY_REGEX named groups. A custom regex may
    omit some of low/medium/high; match.group(<missing>) would raise IndexError per event (escaping
    log_event's handler, breaking syslog forwarding). groupdict().get() must degrade to default instead."""
    def setUp(self):
        self.sent = []
        self._orig = L._send_datagram
        L._send_datagram = lambda endpoint, data: self.sent.append((endpoint, data))
        c = L.config
        c.SYSLOG_SERVER = "127.0.0.1:65001"
        c.LOG_SERVER = None
        c.LOGSTASH_SERVER = None
        c.DISABLE_LOCAL_LOG_STORAGE = True
        c.console = False
        c.PROCESS_COUNT = 1
        c.plugin_functions = None
        c.IGNORE_EVENTS_REGEX = None
        c.WHITELIST = set()
        # reset per-thread log throttling so each event is emitted
        for attr in ("log_bucket", "log_trails"):
            try:
                delattr(L._thread_data, attr)
            except AttributeError:
                pass

    def tearDown(self):
        L._send_datagram = self._orig

    def _ev(self, info, trail, sec=1700000000):
        # (sec, usec, src_ip, src_port, dst_ip, dst_port, proto, type, trail, info, ref)
        return (sec, 0, "203.0.113.7", 4444, "66.66.66.66", 80, "TCP", "IP", trail, info, "(ref)")

    def test_partial_group_regex_no_crash(self):
        # regex defines ONLY (?P<high>...) -> the low/medium lookups must not raise
        L.config.REMOTE_SEVERITY_REGEX = r"(?P<high>malware)"
        L.log_event(self._ev("malware", "t1"))          # would IndexError on match.group("low") pre-fix
        self.assertTrue(self.sent, "a CEF datagram must be sent")
        self.assertIn("|2|", self.sent[-1][1].decode("utf-8"))   # severity high -> 2

    def test_partial_group_regex_defaults_medium_on_no_match(self):
        L.config.REMOTE_SEVERITY_REGEX = r"(?P<high>malware)"
        L.log_event(self._ev("harmless info", "t2"))
        self.assertTrue(self.sent)
        self.assertIn("|1|", self.sent[-1][1].decode("utf-8"))   # no match -> default medium -> 1

    def test_cef_escaping_of_special_chars(self):
        # a URL-style trail with '=' and an info with '|' must be CEF-escaped so the SIEM parses one
        # clean record (extension '=' -> '\=', header '|' -> '\|'); otherwise the fields run together.
        L.config.REMOTE_SEVERITY_REGEX = None
        L.log_event(self._ev("evil|marker", "host.com/?a=b", sec=1700000123))
        cef = self.sent[-1][1].decode("utf-8")
        self.assertIn(r"trail=host.com/?a\=b", cef, "extension value '=' must be escaped")
        self.assertIn(r"evil\|marker", cef, "header '|' must be escaped (else it splits CEF fields)")
        self.assertNotIn("|evil|marker|", cef)                   # the raw unescaped pipe must not appear as a delimiter

    def test_cef_helper_no_change_for_plain_values(self):
        # zero-regression guarantee: a value with no special chars is returned unchanged
        self.assertEqual(L._cef_escape("plain.example.com"), "plain.example.com")
        self.assertEqual(L._cef_escape("1.2.3.4", extension=True), "1.2.3.4")

    def test_logstash_json_contract(self):
        # LOGSTASH forwarding emits one JSON object per event with the fields Logstash/ELK indexes
        import json as _json
        L.config.SYSLOG_SERVER = None
        L.config.LOGSTASH_SERVER = "127.0.0.1:5000"
        L.config.REMOTE_SEVERITY_REGEX = None
        L.log_event(self._ev("malware (x)", "evil.example"))
        self.assertTrue(self.sent, "a JSON datagram must be sent")
        obj = _json.loads(self.sent[-1][1].decode("utf-8"))
        self.assertEqual(obj["src_ip"], "203.0.113.7")
        self.assertEqual(obj["dst_ip"], "66.66.66.66")
        self.assertEqual(obj["trail"], "evil.example")
        self.assertIn("severity", obj)                   # default 'medium' when no regex matches


if __name__ == "__main__":
    unittest.main()
