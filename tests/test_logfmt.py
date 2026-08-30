# coding: utf-8
"""Reading an event log line in either format (issue #19130, LOCAL_LOG_FORMAT).

A LOG_DIR becomes a MIXED directory the moment the option changes: yesterday's text logs sit next
to today's JSON. Every reader therefore decides per line, and both formats must decode to the same
eleven fields or the history silently stops being searchable.

The redaction tests are the important ones. `_filter_events` rewrites a text line with two regexes
tuned to its layout, and neither survives JSON: the custom-trail mask matches inside the JSON
string and leaves the line unparseable, and the address-list collapse silently does nothing.
"""
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from core import logfmt
from core.log import event_json

TUPLE = (1767261603, 123456, "10.0.0.8", 6666, "5.5.5.5", 80, "TCP", "IP", "5.5.5.5", "malware (test)", "(static)")
LOCALTIME = "2026-01-01 10:00:03.123456"
TEXT = '"2026-01-01 10:00:03.123456" sensor-a 10.0.0.8 6666 5.5.5.5 80 TCP IP 5.5.5.5 "malware (test)" (static)'


class TestFormatDetection(unittest.TestCase):
    def test_a_text_line_and_a_json_line_are_told_apart(self):
        self.assertTrue(logfmt.is_json_line(event_json(TUPLE, "medium", "sensor-a", LOCALTIME)))
        self.assertFalse(logfmt.is_json_line(TEXT))
        # a text line always starts with the quoted timestamp, so one character is enough
        self.assertFalse(logfmt.is_json_line(""))
        self.assertTrue(logfmt.is_json_line(b'{"a": 1}'))

    def test_both_formats_decode_to_the_same_fields(self):
        as_json = logfmt.fields(event_json(TUPLE, "medium", "sensor-a", LOCALTIME))
        as_text = logfmt.fields(TEXT)
        self.assertEqual(as_json, as_text)
        self.assertEqual(as_text[0], LOCALTIME, "microseconds must survive the round trip")
        self.assertEqual(as_text[2], "10.0.0.8")
        self.assertEqual(as_text[9], "malware (test)", "a quoted field with spaces stays one field")

    def test_ports_are_text_in_both_formats(self):
        # JSON writes a port as a number; a caller comparing with "6666" must not have to care
        self.assertEqual(logfmt.fields(event_json(TUPLE, "medium", "s", LOCALTIME))[3], "6666")

    def test_a_logstash_json_line_without_time_still_reads(self):
        # the wire form has no "time" field; falling back to the epoch keeps the line usable
        wire = event_json(TUPLE, "medium", "sensor-a")
        self.assertNotIn('"time"', wire)
        self.assertEqual(logfmt.fields(wire)[0], "1767261603")

    def test_junk_is_rejected_rather_than_half_parsed(self):
        self.assertIsNone(logfmt.fields("garbage"))
        self.assertIsNone(logfmt.fields("{not json"))
        self.assertIsNone(logfmt.fields('{"timestamp": 1}'), "a JSON object missing fields is not an event")
        self.assertIsNone(logfmt.fields("[1, 2, 3]"))


class TestJsonRedaction(unittest.TestCase):
    def line(self, info="supersecretname (custom)", ref="(custom)", src="10.0.0.8"):
        t = (1767261603, 0, src, 6666, "5.5.5.5", 80, "TCP", "IP", "5.5.5.5", info, ref)
        return event_json(t, "medium", "sensor-a", LOCALTIME)

    def test_the_custom_mask_removes_the_name_and_keeps_valid_json(self):
        out = logfmt.redact_json(self.line(), True, None)
        self.assertNotIn("supersecretname", out)
        self.assertEqual(json.loads(out)["info"], "-", "the name lives in info, not in trail")
        self.assertEqual(json.loads(out)["trail"], "5.5.5.5", "the trail itself is not the secret")

    def test_the_text_regex_would_have_corrupted_the_line(self):
        # what _filter_events does to a text line, applied to JSON: the secret goes, but so does
        # the line's validity - and a reader that has to parse it then gets nothing at all
        import re
        corrupted = re.sub(r'("[^"]+"|[^ ]+) \(custom\)', "- (custom)", self.line())
        self.assertNotIn("supersecretname", corrupted)
        with self.assertRaises(ValueError):
            json.loads(corrupted)

    def test_an_address_list_is_collapsed_to_the_analysts_own_address(self):
        out = logfmt.redact_json(self.line(src="10.0.0.8,10.0.0.9,10.0.0.10"), False, "10.0.0.8")
        self.assertEqual(json.loads(out)["src_ip"], "10.0.0.8")

    def test_a_non_custom_event_is_returned_untouched(self):
        original = self.line(info="malware (test)", ref="(static)")
        self.assertEqual(logfmt.redact_json(original, True, None), original)

    def test_an_unparseable_line_is_passed_through_not_dropped(self):
        self.assertEqual(logfmt.redact_json("{broken", True, "1.2.3.4"), "{broken")

    def test_key_order_survives_redaction(self):
        before = list(json.loads(self.line()).keys())
        after = list(json.loads(logfmt.redact_json(self.line(), True, None)).keys())
        self.assertEqual(before, after)


if __name__ == "__main__":
    unittest.main()
