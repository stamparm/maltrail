#!/usr/bin/env python

"""
Copyright (c) 2014-2026 Maltrail developers (https://github.com/stamparm/maltrail/)
See the file 'LICENSE' for copying permission
"""

import os
import random
import shutil
import sqlite3
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from core import index  # noqa: E402
from core.compat import xrange  # noqa: E402
from core.log import safe_value  # noqa: E402
from core.settings import config  # noqa: E402

DAY = "2026-08-01"


def _line(sec, src_ip, src_port, dst_ip, dst_port, proto, trail_type, trail, info, reference, sensor="sensor1"):
    localtime = "2026-08-01 10:%02d:%02d.000000" % (sec / 60 % 60, sec % 60)
    return " ".join(_ for _ in (safe_value(localtime), safe_value(sensor), safe_value(src_ip), safe_value(src_port),
                                safe_value(dst_ip), safe_value(dst_port), safe_value(proto), safe_value(trail_type),
                                safe_value(trail), safe_value(info), safe_value(reference))) + "\n"


def _write_log(lines):
    log_dir = tempfile.mkdtemp(prefix="maltrail-index-test-")
    config.LOG_DIR = log_dir
    with open(os.path.join(log_dir, "%s.log" % DAY), "w+") as f:
        f.write("".join(lines))
    return log_dir


def _brute_force(log_dir, day, needle):
    with open(os.path.join(log_dir, "%s.log" % day)) as f:
        return [offset for offset, line in _numbered(f) if needle in line.lower()]


def _numbered(f):
    offset = 0
    for raw in f:
        yield offset, raw
        offset += len(raw)


class IndexTests(unittest.TestCase):
    def setUp(self):
        index._locks.clear()
        self.dirs = []

    def tearDown(self):
        for path in self.dirs:
            shutil.rmtree(path, ignore_errors=True)

    def _log_dir(self, lines):
        self.dirs.append(_write_log(lines))
        return self.dirs[-1]

    def test_split_event_line_round_trips_safe_value(self):
        line = _line(5, "10.0.0.5", 40000, "1.2.3.4", 443, "TCP", "DNS", "a b.ev il.example", 'say "hi"', "(custom)")
        fields = index.split_event_line(line.strip())
        self.assertEqual(len(fields), 11)
        self.assertEqual(fields[8], "a b.ev il.example")
        self.assertEqual(fields[9], 'say "hi"')
        self.assertEqual(fields[10], "(custom)")

    def test_search_matches_brute_force_on_varied_lines(self):
        random.seed(20260801)
        lines = []
        for i in xrange(500):
            trail = "%s.evil%d.example" % (random.choice(("cdn", "mail", "vpn")), i % 7)
            info = random.choice(("malware (test)", 'spam "quoted" info', "path /a b/c"))
            lines.append(_line(i, "10.0.0.%d" % (i % 250 + 1), 40000 + i, "203.0.113.%d" % (i % 250 + 1), 443,
                               random.choice(("TCP", "UDP")), random.choice(("DNS", "URL", "IP")), trail, info, "abuse.ch"))
            if i % 97 == 0:   # a malformed line: still text-searchable, no structured columns
                lines.append("garbage line without eleven fields\n")
        log_dir = self._log_dir(lines)

        self.assertTrue(index.prepare(DAY))
        for needle in ("evil3.example", "EVIL3.EXAMPLE".lower(), "spam", "garbage", "203.0.113.77", "no-such-thing",
                       "evil0.example", "cdn.evil6"):
            got = list(index.search(DAY, needle))
            self.assertEqual(got, _brute_force(log_dir, DAY, needle), needle)
        # offsets are byte positions into the log, so spot-check one against its text
        with open(os.path.join(log_dir, "%s.log" % DAY), "rb") as f:
            f.seek(list(index.search(DAY, "evil0.example"))[0])
            self.assertIn(b"evil0.example", f.readline())

    def test_append_is_picked_up_incrementally(self):
        log_dir = self._log_dir([_line(i, "10.0.0.5", 40000, "1.2.3.4", 443, "TCP", "DNS", "early.example", "malware (test)", "x") for i in xrange(20)])
        self.assertTrue(index.prepare(DAY))
        self.assertEqual(len(list(index.search(DAY, "early.example"))), 20)
        self.assertEqual(list(index.search(DAY, "late.example")), [])

        with open(os.path.join(log_dir, "%s.log" % DAY), "a") as f:
            f.write(_line(99, "10.0.0.6", 40001, "1.2.3.5", 443, "TCP", "DNS", "late.example", "malware (test)", "x"))
        self.assertTrue(index.prepare(DAY))
        got = list(index.search(DAY, "late.example"))
        self.assertEqual(len(got), 1)
        # ... and the offset points at the appended line's bytes
        with open(os.path.join(log_dir, "%s.log" % DAY), "rb") as f:
            f.seek(got[0])
            self.assertIn(b"late.example", f.readline())

    def test_shrunk_log_is_rebuilt(self):
        lines = [_line(i, "10.0.0.5", 40000, "1.2.3.4", 443, "TCP", "DNS", "keep.example" if i < 5 else "drop.example", "malware (test)", "x") for i in xrange(20)]
        log_dir = self._log_dir(lines)
        self.assertTrue(index.prepare(DAY))
        self.assertEqual(len(list(index.search(DAY, "drop.example"))), 15)

        with open(os.path.join(log_dir, "%s.log" % DAY), "w+") as f:
            f.write("".join(lines[:5]))
        self.assertTrue(index.prepare(DAY))
        self.assertEqual(list(index.search(DAY, "drop.example")), [])
        self.assertEqual(len(list(index.search(DAY, "keep.example"))), 5)

    def test_dropped_log_drops_the_sidecar(self):
        log_dir = self._log_dir([_line(0, "10.0.0.5", 40000, "1.2.3.4", 443, "TCP", "DNS", "gone.example", "malware (test)", "x")])
        self.assertTrue(index.prepare(DAY))
        self.assertTrue(os.path.isfile(index._db_path(DAY)))
        os.remove(os.path.join(log_dir, "%s.log" % DAY))
        self.assertFalse(index.prepare(DAY))
        self.assertFalse(os.path.exists(index._db_path(DAY)))

    def test_count_is_exact(self):
        self._log_dir([_line(i, "10.0.0.5", 40000, "1.2.3.4", 443, "TCP", "DNS", "c.example", "malware (test)", "x") for i in xrange(37)])
        self.assertEqual(index.count(DAY), 37)

    def test_partial_trailing_line_is_not_indexed_until_complete(self):
        log_dir = self._log_dir([_line(0, "10.0.0.5", 40000, "1.2.3.4", 443, "TCP", "DNS", "done.example", "malware (test)", "x")])
        with open(os.path.join(log_dir, "%s.log" % DAY), "a") as f:
            f.write(_line(1, "10.0.0.5", 40000, "1.2.3.4", 443, "TCP", "DNS", "writing.example", "malware (test)", "x")[:-10])  # writer mid-append
        self.assertTrue(index.prepare(DAY))
        self.assertEqual(list(index.search(DAY, "writing.example")), [])
        with open(os.path.join(log_dir, "%s.log" % DAY), "a") as f:
            f.write(_line(1, "10.0.0.5", 40000, "1.2.3.4", 443, "TCP", "DNS", "writing.example", "malware (test)", "x")[-10:])
        self.assertTrue(index.prepare(DAY))
        self.assertEqual(len(list(index.search(DAY, "writing.example"))), 1)

    def test_disabled_option_falls_back(self):
        self._log_dir([_line(0, "10.0.0.5", 40000, "1.2.3.4", 443, "TCP", "DNS", "x.example", "malware (test)", "x")])
        config.USE_EVENT_INDEX = False
        try:
            self.assertFalse(index.prepare(DAY))
            self.assertIsNone(index.count(DAY))
        finally:
            config.USE_EVENT_INDEX = True

    def test_wal_mode_and_sidecar_layout(self):
        self._log_dir([_line(0, "10.0.0.5", 40000, "1.2.3.4", 443, "TCP", "DNS", "x.example", "malware (test)", "x")])
        self.assertTrue(index.prepare(DAY))
        self.assertEqual(os.path.dirname(index._db_path(DAY)), os.path.join(config.LOG_DIR, "index"))
        conn = sqlite3.connect(index._db_path(DAY))
        try:
            self.assertEqual(conn.execute("PRAGMA journal_mode").fetchone()[0].lower(), "wal")
        finally:
            conn.close()


if __name__ == "__main__":
    unittest.main()
