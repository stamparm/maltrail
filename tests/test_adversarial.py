#!/usr/bin/env python

"""
Copyright (c) 2014-present Maltrail developers (https://github.com/stamparm/maltrail/)
See the file 'LICENSE' for copying permission

Adversarial/QA tests: hostile inputs driven through the server-side machinery to prove it
degrades the way the design claims - corrupt logs stay searchable,
malformed confidence files answer None, and nothing in the log pipeline lets a weird field
corrupt its neighbours (log injection).
"""

import bisect
import os
import re
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from core import httpd  # noqa: E402
from core import logfmt  # noqa: E402
from core.compat import xrange  # noqa: E402
from core.log import safe_value  # noqa: E402
from core.settings import config  # noqa: E402

DAY = "2026-08-01"


def _line(sec, src_ip, src_port, dst_ip, dst_port, proto, trail_type, trail, info, reference, sensor="sensor1"):
    localtime = "2026-08-01 10:%02d:%02d.000000" % (sec / 60 % 60, sec % 60)
    return " ".join(_ for _ in (safe_value(localtime), safe_value(sensor), safe_value(src_ip), safe_value(src_port),
                                safe_value(dst_ip), safe_value(dst_port), safe_value(proto), safe_value(trail_type),
                                safe_value(trail), safe_value(info), safe_value(reference))) + "\n"


class SplitRoundTrip(unittest.TestCase):
    HOSTILE = ["", "-", "plain", "a b", 'say "hi"', 'he said "don"t"', "back\\slash", "tab\tinside",
               "new\nline", "cr\rreturn", "\r\n", "\"", '""', '"""', " quote", "quote ", "  spaced  ",
               "ünïcödé", "İstanbul", "%s%d{}", "--comment", "a" * 5000]

    def test_safe_value_fields_survive_a_round_trip(self):
        # Whatever a feed/DNS/HTTP layer puts in one field, the eleven-column layout must come
        # back with every field intact - that is what every reader of the log trusts.
        # safe_value flattens CR/LF to spaces and writes empty as '-', so that IS round-trip.
        def expected(field):
            flattened = re.sub(r"[\x0a\x0d]", " ", field)
            return flattened if flattened else "-"

        for position in xrange(11):
            for hostile in self.HOSTILE:
                fields = ["filler-%d" % i for i in xrange(11)]
                fields[position] = hostile
                line = " ".join(safe_value(f) for f in fields)
                got = logfmt.split_text_line(line.strip())
                self.assertEqual(len(got), 11, "%r at %d -> %r" % (hostile, position, got))
                self.assertEqual(got, [expected(f) for f in fields], "%r at %d" % (hostile, position))

    def test_newlines_cannot_split_a_field(self):
        # Log injection: a CR/LF inside any field is flattened by safe_value BEFORE quoting,
        # so one event can never masquerade as two log lines.
        for hostile in ("evil\ndef.com", "a\r\nb", "\nx"):
            line = _line(0, "10.0.0.5", 40000, "1.2.3.4", 443, "TCP", "DNS", hostile, "x", "y")
            self.assertEqual(line.count("\n"), 1)
            self.assertNotIn("\n", logfmt.split_text_line(line.strip())[8])


class HostileLogs(unittest.TestCase):
    """core/httpd.py:_hunt_candidates() - the prefilter /hunt reads a day through - against logs no
    writer should produce. It may let a line through that does not match; it must never hold back
    one that does, so every case compares with a brute-force str.lower() over each line."""

    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="maltrail-adversarial-")
        self.path = os.path.join(self.dir, "%s.log" % DAY)

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def _write(self, data):
        with open(self.path, "wb") as f:
            f.write(data)

    def _candidates(self, needle):
        with open(self.path, "rb") as f:
            return list(httpd._hunt_candidates(f, needle))

    def _assert_complete(self, needle):
        with open(self.path, "rb") as f:
            content = f.read()
        lines = content.split(b"\n")
        lines = [line + b"\n" for line in lines[:-1]] + ([lines[-1]] if lines[-1] else [])
        wanted = [line for line in lines if needle.lower() in line.decode("utf8", "ignore").lower()]
        got = self._candidates(needle)
        for line in wanted:
            self.assertIn(line, got, "%r: a matching line was held back" % needle)
        self.assertEqual(got, [line for line in lines if line in got], "%r: candidates out of file order" % needle)

    def test_binary_garbage_stays_text_searchable(self):
        valid = [_line(i, "10.0.0.5", 40000, "1.2.3.4", 443, "TCP", "DNS", "hit%d.example" % i, "malware (test)", "x")
                 for i in xrange(20)]
        garbage = [b"\x00\x01\x02\xff\xfe binary \x7f noise\n", b"\xff\xff\xff\n", b"\x80\x81 no spaces here but junk \xc3\n"]
        self._write(b"".join(line.encode("utf8") for line in valid[:10]) + b"".join(garbage)
                    + b"".join(line.encode("utf8") for line in valid[10:]))
        for needle in ("hit3.example", "hit15.example", "binary", "no spaces"):
            self._assert_complete(needle)
        self.assertEqual(len([_ for _ in self._candidates("hit3.example") if b"hit" in _]), 1,
                         "the control: a needle on one line selects that line, not every line")

    def test_crlf_lines_are_found_once_each(self):
        self._write(b"".join(_line(i, "10.0.0.5", 40000, "1.2.3.4", 443, "TCP", "DNS", "crlf.example", "x", "y").encode()
                             for i in xrange(5)).replace(b"\n", b"\r\n"))
        self.assertEqual(len(self._candidates("crlf.example")), 5)

    def test_a_last_line_without_a_newline_is_read(self):
        self._write(_line(0, "10.0.0.5", 40000, "1.2.3.4", 443, "TCP", "DNS", "before.example", "x", "y").encode()
                    + b"tail.example without a newline")
        self._assert_complete("tail.example")
        self._assert_complete("before.example")

    def test_lines_across_the_read_boundary(self):
        # Far more than one 1 MB read, so lines straddle every chunk boundary.
        self._write(b"".join(_line(i, "10.0.0.5", 40000, "1.2.3.4", 443, "TCP", "DNS", "row%07d.example" % i, "x", "y").encode()
                             for i in xrange(30000)))
        for needle in ("row0000000", "row0012345", "row0029999"):
            self._assert_complete(needle)

    def test_empty_log(self):
        self._write(b"")
        self.assertEqual(self._candidates("anything"), [])

    def test_unicode_and_metacharacter_needles_match_brute_force(self):
        lines = []
        trails = ["Ünïcodé.example", "İstanbul.example", "percent%.example", "under_score.example",
                  "dot.dot.example", "plain%d.example", "\u212aelvin.example"]
        for i in xrange(60):
            trail = trails[i % len(trails)]
            lines.append(_line(i, "10.0.0.5", 40000, "1.2.3.4", 443, "TCP", "DNS",
                               trail % i if "%d" in trail else trail, "x", "y"))
        self._write("".join(lines).encode("utf8"))
        # "kelvin" is the case bytes.lower() cannot see: the Kelvin sign lower-cases to an ASCII 'k'
        for needle in ("ünïcodé", "ÜNÏCODÉ".lower(), "\u0307", "istanbul", "percent%", "_score",
                       "..", "PLAIN30", "no-such-needle", "e", "kelvin"):
            self._assert_complete(needle)


class HostileConfidenceFile(unittest.TestCase):
    """core/httpd.py:_confidence_lookup() against sidecars no writer should ever produce."""

    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="maltrail-confidence-")
        self.serial = 0

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def _path(self, content):
        # unique name (and therefore stat) per call: the lookup caches its mmap by
        # (mtime, size), and same-second rewrites of one path could legally serve a stale map
        self.serial += 1
        path = os.path.join(self.dir, "trails%d.confidence" % self.serial)
        with open(path, "wb") as f:
            f.write(content)
        return path

    def _lookup(self, key, content):
        return httpd._confidence_lookup(key, path=self._path(content))

    def test_empty_file_answers_none(self):
        self.assertIsNone(self._lookup("anything.example", b""))

    def test_binary_garbage_answers_none_without_hanging(self):
        self.assertIsNone(self._lookup("anything.example", os.urandom(4096)))

    def test_no_trailing_newline_last_record_still_found(self):
        content = b"a.example\t100\nb.example\t60"
        self.assertEqual(self._lookup("b.example", content), 60)
        self.assertEqual(self._lookup("a.example", content), 100)

    def test_nonnumeric_score_answers_none(self):
        self.assertIsNone(self._lookup("a.example", b"a.example\tnot-a-number\n"))

    def test_hostile_keys_answer_something_sane(self):
        content = b"a.example\t100\nb.example\t60\n"
        for key in ("", " ", "\t", "\n", "a.example\t100", "a.example\nb.example", "ümlaut.example",
                    "x" * 300, "a" * 256, "\x00\x01\x02"):
            result = self._lookup(key, content)
            self.assertTrue(result is None or isinstance(result, int), repr(key))

    def test_realistic_sorted_file_hit_and_miss(self):
        rows = ("".join("cdn.a%02d.example\t%d\n" % (i, 40 + 15 * min(i, 4)) for i in xrange(10))).encode()
        self.assertEqual(self._lookup("cdn.a07.example", rows), 100)
        self.assertEqual(self._lookup("cdn.a00.example", rows), 40)
        self.assertIsNone(self._lookup("missing.example", rows))


if __name__ == "__main__":
    unittest.main()
