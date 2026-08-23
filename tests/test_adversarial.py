#!/usr/bin/env python

"""
Copyright (c) 2014-2026 Maltrail developers (https://github.com/stamparm/maltrail/)
See the file 'LICENSE' for copying permission

Adversarial/QA tests: hostile inputs driven through the server-side machinery to prove it
degrades the way the design claims - corrupt logs stay searchable, corrupt sidecars rebuild,
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


class SplitRoundTrip(unittest.TestCase):
    HOSTILE = ["", "-", "plain", "a b", 'say "hi"', 'he said "don"t"', "back\\slash", "tab\tinside",
               "new\nline", "cr\rreturn", "\r\n", "\"", '""', '"""', " quote", "quote ", "  spaced  ",
               "ünïcödé", "İstanbul", "%s%d{}", "--comment", "a" * 5000]

    def test_safe_value_fields_survive_a_round_trip(self):
        # Whatever a feed/DNS/HTTP layer puts in one field, the eleven-column layout must come
        # back with every field intact - that is what the index's structured columns trust.
        # safe_value flattens CR/LF to spaces and writes empty as '-', so that IS round-trip.
        def expected(field):
            flattened = re.sub(r"[\x0a\x0d]", " ", field)
            return flattened if flattened else "-"

        for position in xrange(11):
            for hostile in self.HOSTILE:
                fields = ["filler-%d" % i for i in xrange(11)]
                fields[position] = hostile
                line = " ".join(safe_value(f) for f in fields)
                got = index.split_event_line(line.strip())
                self.assertEqual(len(got), 11, "%r at %d -> %r" % (hostile, position, got))
                self.assertEqual(got, [expected(f) for f in fields], "%r at %d" % (hostile, position))

    def test_newlines_cannot_split_a_field(self):
        # Log injection: a CR/LF inside any field is flattened by safe_value BEFORE quoting,
        # so one event can never masquerade as two log lines.
        for hostile in ("evil\ndef.com", "a\r\nb", "\nx"):
            line = _line(0, "10.0.0.5", 40000, "1.2.3.4", 443, "TCP", "DNS", hostile, "x", "y")
            self.assertEqual(line.count("\n"), 1)
            self.assertNotIn("\n", index.split_event_line(line.strip())[8])


class HostileLogs(unittest.TestCase):
    def setUp(self):
        index._locks.clear()
        self.dir = tempfile.mkdtemp(prefix="maltrail-adversarial-")
        config.LOG_DIR = self.dir

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def _write(self, data, mode="wb"):
        with open(os.path.join(self.dir, "%s.log" % DAY), mode) as f:
            f.write(data)

    def test_binary_garbage_stays_text_searchable(self):
        valid = [_line(i, "10.0.0.5", 40000, "1.2.3.4", 443, "TCP", "DNS", "hit%d.example" % i, "malware (test)", "x")
                 for i in xrange(20)]
        garbage = [b"\x00\x01\x02\xff\xfe binary \x7f noise\n", b"\xff\xff\xff\n", b"\x80\x81 no spaces here but junk \xc3\n"]
        payload = b"".join(line.encode("utf8") for line in valid[:10]) + b"".join(garbage) \
            + b"".join(line.encode("utf8") for line in valid[10:])
        self._write(payload)
        self.assertTrue(index.prepare(DAY))
        for needle in ("hit3.example", "hit15.example", "binary", "no spaces"):
            with open(os.path.join(self.dir, "%s.log" % DAY), "rb") as f:
                brute = []
                offset = 0
                for raw in f:
                    if needle.encode("utf8", "ignore") in raw.lower():
                        brute.append(offset)
                    offset += len(raw)
            self.assertEqual(sorted(index.search(DAY, needle)), brute, needle)

    def test_crlf_lines_index_exactly_once(self):
        self._write(b"".join(_line(i, "10.0.0.5", 40000, "1.2.3.4", 443, "TCP", "DNS", "crlf.example", "x", "y").encode()
                             for i in xrange(5)).replace(b"\n", b"\r\n"))
        self.assertTrue(index.prepare(DAY))
        self.assertEqual(len(list(index.search(DAY, "crlf.example"))), 5)

    def test_huge_newline_less_tail_is_abandoned_not_choked_on(self):
        index._MAX_PENDING_SAVED = index._MAX_PENDING
        index._MAX_PENDING = 4096
        try:
            self._write(_line(0, "10.0.0.5", 40000, "1.2.3.4", 443, "TCP", "DNS", "before.example", "x", "y").encode()
                        + b"x" * 65536)   # newline-less blob far past the cap
            self.assertTrue(index.prepare(DAY))
            self.assertEqual(len(list(index.search(DAY, "before.example"))), 1)
        finally:
            index._MAX_PENDING = index._MAX_PENDING_SAVED

    def test_corrupt_sidecar_rebuilds_itself(self):
        self._write(b"".join(_line(i, "10.0.0.5", 40000, "1.2.3.4", 443, "TCP", "DNS", "keep.example", "x", "y").encode()
                             for i in xrange(9)))
        self.assertTrue(index.prepare(DAY))
        db = index._db_path(DAY)
        with open(db, "wb") as f:
            f.write(os.urandom(8192))          # not a sqlite file at all
        self.assertTrue(index.prepare(DAY))
        self.assertEqual(len(list(index.search(DAY, "keep.example"))), 9)

    def test_empty_and_missing_logs(self):
        self._write(b"")
        self.assertTrue(index.prepare(DAY))
        self.assertEqual(index.count(DAY), 0)
        os.remove(os.path.join(self.dir, "%s.log" % DAY))
        self.assertFalse(index.prepare(DAY))

    def test_unicode_and_metacharacter_needles_match_brute_force(self):
        lines = []
        trails = ["Ünïcodé.example", "İstanbul.example", "percent%.example",
                  "under_score.example", "dot.dot.example", "plain%d.example"]
        for i in xrange(60):
            trail = trails[i % len(trails)]
            lines.append(_line(i, "10.0.0.5", 40000, "1.2.3.4", 443, "TCP", "DNS",
                               trail % i if "%d" in trail else trail, "x", "y"))
        self._write("".join(lines).encode("utf8"))
        self.assertTrue(index.prepare(DAY))

        # the contract is str.lower() per line (bytes.lower() only folds ASCII), so the brute
        # force decodes each line exactly like core/index.py does before comparing
        with open(os.path.join(self.dir, "%s.log" % DAY), "rb") as f:
            content = f.read()
        line_starts, offsets = [], []
        pos = 0
        while pos <= len(content):
            nl = content.find(b"\n", pos)
            end = len(content) if nl < 0 else nl
            line_starts.append(pos)
            offsets.append(content[pos:end].decode("utf8", "ignore").lower())
            if nl < 0:
                break
            pos = nl + 1

        def brute(needle):
            return sorted({line_starts[i] for i, lowered in enumerate(offsets) if needle.lower() in lowered})

        for needle in ("ünïcodé", "ÜNÏCODÉ".lower(), "̇", "istanbul", "percent%", "_score",
                       "..", "PLAIN30", "no-such-needle", "e"):
            self.assertEqual(sorted(index.search(DAY, needle)), brute(needle), needle)


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
