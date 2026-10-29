# coding: utf-8
"""Unit tests for the built-in detection self-check (server.py --detect-test, core/testing.py).

It answers the one question this project's characteristic bug makes hard: "is my install actually detecting
anything?" A check that drives anything other than the shipped sensor binary answers it wrongly - on a healthy
install it prints "0/17 detection(s) fired ... FAILED" and exits 1.

The full replay needs a sensor binary and is asserted where one exists (CI's sensor gate builds it). The part
that must hold everywhere is that the check drives the SHIPPED sensor, and reports a missing one as missing."""

import inspect
import os
import re
import subprocess
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from core import testing as T


class SensorSelectionTest(unittest.TestCase):
    def test_detect_test_drives_the_shipped_sensor_binary(self):
        body = inspect.getsource(T.detect_test)
        self.assertIn("find_sensor()", body)
        self.assertIn("cmd = [binary", body)

    def test_find_sensor_returns_an_executable_or_none(self):
        binary = T.find_sensor()
        if binary is not None:
            self.assertTrue(os.access(binary, os.X_OK), binary)
            self.assertIn("maltrail-sensor", os.path.basename(binary))

    def test_it_reports_a_missing_binary_as_such_rather_than_as_zero_detections(self):
        # the distinction is the whole point: "I cannot find your sensor" is actionable, "0 detections" is a lie
        saved = T.find_sensor
        T.find_sensor = lambda: None
        try:
            import io
            import contextlib
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                result = T.detect_test()
            out = buf.getvalue()
        finally:
            T.find_sensor = saved
        self.assertFalse(result)
        self.assertIn("no sensor binary found", out)
        self.assertNotIn("detection(s) fired", out)


class ReplayTest(unittest.TestCase):
    """The real thing: the crafted pcap through the real binary, asserting every check including the three
    timing-window heuristics that only fire on the pcap's own timestamps."""

    def setUp(self):
        if T.find_sensor() is None:
            self.skipTest("no sensor binary (build with: cargo build --release --manifest-path sensor/Cargo.toml)")

        # Can this interpreter run server.py at all? A build of Python without _sqlite3 cannot import
        # core.common, so the subprocess below dies before detect_test() runs and reports as "0
        # detections" - an environment problem wearing a detection failure's clothes. Skipping on THAT
        # is safe and does not hide a code break: compile-all, test_smoke's import sweep and
        # test_httpd's real server would all fail loudly if server.py genuinely stopped importing.
        probe = subprocess.Popen([sys.executable, os.path.join(ROOT, "server.py"), "--version"],
                                 stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        out = probe.communicate()[0].decode("utf8", "replace")
        if probe.returncode != 0:
            self.skipTest("this interpreter cannot run server.py: %s" % out.strip().split("\n")[-1])

    def test_every_crafted_detection_fires(self):
        cmd = [sys.executable, os.path.join(ROOT, "server.py"), "--detect-test"]
        out = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT).communicate()[0]
        out = out.decode("utf8", "replace")
        self.assertIn("detect test final result: PASSED", out)
        match = re.search(r"(\d+)/(\d+) detection\(s\) fired", out)
        self.assertIsNotNone(match, out)
        fired, total = int(match.group(1)), int(match.group(2))
        self.assertEqual(fired, total, out)
        self.assertGreaterEqual(total, 20, "checks went missing: %s" % out)
        self.assertNotIn("skipped", out)


if __name__ == "__main__":
    unittest.main()
