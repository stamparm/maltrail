# coding: utf-8
"""Unit tests for the built-in detection self-check (server.py --detect-test, core/testing.py).

It answers the one question this project's characteristic bug makes hard: "is my install actually detecting
anything?" It answered it wrongly. It replayed the fixture through old/sensor.py - the retired Python sensor,
which imports pcapy, which has not been a dependency since the sensor became Rust - so on a healthy install it
printed "0/17 detection(s) fired ... FAILED" and exited 1.

The full replay needs a sensor binary and is asserted where one exists (CI's sensor gate builds it). The part
that must hold everywhere is that the check drives the SHIPPED sensor, so that regression cannot come back on a
machine that happens to have pcapy installed."""

import os
import re
import subprocess
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from core import testing as T


class SensorSelectionTest(unittest.TestCase):
    def test_detect_test_does_not_drive_the_retired_python_sensor(self):
        import inspect
        body = inspect.getsource(T.detect_test)
        body = body.replace(T.detect_test.__doc__ or "", "")     # the docstring says "old/sensor.py" on purpose
        self.assertNotIn("sensor.py", body)
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
    timing-window heuristics that were skipped for as long as the old sensor drove this."""

    def setUp(self):
        if T.find_sensor() is None:
            self.skipTest("no sensor binary (build with: cargo build --release --manifest-path sensor/Cargo.toml)")

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
