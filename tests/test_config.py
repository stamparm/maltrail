# coding: utf-8
"""Config robustness tests: an operator's maltrail.conf can be old, half-migrated, or contain typos.
read_config() must either accept it or fail with a CLEAN message (SystemExit) -- never a raw
traceback -- and new-code accessors must tolerate keys an ancient config lacks (graceful defaults).

Runs read_config() in-process (it clear()s config each call) and asserts the outcome class."""
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.settings import read_config, config

# a minimal VALID server-mode config; individual tests override/remove lines
_BASE = {
    "HTTP_ADDRESS": "127.0.0.1",
    "HTTP_PORT": "8338",
    "MONITOR_INTERFACE": "any",
    "CAPTURE_BUFFER": "10MB",
    "LOG_DIR": "/tmp/mt_cfgtest_logs",
    "UPDATE_PERIOD": "86400",
    "SENSOR_NAME": "test",
}
_USERS = "USERS\n    admin:9ab3cd9d67bf49d01f6a2e33d0bd9bc804ddbe6ce1ff5d219c42624851db5dbc:0:\n"


def _write(d, extra="", drop=()):
    lines = ["%s %s" % (k, v) for k, v in d.items() if k not in drop]
    fd, path = tempfile.mkstemp(suffix=".conf")
    with os.fdopen(fd, "w") as f:
        f.write("\n".join(lines) + "\n" + _USERS + extra + "\n")
    return path


def _outcome(path):
    """'ok' if read_config accepts, 'exit' if it exits cleanly. Any OTHER exception propagates ->
    that IS the finding (a config value crashed the parser instead of a clean message)."""
    _so, _se = sys.stdout, sys.stderr
    devnull = open(os.devnull, "w")
    sys.stdout = sys.stderr = devnull
    try:
        read_config(path)
        return "ok"
    except SystemExit:
        return "exit"
    finally:
        sys.stdout, sys.stderr = _so, _se
        devnull.close()
        os.unlink(path)


class TestValidConfigs(unittest.TestCase):
    def test_minimal_valid(self):
        self.assertEqual(_outcome(_write(_BASE)), "ok")

    def test_ancient_config_loads(self):
        # old switches / no new keys -> must still load (deprecation warnings are fine, not fatal)
        d = dict(_BASE);
        self.assertEqual(_outcome(_write(d, extra="USE_MULTIPROCESSING true\nUSE_HEURISTICS true\n")), "ok")

    def test_capture_buffer_forms(self):
        for v in ("512MB", "1GB", "10%", "1048576"):
            d = dict(_BASE); d["CAPTURE_BUFFER"] = v
            self.assertEqual(_outcome(_write(d)), "ok", "CAPTURE_BUFFER=%s" % v)


class TestBadConfigsExitCleanly(unittest.TestCase):
    """Each bad value must yield SystemExit (clean message), not a raw traceback."""

    def test_missing_mandatory(self):
        for key in ("MONITOR_INTERFACE", "CAPTURE_BUFFER", "LOG_DIR"):
            self.assertEqual(_outcome(_write(_BASE, drop=(key,))), "exit", "missing %s" % key)

    def test_garbage_numeric_values(self):
        for key, val in [("HTTP_PORT", "notaport"), ("UPDATE_PERIOD", "soon"), ("CAPTURE_BUFFER", "lots")]:
            d = dict(_BASE); d[key] = val
            self.assertEqual(_outcome(_write(d)), "exit", "%s=%s should exit cleanly" % (key, val))

    def test_udp_port_without_address(self):
        d = dict(_BASE); d["UDP_PORT"] = "8337"
        self.assertEqual(_outcome(_write(d)), "exit")   # UDP_PORT requires UDP_ADDRESS

    def test_udp_port_nonnumeric(self):
        d = dict(_BASE); d["UDP_ADDRESS"] = "0.0.0.0"; d["UDP_PORT"] = "514x"
        self.assertEqual(_outcome(_write(d)), "exit")

    def test_malformed_users(self):
        d = dict(_BASE)
        path = _write(d, extra="")
        # rewrite with a broken USERS entry (3 fields instead of 4)
        with open(path, "a") as f:
            pass
        # build a fresh file with bad USERS
        fd, p2 = tempfile.mkstemp(suffix=".conf")
        with os.fdopen(fd, "w") as f:
            f.write("\n".join("%s %s" % (k, v) for k, v in d.items()))
            f.write("\nUSERS\n    admin:hashonly:0\n")   # only 3 colon-fields
        os.unlink(path)
        self.assertEqual(_outcome(p2), "exit")


class TestNewKeysTolerateGarbage(unittest.TestCase):
    """New heuristic/fast-path accessors must never crash on absent or junk values."""

    def _load(self, extra=""):
        import importlib
        import sensor
        path = _write(_BASE, extra=extra)
        _so = sys.stdout; sys.stdout = open(os.devnull, "w")
        try:
            read_config(path)
        finally:
            sys.stdout.close(); sys.stdout = _so; os.unlink(path)
        return sensor

    def test_junk_scan_window_falls_back(self):
        s = self._load(extra="SCAN_WINDOW abc\n")
        self.assertEqual(s._scan_window(), 30)          # non-numeric -> default, no crash

    def test_absent_new_keys_safe(self):
        s = self._load()                                 # no new keys at all (ancient)
        self.assertEqual(s._scan_window(), 30)
        self.assertTrue(s._heuristic_enabled("port_scanning"))
        self.assertEqual(s._fanout_count(), 0)


class TestValueCoercion(unittest.TestCase):
    """read_config value coercion: boolean switches (USE_/CHECK_/ENABLE_/...) -> real bool, digits -> int,
    absent keys -> None. Non-boolean switch values coerce to False (the silent-misconfig class the warning
    at settings.py guards)."""

    def _load(self, extra):
        path = _write(_BASE, extra=extra)
        _so, _se = sys.stdout, sys.stderr
        dn = open(os.devnull, "w"); sys.stdout = sys.stderr = dn
        try:
            read_config(path)
        finally:
            sys.stdout, sys.stderr = _so, _se; dn.close(); os.unlink(path)

    def test_boolean_true(self):
        self._load("USE_HEURISTICS true\n")
        self.assertIs(config.USE_HEURISTICS, True)

    def test_boolean_false(self):
        self._load("USE_HEURISTICS false\n")
        self.assertIs(config.USE_HEURISTICS, False)

    def test_nonboolean_switch_coerced_false(self):
        self._load("USE_HEURISTICS yes\n")               # not 0/1/true/false -> treated as False (+ warning)
        self.assertIs(config.USE_HEURISTICS, False)

    def test_numeric_is_int(self):
        self._load("")                                    # UPDATE_PERIOD comes from _BASE ("86400")
        self.assertEqual(config.UPDATE_PERIOD, 86400)
        self.assertIsInstance(config.UPDATE_PERIOD, int)

    def test_absent_key_is_none(self):
        self._load("")
        self.assertIsNone(config.SOME_KEY_THAT_DOES_NOT_EXIST)


class TestLogFormatParseContract(unittest.TestCase):
    """The sensor writes events with core.log.safe_value (CSV-style quoting), and the dashboard parses
    them with Papa.parse(delimiter=' '). Python's csv reader has the SAME quote semantics as Papa, so
    this guards the producer<->consumer contract: spaced/quoted fields must round-trip to the exact
    columns the UI indexes (row[0]=time, row[1]=sensor, ... row[9]=info) -- catches format drift."""

    def _roundtrip(self, fields):
        import csv
        from core.log import safe_value
        line = " ".join(safe_value(f) for f in fields)
        return next(csv.reader([line], delimiter=" ", quotechar='"'))

    def test_real_event_line_aligns(self):
        fields = ["2026-07-04 10:00:00.000000", "sensor-a", "10.0.0.5", "4421", "8.8.8.8", "53",
                  "UDP", "DNS", "evil.com", "malware (dummy)", "(static)"]
        parsed = self._roundtrip(fields)
        self.assertEqual(parsed, fields)                 # timestamp(space) + info(space) land in ONE column each
        self.assertEqual(parsed[1], "sensor-a")          # sensor column not shifted by the timestamp space
        self.assertEqual(parsed[9], "malware (dummy)")   # info not split on its internal space

    def test_embedded_quote_and_spaces(self):
        fields = ["a b", 'sen"sor', "info with spaces", "-"]
        self.assertEqual(self._roundtrip(fields), fields)


if __name__ == "__main__":
    unittest.main()
