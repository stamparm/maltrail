# coding: utf-8
"""The two severity classifiers must agree.

Severity is computed twice, in two languages, from two different inputs:

  * REMOTE_SEVERITY_REGEX -> core/log.py:severity_of() and sensor/src/output.rs:severity_for(),
    which produce the `severity` field in JSON logs, the CEF/syslog priority, and the alert
    threshold; and
  * severityOf() in html/js/main.js, which ranks the dashboard.

Nothing compared them, and they drifted twice. 307e0e8 ranked the sensor's own guesses below feed
hits in the dashboard only, so "long domain (suspicious)" read LOW on screen and alerted as
MEDIUM - the noisiest heuristic in the product paging whoever set ALERT_SEVERITY=medium. Then the
#19622 fix capped the IoT dropper at MEDIUM in the dashboard while the regex still called it HIGH,
leaving two green tests asserting opposite severities for one event.

The regex could not express the dashboard's rule at all until it was given the reference:
"(heuristic)" versus "(static)" is what "corroborated" means, and severity_for() only ever saw the
info. It sees both now, and this file is the guard.

The heuristic verdicts are DISCOVERED from the sensor source rather than listed here, so a new one
cannot quietly arrive on one side only.
"""

import io
import json
import os
import re
import subprocess
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from core.log import severity_of                                            # noqa: E402
from core.settings import config, read_config                              # noqa: E402

MAIN_JS = os.path.join(ROOT, "html", "js", "main.js")
SENSOR_SRC = os.path.join(ROOT, "sensor", "src")

# info, reference - the verdicts whose ranking someone actually argued about
CASES = [
    ("potential iot-malware download (suspicious)", "(heuristic)"),
    ("potential infection (suspicious)", "(heuristic)"),
    ("potential port scanning (suspicious)", "(heuristic)"),
    ("long domain (suspicious)", "(heuristic)"),
    ("sinkhole response (malware)", "(heuristic)"),
    ("malware", "abuse.ch"),
    ("phishing", "openphish"),
    ("known attacker", "blocklist.de"),
    ("bad reputation", "x"),
    ("bad reputation (tor node)", "x"),
    ("spammer", "x"),
    ("crawler", "x"),
    ("cobaltstrike (malware)", "(feed)"),
    ("gophish (malicious)", "(feed)"),
    ("ek clearfake (malicious)", "(static)"),
    ("ipinfo (suspicious)", "(static)"),
    ("pua (suspicious)", "(static)"),
    ("crypto mining (suspicious)", "(static)"),
    ("mass scanner", "(static)"),
    ("potential malware site", "x"),
    ("malware distribution", "x"),
    ("c2 cert", "x"),
    ("internal watchlist (custom)", "(custom)"),
]


def _node():
    for candidate in ("node", "nodejs"):
        for directory in os.environ.get("PATH", "").split(os.pathsep):
            if directory and os.access(os.path.join(directory, candidate), os.X_OK):
                return candidate
    return None


def _sensor_verdicts():
    """Every literal '... (suspicious)' / '... (malware)' info the sensor can emit."""

    found = set()
    pattern = re.compile(r'"([a-z][^"]*\((?:suspicious|malware)\))"')
    for base, _dirs, names in os.walk(SENSOR_SRC):
        for name in names:
            if not name.endswith(".rs"):
                continue
            with io.open(os.path.join(base, name), encoding="utf8") as handle:
                for hit in pattern.findall(handle.read()):
                    found.add(hit)
    return sorted(found)


class SeverityParity(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        read_config(os.path.join(ROOT, "maltrail.conf"))
        if not config.REMOTE_SEVERITY_REGEX:
            raise unittest.SkipTest("maltrail.conf ships no REMOTE_SEVERITY_REGEX")
        cls.node = _node()
        cls.verdicts = _sensor_verdicts()

    def _ui(self, cases):
        if not self.node:
            self.skipTest("needs node to evaluate severityOf()")
        with io.open(MAIN_JS, encoding="utf8") as handle:
            js = handle.read()
        parts = []
        for name in ("HEURISTIC_MEDIUM_KEYWORDS", "INFO_SEVERITY_KEYWORDS"):
            found = re.search(r"var %s = \[.*?\];" % name, js, re.S)
            self.assertTrue(found, "could not find %s in main.js" % name)
            parts.append(found.group(0))
        fn = re.search(r"function severityOf\(info, ref\) \{.*?\n  \}", js, re.S)
        self.assertTrue(fn, "could not find severityOf() in main.js")
        script = "\n".join(parts) + "\n" + fn.group(0) + """
var NAMES = ["", "low", "medium", "high"];
var out = [];
%s.forEach(function (c) { out.push(NAMES[severityOf(c[0], c[1])]); });
console.log(JSON.stringify(out));
""" % json.dumps([list(c) for c in cases])
        raw = subprocess.check_output([self.node, "-e", script], stderr=subprocess.STDOUT)
        return json.loads(raw.decode("utf8", "replace").strip().splitlines()[-1])

    def _compare(self, cases):
        ui = self._ui(cases)
        rows = []
        for (info, reference), expected in zip(cases, ui):
            got = severity_of(info, reference)
            if got != expected:
                rows.append("%-46s %-12s dashboard=%-7s alert=%s" % (info, reference, expected, got))
        return rows

    def test_the_argued_cases_agree(self):
        rows = self._compare(CASES)
        self.assertEqual(rows, [],
                         "the dashboard and REMOTE_SEVERITY_REGEX disagree on %d verdict(s). An "
                         "event that reads LOW on screen and pages as MEDIUM is the bug this file "
                         "exists to catch:\n  %s" % (len(rows), "\n  ".join(rows)))

    def test_every_heuristic_the_sensor_emits_agrees(self):
        # Discovered from sensor/src, so a heuristic added on one side shows up here rather than in
        # somebody's pager at 3am.
        self.assertGreater(len(self.verdicts), 10,
                           "found only %d heuristic verdict(s) in %s - the extraction broke, and a "
                           "test that examines nothing passes" % (len(self.verdicts), SENSOR_SRC))
        rows = self._compare([(info, "(heuristic)") for info in self.verdicts])
        self.assertEqual(rows, [],
                         "%d of the sensor's own verdicts are ranked differently by the dashboard "
                         "and by REMOTE_SEVERITY_REGEX:\n  %s" % (len(rows), "\n  ".join(rows)))

    def test_a_guess_never_outranks_a_feed_hit(self):
        # The property underneath both rules: nothing the sensor concluded on its own reaches the
        # rank of something a feed actually listed.
        for info in self.verdicts:
            if info.endswith("(malware)"):
                continue        # a corroborated heuristic (sinkhole response) is not a guess
            self.assertIn(severity_of(info, "(heuristic)"), ("low", "medium"),
                          "%r is ranked as high as a feed hit" % info)


if __name__ == "__main__":
    unittest.main()
