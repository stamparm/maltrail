# coding: utf-8
"""The published platform table must say what the recorded rows say.

docs/compat/README.md is generated from docs/compat/rows/*.json by
tests/install/record.py, and this fails when the two disagree. Without it the table is a claim
maintained by hand, which becomes marketing within two releases - somebody adds a row for a
platform they meant to test, or drops a distribution and forgets the page.

The rows themselves cannot be checked here: recording one needs Docker and a few minutes per
image, and it is CI's Compatibility workflow that does that. What this asserts is the cheap half -
that nobody has edited the page, or added a row without re-rendering.
"""

import io
import json
import os
import subprocess
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ROWS = os.path.join(ROOT, "docs", "compat", "rows")
PAGE = os.path.join(ROOT, "docs", "compat", "README.md")
TOOL = os.path.join(ROOT, "tests", "install", "record.py")


class CompatPage(unittest.TestCase):
    def setUp(self):
        if not os.path.isdir(ROWS):
            self.skipTest("no docs/compat/rows yet")

    def test_the_page_matches_the_rows(self):
        result = subprocess.Popen([sys.executable, TOOL, "render", "--check"],
                                  cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        out = result.communicate()[0].decode("utf-8", "replace")
        self.assertEqual(result.returncode, 0,
                         "docs/compat/README.md disagrees with docs/compat/rows:\n%s" % out)

    def test_every_row_says_what_it_tested_on_and_with(self):
        """A row without provenance is a claim, not evidence."""
        rows = [f for f in os.listdir(ROWS) if f.endswith(".json")]
        self.assertTrue(rows, "docs/compat/rows is empty")
        for name in sorted(rows):
            with io.open(os.path.join(ROWS, name), encoding="utf-8") as handle:
                row = json.load(handle)
            for key in ("os", "machine", "python", "recorded_at", "recorded_by",
                        "sensor_source", "capabilities"):
                self.assertIn(key, row, "%s has no %r" % (name, key))
                self.assertTrue(row[key], "%s has an empty %r" % (name, key))
            self.assertNotEqual(row["os"], "unknown",
                                "%s does not say which distribution it ran on" % name)

    def test_a_failing_capability_is_never_silently_dropped(self):
        """A row may fail. It may not fail invisibly.

        The renderer only knows three states, and 'not applicable' is a claim in its own right -
        it says the platform CANNOT do this, not that nobody looked.
        """
        for name in sorted(os.listdir(ROWS)):
            if not name.endswith(".json"):
                continue
            with io.open(os.path.join(ROWS, name), encoding="utf-8") as handle:
                row = json.load(handle)
            for capability, value in row["capabilities"].items():
                self.assertIn(value, ("✅", "❌", "➖"),
                              "%s: %r has an unknown state %r" % (name, capability, value))


if __name__ == "__main__":
    unittest.main()
