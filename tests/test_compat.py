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
import re
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


class ReadmeAgreesWithTheEvidence(unittest.TestCase):
    """README states a platform count. Counts in prose rot, and this one has a source of truth.

    docs/compat/rows is that source: it is what was actually recorded. A distribution dropped from
    the harness, or added to it, changes the number in README and nothing would otherwise say so -
    which is how "44 feeds" survived in AGENTS.md while there were 42.
    """

    NUMBERS = {"twelve": 12, "thirteen": 13, "fourteen": 14, "fifteen": 15, "sixteen": 16,
               "seventeen": 17, "eighteen": 18, "nineteen": 19, "twenty": 20}

    def setUp(self):
        with io.open(os.path.join(ROOT, "README.md"), encoding="utf-8") as handle:
            self.readme = handle.read()

    def _rows(self):
        out = []
        for name in sorted(os.listdir(ROWS)):
            if name.endswith(".json"):
                with io.open(os.path.join(ROWS, name), encoding="utf-8") as handle:
                    out.append(json.load(handle))
        return out

    def test_the_linux_distribution_count_is_the_recorded_one(self):
        rows = self._rows()
        # By label, not by row: two architectures of Ubuntu are one distribution the installer was
        # verified on, and counting rows would say thirteen where a reader would count twelve.
        linux = set(r["label"] for r in rows
                    if not r["os"].startswith(("FreeBSD", "macOS", "Windows", "NetBSD", "OpenBSD")))
        match = re.search(r"verified on (\w+) Linux distributions", self.readme)
        self.assertTrue(match, "README no longer states a Linux distribution count - if the "
                               "sentence moved, point this test at it rather than deleting it")
        word = match.group(1)
        claimed = self.NUMBERS.get(word)
        self.assertIsNotNone(claimed, "README says %r distributions, which this test cannot read "
                                      "as a number; add it to NUMBERS" % word)
        self.assertEqual(claimed, len(linux),
                         "README claims %d Linux distributions; docs/compat/rows records %d (%s)"
                         % (claimed, len(linux), ", ".join(sorted(linux))))

    def test_every_non_linux_platform_recorded_is_named(self):
        # The reverse rot: FreeBSD and macOS were tested for a release before README mentioned
        # either, so the documentation understated what had been verified.
        #
        # Scoped to the sentence that makes the claim, not to the whole file. Looking anywhere in
        # README passed while the verification sentence said only FreeBSD, because a FreeBSD port
        # and a pfSense package are linked further down - a control that could not fail.
        match = re.search(r"The installer is verified on.*?\.\s", self.readme, re.S)
        self.assertTrue(match, "README no longer has an 'installer is verified on' sentence")
        claim = match.group(0)
        rows = self._rows()
        for family in sorted(set(r["os"].split()[0] for r in rows
                                 if r["os"].startswith(("FreeBSD", "macOS", "NetBSD", "OpenBSD")))):
            self.assertIn(family, claim,
                          "docs/compat records a %s row, but README's verification sentence does "
                          "not name it - the installer is verified on more platforms than the "
                          "documentation says. The sentence: %s" % (family, claim.strip()))


if __name__ == "__main__":
    unittest.main()
