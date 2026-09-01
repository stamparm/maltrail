# coding: utf-8
"""The version is written in five files, and nothing used to check that they agreed.

The monthly release automation bumps `core/settings.py` and pushes a tag. Everything else - the
sensor's Cargo manifest, its lock file, CITATION.cff, and the generated Rust mirror of settings.py
- was left behind. The 3.3 tag went out with settings.py at 3.3 and the mirror still at 3.2, the
release gate refused it, and no binaries were built. The tag was already public by then.

Two tools now cover it: bump_version.py writes all five, check_version.py verifies all five. The
danger is that they drift apart - a sixth location gets added to one and not the other, and the
gap reopens silently. So this pins them TO EACH OTHER, and pins both to the real tree.
"""

import os
import re
import subprocess
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TOOLS = os.path.join(ROOT, "sensor", "tools")
sys.path.insert(0, TOOLS)

import bump_version                                   # noqa: E402
import check_version                                  # noqa: E402


class TestVersionLocations(unittest.TestCase):
    def test_the_tree_agrees_with_itself(self):
        # stdout/stderr=PIPE rather than capture_output/text: CI runs this on Python 3.6, where
        # neither keyword exists yet.
        out = subprocess.run([sys.executable, os.path.join(TOOLS, "bump_version.py"), "--check"],
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.assertEqual(out.returncode, 0,
                         "the version is not the same everywhere it is written:\n%s%s"
                         % (out.stdout.decode("utf8", "replace"),
                            out.stderr.decode("utf8", "replace")))

    def test_every_pattern_matches_exactly_once(self):
        # Zero means the file moved on and the bumper silently stopped covering it - which is how
        # this broke. More than one means the pattern is catching something else (a dependency's
        # version key in the lock file, say) and a bump would corrupt the file.
        for path, pattern, _ in bump_version._edits("9.9"):
            with open(path, encoding="utf8") as f:
                text = f.read()
            n = len(re.findall(pattern, text, re.M))
            self.assertEqual(n, 1, "%s: %d matches for %r (expected exactly 1)"
                             % (os.path.relpath(path, ROOT), n, pattern))

    def test_the_bumper_and_the_checker_cover_the_same_files(self):
        written = {os.path.realpath(p) for p, _, _ in bump_version._edits("9.9")}
        verified = {os.path.realpath(p) for p in (check_version.SETTINGS, check_version.CARGO,
                                                  check_version.CITATION, check_version.SETTINGS_GEN,
                                                  check_version.CARGO_LOCK)}
        rel = lambda s: sorted(os.path.relpath(p, ROOT) for p in s)
        self.assertEqual(rel(written), rel(verified),
                         "bump_version.py writes %s but check_version.py verifies %s - a file in "
                         "one list and not the other is a version location that can go stale "
                         "without anything noticing" % (rel(written), rel(verified)))

    def test_a_bump_is_all_or_nothing(self):
        # A pattern that cannot match must abort BEFORE writing anything: a tree left half-bumped
        # is worse than one not bumped at all, because it looks done.
        original = bump_version._edits

        def broken(version):
            edits = original(version)
            return edits[:-1] + [(edits[-1][0], r'^this pattern cannot match anything$', "x")]

        bump_version._edits = broken
        try:
            before = {p: open(p, encoding="utf8").read() for p, _, _ in original("9.9")}
            with self.assertRaises(SystemExit):
                bump_version.apply("9.9")
            after = {p: open(p, encoding="utf8").read() for p, _, _ in original("9.9")}
            self.assertEqual(before, after, "a refused bump still modified files on disk")
        finally:
            bump_version._edits = original


class TestReleaseGateKeepsTheCheck(unittest.TestCase):
    def test_the_release_workflow_still_verifies_the_tag(self):
        path = os.path.join(ROOT, ".github", "workflows", "release.yml")
        with open(path, encoding="utf8") as f:
            text = f.read()
        self.assertIn("check_version.py --tag", text,
                      "the release workflow no longer checks that the tree's version matches the "
                      "tag it is publishing")

if __name__ == "__main__":
    unittest.main()
