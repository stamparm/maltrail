# coding: utf-8
"""Unit tests for the cited-commit gate (sensor/tools/check_refs.py).

The tool exists because a history rewrite is silent: `git filter-repo` changed every SHA in this
repository and nothing in CI noticed that five citations no longer resolved. The worst was
SECURITY.md telling a reader to run `git show <sha>^:misc/server.pem` to check their own exposure
to the leaked key - a command that had been answering "fatal: Not a valid object name" for weeks.

Both directions matter here, as with every other gate: a checker that reports nothing passes just
as quietly as the problem it was written for."""

import io
import os
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "sensor", "tools"))

import check_refs as C

# The Python 3.6 job runs in the official 3.6 image, which ships no git. Everything that needs to
# resolve a commit is skipped there rather than erroring; the 'version consistency' job has git and
# a full clone, and gates on the tool itself.
NEEDS_GIT = unittest.skipUnless(C.have_git(), "no git on PATH (the 3.6 image has none)")


class TokenTest(unittest.TestCase):
    def _tokens(self, line):
        return [m.group(1) for m in C.TOKEN.finditer(line)]

    def test_a_backticked_short_sha_is_found(self):
        self.assertEqual(self._tokens("landed as `66b2307` (subject)"), ["66b2307"])

    def test_a_bare_sha_after_the_word_commit_is_found(self):
        self.assertEqual(self._tokens("until commit f32c991 this repository"), ["f32c991"])

    def test_hex_glued_to_a_path_or_identifier_is_not_a_citation(self):
        # `deadbeef.tar.gz`, `0xdeadbeef` and `a/deadbeef1/b` are not commit references
        for line in ("see deadbeef1.tar.gz", "the constant 0xdeadbeef1", "path/deadbeef1/x"):
            self.assertEqual(self._tokens(line), [], line)

    def test_a_sha256_is_too_long_to_be_mistaken_for_one(self):
        self.assertEqual(self._tokens("sha256 " + "a1b2c3d4" * 8), [])


@NEEDS_GIT
class ResolutionTest(unittest.TestCase):
    def test_a_real_commit_resolves(self):
        head = subprocess.check_output(["git", "-C", ROOT, "rev-parse", "--short", "HEAD"]).decode().strip()
        self.assertTrue(C.resolves(head))

    def test_an_invented_sha_does_not(self):
        self.assertFalse(C.resolves("deadbeef1"))

    def test_the_tree_is_clean_right_now(self):
        # The assertion that would have caught the split's damage on the day it happened. Most CI
        # jobs check out at depth 1, where no cited commit resolves and this would fail for a
        # reason that is not about the tree - so it defers to the 'version consistency' job, which
        # checks out with fetch-depth: 0 and runs check_refs.py as a gate.
        if C.is_shallow():
            self.skipTest("shallow clone; the 'version consistency' CI job gates this on a full one")
        dangling = {t: w for t, w in C.citations().items()
                    if t not in C.NOT_COMMITS and not C.resolves(t)}
        self.assertEqual(dangling, {}, "cited commit(s) that no longer exist: %s" % sorted(dangling))


class ExemptionTest(unittest.TestCase):
    """NOT_COMMITS is a list of lies about hex, so it has to stay honest."""

    @NEEDS_GIT
    def test_every_exemption_is_still_written_somewhere(self):
        # an exemption for a token nobody writes any more will silently cover a future real one
        found = C.citations()
        stale = [_ for _ in C.NOT_COMMITS if _ not in found]
        self.assertEqual(stale, [], "NOT_COMMITS entries nothing cites any more: %s" % stale)

    def test_every_exemption_carries_a_reason(self):
        for token, reason in C.NOT_COMMITS.items():
            self.assertTrue(reason and len(reason) > 10, "%s has no real reason" % token)

    @NEEDS_GIT
    def test_no_exemption_is_actually_a_commit(self):
        # exempting a real SHA would hide it from the gate for no reason
        for token in C.NOT_COMMITS:
            self.assertFalse(C.resolves(token), "%s resolves - it does not need exempting" % token)


class ShallowCloneTest(unittest.TestCase):
    """On a shallow checkout every citation looks dangling, which is a lie in the other direction.

    Asserted as BEHAVIOUR rather than by inspecting this working copy: the suite runs on both
    shallow and full checkouts, and a test that only passes on one of them is not testing the tool."""

    def test_a_shallow_clone_exits_2_rather_than_reporting_every_citation_broken(self):
        real = C.is_shallow
        C.is_shallow = lambda: True
        try:
            # 2 is "could not run", distinct from 1 ("ran and found problems") and 0 ("clean")
            self.assertEqual(C.main(["--quiet"]), 2)
        finally:
            C.is_shallow = real

    def test_no_git_at_all_also_exits_2(self):
        # the Python 3.6 image has no git binary; before this the tool raised FileNotFoundError and
        # took the whole suite down with it, which is a crash rather than an answer
        real = subprocess.check_output

        def no_git(cmd, *args, **kwargs):
            if cmd and cmd[0] == "git":
                raise OSError(2, "No such file or directory: 'git'")
            return real(cmd, *args, **kwargs)

        subprocess.check_output = no_git
        try:
            self.assertFalse(C.have_git())
            self.assertEqual(C.main(["--quiet"]), 2)
        finally:
            subprocess.check_output = real
        self.assertTrue(C.have_git(), "the patch leaked")

    @NEEDS_GIT
    def test_a_full_clone_is_allowed_to_run(self):
        real = C.is_shallow
        C.is_shallow = lambda: False
        try:
            self.assertIn(C.main(["--quiet"]), (0, 1))
        finally:
            C.is_shallow = real


if __name__ == "__main__":
    unittest.main()
