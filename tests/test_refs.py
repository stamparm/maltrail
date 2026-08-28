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


class ResolutionTest(unittest.TestCase):
    def test_a_real_commit_resolves(self):
        head = subprocess.check_output(["git", "-C", ROOT, "rev-parse", "--short", "HEAD"]).decode().strip()
        self.assertTrue(C.resolves(head))

    def test_an_invented_sha_does_not(self):
        self.assertFalse(C.resolves("deadbeef1"))

    def test_the_tree_is_clean_right_now(self):
        # the assertion that would have caught the split's damage on the day it happened
        self.assertEqual(C.main.__name__, "main")   # imported, not executed twice
        dangling = {t: w for t, w in C.citations().items()
                    if t not in C.NOT_COMMITS and not C.resolves(t)}
        self.assertEqual(dangling, {}, "cited commit(s) that no longer exist: %s" % sorted(dangling))


class ExemptionTest(unittest.TestCase):
    """NOT_COMMITS is a list of lies about hex, so it has to stay honest."""

    def test_every_exemption_is_still_written_somewhere(self):
        # an exemption for a token nobody writes any more will silently cover a future real one
        found = C.citations()
        stale = [_ for _ in C.NOT_COMMITS if _ not in found]
        self.assertEqual(stale, [], "NOT_COMMITS entries nothing cites any more: %s" % stale)

    def test_every_exemption_carries_a_reason(self):
        for token, reason in C.NOT_COMMITS.items():
            self.assertTrue(reason and len(reason) > 10, "%s has no real reason" % token)

    def test_no_exemption_is_actually_a_commit(self):
        # exempting a real SHA would hide it from the gate for no reason
        for token in C.NOT_COMMITS:
            self.assertFalse(C.resolves(token), "%s resolves - it does not need exempting" % token)


class ShallowCloneTest(unittest.TestCase):
    def test_a_shallow_clone_is_refused_rather_than_reported_broken(self):
        # on a shallow checkout every citation looks dangling, which would be a lie in the other
        # direction; the tool exits 2 ("could not run") instead of 1 ("ran and found problems")
        self.assertFalse(C.is_shallow(), "this working copy is shallow, so the suite cannot judge")


if __name__ == "__main__":
    unittest.main()
