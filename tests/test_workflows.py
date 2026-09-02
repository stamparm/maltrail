# coding: utf-8
"""Properties of the CI workflows that are load-bearing rather than cosmetic.

`.github/workflows/regenerate.yml` is allowed to commit to the repository, which makes it the one
piece of automation here whose blast radius is worth pinning down in a test. It regenerates
`sensor/src/settings_gen.rs` when an input changes and opens a pull request, because the person who
usually makes those inputs disagree is editing `data/ua.txt` through the web UI and cannot run the
generator at all.

Two things must stay true of it, and neither is visible from reading a green build:

  * it can only ever change the generated file, and
  * it did not replace the gate that fails when the mirror is stale.

The second matters most. A bot that quietly makes a failing check pass is worse than the failure it
was written to fix, so the gate has to remain, and this asserts it does.
"""

import os
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WORKFLOWS = os.path.join(ROOT, ".github", "workflows")


def _read(name):
    with open(os.path.join(WORKFLOWS, name), encoding="utf-8") as f:
        return f.read()


class TestRegenerateWorkflow(unittest.TestCase):
    def setUp(self):
        self.path = os.path.join(WORKFLOWS, "regenerate.yml")
        if not os.path.isfile(self.path):
            self.skipTest("regenerate.yml is not present")
        self.text = _read("regenerate.yml")

    def test_it_parses(self):
        try:
            import yaml
        except ImportError:
            self.skipTest("needs PyYAML to parse the workflow")
        doc = yaml.safe_load(self.text)
        self.assertIn("regenerate", doc["jobs"], "the regenerate job is gone")

    def test_it_refuses_to_change_anything_but_the_generated_file(self):
        # The guard is the reason this automation is safe to grant contents: write. Without it, a
        # generator that started emitting something else would commit it unreviewed.
        self.assertIn('!= "sensor/src/settings_gen.rs"', self.text,
                      "the one-file guard is gone: regenerate.yml could commit files nobody "
                      "reviewed. It must fail when regeneration touches anything else.")

    def test_it_does_not_write_to_master(self):
        # The fix arrives as a pull request a person merges. A job that pushes to master would be
        # committing unreviewed content to the branch every release is cut from.
        self.assertNotIn("push origin master", self.text)
        self.assertNotIn("push origin HEAD:master", self.text)
        self.assertIn("bot/regenerate-settings-gen", self.text,
                      "the workflow no longer pushes to a dedicated branch")

    def test_it_verifies_what_it_proposes(self):
        # A pull request opened with GITHUB_TOKEN gets no checks of its own, so the job has to run
        # them. If these go, the PR is genuinely unverified rather than just looking that way.
        for command in ("gen_settings.py --check", "cargo fmt", "--test generated"):
            self.assertIn(command, self.text,
                          "regenerate.yml no longer runs %r before opening a PR, and a PR opened "
                          "by GITHUB_TOKEN triggers no workflows - nothing would check it at all"
                          % command)


class TestTheStalenessGateSurvives(unittest.TestCase):
    """The bot must not become the reason the check went away."""

    def test_ci_still_fails_on_a_stale_mirror(self):
        text = _read("ci.yml")
        self.assertIn("gen_settings.py --check", text,
                      "ci.yml no longer fails when settings_gen.rs is stale. The regeneration "
                      "workflow shortens the time to a fix; it is not a substitute for noticing "
                      "that master is inconsistent.")

if __name__ == "__main__":
    unittest.main()
