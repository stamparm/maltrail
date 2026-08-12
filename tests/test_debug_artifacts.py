# coding: utf-8
"""Debug leftovers must not ship, and the shipped maltrail.conf must be the SAFE default.

These checks are not new. They lived in `.github/precommit-hook`, which nothing installed and
nothing referenced, so they had never run - and its second half was Python 2 (`print sys.argv[1]`)
that would have failed on any supported interpreter, plus a VERSION auto-increment that fought the
release discipline `sensor/tools/check_version.py` enforces. The hook is gone; the parts of it that
were still worth having are here, where CI actually runs them.

What each one is about:

  * `debugger;` in served JS halts the dashboard in any browser with devtools open.
  * `console.log` outside the vendored bundle is a debug leftover, and on this frontend it can
    print event data - source addresses, trails - into a place nobody is auditing.
  * `pdb.set_trace()` in the server would hang the request thread that reached it, forever.
  * `SHOW_DEBUG true` in the shipped config sends tracebacks to operators by default.
  * `USE_FEED_UPDATES false` in the shipped config means a fresh install silently stops pulling
    the public feeds - the "installs cleanly, detects less than you think" failure again.
"""
import os
import re
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# The vendored bundle is third-party and not ours to edit.
VENDORED = ("thirdparty.min.js",)

# Directories with no bearing on what ships.
SKIP_DIRS = {".git", "target", "node_modules", "__pycache__", "trails", "misc", "old"}


def _walk(root, suffix):
    for base, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for name in files:
            if name.endswith(suffix):
                yield os.path.join(base, name)


def _read(path):
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        return f.read()


class TestNoDebugArtifacts(unittest.TestCase):
    def _hits(self, paths, pattern):
        found = []
        for path in paths:
            for number, line in enumerate(_read(path).splitlines(), 1):
                if re.search(pattern, line):
                    found.append("%s:%d" % (os.path.relpath(path, REPO), number))
        return found

    def test_no_js_debugger_statement(self):
        js = list(_walk(os.path.join(REPO, "html"), ".js"))
        self.assertTrue(js, "no JavaScript found - the walk is looking in the wrong place")
        self.assertEqual(self._hits(js, r"^\s*debugger\s*;"), [], "`debugger;` would halt the dashboard")

    def test_no_console_log_outside_the_vendored_bundle(self):
        js = [p for p in _walk(os.path.join(REPO, "html"), ".js") if os.path.basename(p) not in VENDORED]
        self.assertTrue(js, "no first-party JavaScript found - the walk is looking in the wrong place")
        self.assertEqual(self._hits(js, r"\bconsole\.log\s*\("), [], "console.log is a debug leftover")

    def test_no_pdb_breakpoints_in_the_server(self):
        py = [p for p in _walk(REPO, ".py") if os.sep + "tests" + os.sep not in p]
        self.assertTrue(py, "no Python found - the walk is looking in the wrong place")
        self.assertEqual(self._hits(py, r"\b(pdb\.set_trace|breakpoint)\s*\("), [],
                         "a breakpoint would hang the request thread that reached it")

    def test_shipped_config_keeps_the_safe_defaults(self):
        conf = _read(os.path.join(REPO, "maltrail.conf"))
        self.assertIsNone(re.search(r"^\s*SHOW_DEBUG\s+true", conf, re.M | re.I),
                          "the shipped config must not send tracebacks to operators by default")
        self.assertIsNone(re.search(r"^\s*USE_FEED_UPDATES\s+false", conf, re.M | re.I),
                          "the shipped config must not disable public feed updates")
        # positive control: the options are actually present, so the assertions above mean something
        self.assertIsNotNone(re.search(r"^\s*SHOW_DEBUG\s+\S+", conf, re.M),
                             "SHOW_DEBUG is missing from maltrail.conf")
        self.assertIsNotNone(re.search(r"^\s*USE_FEED_UPDATES\s+\S+", conf, re.M),
                             "USE_FEED_UPDATES is missing from maltrail.conf")


if __name__ == "__main__":
    unittest.main()
