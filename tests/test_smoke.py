# coding: utf-8
"""Unit tests for `server.py --smoke-test` (core.testing.smoke_test) and for the top-level error handler
that hid its failure.

The smoke test compiled each source file with py_compile, which WRITES the .pyc and ignores
sys.dont_write_bytecode. So it required a writable source tree - and on a tree where an earlier `sudo` run
had left a root-owned __pycache__ it raised PermissionError. server.py caught that under `except IOError`
(an alias of OSError) as "session abruptly terminated", which only ever goes to the log file: the operator
saw NO output at all and exit 1.

Both halves are asserted: the sweep must not write into the tree, and a non-EPIPE OSError out of main()
must print a diagnostic rather than vanish."""

import os
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.dont_write_bytecode = True                       # as server.py does, before anything is imported

from core import testing as T


# Directories holding GENERATED, machine-local state, pruned from the snapshot below. They are
# the gitignored ones - a build tree, the cargo-fuzz corpus/artifacts - plus tool caches.
#
# Not an optimisation for its own sake. The snapshot used to walk the whole repository, which is
# 16,193 files here of which 15,520 are `sensor/target` and the fuzz corpus, so ANY concurrent
# writer in the tree appeared as a file "created by smoke_test()". With `cargo fuzz run` going in
# another terminal this file's guard failed 2 runs in 3; a plain `cargo build` does the same.
# A coverage-guided corpus is SUPPOSED to persist and grow between runs, so it cannot be moved
# to a temporary directory to dodge this - the snapshot is what had to become precise.
#
# Paths, not basenames: `sensor/tests/corpus` is tracked content and must still be watched.
_GENERATED = (
    ".git",
    os.path.join("sensor", "target"),
    os.path.join("sensor", "fuzz", "target"),
    os.path.join("sensor", "fuzz", "corpus"),
    os.path.join("sensor", "fuzz", "artifacts"),
    # tool state with live writers of its own - .codegraph runs a file watcher
    ".codegraph",
    ".pytest_cache",
    ".ruff_cache",
)


def _tree_snapshot():
    seen = {}
    for base, dirs, files in os.walk(ROOT):
        rel = os.path.relpath(base, ROOT)
        if rel == ".":
            rel = ""
        # prune in place so os.walk never descends into them
        dirs[:] = [d for d in dirs
                   if os.path.join(rel, d) not in _GENERATED and d != "__pycache__"]
        if rel in _GENERATED:
            continue
        for name in files:
            path = os.path.join(base, name)
            try:
                seen[path] = os.path.getmtime(path)
            except OSError:
                pass
    return seen


class SmokeTest(unittest.TestCase):
    def test_it_passes_on_the_shipped_tree(self):
        import contextlib
        import io
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            result = T.smoke_test()
        out = buf.getvalue()
        self.assertTrue(result, out)
        self.assertIn("smoke test final result: PASSED", out)
        # a sweep that compiled nothing would also print PASSED, so pin the volume
        count = int(out.split("compiled ")[1].split(" source")[0])
        self.assertGreater(count, 100, out)

    def test_it_writes_nothing_into_the_source_tree(self):
        import contextlib
        import io
        before = _tree_snapshot()
        with contextlib.redirect_stdout(io.StringIO()):
            T.smoke_test()
        after = _tree_snapshot()
        created = sorted(set(after) - set(before))
        self.assertEqual(created, [], "smoke test created %d file(s), e.g. %s" % (len(created), created[:3]))

    def test_the_snapshot_ignores_generated_trees_but_not_tracked_ones(self):
        """The guard above must watch the SOURCE tree and nothing else.

        It used to walk the whole repository - 16,193 files here, of which 15,520 are
        `sensor/target` and the cargo-fuzz corpus. Any concurrent writer therefore looked like a
        file smoke_test() had created: with `cargo fuzz run` going in another terminal this test
        failed 2 runs in 3, and a plain `cargo build` does the same. A coverage-guided corpus is
        meant to persist and grow between runs, so the snapshot is what had to become precise.
        """
        snapshot = _tree_snapshot()
        self.assertTrue(snapshot, "the snapshot must still see the source tree")

        for generated in ("sensor%starget" % os.sep, "fuzz%scorpus" % os.sep,
                          "fuzz%sartifacts" % os.sep, ".codegraph", "__pycache__"):
            offenders = [p for p in snapshot if generated in p]
            self.assertEqual(offenders, [],
                             "%s is generated, machine-local and written by other processes; "
                             "watching it makes this file's guard fail for unrelated reasons "
                             "(e.g. %s)" % (generated, offenders[:1]))

        # ... and the tracked corpus of replay pcaps is NOT generated: it must stay watched
        tracked = [p for p in snapshot if "sensor%stests%scorpus" % (os.sep, os.sep) in p]
        self.assertTrue(tracked,
                        "sensor/tests/corpus is tracked content - pruning by basename instead of "
                        "by path would stop the guard watching it")

    def test_a_syntax_error_is_reported_and_does_not_abort_the_sweep(self):
        import contextlib
        import io
        tmp = tempfile.mkdtemp()
        bad = os.path.join(tmp, "broken.py")
        good = os.path.join(tmp, "fine.py")
        with open(bad, "w") as f:
            f.write("def (:\n")
        with open(good, "w") as f:
            f.write("x = 1\n")
        saved = T._iter_py_files
        T._iter_py_files = lambda: iter([bad, good])
        try:
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                result = T.smoke_test()
            out = buf.getvalue()
        finally:
            T._iter_py_files = saved
        self.assertFalse(result)
        self.assertIn("failed compiling", out)
        self.assertIn("compiled 1 source file(s)", out)   # the good one still counted

    def test_an_unreadable_file_is_reported_not_raised(self):
        import contextlib
        import io
        saved = T._iter_py_files
        T._iter_py_files = lambda: iter([os.path.join(ROOT, "does-not-exist-xyzzy.py")])
        try:
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                result = T.smoke_test()
            out = buf.getvalue()
        finally:
            T._iter_py_files = saved
        self.assertFalse(result)
        self.assertIn("could not read", out)


class ErrorHandlerTest(unittest.TestCase):
    """server.py's __main__ handler, driven by replacing main() with one that raises a chosen error."""

    HARNESS = """
import sys, errno, types
sys.argv = ["server.py"]
sys.path.insert(0, %r)
src = open(%r).read().replace("        main()", "        raise %s")
mod = types.ModuleType("__main__")
exec(compile(src, "server.py", "exec"), mod.__dict__)
"""

    def _run(self, raiser):
        code = self.HARNESS % (ROOT, os.path.join(ROOT, "server.py"), raiser)
        process = subprocess.Popen([sys.executable, "-c", code], stdout=subprocess.PIPE,
                                   stderr=subprocess.STDOUT, cwd=ROOT)
        out = process.communicate()[0].decode("utf8", "replace")
        return process.returncode, out

    def test_a_permission_error_is_printed_not_swallowed(self):
        code, out = self._run("PermissionError(errno.EACCES, 'denied', '/x')")
        self.assertEqual(code, 1)
        self.assertIn("unhandled exception occurred", out)

    def test_a_broken_pipe_stays_quiet(self):
        # stdout is gone by definition, so this one is deliberately silent
        code, out = self._run("BrokenPipeError(errno.EPIPE, 'broken pipe')")
        self.assertEqual(code, 1)
        self.assertNotIn("unhandled exception occurred", out)

    def test_a_non_oserror_still_reaches_the_generic_handler(self):
        code, out = self._run("ValueError('boom')")
        self.assertEqual(code, 1)
        self.assertIn("unhandled exception occurred", out)


if __name__ == "__main__":
    unittest.main()
