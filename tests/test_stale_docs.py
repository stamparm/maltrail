# coding: utf-8
"""Documentation and comments must describe the repository that exists.

The Python sensor (`sensor.py`), its parity harness and its helpers were removed, and the docs kept
describing them for months: `sensor/docs/COMPATIBILITY.md` opened with "Reference implementation:
sensor.py", the install guide called it "the fallback", and over two hundred comments explained the
Rust code by pointing at Python nobody could open any more. Each of those reads as authoritative and
is wrong, so nothing flagged them.

Two checks, both directions:

* every removed artifact below is really gone (the positive control - a list of things that still
  exist would make the second half meaningless), and no tracked file except the CHANGELOG names it;
* every relative Markdown link, and every backticked path into a top-level directory, resolves.
"""

import os
import re
import subprocess
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Removed artifacts: (pattern that names it, paths that must not exist).
REMOVED = (
    (r"\bsensor\.py\b", ("sensor.py", "old/sensor.py")),
    (r"(?i)\bpython sensor\b", ("sensor.py",)),
    (r"\bpcapy\b", ()),
    (r"\bfastfilter\b", ("core/fastfilter.py",)),
    (r"\bparity\.py\b", ("sensor/tools/parity.py", "tools/parity.py")),
    (r"\bshadow_(?:run|diff)\b", ("sensor/tools/shadow_run.sh", "sensor/tools/shadow_diff.py")),
    (r"\bbench_compare\b", ("sensor/tools/bench_compare.py",)),
    (r"\bcore/parallel\.py\b", ("core/parallel.py",)),
    (r"\bPORTING_MAP\b", ("sensor/docs/PORTING_MAP.md",)),
    (r"\bROADMAP\.md\b", ("sensor/docs/ROADMAP.md",)),
    (r"\bREPORT\.md\b", ("sensor/docs/REPORT.md",)),
    (r"\bCOMPATIBILITY\.md\b", ("sensor/docs/COMPATIBILITY.md",)),
)

# History is allowed to name what it removed; this file has to.
EXEMPT = ("CHANGELOG", "tests/test_stale_docs.py")
# Third-party content: indicator lists and feed data, not prose about this repository.
EXEMPT_DIRS = ("trails/", "data/", "misc/")
SKIP_WALK = {".git", "target", "__pycache__", "node_modules", ".venv", "venv"}
TEXT_EXT = (".py", ".rs", ".md", ".sh", ".ps1", ".yml", ".yaml", ".toml", ".conf", ".service", ".js",
            ".html", ".css", ".txt", ".json", ".cfg", ".ini", "Dockerfile", "CHANGELOG")

# Top-level directories a backticked path in prose is expected to point into.
REPO_DIRS = ("sensor/", "core/", "docs/", "tests/", "packaging/", "docker/", "html/", ".github/",
             "integrations/", "feeds/")


def tracked_files():
    """Tracked files when git is there (it is not in the Python 3.6 CI image); otherwise a walk."""
    try:
        out = subprocess.check_output(["git", "ls-files"], cwd=ROOT, stderr=subprocess.DEVNULL)
        return [_ for _ in out.decode("utf-8").splitlines() if os.path.isfile(os.path.join(ROOT, _))]
    except (OSError, subprocess.CalledProcessError):
        found = []
        for dirpath, dirnames, filenames in os.walk(ROOT):
            dirnames[:] = [_ for _ in dirnames if _ not in SKIP_WALK]
            for name in filenames:
                found.append(os.path.relpath(os.path.join(dirpath, name), ROOT).replace(os.sep, "/"))
        return found


def read_text(path):
    try:
        with open(os.path.join(ROOT, path), "rb") as f:
            return f.read().decode("utf-8")
    except (OSError, UnicodeDecodeError):
        return None


class RemovedArtifactsTest(unittest.TestCase):
    def test_removed_artifacts_are_really_gone(self):
        for _, paths in REMOVED:
            for path in paths:
                self.assertFalse(os.path.exists(os.path.join(ROOT, path)),
                                 "%s exists again; drop it from REMOVED or remove it" % path)

    def test_nothing_names_a_removed_artifact(self):
        patterns = [(re.compile(p), p) for p, _ in REMOVED]
        hits = []
        for path in tracked_files():
            if path in EXEMPT or path.startswith(EXEMPT_DIRS) or not path.endswith(TEXT_EXT):
                continue
            text = read_text(path)
            if text is None:
                continue
            for number, line in enumerate(text.splitlines(), 1):
                for regex, source in patterns:
                    if regex.search(line):
                        hits.append("%s:%d: %s" % (path, number, line.strip()[:120]))
                        break
        self.assertEqual(hits, [], "describe the code that exists, not what it replaced:\n" + "\n".join(hits))

    def test_the_check_can_fail(self):
        regex = re.compile(REMOVED[0][0])
        self.assertTrue(regex.search("a port of `sensor.py:_process_packet()`"))
        self.assertFalse(regex.search("the sensor binary"))


LINK = re.compile(r"\]\(([^)\s]+)\)")
BACKTICK = re.compile(r"`([^`\s]+)`")


# Build output a document may legitimately name: it exists after a build, never in a checkout.
BUILD_OUTPUT = ("sensor/target/",)

_KNOWN = []


def known_paths():
    """Tracked files and their directories. Checked against these rather than the disk, so a stale
    build or a scratch file on a developer's machine cannot make a dead reference look alive - the
    check has to give the same answer locally and on a fresh CI checkout."""
    if not _KNOWN:
        found = set()
        for name in tracked_files():
            found.add(name)
            directory = os.path.dirname(name)
            while directory:
                found.add(directory)
                directory = os.path.dirname(directory)
        _KNOWN.append(found)
    return _KNOWN[0]


def resolves(path, target):
    """A path in a document may be written from the repository root, from the document's own
    directory, or from any directory above it (`sensor/docs/X.md` citing `tests/trails.rs` means
    `sensor/tests/trails.rs`)."""
    if target.startswith(BUILD_OUTPUT):
        return True
    known = known_paths()
    directory = os.path.dirname(path)
    while True:
        candidate = os.path.normpath(os.path.join(directory, target)).replace(os.sep, "/").rstrip("/")
        if candidate in known:
            return True
        if not directory:
            return False
        directory = os.path.dirname(directory)


def markdown_problems(path, text):
    problems = []
    in_fence = False
    for number, line in enumerate(text.splitlines(), 1):
        if line.lstrip().startswith("```"):
            in_fence = not in_fence
            continue
        if in_fence:
            continue
        for target in LINK.findall(line):
            target = target.split("#", 1)[0]
            if not target or re.match(r"^[a-z][a-z0-9+.-]*:", target) or target.startswith("/"):
                continue
            if not resolves(path, target):
                problems.append("%s:%d: link to %s" % (path, number, target))
        for token in BACKTICK.findall(line):
            token = token.rstrip(".,;:)")
            if not token.startswith(REPO_DIRS) or any(_ in token for _ in "*<>${}|"):
                continue
            candidate = token.split("::", 1)[0].split(":", 1)[0]
            if not resolves(path, candidate):
                problems.append("%s:%d: `%s`" % (path, number, token))
    return problems


class MarkdownPathsTest(unittest.TestCase):
    def test_every_markdown_path_exists(self):
        problems = []
        for path in tracked_files():
            if path.endswith(".md") and not path.startswith(EXEMPT_DIRS):
                text = read_text(path)
                if text is not None:
                    problems.extend(markdown_problems(path, text))
        self.assertEqual(problems, [], "dead paths in the documentation:\n" + "\n".join(problems))

    def test_a_dead_path_is_reported(self):
        text = "see [the map](docs/NOWHERE.md) and `sensor/src/nowhere.rs`, but `sensor/README.md` is fine"
        found = markdown_problems("README.md", text)
        self.assertEqual(len(found), 2, found)
        # relative to the document's directory and its parents, and `file::test` names
        text = "`docs/INSTALL.md`, `tests/trails.rs::some_test` and `tests/nope.rs`"
        found = markdown_problems("sensor/docs/ARCHITECTURE.md", text)
        self.assertEqual(found, ["sensor/docs/ARCHITECTURE.md:1: `tests/nope.rs`"])


if __name__ == "__main__":
    unittest.main()
