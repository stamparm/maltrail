# coding: utf-8
"""update_trails()'s two builds: one dict, and the streaming build a small host gets (_StreamBuild:
a bit filter finds the few trails seen more than once, only those are held, the rest streamed). The
post-processing renames keys while it walks them and which of two colliding keys wins depends on
insertion order, so both builds must write the same trails.csv, byte for byte."""
import io
import os
import random
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core import update as U
from core.settings import config


class GroupTest(unittest.TestCase):
    # _StreamBuild streams a trail whose group is seen once. That is only exact if no rename the
    # post-processing makes can take a key into another group - checked here, step by step, with the
    # steps the post-processing really takes: an ASCII key is lower-cased and loses "www.", a
    # "?query" and doubled slashes; a non-ASCII key goes through idna first.
    ASCII_STEPS = (
        lambda k: k.lower(),
        lambda k: k[len("www."):] if k.startswith("www.") and '/' not in k else k,
        lambda k: k.split('?')[0] if '?' in k and not k.startswith('/') else k,
        lambda k: k.replace('//', '/'),
    )

    def test_no_rename_leaves_its_group(self):
        rnd = random.Random(20261030)
        parts = ["www.", "WWW.", "Evil", "evil", ".", "//", "/", "?", "q=1", u"bücher", "x", "1.2.3.4", ":8080", "-", u"ü"]
        checked = idn = 0
        for _ in range(20000):
            key = "".join(rnd.choice(parts) for _ in range(rnd.randint(1, 7)))
            if all(ord(_) < 128 for _ in key):
                for step in self.ASCII_STEPS:
                    renamed = step(key)
                    if renamed and renamed != key:
                        self.assertEqual(U._group(renamed), U._group(key), "%r -> %r left its group" % (key, renamed))
                        checked += 1
            else:
                # held back with every group it can reach: whatever the post-processing turns it
                # into - idna's name, or (when idna refuses it) its own ASCII-style renames - is in one
                try:
                    first = key.encode("idna").decode("ascii")
                except Exception:
                    first = key
                forms = [first] + [step(first) for step in self.ASCII_STEPS]
                for form in forms:
                    if form:
                        self.assertIn(U._group(form), U._idn_groups(key), "%r -> %r reaches a group not held back" % (key, form))
                        idn += 1
        self.assertGreater(checked, 5000, "the generator must produce ASCII renames to check")
        self.assertGreater(idn, 5000, "and non-ASCII ones")


class UpdateTrailsParityTest(unittest.TestCase):
    """update_trails() must write the same trails.csv whichever build it uses."""

    STATIC = (
        u"Evil.example,malware,(static)\n"
        u"evil.example,phishing,(static)\n"
        u"www.both.example,c2,(static)\n"
        u"both.example,c2 (other),(static)\n"
        u"WWW.Upper.example,malware,(static)\n"
        u"query.example/x?y=1,malware,(static)\n"
        u"double//slash.example/a,malware,(static)\n"
        u"\"[0-9]{2,3}\\.ru\",suspicious,(static)\n"
        u"bücher-phish.example,phishing,(static)\n"
        u"1.2.3.4,malware,(static)\n"
        u"203.0.113.9,ransomware,(static)\n"
        u"10.0.0.1,bogon,(static)\n"
        u"plainword,suspicious,(static)\n"
    )

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self._saved = dict((_, getattr(config, _, None)) for _ in ("TRAILS_FILE", "STATIC_TRAILS_URL", "UPDATE_SERVER", "CUSTOM_TRAILS_URL", "offline"))
        config.TRAILS_FILE = os.path.join(self.tmp, "trails.csv")
        config.STATIC_TRAILS_URL = "http://127.0.0.1:9/trails.csv.gz"
        config.UPDATE_SERVER = None
        config.CUSTOM_TRAILS_URL = None
        config.offline = True
        with io.open("%s.static" % config.TRAILS_FILE, "w", encoding="utf8") as f:
            f.write(self.STATIC * 1)
        self._low_memory = U._low_memory
        self._sizes = (U._StreamBuild.FILTER_BITS, U._StreamBuild.BATCH, U._StreamBuild.RUN)

    def tearDown(self):
        U._low_memory = self._low_memory
        U._StreamBuild.FILTER_BITS, U._StreamBuild.BATCH, U._StreamBuild.RUN = self._sizes
        for key, value in self._saved.items():
            setattr(config, key, value)
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _build(self, streamed, sizes=None):
        U._low_memory = lambda: streamed
        if sizes:
            U._StreamBuild.FILTER_BITS, U._StreamBuild.BATCH, U._StreamBuild.RUN = sizes
        _so = sys.stdout
        sys.stdout = open(os.devnull, "w")
        try:
            U.update_trails(force=True, offline=True)
        finally:
            sys.stdout.close()
            sys.stdout = _so
        result = []
        for suffix in ("", ".confidence"):
            with open(config.TRAILS_FILE + suffix, "rb") as f:
                result.append(f.read())
        os.remove(config.TRAILS_FILE)
        leftovers = [_ for _ in os.listdir(self.tmp) if ".build" in _]
        self.assertEqual(leftovers, [], "the build leaves nothing behind")
        return result

    def test_streamed_and_in_memory_builds_are_byte_identical(self):
        memory = self._build(False)
        # positive control: the build really did the renames and drops this fixture is made of
        text = memory[0].decode("utf8")
        self.assertIn("evil.example,", text)
        self.assertNotIn("Evil.example", text)
        self.assertNotIn("www.", text)
        self.assertIn("xn--bcher-phish-", text, "IDN keys go through idna")
        self.assertNotIn("10.0.0.1,", text, "bogons are dropped")
        self.assertIn("1.2.3.4,potential malware site", text)
        # assertTrue, not assertEqual: a byte diff of two trail files sends difflib off for minutes
        self.assertTrue(self._build(True) == memory, "the streamed build differs from the in-memory one")
        # Squeezed: a 64-bit filter calls nearly every group repeated, batches of 2 and score runs
        # of 3 put the streaming, interleaving and external-sort paths under every row.
        self.assertTrue(self._build(True, (64, 2, 3)) == memory, "the squeezed streamed build differs")
        self.assertTrue(self._build(True, (1 << 20, 2, 3)) == memory, "the streamed build with few repeats differs")

    def _update_quietly(self):
        _so = sys.stdout
        sys.stdout = open(os.devnull, "w")
        try:
            U.update_trails(force=True, offline=True)
        finally:
            sys.stdout.close()
            sys.stdout = _so

    def test_a_missing_static_set_does_not_replace_a_working_trails_file(self):
        # No download (offline) and no cache: the build is feeds and custom only. Writing it would
        # turn the full set into a few percent of it, for this host and every sensor pulling here.
        os.remove("%s.static" % config.TRAILS_FILE)
        working = b"kept-by-the-guard.example,malware,(static)\n" * 3
        with open(config.TRAILS_FILE, "wb") as f:
            f.write(working)
        self._update_quietly()
        with open(config.TRAILS_FILE, "rb") as f:
            self.assertEqual(f.read(), working, "a feeds-only build replaced a working trails file")
        self.assertTrue(U.last_refusal, "the refusal was not reported")

        # The control: with no static source configured at all, the operator chose this - build.
        config.STATIC_TRAILS_URL = None
        self._update_quietly()
        with open(config.TRAILS_FILE, "rb") as f:
            self.assertNotEqual(f.read(), working, "with no static source configured the build must still be written")
        self.assertIsNone(U.last_refusal)

    def test_static_trails_stream_with_the_csv_dialect(self):
        static = U._StaticTrails("%s.static" % config.TRAILS_FILE)
        rows = dict(static.items())
        self.assertEqual(rows["[0-9]{2,3}\\.ru"], ("suspicious", "(static)"), "a quoted trail with a comma of its own")
        self.assertEqual(len(rows), self.STATIC.count("\n"))


class AvailableMemoryTest(unittest.TestCase):
    def test_reports_something_on_linux(self):
        if not os.path.isfile("/proc/meminfo"):
            self.skipTest("not Linux")
        available = U._available_memory()
        self.assertIsNotNone(available)
        self.assertGreater(available, 0)


if __name__ == "__main__":
    unittest.main()
