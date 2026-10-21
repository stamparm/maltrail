# coding: utf-8
"""core/disktrails.DiskTrailsDict: the SQLite-backed store update_trails() merges into when memory is
short. It has to be indistinguishable from the dict it replaces - the post-processing pass renames
keys while it walks them, and which of two colliding keys wins depends on dict insertion order - so
these tests drive both stores with the same operations and demand the same answers, down to the
bytes of the trails.csv each one produces."""
import io
import os
import random
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core import update as U
from core.disktrails import DiskTrailsDict
from core.settings import config
from core.trailsdict import TrailsDict


class DictSemanticsTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.disk = DiskTrailsDict(os.path.join(self.tmp, "build"))

    def tearDown(self):
        self.disk.close()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_random_operations_match_a_dict(self):
        rnd = random.Random(19641)
        ref = {}
        keys = ["k%d.example" % i for i in range(300)]
        pairs = [("info%d" % i, "(ref%d)" % (i % 7)) for i in range(40)]
        for _ in range(20000):
            key = rnd.choice(keys)
            op = rnd.random()
            if op < 0.55:
                value = rnd.choice(pairs)
                ref[key] = value
                self.disk[key] = value
            elif op < 0.8:
                if key in ref:
                    del ref[key]
                    del self.disk[key]
                else:
                    self.assertRaises(KeyError, self.disk.__delitem__, key)
            else:
                self.assertEqual(key in self.disk, key in ref)
                self.assertEqual(self.disk.get(key), ref.get(key))
        self.assertEqual(len(self.disk), len(ref))
        self.assertEqual(list(self.disk.snapshot_keys()), list(ref.keys()), "insertion order must be a dict's")
        self.assertEqual(list(self.disk.items()), list(ref.items()))
        self.assertEqual(list(self.disk.sorted_items()), sorted(ref.items()))

    def test_renaming_while_walking_a_snapshot_matches_a_dict(self):
        # the shape of update_trails()'s post-processing: rewrite keys mid-walk, some onto keys
        # that exist and have not been visited yet
        words = ["Evil.example", "evil.example", "www.Bad.example", "bad.example", "x//y", "x/y", "ok.example"]
        for store in (self.disk,):
            ref = {}
            for i, w in enumerate(words):
                ref[w] = ("info%d" % i, "(static)")
                store[w] = ("info%d" % i, "(static)")
            for target in (ref, store):
                walk = list(target.keys()) if target is ref else target.snapshot_keys()
                for key in walk:
                    if key not in target:
                        continue
                    new = key.lower().replace("www.", "").replace("//", "/")
                    if new != key:
                        value = target[key]
                        del target[key]
                        target[new] = value
            self.assertEqual(list(store.items()), list(ref.items()))

    def test_close_leaves_nothing_behind(self):
        path = os.path.join(self.tmp, "gone")
        store = DiskTrailsDict(path)
        store["a"] = ("b", "c")
        self.assertTrue(os.path.exists(path))
        store.close()
        self.assertFalse(os.path.exists(path))


class UpdateTrailsParityTest(unittest.TestCase):
    """update_trails() must write the same trails.csv whichever store it merges into."""

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
        self._build_store = U._build_store

    def tearDown(self):
        U._build_store = self._build_store
        for key, value in self._saved.items():
            setattr(config, key, value)
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _build(self, factory):
        used = []

        def store():
            used.append(factory())
            return used[-1]

        U._build_store = store
        _so = sys.stdout
        sys.stdout = open(os.devnull, "w")
        try:
            U.update_trails(force=True, offline=True)
        finally:
            sys.stdout.close()
            sys.stdout = _so
        self.assertEqual(len(used), 1, "update_trails() must merge into the store it was given")
        result = []
        for suffix in ("", ".confidence"):
            with open(config.TRAILS_FILE + suffix, "rb") as f:
                result.append(f.read())
        os.remove(config.TRAILS_FILE)
        return result

    def test_disk_and_memory_builds_are_byte_identical(self):
        memory = self._build(TrailsDict)
        disk = self._build(lambda: DiskTrailsDict("%s.build" % config.TRAILS_FILE))
        # positive control: the build really did the renames and drops this fixture is made of
        text = memory[0].decode("utf8")
        self.assertIn("evil.example,", text)
        self.assertNotIn("Evil.example", text)
        self.assertNotIn("www.", text)
        self.assertIn("xn--bcher-phish-", text, "IDN keys go through idna")
        self.assertNotIn("10.0.0.1,", text, "bogons are dropped")
        self.assertIn("1.2.3.4,potential malware site", text)
        # assertTrue, not assertEqual: a byte diff of two trail files sends difflib off for minutes
        self.assertTrue(disk == memory, "the disk-merged trail set differs from the in-memory one")
        self.assertFalse(os.path.exists("%s.build" % config.TRAILS_FILE), "the merge file is removed")

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
