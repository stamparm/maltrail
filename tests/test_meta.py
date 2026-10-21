# coding: utf-8
"""Unit tests for core/meta.py, the READ side of the condensed observable store (LOG_DIR/meta.sqlite).
The sensor writes and prunes the store (sensor/src/meta.rs, tested in sensor/tests/meta.rs, which
also checks the schema against this reader); these lock what the server reads back: key packing
(v4/v6/domain), the kind/scope decoding, and the read-only open. Pure stdlib, no network."""
import os
import sqlite3
import stat
import sys
import shutil
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from core import meta as M


def write_store(path, rows):
    """A store shaped exactly like the sensor writes it: rows of (observable, flags, first, last, count)."""
    con = sqlite3.connect(path)
    con.execute("PRAGMA journal_mode=DELETE")
    con.execute("CREATE TABLE observables (observable, flags INTEGER, first_seen INTEGER, last_seen INTEGER, count INTEGER, PRIMARY KEY(observable)) WITHOUT ROWID")
    con.execute("CREATE TABLE meta_info (key TEXT PRIMARY KEY, value)")
    con.execute("INSERT INTO meta_info (key, value) VALUES ('schema_version', 1)")
    for observable, flags, first_seen, last_seen, count in rows:
        key = observable if flags & M.FLAG_DNS else M._pack_lookup(observable)[0]
        con.execute("INSERT INTO observables VALUES (?, ?, ?, ?, ?)", (key, flags, first_seen, last_seen, count))
    con.commit()
    con.close()


class MetaTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.db = os.path.join(self.tmp, "meta.sqlite")
        M.configure(self.db)

    def tearDown(self):
        M.configure(None)
        shutil.rmtree(self.tmp, ignore_errors=True)


class TestPackLookup(MetaTestCase):
    def test_addresses_pack_to_blobs_and_names_stay_text(self):
        self.assertEqual(M._pack_lookup("1.2.3.4"), (sqlite3.Binary(b"\x01\x02\x03\x04"), "ip"))
        key, kind = M._pack_lookup("2001:db8::5")
        self.assertEqual((len(bytes(key)), kind), (16, "ip"))
        self.assertEqual(M._pack_lookup("example.org"), ("example.org", "dns"))
        # an all-digit-but-not-4-octet string is NOT a v4 address -> domain
        self.assertEqual(M._pack_lookup("12345")[1], "dns")


class TestLookup(MetaTestCase):
    def setUp(self):
        MetaTestCase.setUp(self)
        local, remote = M.SCOPE_LOCAL << 1, M.SCOPE_REMOTE << 1
        write_store(self.db, [("192.168.0.5", local, 100, 200, 3),
                              ("8.8.8.8", remote, 50, 250, 7),
                              ("2001:db8::1", remote, 10, 20, 1),
                              ("evil.com", M.FLAG_DNS, 1000, 2000, 42)])

    def test_an_address_reads_back_with_its_scope(self):
        self.assertEqual(M.lookup("192.168.0.5"), {"observable": "192.168.0.5", "kind": "ip", "scope": "local",
                                                   "first_seen": 100, "last_seen": 200, "count": 3})
        self.assertEqual(M.lookup("8.8.8.8")["scope"], "remote")
        self.assertEqual(M.lookup("2001:db8::1")["count"], 1)

    def test_a_name_reads_back_as_dns(self):
        row = M.lookup("evil.com")
        self.assertEqual((row["kind"], row["scope"], row["count"]), ("dns", "", 42))

    def test_unknown_and_empty_answer_none(self):
        self.assertIsNone(M.lookup("9.9.9.9"))
        self.assertIsNone(M.lookup("nothing.example"))
        self.assertIsNone(M.lookup(""))

    def test_a_read_only_store_is_still_read(self):
        # The sensor writes it as root and the server reads it as another user: no write access.
        os.chmod(self.db, stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)
        os.chmod(self.tmp, stat.S_IRUSR | stat.S_IXUSR)
        try:
            self.assertEqual(M.lookup("evil.com")["count"], 42)
        finally:
            os.chmod(self.tmp, stat.S_IRWXU)


class TestNoStore(MetaTestCase):
    def test_a_missing_store_answers_none_and_is_not_created(self):
        self.assertIsNone(M.lookup("evil.com"))
        self.assertFalse(os.path.exists(self.db), "a lookup must never create the sensor's store")

    def test_unconfigured_answers_none(self):
        M.configure(None)
        self.assertIsNone(M.lookup("evil.com"))


if __name__ == "__main__":
    unittest.main()
