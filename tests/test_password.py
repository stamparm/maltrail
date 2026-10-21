# coding: utf-8
"""core/password.py: the USERS password field and the login proof. Pure stdlib, no server.

The browser half lives in html/js/main.js (loginProof); it is run under node, when there is one,
against the same pinned vector."""
import binascii
import os
import shutil
import subprocess
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from core import password as P

SALT = binascii.unhexlify("00112233445566778899aabbccddeeff")


class TestPassword(unittest.TestCase):
    def setUp(self):
        self.field = P.make("s3cret", iterations=1000, salt=SALT)

    def test_a_proof_verifies_only_for_its_password_user_and_nonce(self):
        proof = P.proof_for("s3cret", self.field, "admin", "n1")
        self.assertTrue(P.verify(self.field, "admin", "n1", proof))
        self.assertFalse(P.verify(self.field, "admin", "n1", P.proof_for("s3crex", self.field, "admin", "n1")))
        self.assertFalse(P.verify(self.field, "admin", "n2", proof), "a proof is bound to its nonce")
        self.assertFalse(P.verify(self.field, "root", "n1", proof), "and to its username")

    def test_the_stored_field_is_not_a_password(self):
        # what the old sha256 form got wrong: knowing the stored value must not produce a proof
        iterations, salt, stored = P.parse(self.field)
        forged = binascii.hexlify(stored).decode()
        self.assertFalse(P.verify(self.field, "admin", "n1", forged))
        self.assertFalse(P.verify(self.field, "admin", "n1", P.proof_for(self.field, self.field, "admin", "n1")))

    def test_the_field_is_the_published_vector(self):
        # pinned, so main.js and this file cannot drift apart unnoticed
        self.assertEqual(P.proof_for("s3cret", P.make("s3cret", 1000, SALT), "admin", "abcd"),
                         "4043b51417a1a9bf11d9224efe529de98fc78cccb2df8976621400258cb3f3b6")

    def test_the_browser_computes_the_same_proof(self):
        node = shutil.which("node")
        if not node:
            self.skipTest("no node")
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        with open(os.path.join(root, "html", "js", "main.js")) as f:
            src = f.read()
        block = src[src.index("  // ---- SHA-256, HMAC and PBKDF2"):src.index("  function showLogin()")]
        script = block + 'console.log(loginProof("admin", "s3cret", {salt: "00112233445566778899aabbccddeeff", iterations: 1000, nonce: "abcd"}));'
        out = subprocess.check_output([node, "-e", script]).decode().strip()
        self.assertEqual(out, P.proof_for("s3cret", P.make("s3cret", 1000, SALT), "admin", "abcd"))

    def test_garbage_never_verifies_and_never_raises(self):
        for field in ("", None, "9ab3cd9d67bf49d01f6a2e33d0bd9bc804ddbe6ce1ff5d219c42624851db5dbc", "pbkdf2-sha256$x$00$00",
                      "pbkdf2-sha256$0$00$" + "00" * 32, "pbkdf2-sha256$1000$$" + "00" * 32, "$pbkdf2-sha256$29000$aa$bb"):
            self.assertIsNone(P.parse(field), field)
            self.assertFalse(P.verify(field, "admin", "n1", "00" * 32))
        for proof in ("", None, "zz", "00" * 31, "00" * 33):
            self.assertFalse(P.verify(self.field, "admin", "n1", proof))

    def test_is_password_reads_both_forms(self):
        self.assertTrue(P.is_password(self.field, "s3cret"))
        self.assertFalse(P.is_password(self.field, "nope"))
        self.assertTrue(P.is_password(P.legacy_hash("changeme!"), "changeme!"))

    def test_parameters_flag_only_the_old_form(self):
        self.assertEqual(P.parameters(self.field, "admin"), {"iterations": 1000, "salt": "00112233445566778899aabbccddeeff"})
        self.assertTrue(P.parameters(P.legacy_hash("x"), "admin")["legacy"])
        self.assertNotIn("legacy", P.parameters(None, "ghost"))

    def test_the_shipped_configuration_is_salted(self):
        with open(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "maltrail.conf")) as f:
            admin = [_ for _ in f.read().split("\n") if _.strip().startswith("admin:")][0]
        field = admin.split()[0].split(":")[1]
        self.assertIsNotNone(P.parse(field))
        self.assertTrue(P.is_password(field, "changeme!"))


if __name__ == "__main__":
    unittest.main()
