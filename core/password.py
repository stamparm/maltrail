#!/usr/bin/env python3
# coding: utf-8
"""
The password field of a USERS entry, and the login proof checked against it.

A USERS entry used to store sha256(password), and logging in proved knowledge of exactly that:
the browser sent sha256(sha256(password) + nonce). So the stored value WAS the password - anyone
who could read maltrail.conf (a backup, a config-management repository, a support bundle) could
log in with it, without ever learning the password.

The scheme here is SCRAM's (RFC 5802), keyed on the same sha256(password) the browser already
computes:

    salted     = PBKDF2-HMAC-SHA256(sha256hex(password), salt, iterations)
    client_key = HMAC(salted, "Client Key")
    stored_key = SHA256(client_key)                      <- what maltrail.conf holds

    proof      = client_key XOR HMAC(stored_key, "<username>:<nonce>")

The server recovers client_key from the proof and checks that it hashes to stored_key. Knowing
stored_key is not enough to produce a proof - that takes client_key, which only the password
gives - and a proof seen on the wire is bound to its single-use nonce. Entries are written as

    pbkdf2-sha256$<iterations>$<salt hex>$<stored_key hex>

Run as a script it reads a password (prompted, or from stdin) and prints that field.
Deliberately stdlib-only and import-free of the rest of core/, so install.sh can run it alone.
"""

import binascii
import getpass
import hashlib
import hmac
import os
import sys

SCHEME = "pbkdf2-sha256"

# The browser computes PBKDF2 in plain JavaScript (an http:// page has no SubtleCrypto), so this is
# set by what a phone can do in well under a second, not by what a server could afford.
ITERATIONS = 50000

# An unknown user is answered with parameters too, derived from this, so the answer does not say
# which usernames exist.
_DECOY_KEY = os.urandom(32)


def legacy_hash(password):
    """The old stored form, sha256(password) in hex - and the input to the new one."""

    return hashlib.sha256(password.encode("utf8")).hexdigest()


def _stored_key(legacy, salt, iterations):
    salted = hashlib.pbkdf2_hmac("sha256", legacy.encode("utf8"), salt, iterations)
    client_key = hmac.new(salted, b"Client Key", hashlib.sha256).digest()
    return hashlib.sha256(client_key).digest()


def make(password, iterations=ITERATIONS, salt=None):
    """The USERS password field for `password`."""

    salt = salt if salt is not None else os.urandom(16)
    stored = _stored_key(legacy_hash(password), salt, iterations)
    return "%s$%d$%s$%s" % (SCHEME, iterations, binascii.hexlify(salt).decode(), binascii.hexlify(stored).decode())


def parse(field):
    """(iterations, salt, stored_key) of a field in this scheme, or None for anything else."""

    parts = (field or "").strip().split("$")
    if len(parts) != 4 or parts[0] != SCHEME:
        return None
    try:
        iterations = int(parts[1])
        salt = binascii.unhexlify(parts[2])
        stored = binascii.unhexlify(parts[3])
    except (ValueError, TypeError, binascii.Error):
        return None
    if not 1 <= iterations <= 10000000 or not salt or len(stored) != 32:
        return None
    return iterations, salt, stored


def _decoy_salt(username):
    return hmac.new(_DECOY_KEY, (username or "").encode("utf8"), hashlib.sha256).digest()[:16]


_derived = {}


def _resolve(field, username):
    """parse(), plus an entry still in the old sha256(password) form turned into the same scheme.

    That digest is exactly the PBKDF2 input, so the server can derive a stored key from it - with
    the decoy salt, so the parameters it hands out are the ones an unknown user would get. It used
    to flag such entries `legacy` instead, so the browser would send the old digest, and the flag
    alone told anyone which usernames existed with an old entry.
    """

    parsed = parse(field)
    legacy = (field or "").strip().lower()
    if parsed is None and len(legacy) == 64 and all(_ in "0123456789abcdef" for _ in legacy):
        key = (legacy, username)
        if key not in _derived:
            if len(_derived) > 256:     # USERS is a handful of lines; this only bounds junk usernames
                _derived.clear()
            salt = _decoy_salt(username)
            _derived[key] = (ITERATIONS, salt, _stored_key(legacy, salt, ITERATIONS))
        parsed = _derived[key]
    return parsed


def parameters(field, username):
    """What the browser needs before it can compute a proof: {"iterations", "salt"}.

    An unknown user gets decoy parameters, stable per username, so the answer does not say which
    usernames exist; so does an entry in the old form (see _resolve).
    """

    parsed = _resolve(field, username)
    if parsed is None:
        return {"iterations": ITERATIONS, "salt": binascii.hexlify(_decoy_salt(username)).decode()}
    return {"iterations": parsed[0], "salt": binascii.hexlify(parsed[1]).decode()}


def verify(field, username, nonce, proof):
    """Does `proof` (hex) show knowledge of the password behind `field`, for this username and nonce?"""

    parsed = _resolve(field, username)
    if parsed is None:
        return False
    try:
        proof = bytearray(binascii.unhexlify(proof or ""))
    except (ValueError, TypeError, binascii.Error):
        return False
    if len(proof) != 32:
        return False
    stored = parsed[2]
    signature = hmac.new(stored, ("%s:%s" % (username, nonce)).encode("utf8"), hashlib.sha256).digest()
    client_key = bytes(bytearray(a ^ b for a, b in zip(proof, bytearray(signature))))
    return hmac.compare_digest(hashlib.sha256(client_key).digest(), stored)


def proof_for(password, field, username, nonce):
    """The proof a browser sends; for tests and scripted logins."""

    iterations, salt, _ = parse(field)
    salted = hashlib.pbkdf2_hmac("sha256", legacy_hash(password).encode("utf8"), salt, iterations)
    client_key = hmac.new(salted, b"Client Key", hashlib.sha256).digest()
    signature = hmac.new(hashlib.sha256(client_key).digest(), ("%s:%s" % (username, nonce)).encode("utf8"), hashlib.sha256).digest()
    return binascii.hexlify(bytes(bytearray(a ^ b for a, b in zip(bytearray(client_key), bytearray(signature))))).decode()


def is_password(field, password):
    """Is `field` - in either form - the password `password`?"""

    parsed = parse(field)
    if parsed is None:
        return hmac.compare_digest((field or "").strip().lower(), legacy_hash(password))
    iterations, salt, stored = parsed
    return hmac.compare_digest(_stored_key(legacy_hash(password), salt, iterations), stored)


def main():
    if sys.stdin.isatty():
        password = getpass.getpass("Password: ")
        if password != getpass.getpass("Again: "):
            sys.exit("[!] the passwords differ")
    else:
        password = sys.stdin.readline().rstrip("\r\n")
    if not password:
        sys.exit("[!] an empty password")
    print(make(password))
    return 0


if __name__ == "__main__":
    main()
