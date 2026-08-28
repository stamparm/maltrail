#!/usr/bin/env python3
# coding: utf-8

"""Every commit this repository cites must still exist.

    python3 sensor/tools/check_refs.py            # report
    python3 sensor/tools/check_refs.py --quiet    # exit status only

The trails split rewrote history with git-filter-repo, which changes every SHA. Nothing noticed:
five citations were left pointing at commits that no longer resolve, and the worst of them was in
SECURITY.md, telling anyone who wanted to check for the private key Maltrail used to ship to run

    git show <a-sha-that-no-longer-exists>^:misc/server.pem

which had answered "fatal: Not a valid object name" for weeks. A dangling SHA in a comment is
untidy; a dangling SHA in a security advisory is a broken instruction handed to somebody trying to
verify their own exposure.

This is deliberately not clever about what "looks like" a citation. It takes every 7-12 character
hex token out of prose and code, and anything that does not resolve to a commit has to be either
fixed or named in NOT_COMMITS below, with a reason. Sample data (data/, tests/canaries*) is skipped
because a detection list is full of hex that means something else.

Requires full history: a shallow CI checkout resolves nothing, so this refuses to run on one rather
than reporting every citation as broken.
"""

import argparse
import io
import os
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

SUFFIXES = (".md", ".py", ".rs", ".sh", ".yml", ".yaml", ".conf", ".toml", ".service")
# Files whose hex means something other than a commit. tests/test_refs.py is here because it is
# THIS tool's test: it is necessarily full of invented SHAs, and exempting each one individually
# would mean the exemption list grows every time a case is added.
SKIP_PREFIXES = ("data/", "tests/canaries", "tests/test_refs.py", "sensor/tests/vectors/", "thirdparty/")

# Hex-shaped tokens that are not commits. Each one has to earn its place here.
NOT_COMMITS = {
    "aaaabbb":   "a user-agent fragment in data/ua.txt, mirrored into settings_gen.rs",
    "abc1234":   "a placeholder string in sensor/src/smallstr.rs's doc example",
    "b20112211": "a user-agent fragment",
    "c010101":   "a user-agent fragment",
    "cceeded":   "a CSS colour in core/httpd.py",
}

TOKEN = re.compile(r"(?<![0-9a-fx_/.-])([0-9a-f]{7,12})(?![0-9a-zA-Z_/.-])")


def tracked_files():
    out = subprocess.check_output(["git", "-C", ROOT, "ls-files"]).decode("utf8", "replace")
    for name in out.split("\n"):
        if name.endswith(SUFFIXES) and not name.startswith(SKIP_PREFIXES):
            yield name


def is_shallow():
    path = subprocess.check_output(["git", "-C", ROOT, "rev-parse", "--git-dir"]).decode().strip()
    return os.path.exists(os.path.join(ROOT, path, "shallow")) or os.path.exists(os.path.join(path, "shallow"))


def resolves(sha):
    try:
        subprocess.check_output(["git", "-C", ROOT, "cat-file", "-e", "%s^{commit}" % sha],
                                stderr=subprocess.STDOUT)
        return True
    except subprocess.CalledProcessError:
        return False


def citations():
    """{token: [where, ...]} for every hex-shaped token in tracked prose and code."""

    found = {}
    for name in tracked_files():
        try:
            text = io.open(os.path.join(ROOT, name), encoding="utf8", errors="replace").read()
        except EnvironmentError:
            continue
        for number, line in enumerate(text.split("\n"), 1):
            for match in TOKEN.finditer(line):
                token = match.group(1)
                if token.isdigit() or not re.search(r"[a-f]", token):
                    continue            # a decimal number, or one that carries no hex letter at all
                found.setdefault(token, []).append("%s:%d" % (name, number))
    return found


def main(argv=None):
    """`argv` is explicit so a caller in a test suite does not get the runner's own arguments."""

    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--quiet", action="store_true", help="exit status only")
    options = parser.parse_args(argv)

    if is_shallow():
        print("[!] this is a shallow clone - every citation would look dangling")
        print("[!] check out with fetch-depth: 0, or run this on a full clone")
        return 2

    found = citations()
    dangling = {}
    for token, where in found.items():
        if token in NOT_COMMITS or resolves(token):
            continue
        dangling[token] = where

    stale_exemptions = [_ for _ in NOT_COMMITS if _ not in found]

    if not options.quiet:
        print("[i] %d hex-shaped token(s) in %d tracked file(s); %d exempt, %d dangling"
              % (len(found), len(list(tracked_files())), len(NOT_COMMITS), len(dangling)))
        for token in sorted(dangling):
            print("\n[!] %s does not resolve to a commit" % token)
            for where in dangling[token][:6]:
                print("      %s" % where)
            if len(dangling[token]) > 6:
                print("      ... and %d more" % (len(dangling[token]) - 6))
        # An exemption for a token nobody writes any more is a lie waiting to cover a real one.
        for token in sorted(stale_exemptions):
            print("[!] NOT_COMMITS carries '%s' but nothing cites it any more - drop it" % token)
        if not dangling and not stale_exemptions:
            print("[i] every cited commit resolves")

    return 1 if (dangling or stale_exemptions) else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
