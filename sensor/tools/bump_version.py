#!/usr/bin/env python3
# coding: utf-8

"""Move Maltrail's version, everywhere it is written down.

The version lives in FIVE files, and the monthly release automation edited one of them:

    core/settings.py             VERSION = "3.3"
    sensor/Cargo.toml            version = "3.3.0"     (SemVer: three components)
    sensor/Cargo.lock            the maltrail-sensor package entry - the release builds --locked,
                                 so a stale lock fails the build outright
    CITATION.cff                 version: "3.3"
    sensor/src/settings_gen.rs   pub const VERSION: &str = "3.3";

The last one is generated from the first, so the obvious instinct is to re-run gen_settings.py -
but its raw output is not rustfmt-clean, so that also requires a Rust toolchain, and the machine
that runs the monthly bump is a Raspberry Pi with python3 and nothing else. Editing that single
short line in place keeps the file byte-for-byte formatted, and gen_settings.py --check still
passes, so the bump stays a text edit that any machine can do.

That mismatch is not theoretical: the 3.3 tag was pushed with settings.py at 3.3 and the
generated mirror still at 3.2. The release gate refused it, no binaries were built, and the
failure surfaced only after the tag was public.

    python3 sensor/tools/bump_version.py 3.3      # set an explicit version
    python3 sensor/tools/bump_version.py --next   # bump the minor: 3.2 -> 3.3
    python3 sensor/tools/bump_version.py --check  # verify only, change nothing

Every file must match its expected pattern exactly once, or nothing is written at all: a partial
bump is the state this script exists to prevent.
"""

import argparse
import datetime
import io
import os
import re
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))


def _read(path):
    with io.open(path, encoding="utf8") as f:
        return f.read()


def _edits(version):
    """(path, pattern, replacement) for every place the version is written."""

    cargo = "%s.0" % version                       # Cargo requires three components
    return [
        (os.path.join(ROOT, "core", "settings.py"),
         r'^(VERSION\s*=\s*")[^"]*(")', r'\g<1>%s\g<2>' % version),
        (os.path.join(ROOT, "sensor", "Cargo.toml"),
         r'^(version\s*=\s*")[^"]*(")', r'\g<1>%s\g<2>' % cargo),
        # anchored to the package entry: a bare ^version in a lock file would match every
        # dependency in it
        (os.path.join(ROOT, "sensor", "Cargo.lock"),
         r'(name = "maltrail-sensor"\nversion = ")[^"]*(")', r'\g<1>%s\g<2>' % cargo),
        (os.path.join(ROOT, "CITATION.cff"),
         r'^(version\s*:\s*")[^"]*(")', r'\g<1>%s\g<2>' % version),
        (os.path.join(ROOT, "sensor", "src", "settings_gen.rs"),
         r'^(pub const VERSION: &str = ")[^"]*(";)', r'\g<1>%s\g<2>' % version),
    ]


def current():
    match = re.search(r'^VERSION\s*=\s*"([^"]+)"',
                      _read(os.path.join(ROOT, "core", "settings.py")), re.M)
    if not match:
        raise SystemExit("[!] no VERSION assignment in core/settings.py")
    return match.group(1)


def next_minor(version):
    parts = version.split(".")
    if len(parts) < 2 or not all(p.isdigit() for p in parts[:2]):
        raise SystemExit("[!] cannot bump %r - expected 'major.minor'" % version)
    return "%s.%d" % (parts[0], int(parts[1]) + 1)


def apply(version, date_released=None):
    """Rewrite every file, or none of them."""

    planned = []
    for path, pattern, repl in _edits(version):
        text = _read(path)
        new, n = re.subn(pattern, repl, text, flags=re.M)
        # Exactly once. Zero means the file moved on and this script is now lying about
        # covering it; more than once means the pattern is catching something it should not
        # (a dependency's version key, say) and would corrupt the file.
        if n != 1:
            raise SystemExit("[!] %s: expected exactly 1 version line, matched %d\n"
                             "    Refusing to write ANY file - a half-applied bump is the "
                             "failure this script exists to prevent." % (path, n))
        planned.append((path, new, text != new))

    if date_released:
        path = os.path.join(ROOT, "CITATION.cff")
        for i, (p, new, _) in enumerate(planned):
            if p != path:
                continue
            out, n = re.subn(r'^(date-released\s*:\s*")[^"]*(")',
                             r'\g<1>%s\g<2>' % date_released, new, flags=re.M)
            if n != 1:
                raise SystemExit("[!] %s: expected exactly 1 date-released line, matched %d" % (p, n))
            planned[i] = (p, out, out != _read(p))

    for path, new, changed in planned:
        if changed:
            with io.open(path, "w", encoding="utf8") as f:
                f.write(new)
        print("[i] %-34s %s" % (os.path.relpath(path, ROOT), "updated" if changed else "already current"))


def main():
    parser = argparse.ArgumentParser(description="set Maltrail's version in every file that carries it")
    parser.add_argument("version", nargs="?", help="the new version, e.g. 3.3")
    parser.add_argument("--next", action="store_true", help="bump the minor component of the current version")
    parser.add_argument("--check", action="store_true", help="verify only; write nothing")
    parser.add_argument("--date", help="also set CITATION.cff date-released (YYYY-MM-DD, or 'today')")
    args = parser.parse_args()

    if args.check:
        if args.version or args.next:
            parser.error("--check takes no version")
        return _verify()

    if args.next == bool(args.version):
        parser.error("give a version, or --next, but not both")

    version = next_minor(current()) if args.next else args.version
    if not re.match(r'^\d+\.\d+$', version):
        raise SystemExit("[!] %r is not 'major.minor' - Maltrail versions two components" % version)

    date = args.date
    if date == "today":
        date = datetime.date.today().isoformat()
    if date and not re.match(r'^\d{4}-\d{2}-\d{2}$', date):
        raise SystemExit("[!] --date must be YYYY-MM-DD")

    print("[i] %s -> %s" % (current(), version))
    apply(version, date)
    return _verify()


def _verify():
    """Hand off to the checker rather than re-implementing agreement here.

    argv is swapped for the call: check_version parses sys.argv itself, and would otherwise
    reject the flags that were meant for THIS script.
    """

    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import check_version
    argv = sys.argv
    try:
        sys.argv = [check_version.__file__]
        rc = check_version.main() or 0
    finally:
        sys.argv = argv
    if rc:
        print("[x] the tree does not agree with itself after the bump", file=sys.stderr)
    return rc


if __name__ == "__main__":
    sys.exit(main())
