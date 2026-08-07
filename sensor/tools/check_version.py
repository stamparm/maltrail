#!/usr/bin/env python3
# coding: utf-8

"""Assert that Maltrail reports one version, not two.

The server takes its version from `core/settings.py:VERSION` ("3.0") and the sensor from
`sensor/Cargo.toml:version` ("3.0.0"). Nothing linked them, and they have already drifted once:
the sensor kept announcing 2.2 after the tree was bumped to 3.0, which means every event, every
`--version` and every `maltrail_build_info` metric was lying about which build produced it.

Cargo requires three components (SemVer), Maltrail's own scheme uses two, so the comparison is
`major.minor` with the Cargo patch level allowed to move independently.

    python3 sensor/tools/check_version.py            # settings.py == Cargo.toml
    python3 sensor/tools/check_version.py --tag 3.0  # ...and both == the release tag

The tag check is deliberately opt-in. `master` legitimately runs ahead of the last published
tag (3.0 in development while 2.2 is the latest release), so requiring tag equality on every
commit would encode the wrong lifecycle. Release automation passes --tag; ordinary CI does not.
"""

import argparse
import os
import re
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
SETTINGS = os.path.join(ROOT, "core", "settings.py")
CARGO = os.path.join(ROOT, "sensor", "Cargo.toml")


def _read(path):
    with open(path, "r") as f:
        return f.read()


def settings_version():
    """VERSION = "3.0" from core/settings.py, without importing it (it has side effects)."""
    match = re.search(r"^VERSION\s*=\s*[\"']([^\"']+)[\"']", _read(SETTINGS), re.M)
    if not match:
        raise SystemExit("[!] no VERSION assignment found in %s" % SETTINGS)
    return match.group(1)


def cargo_version():
    """version = "3.0.0" from the [package] table only - dependency versions must not match."""
    text = _read(CARGO)
    package = re.search(r"^\[package\]\s*$(.*?)(?=^\[|\Z)", text, re.M | re.S)
    if not package:
        raise SystemExit("[!] no [package] table found in %s" % CARGO)
    match = re.search(r"^version\s*=\s*\"([^\"]+)\"", package.group(1), re.M)
    if not match:
        raise SystemExit("[!] no version key in the [package] table of %s" % CARGO)
    return match.group(1)


def series(version):
    """'3.0.1' and '3.0' both reduce to (3, 0) - Maltrail versions two components, Cargo three."""
    parts = version.split('.')
    if len(parts) < 2:
        raise SystemExit("[!] version %r is not 'major.minor[.patch]'" % version)
    try:
        return (int(parts[0]), int(parts[1]))
    except ValueError:
        raise SystemExit("[!] version %r has non-numeric components" % version)


def main():
    parser = argparse.ArgumentParser(description="check that the sensor and the server agree on the version")
    parser.add_argument("--tag", help="also require both to match this release tag (e.g. '3.0' or 'v3.0')")
    args = parser.parse_args()

    settings, cargo = settings_version(), cargo_version()
    print("[i] core/settings.py VERSION   = %s" % settings)
    print("[i] sensor/Cargo.toml version  = %s" % cargo)

    if series(settings) != series(cargo):
        print("[x] the server and the sensor would report different versions", file=sys.stderr)
        print("[?] make sensor/Cargo.toml '%s.0' or core/settings.py '%d.%d'"
              % (settings, series(cargo)[0], series(cargo)[1]), file=sys.stderr)
        return 1

    if args.tag:
        tag = args.tag.lstrip('vV')
        print("[i] release tag                = %s" % tag)
        if series(tag) != series(settings):
            print("[x] tag %s does not match the tree's version %s" % (args.tag, settings), file=sys.stderr)
            return 1
        print("[i] versions agree with the release tag")
        return 0

    print("[i] versions agree")
    return 0


if __name__ == "__main__":
    sys.exit(main())
