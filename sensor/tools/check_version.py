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
CITATION = os.path.join(ROOT, "CITATION.cff")
SETTINGS_GEN = os.path.join(ROOT, "sensor", "src", "settings_gen.rs")
CARGO_LOCK = os.path.join(ROOT, "sensor", "Cargo.lock")


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


def citation_version():
    """version: "3.0" from CITATION.cff.

    Nothing linked this to the tree, and it drifted: the file still claimed 3.0 while the code,
    the sensor and the published tag were all 3.1.1. That is not cosmetic - CITATION.cff exists
    so a paper can cite a specific version, and it had been quietly citing the wrong one.
    """

    match = re.search(r"^version\s*:\s*[\"']([^\"']+)[\"']", _read(CITATION), re.M)
    if not match:
        raise SystemExit("[!] no version key found in %s" % CITATION)
    return match.group(1)


def settings_gen_version():
    """pub const VERSION: &str = "3.2"; from the generated mirror of core/settings.py.

    This is a FOURTH place the version lives, and it was the one nobody checked here. The Rust
    parity test covers it, but that test needs a Rust toolchain - so the automated monthly bump,
    which is a text edit on a machine that has none, could not tell it had gone stale. It found
    out from a failed release: the tag was already pushed, the gate refused it, and nothing was
    built. A version bump is text; verifying it should be text too.
    """

    match = re.search(r'^pub const VERSION: &str = "([^"]+)";', _read(SETTINGS_GEN), re.M)
    if not match:
        raise SystemExit("[!] no VERSION constant found in %s" % SETTINGS_GEN)
    return match.group(1)


def cargo_lock_version():
    """The maltrail-sensor entry in sensor/Cargo.lock.

    A FIFTH place, and the release builds with --locked: a lock that still names the old version
    does not warn, it refuses to build.
    """

    match = re.search(r'name = "maltrail-sensor"\nversion = "([^"]+)"', _read(CARGO_LOCK))
    if not match:
        raise SystemExit("[!] no maltrail-sensor package entry found in %s" % CARGO_LOCK)
    return match.group(1)


def series(version):
    """'3.0.1' and '3.0' both reduce to (3, 0) - Maltrail versions two components, Cargo three.

    A SemVer pre-release / build suffix is stripped first, so 'v3.0-rc1' and '3.0.0+deb' are the
    3.0 series like anything else. Release candidates are the whole point of having a release
    pipeline that can be rehearsed, and refusing to name one would have made that impossible.
    """
    version = re.split(r"[-+]", version, 1)[0]
    parts = version.split('.')
    if len(parts) < 2:
        raise SystemExit("[!] version %r is not 'major.minor[.patch]'" % version)
    try:
        return (int(parts[0]), int(parts[1]))
    except ValueError:
        raise SystemExit("[!] version %r has non-numeric components" % version)


def main():
    parser = argparse.ArgumentParser(description="check that the sensor, the server and CITATION.cff agree on the version")
    parser.add_argument("--tag", help="also require both to match this release tag (e.g. '3.0' or 'v3.0')")
    args = parser.parse_args()

    settings, cargo, citation = settings_version(), cargo_version(), citation_version()
    generated, locked = settings_gen_version(), cargo_lock_version()
    print("[i] core/settings.py VERSION   = %s" % settings)
    print("[i] sensor/Cargo.toml version  = %s" % cargo)
    print("[i] CITATION.cff version       = %s" % citation)
    print("[i] settings_gen.rs VERSION    = %s" % generated)
    print("[i] Cargo.lock version         = %s" % locked)

    if series(settings) != series(cargo):
        print("[x] the server and the sensor would report different versions", file=sys.stderr)
        print("[?] make sensor/Cargo.toml '%s.0' or core/settings.py '%d.%d'"
              % (settings, series(cargo)[0], series(cargo)[1]), file=sys.stderr)
        return 1

    # Exact, not by series: this one is a generated copy of that exact string, and the Rust
    # parity test compares it verbatim. "3.3" vs "3.3.0" would pass a series check and still
    # fail the build.
    if generated != settings:
        print("[x] sensor/src/settings_gen.rs says %s while core/settings.py says %s"
              % (generated, settings), file=sys.stderr)
        print("[?] set it with: python3 sensor/tools/bump_version.py %s" % settings, file=sys.stderr)
        return 1

    if locked != cargo:
        print("[x] sensor/Cargo.lock says %s while sensor/Cargo.toml says %s"
              % (locked, cargo), file=sys.stderr)
        print("[?] the release builds --locked, so this fails the build, not just the check",
              file=sys.stderr)
        return 1

    if series(citation) != series(settings):
        print("[x] CITATION.cff cites %s while the tree is %s" % (citation, settings), file=sys.stderr)
        print("[?] set CITATION.cff 'version' to '%s' (and date-released to that release's date)"
              % settings, file=sys.stderr)
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
