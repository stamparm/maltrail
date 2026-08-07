#!/usr/bin/env python3
# coding: utf-8
"""Dump what Python's `core.common.load_trails()` actually loaded, as a parity oracle.

The Rust loader must accept exactly the rows Python accepts, split them into exactly the same
three fields, and build the wildcard regex out of exactly the same patterns. This script produces
the reference dump that `sensor/tests/loader_parity.rs` compares against, so the comparison
runs against the operator's REAL trails.csv rather than a fixture that can drift out of date.

    python3 sensor/tools/dump_trails.py --trails ~/.maltrail/trails.csv -o /tmp/dump

Output (UTF-8, LF):

    #count <accepted rows, duplicates included>
    #unique <len(trails)>
    #regex-groups <n>
    #regex-pattern <pattern>        (one line per compiled wildcard pattern, in order)
    #wildcard-rejected <trail>      (wildcard trail CPython's re refused to compile)
    <trail>\x1f<info>\x1f<reference>    (one line per accepted row, in CSV order)

Rows are emitted in CSV order, duplicates included, because the order decides which value wins
and which wildcard trail gets which group.
"""
from __future__ import print_function

import argparse
import csv
import os
import re
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
sys.path.insert(0, ROOT)
sys.dont_write_bytecode = True

UNIT = "\x1f"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--trails", required=True, help="trails.csv to dump")
    parser.add_argument("-c", dest="config_file", default=os.path.join(ROOT, "maltrail.conf"))
    parser.add_argument("-o", dest="out", required=True, help="where to write the dump")
    options = parser.parse_args()

    from core.settings import config, read_config
    read_config(options.config_file)
    config.TRAILS_FILE = options.trails

    # load_trails() applies the whitelist and builds the regex; use it, don't reimplement it.
    from core.common import check_whitelisted, load_trails
    trails = load_trails(quiet=True)

    csv.field_size_limit(1 << 20)
    accepted = []
    with open(options.trails, "r") as f:
        for row in csv.reader(f, delimiter=',', quotechar='"'):
            if row and len(row) == 3:
                trail, info, reference = row
                if not check_whitelisted(trail):
                    accepted.append((trail, info, reference))

    # The exact pattern list build_trails_regex() produced, recovered from the alternation it
    # wrote (the source is the ground truth the Rust side must reproduce).
    source = trails._regex or ""
    patterns = []
    for alt in re.split(r"\|(?=\(\?P<g\d+>)", source) if source else []:
        m = re.match(r"^\(\?P<g\d+>(.*)\)$", alt, re.S)
        patterns.append(m.group(1) if m else alt)

    # Wildcard `(static)` trails CPython's own `re` rejects: build_trails_regex() skips these, so
    # they are trails BOTH sensors are expected to ignore.
    wildcard = re.compile(r"[\].][*+]|\[[a-z0-9_.\-]+\]", re.I)
    rejected = []
    for trail, info, reference in accepted:
        if "static" in reference and wildcard.search(trail) and re.escape(trail) != trail:
            try:
                re.compile(trail)
            except re.error:
                rejected.append(trail)

    with open(options.out, "w") as f:
        f.write("#count %d\n" % len(accepted))
        f.write("#unique %d\n" % len(trails))
        f.write("#regex-groups %d\n" % len(patterns))
        for pattern in patterns:
            f.write("#regex-pattern %s\n" % pattern.replace("\n", "\\n"))
        for trail in rejected:
            f.write("#wildcard-rejected %s\n" % trail.replace("\n", "\\n"))
        for trail, info, reference in accepted:
            f.write("%s%s%s%s%s\n" % (trail, UNIT, info, UNIT, reference))

    print("[i] dumped %d row(s), %d unique, %d wildcard pattern(s), %d rejected to '%s'"
          % (len(accepted), len(trails), len(patterns), len(rejected), options.out))
    return 0


if __name__ == "__main__":
    sys.exit(main())
