#!/usr/bin/env python3
# coding: utf-8

"""Compare a day of events from the two sensors running side by side (ROADMAP Gate 2.3).

The shadow deployment is the gate that actually earns "production ready": both sensors, same
traffic, same trails, on a real gateway, for at least a week. Corpus parity proves the sensors
agree on traffic we thought to synthesize; only real traffic proves it on traffic we did not.

This is the nightly comparison. Point it at both LOG_DIRs and it answers the one question that
decides the cutover:

    ARE THERE DETECTIONS THE OLD SENSOR MAKES THAT THE NEW ONE DOES NOT?

    python3 sensor/tools/shadow_diff.py --new /var/log/maltrail --old /var/log/maltrail-old
    python3 sensor/tools/shadow_diff.py --new ... --old ... --date 2026-08-07
    python3 sensor/tools/shadow_diff.py --new ... --old ... --days 7 --json report.json

Exit status is 1 when the old sensor detected something the new one missed, so this can be run
from cron and alerted on. New-sensor-only detections are reported but are NOT a failure: the
Rust sensor legitimately detects more (it sees pcap timestamps the Python sensor discards, and
it refreshes trails on its own timer), and every corpus run shows the same asymmetry.

Events are compared as SETS of (src_ip, dst_ip, type, trail, info) — not counts and not
timestamps. Counts differ by design: the two throttles are different mechanisms, and each
sensor's worker count changes how often the same detection is written.
"""

import argparse
import collections
import csv
import datetime
import glob
import io
import json
import os
import re
import sys

# The event line is whitespace-separated with CSV quoting; see core/log.py.
FIELDS = ("time", "sensor", "src_ip", "src_port", "dst_ip", "dst_port", "proto", "type", "trail", "info", "reference")
# What identifies a DETECTION, as opposed to one writing of it. Ports are excluded: the same
# scan or beacon reappears on a new ephemeral port every time and would otherwise look like a
# different finding on each side.
KEY = ("src_ip", "dst_ip", "type", "trail", "info")

# "excessive no such domain" bundles the observed sub-labels into the trail by iterating a Python
# SET, so sensor.py emits them in an arbitrary order that varies from run to run (string hashing
# is randomised per process). The Rust sensor sorts them. Same detection, different rendering —
# sort both sides, exactly as tools/parity.py does. This is the only value-level normalisation,
# and it must stay the only one: every other difference is a real difference.
NXDOMAIN_BUNDLE_RE = re.compile(r"^\((?P<names>[^()]*,[^()]*)\)(?P<suffix>\..*)$")


def normalize_trail(trail, info):
    if "excessive no such domain" not in info:
        return trail
    match = NXDOMAIN_BUNDLE_RE.match(trail)
    if not match:
        return trail
    return "(%s)%s" % (",".join(sorted(match.group("names").split(","))), match.group("suffix"))


def key_of(event):
    event = dict(event)
    event["trail"] = normalize_trail(event["trail"], event["info"])
    return tuple(event[k] for k in KEY)


def parse_line(line):
    """One event line -> dict, or None if it is not one."""
    line = line.strip()
    if not line or line.startswith('#'):
        return None
    try:
        fields = next(csv.reader(io.StringIO(line), delimiter=' ', quotechar='"'))
    except Exception:
        return None
    if len(fields) != len(FIELDS):
        return None
    return dict(zip(FIELDS, fields))


def load_day(log_dir, date):
    """The set of distinct detections in <log_dir>/<date>.log, plus how many lines produced it."""
    path = os.path.join(log_dir, "%s.log" % date)
    detections = collections.Counter()
    lines = 0
    if not os.path.isfile(path):
        return detections, lines, path
    with open(path, "r", errors="replace") as f:
        for line in f:
            event = parse_line(line)
            if not event:
                continue
            lines += 1
            detections[tuple(event[k] for k in KEY)] += 1
    return detections, lines, path


def dates_for(days, explicit):
    if explicit:
        return [explicit]
    today = datetime.date.today()
    return [(today - datetime.timedelta(days=n)).strftime("%Y-%m-%d") for n in range(days)]


def load_all(log_dir):
    """Every event in every daily log, ignoring which file it landed in.

    Required when comparing a REPLAY rather than a live day: the sensors date their log files
    differently by design. The Rust sensor stamps events with the packet's own timestamp, while
    sensor.py on Python 3 substitutes wall-clock time (sensor.py:1523) — so replaying a capture
    recorded in 2023 writes 2023-11-14.log on one side and today's date on the other, with
    byte-identical contents. Comparing per date would call that a total disagreement.
    """
    detections = collections.Counter()
    lines = 0
    paths = sorted(glob.glob(os.path.join(log_dir, "*.log")))
    paths = [p for p in paths if os.path.basename(p) != "error.log"]
    for path in paths:
        with open(path, "r", errors="replace") as f:
            for line in f:
                event = parse_line(line)
                if not event:
                    continue
                lines += 1
                detections[key_of(event)] += 1
    return detections, lines, paths


def describe(key):
    src, dst, kind, trail, info = key
    return "%s -> %s  %-5s %s (%s)" % (src, dst, kind, trail, info)


def main():
    parser = argparse.ArgumentParser(description="compare event sets from a shadow deployment")
    parser.add_argument("--new", required=True, metavar="LOG_DIR", help="LOG_DIR of the Rust sensor")
    parser.add_argument("--old", required=True, metavar="LOG_DIR", help="LOG_DIR of old/sensor.py")
    parser.add_argument("--date", help="a single YYYY-MM-DD (default: the last --days days)")
    parser.add_argument("--days", type=int, default=1, help="how many days back to compare (default 1)")
    parser.add_argument("--show", type=int, default=20, help="how many differing detections to print per day")
    parser.add_argument("--json", metavar="FILE", help="also write a machine-readable report")
    parser.add_argument("--all", action="store_true",
                        help="compare every daily log in each directory regardless of filename "
                             "(use for REPLAYS: the two sensors date their files differently)")
    args = parser.parse_args()

    report = {"days": [], "missed_total": 0, "extra_total": 0}
    worst = 0

    if args.all:
        new, new_lines, new_paths = load_all(args.new)
        old, old_lines, old_paths = load_all(args.old)
        missed = sorted(set(old) - set(new))
        extra = sorted(set(new) - set(old))
        shared = set(old) & set(new)

        print("\n=== all logs ===")
        print("[i] old sensor: %6d line(s), %5d distinct detection(s)  (%d file(s))"
              % (old_lines, len(old), len(old_paths)))
        print("[i] new sensor: %6d line(s), %5d distinct detection(s)  (%d file(s))"
              % (new_lines, len(new), len(new_paths)))
        print("[i] agreed on %d detection(s)" % len(shared))
        if missed:
            print("[x] %d detection(s) ONLY the old sensor made — these block the cutover:" % len(missed))
            for key in missed[:args.show]:
                print("      %s   [old wrote it %dx]" % (describe(key), old[key]))
            if len(missed) > args.show:
                print("      ... and %d more" % (len(missed) - args.show))
        else:
            print("[o] no detection was made only by the old sensor")
        if extra:
            print("[i] %d detection(s) only the new sensor made (expected; not a failure):" % len(extra))
            for key in extra[:args.show]:
                print("      %s" % describe(key))
            if len(extra) > args.show:
                print("      ... and %d more" % (len(extra) - args.show))
        report["days"].append({
            "date": "all", "old_lines": old_lines, "new_lines": new_lines,
            "old_distinct": len(old), "new_distinct": len(new), "agreed": len(shared),
            "missed": [list(k) for k in missed], "extra_count": len(extra),
        })
        report["missed_total"] = len(missed)
        report["extra_total"] = len(extra)
        return finish(report, args)

    for date in dates_for(args.days, args.date):
        new, new_lines, new_path = load_day(args.new, date)
        old, old_lines, old_path = load_day(args.old, date)

        if not os.path.isfile(new_path) and not os.path.isfile(old_path):
            print("[i] %s: no logs on either side, skipping" % date)
            continue

        # The number that decides the cutover.
        missed = sorted(set(old) - set(new))
        extra = sorted(set(new) - set(old))
        shared = set(old) & set(new)

        print("\n=== %s ===" % date)
        print("[i] old sensor: %6d line(s), %5d distinct detection(s)  (%s)" % (old_lines, len(old), old_path))
        print("[i] new sensor: %6d line(s), %5d distinct detection(s)  (%s)" % (new_lines, len(new), new_path))
        print("[i] agreed on %d detection(s)" % len(shared))

        if missed:
            print("[x] %d detection(s) ONLY the old sensor made — these block the cutover:" % len(missed))
            for key in missed[:args.show]:
                print("      %s   [old wrote it %dx]" % (describe(key), old[key]))
            if len(missed) > args.show:
                print("      ... and %d more" % (len(missed) - args.show))
        else:
            print("[o] no detection was made only by the old sensor")

        if extra:
            print("[i] %d detection(s) only the new sensor made (expected; not a failure):" % len(extra))
            for key in extra[:args.show]:
                print("      %s" % describe(key))
            if len(extra) > args.show:
                print("      ... and %d more" % (len(extra) - args.show))

        report["days"].append({
            "date": date,
            "old_lines": old_lines, "new_lines": new_lines,
            "old_distinct": len(old), "new_distinct": len(new),
            "agreed": len(shared),
            "missed": [list(k) for k in missed],
            "extra_count": len(extra),
        })
        report["missed_total"] += len(missed)
        report["extra_total"] += len(extra)
        worst = max(worst, len(missed))

    return finish(report, args)


def finish(report, args):
    print("\n[i] total: %d detection(s) missed by the new sensor, %d extra"
          % (report["missed_total"], report["extra_total"]))

    if args.json:
        with open(args.json, "w") as f:
            json.dump(report, f, indent=2, sort_keys=True)
        print("[i] wrote %s" % args.json)

    if report["missed_total"]:
        print("[!] the shadow gate is NOT met: the old sensor detected something the new one did not")
        return 1
    print("[o] shadow gate met for this window: zero old-sensor-only detections")
    return 0


if __name__ == "__main__":
    sys.exit(main())
