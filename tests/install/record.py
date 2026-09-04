#!/usr/bin/env python3

"""
Copyright (c) 2014-2026 Maltrail developers (https://github.com/stamparm/maltrail/)
See the file 'LICENSE' for copying permission

Record what Maltrail actually does on a platform, then publish it.

    python3 tests/install/record.py record rocky alma arch
    python3 tests/install/record.py render
    python3 tests/install/record.py render --check

`record` runs tests/install/run.sh for each environment, reads the marks the container printed, and
writes one row per platform into docs/compat/rows/. A row says what the platform IS (distribution,
kernel, arch, python, libc) and what Maltrail DID there, capability by capability - never a single
tick, because Maltrail is a service and "it installed" is not the interesting part.

`render` turns those rows into the table in docs/compat/README.md, and `--check` FAILS when the
published table does not say what the rows say. tests/test_compat.py runs that, so the claim and
the evidence cannot drift apart - which is the whole point. A table maintained by hand becomes
marketing within two releases; this one cannot, because nobody types it.

Why it exists: the harness covered five containers while README.md claimed six platforms, and the
first widening to twelve found install.sh dead on the entire RHEL 9 family - curl-minimal conflicts
with curl, so dnf refused the transaction and nothing installed at all. Arch, meanwhile, had worked
since pacman support was added and nobody could say so.
"""

import argparse
import datetime
import io
import json
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
ROWS = os.path.join(ROOT, "docs", "compat", "rows")
PAGE = os.path.join(ROOT, "docs", "compat", "README.md")

# (column heading, the marks that must ALL be present). Order is the story an operator reads:
# it installed, it runs, it is correct, it upgrades, it leaves cleanly.
CAPABILITIES = [
    ("install", ["tree", "conf", "user", "logdir", "logdir-writable"]),
    ("server", ["unit-server", "unit-server-conf"]),
    ("/ping", ["server-ping"]),
    ("sensor", ["unit-sensor", "unit-sensor-conf"]),
    ("sensor runs", ["sensor-runs", "sensor-selftest"]),
    ("upgrade", ["rerun-ok", "conf-preserved", "tree-after-rerun"]),
    ("in-place", ["inplace-adopted", "inplace-kept-edit", "inplace-kept-custom-trail"]),
    ("uninstall", ["uninstall-ran", "uninstall-removed-tree", "uninstall-kept-conf"]),
]

YES, NO, NA = "✅", "❌", "➖"


def _libc(reported):
    """'ldd (Ubuntu GLIBC 2.39-0ubuntu8.5) 2.39' -> 'glibc 2.39'. Which libc a platform has is the
    thing that decides which sensor build it needs, so it belongs in the table in a form somebody
    can read."""

    text = (reported or "").strip()
    if not text:
        return "unknown"
    if "musl" in text.lower():
        return "musl"
    found = re.search(r"(\d+\.\d+)\s*$", text)
    return "glibc %s" % found.group(1) if found else text


def _sensor_identity(facts):
    """Which sensor this row is about, in words that mean something.

    `os.path.basename` of the path gives "maltrail-sensor" for every binary ever built, which
    answers nothing - and the answer matters: a sensor built on 24.04 carries a glibc 2.39 floor
    and will not run on Debian 12, while the release targets 2.28. Prefer what the binary said
    about itself; fall back to the release directory name; then to the path.
    """

    reported = facts.get("sensor_version", "").strip()
    if reported:
        return reported

    path = os.environ.get("MALTRAIL_TEST_SENSOR", "")
    if not path:
        return "sensor/target/release (local build)"
    parent = os.path.basename(os.path.dirname(path.rstrip("/")))
    return parent if parent.startswith("maltrail-sensor-") else path


def _row_path(label, machine="x86_64"):
    # The architecture is part of the identity. Without it a row recorded on an arm runner
    # overwrites the x86_64 one of the same name, and sixteen CI jobs quietly become twelve rows.
    return os.path.join(ROWS, "%s-%s.json" % (label, machine))


def record_native(label):
    """Record a row on THIS machine, without a container.

    A container shares the host's kernel, so there is no image that can stand in for FreeBSD or
    macOS - the platforms this exists to cover are exactly the ones docker cannot reach. assert.sh
    is POSIX sh and takes MALTRAIL_SRC, so it runs here directly and prints the same marks the
    container half prints. One recorder, two ways in.

    It INSTALLS Maltrail on this machine, which is why it is a separate flag and not a fallback.
    """

    raw = os.path.join(ROOT, ".compat-raw")
    if not os.path.isdir(raw):
        os.makedirs(raw)
    out = os.path.join(raw, "%s.out" % label)
    args = ["sh", os.path.join(HERE, "assert.sh"), "--repo", "file://%s" % ROOT,
            "--no-service", "--unit-dir", os.path.join(raw, "units")]
    sensor = os.environ.get("MALTRAIL_TEST_SENSOR")
    if sensor:
        args += ["--sensor-bin", sensor]
    env = dict(os.environ, MALTRAIL_SRC=ROOT)
    with io.open(out, "w", encoding="utf-8") as handle:
        proc = subprocess.Popen(args, cwd=ROOT, env=env,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        text = proc.communicate()[0].decode("utf-8", "replace")
        handle.write(text)
    with io.open(os.path.join(raw, "%s.image" % label), "w", encoding="utf-8") as handle:
        handle.write("native")
    print("[i] %s: assert.sh exited %d" % (label, proc.returncode))


def record(labels, native=False):
    raw = os.path.join(ROOT, ".compat-raw")
    if native:
        for label in labels:
            record_native(label)
    else:
        env = dict(os.environ, MALTRAIL_INSTALL_RAW=raw)
        subprocess.call(["bash", os.path.join(HERE, "run.sh")] + list(labels), cwd=ROOT, env=env)

    if not os.path.isdir(ROWS):
        os.makedirs(ROWS)

    for label in labels:
        out = os.path.join(raw, "%s.out" % label)
        if not os.path.isfile(out):
            print("[!] %s produced no output - not recording a row for it" % label)
            continue
        with io.open(out, encoding="utf-8", errors="replace") as handle:
            text = handle.read()

        marks = set(re.findall(r"^A (\S+)", text, re.M))
        findings = re.findall(r"^F (.+)$", text, re.M)
        facts = dict(re.findall(r"^P (\S+) (.*)$", text, re.M))

        image = ""
        image_file = os.path.join(raw, "%s.image" % label)
        if os.path.isfile(image_file):
            with io.open(image_file, encoding="utf-8") as handle:
                image = handle.read().strip()

        # A capability with no marks at all is NOT a pass. Alpine cannot run the glibc sensor, and
        # that is "does not apply here", not "worked" - the finding says which.
        musl = any("musl" in f or "not found" in f for f in findings)
        capabilities = {}
        for name, required in CAPABILITIES:
            if name in ("sensor", "sensor runs") and musl:
                capabilities[name] = NA
            else:
                capabilities[name] = YES if all(m in marks for m in required) else NO

        row = {
            "label": label,
            "image": image,
            "os": facts.get("os", "unknown"),
            # The host's, not the platform's - a container shares the kernel it runs on.
            "host_kernel": facts.get("host_kernel", "unknown"),
            "machine": facts.get("machine", "unknown"),
            "python": facts.get("python", "unknown"),
            "libc": _libc(facts.get("libc", "")),
            "capabilities": capabilities,
            "marks": sorted(marks),
            "findings": findings,
            "recorded_at": datetime.date.today().isoformat(),
            "recorded_by": os.environ.get("MALTRAIL_RECORDED_BY", "ci" if os.environ.get("CI") else "local"),
            # Which binary was tested decides what the sensor columns MEAN. A locally built sensor
            # carries the build host's glibc floor - one built on 24.04 needs 2.39 and will not run
            # on Debian 12, Rocky 9 or Leap 15.6, which made those look unsupported when they are
            # not. The release binary targets 2.28 on purpose. Recorded, so the table cannot quietly
            # be answering a different question than it appears to.
            "sensor_source": _sensor_identity(facts),
        }
        with io.open(_row_path(label, row["machine"]), "w", encoding="utf-8") as handle:
            handle.write(json.dumps(row, indent=2, sort_keys=True, ensure_ascii=False) + "\n")
        print("[i] recorded %s (%d marks, %d finding(s))" % (label, len(marks), len(findings)))
    return 0


def _rows():
    if not os.path.isdir(ROWS):
        return []
    out = []
    for name in sorted(os.listdir(ROWS)):
        if not name.endswith(".json"):
            continue
        with io.open(os.path.join(ROWS, name), encoding="utf-8") as handle:
            out.append(json.load(handle))
    return out


def table(rows):
    heads = [name for name, _ in CAPABILITIES]
    lines = ["| Platform | Arch | libc | Python | " + " | ".join(heads) + " |",
             "| --- | --- | --- | --- | " + " | ".join(["---"] * len(heads)) + " |"]
    for row in rows:
        cells = [row["capabilities"].get(name, NO) for name in heads]
        lines.append("| **%s** | %s | %s | %s | %s |"
                     % (row["os"], row["machine"], row.get("libc", "?"),
                        row["python"], " | ".join(cells)))
    return "\n".join(lines)


def page(rows):
    when = max([r["recorded_at"] for r in rows] or ["-"])
    passed = sum(1 for r in rows for v in r["capabilities"].values() if v == YES)
    na = sum(1 for r in rows for v in r["capabilities"].values() if v == NA)
    failed = sum(1 for r in rows for v in r["capabilities"].values() if v == NO)
    body = [
        "# Where Maltrail is known to run",
        "",
        "%s %s the capability was exercised and worked, %s it cannot apply on that platform, "
        "%s it did not. Every cell was produced by `tests/install/run.sh` installing Maltrail in "
        "that image and asking it questions - never by hand." % (YES, "—", NA, NO),
        "",
        "**%d platforms, %d capabilities verified, %d not applicable, %d failing.** "
        "Last recorded %s." % (len(rows), passed, na, failed, when),
        "",
        "Kernel version is deliberately not listed: these run as containers, which share the "
        "host's kernel, so it would say the same thing on every row and describe none of them. "
        "The libc is listed instead - it is what decides which sensor build a platform needs.",
        "",
        table(rows),
        "",
        "## What each column means",
        "",
        "| Column | The question it answers |",
        "| --- | --- |",
        "| install | Did `install.sh` produce a tree, a config, a user and a writable log directory? |",
        "| server | Did the server unit render with paths that resolve? |",
        "| /ping | Did the server actually start and answer? |",
        "| sensor | Did the sensor unit render with paths that resolve? |",
        "| sensor runs | Did the sensor start and pass its own `-T` self-test? |",
        "| upgrade | Did re-running the installer keep operator configuration? |",
        "| in-place | Did installing from an existing checkout adopt it without cloning over it? |",
        "| uninstall | Did `--uninstall` remove the tree and units but keep config and logs? |",
        "",
        "## Rows",
        "",
        "One JSON file per platform under [`rows/`](rows), each carrying what the platform is, "
        "every mark the container printed, any findings, and who recorded it when.",
        "",
    ]
    for row in rows:
        body.append("### %s" % row["os"])
        body.append("")
        body.append("`%s` · %s · %s · python %s · recorded %s by %s"
                    % (row["image"] or row["label"], row["machine"], row.get("libc", "?"),
                       row["python"], row["recorded_at"], row["recorded_by"]))
        if row.get("sensor_source"):
            body.append("")
            body.append("Sensor tested: `%s`" % row["sensor_source"])
        if row["findings"]:
            body.append("")
            for finding in row["findings"]:
                body.append("- %s" % finding)
        body.append("")
    return "\n".join(body)


def render(check):
    rows = _rows()
    if not rows:
        print("[!] no rows in %s - run 'record' first" % ROWS)
        return 2
    want = page(rows)
    have = ""
    if os.path.isfile(PAGE):
        with io.open(PAGE, encoding="utf-8") as handle:
            have = handle.read()
    if check:
        if have.strip() != want.strip():
            print("[!] docs/compat/README.md does not say what docs/compat/rows says.")
            print("[!] Re-run: python3 tests/install/record.py render")
            return 1
        print("[i] %d platform row(s), page current" % len(rows))
        return 0
    if not os.path.isdir(os.path.dirname(PAGE)):
        os.makedirs(os.path.dirname(PAGE))
    with io.open(PAGE, "w", encoding="utf-8") as handle:
        handle.write(want.rstrip("\n") + "\n")
    print("[i] wrote %s from %d row(s)" % (PAGE, len(rows)))
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__.strip().split("\n")[0])
    sub = parser.add_subparsers(dest="command")
    one = sub.add_parser("record", help="run the harness and write rows")
    one.add_argument("labels", nargs="+")
    one.add_argument("--native", action="store_true",
                     help="install on THIS machine instead of in a container (FreeBSD, macOS)")
    two = sub.add_parser("render", help="build docs/compat/README.md from the rows")
    two.add_argument("--check", action="store_true", help="fail if the page is not current")
    options = parser.parse_args()

    if options.command == "record":
        return record(options.labels, native=options.native)
    if options.command == "render":
        return render(options.check)
    parser.print_help()
    return 2


if __name__ == "__main__":
    sys.exit(main())
