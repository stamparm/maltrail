#!/usr/bin/env python3

"""
Copyright (c) 2014-present Maltrail developers (https://github.com/stamparm/maltrail/)
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
    ("captures", ["sensor-captures", "sensor-captures-ip"]),
    ("upgrade", ["rerun-ok", "conf-preserved", "tree-after-rerun"]),
    ("in-place", ["inplace-adopted", "inplace-kept-edit", "inplace-kept-custom-trail"]),
    ("uninstall", ["uninstall-ran", "uninstall-removed-tree", "uninstall-kept-conf"]),
]

YES, NO, NA = "✅", "❌", "➖"

# The columns that describe install.sh's work, which Windows has no equivalent of. "sensor" is in
# here because it asks about a SERVICE FILE, not about the binary - "sensor runs" is the column
# that asks whether the binary works, and that one Windows answers for real.
WINDOWS_NOT_APPLICABLE = ("install", "server", "sensor", "upgrade", "in-place", "uninstall")


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
    # ONE unit directory, told to both halves. assert.sh checks whatever MALTRAIL_UNITS says and
    # install.sh writes wherever --unit-dir says; passing different paths made every service-file
    # check look for files that had been written somewhere else.
    units = os.path.join(raw, "units")
    args = ["sh", os.path.join(HERE, "assert.sh"), "--repo", "file://%s" % ROOT,
            "--no-service", "--unit-dir", units]
    sensor = os.environ.get("MALTRAIL_TEST_SENSOR")
    if sensor:
        args += ["--sensor-bin", sensor]
    env = dict(os.environ, MALTRAIL_SRC=ROOT, MALTRAIL_UNITS=units)
    with io.open(out, "w", encoding="utf-8") as handle:
        proc = subprocess.Popen(args, cwd=ROOT, env=env,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        text = proc.communicate()[0].decode("utf-8", "replace")
        handle.write(text)
    with io.open(os.path.join(raw, "%s.image" % label), "w", encoding="utf-8") as handle:
        handle.write("native")
    print("[i] %s: assert.sh exited %d" % (label, proc.returncode))


def record_windows(label):
    """Record a row on Windows, where neither the container harness nor assert.sh can go.

    `windows.py` prints the same mark protocol, so everything downstream is the shared code path.
    """

    raw = os.path.join(ROOT, ".compat-raw")
    if not os.path.isdir(raw):
        os.makedirs(raw)
    args = [sys.executable, os.path.join(HERE, "windows.py")]
    sensor = os.environ.get("MALTRAIL_TEST_SENSOR")
    if sensor:
        args += ["--sensor-bin", sensor]
    out = os.path.join(raw, "%s.out" % label)
    with io.open(out, "w", encoding="utf-8") as handle:
        proc = subprocess.Popen(args, cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        handle.write(proc.communicate()[0].decode("utf-8", "replace"))
    with io.open(os.path.join(raw, "%s.image" % label), "w", encoding="utf-8") as handle:
        handle.write("native")
    print("[i] %s: windows.py exited %d" % (label, proc.returncode))


def record(labels, native=False, windows=False):
    raw = os.path.join(ROOT, ".compat-raw")
    if windows:
        for label in labels:
            record_windows(label)
    elif native:
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
        # Windows has no install.sh, no system-user creation and no service manager any of the
        # unit checks know about, so five of the eight columns are asking about machinery that
        # does not exist rather than machinery that failed. Marking them NA says that; marking
        # them ❌ would claim the installer was tried and broke, which is not what happened.
        windows = facts.get("os", "").startswith("Windows")
        capabilities = {}
        for name, required in CAPABILITIES:
            if name in ("sensor", "sensor runs", "captures") and musl:
                capabilities[name] = NA
            elif windows and name in WINDOWS_NOT_APPLICABLE:
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
        "%s it did not. Every cell was produced by installing Maltrail on that platform and asking "
        "it questions - in a container where one can stand in for the real thing, and on a real "
        "FreeBSD VM or a real Mac where it cannot, because a container shares this kernel. Never "
        "by hand." % (YES, "—", NA, NO),
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
        "| captures | Did it then see real packets? A DNS query for a trail domain and a TCP SYN "
        "to a trail address, matched live off the wire — two protocols and two matchers, so a "
        "green cell means more than one path through the sensor works. `-T` proves the "
        "configuration resolves; only this proves capture does, which is how "
        "`MONITOR_INTERFACE any` passed `-T` on Windows and then opened nothing. |",
        "| upgrade | Did re-running the installer keep operator configuration? |",
        "| in-place | Did installing from an existing checkout adopt it without cloning over it? |",
        "| uninstall | Did `--uninstall` remove the tree and units but keep config and logs? |",
        "",
        "## What `captures` is for",
        "",
        "`-T` proves a configuration parses and an interface name resolves. It does not open a "
        "capture handle, so it cannot tell you whether a packet ever reaches the sensor — and for "
        "nineteen rows that was the only evidence the sensor worked at all.",
        "",
        "The column was added, and on its first run it went red on every glibc Linux row. Not the "
        "check being wrong: the 3.3 release binary links libpcap 1.10.5 statically, that version "
        "refuses to activate the `any` device when promiscuous mode is requested, and `install.sh` "
        "never rewrites `MONITOR_INTERFACE` — so a machine installed from a release stopped at "
        "`opening interface 'any'` and captured nothing. A developer build links the system "
        "libpcap, which tolerates it, so nothing in development ever showed it. Fixed in 3.4, "
        "which is what these cells are now recorded against.",
        "",
        "## What the BSD rows cost",
        "",
        "FreeBSD, NetBSD and OpenBSD are all here, and none of them arrived free. Each needed a "
        "native VM — the bundled SQLite wants a C compiler for the target, and rustup has no "
        "OpenBSD std at all — and between them they turned up six things nothing else could have:",
        "",
        "| | |",
        "| --- | --- |",
        "| OpenBSD | `sysctlbyname` does not exist there, and neither does the libc crate's "
        "`HW_PHYSMEM64`, so `total_physmem()` uses `sysconf` |",
        "| OpenBSD | base ships libpcap with no pkg-config file, so the build needs "
        "`LIBPCAP_LIBDIR` named |",
        "| NetBSD | `install.sh` linked the sensor into `/usr/local/bin`, which NetBSD does not "
        "have — pkgsrc uses `/usr/pkg/bin`, so the link failed and the sensor never reached PATH |",
        "| NetBSD | pkgsrc installs the interpreter as `python3.12` and leaves `python3` to the "
        "administrator |",
        "| both | the capture probe aimed at unroutable TEST-NET, which needs a default route to "
        "leave the interface |",
        "",
        "The NetBSD job also spent three runs looking like the CI action was broken — its `run` "
        "phase produced no output at all — when one absent optional package was making `prepare` "
        "exit non-zero, and a failing prepare means `run` never executes. Nothing about the "
        "platform; the evidence just pointed at the wrong layer.",
        "",
        "## Windows",
        "",
        "Supported, released, and it captures. Verified on **Windows 10 IoT Enterprise LTSC 2021 "
        "(10.0.19044)** from the shipped `maltrail.conf` unedited: DNS queries, a wildcard-regex "
        "domain and an ICMP destination all matched against their trails and written to the event "
        "log.",
        "",
        "| | |",
        "| --- | --- |",
        "| Binary | `x86_64-pc-windows-msvc`, on the releases page with a SHA-256 |",
        "| Needs | Windows 10 or later, 64-bit, and [Npcap](https://npcap.com). `wpcap.dll` is a "
        "load-time dependency, so nothing starts without it — not even `--version` |",
        "| Run as | An elevated prompt. Capture needs Administrator here the way it needs root or "
        "`CAP_NET_RAW` elsewhere |",
        "| First command | `maltrail-sensor.exe -T -c maltrail.conf` — checks a configuration and "
        "reports what would and would not work |",
        "",
        "Every push runs the Windows build for real, on a Linux runner: mingw-w64 cross-compiles "
        "it, `wpcap.dll` is lifted out of the Npcap installer's NSIS archive without installing "
        "anything, and Wine executes the result. `sensor/tools/check_windows.sh` runs the whole "
        "Windows unit suite, `-T` against the shipped configuration, every pcap in the corpus "
        "through both the Windows and the native binary with the detections compared byte for "
        "byte, and the server answering `/ping` under a real Windows Python. That found four bugs "
        "compiling could not, and the VM run found a fifth — `MONITOR_INTERFACE any` is a Linux "
        "pseudo-device, so it is now substituted with the real interface names wherever the "
        "platform has no such device, exactly as Maltrail v1 did.",
        "",
        "There is no row in the table above because the table records what `install.sh` did, and "
        "Windows has no `install.sh` — no system user, no service unit, no prefix to remove. "
        "`python3 tests/install/record.py record --windows <label>` writes one on a Windows "
        "machine if you want the remaining columns filled in.",
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
    one.add_argument("--windows", action="store_true",
                     help="probe THIS Windows machine (no installer exists there)")
    two = sub.add_parser("render", help="build docs/compat/README.md from the rows")
    two.add_argument("--check", action="store_true", help="fail if the page is not current")
    options = parser.parse_args()

    if options.command == "record":
        return record(options.labels, native=options.native, windows=options.windows)
    if options.command == "render":
        return render(options.check)
    parser.print_help()
    return 2


if __name__ == "__main__":
    sys.exit(main())
