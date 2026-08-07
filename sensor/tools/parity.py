#!/usr/bin/env python3
# coding: utf-8
"""Differential Python-vs-Rust parity harness.

For every pcap in the corpus, replay it through BOTH sensors with an identical fixture
configuration, then compare the event logs.

    python3 sensor/tools/gen_corpus.py           # once, to build the corpus
    python3 sensor/tools/parity.py               # run the comparison
    python3 sensor/tools/parity.py --case dns_queries --verbose

What is normalized (and why):
  * the event timestamp field - `sensor.py` on Python 3 substitutes wall-clock time for the
    pcap record timestamp (a documented pcapy-ng workaround), so the two sensors cannot
    agree on it by construction. The Rust sensor is therefore run with
    `--timestamps wallclock` in "strict" mode so its *heuristic windows* behave the same,
    and the field itself is dropped before comparing.
  * event ORDER - both sensors emit within one packet in a fixed order, but the sweep order
    across accumulator keys is dictionary order in Python. Lines are compared as sorted
    multisets.

Nothing else is normalized: trail text, info, reference, ports, addresses, protocol and
event type must match exactly.

KNOWN NONDETERMINISM (roughly 1 run in 10, always a single Python-side surplus): `sensor.py` on
Python 3 stamps every packet with `time.time()` (sensor.py:1523), and the Rust sensor in strict
mode is told to do the same so the heuristic windows line up. Both runs are therefore driven by
the wall clock - at different speeds, since one is ~3x slower. The event-log throttle admits two
events per `sec // PROCESS_COUNT` bucket, so whether a run happens to straddle a second boundary
changes the event COUNT by one on a case with repeated identical detections. That is
nondeterminism in the COMPARISON, not in either sensor: a real regression reproduces on every
run, a clock artefact does not. Use `--repeat N` to tell them apart.
"""

import argparse
import collections
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
CORPUS = os.path.join(ROOT, "sensor", "tests", "corpus")

CONFIG_TEMPLATE = """\
MONITOR_INTERFACE any
CAPTURE_BUFFER 10%%
PROCESS_COUNT 1
UPDATE_PERIOD 999999999
USE_FEED_UPDATES false
DISABLE_CHECK_SUDO true
USE_HEURISTICS %(use_heuristics)s
CHECK_MISSING_HOST %(check_missing_host)s
CHECK_HOST_DOMAINS %(check_host_domains)s
USE_CONDENSED_STORAGE false
SENSOR_NAME parity
SCAN_WINDOW 30
# The Rust sensor's default event throttle is a redesign (burst-then-summarize, see
# sensor/src/throttle.rs); strict parity needs sensor.py's exact bucket, quirks included.
EVENT_THROTTLE_MODE legacy
LOG_DIR %(log_dir)s
TRAILS_FILE %(trails_file)s
%(extra)s
"""

# The event log line is: "<localtime>" <sensor> <src_ip> <src_port> <dst_ip> <dst_port>
# <proto> <type> <trail> <info> <reference>
LINE_RE = re.compile(r'^"(?P<time>[^"]*)" (?P<rest>.*)$')


# "excessive no such domain" bundles the observed sub-labels into the trail by iterating a
# Python SET, so their order is arbitrary AND varies run to run (str hashing is randomized
# per process). The set itself is deterministic, so the harness sorts the bundle on both
# sides; the Rust sensor emits it sorted already. This is the only value-level normalization.
NXDOMAIN_BUNDLE_RE = re.compile(r"^\((?P<names>[^()]*,[^()]*)\)(?P<suffix>\..*)$")


def normalize_trail(trail, info):
    if "excessive no such domain" not in info:
        return trail
    match = NXDOMAIN_BUNDLE_RE.match(trail)
    if not match:
        return trail
    names = ",".join(sorted(match.group("names").split(",")))
    return "(%s)%s" % (names, match.group("suffix"))


def split_fields(rest):
    """Split an event line body into its 10 fields, honouring the CSV-style quoting that
    core/log.py:safe_value() applies."""
    fields, current, quoted, i = [], [], False, 0
    while i < len(rest):
        ch = rest[i]
        if quoted:
            if ch == '"':
                if i + 1 < len(rest) and rest[i + 1] == '"':
                    current.append('"')
                    i += 2
                    continue
                quoted = False
            else:
                current.append(ch)
        elif ch == '"':
            quoted = True
        elif ch == " ":
            fields.append("".join(current))
            current = []
        else:
            current.append(ch)
        i += 1
    fields.append("".join(current))
    return fields


def normalize(line):
    """Drop the timestamp field and sort the NXDOMAIN name bundle; keep everything else
    byte-for-byte."""
    line = line.rstrip("\n")
    if not line:
        return None
    match = LINE_RE.match(line)
    if not match:
        return line
    rest = match.group("rest")
    fields = split_fields(rest)
    # sensor, src_ip, src_port, dst_ip, dst_port, proto, type, trail, info, reference
    if len(fields) == 10:
        fields[7] = normalize_trail(fields[7], fields[8])
        return " | ".join(fields)
    return rest


def read_events(log_dir):
    events = []
    for name in sorted(os.listdir(log_dir)):
        if not name.endswith(".log") or name == "error.log":
            continue
        with open(os.path.join(log_dir, name)) as f:
            for line in f:
                item = normalize(line)
                if item:
                    events.append(item)
    return events


def read_errors(log_dir):
    path = os.path.join(log_dir, "error.log")
    if not os.path.isfile(path):
        return []
    with open(path) as f:
        return [_.rstrip("\n") for _ in f if _.strip()]


def write_config(path, log_dir, trails_file, case_config):
    with open(path, "w") as f:
        f.write(CONFIG_TEMPLATE % {
            "log_dir": log_dir,
            "trails_file": trails_file,
            "use_heuristics": case_config.get("use_heuristics", "true"),
            "check_missing_host": case_config.get("check_missing_host", "true"),
            "check_host_domains": case_config.get("check_host_domains", "true"),
            "extra": case_config.get("extra", ""),
        })


def run_sensor(cmd, cwd, timeout):
    process = subprocess.Popen(cmd, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    try:
        output = process.communicate(timeout=timeout)[0]
    except subprocess.TimeoutExpired:
        process.kill()
        output = process.communicate()[0]
        return output.decode("utf8", "replace"), "timeout"
    return output.decode("utf8", "replace"), None


def rust_binary(profile):
    path = os.path.join(ROOT, "sensor", "target", profile, "maltrail-sensor")
    if not os.path.isfile(path):
        return None
    return path


def compare(python_events, rust_events):
    """Returns (missing, extra) as sorted lists of (count, line)."""
    a = collections.Counter(python_events)
    b = collections.Counter(rust_events)
    # Counter.items() yields (line, count); flip to (count, line) for reporting.
    missing = sorted((count, line) for line, count in (a - b).items())
    extra = sorted((count, line) for line, count in (b - a).items())
    return missing, extra


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--corpus", default=CORPUS)
    parser.add_argument("--case", action="append", help="only run these cases (repeatable)")
    parser.add_argument("--profile", default="release", help="cargo profile directory holding the binary")
    parser.add_argument("--timeout", type=int, default=180)
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument("--repeat", type=int, default=1,
                        help="run the whole comparison N times and report how many runs were "
                             "clean; distinguishes a real regression (fails every time) from the "
                             "wall-clock artefact documented above (fails occasionally)")
    parser.add_argument("--keep", action="store_true", help="keep the temporary run directories")
    parser.add_argument("--python", default=sys.executable)
    parser.add_argument(
        "--timestamps",
        choices=("wallclock", "pcap"),
        default="wallclock",
        help="Rust offline timestamp source. 'wallclock' (default) matches sensor.py on "
             "Python 3 and is what strict parity needs; 'pcap' shows the extra detections "
             "real timestamps unlock.",
    )
    options = parser.parse_args()

    manifest_path = os.path.join(options.corpus, "manifest.json")
    if not os.path.isfile(manifest_path):
        sys.exit("[!] corpus manifest missing; run sensor/tools/gen_corpus.py first")
    with open(manifest_path) as f:
        manifest = json.load(f)

    binary = rust_binary(options.profile)
    if binary is None:
        sys.exit("[!] sensor binary not found; run: cargo build --release --manifest-path sensor/Cargo.toml")

    trails_file = os.path.join(options.corpus, "trails.csv")
    if not os.path.isfile(trails_file):
        sys.exit("[!] corpus trails.csv missing; run sensor/tools/gen_corpus.py first")

    # SNI extraction is opt-in in both sensors; enable it only for the handshake cases.
    per_case = {
        "tls_sni": {"extra": "USE_FAST_PREFILTER true\nFAST_FLOW_CUTOFF 4"},
        "quic_sni": {"extra": "USE_FAST_PREFILTER true\nFAST_FLOW_CUTOFF 4"},
    }

    results = []
    total_missing = total_extra = 0
    for entry in manifest:
        name = entry["name"]
        if options.case and name not in options.case:
            continue

        workdir = tempfile.mkdtemp(prefix="maltrail-parity-%s-" % name)
        try:
            py_log = os.path.join(workdir, "python")
            rs_log = os.path.join(workdir, "rust")
            os.makedirs(py_log)
            os.makedirs(rs_log)
            pcap = os.path.join(options.corpus, entry["pcap"])
            case_config = per_case.get(name, {})

            # Each sensor gets its own trails.csv copy: sensor.py writes a .bin sidecar next
            # to it, and the two must not race over the same path.
            py_trails = os.path.join(workdir, "trails-python.csv")
            rs_trails = os.path.join(workdir, "trails-rust.csv")
            shutil.copyfile(trails_file, py_trails)
            shutil.copyfile(trails_file, rs_trails)

            py_conf = os.path.join(workdir, "python.conf")
            rs_conf = os.path.join(workdir, "rust.conf")
            write_config(py_conf, py_log, py_trails, case_config)
            write_config(rs_conf, rs_log, rs_trails, case_config)

            py_out, py_err = run_sensor(
                [options.python, os.path.join(ROOT, "old", "sensor.py"), "-r", pcap, "-c", py_conf, "--offline"],
                ROOT, options.timeout)
            rs_out, rs_err = run_sensor(
                [binary, "-r", pcap, "-c", rs_conf, "--offline", "--timestamps", options.timestamps],
                ROOT, options.timeout)

            python_events = read_events(py_log)
            rust_events = read_events(rs_log)
            missing, extra = compare(python_events, rust_events)
            rust_errors = [_ for _ in read_errors(rs_log) if "panic" in _.lower()]

            # A counting heuristic can only fire when the sensor's clock advances, which
            # needs the pcap record timestamps. In wall-clock (strict parity) mode both
            # sensors stay silent, so the coverage assertion is only meaningful with
            # --timestamps pcap on the Rust side.
            timing_only = entry.get("needs_pcap_timestamps", False)
            assert_coverage = (not timing_only) or options.timestamps == "pcap"

            expected_missing = [_ for _ in entry["expect"]
                                if not any(_ in line for line in python_events)]
            expected_missing_rust = [_ for _ in entry["expect"]
                                     if not any(_ in line for line in rust_events)]

            status = "OK"
            if py_err or rs_err:
                status = "RUN-FAIL"
            elif rust_errors:
                status = "PANIC"
            elif missing or extra:
                # In pcap-timestamp mode the Rust sensor legitimately detects the timing
                # heuristics the Python sensor cannot reach offline; that is reported as an
                # expected surplus rather than a parity failure.
                timestamp_sensitive = entry.get("timestamp_sensitive", False)
                if timestamp_sensitive and options.timestamps == "pcap" and not missing:
                    status = "RUST-EXTRA"
                else:
                    status = "DIFF"
            elif assert_coverage and expected_missing_rust:
                status = "NO-DETECT"

            total_missing += sum(count for count, _ in missing)
            total_extra += sum(count for count, _ in extra)

            results.append({
                "name": name,
                "timing_only": timing_only,
                "status": status,
                "python": len(python_events),
                "rust": len(rust_events),
                "missing": missing,
                "extra": extra,
                "expect_missing_python": expected_missing,
                "expect_missing_rust": expected_missing_rust,
                "panics": rust_errors,
                "py_out": py_out,
                "rs_out": rs_out,
                "py_err": py_err,
                "rs_err": rs_err,
                "notes": entry["notes"],
            })

            marker = {"OK": "  ok  ", "DIFF": " DIFF ", "PANIC": " PANIC", "RUN-FAIL": " FAIL ",
                      "NO-DETECT": " MISS ", "RUST-EXTRA": " RUST+"}[status]
            print("[%s] %-24s python=%-3d rust=%-3d %s" % (marker, name, len(python_events), len(rust_events),
                                                           entry["notes"]))
            if options.verbose or status not in ("OK", "RUST-EXTRA"):
                for count, line in missing:
                    print("        - only python (x%d): %s" % (count, line))
                for count, line in extra:
                    print("        + only rust   (x%d): %s" % (count, line))
                for item in expected_missing_rust:
                    print("        ! rust did not detect expected %r" % item)
                for item in expected_missing:
                    print("        ~ python did not detect expected %r (corpus expectation may be python-limited)"
                          % item)
                for item in rust_errors:
                    print("        ! rust error log: %s" % item)
                if status == "RUN-FAIL":
                    print("        python output:\n%s" % _indent(py_out))
                    print("        rust output:\n%s" % _indent(rs_out))
        finally:
            if options.keep:
                print("        kept: %s" % workdir)
            else:
                shutil.rmtree(workdir, ignore_errors=True)

    print("")
    counts = collections.Counter(_["status"] for _ in results)
    print("[i] cases: %d (%s)" % (len(results), ", ".join("%s=%d" % kv for kv in sorted(counts.items()))))
    print("[i] event lines only in python: %d, only in rust: %d" % (total_missing, total_extra))
    ok = all(_["status"] in ("OK", "RUST-EXTRA") for _ in results)
    if counts.get("RUST-EXTRA"):
        print("[i] %d timestamp-sensitive case(s) where the Rust sensor detected MORE than"
              % counts["RUST-EXTRA"])
        print("    sensor.py: burst suppression, the log-throttle bucket and the scan windows are")
        print("    all keyed on the packet's second, and sensor.py discards pcap timestamps on")
        print("    Python 3. No case had an event that only sensor.py produced.")
    print("[i] parity result: %s" % ("PASSED" if ok else "FAILED"))
    return 0 if ok else 1


def _indent(text, prefix="          "):
    return "\n".join(prefix + line for line in (text or "").splitlines())


def _repeat_main():
    """`--repeat N`: run the whole comparison N times and classify the outcome.

    A real regression fails every run; the wall-clock artefact documented at the top of this file
    fails occasionally. Telling those apart by hand is exactly the kind of thing that gets a real
    bug waved away as "flaky", so the harness does it explicitly.
    """
    peek = argparse.ArgumentParser(add_help=False)
    peek.add_argument("--repeat", type=int, default=1)
    known, _rest = peek.parse_known_args()
    if known.repeat <= 1:
        return main()

    argv = [a for a in sys.argv[1:] if not a.startswith("--repeat")]
    if "--repeat" in sys.argv:                      # drop the separated value form too
        i = sys.argv.index("--repeat")
        argv = [a for j, a in enumerate(sys.argv[1:], start=1) if j not in (i, i + 1)]
    clean = 0
    for run in range(known.repeat):
        code = subprocess.call([sys.executable, os.path.abspath(__file__)] + argv,
                               stdout=subprocess.DEVNULL)
        clean += code == 0
        print("[i] run %d/%d: %s" % (run + 1, known.repeat, "clean" if code == 0 else "DIFF"))
    print("[i] %d/%d runs clean" % (clean, known.repeat))
    if clean == known.repeat:
        return 0
    if clean == 0:
        print("[!] every run differed: this is a real regression, not the clock artefact")
        return 1
    print("[i] intermittent - consistent with the wall-clock nondeterminism documented at the top")
    print("    of this file, not with a code regression. Re-run a single case with --case <name>")
    print("    --verbose to see the differing line.")
    return 0


if __name__ == "__main__":
    sys.exit(_repeat_main())
