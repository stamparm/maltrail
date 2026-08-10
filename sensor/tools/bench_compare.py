#!/usr/bin/env python3
# coding: utf-8
"""Reproducible Python-vs-Rust sensor benchmark (offline full-sensor replay).

Both sensors replay the SAME generated pcap with the SAME configuration and the SAME trail
set, so the comparison is apples to apples: identical work, identical detections (verified by
tools/parity.py), only the implementation differs.

    python3 sensor/tools/bench_compare.py                 # 200k packets
    python3 sensor/tools/bench_compare.py --packets 1000000
    python3 sensor/tools/bench_compare.py --trails ~/.maltrail/trails.csv

Measured per sensor: wall clock, user+system CPU time, peak RSS and packets/second, plus the
line rate implied by the generated packet-size mix. Event counts from both runs are printed so
a throughput number can never be read without its correctness context.
"""

import argparse
import os
import resource
import shutil
import subprocess
import sys
import tempfile
import threading
import time

ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
sys.path.insert(0, os.path.join(ROOT, "sensor", "tools"))

import gen_corpus as G  # noqa: E402  (reuses the corpus builders)

CONFIG = """\
MONITOR_INTERFACE any
CAPTURE_BUFFER 10%%
PROCESS_COUNT 1
UPDATE_PERIOD 999999999
USE_FEED_UPDATES false
DISABLE_CHECK_SUDO true
USE_HEURISTICS true
CHECK_HOST_DOMAINS true
CHECK_MISSING_HOST true
USE_CONDENSED_STORAGE false
SENSOR_NAME bench
LOG_DIR %(log_dir)s
TRAILS_FILE %(trails_file)s
"""


def build_mix(count):
    """A realistic mix mirroring benches/hotpath.rs: 60%% bulk TLS, 15%% SYN, 10%% DNS,
    10%% HTTP, 5%% ICMP/UDP."""
    templates = []
    for i in range(60):
        templates.append(G.eth(G.ipv4("10.0.0.5", "93.184.216.%d" % (i % 250), 6,
                                      G.tcp(50000 + i, 443, 0x10, b"\x17" * 1400))))
    for i in range(15):
        templates.append(G.eth(G.ipv4("10.0.0.5", "93.184.216.%d" % (i % 250), 6,
                                      G.tcp(50000 + i, 443, 0x02))))
    for i in range(10):
        templates.append(G.eth(G.ipv4("10.0.0.5", "8.8.8.8", 17,
                                      G.udp(40000 + i, 53, G.dns_query("host%d.example.org" % i)))))
    for i in range(10):
        payload = G.http_get("/index%d.html?id=%d" % (i, i), "www.example.org", ua="Mozilla/5.0")
        templates.append(G.eth(G.ipv4("10.0.0.5", "93.184.216.34", 6, G.tcp(50000 + i, 80, 0x18, payload))))
    for _ in range(5):
        templates.append(G.eth(G.ipv4("10.0.0.5", "8.8.4.4", 1, G.icmp(8))))
        templates.append(G.eth(G.ipv4("10.0.0.5", "224.0.0.251", 17, G.udp(5353, 5353, b"\x00" * 40))))

    packets = []
    for i in range(count):
        # advance the clock once per 1000 packets so the time-based paths stay realistic
        packets.append((G.BASE_SEC + i // 1000, templates[i % len(templates)]))
    return packets


def _peak_rss_kb(pid):
    """VmHWM (peak resident set) of one process, in kB. 0 if it already exited."""
    try:
        with open("/proc/%d/status" % pid) as f:
            for line in f:
                if line.startswith("VmHWM:"):
                    return int(line.split()[1])
    except (IOError, OSError, ValueError, IndexError):
        pass
    return 0


def run(cmd, cwd):
    """Run a sensor and return (wall, user_cpu, sys_cpu, peak_rss_kb, output).

    Peak RSS is sampled from /proc/<pid>/status while the child runs: ru_maxrss from
    RUSAGE_CHILDREN is a running MAXIMUM across all children, so it would report the first
    sensor's peak for the second one as well.
    """
    before = resource.getrusage(resource.RUSAGE_CHILDREN)
    started = time.time()
    process = subprocess.Popen(cmd, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

    peak = [0]

    def sampler():
        while process.poll() is None:
            peak[0] = max(peak[0], _peak_rss_kb(process.pid))
            time.sleep(0.02)
        peak[0] = max(peak[0], _peak_rss_kb(process.pid))

    thread = threading.Thread(target=sampler)
    thread.daemon = True
    thread.start()

    output = process.communicate()[0]
    thread.join(timeout=1.0)
    wall = time.time() - started
    after = resource.getrusage(resource.RUSAGE_CHILDREN)
    return (wall,
            after.ru_utime - before.ru_utime,
            after.ru_stime - before.ru_stime,
            peak[0],
            output.decode("utf8", "replace"),
            process.returncode)


def _indent(text, prefix="      "):
    return "\n".join(prefix + line for line in (text or "").strip().splitlines())


def oracle_is_runnable(python):
    """Can old/sensor.py replay a pcap at all? Returns None if yes, else why not."""
    probe = subprocess.Popen(
        [python, "-c", "import pcapy"], cwd=ROOT,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    out = probe.communicate()[0].decode("utf8", "replace").strip()
    if probe.returncode == 0:
        return None
    # The last traceback line is the diagnosis; the frames above it are noise here.
    return (out.strip().splitlines() or ["pcapy/pcapy-ng is not importable"])[-1].strip()


def count_events(log_dir):
    total = 0
    for name in os.listdir(log_dir):
        if name.endswith(".log") and name != "error.log":
            with open(os.path.join(log_dir, name)) as f:
                total += sum(1 for line in f if line.strip())
    return total


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--packets", type=int, default=200000)
    parser.add_argument("--trails", default=os.path.join(ROOT, "sensor", "tests", "corpus", "trails.csv"))
    parser.add_argument("--profile", default="release")
    parser.add_argument("--python", default=sys.executable)
    parser.add_argument("--keep", action="store_true")
    parser.add_argument("--repeat", type=int, default=3,
                        help="runs per measurement; the FASTEST is reported (min removes "
                             "scheduler and page-cache noise, which otherwise makes the "
                             "startup/steady-state split unstable)")
    parser.add_argument("--skip-python", action="store_true", help="only benchmark the Rust sensor")
    # ON BY DEFAULT. The headline claim about this sensor is its per-packet cost, and the raw
    # wall-clock ratio does not measure that: on a 300k-packet replay with a real 1.5M-row trail
    # set, most of the wall clock on BOTH sensors is trail loading. Reporting only the ratio made
    # the documented command contradict the documented number — 3x instead of 28x — which reads
    # as either a lie or a regression. Neither was true; they measured different things.
    parser.add_argument("--no-startup-split", dest="slope", action="store_false", default=True,
                        help="skip the startup measurement and report only whole-process wall clock")
    options = parser.parse_args()

    binary = os.path.join(ROOT, "sensor", "target", options.profile, "maltrail-sensor")
    if not os.path.isfile(binary):
        sys.exit("[!] build first: cargo build --release --manifest-path sensor/Cargo.toml")
    if not os.path.isfile(options.trails):
        default_corpus = os.path.join(ROOT, "sensor", "tests", "corpus", "trails.csv")
        if os.path.abspath(options.trails) == os.path.abspath(default_corpus):
            sys.exit("[!] trails file not found: %s\n"
                     "[?] build the fixture corpus:  python3 sensor/tools/gen_corpus.py"
                     % options.trails)
        # Telling someone to run gen_corpus.py here is a dead end: it writes the FIXTURE corpus
        # under sensor/tests/corpus/ and can never create the path they asked for, so the same
        # error comes straight back. It did, repeatedly, to somebody benchmarking a Pi.
        sys.exit("[!] trails file not found: %s\n"
                 "[?] that is the operator's real trail set; build it with either\n"
                 "      python3 sensor/tools/update_trails.py -c maltrail.conf\n"
                 "    or by starting the sensor once (it builds the trail set on first run).\n"
                 "[?] to benchmark against the bundled fixture set instead, drop --trails and run\n"
                 "      python3 sensor/tools/gen_corpus.py"
                 % options.trails)

    if not options.skip_python:
        unrunnable = oracle_is_runnable(options.python)
        if unrunnable:
            sys.exit("[!] the python sensor (old/sensor.py) cannot run: %s\n"
                     "[?] install its capture bindings:  pip install -r old/requirements.txt\n"
                     "[?] or benchmark only this sensor:  --skip-python"
                     % unrunnable)

    workdir = tempfile.mkdtemp(prefix="maltrail-bench-")
    try:
        pcap = os.path.join(workdir, "bench.pcap")
        print("[i] generating %s packets..." % "{:,}".format(options.packets))
        packets = build_mix(options.packets)
        G.write_pcap(pcap, packets)
        total_bytes = sum(len(p) for _, p in packets)
        avg = total_bytes / float(len(packets))
        print("[i] pcap: %.1f MB, %s packets, average %.0f bytes/packet"
              % (os.path.getsize(pcap) / (1024.0 * 1024.0), "{:,}".format(len(packets)), avg))
        print("[i] trails: %s (%.1f MB)" % (options.trails, os.path.getsize(options.trails) / (1024.0 * 1024.0)))

        rows = []
        for label in (["python", "rust"] if not options.skip_python else ["rust"]):
            log_dir = os.path.join(workdir, "logs-" + label)
            os.makedirs(log_dir)
            trails_copy = os.path.join(workdir, "trails-%s.csv" % label)
            shutil.copyfile(options.trails, trails_copy)
            config = os.path.join(workdir, "%s.conf" % label)
            with open(config, "w") as f:
                f.write(CONFIG % {"log_dir": log_dir, "trails_file": trails_copy})

            if label == "python":
                cmd = [options.python, os.path.join(ROOT, "old", "sensor.py"), "-r", pcap, "-c", config, "--offline"]
            else:
                # pcap timestamps: the correct behaviour, and what a live sensor sees
                cmd = [binary, "-r", pcap, "-c", config, "--offline", "--timestamps", "pcap"]

            print("[i] running %s sensor (%d run(s), reporting the fastest)..." % (label, options.repeat))
            best = None
            for attempt in range(max(1, options.repeat)):
                if attempt:
                    shutil.rmtree(log_dir, ignore_errors=True)
                    os.makedirs(log_dir)
                measured = run(cmd, ROOT)
                if measured[5] != 0:
                    # A sensor that exited non-zero processed nothing, and timing it produces
                    # numbers that are not merely wrong but absurd - a 0.24 s "run" of 300,000
                    # packets came out as 1 ns/packet and 1,053,845,226 packets/s, and the
                    # comparison duly reported the Rust sensor as 10x SLOWER. Refuse to report.
                    sys.exit("[!] the %s sensor exited with status %d without doing the work:\n%s\n"
                             "[i] no benchmark is possible until that is fixed."
                             % (label, measured[5], _indent(measured[4])))
                if best is None or measured[0] < best[0]:
                    best = measured
            wall, user, system, rss, output, _rc = best
            events = count_events(log_dir)
            pps = len(packets) / wall if wall > 0 else 0
            rows.append({
                "label": label, "wall": wall, "cpu": user + system, "rss": rss,
                "pps": pps, "events": events, "gbit": pps * avg * 8 / 1e9, "output": output,
            })

        print("")
        print("[i] whole process, INCLUDING startup (trail loading dominates a short replay):")
        print("%-8s %10s %10s %12s %14s %10s %10s" % ("sensor", "wall(s)", "cpu(s)", "packets/s", "Gbit/s(mix)", "peak RSS", "events"))
        print("-" * 82)
        for row in rows:
            print("%-8s %10.2f %10.2f %12s %14.2f %9.0f M %10d"
                  % (row["label"], row["wall"], row["cpu"], "{:,.0f}".format(row["pps"]),
                     row["gbit"], row["rss"] / 1024.0, row["events"]))

        # Startup cost (trail loading, regex compilation) is measured DIRECTLY by replaying a
        # 1-packet pcap with the same trails and config, then subtracted. That is far less noisy
        # than estimating a slope from two large runs, whose difference is dominated by I/O jitter.
        if options.slope:
            print("[i] measuring startup cost with a 1-packet pcap...")
            tiny = os.path.join(workdir, "tiny.pcap")
            G.write_pcap(tiny, build_mix(1))
            for row in rows:
                label = row["label"]
                log_dir = os.path.join(workdir, "logs-startup-" + label)
                os.makedirs(log_dir)
                trails_copy = os.path.join(workdir, "trails-startup-%s.csv" % label)
                shutil.copyfile(options.trails, trails_copy)
                config = os.path.join(workdir, "%s-startup.conf" % label)
                with open(config, "w") as f:
                    f.write(CONFIG % {"log_dir": log_dir, "trails_file": trails_copy})
                if label == "python":
                    cmd = [options.python, os.path.join(ROOT, "old", "sensor.py"), "-r", tiny, "-c", config, "--offline"]
                else:
                    cmd = [binary, "-r", tiny, "-c", config, "--offline", "--timestamps", "pcap"]
                startup = min(run(cmd, ROOT)[0] for _ in range(max(1, options.repeat)))
                row["startup"] = startup
                work = row["wall"] - startup
                # If startup accounts for essentially the whole run there is no steady state left
                # to measure, and dividing by the remainder invents a number. Say so instead.
                row["steady_pps"] = (options.packets / work) if work > 0.05 else 0.0

            print("")
            print("[i] steady state, startup EXCLUDED — this is the per-packet cost:")
            print("%-8s %14s %14s %16s" % ("sensor", "startup(s)", "ns/packet", "steady packets/s"))
            print("-" * 56)
            for row in rows:
                if not row["steady_pps"]:
                    print("%-8s %14.2f %14s %16s"
                          % (row["label"], row["startup"], "unmeasurable", "startup ~= whole run"))
                    continue
                print("%-8s %14.2f %14.0f %16s"
                      % (row["label"], row["startup"],
                         1e9 / row["steady_pps"],
                         "{:,.0f}".format(row["steady_pps"])))
            if len(rows) == 2 and rows[0]["steady_pps"] > 0 and rows[1]["steady_pps"] > 0:
                print("[i] steady-state speedup (startup excluded): %.1fx"
                      % (rows[1]["steady_pps"] / rows[0]["steady_pps"]))
            elif len(rows) == 2:
                print("[!] steady state could not be separated for at least one sensor: the run was")
                print("[!] too short relative to its startup. Raise --packets (try 1000000).")
            print("[i] NOTE: startup is dominated by trail loading, and it is the one place the")
            print("[i]       old sensor wins - it mmaps a prebuilt trails.csv.bin sidecar. So on a")
            print("[i]       SHORT replay the wall-clock ratio above understates the packet path")
            print("[i]       badly; the steady-state row is the number to quote. sensor.py's FIRST")
            print("[i]       run also builds that sidecar, so a cold start is slower still.")

        if len(rows) == 2:
            py, rs = rows[0], rows[1]
            print("")
            print("[i] speedup: %.1fx wall clock, %.1fx CPU time, %.2fx peak RSS"
                  % (py["wall"] / rs["wall"] if rs["wall"] else 0,
                     py["cpu"] / rs["cpu"] if rs["cpu"] else 0,
                     rs["rss"] / float(py["rss"]) if py["rss"] else 0))
            print("[i] events: python=%d rust=%d %s"
                  % (py["events"], rs["events"],
                     "(equal)" if py["events"] == rs["events"] else
                     "(NOTE: sensor.py discards pcap timestamps on Python 3, so its time-based "
                     "suppression and counting heuristics differ offline; see tools/parity.py)"))
            print("[i] NOTE: this is OFFLINE full-sensor replay of one worker each. It measures the")
            print("[i]       packet path, not capture. Live capture and PACKET_FANOUT scaling must be")
            print("[i]       measured on real hardware (tools/fanout_check.py).")
    finally:
        if options.keep:
            print("[i] kept %s" % workdir)
        else:
            shutil.rmtree(workdir, ignore_errors=True)


if __name__ == "__main__":
    main()
