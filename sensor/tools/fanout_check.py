#!/usr/bin/env python3
# coding: utf-8
"""Live-capture and PACKET_FANOUT verification (needs root / CAP_NET_RAW).

Proves the two properties that matter for multi-worker capture:

  1. **Distribution** - with N workers in one fanout group, every worker receives traffic.
  2. **No duplication** - N workers see the same TOTAL packet count as 1 worker does. This is
     the property that breaks if fanout is not actually configured: N independent AF_PACKET
     sockets each receive EVERY packet, so the total would be ~N x the baseline (and every
     detection would be reported N times).

The test is self-calibrating: it runs a 1-worker baseline first and compares against it, so it
does not depend on how many copies of a packet the loopback driver happens to present.

    sudo python3 sensor/tools/fanout_check.py
    sudo python3 sensor/tools/fanout_check.py --interface eth0 --workers 4
    sudo python3 sensor/tools/fanout_check.py --interface lo --workers 8 --packets 20000

On a real interface, supply your own traffic instead of the built-in loopback generator with
`--no-generate` and drive load from elsewhere.
"""
from __future__ import print_function

import argparse
import os
import re
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time

ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))

CONFIG = """\
MONITOR_INTERFACE %(interface)s
CAPTURE_BUFFER 10%%
PROCESS_COUNT 1
UPDATE_PERIOD 999999999
USE_FEED_UPDATES false
DISABLE_CHECK_SUDO true
USE_HEURISTICS false
USE_CONDENSED_STORAGE false
SENSOR_NAME fanout-check
LOG_DIR %(log_dir)s
TRAILS_FILE %(trails_file)s
CAPTURE_FILTER %(filter)s
CAPTURE_WORKERS %(workers)d
CAPTURE_FANOUT_MODE %(mode)s
CAPTURE_TIMEOUT 50
METRICS_INTERVAL 0
"""

# One line per worker in the final summary: "w0=<processed>/<events> w1=..."
WORKER_RE = re.compile(r"w(\d+)=(\d+)/(\d+)")
PROCESSED_RE = re.compile(r"\bprocessed=(\d+)")
RECEIVED_RE = re.compile(r"\breceived=(\d+)")
FANOUT_RE = re.compile(r"PACKET_FANOUT: (.*)")


def generate_traffic(port_base, packets, host_count):
    """Many distinct flows so a HASH fanout has something to spread."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    payload = b"maltrail-fanout-check"
    sent = 0
    for i in range(packets):
        host = "127.0.0.%d" % (1 + (i % host_count))
        port = port_base + (i % 1000)
        try:
            sock.sendto(payload, (host, port))
            sent += 1
        except OSError:
            time.sleep(0.001)
    sock.close()
    return sent


def run_sensor(binary, config, duration, generate, port_base, packets, host_count):
    process = subprocess.Popen([binary, "-c", config], cwd=ROOT,
                               stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    lines = []

    def reader():
        for line in process.stdout:
            lines.append(line.decode("utf8", "replace").rstrip("\n"))

    thread = threading.Thread(target=reader)
    thread.daemon = True
    thread.start()

    # let the capture handles come up
    time.sleep(1.5)
    sent = 0
    if generate:
        sent = generate_traffic(port_base, packets, host_count)
    time.sleep(duration)

    process.send_signal(signal.SIGTERM)
    try:
        process.wait(timeout=15)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()
    thread.join(timeout=5)
    return sent, lines


def parse_summary(lines):
    """Returns (total_processed, {worker: processed}, fanout_line, received)."""
    per_worker, total, received, fanout = {}, None, None, None
    for line in lines:
        if "PACKET_FANOUT:" in line:
            match = FANOUT_RE.search(line)
            if match:
                fanout = match.group(1)
        if "metrics:" in line:
            match = PROCESSED_RE.search(line)
            if match:
                total = int(match.group(1))
            match = RECEIVED_RE.search(line)
            if match:
                received = int(match.group(1))
            found = WORKER_RE.findall(line)
            if found:
                per_worker = dict((int(w), int(p)) for w, p, _e in found)
    return total, per_worker, fanout, received


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--interface", default="lo")
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument("--packets", type=int, default=20000)
    parser.add_argument("--hosts", type=int, default=64, help="distinct loopback destinations (flow spread)")
    parser.add_argument("--duration", type=float, default=3.0, help="seconds to keep capturing after sending")
    parser.add_argument("--profile", default="release")
    parser.add_argument("--mode", default="hash", choices=("hash", "lb", "cpu", "rollover", "random", "qm"))
    parser.add_argument("--no-generate", action="store_true", help="do not generate traffic (drive it yourself)")
    parser.add_argument("--tolerance", type=float, default=0.35,
                        help="allowed relative difference between the 1-worker and N-worker totals")
    options = parser.parse_args()

    binary = os.path.join(ROOT, "sensor", "target", options.profile, "maltrail-sensor")
    if not os.path.isfile(binary):
        sys.exit("[!] build first: cargo build --release --manifest-path sensor/Cargo.toml")
    if os.geteuid() != 0:
        # A file capability on the binary works too, so this is a warning rather than a refusal:
        #   sudo setcap 'cap_net_raw,cap_net_admin+eip' sensor/target/release/maltrail-sensor
        print("[?] not running as root; this only works if the sensor binary carries CAP_NET_RAW")
    if options.workers < 2:
        sys.exit("[!] --workers must be >= 2 to test fanout")

    workdir = tempfile.mkdtemp(prefix="maltrail-fanout-")
    try:
        trails_file = os.path.join(workdir, "trails.csv")
        with open(trails_file, "w") as f:
            f.write("fanout-check-never-matches.invalid,test,(static)\n")

        port_base = 30000
        bpf = "udp and dst portrange %d-%d" % (port_base, port_base + 999)

        results = {}
        for workers in (1, options.workers):
            log_dir = os.path.join(workdir, "logs-%d" % workers)
            os.makedirs(log_dir)
            config = os.path.join(workdir, "sensor-%d.conf" % workers)
            with open(config, "w") as f:
                f.write(CONFIG % {
                    "interface": options.interface,
                    "log_dir": log_dir,
                    "trails_file": trails_file,
                    "filter": bpf,
                    "workers": workers,
                    "mode": options.mode,
                })

            print("[i] run with %d worker(s) on '%s'..." % (workers, options.interface))
            sent, lines = run_sensor(binary, config, options.duration, not options.no_generate,
                                     port_base, options.packets, options.hosts)
            total, per_worker, fanout, received = parse_summary(lines)
            if total is None:
                print("\n".join(lines))
                sys.exit("[!] the sensor produced no metrics line; see the output above")
            results[workers] = {"sent": sent, "total": total, "per_worker": per_worker,
                                "fanout": fanout, "received": received}
            print("    sent=%d received=%s processed=%d fanout=%s"
                  % (sent, received, total, fanout))
            print("    per worker: %s" % ", ".join("w%d=%d" % kv for kv in sorted(per_worker.items())))

        one, many = results[1], results[options.workers]
        failures = []

        # 1. distribution
        active = [w for w, count in many["per_worker"].items() if count > 0]
        if len(many["per_worker"]) != options.workers:
            failures.append("expected %d worker slots, saw %d" % (options.workers, len(many["per_worker"])))
        if len(active) < 2:
            failures.append("only %d worker(s) received traffic - fanout is not distributing "
                            "(single flow? try more --hosts)" % len(active))

        # 2. no duplication: N workers must see the SAME total as one worker, not N x
        if one["total"] == 0:
            failures.append("the 1-worker baseline captured nothing; check the interface and filter")
        else:
            ratio = many["total"] / float(one["total"])
            print("\n[i] total processed: 1 worker=%d, %d workers=%d (ratio %.2f)"
                  % (one["total"], options.workers, many["total"], ratio))
            if ratio > 1.0 + options.tolerance:
                failures.append("N workers processed %.2fx the 1-worker total - packets are being "
                                "DUPLICATED across sockets (fanout not in effect)" % ratio)
            if ratio < 1.0 - options.tolerance:
                failures.append("N workers processed only %.2fx the 1-worker total - packets are "
                                "being LOST" % ratio)

        # 3. fanout must actually be reported as enabled
        if not many["fanout"] or "enabled" not in many["fanout"]:
            failures.append("the sensor did not report PACKET_FANOUT as enabled: %r" % many["fanout"])

        print("")
        if failures:
            for item in failures:
                print("[!] %s" % item)
            print("[!] fanout check: FAILED")
            return 1
        print("[i] distribution: %d/%d workers received traffic" % (len(active), options.workers))
        print("[i] no duplication: N-worker total matches the 1-worker baseline")
        print("[i] fanout: %s" % many["fanout"])
        print("[i] fanout check: PASSED")
        return 0
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
