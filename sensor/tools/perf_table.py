#!/usr/bin/env python3
# coding: utf-8

"""The README's "Time per packet" table, measured rather than remembered.

    python3 sensor/tools/perf_table.py                 # build, replay, print the table
    python3 sensor/tools/perf_table.py --runs 3        # quicker, noisier
    python3 sensor/tools/perf_table.py --conf my.conf  # a different configuration

WHERE THE PACKETS COME FROM. Every row is cut out of refnet (`sensor/tools/refnet.py`), the
synthetic reference network the detection numbers come from, generated first if `refnet-run/`
is missing. Rows refnet does not carry are built from refnet's own flows and say how:

    ICMP echo, TCP SYN, TLS ClientHello, warm DNS, the whole mix   refnet's packets as they are
    DNS with unique names    refnet's queries, the first label rewritten so no name repeats
    bulk TLS                 refnet's TLS flows, server to client, payload grown to the frame size
    HTTP request             refnet's TLS flows sent to port 80 as a GET for the ClientHello's SNI

Each row is repeated until it has `--packets` packets, so the timer's millisecond resolution is
noise, and re-stamped at `--rate` packets per second of capture time, in refnet's order. Refnet
is a quiet network - its ICMP arrives at 5 packets a second - and the sensor's heuristics sweep
runs once per second of capture time, so at refnet's own pace a sweep landed every 5 packets and
the table measured the sweep, not the packet. A per-packet cost is a busy link's question.

WHAT IS TIMED. The sensor's per-file line, "<file>: ... (N packet(s), E event(s)) in X s", which
the worker measures from opening the file to its end: libpcap read, DLT, packet path, event
writing. Trail loading and the final flush of the condensed store are outside it. Runs are
interleaved across rows, so drift on the machine lands on every row alike, and pinned to one CPU.

WHY IT REFUSES THINGS. Every number this table ever printed by hand was wrong at least once in a
way nobody saw: a sensor that had exited, a timer that rounded to 50 ms, a benchmark of a
configuration nobody runs. So the tool stops rather than print a number when
  * the sensor did not report the whole file (a crash, an early exit, a parse failure),
  * the whole-mix replay found nothing, or not the same thing every run (the positive control),
  * a row ran under --min-seconds (resolution), or its middle runs spread more than --max-spread,
  * every run of a row landed on the same 50 ms step (the quantization this tool was written after).
The configuration is the shipped default unless --conf says otherwise, and the header says which.
"""

import argparse
import os
import platform
import re
import shutil
import statistics
import struct
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT)

from core.tls_intel import parse_client_hello  # noqa: E402

PCAP_HEADER = struct.Struct("<IHHiIII")
RECORD = struct.Struct("<IIII")
REPORT = re.compile(r"\] (\S+): .*?\((\d+) packet\(s\), (\d+) event\(s\)\) in ([0-9.]+)s")


def read_pcap(path):
    """[(sec, usec, frame)] of an Ethernet pcap."""

    with open(path, "rb") as f:
        head = f.read(24)
        magic, _, _, _, _, _, link = PCAP_HEADER.unpack(head)
        if magic != 0xa1b2c3d4 or link != 1:
            sys.exit("[!] %s: expected a microsecond little-endian Ethernet pcap (refnet's)" % path)
        packets = []
        while True:
            rec = f.read(16)
            if len(rec) < 16:
                break
            sec, usec, caplen, _ = RECORD.unpack(rec)
            packets.append((sec, usec, f.read(caplen)))
    return packets


def ipv4(frame):
    """(ihl, protocol, l4) of an untagged IPv4 Ethernet frame, or None."""

    if len(frame) < 34 or frame[12:14] != b"\x08\x00" or frame[14] >> 4 != 4:
        return None
    ihl = (frame[14] & 15) * 4
    return ihl, frame[23], frame[14 + ihl:]


def checksum(data):
    if len(data) % 2:
        data += b"\0"
    s = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    return ~s & 0xffff


def rebuild(frame, ihl, l4):
    """`frame` with its transport part replaced by `l4`: IPv4 length and checksum fixed."""

    ip = bytearray(frame[14:14 + ihl])
    ip[2:4] = struct.pack("!H", ihl + len(l4))
    ip[10:12] = b"\0\0"
    ip[10:12] = struct.pack("!H", checksum(bytes(ip)))
    return frame[:14] + bytes(ip) + l4


def swap(frame, ihl, l4):
    """The same TCP segment in the other direction: MACs, addresses and ports exchanged."""

    ip = bytearray(frame[14:14 + ihl])
    ip[12:16], ip[16:20] = ip[16:20], ip[12:16]
    tcp = bytearray(l4)
    tcp[0:2], tcp[2:4] = tcp[2:4], tcp[0:2]
    return frame[6:12] + frame[0:6] + frame[12:14] + bytes(ip), bytes(tcp)


def dns_query(l4):
    """(qname offset in the UDP payload, first label length) of a DNS query, or None."""

    if len(l4) < 8 + 13 or 53 not in struct.unpack("!HH", l4[:4]):
        return None
    dns = l4[8:]
    if dns[2] & 0x80:                       # a response
        return None
    return 12, dns[12]


def qname(l4):
    dns, i, labels = l4[8:], 12, []
    while i < len(dns) and dns[i]:
        labels.append(dns[i + 1:i + 1 + dns[i]])
        i += 1 + dns[i]
    return b".".join(labels)


def tcp_payload(l4):
    return l4[(l4[12] >> 4) * 4:] if len(l4) >= 20 else b""


BASE36 = "0123456789abcdefghijklmnopqrstuvwxyz"


def rows_from(packets):
    """{row: [(sec, usec, frame)]}: the base packets of each row, with their own timestamps."""

    icmp, syn, hello, warm, unique, mix = [], [], [], [], [], []
    seen = set()
    for packet in packets:
        frame = packet[2]
        mix.append(packet)
        parsed = ipv4(frame)
        if not parsed:
            continue
        ihl, proto, l4 = parsed
        if proto == 1 and l4[:1] == b"\x08":
            icmp.append(packet)
        elif proto == 6 and len(l4) >= 20:
            if l4[13] & 0x12 == 0x02:
                syn.append(packet)
            elif struct.unpack("!H", l4[2:4])[0] == 443 and tcp_payload(l4)[:1] == b"\x16":
                hello.append(packet)
        elif proto == 17:
            q = dns_query(l4)
            if q:
                name = qname(l4)
                if name in seen:
                    warm.append(packet)
                seen.add(name)
                if q[1] >= 4:
                    unique.append(packet)
    return {"icmp": icmp, "syn": syn, "hello": hello, "warm": warm, "unique": unique, "mix": mix}


def bulk_tls(frame, size):
    """A ClientHello's flow, turned around: the server's 1,473-byte (by default) application data."""

    ihl, _, l4 = ipv4(frame)
    head, tcp = swap(frame, ihl, l4)
    tcp = bytearray(tcp[:20])
    tcp[12] = 0x50
    tcp[13] = 0x18                          # PSH|ACK
    record_len = size - 14 - ihl - 20 - 5
    payload = b"\x17\x03\x03" + struct.pack("!H", record_len) + bytes(record_len)
    return rebuild(head + frame[14 + ihl:14 + ihl], ihl, bytes(tcp) + payload)


def http_request(frame):
    """A ClientHello's flow, sent to port 80 as a GET for the name the ClientHello carried."""

    ihl, _, l4 = ipv4(frame)
    sni = parse_client_hello(tcp_payload(l4)).get("sni") or "www.example.org"
    tcp = bytearray(l4[:20])
    tcp[2:4] = struct.pack("!H", 80)
    tcp[12] = 0x50
    tcp[13] = 0x18
    req = ("GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n"
           "Accept: */*\r\n\r\n" % sni).encode()
    return rebuild(frame, ihl, bytes(tcp) + req)


def unique_name(frame, n):
    """A DNS query whose first label begins with `n` in base 36: the same length, never repeated."""

    ihl, _, l4 = ipv4(frame)
    l4 = bytearray(l4)
    digits = ""
    for _ in range(4):
        n, r = divmod(n, 36)
        digits = BASE36[r] + digits
    l4[8 + 13:8 + 13 + 4] = digits.encode()
    l4[6:8] = b"\0\0"                       # UDP checksum: none, which IPv4 allows
    return frame[:14 + ihl] + bytes(l4)


def write_row(path, base, rate, target, transform=None):
    """`base` repeated until `target` packets, `rate` packets per second; returns (packets, avg bytes)."""

    count = total = 0
    with open(path, "wb") as f:
        f.write(PCAP_HEADER.pack(0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        start = base[0][0]
        while count < target:
            for (_, _, frame) in base:
                if count >= target:
                    break
                if transform:
                    frame = transform(frame, count)
                sec, usec = divmod(count * 1000000 // rate, 1000000)
                f.write(RECORD.pack(start + sec, usec, len(frame), len(frame)) + frame)
                count += 1
                total += len(frame)
    return count, total // max(count, 1)


def replay(sensor, conf, pcap, cpu):
    cmd = [sensor, "-c", conf, "--offline", "-r", pcap]
    if cpu is not None and shutil.which("taskset"):
        cmd = ["taskset", "-c", str(cpu)] + cmd
    out = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True).stdout
    for m in REPORT.finditer(out):
        if os.path.basename(m.group(1)) == os.path.basename(pcap):
            return int(m.group(2)), int(m.group(3)), float(m.group(4))
    sys.exit("[!] the sensor reported nothing for %s - it did not run to the end:\n%s" % (pcap, out[-1500:]))


def default_conf(workdir, trails):
    path = os.path.join(workdir, "perf.conf")
    logs = os.path.join(workdir, "logs")
    os.makedirs(logs, exist_ok=True)
    with open(os.path.join(ROOT, "maltrail.conf")) as f:
        shipped = f.read()
    with open(path, "w") as f:
        f.write(shipped)
        # the shipped file, with only what an offline replay in a scratch directory needs
        f.write("\nLOG_DIR %s\nTRAILS_FILE %s\nUPDATE_PERIOD 999999999\nDISABLE_CHECK_SUDO true\n" % (logs, trails))
    return path


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--sensor", default=os.path.join(ROOT, "sensor", "target", "release", "maltrail-sensor"))
    parser.add_argument("--refnet", default=os.path.join(ROOT, "refnet-run"), help="refnet output directory")
    parser.add_argument("--conf", default=None, help="sensor configuration (default: the shipped maltrail.conf)")
    parser.add_argument("--packets", type=int, default=1000000, help="packets per row (bulk TLS: a third)")
    parser.add_argument("--runs", type=int, default=7)
    parser.add_argument("--rate", type=int, default=100000, help="packets per second of capture time")
    parser.add_argument("--cpu", type=int, default=(os.cpu_count() or 1) - 1, help="CPU to pin to (-1: none)")
    parser.add_argument("--min-seconds", type=float, default=0.1, help="the timer resolves 1 ms: 0.1 s is 1%%")
    parser.add_argument("--max-spread", type=float, default=0.05,
                        help="spread allowed per row, fastest and slowest run left out: one stray run neither passes nor fails a row")
    parser.add_argument("--workdir", default=None, help="for the row pcaps (default: a temporary directory)")
    parser.add_argument("--keep", action="store_true", help="keep the work directory")
    args = parser.parse_args()

    if not os.access(args.sensor, os.X_OK):
        sys.exit("[!] no sensor binary at %s (cargo build --release --manifest-path sensor/Cargo.toml)" % args.sensor)
    pcap = os.path.join(args.refnet, "network.pcap")
    trails = os.path.join(args.refnet, "trails.csv")
    if not os.path.isfile(pcap) or not os.path.isfile(trails):
        print("[i] no refnet capture in %s; generating it" % args.refnet)
        subprocess.check_call([sys.executable, os.path.join(ROOT, "sensor", "tools", "refnet.py"), "--generate", "--out", args.refnet])

    workdir = args.workdir or tempfile.mkdtemp(prefix="maltrail-perf-")
    os.makedirs(workdir, exist_ok=True)
    try:
        conf = args.conf or default_conf(workdir, trails)
        cpu = None if args.cpu < 0 else args.cpu
        packets = read_pcap(pcap)
        base = rows_from(packets)

        def remade(rows, make):
            return [(sec, usec, make(frame)) for sec, usec, frame in rows]

        specs = [
            ("ICMP echo", "refnet", base["icmp"], None, args.packets),
            ("TCP SYN", "refnet", base["syn"], None, args.packets),
            ("TLS ClientHello", "refnet", base["hello"], None, args.packets),
            ("Bulk TLS", "refnet's TLS flows, server to client", remade(base["hello"], lambda f: bulk_tls(f, 1473)), None, args.packets // 3),
            ("DNS query with a warm cache", "refnet, names already queried", base["warm"], None, args.packets),
            ("DNS query with a unique name", "refnet's queries, first label made unique", base["unique"], unique_name, args.packets),
            ("HTTP request", "refnet's TLS flows, as a GET for their SNI", remade(base["hello"], http_request), None, args.packets),
            ("Refnet mix", "the whole capture", base["mix"], None, args.packets),
        ]
        rows = []
        for i, (name, how, frames, transform, target) in enumerate(specs):
            if not frames:
                sys.exit("[!] refnet has no packets for the '%s' row" % name)
            path = os.path.join(workdir, "row%d.pcap" % i)
            count, avg = write_row(path, frames, args.rate, target, transform)
            rows.append({"name": name, "how": how, "path": path, "packets": count, "avg": avg, "times": [], "events": set()})

        version = subprocess.run([args.sensor, "--version"], stdout=subprocess.PIPE, universal_newlines=True).stdout.strip()
        print("[i] %s, %s; %s; %d run(s) per row, interleaved, pinned to CPU %s; %s packets/s of capture time" % (
            version, _rev(), "shipped maltrail.conf" if not args.conf else args.conf, args.runs, cpu, "{:,}".format(args.rate)))
        for run in range(args.runs):
            for row in rows:
                got, events, seconds = replay(args.sensor, conf, row["path"], cpu)
                if got != row["packets"]:
                    sys.exit("[!] %s: the sensor read %d of %d packets" % (row["name"], got, row["packets"]))
                row["times"].append(seconds)
                row["events"].add(events)
            print("[i] run %d/%d done" % (run + 1, args.runs), file=sys.stderr)

        mix = rows[-1]
        if mix["events"] == {0} or len(mix["events"]) != 1:
            sys.exit("[!] positive control failed: the refnet mix produced %s event(s) across runs" % sorted(mix["events"]))

        problems = []
        for row in rows:
            t = row["times"]
            median = statistics.median(t)
            if median < args.min_seconds:
                problems.append("%s: %.3f s per run is under --min-seconds %.2f" % (row["name"], median, args.min_seconds))
            inner = sorted(t)[1:-1] if len(t) >= 5 else sorted(t)
            row["spread"] = (inner[-1] - inner[0]) / median
            if row["spread"] > args.max_spread:
                problems.append("%s: runs spread %.0f%% (%s)" % (row["name"], 100 * row["spread"], " ".join("%.3f" % x for x in t)))
            if len(t) > 1 and all(abs(x / 0.05 - round(x / 0.05)) < 1e-6 for x in t):
                problems.append("%s: every run is a multiple of 50 ms - a quantized timer, not a measurement" % row["name"])
            row["ns"] = median / row["packets"] * 1e9

        print()
        print("| Traffic | Time per packet |")
        print("| --- | ---: |")
        for row in rows:
            size = ("{:,}-byte average" if row["name"] == "Refnet mix" else "{:,} bytes").format(row["avg"])
            print("| %s, %s | %s ns |" % (row["name"], size, "{:,.0f}".format(row["ns"])))
        print()
        for row in rows:
            print("[i] %-30s %s; %s packets, %s event(s), %.3f s per run, spread %.1f%%" % (
                row["name"], row["how"], "{:,}".format(row["packets"]), "/".join(str(e) for e in sorted(row["events"])),
                statistics.median(row["times"]), 100 * row["spread"]))
        if problems:
            print()
            for p in problems:
                print("[!] %s" % p)
            sys.exit(1)
    finally:
        if not args.keep and not args.workdir:
            shutil.rmtree(workdir, ignore_errors=True)


def _rev():
    try:
        return subprocess.run(["git", "-C", ROOT, "describe", "--always", "--dirty"], stdout=subprocess.PIPE,
                              universal_newlines=True).stdout.strip()
    except OSError:
        return "?"


if __name__ == "__main__":
    main()
