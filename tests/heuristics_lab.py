#!/usr/bin/env python
# coding: utf-8
"""Tunable battle-test lab for Maltrail's windowed heuristics.

Synthesizes scan / exhaustion / benign traffic with knobs, runs it through the REAL
sensor._process_packet, and faithfully models the multiprocessing round-robin (each of N workers
gets every Nth packet with its OWN heuristic state, like core/parallel.worker()'s `count % mod`),
then reports what Maltrail detected, missed, or false-flagged. Turn the knobs and watch.

Examples:
  python tests/heuristics_lab.py                                  # full battery
  python tests/heuristics_lab.py --scenario port_scan --workers 16 --size 50 --rate 200 --duration 1
  python tests/heuristics_lab.py --sweep workers --scenario port_scan --size 60
  python tests/heuristics_lab.py --sweep rate    --scenario web_scan  --size 30
  python tests/heuristics_lab.py --scenario port_scan --src-local --dst-local   # internal recon
  python tests/heuristics_lab.py --scenario benign --workers 8                   # FP probe

Knobs: --scenario --workers --size --rate(pkts/s) --duration(s) --src-local/--dst-local
       --port-threshold/--web-threshold/--infection-threshold/--dns-threshold (override constants)
       --disabled "port_scanning,dns_exhaustion"
"""
import os
import sys
import argparse

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _pcapgen as G
import sensor
from core.enums import TRAIL

ETH = lambda ip: G.eth() + ip          # ip_offset = 14
IP_OFFSET = 14

EXT_SRC = "203.0.113.%d"               # TEST-NET-3, non-whitelisted "attacker"
EXT_DST = "198.51.100.%d"              # TEST-NET-2 "victim"
INT_SRC = "10.0.0.%d"
INT_DST = "10.0.9.%d"


def _syn(src, dst, dport):
    return ETH(G.ipv4(6, src, dst, G.tcp(40000, dport, 0x02, b"")))

def _tcp_flag(src, dst, dport, flags):
    return ETH(G.ipv4(6, src, dst, G.tcp(40000, dport, flags, b"")))

def _udp_pkt(src, dst, dport):
    return ETH(G.ipv4(17, src, dst, G.udp(40000, dport, b"\x00" * 8)))

def _http_get(src, dst, seg):
    payload = ("GET /%s/x HTTP/1.1\r\nHost: %s\r\nUser-Agent: lab\r\n\r\n" % (seg, dst)).encode()
    return ETH(G.ipv4(6, src, dst, G.tcp(40000, 80, 0x18, payload)))   # PSH+ACK (not SYN)

def _dns_q(src, dst, name):
    import struct
    hdr = struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
    q = b""
    for label in name.split('.'):
        q += struct.pack("!B", len(label)) + label.encode()
    q += b"\x00" + struct.pack("!HH", 1, 1)
    return ETH(G.ipv4(17, src, dst, G.udp(40000, 53, hdr + q)))

def _tick():
    # benign packet in a later second -> forces the per-second sweep; itself triggers nothing
    return ETH(G.ipv4(17, "192.0.2.1", "192.0.2.2", G.udp(1111, 2222, b"\x00" * 8)))


def _timed(packets, rate, t0=0.0):
    """Spread packets over time at `rate` pkts/sec -> list of (sec, usec, packet)."""
    out = []
    for i, p in enumerate(packets):
        t = t0 + (i / float(rate) if rate > 0 else 0)
        out.append((int(t), int((t - int(t)) * 1e6), p))
    return out


def build(scenario, size, rate, duration, src_local, dst_local):
    src_t = INT_SRC if src_local else EXT_SRC
    dst_t = INT_DST if dst_local else EXT_DST
    src = src_t % 5
    dst = dst_t % 7
    pkts = []
    if scenario == "port_scan":
        pkts = [_syn(src, dst, 1000 + i) for i in range(size)]          # one src -> one dst, N ports
    elif scenario in ("stealth_fin", "stealth_null", "stealth_xmas", "stealth_ack"):
        fl = {"stealth_fin": 0x01, "stealth_null": 0x00, "stealth_xmas": 0x29, "stealth_ack": 0x10}[scenario]
        pkts = [_tcp_flag(src, dst, 1000 + i, fl) for i in range(size)]  # stealth scan flag probes
    elif scenario == "udp_scan":
        pkts = [_udp_pkt(src, dst, 1000 + i) for i in range(size)]       # one src -> one dst, N UDP ports
    elif scenario == "udp_benign":
        pkts = [_udp_pkt(src, EXT_DST % (i % 50), 443) for i in range(size)]  # QUIC-like: 1 port, many dsts (must be CLEAN)
    elif scenario == "web_scan":
        pkts = [_http_get(src, dst, "seg%d" % i) for i in range(size)]  # N distinct first path segments
    elif scenario == "infection":
        pkts = [_syn(src, dst_t % (i + 2), 445) for i in range(size)]   # one src -> N hosts, port 445
    elif scenario == "dns_exhaustion":
        pkts = [_dns_q(src, "10.0.0.53", "h%d.victim.com" % i) for i in range(size)]
    elif scenario == "benign":
        # realistic benign: a few hosts, few ports, normal browsing (must stay FP-free)
        pkts = []
        for i in range(size):
            pkts.append(_syn(INT_SRC % (i % 4), EXT_DST % (i % 3), 443))         # https
            pkts.append(_http_get(INT_SRC % (i % 4), EXT_DST % (i % 3), "static"))  # one path segment
    else:
        raise SystemExit("unknown scenario %r" % scenario)
    return _timed(pkts, rate)


def _reset(detections):
    sensor.config.USE_HEURISTICS = True
    sensor.config.plugin_functions = None
    sensor.config.CHECK_HOST_DOMAINS = False
    sensor.WHITELIST = set()
    sensor._result_cache = {}
    sensor._connect_src_dst = {}
    sensor._connect_src_details = {}
    sensor._path_src_dst = {}
    sensor._path_src_dst_details = {}
    sensor._subdomains = sensor._subdomains.__class__() if hasattr(sensor, "_subdomains") else {}
    try:
        sensor._dns_exhausted_domains.clear()
    except Exception:
        pass
    sensor._connect_sec = 0
    sensor._scan_window_start = 0
    sensor._scan_alerted = set()
    sensor._path_alerted = set()
    sensor._udp_scan = {}
    sensor._udp_scan_details = {}
    sensor._udp_alerted = set()
    sensor._subdomains_sec = 0
    for g in ("_last_syn", "_last_logged_syn", "_last_udp", "_last_logged_udp"):
        setattr(sensor, g, None)
    sensor._disabled_heuristics_cache[0] = None
    sensor.log_event = lambda event, packet=None, **kw: detections.append(event)


def _worker_of(event, i, workers, affinity):
    if not affinity:
        return i % workers                                 # round-robin by arrival (real ring today)
    # source-affinity: route by src IP so one worker sees a whole scan (models the proposed fix)
    src = event[2][IP_OFFSET + 12:IP_OFFSET + 16]          # IPv4 src bytes
    return (sum(bytearray(src)) if src else 0) % workers


def run(events, workers, affinity=False):
    """Distribute `events` across `workers` independent heuristic states (round-robin, or by
    source IP when affinity=True) and return all detections."""
    last_sec = max((e[0] for e in events), default=0)
    dets = []
    for w in range(workers):
        sub = [e for i, e in enumerate(events) if _worker_of(e, i, workers, affinity) == w]
        if not sub:
            continue
        _reset(dets)
        for sec, usec, pkt in sub:
            sensor._process_packet(pkt, sec, usec, IP_OFFSET)
        sensor._process_packet(_tick(), last_sec + 2, 0, IP_OFFSET)   # flush this worker's window
    return dets


def _apply_thresholds(args):
    if args.port_threshold is not None:      sensor.PORT_SCANNING_THRESHOLD = args.port_threshold
    if args.web_threshold is not None:       sensor.WEB_SCANNING_THRESHOLD = args.web_threshold
    if args.infection_threshold is not None: sensor.INFECTION_SCANNING_THRESHOLD = args.infection_threshold
    if args.dns_threshold is not None:       sensor.DNS_EXHAUSTION_THRESHOLD = args.dns_threshold
    if args.disabled is not None:            sensor.config.DISABLED_HEURISTICS = args.disabled


_EXPECT = {"port_scan": TRAIL.IP, "web_scan": TRAIL.PATH, "infection": TRAIL.PORT, "dns_exhaustion": TRAIL.DNS,
           "stealth_fin": TRAIL.IP, "stealth_null": TRAIL.IP, "stealth_xmas": TRAIL.IP, "stealth_ack": TRAIL.IP,
           "udp_scan": TRAIL.IP, "udp_benign": TRAIL.IP}


def one(args, scenario=None, workers=None, size=None, rate=None):
    scenario = scenario or args.scenario
    workers = workers or args.workers
    size = size if size is not None else args.size
    rate = rate or args.rate
    events = build(scenario, size, rate, args.duration, args.src_local, args.dst_local)
    dets = run(events, workers, affinity=args.affinity)
    if scenario in ("benign", "udp_benign"):
        fp = len(dets)
        return {"events": len(events), "detections": fp, "fp": fp, "verdict": "CLEAN" if fp == 0 else "FALSE POSITIVE x%d" % fp}
    want = _EXPECT[scenario]
    hits = [e for e in dets if e[7] == want]
    return {"events": len(events), "detections": len(dets), "tp": len(hits),
            "verdict": "DETECTED (%d ev)" % len(hits) if hits else "MISSED"}


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--scenario", default=None)
    p.add_argument("--workers", type=int, default=1)
    p.add_argument("--size", type=int, default=50)
    p.add_argument("--rate", type=float, default=1000.0)
    p.add_argument("--duration", type=float, default=1.0)
    p.add_argument("--src-local", action="store_true")
    p.add_argument("--dst-local", action="store_true")
    p.add_argument("--port-threshold", type=int, default=None)
    p.add_argument("--web-threshold", type=int, default=None)
    p.add_argument("--infection-threshold", type=int, default=None)
    p.add_argument("--dns-threshold", type=int, default=None)
    p.add_argument("--disabled", default=None)
    p.add_argument("--affinity", action="store_true", help="route packets to workers by src IP (models source-affinity fix)")
    p.add_argument("--sweep", default=None, choices=["workers", "rate", "size"])
    args = p.parse_args()
    _apply_thresholds(args)

    if args.sweep:
        scenario = args.scenario or "port_scan"
        grid = {"workers": [1, 2, 4, 8, 16], "rate": [5, 10, 25, 100, 1000], "size": [10, 20, 40, 80, 160]}[args.sweep]
        print("# sweep %s | scenario=%s size=%d rate=%g workers=%d" % (args.sweep, scenario, args.size, args.rate, args.workers))
        print("%-10s %-9s %-9s %s" % (args.sweep, "events", "detect", "verdict"))
        for v in grid:
            kw = {args.sweep: v}
            r = one(args, scenario=scenario, **kw)
            print("%-10s %-9d %-9d %s" % (v, r["events"], r["detections"], r["verdict"]))
        return

    if args.scenario:
        r = one(args)
        print("scenario=%s workers=%d size=%d rate=%g -> %s (events=%d, total_logged=%d)" %
              (args.scenario, args.workers, args.size, args.rate, r["verdict"], r["events"], r["detections"]))
        return

    # default battery
    print("== Maltrail heuristics battle-test (default battery) ==")
    print("%-16s %-8s %-6s %-6s %s" % ("scenario", "workers", "size", "rate", "verdict"))
    battery = [
        ("port_scan", 1, 50, 1000), ("port_scan", 16, 50, 1000), ("port_scan", 16, 200, 1000),
        ("web_scan", 1, 30, 1000), ("web_scan", 16, 30, 1000),
        ("infection", 1, 50, 1000), ("infection", 16, 50, 1000),
        ("benign", 1, 40, 1000), ("benign", 16, 40, 1000),
    ]
    for sc, w, sz, rt in battery:
        r = one(args, scenario=sc, workers=w, size=sz, rate=rt)
        print("%-16s %-8d %-6d %-6g %s" % (sc, w, sz, rt, r["verdict"]))


if __name__ == "__main__":
    main()
