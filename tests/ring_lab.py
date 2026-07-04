#!/usr/bin/env python
# coding: utf-8
"""Real-worker battle test: drives core/parallel's ACTUAL shared-memory ring with REAL forked
worker processes (separate memory, like production multiprocessing), feeds a synthetic scan, and
counts how many detections come back. This measures the genuine per-worker state fragmentation on
the real machinery -- not an in-process model -- and is the harness any ring/heuristics fix must
pass.

  python tests/ring_lab.py [n_workers] [scan_ports]      # default: sweep 1,2,4,8

A port scan is ONE src hitting `scan_ports` ports on ONE dst. With the round-robin ring each worker
sees ~ports/N -> detection needs ports > PORT_SCANNING_THRESHOLD * N. Watch detection collapse as N
rises. (Linux/fork only.)
"""
import os
import sys
import time
import struct
import multiprocessing

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _pcapgen as G

IP_OFFSET = 14
SCAN_SRC = "203.0.113.9"          # external (non-whitelisted) scanner
SCAN_DST = "198.51.100.7"         # external victim (avoids any local-prefix interplay)


def _syn(dport):
    return G.eth() + G.ipv4(6, SCAN_SRC, SCAN_DST, G.tcp(40000, dport, 0x02, b""))

def _tick():
    # same src as the scan, so under source-affinity it lands on the SAME worker and triggers that
    # worker's per-second sweep (real traffic always advances the second; the synthetic test must too)
    return G.eth() + G.ipv4(17, SCAN_SRC, "192.0.2.2", G.udp(1, 2, b"\x00" * 8))


def measure(n_workers, scan_ports, buffer_mb=32, affinity=False):
    """Spin n_workers real processes over the real ring; return number of port-scan detections.
    affinity=True routes each packet to worker (hash(src) % N) by skip-padding the ring -- the same
    mechanism the sensor's CAPTURE_AFFINITY uses (no change to the worker/ring code)."""
    import sensor
    from core.settings import config
    from core import parallel
    import mmap

    # --- configure the sensor globals the workers will inherit via fork ---
    config.USE_HEURISTICS = True
    config.PROCESS_COUNT = n_workers + 1          # parent + N workers (sensor's own convention)
    config.CAPTURE_BUFFER = buffer_mb * 1024 * 1024
    config.plugin_functions = None
    config.UPDATE_PERIOD = 10 ** 9                # never let the worker's reload timer fire
    sensor.WHITELIST = set()
    sensor._result_cache = {}
    sensor._connect_src_dst = {}
    sensor._connect_src_details = {}
    sensor._path_src_dst = {}
    sensor._path_src_dst_details = {}
    sensor._connect_sec = 0
    sensor._scan_window_start = 0
    sensor._scan_alerted = set()
    sensor._path_alerted = set()
    sensor._udp_scan = {}
    sensor._udp_scan_details = {}
    sensor._udp_alerted = set()
    for g in ("_last_syn", "_last_logged_syn", "_last_udp", "_last_logged_udp"):
        setattr(sensor, g, None)

    q = multiprocessing.Queue()
    # detections captured in EACH worker -> pushed over the queue (inherited via fork)
    sensor.log_event = lambda event, packet=None, **kw: q.put(event[7])   # event[7] = TRAIL type

    buf = mmap.mmap(-1, config.CAPTURE_BUFFER)
    buf.write(b"\x00" * config.CAPTURE_BUFFER); buf.seek(0)
    n = multiprocessing.Value('L', lock=False)

    procs = []
    for i in range(n_workers):
        p = multiprocessing.Process(target=parallel.worker, args=(buf, n, i, n_workers, sensor._process_packet))
        p.daemon = True
        p.start()
        procs.append(p)

    def emit(packet, sec):
        block = struct.pack("=III", sec, 0, IP_OFFSET) + packet
        if affinity and n_workers > 1:
            target = sensor._src_hash(packet, IP_OFFSET) % n_workers   # the REAL sensor routing fn
            while n.value % n_workers != target:          # skip-pad: empty blocks consumed by their modulo-worker
                parallel.write_block(buf, n.value, b"")
                n.value = n.value + 1
        parallel.write_block(buf, n.value, block)
        n.value = n.value + 1

    for dport in range(1000, 1000 + scan_ports):     # the scan (all at sec=0)
        emit(_syn(dport), 0)
    for _ in range(n_workers * 3):                   # ticks at sec=2 -> force each worker's sweep
        emit(_tick(), 2)

    time.sleep(0.5)                                  # let workers drain
    from core.enums import BLOCK_MARKER
    for _ in range(n_workers):                       # END markers -> workers exit
        parallel.write_block(buf, n.value, b"", BLOCK_MARKER.END)
        n.value = n.value + 1
    for p in procs:
        p.join(timeout=2)
        if p.is_alive():
            p.terminate()

    from core.enums import TRAIL
    detections = 0
    while not q.empty():
        if q.get() == TRAIL.IP:                      # port-scan logs TRAIL.IP
            detections += 1
    return detections


def main():
    if len(sys.argv) > 1:
        n = int(sys.argv[1]); ports = int(sys.argv[2]) if len(sys.argv) > 2 else 60
        print("workers=%d ports=%d -> %d port-scan detection(s)" % (n, ports, measure(n, ports)))
        return
    print("== real-worker ring battle test: port scan (60 ports, one src->one dst), threshold=10 ==")
    print("%-9s %-22s %s" % ("workers", "round-robin (today)", "source-affinity (fix)"))
    for n in (1, 4, 8):
        rr = measure(n, 60, affinity=False)
        af = measure(n, 60, affinity=True)
        print("%-9d %-22s %s" % (n,
              "%d det %s" % (rr, "OK" if rr else "MISSED"),
              "%d det %s" % (af, "OK" if af else "MISSED")))


if __name__ == "__main__":
    main()
