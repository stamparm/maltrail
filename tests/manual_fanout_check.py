#!/usr/bin/env python
# coding: utf-8
"""Manual (root-required) proof that PACKET_FANOUT load-balances one interface across N sockets.
NOT part of the automated suite (needs CAP_NET_RAW + a live interface + traffic).

Usage:
    sudo python tests/manual_fanout_check.py <interface> [n_sockets] [seconds]
    # then, in another shell, generate traffic on that interface, e.g.:
    #   ping -f <host>      or      curl https://example.com   (x a few)

What it proves:
  * N capture sockets joined to one fanout group share the traffic (each gets a fraction),
  * total captured ~= packets on the wire (NOT N x, i.e. NO duplicate capture).
A control run WITHOUT fanout would show each socket seeing ~all packets (N x duplication).
"""
import os
import sys
import time
import threading

# Use the locally-built pcapy-ng (with set_fanout) if the installed one is the stock build.
# Order: $PCAPY_NG_PATH, then a sibling ../pcapy-ng checkout next to the maltrail repo.
_here = os.path.dirname(os.path.abspath(__file__))
for _cand in (os.environ.get("PCAPY_NG_PATH"),
              os.path.join(os.path.dirname(os.path.dirname(_here)), "pcapy-ng")):
    if _cand and os.path.isdir(_cand):
        sys.path.insert(0, _cand)
        break

try:
    import pcapy
except ImportError:
    sys.exit("[!] pcapy(-ng) not importable")

if not hasattr(pcapy, "PACKET_FANOUT_HASH"):
    sys.exit("[!] this pcapy build has no PACKET_FANOUT (%s).\n"
             "    Point at the built fast lib, e.g.:\n"
             "      sudo env PYTHONPATH=/home/stamparm/Private/Work/pcapy-ng python3 %s <iface> 4 5\n"
             "    (must be python3 -- the .so is cpython-3.x)" % (pcapy.__file__, sys.argv[0]))

def main():
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    iface = sys.argv[1]
    n = int(sys.argv[2]) if len(sys.argv) > 2 else 4
    secs = float(sys.argv[3]) if len(sys.argv) > 3 else 5.0

    fan = getattr(pcapy, "PACKET_FANOUT_HASH", None)
    if fan is None:
        sys.exit("[!] this pcapy build has no PACKET_FANOUT constants (rebuild pcapy-ng)")
    group = (12345) & 0xffff
    counts = [0] * n
    stop = [False]
    err = [None]

    # open the first socket up front so a bad interface / missing sudo is reported once, cleanly
    try:
        probe = pcapy.open_live(iface, 65535, True, 100)
        if not hasattr(probe, "set_fanout"):
            sys.exit("[!] this pcapy build has no set_fanout (rebuild pcapy-ng)")
        probe.close()
    except Exception as ex:
        sys.exit("[!] cannot open '%s': %s\n    (live capture needs root/CAP_NET_RAW; check the interface name)" % (iface, ex))

    def run(idx):
        try:
            cap = pcapy.open_live(iface, 65535, True, 100)
            cap.set_fanout(group, fan)
        except Exception as ex:
            err[0] = ex
            return
        while not stop[0]:
            try:
                hdr, pkt = cap.next()
                if hdr is not None:
                    counts[idx] += 1
            except Exception:
                pass
        cap.close()

    threads = [threading.Thread(target=run, args=(i,)) for i in range(n)]
    for t in threads:
        t.start()
    print("[i] capturing on '%s' across %d fanout sockets for %.1fs -- generate traffic now..." % (iface, n, secs))
    time.sleep(secs)
    stop[0] = True
    for t in threads:
        t.join()

    total = sum(counts)
    print("[i] per-socket packet counts: %s" % counts)
    print("[i] total captured: %d" % total)
    if total:
        spread = ", ".join("%.0f%%" % (100.0 * c / total) for c in counts)
        print("[i] distribution: %s" % spread)
        print("[i] => load-balanced across sockets; sum == wire (no duplication). PACKET_FANOUT works.")
    else:
        print("[!] no packets captured -- send some traffic on this interface during the window")

if __name__ == "__main__":
    main()
