#!/usr/bin/env python3
# coding: utf-8

"""A synthetic reference network, so detection and false-positive rates are numbers rather than opinions.

    python3 sensor/tools/refnet.py --run          # generate, replay, score
    python3 sensor/tools/refnet.py --generate     # pcap + ground truth only
    python3 sensor/tools/refnet.py --score DIR    # score an existing run

WHY THIS EXISTS. Every claim about Maltrail's noise - "the scan heuristics are loud", "confidence
gating would hide too much" - was unfalsifiable, because nobody could state a false-positive rate.
Three numbers per run make those arguments decidable: detection rate against planted ground truth,
false positives against traffic that is known-clean by construction, and events per day per 1000
hosts so an operator can predict their own volume.

WHY HOSTS HAVE PROFILES. The first version of this generator emitted uniform random traffic and
produced 49,805 events from 200,000 packets. The sensor was right: thousands of sources touching
one address on random ports IS a scan. A host that returns to a small stable set of destinations,
resolves them consistently and completes a handshake before talking is a workstation. Until the
generator behaves, the false-positive rate measures the generator.

WHAT IT DOES NOT COVER YET. No DoH/ECH share, no beaconing, no JA3/certificate trails, no IPv6, no
tunnelling. Those are extensions of the same harness; each one added is a class of detection that
stops being unmeasured. The numbers printed are for the traffic actually generated and say nothing
about traffic that is not.
"""

import argparse
import csv
import glob
import io
import json
import os
import random
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(ROOT, "sensor", "tools"))

import gen_corpus as G  # noqa: E402  - the packet builders, already pure stdlib

# Destinations a workstation actually returns to. Deliberately ordinary: if one of these is ever in
# the trail set the run reports it as a false positive, which is the correct verdict for a name this
# recognisable.
SITES = (
    "google.com", "cloudflare.com", "github.com", "microsoft.com", "apple.com", "wikipedia.org",
    "stackoverflow.com", "debian.org", "mozilla.org", "office.com", "slack.com", "zoom.us",
    "atlassian.net", "gitlab.com", "docker.io", "npmjs.com", "pypi.org", "ubuntu.com",
    "cdn.jsdelivr.net", "fonts.googleapis.com", "api.github.com", "registry.npmjs.org",
)

RESOLVER = "10.0.0.1"
BASE = 1700000000.0


def _hosts(count, rnd):
    """(ip, favourite sites, requests/minute) per host.

    The favourites are what make this a network rather than noise - a host that picks a fresh
    destination every request is indistinguishable from a scanner, correctly.
    """

    out = []
    for i in range(count):
        ip = "10.%d.%d.%d" % (1 + i // 65025, (i // 255) % 255, 1 + i % 255)
        out.append((ip, rnd.sample(SITES, rnd.randint(3, 7)), rnd.uniform(0.5, 4.0)))
    return out


def _trail_pools(path, limit=400000):
    """Real trails, split by the shape the sensor matches them in."""

    domains, ipports, urls = [], [], []
    with io.open(path, encoding="utf8", errors="replace") as handle:
        for row in csv.reader(handle):
            if not row or len(row) != 3 or row[0].startswith("#"):
                continue
            key = row[0]
            if len(domains) + len(ipports) + len(urls) > limit:
                break
            head = key.split("/", 1)[0]
            if "/" in key and head.count(".") == 3 and head.replace(".", "").isdigit():
                if len(key.split("/", 1)[1]) > 3:
                    urls.append(key)
            elif ":" in key and key.split(":")[0].count(".") == 3:
                ipports.append(key)
            elif "." in key and ":" not in key and "/" not in key and not key.startswith("."):
                # NOT a bare address. A dotted quad has no colon and no slash either, so it landed
                # in this pool and got planted as a DNS query for "141.8.225.181" - a name nothing
                # resolves and no IP trail matches. The run then reported a detection miss that was
                # entirely the generator's doing, which is the failure mode this whole tool is for.
                if not (key.count(".") == 3 and key.replace(".", "").isdigit()):
                    domains.append(key)
    return domains, ipports, urls


def generate(out, hosts=500, minutes=60, seed=1312, planted=10, scans=3, trails=None):
    rnd = random.Random(seed)
    profiles = _hosts(hosts, rnd)
    site_ip = {s: "93.184.%d.%d" % (rnd.randint(0, 255), rnd.randint(1, 254)) for s in SITES}

    packets, benign = [], 0
    for ip, favourites, rate in profiles:
        for minute in range(minutes):
            for _ in range(max(0, int(rnd.gauss(rate, rate / 3.0)))):
                site = rnd.choice(favourites)
                when = BASE + minute * 60 + rnd.uniform(0, 60)
                sport = rnd.randint(30000, 60000)
                # resolve, then connect, then speak - a handshake before payload is most of what
                # separates a client from a scanner
                packets.append((when, G.eth(G.ipv4(ip, RESOLVER, 17, G.udp(sport, 53, G.dns_query(site))))))
                packets.append((when + 0.01, G.eth(G.ipv4(RESOLVER, ip, 17, G.udp(53, sport, G.dns_response_a(site, site_ip[site]))))))
                packets.append((when + 0.02, G.eth(G.ipv4(ip, site_ip[site], 6, G.tcp(sport, 443, 0x02)))))
                packets.append((when + 0.05, G.eth(G.ipv4(ip, site_ip[site], 6, G.tcp(sport, 443, 0x18, G.tls_client_hello(site))))))
                benign += 4

    truth = []
    domains, ipports, urls = _trail_pools(trails or os.path.join(ROOT, "trails.csv"))
    addresses = [_[0] for _ in profiles]

    for kind, pool in (("DNS", domains), ("IPORT", ipports), ("URL", urls)):
        if not pool:
            continue
        for key in rnd.sample(pool, min(planted, len(pool))):
            ip = rnd.choice(addresses)
            when = BASE + rnd.uniform(0, minutes * 60)
            sport = rnd.randint(30000, 60000)
            if kind == "DNS":
                packets.append((when, G.eth(G.ipv4(ip, RESOLVER, 17, G.udp(sport, 53, G.dns_query(key))))))
            elif kind == "IPORT":
                dst, port = key.split(":")
                packets.append((when, G.eth(G.ipv4(ip, dst, 6, G.tcp(sport, int(port), 0x02)))))
            else:
                dst, path = key.split("/", 1)
                packets.append((when, G.eth(G.ipv4(ip, dst, 6, G.tcp(sport, 80, 0x18, G.http_get("/" + path, host=dst))))))
            truth.append({"host": ip, "trail": key, "kind": kind})

    # Inbound scans: ground truth for a HEURISTIC rather than a trail. One source, many ports on one
    # local host, inside SCAN_WINDOW. Deliberately generated alongside the ordinary traffic, because
    # the heuristic learns which prefix is local from what it sees - a scan replayed on its own has
    # no network to be inbound to, and does not fire.
    for _ in range(scans):
        scanner = "203.0.113.%d" % rnd.randint(2, 254)
        target = rnd.choice(addresses)
        when = BASE + rnd.uniform(60, max(120, minutes * 60 - 60))
        for i in range(60):
            packets.append((when + i * 0.02,
                            G.eth(G.ipv4(scanner, target, 6, G.tcp(40000 + i, 1000 + i, 0x02)))))
        truth.append({"host": scanner, "trail": scanner, "kind": "SCAN"})

    packets.sort(key=lambda _: _[0])
    if not os.path.isdir(out):
        os.makedirs(out)
    pcap = os.path.join(out, "network.pcap")
    G.write_pcap(pcap, packets)
    meta = {"hosts": hosts, "minutes": minutes, "seed": seed, "packets": len(packets),
            "benign_packets": benign, "truth": truth}
    with io.open(os.path.join(out, "truth.json"), "w", encoding="utf8") as handle:
        handle.write(json.dumps(meta, indent=1, sort_keys=True))
    return pcap, meta


def events(logdir):
    """(source, trail, info) per logged event."""

    out = []
    for path in sorted(glob.glob(os.path.join(logdir, "*.log"))):
        if os.path.basename(path) == "error.log":
            continue
        for line in io.open(path, encoding="utf8", errors="replace"):
            parts = line.split()
            if len(parts) > 10:
                out.append((parts[3], parts[9].strip('"'), line.split('"')[-2] if line.count('"') >= 4 else ""))
    return out


def score(meta, logged):
    """The three numbers, plus what was missed and what was invented."""

    planted = {(_["host"], _["trail"]) for _ in meta["truth"] if _["kind"] != "SCAN"}
    scanners = {_["host"] for _ in meta["truth"] if _["kind"] == "SCAN"}
    seen = {(_[0], _[1]) for _ in logged}

    # The sensor BRACKETS the part of a URL that matched: a request to 1.2.3.4/a/b.php whose listed
    # trail is the bare path is logged as "(1.2.3.4)/a/b.php". It is the same detection on the same
    # request, credited to a more specific trail than the one planted, so comparing the strings
    # literally scored it as a miss AND as a false positive - twice wrong from one formatting rule.
    def credits(host, logged_trail):
        bare = logged_trail.replace("(", "").replace(")", "")
        for planted_host, planted_trail in planted:
            if planted_host == host and (bare == planted_trail or planted_trail.endswith(bare)):
                return (planted_host, planted_trail)
        return None

    detected, explained = set(), set()
    for host, trail, _info in logged:
        hit = credits(host, trail)
        if hit:
            detected.add(hit)
            explained.add((host, trail))
    missed = planted - detected
    # a scan is credited to its SOURCE, whatever trail string the heuristic writes
    scans_found = {_ for _ in scanners if any(e[0] == _ for e in logged)}
    false = [_ for _ in seen if _ not in planted and _ not in explained and _[0] not in scanners]

    hours = meta["minutes"] / 60.0
    per_1000_day = (len(logged) / max(hours, 1e-9)) * 24.0 * (1000.0 / meta["hosts"])
    return {
        "planted": len(planted), "detected": len(detected), "missed": sorted(missed)[:10],
        "scans_planted": len(scanners), "scans_detected": len(scans_found),
        "false_positives": len(false), "false_examples": sorted(false)[:10],
        "benign_packets": meta["benign_packets"], "events": len(logged),
        "detection_rate": 100.0 * len(detected) / max(len(planted), 1),
        "fp_per_100k_benign": 100000.0 * len(false) / max(meta["benign_packets"], 1),
        "events_per_day_per_1000_hosts": per_1000_day,
    }


def replay(pcap, out, trails, sensor=None):
    sensor = sensor or os.path.join(ROOT, "sensor", "target", "release", "maltrail-sensor")
    if not os.path.isfile(sensor):
        raise SystemExit("[!] %s not built - cargo build --release --manifest-path sensor/Cargo.toml" % sensor)
    logdir = os.path.join(out, "logs")
    if not os.path.isdir(logdir):
        os.makedirs(logdir)
    conf = os.path.join(out, "sensor.conf")
    with io.open(conf, "w", encoding="utf8") as handle:
        # USE_HEURISTICS EXPLICITLY. An absent key reads as false, so a config that simply omits it
        # runs with every heuristic off - and the first version of this file did exactly that, then
        # reported 0/3 scans detected as though the sensor had missed them. A reference network that
        # forgets to turn on what it is measuring produces confident, meaningless numbers.
        handle.write(u"MONITOR_INTERFACE any\nCAPTURE_BUFFER 10MB\nSENSOR_NAME refnet\n"
                     u"USE_HEURISTICS true\n"
                     u"DISABLE_CHECK_SUDO true\nDISABLE_TRAIL_UPDATES true\nUSE_SERVER_UPDATE_TRAILS false\n"
                     u"UPDATE_PERIOD 86400\nLOG_DIR %s\nTRAILS_FILE %s\n" % (logdir, trails))
    started = time.time()
    subprocess.check_call([sensor, "-c", conf, "-r", pcap], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return logdir, time.time() - started


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--out", default=os.path.join(ROOT, "refnet-run"))
    parser.add_argument("--hosts", type=int, default=500)
    parser.add_argument("--minutes", type=int, default=60)
    parser.add_argument("--seed", type=int, default=1312)
    parser.add_argument("--planted", type=int, default=10, help="per trail kind")
    parser.add_argument("--scans", type=int, default=3)
    parser.add_argument("--trails", default=os.path.expanduser("~/.maltrail/trails.csv"))
    parser.add_argument("--sensor", default=None)
    parser.add_argument("--generate", action="store_true", help="write the pcap and stop")
    parser.add_argument("--score", metavar="DIR", help="score a directory a previous run wrote")
    parser.add_argument("--min-detection", type=float, default=None, help="fail below this %%")
    parser.add_argument("--max-false", type=int, default=None, help="fail above this many false positives")
    options = parser.parse_args()

    if options.score:
        meta = json.load(io.open(os.path.join(options.score, "truth.json"), encoding="utf8"))
        result = score(meta, events(os.path.join(options.score, "logs")))
    else:
        if not os.path.isfile(options.trails):
            raise SystemExit("[!] no trail set at %s (pass --trails)" % options.trails)
        pcap, meta = generate(options.out, options.hosts, options.minutes, options.seed,
                              options.planted, options.scans, options.trails)
        print("[i] %d host(s), %d minute(s), seed %d -> %d packets (%.0f MB)"
              % (meta["hosts"], meta["minutes"], meta["seed"], meta["packets"], os.path.getsize(pcap) / 1e6))
        if options.generate:
            return 0
        logdir, elapsed = replay(pcap, options.out, options.trails, options.sensor)
        print("[i] replayed in %.2fs" % elapsed)
        result = score(meta, events(logdir))

    print("\n[i] detection rate            %5.1f%%  (%d/%d planted trails)"
          % (result["detection_rate"], result["detected"], result["planted"]))
    print("[i] scans detected            %5d/%d" % (result["scans_detected"], result["scans_planted"]))
    print("[i] false positives           %5d   (%.2f per 100k benign packets)"
          % (result["false_positives"], result["fp_per_100k_benign"]))
    print("[i] events/day/1000 hosts     %5.0f" % result["events_per_day_per_1000_hosts"])
    if result["missed"]:
        print("\n[!] missed: %s" % ", ".join("%s->%s" % _ for _ in result["missed"][:5]))
    if result["false_examples"]:
        print("\n[!] false positives: %s" % ", ".join("%s->%s" % _ for _ in result["false_examples"][:5]))

    failed = False
    if options.min_detection is not None and result["detection_rate"] < options.min_detection:
        print("\n[x] detection rate below --min-detection %.1f%%" % options.min_detection)
        failed = True
    if options.max_false is not None and result["false_positives"] > options.max_false:
        print("\n[x] more false positives than --max-false %d" % options.max_false)
        failed = True
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
