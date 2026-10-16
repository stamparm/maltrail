#!/usr/bin/env python3
# coding: utf-8

"""A synthetic reference network, so detection and false-positive rates are numbers rather than opinions.

    python3 sensor/tools/refnet.py                # generate, replay, score
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

HEURISTICS ARE PLANTED TOO. Inbound port scans, ICMP tunnels and IDN homographs of the sites the
hosts actually use are ground truth, next to benign traffic built to tempt the same heuristics:
a monitoring box pinging fifty hosts every minute, workstations running Windows and Linux ping
long enough to cross the tunnel threshold, and lookups of ordinary IDNs. One scan is placed after
everything else, in the last second of the capture, where the heuristics used to have no later
packet to report on.

WHAT IT DOES NOT COVER YET. No DoH/ECH share, no beaconing, no DNS tunneling, no JA3/certificate
trails, no IPv6. Those are extensions of the same harness; each one added is a class of detection
that stops being unmeasured. The numbers printed are for the traffic actually generated and say
nothing about traffic that is not.
"""

import argparse
import csv
import glob
import io
import json
import os
import random
import shutil
import struct
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(ROOT, "sensor", "tools"))

import gen_corpus as G  # noqa: E402  - the packet builders, already pure stdlib
import gen_ja_vectors as J  # noqa: E402  - ClientHello builder, plus core.tls_intel for the JA3/JA4
from core.tls_intel import parse_client_hello  # noqa: E402

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
MONITOR = "10.0.0.2"
BASE = 1700000000.0

# Kinds scored as "is this trail reported for this host", against kinds scored per heuristic.
TRAIL_KINDS = ("DNS", "IPORT", "URL")

# What real ping tools put in an echo request (see sensor/src/heuristics/icmp.rs).
WINDOWS_PING = b"abcdefghijklmnopqrstuvwabcdefghi"
BLACKBOX_PING = b"Prometheus Blackbox Exporter"

# Ordinary IDNs: lookups a network makes that look like nothing but themselves.
BENIGN_IDNS = (u"m\u00fcnchen.de", u"b\u00fccher.de", u"k\u00f6ln.de", u"z\u00fcrich.ch",
               u"\u043c\u043e\u0441\u043a\u0432\u0430.\u0440\u0444", u"\u043f\u0440\u0438\u043c\u0435\u0440.\u0440\u0444",
               u"\u4f8b\u3048.jp", u"\u00f1and\u00fa.es")

# Cyrillic letters that render as these Latin ones: what a homograph registration swaps in.
CYRILLIC_TWIN = {"a": u"\u0430", "c": u"\u0441", "e": u"\u0435", "o": u"\u043e", "p": u"\u0440",
                 "i": u"\u0456", "s": u"\u0455", "x": u"\u0445", "y": u"\u0443"}

# Sites in SITES that data/whitelist.txt lists, i.e. what a lookalike would be built to imitate.
LOOKALIKE_TARGETS = ("google.com", "github.com", "microsoft.com", "apple.com", "office.com")


def _echo(seq, payload):
    return struct.pack("!BBHHH", 8, 0, 0, 0x4d54, seq & 0xffff) + payload


def _iputils_payload(when):
    # struct timeval, then byte i == i: what `ping` from iputils sends
    return struct.pack("<qq", int(when), int((when % 1) * 1e6)) + bytes(bytearray(range(16, 56)))


def _homograph(site, rnd):
    """`site` with ONE Latin letter of its name swapped for its Cyrillic twin, IDNA-encoded."""
    name, _, tld = site.partition(".")
    positions = [i for i, c in enumerate(name) if c in CYRILLIC_TWIN]
    i = rnd.choice(positions)
    fake = name[:i] + CYRILLIC_TWIN[name[i]] + name[i + 1:]
    return fake.encode("idna").decode("ascii") + "." + tld


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
                # only a bare port: "1.2.3.4:34283/i" (a URL on a port) crashed the generator with
                # int("34283/i"), so the whole run died against a current trail set
                if key.split(":", 1)[1].isdigit():
                    ipports.append(key)
            elif "." in key and ":" not in key and "/" not in key and not key.startswith("."):
                # NOT a bare address. A dotted quad has no colon and no slash either, so it landed
                # in this pool and got planted as a DNS query for "141.8.225.181" - a name nothing
                # resolves and no IP trail matches. The run then reported a detection miss that was
                # entirely the generator's doing, which is the failure mode this whole tool is for.
                # Nor a dynamic-DNS / free-hosting provider: the sensor reports only SUBDOMAINS of
                # those (the bare provider name is not an indicator), so planting the bare name
                # measured a design decision as a miss.
                dynamic = "dynamic" in row[1] or "free web" in row[1]
                if not (key.count(".") == 3 and key.replace(".", "").isdigit()) and not dynamic:
                    domains.append(key)
    return domains, ipports, urls


def _vlan2(ip_packet):
    """An Ethernet frame with two VLAN tags (QinQ: 802.1ad outer, 802.1Q inner)."""
    return (b"\x00\x11\x22\x33\x44\x55\x00\x66\x77\x88\x99\xaa" + b"\x88\xa8" + struct.pack("!H", 100)
            + b"\x81\x00" + struct.pack("!H", 200) + b"\x08\x00" + ip_packet)


def _ipv6_hbh(src, dst, udp_payload):
    """IPv6 whose transport header sits behind a Hop-by-Hop extension header."""
    import socket
    hbh = struct.pack("!BB", 17, 0) + b"\x01\x04\x00\x00\x00\x00"     # next=UDP, len 8, PadN
    body = hbh + udp_payload
    header = (struct.pack("!IHBB", 0x60000000, len(body), 0, 64)
              + socket.inet_pton(socket.AF_INET6, src) + socket.inet_pton(socket.AF_INET6, dst))
    return G.eth(header + body, ethertype=0x86dd)


def _certificate_flight(der):
    """A server's TLS handshake record carrying one Certificate message with leaf `der`."""
    def u24(n):
        return struct.pack("!I", n)[1:]
    entry = u24(len(der)) + der
    msg = b"\x0b" + u24(len(entry) + 3) + u24(len(entry)) + entry
    return b"\x16\x03\x03" + struct.pack("!H", len(msg)) + msg


def _plant_more(packets, truth, rnd, addresses, domains, minutes, extra_trails):
    """Ground truth for the detections added since August, each beside the bait most likely to
    make it fire wrongly. Returns how many benign packets the bait added."""
    benign, span = 0, minutes * 60
    pick = lambda: rnd.choice(addresses)  # noqa: E731
    start = lambda room: BASE + rnd.uniform(0, max(1, span - room))  # noqa: E731

    # Beaconing: a SYN to one destination every 55..65 s for the whole run (CV ~ 0.03).
    implant, c2 = pick(), "203.0.113.%d" % rnd.randint(150, 199)
    when = BASE + rnd.uniform(0, 30)
    while when < BASE + span:
        packets.append((when, G.eth(G.ipv4(implant, c2, 6, G.tcp(rnd.randint(30000, 60000), 8443, 0x02)))))
        when += rnd.uniform(55, 65)
    truth.append({"host": implant, "trail": None, "info": "beaconing", "kind": "BEACONING"})

    # DNS tunneling: 220 queries over ~4 minutes, a 52-character base32 label each, to one zone.
    # Bait: as many hash-labelled lookups to an antivirus reputation zone, the shape it must ignore.
    alphabet = "abcdefghijklmnopqrstuvwxyz234567"
    for kind, zone in (("DNS_TUNNEL", "t%d.exfil-refnet.net" % rnd.randint(1, 99)), (None, "avqs.mcafee.com")):
        host, when = pick(), start(400)
        for i in range(220):
            label = "".join(rnd.choice(alphabet if kind else "0123456789abcdef") for _ in range(52 if kind else 40))
            packets.append((when + i * 1.1, G.eth(G.ipv4(host, RESOLVER, 17, G.udp(rnd.randint(30000, 60000), 53,
                                                                                   G.dns_query(label + "." + zone))))))
        if kind:
            # matched on the last two labels: that is what the long-domain throttle groups and names
            truth.append({"host": host, "trail": None, "info": "dns tunneling", "kind": kind,
                          "explains": ".".join(zone.split(".")[-2:])})
        else:
            benign += 220

    # DNS exhaustion ("water torture"): 1,100 random subdomains of one victim domain in under a
    # minute - the heuristic counts per 60-second window, so a slower flood is not one.
    host, when, victim = pick(), start(300), "victim%d-refnet.org" % rnd.randint(1, 99)
    for i in range(1100):
        name = "%08x.%s" % (rnd.getrandbits(32), victim)
        packets.append((when + i * 0.045, G.eth(G.ipv4(host, RESOLVER, 17, G.udp(rnd.randint(30000, 60000), 53, G.dns_query(name))))))
    truth.append({"host": host, "trail": None, "info": "dns exhaustion", "kind": "DNS_EXHAUSTION", "explains": victim})

    # A DGA bot: 300 algorithmically generated names in ten minutes, every one NXDOMAIN. Bait: the
    # NXDOMAIN noise every Windows network makes all day (WPAD and DC-locator lookups).
    bot, when = pick(), start(700)
    for i in range(300):
        name = "".join(rnd.choice("bcdfghjklmnpqrstvwxz" if j % 3 else "aeiou") for j in range(rnd.randint(12, 18))) + ".com"
        sport = rnd.randint(30000, 60000)
        packets.append((when + i * 2, G.eth(G.ipv4(bot, RESOLVER, 17, G.udp(sport, 53, G.dns_query(name))))))
        packets.append((when + i * 2 + 0.01, G.eth(G.ipv4(RESOLVER, bot, 17, G.udp(53, sport, G.dns_nxdomain(name))))))
    truth.append({"host": bot, "trail": None, "info": "no such domain", "kind": "DGA", "explains": ".com", "via": "dst"})
    for i in range(30):
        host, sport = pick(), rnd.randint(30000, 60000)
        name = rnd.choice(("wpad.corp.example", "_ldap._tcp.dc._msdcs.corp.example", "isatap.corp.example"))
        when = start(1)
        packets.append((when, G.eth(G.ipv4(host, RESOLVER, 17, G.udp(sport, 53, G.dns_query(name))))))
        packets.append((when + 0.01, G.eth(G.ipv4(RESOLVER, host, 17, G.udp(53, sport, G.dns_nxdomain(name))))))
        benign += 2

    # A trail lookup inside each encapsulation the sensor now follows.
    names = rnd.sample(domains, 4) if len(domains) >= 4 else []
    for kind, name in zip(("VXLAN", "GRE", "IPV6_EXT", "QINQ"), names):
        when, sport = start(1), rnd.randint(30000, 60000)
        if kind == "VXLAN":
            inner = "172.20.%d.%d" % (rnd.randint(0, 255), rnd.randint(1, 254))
            frame = G.eth(G.ipv4(inner, "172.20.0.1", 17, G.udp(sport, 53, G.dns_query(name))))
            vxlan = b"\x08\x00\x00\x00" + struct.pack("!I", 4242 << 8) + frame
            packet = G.eth(G.ipv4("192.0.2.10", "192.0.2.11", 17, G.udp(45000, 4789, vxlan)))
        elif kind == "GRE":
            inner = "172.21.%d.%d" % (rnd.randint(0, 255), rnd.randint(1, 254))
            gre = b"\x00\x00\x08\x00" + G.ipv4(inner, "172.21.0.1", 17, G.udp(sport, 53, G.dns_query(name)))
            packet = G.eth(G.ipv4("192.0.2.20", "192.0.2.21", 47, gre))
        elif kind == "IPV6_EXT":
            inner = "fd00::%x" % rnd.randint(1, 0xffff)
            packet = _ipv6_hbh(inner, "fd00::53", G.udp(sport, 53, G.dns_query(name)))
        else:
            inner = pick()
            packet = _vlan2(G.ipv4(inner, RESOLVER, 17, G.udp(sport, 53, G.dns_query(name))))
        packets.append((when, packet))
        truth.append({"host": inner, "trail": name, "kind": kind})

    # JA3 and JA4 trails: ClientHellos unlike the one every benign host sends, so the trail added
    # for them cannot match the background.
    benign_hello = parse_client_hello(G.tls_client_hello("example.com"))
    for kind, ciphers in (("JA3", (0x1301, 0xc02f, 0x009c)), ("JA4", (0x1302, 0xc030, 0x009d))):
        host, server, sport = pick(), "198.51.100.%d" % rnd.randint(150, 199), rnd.randint(30000, 60000)
        hello = J.hello(sni_ext=J.sni_ext("refnet-%s.example" % kind.lower()), ciphers=ciphers)
        fingerprint = parse_client_hello(hello)[kind.lower()]
        assert fingerprint != benign_hello[kind.lower()], "the planted hello must not be the background's"
        extra_trails.append((fingerprint, "malware (refnet %s)" % kind))
        packets.append((start(1), G.eth(G.ipv4(host, server, 6, G.tcp(sport, 443, 0x18, hello)))))
        truth.append({"host": host, "trail": fingerprint, "kind": kind})

    # A TLS server certificate listed by its SHA-1 (credited to whichever server sent it).
    import hashlib
    der = b"0\x82refnet-leaf-certificate-" + bytes(bytearray(rnd.getrandbits(8) for _ in range(200)))
    digest = hashlib.sha1(der).hexdigest()
    extra_trails.append((digest, "malware (refnet CERT)"))
    server, client = "198.51.100.%d" % rnd.randint(200, 249), pick()
    packets.append((start(1), G.eth(G.ipv4(server, client, 6, G.tcp(443, rnd.randint(30000, 60000), 0x18, _certificate_flight(der))))))
    truth.append({"host": None, "trail": digest, "kind": "CERT"})

    # IoT dropper fetched by one of OUR hosts. Bait: the same request between two outside hosts,
    # somebody else's infection crossing the link, which must stay silent (#19622).
    host, dropper = pick(), "203.0.113.%d" % rnd.randint(200, 249)
    for src, kind in ((host, "IOT_DROPPER"), ("198.18.0.50", None)):
        request = G.http_get("/bins/mips", host=dropper)
        packets.append((start(1), G.eth(G.ipv4(src, dropper, 6, G.tcp(rnd.randint(30000, 60000), 80, 0x18, request)))))
        if kind:
            truth.append({"host": host, "trail": None, "info": "iot-malware", "kind": kind})
        else:
            benign += 1
    return benign


def generate(out, hosts=500, minutes=60, seed=1312, planted=10, scans=3, trails=None, tunnels=2, homographs=3):
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

    # Benign ICMP, built to tempt the tunnel heuristic: a monitoring box pinging fifty hosts every
    # minute (fping's zeros) and one target with a constant string (blackbox exporter), then
    # workstations running Windows or Linux ping 30 times at one target - far past the threshold
    # in packets, so only the payload classification stands between them and an alert.
    for minute in range(minutes):
        for ip in addresses[:50]:
            packets.append((BASE + minute * 60 + rnd.uniform(0, 1), G.eth(G.ipv4(MONITOR, ip, 1, _echo(minute, b"\0" * 56)))))
            benign += 1
        packets.append((BASE + minute * 60 + 1.5, G.eth(G.ipv4(MONITOR, site_ip["google.com"], 1, _echo(minute, BLACKBOX_PING)))))
        benign += 1
    for ip in rnd.sample(addresses, min(20, len(addresses))):
        windows = rnd.random() < 0.5
        when = BASE + rnd.uniform(0, max(1, minutes * 60 - 60))
        for seq in range(30):
            payload = WINDOWS_PING if windows else _iputils_payload(when + seq)
            packets.append((when + seq, G.eth(G.ipv4(ip, "8.8.8.8", 1, _echo(seq, payload)))))
            benign += 1
    # Ordinary IDNs, built to tempt the homograph heuristic.
    for name in BENIGN_IDNS:
        ip, when, sport = rnd.choice(addresses), BASE + rnd.uniform(0, minutes * 60), rnd.randint(30000, 60000)
        packets.append((when, G.eth(G.ipv4(ip, RESOLVER, 17, G.udp(sport, 53, G.dns_query(name.encode("idna").decode("ascii")))))))
        benign += 1

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

    # ICMP tunnels: a workstation carrying data out in its echo requests (icmpsh, ptunnel).
    for _ in range(tunnels):
        victim, far = rnd.choice(addresses), "198.51.100.%d" % rnd.randint(2, 254)
        when = BASE + rnd.uniform(60, max(120, minutes * 60 - 120))
        for seq in range(40):
            data = bytes(bytearray(rnd.getrandbits(8) for _ in range(64)))
            packets.append((when + seq * 0.5, G.eth(G.ipv4(victim, far, 1, _echo(seq, data)))))
        truth.append({"host": victim, "trail": far, "kind": "ICMP_TUNNEL"})

    # IDN homographs of the sites this network actually visits.
    for site in rnd.sample(LOOKALIKE_TARGETS, min(homographs, len(LOOKALIKE_TARGETS))):
        ip, when, sport = rnd.choice(addresses), BASE + rnd.uniform(0, minutes * 60), rnd.randint(30000, 60000)
        name = _homograph(site, rnd)
        packets.append((when, G.eth(G.ipv4(ip, RESOLVER, 17, G.udp(sport, 53, G.dns_query(name))))))
        truth.append({"host": ip, "trail": name, "kind": "HOMOGRAPH"})

    extra_trails = []
    benign += _plant_more(packets, truth, rnd, addresses, domains, minutes, extra_trails)

    # A scan after everything else: its threshold is crossed in the capture's last second.
    if scans:
        scanner, target = "203.0.113.1", rnd.choice(addresses)
        last = max([_[0] for _ in packets] or [BASE]) + 5
        for i in range(60):
            packets.append((last + i * 0.001, G.eth(G.ipv4(scanner, target, 6, G.tcp(41000 + i, 2000 + i, 0x02)))))
        truth.append({"host": scanner, "trail": scanner, "kind": "TAIL_SCAN"})

    packets.sort(key=lambda _: _[0])
    if not os.path.isdir(out):
        os.makedirs(out)
    pcap = os.path.join(out, "network.pcap")
    G.write_pcap(pcap, packets)
    # The run's own trail set: the given one plus the fingerprints planted above.
    run_trails = os.path.join(out, "trails.csv")
    with io.open(trails or os.path.join(ROOT, "trails.csv"), "rb") as src, io.open(run_trails, "wb") as dst:
        dst.write(src.read().rstrip(b"\n") + b"\n")
        dst.write(b"".join((u"%s,%s,(static)\n" % _).encode("utf8") for _ in extra_trails))
    meta = {"hosts": hosts, "minutes": minutes, "seed": seed, "packets": len(packets),
            "benign_packets": benign, "truth": truth, "trails": run_trails}
    with io.open(os.path.join(out, "truth.json"), "w", encoding="utf8") as handle:
        handle.write(json.dumps(meta, indent=1, sort_keys=True))
    return pcap, meta


def events(logdir):
    """(source, trail, info, destination) per logged event."""

    out = []
    for path in sorted(glob.glob(os.path.join(logdir, "*.log"))):
        if os.path.basename(path) == "error.log":
            continue
        for line in io.open(path, encoding="utf8", errors="replace"):
            parts = line.split()
            if len(parts) > 10:
                out.append((parts[3], parts[9].strip('"'), line.split('"')[-2] if line.count('"') >= 4 else "", parts[5]))
    return out


def score(meta, logged):
    """The three numbers, plus what was missed and what was invented."""

    planted = {(_["host"], _["trail"]) for _ in meta["truth"] if _["kind"] in TRAIL_KINDS}
    scanners = {_["host"] for _ in meta["truth"] if _["kind"] in ("SCAN", "TAIL_SCAN")}
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
    for entry in logged:
        host, trail = entry[0], entry[1]
        hit = credits(host, trail)
        if hit:
            detected.add(hit)
            explained.add((host, trail))
    missed = planted - detected
    # a scan is credited to its SOURCE, whatever trail string the heuristic writes (the tail scan
    # is scored with the other heuristics below, so it shows on its own line)
    inbound = {_["host"] for _ in meta["truth"] if _["kind"] == "SCAN"}
    scans_found = {_ for _ in inbound if any(e[0] == _ for e in logged)}

    # The other planted heuristics, each credited only by the event that IS its detection, so a
    # tunnel's or a lookalike's host is still charged for anything else it sets off.
    def found(entry):
        kind, host, trail = entry["kind"], entry["host"], entry["trail"]
        if kind in ("SCAN", "TAIL_SCAN"):
            return [e for e in logged if e[0] == host]
        if kind == "ICMP_TUNNEL":
            return [e for e in logged if e[0] == host and e[1] == trail and "icmp tunneling" in e[2]]
        info = entry.get("info")
        # verdicts on a DNS REPLY carry the resolver as source and our host as destination
        side = 3 if entry.get("via") == "dst" else 0
        return [e for e in logged if (host is None or e[side] == host) and (trail is None or e[1] == trail)
                and (info is None or info in e[2])]

    # Events a planted attack causes BESIDES its own detection (another heuristic firing on the
    # same traffic) are not false positives - the traffic is malicious - but they are noise an
    # operator pays for, so they are counted per attack instead of being hidden.
    heuristics, noise = {}, {}
    for entry in meta["truth"]:
        if entry["kind"] in TRAIL_KINDS:
            continue
        hits = found(entry)
        explained.update((e[0], e[1]) for e in hits)
        if entry.get("explains"):
            # brackets mark what matched ("(label.t74).zone"), so compare without them
            side = 3 if entry.get("via") == "dst" else 0
            extra = {(e[0], e[1]) for e in logged if e[side] == entry["host"]
                     and entry["explains"] in e[1].replace("(", "").replace(")", "")} - set(
                (e[0], e[1]) for e in hits)
            explained.update(extra)
            noise[entry["kind"]] = noise.get(entry["kind"], 0) + len(extra)
        done, total = heuristics.get(entry["kind"], (0, 0))
        heuristics[entry["kind"]] = (done + (1 if hits else 0), total + 1)
    false = [_ for _ in seen if _ not in planted and _ not in explained and _[0] not in scanners]

    hours = meta["minutes"] / 60.0
    per_1000_day = (len(logged) / max(hours, 1e-9)) * 24.0 * (1000.0 / meta["hosts"])
    return {
        "planted": len(planted), "detected": len(detected), "missed": sorted(missed)[:10],
        "scans_planted": len(inbound), "scans_detected": len(scans_found), "heuristics": heuristics,
        "attack_noise": noise,
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
    # Start empty. The sensor APPENDS to its daily log, so a second run into the same --out (the
    # default is a fixed directory) scored the previous run's events too - every count inflated,
    # false positives included.
    if os.path.isdir(logdir):
        shutil.rmtree(logdir)
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
    parser.add_argument("--tunnels", type=int, default=2, help="ICMP tunnels")
    parser.add_argument("--homographs", type=int, default=3, help="IDN lookalike lookups")
    parser.add_argument("--trails", default=os.path.expanduser("~/.maltrail/trails.csv"))
    parser.add_argument("--sensor", default=None)
    parser.add_argument("--generate", action="store_true", help="write the pcap and stop")
    parser.add_argument("--score", metavar="DIR", help="score a directory a previous run wrote")
    parser.add_argument("--min-detection", type=float, default=None, help="fail below this %%")
    parser.add_argument("--max-false", type=int, default=None, help="fail above this many false positives")
    parser.add_argument("--require-heuristics", action="store_true",
                        help="fail if any planted heuristic (scan, tunnel, beacon, ...) goes undetected")
    options = parser.parse_args()

    if options.score:
        meta = json.load(io.open(os.path.join(options.score, "truth.json"), encoding="utf8"))
        result = score(meta, events(os.path.join(options.score, "logs")))
    else:
        if not os.path.isfile(options.trails):
            raise SystemExit("[!] no trail set at %s (pass --trails)" % options.trails)
        pcap, meta = generate(options.out, options.hosts, options.minutes, options.seed,
                              options.planted, options.scans, options.trails, options.tunnels, options.homographs)
        print("[i] %d host(s), %d minute(s), seed %d -> %d packets (%.0f MB)"
              % (meta["hosts"], meta["minutes"], meta["seed"], meta["packets"], os.path.getsize(pcap) / 1e6))
        if options.generate:
            return 0
        logdir, elapsed = replay(pcap, options.out, meta["trails"], options.sensor)
        print("[i] replayed in %.2fs" % elapsed)
        result = score(meta, events(logdir))

    print("\n[i] detection rate            %5.1f%%  (%d/%d planted trails)"
          % (result["detection_rate"], result["detected"], result["planted"]))
    print("[i] scans detected            %5d/%d" % (result["scans_detected"], result["scans_planted"]))
    for kind, label in (("TAIL_SCAN", "scan at end of capture"), ("ICMP_TUNNEL", "icmp tunnels"),
                        ("HOMOGRAPH", "idn homographs"), ("BEACONING", "beaconing"),
                        ("DNS_TUNNEL", "dns tunneling"), ("DNS_EXHAUSTION", "dns exhaustion"),
                        ("VXLAN", "trail inside VXLAN"), ("GRE", "trail inside GRE"),
                        ("IPV6_EXT", "trail behind IPv6 ext hdr"), ("QINQ", "trail behind QinQ"),
                        ("DGA", "dga bot (nxdomain)"),
                        ("JA3", "JA3 trail"), ("JA4", "JA4 trail"), ("CERT", "certificate SHA-1 trail"),
                        ("IOT_DROPPER", "iot dropper (our host)")):
        if kind in result["heuristics"]:
            extra = result.get("attack_noise", {}).get(kind)
            print("[i] %-26s%5d/%d%s" % (label, result["heuristics"][kind][0], result["heuristics"][kind][1],
                                         "   (+%d other events on the same traffic)" % extra if extra else ""))
    print("[i] false positives           %5d   (%.2f per 100k benign packets)"
          % (result["false_positives"], result["fp_per_100k_benign"]))
    print("[i] events/day/1000 hosts     %5.0f" % result["events_per_day_per_1000_hosts"])
    if result["missed"]:
        print("\n[!] missed: %s" % ", ".join("%s->%s" % _ for _ in result["missed"][:5]))
    if result["false_examples"]:
        print("\n[!] false positives: %s" % ", ".join("%s->%s" % _ for _ in result["false_examples"][:5]))

    failures = gate(result, options.min_detection, options.max_false, options.require_heuristics)
    for failure in failures:
        print("\n[x] %s" % failure)
    return 1 if failures else 0


def gate(result, min_detection=None, max_false=None, require_heuristics=False):
    """Why this run fails the thresholds asked for; empty when it passes."""
    failures = []
    if min_detection is not None and result["detection_rate"] < min_detection:
        failures.append("detection rate below --min-detection %.1f%%" % min_detection)
    if max_false is not None and result["false_positives"] > max_false:
        failures.append("more false positives than --max-false %d" % max_false)
    if require_heuristics:
        if result["scans_detected"] < result["scans_planted"]:
            failures.append("scans detected %d/%d" % (result["scans_detected"], result["scans_planted"]))
        for kind, (found, total) in sorted(result["heuristics"].items()):
            if found < total:
                failures.append("%s detected %d/%d" % (kind, found, total))
    return failures


if __name__ == "__main__":
    sys.exit(main())
