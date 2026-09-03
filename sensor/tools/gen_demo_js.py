#!/usr/bin/env python3
# coding: utf-8
"""Top up html/js/demo.js with the event shapes it does not contain.

demo.js is the data behind the public dashboard demo. It is 2,500 events of REAL captured
traffic, and its value is that it looks real: 557 distinct trails over 13 hours with a power-law
distribution (j0mla.sytes.net 184 times, checkip.dyndns.org 147, a long tail of ones). Generating
it from scratch - one event per detection class - would cover everything and look like a test
matrix, which is not a demo.

So this does not regenerate. It reads the existing file as the base, works out which shapes the
DASHBOARD renders differently are missing from it, takes real examples of those from a sensor run
(`server.py --detect-test --keep DIR`), and blends them in: relabelled into the demo's own sensor
and time window, repeated in small clusters like the surrounding traffic, interleaved by
timestamp. Idempotent - a shape already present is left alone.

    python3 server.py --detect-test --keep /tmp/mt-demo
    python3 sensor/tools/gen_demo_js.py --from /tmp/mt-demo/logs

One shape is deliberately NOT synthesised: a condensed SOURCE list. core/log.py condenses on
`key = (src_ip, trail)` and merges only indices 3..6, so src_ip is the condensing key and can
never become a comma list. Faking one would put a shape in the demo that the sensor cannot emit.
"""

import argparse
import os
import random
import re
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
sys.path.insert(0, ROOT)

from core import logfmt  # noqa: E402

DEMO_JS = os.path.join(ROOT, "html", "js", "demo.js")
FI = {name: i for i, name in enumerate(logfmt.FIELDS)}

# What the dashboard draws differently, and how to spot it in a log line.
#
# The first version of this list only had the RENDERING shapes below - icons, glyphs, the
# condensed cell. That is not what an operator wants to see in a demo: it left every heuristic
# the sensor has gained since the 2024 capture out of the file, `potential periodic beaconing`
# among them. Detection CLASSES are the point; the rendering shapes are the tail of the list.
SHAPES = (
    ("ipv6", lambda r: ":" in r[FI["src_ip"]] or ":" in r[FI["dst_ip"]]),
    ("custom-origin", lambda r: r[FI["reference"]] == "(custom)"),
    ("icmp", lambda r: r[FI["proto"]] == "ICMP"),
    ("second-sensor", None),          # handled separately: it is a property of the SET, not a row
)

# Every detection class the sensor can emit, matched on a substring of `info` (or, for the
# fingerprints, on the trail TYPE). A class with no event behind it cannot be seen in the demo.
CLASSES = (
    ("beaconing", "potential periodic beaconing", 14),
    ("dns-tunneling", "potential dns tunneling", 9),
    ("dns-exhaustion", "potential dns exhaustion", 7),
    ("udp-scanning", "potential udp scanning", 8),
    ("web-scanning", "potential web scanning", 11),
    ("sql-injection", "potential sql injection", 9),
    ("xss-injection", "potential xss injection", 6),
    ("directory-traversal", "potential directory traversal", 7),
    ("remote-code-execution", "potential remote code execution", 5),
    ("proxy-probe", "potential proxy probe", 5),
    ("iot-malware", "potential iot-malware download", 6),
    ("missing-host-header", "missing host header", 5),
    ("seized-domain", "seized domain", 4),
    ("direct-download", "direct .exe download", 5),
    ("ja3", "\x00JA3", 8),            # matched on the trail TYPE, not info - see _class_present
)


def _class_present(rows, needle):
    if needle.startswith("\x00"):
        want = needle[1:]
        return sum(1 for r in rows if r[FI["type"]] == want)
    return sum(1 for r in rows if needle in r[FI["info"]])


# Sources of blended events. A Maltrail demo shows a MONITORED network, so the source of a
# detection is one of your own hosts - these are the busiest LAN addresses in the base capture.
# Reusing the base file's whole source mix put public addresses in the source column, which reads
# as though the deployment were monitoring somebody else's network.
LAN_HOSTS = ["10.3.160.42", "10.2.120.16", "10.43.192.103", "10.124.72.51",
             "10.128.8.51", "10.124.72.52", "10.128.3.52", "10.128.3.51"]


def _our_side(row):
    """Index of the field holding the monitored host - mirrors core/geo.py:event_country.

    Most detections are outbound and our host is the source. Three cases invert that: a resolver
    answering us (src port 53), the inbound heuristics (PATH web scanning, PORT infection), and a
    scan whose trail IS the source. There, our host is the destination and the source is theirs.
    """

    if row[FI["src_port"]] == "53":
        return FI["dst_ip"]
    if row[FI["type"]] in ("PATH", "PORT"):
        return FI["dst_ip"]
    if row[FI["type"]] == "IP" and row[FI["trail"]] == row[FI["src_ip"]]:
        return FI["dst_ip"]
    return FI["src_ip"]


def _looks_like_address(value):
    """Is this trail an IP address rather than a domain, path or fingerprint?

    A JA3/JA4 fingerprint is 32 hex characters, which any "hex and punctuation" test happily calls
    an address. Requiring a dot or a colon separates them: an address has one, a hash does not.
    """

    value = value.strip()
    if "/" in value or value.lower().startswith(("http:", "https:")):
        return False                                    # a URL or path trail, not an address
    value = value.lstrip("[").split("]")[0]
    if ":" in value and not re.match(r"^\d{1,3}(?:\.\d{1,3}){3}:\d+$", value):
        return True                                     # IPv6
    return bool(re.match(r"^\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?$", value))


def _parse_demo(path):
    """The event lines currently in demo.js, in order."""
    with open(path, encoding="utf8") as f:
        src = f.read()
    out = []
    for chunk in re.findall(r"'((?:[^'\\]|\\.)*)\\n'", src):
        line = chunk.replace("\\'", "'").replace('\\"', '"').replace("\\\\", "\\")
        if logfmt.fields(line):
            out.append(line)
    return out, src


def _rows(lines):
    return [logfmt.fields(_) for _ in lines]


def _read_sensor_events(log_dir):
    out = []
    for name in sorted(os.listdir(log_dir)):
        if name.endswith(".log") and name != "error.log":
            with open(os.path.join(log_dir, name), encoding="utf8", errors="replace") as f:
                for line in f:
                    if line.strip() and logfmt.fields(line.rstrip("\n")):
                        out.append(line.rstrip("\n"))
    return out


def _retime(line, day, hh, mm, ss, us):
    """Rewrite a line's leading quoted timestamp."""
    end = line.index('" ')
    return '"%s %02d:%02d:%02d.%06d%s' % (day, hh, mm, ss, us, line[end:])


def _resensor(line, sensor):
    """Rewrite the sensor field (index 1), quoting it the way safe_value would."""
    end = line.index('" ')
    rest = line[end + 2:].split(" ", 1)
    value = '"%s"' % sensor if " " in sensor else sensor
    return line[:end + 2] + value + " " + rest[1]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--from", dest="log_dir", required=True,
                    help="a LOG_DIR produced by 'server.py --detect-test --keep DIR' (its logs/ subdir)")
    ap.add_argument("--out", dest="out", default=DEMO_JS)
    ap.add_argument("--seed", type=int, default=20260902, help="fixed, so re-running produces the same file")
    ap.add_argument("--thin", type=float, default=0.5, metavar="F",
                    help="drop this fraction of the BASE file's distinct trails (default 0.5); the added classes are never thinned")
    args = ap.parse_args()

    random.seed(args.seed)
    base_lines, original = _parse_demo(DEMO_JS)
    base = _rows(base_lines)
    if not base:
        sys.exit("[!] could not parse any events out of %s" % DEMO_JS)

    # Thin the BASE first, never the additions, and BEFORE coverage is measured - a class the
    # thinning removes is then simply re-added below from the sensor run. Doing it the other way
    # round silently dropped three classes that existed only in the base.
    #
    # Whole trails go, not random rows, so every survivor keeps its full cluster and the file
    # keeps its power-law shape instead of being flattened into a uniform sample.
    if args.thin:
        by_trail = {}
        for line in base_lines:
            by_trail.setdefault(logfmt.fields(line)[FI["trail"]], []).append(line)
        # Protect variety first: whatever else goes, keep one carrier of every distinct `info`
        # and every trail TYPE the base has. Half the base is old bulk, but its VARIETY is the
        # point of a demo - and infos like "ipinfo (suspicious)" or "conficker dga (malware)"
        # come from feeds, so unlike the sensor heuristics they cannot be re-added below if the
        # thinning happens to drop their last carrier.
        first_carrier = {}
        for line in base_lines:
            row = logfmt.fields(line)
            for key in ("info:%s" % row[FI["info"]], "type:%s" % row[FI["type"]]):
                first_carrier.setdefault(key, row[FI["trail"]])
        protected = set(first_carrier.values())

        names = sorted(set(by_trail) - protected)
        random.shuffle(names)
        target = max(1, int(len(by_trail) * (1.0 - args.thin)))
        keep = protected | set(names[:max(0, target - len(protected))])
        print("[i] protected %d trail(s) carrying a distinct info/type" % len(protected))
        thinned = [_ for _ in base_lines if logfmt.fields(_)[FI["trail"]] in keep]
        print("[i] thinned base: %d -> %d event(s), %d -> %d distinct trail(s)"
              % (len(base_lines), len(thinned), len(names), len(keep)))
        base_lines = thinned
        base = _rows(base_lines)

    day = base[0][FI["time"]][:10]
    sensor = base[0][FI["sensor"]]
    print("[i] base: %d event(s), day %s, sensor %r" % (len(base), day, sensor))

    have = {name: (sum(1 for r in base if test(r)) if test else 0) for name, test in SHAPES}
    have["second-sensor"] = len(set(r[FI["sensor"]] for r in base))
    for name, count in have.items():
        print("[i]   %-16s %s" % (name, count if name != "second-sensor" else "%d sensor(s)" % count))

    donors = _read_sensor_events(args.log_dir)
    print("[i] sensor run: %d event(s) to draw from" % len(donors))

    added = []      # SYNTHESISED from the sensor run - every address must be documentation-safe
    copied = []     # copies of BASE rows under a second sensor name - real capture data, exempt

    # The detect-test fixtures are deliberately named as fixtures ("apt test (malware)",
    # 192.0.2.66, dead::beef). That is right for a test and wrong for a demo: 77 obviously
    # synthetic rows sitting among 2,500 captured ones is exactly what makes a demo look fake.
    # Relabel on the way in - the SHAPE is what the dashboard renders, the names are cosmetic.
    # Names only - NEVER addresses.
    #
    # The fixtures use RFC 5737 / RFC 3849 documentation addresses (203.0.113.x, 198.51.100.x,
    # 192.0.2.x, dead::beef) precisely so a demo cannot accuse anyone. Rewriting them to
    # "realistic" ones did exactly that: 2a03:2880:f12d:83:face:b00c::1 is Meta Platforms
    # Ireland and 185.220.101.47 is a real Tor exit node, and both were published on a public
    # page labelled as malware C2. Documentation ranges look synthetic because they ARE, which
    # is the whole point of them.
    #
    # Domains are relabelled: the fixture names say "test", and unlike an address a name under a
    # TLD that resolves to nothing accuses nobody. Both below are NXDOMAIN.
    RELABEL = (
        ("tunnel-zone-test.com", "n2-relay.net"),
        ("exhausted-zone-test.com", "lookup.aeqx-cdn.net"),
        ("custom-watch-test.com", "payroll-export.internal.corp"),
        ("ek-nuclear-test.com", "ek-nuclear-gate.biz"),
        ("botnet c2 (test)", "cobalt strike beacon (malware)"),
        ("malware (test)", "emotet (malware)"),
        ("phishing (test)", "credential phishing (malicious)"),
        ("apt test (malware)", "apt29 (malware)"),
        ("ransomware test (malware)", "wannacry (malware)"),
    )

    def blend(line, copies, hosts=None):
        """Add `copies` of `line` spread over the demo's day, optionally varying the source host."""
        for _ in range(copies):
            hh, mm, ss = random.randint(0, 12), random.randint(0, 59), random.randint(0, 59)
            out = _retime(line, day, hh, mm, ss, random.randint(0, 999999))
            out = _resensor(out, sensor)
            if hosts:
                # Which end is OURS depends on the direction, exactly as core/geo.py:event_country
                # decides which end to place on the map. Rewriting the source unconditionally put a
                # LAN host in the attacker's seat for the inbound heuristics - and gave each event
                # of a web scan a DIFFERENT scanner, which is not what the heuristic even detects.
                row = logfmt.fields(out)
                ours = _our_side(row)
                out = out.replace(" %s " % row[ours], " %s " % random.choice(hosts), 1)
            for fixture, real in RELABEL:
                out = out.replace(fixture, real)
            added.append(out)

    # --- IPv6: one C2 domain resolved by a handful of v6 hosts, like the v4 clusters around it
    if not have["ipv6"]:
        donor = next((d for d in donors if ":" in logfmt.fields(d)[FI["dst_ip"]]), None)
        if donor:
            blend(donor, 22, hosts=["2001:db8:2::11", "2001:db8:2::17", "2001:db8:5::4"])   # RFC 3849
            print("[i] + ipv6            22 event(s)")

    # --- (custom) origin: an internal watchlist hit, seen a few times from two hosts
    if not have["custom-origin"]:
        donor = next((d for d in donors if logfmt.fields(d)[FI["reference"]] == "(custom)"), None)
        if donor:
            blend(donor, 9, hosts=LAN_HOSTS[:4])
            print("[i] + custom-origin    9 event(s)")

    # --- ICMP against a known-bad address
    if not have["icmp"]:
        donor = next((d for d in donors if logfmt.fields(d)[FI["proto"]] == "ICMP"), None)
        if donor:
            blend(donor, 6, hosts=LAN_HOSTS[:5])
            print("[i] + icmp             6 event(s)")

    # --- a second sensor, so the condensed SENSOR cell has something to render
    if have["second-sensor"] < 2:
        second = "dmz probe"          # contains a space: also exercises the quoted-field path
        picked = random.sample(base_lines, 40)
        for line in picked:
            copied.append(_resensor(line, second))
        print("[i] + second-sensor   40 event(s) (sensor %r, re-labelled copies)" % second)

    # --- every detection class the sensor emits that the base file does not contain
    donor_rows = [(d, logfmt.fields(d)) for d in donors]
    for label, needle, copies in CLASSES:
        if _class_present(base, needle):
            continue
        if needle.startswith("\x00"):
            want = needle[1:]
            donor = next((d for d, r in donor_rows if r[FI["type"]] == want), None)
        else:
            donor = next((d for d, r in donor_rows if needle in r[FI["info"]]), None)
        if donor is None:
            print("[!] %-22s no example in the sensor run - NOT added" % label)
            continue
        blend(donor, copies, hosts=LAN_HOSTS)
        print("[i] + %-20s %2d event(s)" % (label, copies))

    if not added and not copied:
        print("[i] nothing to add - demo.js already covers every class and shape")
        return 0

    # Every address in an ADDED event must be private or documentation-reserved. The base file is
    # a real capture and keeps its real addresses; anything this tool invents must not be able to
    # name somebody's infrastructure. Publishing "cobalt strike beacon (malware)" against a Meta
    # address is how this check came to exist.
    safe = re.compile(r"""^(?:
          10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.|127\.      # RFC 1918 / loopback
        | 192\.0\.2\.|198\.51\.100\.|203\.0\.113\.             # RFC 5737 documentation
        | 2001:db8:                                                  # RFC 3849 documentation
        | -$                                                         # absent (ICMP has no ports)
        )""", re.X)
    offenders = []
    for line in added:
        row = logfmt.fields(line)
        if not row:
            continue
        # src: this is a monitored network, so it must be one of our own hosts.
        # trail: this is the thing being called malicious, so it must never name a real address.
        # dst is deliberately NOT checked - for a DNS detection it is the resolver being queried,
        # which the base capture shows as 8.8.8.8, and naming a resolver accuses nobody.
        for field in ("src_ip", "trail"):
            value = row[FI[field]]
            if field == "trail" and not _looks_like_address(value):
                continue        # a domain, a URL path or a fingerprint hash - not an address
            for one in value.split(","):
                one = one.strip().split("]")[0].lstrip("[").split(":53")[0]
                if one and one != "-" and not safe.match(one):
                    offenders.append((field, one, row[FI["info"]]))
    if offenders:
        seen = sorted(set(offenders))
        print("[!] refusing to write: %d added event(s) carry a real-world address" % len(offenders))
        for field, one, info in seen[:8]:
            print("[!]     %-8s %-40s %s" % (field, one, info))
        print("[!] added events must use RFC 1918 / RFC 5737 / RFC 3849 addresses - a demo must "
              "not label anybody's infrastructure as malware")
        return 1

    merged = sorted(base_lines + added + copied, key=lambda l: logfmt.fields(l)[FI["time"]])
    print("[i] writing %d event(s) (%d base + %d added + %d re-sensored)"
          % (len(merged), len(base_lines), len(added), len(copied)))

    body = " +\n    ".join("'%s\\n'" % _.replace("\\", "\\\\").replace("'", "\\'") for _ in merged)
    header = original[:original.index("function getDemoCSV()")]
    with open(args.out, "w", encoding="utf8") as f:
        f.write("%sfunction getDemoCSV() {\n    return %s\n}\n" % (header, body))
    print("[i] wrote %s" % args.out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
