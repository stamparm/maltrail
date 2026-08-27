#!/usr/bin/env python3

"""
Copyright (c) 2014-2026 Maltrail developers (https://github.com/stamparm/maltrail/)
See the file 'LICENSE' for copying permission

Does anything we PUBLISH point at infrastructure that other people share?

Maltrail's trails are redistributed. They go into FireHOL's ipsets, oisd, NextDNS, NoTracking,
pfBlockerNG, MobSF and others - nine "trails only" integrations in the README - and none of those
consumers run update_trails(). They take the lists verbatim and turn them into firewall DROP rules
and DNS blocklists.

That breaks the usual reasoning about a bad indicator. Inside Maltrail, a trail on a Cloudflare edge
is harmless: core/update.py deletes it before the sensor ever sees it, so it produces no event and
no false positive. Downstream it is a live rule that blocks a CDN edge for everybody applying the
set - and it arrives with our name on it. That is a reputational failure, not a detection one, and
nothing in this project was looking for it: sensor/tools/check_trails.py judges an entry by whether
MALTRAIL would match it.

So this asks the other question, against what is actually published, using the providers' own
current ranges rather than a snapshot that can go stale:

    python3 sensor/tools/check_redistribution.py --path ../trails
    python3 sensor/tools/check_redistribution.py --aggregate trails.csv

Exit status: 0 clean, 1 something we publish is on shared infrastructure, 2 the check could not run
(a provider list was unreachable). 2 is not 0 on purpose - "could not check" must never read as
"nothing found".
"""

from __future__ import print_function

import argparse
import ipaddress
import json
import os
import re
import sys

try:
    from urllib.request import Request, urlopen
except ImportError:                                     # pragma: no cover - py2 shim
    from urllib2 import Request, urlopen                # noqa: F401

TIMEOUT = 30
IPV4_KEY = re.compile(r"\A(\d{1,3}(?:\.\d{1,3}){3})(?:[:/]\d+)?\Z")
IPV6_KEY = re.compile(r"\A([0-9A-Fa-f:]{2,45})(?:/\d+)?\Z")

# SHARED infrastructure only, which is a much narrower thing than "an address a cloud provider
# owns" - and getting that wrong makes this tool useless rather than merely wrong.
#
# The first version of this check flagged 32,667 entries, 17,006 of them AWS. Nearly all were real:
# an AdaptixC2 server on an EC2 instance is genuinely malicious and genuinely worth blocking,
# because that address is ONE tenant's machine. A Cloudflare edge is not - it fronts thousands of
# unrelated sites, so a rule against it is collateral damage against everyone but the attacker.
# An alarm that fires 32,000 times is muted on the first day, and then it protects nothing.
#
# So: reverse proxies and CDNs in full, and from AWS only the services that are a shared front
# door. EC2, EBS, WORKSPACES and the rest are single-tenant and stay eligible for listing. GCP's
# cloud.json is tenant compute for the same reason; goog.json is Google's own frontend and is not.
AWS_SHARED_SERVICES = ("CLOUDFRONT", "GLOBALACCELERATOR", "S3", "API_GATEWAY", "ROUTE53_RESOLVER")

SOURCES = (
    ("cloudflare", "https://www.cloudflare.com/ips-v4/", "lines"),
    ("cloudflare", "https://www.cloudflare.com/ips-v6/", "lines"),
    ("aws", "https://ip-ranges.amazonaws.com/ip-ranges.json", "aws"),
    # goog.json is EVERY Google-owned range, GCP customer compute included, so on its own it
    # flagged 15,728 entries - 13,487 of them Gafgyt bots on rented instances, which are exactly
    # the single-tenant addresses that SHOULD be listable. Google documents the subtraction:
    # goog.json minus cloud.json leaves Google's own frontend, which is the shared part.
    ("google", "https://www.gstatic.com/ipranges/goog.json", "gcp"),
    ("google:exclude", "https://www.gstatic.com/ipranges/cloud.json", "gcp"),
    ("fastly", "https://api.fastly.com/public-ip-list", "fastly"),
)

# Piles whose whole purpose is to name shared infrastructure. update_trails() spares them and so
# does this: reporting them would be reporting the intent.
EXEMPT_INFO = ("parking", "sinkhole", "cdn", "mass scanner")


def fetch(url):
    request = Request(url, headers={"User-agent": "maltrail-redistribution-check"})
    return urlopen(request, timeout=TIMEOUT).read().decode("utf8", "replace")


def networks():
    """{provider: [ip_network, ...]} from the providers' own published lists."""

    retval = {}
    for provider, url, kind in SOURCES:
        try:
            body = fetch(url)
        except Exception as ex:
            raise RuntimeError("%s (%s): %s" % (provider, url, ex))

        prefixes = []
        if kind == "lines":
            prefixes = [_.strip() for _ in body.splitlines() if _.strip()]
        elif kind == "aws":
            data = json.loads(body)
            prefixes = [_["ip_prefix"] for _ in data.get("prefixes", [])
                        if _.get("service") in AWS_SHARED_SERVICES]
            prefixes += [_["ipv6_prefix"] for _ in data.get("ipv6_prefixes", [])
                         if _.get("service") in AWS_SHARED_SERVICES]
        elif kind == "gcp":
            data = json.loads(body)
            for entry in data.get("prefixes", []):
                prefixes.append(entry.get("ipv4Prefix") or entry.get("ipv6Prefix"))
        elif kind == "fastly":
            data = json.loads(body)
            prefixes = list(data.get("addresses", [])) + list(data.get("ipv6_addresses", []))

        nets = retval.setdefault(provider, [])
        for prefix in prefixes:
            if not prefix:
                continue
            try:
                nets.append(ipaddress.ip_network(prefix.strip(), strict=False))
            except ValueError:
                continue
    return retval


def index(provider_nets):
    """Bucket the prefixes so a lookup is a short list scan, not 11,600 comparisons.

    Keyed on the leading octet for v4 and the leading hextet for v6, which is what
    core/settings.py does for CDN_RANGES. A naive nested loop over 1.8M entries never finished.
    """

    buckets = {}
    for provider, nets in provider_nets.items():
        for net in nets:
            first = int(net.network_address)
            last = int(net.broadcast_address)
            if net.version == 4:
                lo, hi, shift = first >> 24, last >> 24, 4
            else:
                lo, hi, shift = first >> 112, last >> 112, 6
            # A prefix shorter than the bucket width spans several buckets; register it in each.
            for key in range(lo, hi + 1):
                buckets.setdefault((shift, key), []).append((first, last, provider))
    return buckets


def match(buckets, address, exclude=None):
    """The provider whose SHARED range contains `address`, or None.

    `exclude` is checked first. goog.json publishes 34.64.0.0/10 - a superset that swallows GCP
    customer compute - while cloud.json carves out the specific customer prefixes inside it, like
    34.102.128.0/17. Subtracting one prefix list from the other needs real prefix arithmetic;
    asking "is this address also in the customer list" at lookup time is exact and costs nothing.
    Without it this flagged 13,487 Gafgyt bots on rented instances, which are precisely the
    single-tenant addresses that SHOULD be listable.
    """

    value = int(address)
    key = (4, value >> 24) if address.version == 4 else (6, value >> 112)

    if exclude is not None:
        for first, last, _ in exclude.get(key, ()):
            if first <= value <= last:
                return None

    for first, last, provider in buckets.get(key, ()):
        if first <= value <= last:
            return provider
    return None


def _address(key):
    match = IPV4_KEY.match(key)
    if match:
        try:
            return ipaddress.ip_address(match.group(1))
        except ValueError:
            return None
    match = IPV6_KEY.match(key)
    if match and match.group(1).count(':') >= 2:
        try:
            return ipaddress.ip_address(match.group(1))
        except ValueError:
            return None
    return None


def scan_tree(root):
    """(key, info, where) for every address entry in a content tree."""

    for base, _, files in os.walk(root):
        for name in sorted(files):
            if not name.endswith(".txt"):
                continue
            path = os.path.join(base, name)
            info = os.path.splitext(name)[0].replace('_', ' ')
            with open(path, "rb") as handle:
                for number, line in enumerate(handle, 1):
                    line = line.decode("utf8", "replace").strip()
                    if not line or line.startswith('#'):
                        continue
                    line = re.sub(r"\s*#.*", "", line).strip()
                    if line:
                        yield line, info, "%s:%d" % (os.path.relpath(path, root), number)


def scan_aggregate(path):
    """(key, info, where) for every address row in an assembled trails.csv."""

    import csv

    with open(path, "r") as handle:
        for number, row in enumerate(csv.reader(handle, delimiter=',', quotechar='"'), 1):
            if row and len(row) == 3:
                yield row[0], row[1], "%s:%d" % (os.path.basename(path), number)


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--path", help="a checkout of the trails content repository")
    group.add_argument("--aggregate", help="an assembled trails.csv")
    parser.add_argument("--max-report", type=int, default=40, help="how many hits to print (default 40)")
    options = parser.parse_args()

    try:
        provider_nets = networks()
    except RuntimeError as ex:
        # Loudly, and NOT exit 0. An unreachable provider list means this check did not run; a green
        # tick would say "we looked and it is fine", which is the lie this whole tool exists to stop.
        print("[x] could not fetch a provider range list: %s" % ex, file=sys.stderr)
        print("[!] the redistribution check DID NOT RUN - treat this as unknown, not clean", file=sys.stderr)
        return 2

    total = sum(len(v) for k, v in provider_nets.items() if not k.endswith(":exclude"))
    print("[i] shared ranges: %s (%d prefixes)"
          % (", ".join("%s=%d" % (k, len(v)) for k, v in sorted(provider_nets.items()) if not k.endswith(":exclude")), total))

    excluded = {k: v for k, v in provider_nets.items() if k.endswith(":exclude")}
    provider_nets = {k: v for k, v in provider_nets.items() if not k.endswith(":exclude")}
    buckets = index(provider_nets)
    exclude_buckets = index(excluded) if excluded else None
    entries = scan_tree(options.path) if options.path else scan_aggregate(options.aggregate)

    hits = []
    checked = 0
    for key, info, where in entries:
        address = _address(key)
        if address is None:
            continue
        checked += 1
        if any(_ in (info or "").lower() for _ in EXEMPT_INFO):
            continue
        provider = match(buckets, address, exclude_buckets)
        if provider:
            hits.append((provider, key, info, where))

    print("[i] address entries checked: %d" % checked)

    if not hits:
        print("[i] nothing we publish sits on shared provider infrastructure")
        return 0

    by_provider = {}
    for provider, key, info, where in hits:
        by_provider.setdefault(provider, []).append((key, info, where))

    print("")
    print("[!] %d entr%s on shared provider infrastructure." % (len(hits), "y" if len(hits) == 1 else "ies"))
    print("[!] These are redistributed - FireHOL ipsets, DNS blocklists - by consumers that do NOT")
    print("[!] run update_trails(), so each one becomes a live rule blocking a shared address.")
    print("")
    shown = 0
    for provider in sorted(by_provider):
        rows = by_provider[provider]
        print("  %s (%d)" % (provider, len(rows)))
        for key, info, where in rows:
            if shown >= options.max_report:
                print("      ... and %d more" % (len(hits) - shown))
                return 1
            print("      %-24s %-28s %s" % (key, info, where))
            shown += 1
    return 1


if __name__ == "__main__":
    sys.exit(main())
