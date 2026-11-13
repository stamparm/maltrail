#!/usr/bin/env python3
# coding: utf-8

"""Find static trail entries that can never match anything.

    python3 sensor/tools/check_trails.py            # report
    python3 sensor/tools/check_trails.py --quiet    # exit status only
    python3 sensor/tools/check_trails.py --strict   # warnings fail too

And the other direction - no trail may match a name it must never match:

    python3 sensor/tools/check_trails.py --canaries              # tests/canaries.txt, ~3s (what CI runs)
    python3 sensor/tools/check_trails.py --path-canaries         # tests/canaries-paths.txt: host-less paths

    python3 sensor/tools/check_trails.py --path ../trails/malware --kinds regex \
        --canaries misc/alexa_top-1m.csv.zip:500000 \
                   misc/cisco_top-1m.csv.zip:250000 \
                   misc/tranco_top-1m.csv.zip:50000                # ~7s, run locally

The second form is why this exists: a popularity-list INTERSECTION (misc/alexa1m.py) compares sets,
so a pattern is never equal to a domain and every regex trail is invisible to it.

The `:N` caps and the `malware` path are not decoration - they are misc/alexa1m.py's own choices,
and running without them is wrong. Those lists rank by DNS QUERY VOLUME, which a live phishing
campaign produces in quantity, so their tails are full of real malware; alexa1m.py reads only the
head of each, at a different depth per list because the lists differ in quality. Ignoring that
produced 47 "findings" here of which 46 were list-tail noise (`id-bca.top` is Indonesian bank
phishing, which is roamingmantis' actual target set - being in Tranco says nothing about it).

A hit is a QUESTION, not a verdict: `--allow-trail` accepts a pattern that is broad on purpose.

A trail is only useful in the form the sensor sees on the wire, and the source file is NOT that
form: `core/update.py` runs every non-ASCII key through `key.encode("idna")` on its way into
`trails.csv`. So the question this tool answers is about the WIRE form, not the written one.

    written                    stored in trails.csv          matches?
    -------------------------  ----------------------------  --------------------------------
    ortakoporotör.com          xn--ortakoporotr-fjb.com      yes - the query arrives punycoded
    evil․com  (U+2024 dot)     evil.com                      yes - nameprep maps it to a dot
    a<en-dash>b.com            xn--ab-41t.com                loads, but no such domain exists
    a<nbsp>b.com               "a b.com"                      no - the space is not a DNS name
    host_.tld_                 unchanged                      no - no such TLD

Only the last two rows are INERT (non-zero exit). The en-dash row is a WARNING: idna produced a
syntactically fine name, and nothing here can know whether that punycode domain is real, but a
separator lookalike is the signature of an indicator transcribed out of a PDF rather than
internationalised on purpose.

Inert means: the trail loads, occupies a row, and matches nothing. Same class of failure as a
dead feed - it looks exactly like "no detections". The cases:

  * a non-ASCII key that idna REFUSES. It is stored verbatim, and no query can carry it.
  * a wire form that `core/settings.py:VALID_DNS_NAME_REGEX` rejects - the QUERY is refused
    before the lookup, so what is stored is irrelevant. (Verified by replay: no event.)
  * an UNDERSCORE in the last label. `_` is legal in every other label; a TLD does not have one.
  * a last label in `IGNORE_DNS_QUERY_SUFFIXES` - the query is dropped before the lookup.

Reported but NOT failing the gate: a trail whose PARENT domain is whitelisted. The sensor's loader drops it
(`whitelist::check_domain_member` walks parents), while the updater's own `check_whitelisted()` does not walk
parents - so it survives the build, lands in trails.csv, and is discarded at load. 3,082 static entries are in
that state, most of them specific malicious names on shared platforms (676 under cloudfront.net, 491 under
amazonaws.com, 398 under azurewebsites.net). Which list should win is a policy call, not a typo, so this is a
report: the point is that the number was invisible.

A bare TLD like `xyz` is NOT reported. Those come from the `.xyz`-style entries in
suspicious/domain.txt, the loader strips the leading dot, and the sensor's parent-domain walk
reaches them - `evil.xyz` matches the trail `xyz`. Confirmed the same way.

The idna claim is not a reading of the code: `xn--supportforum-tqa.org` (written
`support¬forum.org` in malware/apt_darkhotel.txt) was replayed as a DNS query through the release
sensor against a one-row trail set - 2 packets, 1 event, and none for the control name. Reporting
it as unreachable, which this tool used to do, was the false positive that kept it out of CI.
"""

import argparse
import datetime
import difflib
import io
import ipaddress
import os
import re
import sys
import zipfile

ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))


def _default_trails_path():
    """Where to look for the static trail content, now that it is a separate repository."""

    for candidate in (os.environ.get("MALTRAIL_TRAILS_DIR"),
                      os.path.join(os.path.dirname(ROOT), "trails"),   # a sibling checkout
                      os.path.join(ROOT, "trails", "static")):         # a pre-split tree
        if candidate and os.path.isdir(candidate):
            return candidate
    return os.path.join(os.path.dirname(ROOT), "trails")
sys.path.insert(0, ROOT)

from core.assemble import fingerprint  # noqa: E402
from core.common import bogon_ip, cdn_ip  # noqa: E402
from core.settings import IGNORE_DNS_QUERY_SUFFIXES  # noqa: E402
from core.settings import VALID_DNS_NAME_REGEX  # noqa: E402
from core.settings import read_bogon_ranges, read_cdn_ranges  # noqa: E402

# The same tables update_trails() filters on, so this agrees with the build by construction rather
# than by keeping a second copy of anybody's published ranges in step.
read_cdn_ranges()
read_bogon_ranges()

VALID_DNS = re.compile(VALID_DNS_NAME_REGEX)
IPV4 = re.compile(r"\A\d+\.\d+\.\d+\.\d+\Z")
# A TLS fingerprint written bare - the shapes the sensor recognises (`trails::fingerprint_shape`):
# JA3 (MD5 hex), a certificate's SHA-1 or SHA-256 hex, anything ending in JA4's `_<12 hex>_<12 hex>`.
# Static files write them typed ("ja3:...", see core/assemble.py:fingerprint); a bare one still
# matches, but nothing says which kind of hash it is.
FINGERPRINT = re.compile(r"\A(?:[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64}|.*_[0-9a-f]{12}_[0-9a-f]{12})\Z")
# A hosts-file line pasted without its separator: `0.0.0.0 www.evil.com` became `0.0.0.0www.evil.com`
# (or `0www.evil.com` when the column was cut short). Still a valid name, so it loads - for a host
# nobody will ever query. Only the sink addresses hosts files use, and only before a whole name:
# `360www.ca`, `222www.no-ip.biz` and `001www.com` are real names, and a looser prefix reported them.
HOSTS_PASTE = re.compile(r"\A(?:0\.0\.0\.0|127\.0\.0\.1|0)www\.[^.]+\.")
# A sandbox whose resolver had `ovh.net` as its DNS search domain: the real C2 name with the search
# domain glued on (`kiss58.myvnc.com.ovh.net`). Nobody queries that, so the trail is dead and the real
# name is missing. Only reported when the part before `.ovh.net` itself ends in a TLD - OVH's own
# names (`vps-1a2b3c4d.vps.ovh.net`, `ns341617.ovh.net`) never do.
SEARCH_DOMAIN = re.compile(r"\A(.+\.([a-z]+))\.ovh\.net\Z")
# A typed fingerprint with the prefix mistyped (`ja3=`, `cer:`, `ja4 :`): judged as a name or an
# address it got a verdict about DNS or ports, or for `ja4=` only "a bare fingerprint" (#19658).
MISTYPED_FINGERPRINT = re.compile(r"\A(?:ja3|ja4|cert?)\s*[=:]", re.I)
# Underscore names a domain publishes for OTHER parties to look up (RFC 8552 attribute leaves, SRV
# services, RFC 7929/8460/8461): mail servers ask _dmarc. and _mta-sts., CAs _acme-challenge., SIP and
# XMPP clients their SRV names. Malware does not, so such a trail flags the victim's mail server or a
# certificate renewal. A passive-DNS dump brings them in with the real C2 name (#19660). Only these
# labels: `_dc-mx.<hash>.` and the like are the campaign's own names.
SERVICE_LABEL = re.compile(r"(?:\A|\.)_(?:openpgpkey|acme-challenge|amazonses|asuid|bimi|caldav|carddav|dmarc|dns-sd|"
                           r"dnsauth|domainkey|gc|github-challenge|globalsign-domain-verification|kerberos|kpasswd|ldap|"
                           r"mta-sts|services|sip|sipfederationtls|sipinternal|sipinternaltls|sips|smtp|tls|tcp|udp|spf|"
                           r"xmpp-client|xmpp-server)\.")
# suspicious/bad_rmmtool.txt lists RMM servers an attacker runs. A university's or a government's own
# ScreenConnect/SimpleHelp is not that - 79 of them arrived in one bulk "every server running X" import
# (removed 2026-11), and each one flags that institution's IT department talking to its own helpdesk.
INSTITUTIONAL = re.compile(r"\.(?:edu|gov|mil|gov\.[a-z]{2}|ac\.uk|ac\.za|ac\.jp|edu\.au|ac\.nz)\Z")
# IPv6 ranges that name a machine's OWN interface or segment rather than anything on the internet. A
# sandbox report lists them because the sample talked to its own link-local neighbour. Deliberately
# NOT `ipaddress`'s is_private/is_reserved: those include 200::/7, which is Yggdrasil - real overlay
# C2 (`[201:b479:...]:8080` in malware/norddragonscan.txt) that the sensor matches like any other.
ULA = ipaddress.ip_network("fc00::/7")

# Characters that look like a separator but are not one. An indicator carrying these was almost
# certainly transcribed from a report rather than internationalised on purpose.
LOOKALIKES = {
    0x2010: "hyphen (U+2010)", 0x2011: "non-breaking hyphen", 0x2012: "figure dash",
    0x2013: "en dash", 0x2014: "em dash", 0x2212: "minus sign",
    0x2024: "one dot leader", 0x3002: "ideographic full stop", 0xFF0E: "fullwidth full stop",
    0x00A0: "non-breaking space",
}


def public_suffixes():
    """Every ICANN public suffix, from data/public_suffix_icann.txt. Empty set if the file is missing.

    A trail equal to one of these does not name a host, it names a REGISTRY: the sensor's
    parent-domain walk makes a trail on `com.cn` match every domain in China's commercial namespace.
    That is the most expensive mistake this content can make, and the rule for catching it lived in
    a script on one workstation rather than in CI.
    """

    path = os.path.join(ROOT, "data", "public_suffix_icann.txt")
    try:
        with io.open(path, encoding="utf8", errors="replace") as handle:
            return set(_.strip().lower() for _ in handle
                       if _.strip() and not _.startswith("#"))
    except EnvironmentError:
        print("[!] %s is missing; skipping the public-suffix check" % os.path.relpath(path, ROOT))
        return set()


def private_suffixes():
    """The PRIVATE half of the Public Suffix List (data/public_suffix_private.txt): hosting platforms
    and second-level registries. Empty set if the file is missing."""

    path = os.path.join(ROOT, "data", "public_suffix_private.txt")
    try:
        with io.open(path, encoding="utf8", errors="replace") as handle:
            return set(_.strip().lower() for _ in handle if _.strip() and not _.startswith("#"))
    except EnvironmentError:
        print("[!] %s is missing; skipping the hosting-platform check" % os.path.relpath(path, ROOT))
        return set()


def whitelisted_parents():
    """The whitelist as loaded: data/whitelist.txt plus the configured WHITELIST.

    What it MEANS for a trail changed in 3.2. Before that, a name was suppressed whenever any ancestor was
    whitelisted, which made every exact trail on a shared platform dead on arrival. The sensor now applies
    longest-match precedence: only an entry equal to the full name vetoes a trail hit, so
    `evil.cloudfront.net` fires even though `cloudfront.net` is whitelisted. A whitelisted ancestor still
    suppresses HEURISTICS on that host, and still suppresses wildcard trails, neither of which is a
    reachability question about a written trail.

    Both the updater's `check_whitelisted()` and the loader's are exact-match plus IPv4 ranges - neither
    walks parents - so nothing is dropped from the build or the load on an ancestor's account either.
    """

    try:
        from core.settings import read_config, read_whitelist
        import core.settings as settings
        read_config(os.path.join(ROOT, "maltrail.conf"))
        read_whitelist()
        return set(settings.WHITELIST or ())
    except Exception as ex:
        print("[!] could not load the whitelist (%s); skipping that check" % ex)
        return set()


def whitelisted_parent(name, whitelist):
    """The whitelisted ancestor that suppresses `name`, or None.

    >>> whitelisted_parent("evil.cloudfront.net", {"cloudfront.net"})
    'cloudfront.net'
    >>> whitelisted_parent("a.b.evil.example", {"evil.example"})
    'evil.example'
    >>> whitelisted_parent("cloudfront.net", {"cloudfront.net"}) is None
    True
    >>> whitelisted_parent("notcloudfront.net", {"cloudfront.net"}) is None
    True
    """

    parts = name.split('.')
    for i in range(1, len(parts) - 1):           # strict ancestors only: an exactly-listed name is the operator's own call
        candidate = '.'.join(parts[i:])
        if candidate in whitelist:
            return candidate
    return None


def entries(path, host_only=True):
    """(line number, key, raw line) for each trail a file contributes, normalised the way core/assemble.py does.

    `host_only` reduces a URL trail to its host, which is what the reachability checks want: only
    the host part has to be a resolvable name. It is WRONG for the popularity/canary index, and was
    used there - so `archive.org/download/hbankers-latest/HBankers_Latest.hta` was indexed as the
    literal `archive.org` and reported as a trail on one of the most important sites on the web. Ten
    of eighty top-10k hits were that artifact, every one of them a correct trail.
    """
    # `with`, because a caller that stops early (or a generator the GC has not reached) otherwise
    # leaves the handle open - visible as a ResourceWarning once anything iterates thousands of these.
    with io.open(path, encoding="utf8", errors="replace") as handle:
        for number, line in enumerate(handle, 1):
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            line = re.sub(r"\s*#.*", "", line)      # inline comments are stripped by the loader
            if not line:
                continue
            raw = line
            if host_only:
                if '://' in line:
                    line = re.search(r"://(.*)", line).group(1)
                if '/' in line:                      # URL/path trail: the host part is what must be a name
                    line = line.split('/')[0]
            # The raw key travels with the reduced one: a whitelisted host kills a bare-domain trail and a
            # URL trail on that host in DIFFERENT ways, and a report that names the wrong one is worse than
            # one that says nothing.
            yield number, line.strip('.'), raw


def wire_form(key):
    """What `core/update.py` will store for this key, or None if it refuses to encode it."""
    if all(ord(c) < 128 for c in key):
        return key.lower()                       # the ASCII path: update.py only lowercases
    try:
        return key.encode("idna").decode("ascii").lower()
    except Exception:
        return None                              # stored verbatim, and no query can carry it


# Roots outside ICANN that malware really resolves through: EmerCoin, Namecoin, OpenNIC, Tor, I2P, ENS.
ALT_ROOTS = frozenset("bazar bit coin emc lib dyn geek libre oss pirate parody gopher indy glue null fur o bbs "
                      "chan cyb epic neo oz i2p onion exit eth".split())


def tlds(suffixes):
    """Every delegated TLD: the last label of each ICANN suffix."""
    return frozenset(_.rsplit('.', 1)[-1] for _ in suffixes or ())


def address_problem(key, info=""):
    """(verdict, name) for a key that looks like an address: `verdict` as classify() returns it, and `name`
    set only when the key turned out to be a NAME with a port, which the caller then judges as a name.

    Every key with a ':' used to be waved through here as "an address", so a malformed one was the
    quietest kind of inert: `182.86.133:8880` (a quad missing), `144.31.61.102::8084` (a doubled colon),
    `[201:b479:2771:8df4:b5eb:d007:63b0]:2838` (seven groups). The sensor matches an address trail
    against the address it RENDERS from the packet (`1.2.3.4`, `1.2.3.4:80`, `2001:db8::1`,
    `[2001:db8::1]:80` - core/addr.py:canonical_ip_trail), so a string no address renders as matches
    nothing, ever. The stdlib parser decides, not another regex.
    """

    host, port, bracketed = key, None, key.startswith('[')
    if bracketed:
        host, _, port = key[1:].partition(']')
        if not port.startswith(':'):
            return ("inert", "a bracketed address is only ever rendered as '[IPv6]:port'"), None
        port = port[1:]
    elif key.count(':') == 1:
        host, _, port = key.partition(':')
    if port is not None and not (port.isdigit() and 0 < int(port) <= 0xffff):
        return ("inert", "invalid port: %r is not 1-65535, so no connection is rendered with it" % port), None
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        if re.match(r"\A[\d.]+(?::\d+){2,}\Z", key):
            # `213.165.60.118:22:443` - a report's "ports 22 and 443", written as one trail
            return ("inert", "several ports on one address: write one trail per port (%r matches nothing)" % key), None
        if bracketed or ':' in host or re.match(r"\A[\d.]+\Z", host):
            return ("inert", "not a valid IPv4/IPv6 address, with or without a port - nothing on the wire "
                             "is rendered as %r" % key), None
        return None, host                        # `evil.com:443`: a name with a port

    # update_trails() spares parking/sinkhole entries, whose whole point is to name shared
    # infrastructure. Mirror that, or this reports them as broken when they are deliberate.
    if any(_ in info for _ in ("parking", "sinkhole")):
        return None, None
    if address.version == 4:
        # An ADDRESS trail can be unreachable for a second reason, and until this looked it was the
        # one inert class nothing reported. update_trails() deletes any trail whose leading quad is a
        # CDN edge or a bogon (core/update.py), so such an entry is added, reviewed, committed, and then
        # silently dropped from every build: the report said "C2 at 104.16.155.10:8888", somebody put it
        # in, and no deployment ever matched it. That is worse than a false positive, because it looks
        # like detection.
        if cdn_ip(str(address)):
            return ("inert", "%s is a CDN edge address: update_trails() drops it, so this trail never reaches a deployment" % address), None
        if bogon_ip(str(address)):
            return ("inert", "%s is a bogon: update_trails() drops it, so this trail never reaches a deployment" % address), None
        return None, None
    # IPv6 has no bogon table in update_trails() (bogon_ip() is IPv4-only), so these DO ship: a warning,
    # not inert. They can only ever match traffic on a sensor's own segment, never the C2 of the report.
    if address.ipv4_mapped:
        return ("warn", "an IPv4-mapped IPv6 address: on the wire this is plain IPv4 %s, so write that" % address.ipv4_mapped), None
    if address.is_unspecified or address.is_loopback or address.is_link_local or address.is_multicast or address in ULA:
        return ("warn", "a non-routable IPv6 address (loopback/link-local/unique-local/multicast): %s is the "
                        "sandbox's own segment, not a C2 - it ships, but matches only a sensor's local traffic" % address), None
    return None, None


def path_problem(raw):
    """(severity, reason) for a URL/path trail whose PATH can never match, or None.

    The sensor looks a request up by its path exactly as it arrived - still percent-encoded, only
    lowercased (sensor/src/protocols/http.rs:build_checks). A client never sends a literal space or a
    raw non-ASCII byte there, so a trail carrying one was copied from a browser's address bar or a
    report's rendering, and matches nothing. entries() reduces a URL trail to its host for every other
    check, so this one reads `raw`.
    """

    rest = (raw or "").split("://", 1)[-1]
    if '/' not in rest or '\\' in raw or WILDCARD.search(raw):
        return None                              # no path, or a regex trail with its own grammar
    hostless = rest.startswith('/')
    path = rest[rest.index('/'):]
    if not hostless:
        path = path.split('?')[0]                # update_trails() drops a host-ful trail's query anyway
    bad = sorted(set(c for c in path if c.isspace() or ord(c) > 127))
    if bad:
        return ("inert", "the path carries %s, but the sensor matches the raw, still percent-encoded request path: "
                         "percent-encode it (UTF-8)" % ", ".join("U+%04X" % ord(c) for c in bad))
    if hostless and path.endswith('?'):
        # A host-ful trail loses its '?query' in update_trails(); a host-less one keeps it, so `/x.php?`
        # matches only a request for exactly `/x.php?` - not `/x.php`, not `/x.php?id=1`.
        return ("warn", "a trailing '?' with no query: this matches only a request for literally '%s', while '%s' "
                        "matches that one and every query too" % (path, path[:-1]))
    return None


def classify(key, whitelist=None, info="", raw=None, suffixes=None, known_tlds=None, platforms=None):
    """(severity, reason) for one trail key, or None when it is reachable as written.

    severity is "inert" - it cannot match, ever - "overbroad": it matches an entire registry rather than a
    host - "shadowed": the whitelist carries the same name, or "warn": it will match something, but probably
    not what the report meant.

    The host (`key`) and the path (`raw`) are judged separately; the worse verdict wins, so a path
    warning never hides an inert host and an inert path is never hidden by a host warning."""

    verdict = _classify_key(key, whitelist, info, raw, suffixes, known_tlds, platforms)
    path = path_problem(raw)
    if path and (verdict is None or (path[0] == "inert" and verdict[0] != "inert")):
        return path
    return verdict


def _classify_key(key, whitelist=None, info="", raw=None, suffixes=None, known_tlds=None, platforms=None):
    """classify() for the host part alone."""

    # Typed TLS fingerprints ("ja3:", "ja4:", "cert:") are matched against a handshake, never as a
    # name - judged as one, a JA4 was "not a valid DNS name" and the gate refused every static JA4.
    typed = fingerprint(raw if raw is not None else key)
    if typed is not None:
        if typed[1] is None:
            return ("inert", "not a valid %s value: core/assemble.py leaves it out, so it never reaches a deployment" % typed[0])
        return None
    if MISTYPED_FINGERPRINT.match(raw if raw is not None else key or ""):
        return ("inert", "a mistyped TLS fingerprint prefix: write ja3:, ja4: or cert: directly followed by the value")
    if key and FINGERPRINT.match(key):
        return ("warn", "a bare TLS fingerprint: write it as ja3:/ja4:/cert:<value> so its type is explicit")
    if not key:
        return None                              # a host-less path trail: path_problem() judges it
    if IPV4.match(key) or ':' in key:
        verdict, key = address_problem(key, info)
        if verdict or key is None:
            return verdict
        # else `key` was a NAME with a port (`evil.com:443/gate.php`), and the name is judged below
    if re.search(r"[*\[\]]", key):
        return None                              # wildcard trail, matched by regex instead

    lookalike = sorted({LOOKALIKES[ord(c)] for c in key if ord(c) in LOOKALIKES})
    wire = wire_form(key)

    if wire is None:
        return ("inert", "not ASCII and idna refuses it: stored verbatim, unreachable")

    # A dotless key is a bare-TLD trail (the `.xyz` entries in suspicious/domain.txt, with the
    # leading dot stripped by the loader). It is never a query itself - the parent-domain walk
    # reaches it from `evil.xyz` - so validate the query that WOULD reach it, not the key.
    # This subsumes an UNDERSCORE in the last label: VALID_DNS_NAME_REGEX accepts '_' in every
    # label but the last, and there is no TLD with one. (It used to reject the character outright,
    # which stranded 134 trails - dynamic-DNS hosts and the like - because the query was refused
    # before the lookup ever happened.)
    if not VALID_DNS.search(wire if '.' in wire else "probe.%s" % wire):
        return ("inert", "wire form %r is not a valid DNS name: the query is refused before the lookup" % wire)

    last = wire.rsplit('.', 1)[-1]
    if last.isdigit():
        # No TLD is all-numeric, so this is an address with a quad missing (`http://144.172.84`, #19630):
        # loaded as a name, it never matches a name or an address.
        return ("inert", "last label '%s' is a number: not a whole IPv4 address and not a name, so nothing can match it" % last)
    if known_tlds and last not in known_tlds and last not in ALT_ROOTS:
        # A scrape that lost or glued the last label (`minglu.de5` for minglu.de5.net, `1337x.pro2icu`, #19631).
        # Such a name can still be queried, but only as an NXDOMAIN, so it is almost always a broken entry.
        return ("inert", "'.%s' is not a TLD: a truncated or mistyped name (add it to ALT_ROOTS if it is a real alternative root)" % last)
    if last in IGNORE_DNS_QUERY_SUFFIXES:
        # The query is dropped by the ignore-suffix filter BEFORE the lookup, so this trail can
        # never match. Found by a volume test: "dev" sat on that list from when .dev meant a local
        # development name, and kept 7,658 real trails from ever firing after it became a
        # registrable gTLD in 2019.
        return ("inert", "last label '%s' is in IGNORE_DNS_QUERY_SUFFIXES: the query is dropped before lookup" % last)

    if suffixes and wire in suffixes and not (raw or "").startswith("."):
        # WRITTEN BARE. suspicious/domain.txt lists whole namespaces on purpose and marks them with a
        # leading dot - `.tk`, `.xyz`, `.cf` - which the loader strips and which this reads as "yes,
        # the entire namespace, deliberately". Without the dot it is an ordinary trail that nobody
        # noticed was a registry, and it will match every name under it.
        return ("overbroad", "'%s' is an ICANN public suffix: this matches every domain in that "
                             "registry, not a host. Write it as '.%s' if the whole namespace is meant."
                % (wire, wire))
    if platforms and wire in platforms and not (raw or "").startswith("."):
        # `platforms` is passed for malware/ and malicious/ only: suspicious/dynamic_domain.txt
        # lists the providers themselves on purpose.
        return ("overbroad", "'%s' is a hosting platform or registry (Public Suffix List, private section): "
                             "this matches every customer's name under it, not a host" % wire)

    if whitelist and wire in whitelist:
        # LONGEST-MATCH PRECEDENCE (3.2). Only an entry equal to the FULL name vetoes a trail; a tie
        # goes to the whitelist, because the operator cleared this exact name on purpose. Both the
        # updater's check_whitelisted() and the sensor loader's are exact-match too, so the trail is
        # dropped at build time and never reaches trails.csv.
        #
        # This used to report a whitelisted ANCESTOR as suppressing its children, which stopped being
        # true in 3.2 - and it said so with "the sensor's loader drops this trail", which the loader
        # does not do. Measured against the current
        # content that was 3,081 live trails on shared platforms (cloudfront.net, azurewebsites.net,
        # blogspot.com) reported as dead, against 3 that really are. The sensor's behaviour is
        # pinned by sensor/tests/detection.rs::trail_under_whitelisted_parent_fires.
        #
        # Not covered: a WILDCARD trail under a whitelisted ancestor genuinely is still suppressed
        # (wildcard_trail_still_suppressed_by_whitelisted_ancestor), and classify() returns early for
        # wildcards above. There are 25 wildcard trails in the content and none of them sits under a
        # whitelisted parent, so parsing a regex's trailing literal to find them would be fragile
        # code for an empty set. Worth revisiting if that count stops being zero.
        if raw is not None and raw.strip('.') != key:
            # a URL trail: the full key is not whitelisted, so it survives the build AND the load. It dies
            # later, when the sensor refuses to examine a request whose HOST the operator cleared.
            return ("shadowed", "the whitelist carries this host, so the sensor never examines a request to "
                                "it: this URL trail is loaded and can never match")
        return ("shadowed", "the whitelist carries this exact name: a tie goes to the whitelist, so the "
                            "build drops this trail before it reaches trails.csv")

    service = SERVICE_LABEL.search(wire)
    if service:
        return ("warn", "a DNS service record name (%s): mail servers, CAs and SRV clients query it, not malware - "
                        "list the domain it belongs to instead" % service.group(0).strip("."))
    glued = SEARCH_DOMAIN.match(wire)
    if glued and known_tlds and glued.group(2) in known_tlds:
        return ("warn", "a sandbox's DNS search domain glued onto the real name: nobody queries this, "
                        "write '%s'" % glued.group(1))
    if info == "bad rmmtool" and INSTITUTIONAL.search(wire):
        return ("warn", "an institution's own RMM server, not an attacker's: it flags their IT staff at work")
    if HOSTS_PASTE.match(wire):
        return ("warn", "looks like a hosts-file line pasted without its separator ('0.0.0.0 www.x' -> '0.0.0.0www.x'): "
                        "write the name alone")
    if lookalike:
        # idna turned it into a syntactically valid name, so it is not inert - but a dash lookalike
        # punycodes to a domain that almost certainly does not exist.
        return ("warn", "separator lookalike (%s): matches %r, which is probably not the domain in the report"
                % (", ".join(lookalike), wire))
    return None                                  # includes deliberate IDNs: they match their punycode


# The two header lines a trail file carries above its entries. They are not decoration: the
# dashboard quotes the '# Reference:' above a matched trail as its source citation, and downstream
# tooling reads both. A typo ('# Referecne:', '# Reference:https://...', a second colon) is invisible
# in review, survives forever, and silently drops the citation - which is what #19597 is about.
HEADER_KEYS = ("reference", "aliases")
HEADER_CANONICAL = re.compile(r"^# (Reference|Aliases): \S")
# A comment that OPENS with a word and a colon is a header candidate; anything else is prose.
HEADER_CANDIDATE = re.compile(r"^(#+)(\s*)([A-Za-z][A-Za-z ]{2,20}?)\s*(:+)(.*)$")
# The header name followed by the WRONG separator: '# Reference; https://...' (malware/powershell_injector.txt).
# HEADER_CANDIDATE needs a colon to see a header at all, so this was invisible. The name has to be the
# whole first word and something has to follow the separator, so prose ('# References, see below' or a
# sentence that ends in 'Aliases.') is not caught.
HEADER_SEPARATOR = re.compile(r"^#+\s*(?:Reference|Aliases)\s*[;,.=]\s*\S", re.I)


def header_problem(raw):
    """Why this comment line is a malformed '# Reference:' / '# Aliases:' header, or None."""
    if HEADER_SEPARATOR.match(raw):
        return "wrong separator after header name (expected ':')"
    match = HEADER_CANDIDATE.match(raw.rstrip('\n'))
    if not match:
        return None
    hashes, lead, key, colons, value = match.groups()
    folded = key.lower()
    if folded not in HEADER_KEYS:
        # Near-misses only: 'Referecne', 'Refernce', 'Alises'. Everything else is a normal comment
        # ('# Note:', '# Generic trails:'), which this must not touch.
        if not difflib.get_close_matches(folded, HEADER_KEYS, n=1, cutoff=0.82):
            return None
        return "misspelled header %r (expected 'Reference' or 'Aliases')" % key
    line = raw.rstrip('\n')
    if value.lstrip().startswith('#'):
        return "a header pasted into a header ('# Reference: # Reference: ...', #19624)"
    if HEADER_CANONICAL.match(line) and line == line.rstrip():
        return None
    if hashes != '#':
        return "one '#' starts a header, not %d" % len(hashes)
    if lead != ' ':
        return "exactly one space belongs between '#' and the header name"
    if key not in ("Reference", "Aliases"):
        return "header case: %r should be %r" % (key, key.capitalize())
    if colons != ':':
        return "%d colons after the header name" % len(colons)
    if not value.strip():
        # A bare '# Reference:' is deliberate: it breaks the pile so the entries below it are NOT
        # attributed to the citation above (core/httpd.py takes the nearest header above a match).
        # Only the invisible trailing space on one is worth reporting.
        return None if not value else "trailing whitespace on an empty header"
    if not value.startswith(' ') or value.startswith('  '):
        return "exactly one space belongs after the colon"
    if line != line.rstrip():
        return "trailing whitespace"
    return "malformed header"


def header_problems(root):
    """[(path, line, text, reason)] for every malformed Reference/Aliases header under `root`."""
    found = []
    for base, _, files in os.walk(root):
        for name in sorted(files):
            if not name.endswith(".txt"):
                continue
            path = os.path.join(base, name)
            with io.open(path, encoding="utf8", errors="replace") as handle:
                for number, line in enumerate(handle, 1):
                    if not line.startswith('#'):
                        continue
                    why = header_problem(line)
                    if why:
                        found.append((path, number, line.rstrip('\n'), why))
    return found


def repeats(root):
    """[(path, line, key, first line)] for an entry listed twice under the SAME '# Reference:' header.

    Repeats pass only when every copy carries a distinct inline note.

    A repeat under a DIFFERENT reference is kept on purpose: it records that two reports saw the
    same indicator. Within one block it is a paste accident (tinba had a DGA list pasted twice,
    402 lines), and nothing about it survives assembly except the noise in review.
    """
    found = []
    for base, _, files in os.walk(root):
        for name in sorted(files):
            if not name.endswith(".txt"):
                continue
            path = os.path.join(base, name)
            seen = {}
            with io.open(path, encoding="utf8", errors="replace") as handle:
                for number, line in enumerate(handle, 1):
                    line = line.strip()
                    if line.startswith("# Reference:"):
                        seen = {}                    # a new block, even if it cites the same URL again
                        continue
                    key = re.sub(r"\s*#.*", "", line)
                    if not key:
                        continue
                    note = line[len(key):].strip()
                    if key not in seen:
                        seen[key] = (number, set([note]))
                        continue
                    first, notes = seen[key]
                    # Copies that each carry their own note are a record, not an accident:
                    # data/mass_scanner.txt lists an address once per rDNS name it was seen under.
                    if not note or '' in notes or note in notes:
                        found.append((path, number, key, first))
                    notes.add(note)
    return found


def problems(root, whitelist=None, suffixes=None):
    """[(path, line, key, severity, reason)] for every trail entry that is inert, overbroad, shadowed or suspect."""
    found = []
    if suffixes is None:
        suffixes = public_suffixes()
    known_tlds = tlds(suffixes)
    platforms = private_suffixes()
    for base, _, files in os.walk(root):
        for name in sorted(files):
            if not name.endswith(".txt"):
                continue
            path = os.path.join(base, name)
            # The info the assembler will give these entries: the filename, underscores to spaces.
            # Only used for the parking/sinkhole exemption below, which is keyed on it.
            info = os.path.splitext(name)[0].replace('_', ' ')
            # Per FILE, not per entry: relpath() on every one of ~1.9M lines was the single largest cost here.
            pile = os.path.relpath(path, root).replace(os.sep, "/").split("/")[0]
            hosting = platforms if pile in ("malware", "malicious") or root.rstrip("/").endswith(("/malware", "/malicious")) else None
            for number, key, raw in entries(path):
                verdict = classify(key, whitelist, info, raw, suffixes, known_tlds, hosting)
                if verdict:
                    found.append((path, number, key or raw, verdict[0], verdict[1]))   # a host-less path has no key
    return found


def sinkhole_conflicts(root):
    """[(path, line, address, sinkhole path)] for an address listed bare in a sinkhole_*.txt AND as plain
    infrastructure in another file.

    The build keeps the LAST copy of a key, so which label the alert carries - "sinkhole" or the family -
    depended on file order. 657 such entries were found by hand (2026-11): a sandbox report lists every
    address the sample contacted, sinkholes included, and they were pasted in as C2. A URL trail with a
    path on a sinkhole address is a different indicator and is left alone.
    """

    sinks, found = {}, []
    files = []
    for base, _, names in os.walk(root):
        files.extend(os.path.join(base, _) for _ in sorted(names) if _.endswith(".txt"))
    for path in files:
        if os.path.basename(path).startswith("sinkhole_"):
            for _, key, raw in entries(path):
                if IPV4.match(key) and "/" not in raw.split("://", 1)[-1].rstrip("/"):
                    sinks.setdefault(key, path)
    for path in files:
        if os.path.basename(path).startswith("sinkhole_"):
            continue
        for number, key, raw in entries(path):
            address = key.split(":")[0]
            if address in sinks and "/" not in raw.split("://", 1)[-1].rstrip("/"):
                found.append((path, number, key, sinks[address]))
    return found


def base_domain(name, suffixes):
    """The registrable domain of `name` - one label under its longest public suffix - or None.

    >>> base_domain("a.b.aliyuncs.com", {"com"})
    'aliyuncs.com'
    >>> base_domain("bucket.s3.amazonaws.com", {"com", "s3.amazonaws.com"})
    'bucket.s3.amazonaws.com'
    >>> base_domain("com", {"com"}) is None
    True
    """

    labels = name.split(".")
    for i in range(1, len(labels)):
        if ".".join(labels[i:]) in suffixes:
            return ".".join(labels[i - 1:])
    return None


def _allowed(options):
    allowed = set(options.allow_trail)
    for path in options.allow_file:
        allowed.update(allow_file(path))
    return allowed


def _ranked(specs):
    return set(name for spec in specs for name in canaries(*canary_source(spec)))


def brand_report(options):
    """`--brand-subdomains`: no host trail may sit under one of the most popular domains.

    The literal canary check only fires when a trail IS a ranked name. A trail one label below one -
    `ssls.microsoft.com`, `*.mcas.ms` (Microsoft's own Defender proxy), `email.189.cn`, `*.cms.gov` - was
    invisible to it, and that was the bulk of the 2026-11 false-positive clean-up. Host trails only: a
    URL trail with a path names one object on that host, which --stock-paths judges.

    Platforms whose subdomains belong to customers (`*.b-cdn.net`, `*.medium.com`) are allowed WHOLE by a
    leading-dot line in the allow file (`.b-cdn.net  # reason`); anything else is allowed per trail.
    """

    suffixes = public_suffixes() | private_suffixes()
    top, allowed = _ranked(options.brand_subdomains), _allowed(options)
    found = []
    for base, _, files in os.walk(options.path):
        for name in sorted(files):
            if not name.endswith(".txt"):
                continue
            path = os.path.join(base, name)
            for number, key, raw in entries(path):
                key = key.lower()
                if "/" in raw.split("://", 1)[-1] or ":" in key or IPV4.match(key) or WILDCARD.search(raw):
                    continue
                parent = base_domain(key, suffixes)
                if parent and parent != key and parent in top and key not in allowed and "." + parent not in allowed:
                    found.append((path, number, key, parent))
    if not options.quiet:
        print("[i] host trails under the %d most popular domain(s): %d not allowed" % (len(top), len(found)))
        for path, number, key, parent in found[:options.limit]:
            print("      %s:%d  %s  -- under %s" % (os.path.relpath(path, options.path), number, key, parent))
        if len(found) > options.limit:
            print("      ... and %d more" % (len(found) - options.limit))
    return 1 if found else 0


def stock_path_report(options):
    """`--stock-paths`: no URL trail may name an ordinary file on a popular host.

    `luxurylaunches.com/xmlrpc.php` is not a domain, so the canary check never sees it, and it is not
    host-less, so --path-canaries does not either - yet it fires on every WordPress pingback to a
    top-30k site. 429 gootkit trails had that shape, plus `dailynk.com/.../jquery.min.js`. A trail's path
    is stock when an ordinary request (tests/canaries-paths.txt) is looked up under it.
    """

    top, allowed = _ranked(options.stock_paths), _allowed(options)
    stock = set()
    for request in canaries(os.path.join(ROOT, "tests", "canaries-paths.txt")):
        stock.update(path_candidates(request))
    found = []
    for base, _, files in os.walk(options.path):
        for name in sorted(files):
            if not name.endswith(".txt"):
                continue
            path = os.path.join(base, name)
            for number, _, raw in entries(path, host_only=False):
                rest = raw.split("://", 1)[-1].lower()
                if "/" not in rest or rest.startswith("/") or WILDCARD.search(rest) or rest in allowed:
                    continue
                host, _, tail = rest.partition("/")
                trail_path = ("/" + tail).split("?")[0].rstrip("/") or "/"
                if host.split(":")[0] in top and trail_path in stock:
                    found.append((path, number, rest))
    if not options.quiet:
        print("[i] URL trails naming an ordinary file on a popular host: %d not allowed" % len(found))
        for path, number, rest in found[:options.limit]:
            print("      %s:%d  %s" % (os.path.relpath(path, options.path), number, rest))
    return 1 if found else 0


# `re.search(r"[\].][*+]|\[[a-z0-9_.\-]+\]", trail, re.I)` - the rule
# sensor/src/trails/regexset.rs:is_wildcard_trail() implements, and the only trails compiled as
# patterns rather than stored as literals.
WILDCARD = re.compile(r"[\].][*+]|\[[a-z0-9_.\-]+\]", re.I)


# A vendored popularity list carries "# Refreshed: YYYY-MM-DD" in its header. Reported, never
# fatal: a stale canary list is wrong only in the harmless direction - a domain that was in the top
# 10k a year ago is still one that must never be flagged - so the cost of staleness is coverage of
# names that became popular since, not a wrong answer. Measured churn on the top 10k is ~15% per
# six months, hence a year before it starts nagging.
#
# It says the age out loud because the failure mode of a hand-maintained snapshot is that everyone
# forgets it is a snapshot.
REFRESHED = re.compile(r"^#\s*Refreshed:\s*(\d{4})-(\d{2})-(\d{2})\s*$", re.M)
STALE_DAYS = 365


def refreshed_on(path):
    """The '# Refreshed:' date in a canary file's header, or None if it carries no stamp."""

    try:
        with io.open(path, encoding="utf8", errors="replace") as handle:
            match = REFRESHED.search(handle.read(8192))
    except EnvironmentError:
        return None
    if not match:
        return None
    try:
        return datetime.date(*(int(_) for _ in match.groups()))
    except ValueError:
        return None


def staleness(path):
    """A one-line note on how old a vendored list is, or None when it carries no stamp."""

    stamped = refreshed_on(path)
    if stamped is None:
        return None
    age = (datetime.date.today() - stamped).days
    note = "%s: refreshed %s, %d day(s) ago" % (os.path.relpath(path, ROOT), stamped, age)
    return ("[!] %s - worth regenerating, see the header" % note) if age > STALE_DAYS else "[i] %s" % note


def allow_file(path):
    """Trails accepted despite matching a popular name, one per line, `# reason` after each.

    A popularity list ranks by DNS QUERY VOLUME, so a C2 with a large botnet earns a rank the same
    way a news site does - trafficconverter.biz is Conficker's 2008 domain at #28,676, still ranked
    because infected machines still beacon at it. Those are correct trails and must not be deleted
    to quiet a gate, so they are written down WITH the reason instead.

    This is misc/alexa1m.py's IGNORE set, except tracked: that one is the right idea living on one
    workstation, where nobody else can review it or learn from it.
    """

    for line in io.open(path, encoding="utf8", errors="replace"):
        line = re.sub(r"\s*#.*", "", line).strip()
        if line:
            yield line


def canary_source(spec):
    """`PATH` or `PATH:N` -> (path, limit).

    The limit is the point of the syntax. A popularity list is ranked, and its TAIL is full of live
    malware - a widely distributed phishing campaign generates plenty of DNS query volume, which is
    what these lists measure. misc/alexa1m.py therefore reads only the head of each, and the depths
    differ by list because the lists differ in quality:

        alexa 500000, cisco 250000, tranco 50000

    Ignoring that was worth ~46 spurious findings out of 47 on the first run of this tool.

    >>> canary_source("misc/tranco_top-1m.csv.zip:50000")
    ('misc/tranco_top-1m.csv.zip', 50000)
    >>> canary_source("tests/canaries.txt")
    ('tests/canaries.txt', None)
    """

    head, _, tail = spec.rpartition(':')
    if head and tail.isdigit():
        return (head, int(tail))
    return (spec, None)


def canaries(path, limit=None):
    """Stream the names a trail must never match.

    Two shapes, because the same check serves two list sizes: a plain file (tests/canaries.txt, ~50
    names, what CI runs) and a popularity list as shipped - `*.csv.zip` holding `rank,domain` rows,
    which is what misc/ already has cached for the Alexa / Cisco / Tranco top-1M. Pointing this at a
    2.4M-row zip is the thorough pass; it streams rather than building a set, because the trail
    literals already cost ~150 MB of memory and holding both is how a laptop starts swapping.
    """

    seen = 0
    if path.endswith(".zip"):
        with zipfile.ZipFile(path) as archive:
            for name in archive.namelist():
                with archive.open(name) as raw:
                    for line in io.TextIOWrapper(raw, encoding="utf8", errors="ignore"):
                        line = line.strip()
                        if not line or line.startswith('#'):
                            continue
                        seen += 1
                        if limit and seen > limit:      # ranked file: stop at the requested depth
                            return
                        yield line.split(',')[-1].strip().lower()   # "rank,domain" or a bare domain
        return

    with io.open(path, encoding="utf8", errors="replace") as handle:
        for line in handle:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            seen += 1
            if limit and seen > limit:
                return
            # Same normalisation as the zip branch: an UNZIPPED popularity CSV is still "rank,domain",
            # and yielding "1,host.biz" would match nothing and look like a clean run. A canary file's
            # bare names have no comma, so this leaves them alone.
            yield line.split(',')[-1].strip().lower()


def trail_index(root):
    """({literal key: (path, line)}, [(path, line, pattern)]) for a static trail tree."""

    literals, patterns = {}, []

    for base, _, files in os.walk(root):
        for name in sorted(files):
            if not name.endswith(".txt"):
                continue
            path = os.path.join(base, name)
            # host_only=False: a trail is only a false positive against a popular DOMAIN if the
            # trail IS that domain. A path under it is a different indicator entirely.
            for number, key, _raw in entries(path, host_only=False):
                if not key:
                    continue
                if WILDCARD.search(key):
                    try:
                        re.compile(key)
                    except re.error:
                        continue                 # unparseable patterns are the other gate's business
                    patterns.append((path, number, key))
                else:
                    literals.setdefault(key.lower(), (path, number))

    return literals, patterns


def popular_matches(root, names, whitelist=None, stats=None, kinds="both"):
    """[(path, line, key, name, kind)] for every trail that matches one of `names`.

    NOT a false-positive report. Whether a hit is wrong is a judgement this cannot make: a name being
    in a popularity list is not evidence that it is benign, because those lists rank by DNS query
    volume and a live campaign produces plenty of it. `id-bca.top` looks exactly like the Indonesian
    bank phishing roamingmantis targets. A hit means "a human should look at this pattern".

    `kind` is "literal" or "regex". The regexes are the reason this exists: a popularity-list
    INTERSECTION (misc/alexa1m.py) compares sets, so a pattern is never equal to a domain and every
    regex trail is invisible to it. That is the class that reached a customer - a roamingmantis
    pattern matching 89 top-1M domains, amazon-corp.com among them.

    `names` may be a 50-line canary file or a 2.4M-row popularity list, so the regexes are compiled
    into ONE alternation and each name is scanned once; only a name that hits is then attributed to
    a pattern. Measured on the three cached top-1M zips: 11.5s for 2,457,622 names against 27
    patterns, where 27 separate scans would be ~27s.

    Whitelisted names are skipped: the sensor refuses a whitelisted QUERY before any lookup
    (sensor/src/process.rs:147), so a trail matching one cannot fire and reporting it would be a
    false positive that is itself false.
    """

    literals, patterns = trail_index(root)
    # No re.I anywhere: the loader lowercases trails and the sensor's alternation carries no case
    # flag, so matching is case-sensitive on both sides.
    combined = re.compile("|".join("(?:%s)" % _[2] for _ in patterns)) if patterns else None
    compiled = [(path, number, key, re.compile(key)) for path, number, key in patterns]
    found = []

    if stats is not None:
        stats.setdefault("total", 0)
        stats.setdefault("covered", 0)
        stats.setdefault("covered_examples", [])
        stats["patterns"] = len(patterns)

    for name in names:
        if stats is not None:
            stats["total"] += 1
        if whitelist and name in whitelist:
            # EXACT entries only. A whitelisted ancestor does not protect its children since 3.2, so
            # skipping `www.example.com` because `example.com` is whitelisted would hide a real false
            # positive - an exact trail on that host fires. Measured on the top 100k: 197 canaries
            # were being skipped for that reason, none of which we currently list. A latent hole
            # rather than a missed finding, but the gate is meant to be the thing that notices.
            #
            # Counted, not silently dropped: a canary the whitelist already protects cannot fail this
            # gate, and a list made only of such names would pass no matter how broken the trails are.
            if stats is not None:
                stats["covered"] += 1
                if len(stats["covered_examples"]) < 8:
                    stats["covered_examples"].append(name)
            continue
        if kinds in ("both", "literal") and name in literals:
            path, number = literals[name]
            found.append((path, number, name, name, "literal"))
        if kinds in ("both", "regex") and combined is not None and combined.search(name):
            for path, number, key, pattern in compiled:
                if pattern.search(name):
                    found.append((path, number, key, name, "regex"))

    return found


def canary_report(options, whitelist):
    """`--canaries`: no trail may match a name that must never be flagged."""

    sources = [canary_source(_) for _ in options.canaries]

    def names():
        for path, limit in sources:
            for name in canaries(path, limit):
                yield name

    stats = {}
    hits = popular_matches(options.path, names(), whitelist, stats, options.kinds)
    pairs, trails = set(options.allow), set(options.allow_trail)
    for path in options.allow_file:
        trails.update(allow_file(path))
    unexpected = [_ for _ in hits if _[2] not in trails and ("%s:%s" % (_[2], _[3])) not in pairs]

    if not options.quiet:
        print("[i] %s: %d name(s), %d checked against %d pattern(s), %d already covered by the whitelist"
              % (", ".join("%s%s" % (os.path.relpath(_[0], ROOT), ":%d" % _[1] if _[1] else "") for _ in sources), stats["total"],
                 stats["total"] - stats["covered"], stats["patterns"], stats["covered"]))
        # A canary the whitelist protects cannot fail this gate, so it is not silently counted as a
        # pass: google.com, 1.1.1.1 and github.com are all in data/whitelist.txt, and a canary list
        # made only of those would be reassuring and worthless.
        for path, _ in sources:
            note = staleness(path)
            if note:
                print(note)
        if stats["covered"]:
            print("[!] not exercised (whitelist covers them): %s%s"
                  % (", ".join(stats["covered_examples"]), " ..." if stats["covered"] > 8 else ""))

        # Grouped by TRAIL, not one line per hit: one loose pattern against a 1M list produces
        # hundreds of names, and the unit of triage is the pattern - keep it, fix it, or allow it.
        grouped = {}
        for path, number, key, name, kind in unexpected:
            # a set: the three popularity lists overlap heavily, and the same name arriving twice is
            # not two findings
            grouped.setdefault((path, number, key, kind), set()).add(name)
        for (path, number, key, kind), matched in sorted(grouped.items(), key=lambda kv: -len(kv[1])):
            print("\n[?] %s:%d  matches %d name(s) in the list (%s)" % (os.path.relpath(path, ROOT), number, len(matched), kind))
            print("      %s" % key[:110])
            print("      e.g. %s" % ", ".join(sorted(matched)[:5]))
            if len(matched) > 5:
                print("      ... and %d more" % (len(matched) - 5))

        literal = sum(1 for _ in unexpected if _[4] == "literal")
        if literal > 5 and options.kinds == "both":
            print("\n[i] %d of those are LITERAL trails. A popularity list ranks by query volume, so live" % literal)
            print("[i] malware domains legitimately appear in it - that is what misc/alexa1m.py's curated")
            print("[?] IGNORE set absorbs. For the regex-trail question alone, add: --kinds regex")
        if pairs or trails:
            print("\n[i] %d hit(s) accepted via --allow / --allow-trail" % (len(hits) - len(unexpected)))
        if not unexpected:
            print("[i] no trail matches a canary")

    return 1 if unexpected else 0


_PARAM_VALUE = re.compile(r"(\w+=)[^&=]+")


def path_candidates(path):
    """Every key the sensor looks an HTTP request path up under - sensor/src/protocols/http.rs:
    build_checks, without POST data. A host-less trail fires when it equals ANY of them.

    >>> path_candidates("/wp-includes/id3/about.php")
    ['/wp-includes/id3/about.php', '/wp-includes/id3', '/about.php']
    >>> path_candidates("/a/b.php?id=1")
    ['/a/b.php?id=1', '/a/b.php', '/a/b.php?id=', '/a', '/b.php']
    """

    checks = [path.rstrip("/")]
    if "?" in path:
        checks.append(path.split("?")[0].rstrip("/"))
        if "=" in path:
            checks.append(path[:path.index("=") + 1])
        stripped = _PARAM_VALUE.sub(r"\1", path)
        if stripped not in checks:
            checks.append(stripped)
            if stripped.count("/") > 1:
                checks.append("/" + stripped.rsplit("/", 1)[1])
    if checks[-1].count("/") > 1:
        checks.append(checks[-1][:checks[-1].rfind("/")])
        checks.append(checks[0][checks[0].rfind("/"):].split("?")[0])
    return checks


def path_canary_report(options):
    """`--path-canaries`: no host-less path trail may match an ordinary request path."""

    literals, _ = trail_index(options.path)
    trails = {}
    for key, where in literals.items():
        if key.startswith("/") and not key.startswith("//"):
            # core/assemble.py stores "/a/b/" as "/a/b" (a single segment keeps its slash)
            trails.setdefault(key.rstrip("/") if key.count("/") > 1 else key, where)
    allowed = set(options.allow_trail)
    for path in options.allow_file:
        allowed.update(allow_file(path))

    found, checked = {}, 0
    for path, limit in (canary_source(_) for _ in options.path_canaries):
        for request in canaries(path, limit):
            checked += 1
            for candidate in path_candidates(request):
                if candidate in trails and candidate not in allowed:
                    found.setdefault(candidate, set()).add(request)

    if not options.quiet:
        print("[i] %d request path(s) checked against %d host-less path trail(s)" % (checked, len(trails)))
        for key, requests in sorted(found.items(), key=lambda kv: (-len(kv[1]), kv[0])):
            where, number = trails[key]
            print("\n[?] %s:%d  %s  matches %d canary path(s)" % (os.path.relpath(where, options.path), number, key, len(requests)))
            print("      e.g. %s" % ", ".join(sorted(requests)[:5]))
        if not found:
            print("[i] no path trail matches a canary")
    return 1 if found else 0


def _has_trails(path):
    """True when `path` holds at least one trail file. Cheap: stops at the first hit."""

    if not os.path.isdir(path):
        return False
    for _, _, files in os.walk(path):
        if any(name.endswith(".txt") for name in files):
            return True
    return False


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    # Static trail content lives in its own repository now, so there is no in-repo default that is
    # right for everyone. MALTRAIL_TRAILS_DIR, then a sibling checkout, then the pre-split location.
    parser.add_argument("--path", default=_default_trails_path())
    parser.add_argument("--quiet", action="store_true", help="exit status only")
    parser.add_argument("--strict", action="store_true", help="a warning fails too")
    parser.add_argument("--no-whitelist", action="store_true", help="skip the whitelist-shadowing report")
    parser.add_argument("--canaries", nargs="*", default=None, metavar="FILE",
                        help="instead: check that no trail matches a name in FILE (default: tests/canaries.txt). "
                             "Accepts a plain list or a popularity list as shipped (*.csv.zip), and several files")
    parser.add_argument("--path-canaries", nargs="*", default=None, metavar="FILE",
                        help="instead: check that no host-less path trail matches a request path in FILE "
                             "(default: tests/canaries-paths.txt)")
    parser.add_argument("--brand-subdomains", nargs="+", default=None, metavar="FILE[:N]",
                        help="instead: check that no host trail sits under a domain in FILE (a ranked list, "
                             "first N); allow customer platforms whole with '.domain' in --allow-file")
    parser.add_argument("--stock-paths", nargs="+", default=None, metavar="FILE[:N]",
                        help="instead: check that no URL trail names an ordinary file "
                             "(tests/canaries-paths.txt) on a host in FILE")
    parser.add_argument("--allow", action="append", default=[], metavar="TRAIL:CANARY",
                        help="a known, accepted canary hit (repeatable)")
    parser.add_argument("--allow-trail", action="append", default=[], metavar="TRAIL",
                        help="accept every hit from this trail - the intentional broad ones (repeatable)")
    parser.add_argument("--allow-file", action="append", default=[], metavar="FILE",
                        help="a file of accepted trails, one per line with '# reason' (repeatable)")
    parser.add_argument("--kinds", choices=("both", "regex", "literal"), default="both",
                        help="which trails to check against the list (default: both; use 'regex' for a "
                             "popularity list, which legitimately contains malware domains)")
    parser.add_argument("--limit", type=int, default=25, help="lines shown per category")
    options = parser.parse_args()

    # A path with no trails in it is NOT a pass. _default_trails_path() falls back to a sibling
    # checkout that may not exist, and until this was here `check_trails.py` with no arguments
    # walked that missing directory, found nothing, printed "0 entry(ies) that cannot match" and
    # exited 0 - which is how ci.yml gated on this step for months after the split while checking
    # nothing at all. Exit 2, so "could not run" is distinguishable from "ran and found problems".
    if not _has_trails(options.path):
        print("[!] no trail files under '%s'" % options.path)
        print("[!] the static trails are a separate repository: clone https://github.com/stamparm/trails")
        print("[!] beside maltrail, pass --path, or set MALTRAIL_TRAILS_DIR")
        return 2

    whitelist = None if options.no_whitelist else whitelisted_parents()

    if options.brand_subdomains is not None:
        return brand_report(options)
    if options.stock_paths is not None:
        return stock_path_report(options)
    if options.path_canaries is not None:
        options.path_canaries = options.path_canaries or [os.path.join(ROOT, "tests", "canaries-paths.txt")]
        return path_canary_report(options)
    if options.canaries is not None:
        options.canaries = options.canaries or [os.path.join(ROOT, "tests", "canaries.txt")]
        return canary_report(options, whitelist)
    found = problems(options.path, whitelist)
    inert = [_ for _ in found if _[3] == "inert"]
    shadowed = [_ for _ in found if _[3] == "shadowed"]
    warned = [_ for _ in found if _[3] == "warn"]
    overbroad = [_ for _ in found if _[3] == "overbroad"]
    headers = header_problems(options.path)
    repeated = repeats(options.path)
    sunk = sinkhole_conflicts(options.path)

    if not options.quiet:
        print("[i] %s: %d entry(ies) that cannot match, %d that match a whole registry, %d suspect, "
              "%d shadowed by the whitelist, %d malformed header(s), %d repeated under one reference, "
              "%d sinkhole(s) listed as infrastructure"
              % (options.path, len(inert), len(overbroad), len(warned), len(shadowed), len(headers), len(repeated), len(sunk)))
        if sunk:
            print("\n[!] a sinkhole address listed as infrastructure too: drop this copy (%d)" % len(sunk))
            for path, number, key, sink in sunk[:options.limit]:
                print("      %s:%d  %s  -- sinkhole per %s" % (os.path.relpath(path, ROOT), number, key, os.path.relpath(sink, ROOT)))
            if len(sunk) > options.limit:
                print("      ... and %d more" % (len(sunk) - options.limit))
        if headers:
            print("\n[!] malformed '# Reference:' / '# Aliases:' header(s) (%d)" % len(headers))
            for path, number, line, why in headers[:options.limit]:
                print("      %s:%d  %s\n          %s" % (os.path.relpath(path, ROOT), number, why, line[:110]))
            if len(headers) > options.limit:
                print("      ... and %d more" % (len(headers) - options.limit))
        if repeated:
            print("\n[!] listed twice under the same '# Reference:' (%d)" % len(repeated))
            for path, number, key, first in repeated[:options.limit]:
                print("      %s:%d  %s  -- already on line %d" % (os.path.relpath(path, ROOT), number, key, first))
            if len(repeated) > options.limit:
                print("      ... and %d more" % (len(repeated) - options.limit))
        for label, group in (("cannot match", inert), ("matches a whole registry", overbroad), ("suspect", warned)):
            buckets = {}
            for path, number, key, _, why in group:
                buckets.setdefault(why.split(';')[0].split(':')[0], []).append((path, number, key, why))
            for bucket, items in sorted(buckets.items(), key=lambda kv: -len(kv[1])):
                print("\n[!] %s - %s (%d)" % (label, bucket, len(items)))
                for path, number, key, why in items[:options.limit]:
                    print("      %s:%d  %s  -- %s" % (os.path.relpath(path, ROOT), number, key, why))
                if len(items) > options.limit:
                    print("      ... and %d more" % (len(items) - options.limit))

        # Listed per entry now rather than summarised per platform. Under longest-match precedence this is a
        # name-for-name collision between two operator-visible lists, and there are eleven of them in the
        # current content rather than the three thousand the pre-3.2 rule produced.
        if shadowed:
            by_name = {}
            for path, number, key, _, why in shadowed:
                by_name.setdefault(key, []).append((path, number, "never examines" in why))
            print("\n[!] the whitelist carries this name too, so the trail can never fire (%d entr(ies), %d name(s))"
                  % (len(shadowed), len(by_name)))
            print("      one of the two lists is wrong about it; which one is a policy call")
            for name, places in sorted(by_name.items(), key=lambda kv: -len(kv[1]))[:options.limit]:
                where = ", ".join("%s:%d" % (os.path.relpath(_[0], ROOT), _[1]) for _ in places[:3])
                # bare-domain trails die at build time; URL trails on the same host survive the build and
                # are vetoed when the request arrives. Different mechanisms, so say which.
                kind = "URL trail on a cleared host" if places[0][2] else "dropped at build"
                print("      %-30s %2d  %-27s %s%s"
                      % (name, len(places), kind, where, " ..." if len(places) > 3 else ""))
            if len(by_name) > options.limit:
                print("      ... and %d more name(s)" % (len(by_name) - options.limit))

        if not inert and not overbroad and not warned and not shadowed and not headers and not repeated and not sunk:
            print("[i] no unreachable trails")

    # Shadowing is a COLLISION between two operator-visible lists, not a defect in the entry, so it is reported
    # and does not fail the gate: which of the two wins is a policy call (see the note in the module docstring).
    return 1 if (inert or overbroad or headers or repeated or sunk or (options.strict and warned)) else 0


if __name__ == "__main__":
    sys.exit(main())
