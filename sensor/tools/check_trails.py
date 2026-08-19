#!/usr/bin/env python3
# coding: utf-8

"""Find static trail entries that can never match anything.

    python3 sensor/tools/check_trails.py            # report
    python3 sensor/tools/check_trails.py --quiet    # exit status only
    python3 sensor/tools/check_trails.py --strict   # warnings fail too

And the other direction - no trail may match a name it must never match:

    python3 sensor/tools/check_trails.py --canaries              # tests/canaries.txt, ~3s (what CI runs)

    python3 sensor/tools/check_trails.py --path trails/static/malware --kinds regex \
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
import io
import os
import re
import sys
import zipfile

ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
sys.path.insert(0, ROOT)

from core.settings import IGNORE_DNS_QUERY_SUFFIXES  # noqa: E402
from core.settings import VALID_DNS_NAME_REGEX  # noqa: E402

VALID_DNS = re.compile(VALID_DNS_NAME_REGEX)
IPV4 = re.compile(r"\A\d+\.\d+\.\d+\.\d+\Z")
IPV4_PORT = re.compile(r"\A\d{1,3}(?:\.\d{1,3}){3}:\d{1,5}\Z")

# Characters that look like a separator but are not one. An indicator carrying these was almost
# certainly transcribed from a report rather than internationalised on purpose.
LOOKALIKES = {
    0x2010: "hyphen (U+2010)", 0x2011: "non-breaking hyphen", 0x2012: "figure dash",
    0x2013: "en dash", 0x2014: "em dash", 0x2212: "minus sign",
    0x2024: "one dot leader", 0x3002: "ideographic full stop", 0xFF0E: "fullwidth full stop",
    0x00A0: "non-breaking space",
}


def whitelisted_parents():
    """The whitelist, as the SENSOR applies it: a name is suppressed when it or any PARENT is listed.

    `core/settings.read_whitelist()` loads data/whitelist.txt plus the configured WHITELIST, and the sensor's
    loader drops a trail whose name has a whitelisted parent (`whitelist::check_domain_member`, the same walk
    `TrailDb::contains_domain_member` uses). The updater's own `check_whitelisted()` does NOT walk parents, so
    such a trail survives the build, lands in trails.csv, and is then discarded at load: present, counted,
    and unable to match. Nothing said so before this.
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


def entries(path):
    """The trail keys a file contributes, normalised the way trails/static/__init__.py does."""
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
            if '://' in line:
                line = re.search(r"://(.*)", line).group(1)
            if '/' in line:                          # URL/path trail: the host part is what must be a name
                line = line.split('/')[0]
            yield number, line.strip('.')


def wire_form(key):
    """What `core/update.py` will store for this key, or None if it refuses to encode it."""
    if all(ord(c) < 128 for c in key):
        return key.lower()                       # the ASCII path: update.py only lowercases
    try:
        return key.encode("idna").decode("ascii").lower()
    except Exception:
        return None                              # stored verbatim, and no query can carry it


def classify(key, whitelist=None):
    """(severity, reason) for one trail key, or None when it is reachable as written.

    severity is "inert" - it cannot match, ever - "shadowed": a whitelisted parent domain suppresses it, or
    "warn": it will match something, but probably not what the report meant."""

    if not key or IPV4.match(key) or IPV4_PORT.match(key) or ':' in key:
        return None                              # IPv4, IPv4:port and IPv6 are not names
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
    if last in IGNORE_DNS_QUERY_SUFFIXES:
        # The query is dropped by the ignore-suffix filter BEFORE the lookup, so this trail can
        # never match. Found by a volume test: "dev" sat on that list from when .dev meant a local
        # development name, and kept 7,658 real trails from ever firing after it became a
        # registrable gTLD in 2019.
        return ("inert", "last label '%s' is in IGNORE_DNS_QUERY_SUFFIXES: the query is dropped before lookup" % last)

    if whitelist:
        parent = whitelisted_parent(wire, whitelist)
        if parent:
            return ("shadowed", "parent domain '%s' is whitelisted: the sensor's loader drops this trail" % parent)

    if lookalike:
        # idna turned it into a syntactically valid name, so it is not inert - but a dash lookalike
        # punycodes to a domain that almost certainly does not exist.
        return ("warn", "separator lookalike (%s): matches %r, which is probably not the domain in the report"
                % (", ".join(lookalike), wire))
    return None                                  # includes deliberate IDNs: they match their punycode


def problems(root, whitelist=None):
    """[(path, line, key, severity, reason)] for every trail entry that is inert, shadowed or suspect."""
    found = []
    for base, _, files in os.walk(root):
        for name in sorted(files):
            if not name.endswith(".txt"):
                continue
            path = os.path.join(base, name)
            for number, key in entries(path):
                verdict = classify(key, whitelist)
                if verdict:
                    found.append((path, number, key, verdict[0], verdict[1]))
    return found


# `re.search(r"[\].][*+]|\[[a-z0-9_.\-]+\]", trail, re.I)` - the rule
# sensor/src/trails/regexset.rs:is_wildcard_trail() implements, and the only trails compiled as
# patterns rather than stored as literals.
WILDCARD = re.compile(r"[\].][*+]|\[[a-z0-9_.\-]+\]", re.I)


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
            for number, key in entries(path):
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
        if whitelist and (name in whitelist or whitelisted_parent(name, whitelist)):
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
    unexpected = [_ for _ in hits if _[2] not in trails and ("%s:%s" % (_[2], _[3])) not in pairs]

    if not options.quiet:
        print("[i] %s: %d name(s), %d checked against %d pattern(s), %d already covered by the whitelist"
              % (", ".join("%s%s" % (os.path.relpath(_[0], ROOT), ":%d" % _[1] if _[1] else "") for _ in sources), stats["total"],
                 stats["total"] - stats["covered"], stats["patterns"], stats["covered"]))
        # A canary the whitelist protects cannot fail this gate, so it is not silently counted as a
        # pass: google.com, 1.1.1.1 and github.com are all in data/whitelist.txt, and a canary list
        # made only of those would be reassuring and worthless.
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


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--path", default=os.path.join(ROOT, "trails", "static"))
    parser.add_argument("--quiet", action="store_true", help="exit status only")
    parser.add_argument("--strict", action="store_true", help="a warning fails too")
    parser.add_argument("--no-whitelist", action="store_true", help="skip the whitelist-shadowing report")
    parser.add_argument("--canaries", nargs="*", default=None, metavar="FILE",
                        help="instead: check that no trail matches a name in FILE (default: tests/canaries.txt). "
                             "Accepts a plain list or a popularity list as shipped (*.csv.zip), and several files")
    parser.add_argument("--allow", action="append", default=[], metavar="TRAIL:CANARY",
                        help="a known, accepted canary hit (repeatable)")
    parser.add_argument("--allow-trail", action="append", default=[], metavar="TRAIL",
                        help="accept every hit from this trail - the intentional broad ones (repeatable)")
    parser.add_argument("--kinds", choices=("both", "regex", "literal"), default="both",
                        help="which trails to check against the list (default: both; use 'regex' for a "
                             "popularity list, which legitimately contains malware domains)")
    parser.add_argument("--limit", type=int, default=25, help="lines shown per category")
    options = parser.parse_args()

    whitelist = None if options.no_whitelist else whitelisted_parents()

    if options.canaries is not None:
        options.canaries = options.canaries or [os.path.join(ROOT, "tests", "canaries.txt")]
        return canary_report(options, whitelist)
    found = problems(options.path, whitelist)
    inert = [_ for _ in found if _[3] == "inert"]
    shadowed = [_ for _ in found if _[3] == "shadowed"]
    warned = [_ for _ in found if _[3] == "warn"]

    if not options.quiet:
        print("[i] %s: %d entry(ies) that cannot match, %d suspect, %d shadowed by the whitelist"
              % (options.path, len(inert), len(warned), len(shadowed)))
        for label, group in (("cannot match", inert), ("suspect", warned)):
            buckets = {}
            for path, number, key, _, why in group:
                buckets.setdefault(why.split(';')[0].split(':')[0], []).append((path, number, key, why))
            for bucket, items in sorted(buckets.items(), key=lambda kv: -len(kv[1])):
                print("\n[!] %s - %s (%d)" % (label, bucket, len(items)))
                for path, number, key, why in items[:options.limit]:
                    print("      %s:%d  %s  -- %s" % (os.path.relpath(path, ROOT), number, key, why))
                if len(items) > options.limit:
                    print("      ... and %d more" % (len(items) - options.limit))

        # Summarised per whitelisted parent, not per entry: these come in thousands, and the useful unit is the
        # PARENT - each line is one platform where the whitelist and the trail set disagree about the same names.
        if shadowed:
            by_parent = {}
            for path, number, key, _, why in shadowed:
                by_parent.setdefault(why.split("'")[1], []).append((path, number, key))
            print("\n[!] shadowed by a whitelisted parent domain (%d entries, %d parent(s))"
                  % (len(shadowed), len(by_parent)))
            print("      these load into trails.csv and are then dropped by the sensor's loader")
            for parent, items in sorted(by_parent.items(), key=lambda kv: -len(kv[1]))[:options.limit]:
                path, number, key = items[0]
                print("      %-28s %5d  e.g. %s:%d  %s" % (parent, len(items), os.path.relpath(path, ROOT), number, key))
            if len(by_parent) > options.limit:
                print("      ... and %d more parent(s)" % (len(by_parent) - options.limit))

        if not inert and not warned and not shadowed:
            print("[i] no unreachable trails")

    # Shadowing is a COLLISION between two operator-visible lists, not a defect in the entry, so it is reported
    # and does not fail the gate: which of the two wins is a policy call (see the note in the module docstring).
    return 1 if (inert or (options.strict and warned)) else 0


if __name__ == "__main__":
    sys.exit(main())
