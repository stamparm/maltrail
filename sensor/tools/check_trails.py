#!/usr/bin/env python3
# coding: utf-8

"""Find static trail entries that can never match anything.

    python3 sensor/tools/check_trails.py            # report
    python3 sensor/tools/check_trails.py --quiet    # exit status only
    python3 sensor/tools/check_trails.py --strict   # warnings fail too

And the other direction - no trail may match a name it must never match:

    python3 sensor/tools/check_trails.py --canaries              # tests/canaries.txt, ~3s (what CI runs)

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

from core.addr import leading_ipv4  # noqa: E402
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
    """The whitelist as loaded: data/whitelist.txt plus the configured WHITELIST.

    What it MEANS for a trail changed in 3.2. The retired Python sensor suppressed a name whenever any
    ancestor was whitelisted, which made every exact trail on a shared platform dead on arrival. The Rust
    sensor applies longest-match precedence: only an entry equal to the full name vetoes a trail hit, so
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


def classify(key, whitelist=None, info="", raw=None):
    """(severity, reason) for one trail key, or None when it is reachable as written.

    severity is "inert" - it cannot match, ever - "shadowed": a whitelisted parent domain suppresses it, or
    "warn": it will match something, but probably not what the report meant."""

    if not key or IPV4.match(key) or IPV4_PORT.match(key) or ':' in key:
        # Not names - but an ADDRESS trail can still be unreachable, and until this looked it was
        # the one inert class nothing reported. update_trails() deletes any trail whose leading
        # quad is a CDN edge or a bogon (core/update.py), so such an entry is added, reviewed,
        # committed, and then silently dropped from every build: the report said "C2 at
        # 104.16.155.10:8888", somebody put it in, and no deployment ever matched it. That is worse
        # than a false positive, because it looks like detection.
        address = leading_ipv4(key)
        if address:
            # update_trails() spares parking/sinkhole entries, whose whole point is to name shared
            # infrastructure. Mirror that, or this reports them as broken when they are deliberate.
            if not any(_ in info for _ in ("parking", "sinkhole")):
                if cdn_ip(address):
                    return ("inert", "%s is a CDN edge address: update_trails() drops it, so this trail never reaches a deployment" % address)
                if bogon_ip(address):
                    return ("inert", "%s is a bogon: update_trails() drops it, so this trail never reaches a deployment" % address)
        return None
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

    if whitelist and wire in whitelist:
        # LONGEST-MATCH PRECEDENCE (3.2). Only an entry equal to the FULL name vetoes a trail; a tie
        # goes to the whitelist, because the operator cleared this exact name on purpose. Both the
        # updater's check_whitelisted() and the sensor loader's are exact-match too, so the trail is
        # dropped at build time and never reaches trails.csv.
        #
        # This used to report a whitelisted ANCESTOR as suppressing its children, which was true of
        # the retired Python sensor and stopped being true in 3.2 - and it said so with "the sensor's
        # loader drops this trail", which the loader does not do. Measured against the current
        # content that was 3,081 live trails on shared platforms (cloudfront.net, azurewebsites.net,
        # blogspot.com) reported as dead, against 3 that really are. The Rust sensor's behaviour is
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


def header_problem(raw):
    """Why this comment line is a malformed '# Reference:' / '# Aliases:' header, or None."""
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


def problems(root, whitelist=None):
    """[(path, line, key, severity, reason)] for every trail entry that is inert, shadowed or suspect."""
    found = []
    for base, _, files in os.walk(root):
        for name in sorted(files):
            if not name.endswith(".txt"):
                continue
            path = os.path.join(base, name)
            # The info the assembler will give these entries: the filename, underscores to spaces.
            # Only used for the parking/sinkhole exemption below, which is keyed on it.
            info = os.path.splitext(name)[0].replace('_', ' ')
            for number, key, raw in entries(path):
                verdict = classify(key, whitelist, info, raw)
                if verdict:
                    found.append((path, number, key, verdict[0], verdict[1]))
    return found


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

    if options.canaries is not None:
        options.canaries = options.canaries or [os.path.join(ROOT, "tests", "canaries.txt")]
        return canary_report(options, whitelist)
    found = problems(options.path, whitelist)
    inert = [_ for _ in found if _[3] == "inert"]
    shadowed = [_ for _ in found if _[3] == "shadowed"]
    warned = [_ for _ in found if _[3] == "warn"]
    headers = header_problems(options.path)

    if not options.quiet:
        print("[i] %s: %d entry(ies) that cannot match, %d suspect, %d shadowed by the whitelist, %d malformed header(s)"
              % (options.path, len(inert), len(warned), len(shadowed), len(headers)))
        if headers:
            print("\n[!] malformed '# Reference:' / '# Aliases:' header(s) (%d)" % len(headers))
            for path, number, line, why in headers[:options.limit]:
                print("      %s:%d  %s\n          %s" % (os.path.relpath(path, ROOT), number, why, line[:110]))
            if len(headers) > options.limit:
                print("      ... and %d more" % (len(headers) - options.limit))
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

        if not inert and not warned and not shadowed and not headers:
            print("[i] no unreachable trails")

    # Shadowing is a COLLISION between two operator-visible lists, not a defect in the entry, so it is reported
    # and does not fail the gate: which of the two wins is a policy call (see the note in the module docstring).
    return 1 if (inert or headers or (options.strict and warned)) else 0


if __name__ == "__main__":
    sys.exit(main())
