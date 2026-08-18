#!/usr/bin/env python3
# coding: utf-8

"""Find static trail entries that can never match anything.

    python3 sensor/tools/check_trails.py            # report
    python3 sensor/tools/check_trails.py --quiet    # exit status only
    python3 sensor/tools/check_trails.py --strict   # warnings fail too

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
    for number, line in enumerate(io.open(path, encoding="utf8", errors="replace"), 1):
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


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--path", default=os.path.join(ROOT, "trails", "static"))
    parser.add_argument("--quiet", action="store_true", help="exit status only")
    parser.add_argument("--strict", action="store_true", help="a warning fails too")
    parser.add_argument("--no-whitelist", action="store_true", help="skip the whitelist-shadowing report")
    parser.add_argument("--limit", type=int, default=25, help="lines shown per category")
    options = parser.parse_args()

    whitelist = None if options.no_whitelist else whitelisted_parents()
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
