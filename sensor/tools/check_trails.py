#!/usr/bin/env python3
# coding: utf-8

"""Find static trail entries that can never match anything.

    python3 sensor/tools/check_trails.py            # report
    python3 sensor/tools/check_trails.py --quiet    # exit status only

A trail is only useful if it is written the way the sensor will see it on the wire. Several
kinds of entry are silently inert:

  * a NON-ASCII domain. DNS carries punycode, so `ortakoporotör.com` never matches - the query
    arrives as `xn--ortakoporotr-fjb.com`.
  * a SEPARATOR LOOKALIKE - an en-dash for a hyphen, U+2024 for a dot. These come from copying
    an indicator out of a report, and produce a domain that does not exist.
  * an UNDERSCORE in a hostname. `core/settings.py:VALID_DNS_NAME_REGEX` rejects the QUERY
    before the lookup happens, so the trail is unreachable regardless of what is stored.
    (Verified by replaying such a query through the sensor: no event.)

A bare TLD like `xyz` is NOT reported. Those come from the `.xyz`-style entries in
suspicious/domain.txt, the loader strips the leading dot, and the sensor's parent-domain walk
reaches them - `evil.xyz` matches the trail `xyz`. Confirmed the same way.

None of these produce an error anywhere: the trail loads, occupies a row, and matches nothing.
That is the same class of failure as a dead feed - it looks exactly like "no detections".

Reported as counts plus the offending lines, and a non-zero exit when anything is found, so it
can gate a change to trails/static/.
"""

import argparse
import io
import os
import re
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
sys.path.insert(0, ROOT)

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


def problems(root):
    found = []
    for base, _, files in os.walk(root):
        for name in sorted(files):
            if not name.endswith(".txt"):
                continue
            path = os.path.join(base, name)
            for number, key in entries(path):
                if not key or IPV4.match(key) or IPV4_PORT.match(key) or ':' in key:
                    continue                     # IPv4, IPv4:port and IPv6 are not names
                if re.search(r"[*\[\]]", key):
                    continue                     # wildcard trail, matched by regex instead
                lookalike = sorted({LOOKALIKES[ord(c)] for c in key if ord(c) in LOOKALIKES})
                if lookalike:
                    found.append((path, number, key, "separator lookalike: %s" % ", ".join(lookalike)))
                elif any(ord(c) > 127 for c in key):
                    try:
                        puny = key.encode("idna").decode("ascii")
                        found.append((path, number, key, "not punycode; the wire form is %s" % puny))
                    except Exception:
                        found.append((path, number, key, "not ASCII and not encodable as punycode"))
                elif key.rsplit('.', 1)[-1].count('_'):
                    # VALID_DNS_NAME_REGEX accepts '_' in every label but the last, so only an
                    # underscore in the TLD position is still unreachable. (It used to reject the
                    # character outright, which stranded 134 trails - dynamic-DNS hosts and the
                    # like - because the QUERY was refused before the lookup ever happened.)
                    found.append((path, number, key, "underscore in the last label: no such TLD, unreachable"))
    return found


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--path", default=os.path.join(ROOT, "trails", "static"))
    parser.add_argument("--quiet", action="store_true", help="exit status only")
    parser.add_argument("--limit", type=int, default=25, help="lines shown per category")
    options = parser.parse_args()

    found = problems(options.path)
    if not options.quiet:
        buckets = {}
        for path, number, key, why in found:
            buckets.setdefault(why.split(';')[0].split(':')[0], []).append((path, number, key, why))
        print("[i] %s: %d entry(ies) that cannot match" % (options.path, len(found)))
        for bucket, items in sorted(buckets.items(), key=lambda kv: -len(kv[1])):
            print("\n[!] %s (%d)" % (bucket, len(items)))
            for path, number, key, why in items[:options.limit]:
                print("      %s:%d  %s  -- %s" % (os.path.relpath(path, ROOT), number, key, why))
            if len(items) > options.limit:
                print("      ... and %d more" % (len(items) - options.limit))
        if not found:
            print("[i] no unreachable trails")
    return 1 if found else 0


if __name__ == "__main__":
    sys.exit(main())
