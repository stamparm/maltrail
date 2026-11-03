#!/usr/bin/env python3
"""
Format gate for the engine's own lists in data/.

Each loader in core/settings.py skips (or, for the range lists, crashes on) a line it cannot read,
so a typo in data/ installs, starts and does nothing: '1.2.3.0/24, name' became a name with a
leading space, an IPv6 range in worst_asns.txt never loaded, and a whitelist entry with an inline
comment whitelisted the literal string '92.222.150.60   # ...'. This checks every entry against
what its loader actually accepts, and every '# Reference:' header with the trail gate's rule.

A data/*.txt file this does not know fails the gate: an unchecked list is how this started.
"""

import ipaddress
import os
import re
import sys
import warnings

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from check_trails import header_problem  # noqa: E402


def _net(value, versions=(4,)):
    try:
        net = ipaddress.ip_network(value, strict=False)
    except ValueError:
        return "not a CIDR range"
    if net.version not in versions:
        return "IPv%d: the loader reads IPv%s only" % (net.version, "/".join(str(_) for _ in versions))
    if '/' not in value:
        return "no '/prefix'"
    return None


def _worst_asn(line):
    match = re.match(r"\A([^,\s]+),([a-z0-9._-]+)\Z", line)
    if not match:
        return "expected 'CIDR,name' - no spaces, lowercase name"
    return _net(match.group(1), (4, 6))


def _commented_cidr(line, versions=(4,)):
    # 'CIDR' or 'CIDR # note' - these loaders split the comment off
    return _net(line.split('#')[0].strip(), versions)


def _scanner(line):
    # a trail list: a single address is as valid as a range
    value = line.split('#')[0].strip()
    return _net(value + ("" if '/' in value else "/32"))


def _whitelist(line):
    # read_whitelist() keeps the whole line, so an inline comment becomes part of the entry
    return "whitespace or an inline comment (the loader keeps the whole line)" if re.search(r"\s|#", line) else None


def _suffix(line):
    return None if re.match(r"\A[^\sA-Z.][^\sA-Z]*\Z", line) else "not a lowercase suffix"


def _ua(line):
    if " (compatible" in line:
        return None
    try:
        # a mid-pattern '(?i)' is only a DeprecationWarning before Python 3.11, and an error after:
        # the server built on a new Python escapes it into literal text, and so does the sensor
        with warnings.catch_warnings():
            warnings.simplefilter("error")
            re.compile(line)
    except (re.error, Warning) as ex:
        # read_ua() would quietly match it as literal text instead
        return "not a regular expression (%s)" % ex
    return None


def _ignore(line):
    return None if re.sub(r"\s+", "", line).count(';') == 3 else "expected src_ip;src_port;dst_ip;dst_port"


CHECKS = {
    "bogon_ranges.txt": lambda line: _net(line),
    "cdn_ranges.txt": lambda line: _net(line),
    "drop.txt": lambda line: _commented_cidr(line, (4, 6)),
    "ignore_events.txt": _ignore,
    "mass_scanner.txt": None,  # a trail list: sensor/tools/check_trails.py gates its entries
    "mass_scanner_cidr.txt": _scanner,
    "public_suffix_icann.txt": _suffix,
    "ua.txt": _ua,
    "whitelist.txt": _whitelist,
    "worst_asns.txt": _worst_asn,
}


def problems(root):
    """[(file, line number, text, reason)] for every entry or header its loader would misread."""
    found = []
    for name in sorted(os.listdir(root)):
        if not name.endswith(".txt"):
            continue
        if name not in CHECKS:
            found.append((name, 0, "", "no format check for this file: add it to CHECKS in %s" % os.path.basename(__file__)))
            continue
        check = CHECKS[name]
        with open(os.path.join(root, name), encoding="utf8") as handle:
            for number, raw in enumerate(handle, 1):
                line = raw.strip()
                if not line:
                    continue
                why = header_problem(raw) if line.startswith('#') else (check(line) if check else None)
                if why:
                    found.append((name, number, line, why))
    return found


def main():
    root = sys.argv[1] if len(sys.argv) > 1 else os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "data")
    found = problems(root)
    for name, number, line, why in found:
        print("%s:%d: %s: %s" % (name, number, why, line[:120]))
    print("[%s] %d problem(s) in %s" % ("x" if found else "i", len(found), os.path.normpath(root)))
    return 1 if found else 0


if __name__ == "__main__":
    sys.exit(main())
