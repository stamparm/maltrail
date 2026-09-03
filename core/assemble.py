#!/usr/bin/env python

"""
Copyright (c) 2014-2026 Maltrail developers (https://github.com/stamparm/maltrail/)
See the file 'LICENSE' for copying permission
"""

from __future__ import print_function

import csv
import glob
import io
import os
import re
import sys

sys.dont_write_bytecode = True
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))  # to enable calling from current directory too

from core.settings import UNICODE_ENCODING  # noqa: E402

__url__ = "(static)"

# The threat class a trail carries in its `info` - "... (malware)", "... (suspicious)" - is the
# NAME OF THE DIRECTORY it sits in, and these three are the only names that mean anything. It used
# to be "whatever directory this is", with the single directory called `static` special-cased to
# mean none; that made the class an accident of where the tree happened to be checked out. Moving
# the scanner lists one level down was enough to relabel 19,942 keys as "mass scanner (misc)", and
# the class lands in every event's info field and in the severity classification that reads it.
# Naming them makes the rule survive the content living in its own repository, at whatever path.
CATEGORIES = ("malware", "malicious", "suspicious")


def parse_static_lines(handle, info, reference, retval, provenance=None, source=None):
    """Merge one static trail file into `retval`.

    The one place static trail lines are parsed. `core/custom_trails.py` deliberately does NOT
    reuse it: the custom parser always rstrips a trailing '/', while this one adds one to a bare
    host taken from a URL and only strips when there is more than one '/'. Those differences are
    load-bearing (they decide whether "evil.com/" is a URL trail or a domain trail), so they stay
    separate until something proves they can be merged.
    """

    pile = ""
    for line in handle:
        line = line.decode(UNICODE_ENCODING)
        line = line.strip()
        if line.startswith('#'):
            # '# Reference:' applies to the entries BELOW it until the next one, which is how the
            # trail drawer cites a detection. A bare '# Reference:' with no value deliberately ends
            # a group, so what follows is not attributed to the citation above it.
            match = re.match(r"#\s*Reference:\s*(.*)$", line)
            if match is not None:
                pile = match.group(1).strip()
            continue
        if not line:
            continue
        line = re.sub(r"\s*#.*", "", line)
        if '://' in line:
            line = re.search(r"://(.*)", line).group(1)
            if '/' not in line:
                line = "%s/" % line
        if '/' in line:
            if line.count('/') > 1:
                line = line.rstrip('/')
            retval[line] = (info, reference)
            _note(provenance, source, pile, line)
            line = line.split('/')[0]
        elif re.search(r"\A\d+\.\d+\.\d+\.\d+\Z", line):
            retval[line] = (info, reference)
            _note(provenance, source, pile, line)
        else:
            retval[line.strip('.')] = (info, reference)
            _note(provenance, source, pile, line.strip('.'))

    return retval


def _note(provenance, source, pile, trail):
    """Record which file and which '# Reference:' a trail came from.

    Last write wins, exactly as the trail set itself resolves a key listed twice, so the citation
    always describes the entry that actually won.
    """

    if provenance is None:
        return
    pairs, trails = provenance
    key = (source, pile)
    index = pairs.get(key)
    if index is None:
        index = pairs[key] = len(pairs)
    trails[trail] = index


def merge_file(path, retval, category=None, provenance=None, root=None):
    """Merge one `*.txt` static trail file, deriving its `info` from the filename."""

    info = os.path.splitext(os.path.basename(path))[0].replace('_', " ")
    if category:
        info = "%s (%s)" % (info, category)

    source = os.path.relpath(path, root).replace(os.sep, '/') if root else os.path.basename(path)

    with open(path, "rb") as f:
        return parse_static_lines(f, info, "(static)", retval, provenance, source)


def fetch(root, provenance=None):
    """Every trail the static content tree at `root` contributes, as {trail: (info, reference)}.

    `root` is the checkout of the content repository. Its top level holds one directory per threat
    class; anything else there is class-less.
    """

    retval = {}

    # glob() hands back DIRECTORY ORDER, and both sorts below are stable, so within a group the
    # order was whatever the filesystem happened to hold. An indicator listed in two piles is
    # labelled by whichever file is read LAST, so that arbitrary order decided the label - and it
    # changes when files are rewritten or the tree is re-checked out. Found by rebuilding the set
    # before and after a commit that only edited comment lines: same 1,632,336 keys, 5,950 of them
    # differently attributed (metamorfo vs latentbot, cobaltstrike-1 vs -2, ...). Sort by name
    # first, so the same checkout builds the same trails.csv on every machine.
    #
    # The second sort key reads the BASENAME, not the whole path. It used to match the path, so a
    # checkout under e.g. /home/me/malicious/ silently reordered the merge and re-attributed
    # indicators - the same class of bug, one directory up.
    directories = [root] + sorted(glob.glob(os.path.join(root, "*")))
    directories = sorted(directories, key=lambda _: -1 if any(__ in os.path.basename(_) for __ in ("suspicious", "malicious")) else int("custom" in os.path.basename(_)))

    for directory in directories:
        if not os.path.isdir(directory):
            continue

        name = os.path.split(directory)[-1]
        category = name if name in CATEGORIES else None

        for filename in sorted(glob.glob(os.path.join(directory, "*.csv"))):
            reference = "%s (static)" % os.path.splitext(os.path.basename(filename))[0]
            with open(filename, "rb") as f:
                for line in f:
                    line = line.decode(UNICODE_ENCODING).strip()
                    if not line or line.startswith('#'):
                        continue
                    value, info = line.split(',', 1)
                    info = info.strip('"')
                    if category:
                        info = "%s (%s)" % (info, category)
                    if '://' in value:
                        value = re.search(r"://(.*)", value).group(1)
                    value = value.rstrip('/')
                    if '/' in value:
                        retval[value] = (info, reference)
                        value = value.split('/')[0]
                    elif re.search(r"\A\d+\.\d+\.\d+\.\d+\Z", value):
                        retval[value] = (info, reference)
                    else:
                        retval[value.strip('.')] = (info, reference)

        filenames = sorted(glob.glob(os.path.join(directory, "*.txt")))
        filenames = sorted(filenames, key=lambda _: "history" in _)

        for filename in filenames:
            merge_file(filename, retval, category, provenance, root)

    return retval


# A hostname, and nothing else: no IP (a numeric last label), no URL or path (a slash), and none
# of the regex trails, whose metacharacters simply fail to match here.
_DOMAIN_RE = re.compile(r"^(?!-)[a-z0-9_-]{1,63}(?<!-)(?:\.(?!-)[a-z0-9_-]{1,63}(?<!-))+$")


def malware_domains(trails):
    """Sorted, de-duplicated domain-only view of the malware trails.

    Published for the DNS-filtering integrations that consume the list without running Maltrail -
    NextDNS, NoTracking, pfBlockerNG, MobSF and MobileAudit all fetched it from a URL that stopped
    existing (#19620). They cannot use trails.csv: it carries IPs, URLs and regexes they would try
    to resolve as names.

    Sorting is safe here and wanted, unlike in the aggregate. The warning against sorting there is
    about label attribution - "www.x" and "x" collapse onto one key and the last one merged wins -
    and this output has no labels to mis-attribute.
    """

    out = set()
    for trail, (info, _reference) in trails.items():
        if not info.endswith("(malware)"):
            continue
        name = trail.strip().lower()
        if not _DOMAIN_RE.match(name):
            continue
        if name.rsplit(".", 1)[-1].isdigit():        # a dotted quad, not a hostname
            continue
        out.add(name)
    return sorted(out)


def main():
    import argparse

    parser = argparse.ArgumentParser(description="Assemble the static trail aggregate from a content-repository checkout")
    parser.add_argument("--root", required=True, help="checkout of the trails content repository")
    parser.add_argument("--out", help="write the aggregate here (default: stdout)")
    parser.add_argument("--provenance", help="also write the provenance sidecar here")
    parser.add_argument("--domains-out", dest="domains_out",
                        help="also write a domain-only list of the malware trails, for DNS filtering")
    options = parser.parse_args()

    if not os.path.isdir(options.root):
        sys.exit("[!] not a directory: '%s'" % options.root)

    provenance = ({}, {}) if options.provenance else None
    trails = fetch(options.root, provenance)
    if not trails:
        # An empty aggregate published to every sensor is the worst possible outcome: it installs
        # cleanly, starts, serves a dashboard and detects nothing. Refuse instead.
        sys.exit("[!] '%s' yielded no trails - wrong directory, or an empty checkout" % options.root)

    # csv.writer, with the same dialect update_trails() uses to write trails.csv and load_trails()
    # uses to read it. A trail can contain a comma - regex trails like `[0-9]{2,3}\.ru`, URL trails
    # like `/44285,5327891204.dat` - and 24 of them do. Written with plain string formatting they
    # come back as three different trails, or as one with a quote wedged into the middle of a regex.
    #
    # ROW ORDER IS INSERTION ORDER, deliberately, and must not be "tidied" into sorted order.
    # update_trails() strips a leading "www." while merging, so `www.evil.com` and `evil.com`
    # collapse onto one key and the one merged LAST wins. Sorting put `www.` after the bare name and
    # silently re-attributed greenfleld.com from lokibot to andromeda, and comtoway.com from siesta
    # to apt commentcrew. Insertion order is already deterministic - the directory sort, the file
    # sort and the line order fix it - so there is nothing to gain by sorting and a label to lose.
    buf = io.StringIO()
    writer = csv.writer(buf, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL, lineterminator="\n")
    for trail, (info, reference) in trails.items():
        writer.writerow((trail, info, reference))
    payload = buf.getvalue().encode(UNICODE_ENCODING)

    if options.out:
        with open(options.out, "wb") as f:
            f.write(payload)
    else:
        sys.stdout.write(payload.decode(UNICODE_ENCODING))

    import hashlib
    print("[i] %d trails, %d bytes, sha256 %s" % (len(trails), len(payload), hashlib.sha256(payload).hexdigest()), file=sys.stderr)

    if options.domains_out:
        domains = malware_domains(trails)
        if not domains:
            sys.exit("[!] no malware domains derived - refusing to publish an empty blocklist")
        with open(options.domains_out, "wb") as f:
            f.write(("\n".join(domains) + "\n").encode(UNICODE_ENCODING))
        print("[i] %d malware domains -> %s" % (len(domains), options.domains_out), file=sys.stderr)

    if options.provenance:
        from core import provenance as provenance_module

        pairs, trail_index = provenance
        # The pair table is written in index order, so a lookup can index straight into it.
        table = [None] * len(pairs)
        for (source, reference), index in pairs.items():
            table[index] = [source, reference]
        # Only trails that survived into the aggregate: a key listed twice is cited by the entry
        # that actually won, and one dropped along the way is not cited at all.
        entries = [(trail, index) for trail, index in trail_index.items() if trail in trails]
        rows, npairs = provenance_module.build(entries, table, options.provenance)
        print("[i] provenance: %d trails, %d distinct (file, reference) pair(s), %d bytes"
              % (rows, npairs, os.path.getsize(options.provenance)), file=sys.stderr)


if __name__ == "__main__":
    main()
