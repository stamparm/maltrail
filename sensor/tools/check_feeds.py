#!/usr/bin/env python3

"""
Copyright (c) 2014-2026 Maltrail developers (https://github.com/stamparm/maltrail/)
See the file 'LICENSE' for copying permission

Is a feed still ALIVE, or just still answering?

core/update.py already says a feed that comes back empty every run "is dead and should be removed,
not tolerated". Empty is the easy case: it is visible. The hard case is a feed that answers 200
with the same bytes it answered two years ago, because nothing looks at the date - the trails
merge, the counts look normal, and a deployment ships years-old addresses as current intelligence.

It had happened four times when this was written:

    maxmind_proxy_fraud    frozen 2019-08-25   583 IPs   "bad reputation (suspicious)"
    bi_any_2_7d (badips)   frozen 2020-12-14   976 IPs   "known attacker"
    dshield_top_1000       frozen 2021-06-09 1,000 IPs   "known attacker"
    alienvault             frozen 2021-11-12   609 IPs   "bad reputation"

badips.com had stopped resolving entirely; the feed survived on a mirror OF the dead service. An
address reassigned since 2019 is somebody else's, and the label is ours.

This is a MAINTAINER alarm, not an operator one. An operator cannot fix a frozen upstream, and
failing their update over it would punish them for a third party - so nothing here runs on the
update path. It runs on a schedule, and the answer is "drop the feed" or "repoint it".

    python3 sensor/tools/check_feeds.py
    python3 sensor/tools/check_feeds.py --max-age 180

Exit status: 0 everything fresh (or undatable), 1 a feed is frozen, 2 the check could not run.
2 is not 0 on purpose - "could not check" must never read as "checked and fine".
"""

import argparse
import datetime
import email.utils
import os
import re
import ssl
import sys
from concurrent.futures import ThreadPoolExecutor

try:
    from urllib.request import Request, urlopen
except ImportError:
    from urllib2 import Request, urlopen                          # noqa: F401  (py2 fallback)

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
FEEDS = os.path.join(ROOT, "feeds")
AGENT = "Mozilla/5.0 (maltrail feed freshness check)"


def _disabled():
    """DISABLED_FEEDS from maltrail.conf - a feed nobody fetches cannot go stale on anyone."""

    path = os.path.join(ROOT, "maltrail.conf")
    if not os.path.isfile(path):
        return set()
    with open(path, encoding="utf-8") as handle:
        for line in handle:
            if line.startswith("DISABLED_FEEDS"):
                value = line.split(None, 1)[1] if len(line.split(None, 1)) > 1 else ""
                return set(_.strip() for _ in value.replace(",", " ").split() if _.strip())
    return set()


def _feeds():
    """(name, url) for every enabled feed that declares a fetchable __url__."""

    disabled, out = _disabled(), []
    for name in sorted(os.listdir(FEEDS)):
        if not name.endswith(".py") or name.startswith("__"):
            continue
        stem = name[:-3]
        if stem in disabled:
            continue
        with open(os.path.join(FEEDS, name), encoding="utf-8") as handle:
            found = re.search(r'__url__\s*=\s*"([^"]+)"', handle.read())
        # A "*" in the URL is a display value for a feed that fetches several concrete ones
        # (dataplane), not something to probe.
        if found and "*" not in found.group(1):
            out.append((stem, found.group(1)))
    return out


def _probe(item):
    name, url = item
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        with urlopen(Request(url, headers={"User-Agent": AGENT}), timeout=60, context=context) as response:
            response.read(1024)
            return name, url, response.headers.get("Last-Modified"), None
    except Exception as ex:                                       # noqa: BLE001  - any failure is a failure
        return name, url, None, str(ex)[:80]


def main():
    parser = argparse.ArgumentParser(description="Warn about feeds whose content has stopped changing")
    parser.add_argument("--max-age", type=int, default=365, metavar="DAYS",
                        help="a feed whose content is older than this is reported (default 365)")
    options = parser.parse_args()

    feeds = _feeds()
    if not feeds:
        print("[!] no enabled feeds found in '%s'" % FEEDS)
        return 2

    now = datetime.datetime.now(datetime.timezone.utc)
    stale, unreachable, undatable, fresh = [], [], [], []
    with ThreadPoolExecutor(max_workers=12) as pool:
        for name, url, last_modified, error in pool.map(_probe, feeds):
            if error is not None:
                unreachable.append((name, url, error))
                continue
            if not last_modified:
                undatable.append(name)
                continue
            try:
                when = email.utils.parsedate_to_datetime(last_modified)
                if when.tzinfo is None:
                    when = when.replace(tzinfo=datetime.timezone.utc)
            except (TypeError, ValueError):
                undatable.append(name)
                continue
            age = (now - when).days
            (stale if age > options.max_age else fresh).append((name, url, age))

    print("[i] %d enabled feed(s): %d fresh, %d undatable, %d unreachable, %d STALE (over %d days)"
          % (len(feeds), len(fresh), len(undatable), len(unreachable), len(stale), options.max_age))
    for name, url, error in sorted(unreachable):
        print("[!] %-22s unreachable: %s" % (name, error))
    for name, url, age in sorted(stale, key=lambda _: -_[2]):
        print("[!] %-22s content last changed %d days ago - %s" % (name, age, url))

    if stale:
        print("[!] a frozen feed ships old addresses as current intelligence; drop it or repoint it")
        return 1
    if unreachable:
        print("[!] could not check every feed, which is not the same as everything being fine")
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
