#!/usr/bin/env python

"""
Copyright (c) 2014-present Maltrail developers (https://github.com/stamparm/maltrail/)
See the file 'LICENSE' for copying permission
"""

import codecs
import csv
import glob
import io
import gzip
import hashlib
import inspect
import json
import os
import re
import socket
import sqlite3
import sys
import time

sys.dont_write_bytecode = True
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))  # to enable calling from current directory too

from core.addr import addr_to_int
from core.addr import int_to_addr
from core.addr import leading_ipv4
from core.addr import make_mask
from core import assemble
from core import custom_trails
from core.common import bogon_ip
from core.common import cdn_ip
from core.common import check_whitelisted
from core.common import load_trails
from core.common import retrieve_content
from core.compat import xrange
from core.enums import HTTP_HEADER
from core.geo import GEO_DELTA_MAGIC
from core.settings import config
from core.settings import USER_AGENT
from core.settings import read_config
from core.settings import read_drop
from core.settings import read_whitelist
from core.settings import BAD_TRAIL_PREFIXES
from core.settings import DROP6_URL
from core.settings import DROP_FILE
from core.settings import DROP_URL
from core.settings import FRESH_DROP_DELTA_DAYS
from core.settings import FRESH_IPCAT_DELTA_DAYS
from core.settings import FRESH_GEO_DELTA_DAYS
from core.settings import GEO_IP2CC_FILE
from core.settings import GEO_IP2CC6_FILE
from core.settings import RIR_DELEGATED_URLS
from core.settings import LOW_PRIORITY_INFO_KEYWORDS
from core.settings import HIGH_PRIORITY_INFO_KEYWORDS
from core.settings import HIGH_PRIORITY_REFERENCES
from core.settings import IPCAT_CSV_FILE
from core.settings import IPCAT_SQLITE_FILE
from core.settings import IPCAT_URL
from core.settings import IS_WIN
from core.settings import LOCAL_STATIC_TRAIL_FILES
from core.settings import ROOT_DIR
from core.settings import UNICODE_ENCODING
from core.settings import USERS_DIR
from core.trailsdict import TrailsDict
import urllib.error
import urllib.parse
import urllib.request
import urllib.response
import urllib as _urllib

# patch for self-signed certificates (e.g. CUSTOM_TRAILS_URL)
try:
    import ssl
    ssl._create_default_https_context = ssl._create_unverified_context
except (ImportError, AttributeError):
    pass

# NOTE: post-processing walks every trail (millions), so these per-key regexes are precompiled once instead of
# being recompiled/cache-looked-up via re.search(<string>, ...) on each iteration
_ALPHA_ONLY_REGEX = re.compile(r"(?i)\A\.?[a-z]+\Z")
_IPV4_REGEX = re.compile(r"\A\d+\.\d+\.\d+\.\d+\Z")

_CUSTOM_STATIC_REGEX = re.compile(r"\b(custom|static)\b")

# str.isascii() is 3.7+, and this ONE call was the whole reason the project claimed a 3.7 floor -
# which wrote off RHEL 8, CentOS 7, openSUSE Leap 15 / SLE 15 and Amazon Linux 2, whose default
# `python3` is 3.6. It did not degrade gracefully either: the updater died with "'str' object has
# no attribute 'isascii'", so the trail set stayed empty and the sensor detected nothing (#19596's
# neighbour, and the reason sensor/src/trailupdate.rs went looking for a versioned interpreter).
#
# 3.7+ keeps the C method; 3.6 gets a precompiled regex. Both answer identically, including for the
# empty string (True) and for lone surrogates (False).
_NON_ASCII_REGEX = re.compile(r"[^\x00-\x7f]")

if hasattr(str, "isascii"):
    def _is_ascii(value):
        return value.isascii()
else:
    def _is_ascii(value):                       # the 3.6 path; equivalence is asserted in tests/test_update.py
        return _NON_ASCII_REGEX.search(value) is None

def _chown(filepath):
    if not IS_WIN and os.path.exists(filepath):
        try:
            os.chown(filepath, int(os.environ.get("SUDO_UID", -1)), int(os.environ.get("SUDO_GID", -1)))
        except Exception as ex:
            print("[!] chown problem with '%s' ('%s')" % (filepath, ex))

def _fopen(filepath, mode="rb", opener=open):
    retval = opener(filepath, mode)
    if "w+" in mode:
        _chown(filepath)
    return retval

NOT_MODIFIED = 304   # the only status this module reasons about beyond "did the body arrive"

def _stored_etag(path):
    """The validator for the trail set we are holding, or None.

    Deliberately conditional on the trail set still being there and non-empty: an `If-None-Match`
    we cannot back with content would earn a 304 and leave the deployment with no trails at all.
    A validator without its bytes is worse than no validator.
    """

    try:
        if not os.path.isfile(config.TRAILS_FILE) or os.path.getsize(config.TRAILS_FILE) == 0:
            return None
        with open(path, "r") as f:
            return f.read().strip() or None
    except (IOError, OSError):
        return None

def _store_etag(path, etag):
    """Record `etag` for the set just written, or clear a stale one when the server sent none.

    Leaving the previous file in place when the server stops sending validators would offer a tag
    describing a trail set we no longer hold.
    """

    try:
        if etag:
            with open(path, "w") as f:
                f.write(etag.strip())
            _chown(path)
        elif os.path.exists(path):
            os.remove(path)
    except (IOError, OSError):
        pass

def _atomic_replace(src, dst):
    # NOTE: rename within the same directory is atomic on POSIX, so concurrent readers (sensor worker reloads,
    # the httpd '/trails' endpoint, downstream UPDATE_SERVER sensors) always see either the old or the new
    # complete file - never a half-written truncation.
    os.replace(src, dst)  # atomic, and overwrites an existing destination on both POSIX and Windows

def confidence_score(reference, agreeing_sources):
    """
    0-100 confidence for one trail, from how many distinct feeds listed it.

    `duplicates` in update_trails() collects the references of every feed that re-listed an
    already-known trail, so its length is the agreement count (0 = single source). One feed
    saying "malware" is exactly how a park page or a vendored blocklist mistake gets into
    trails.csv; four feeds independently agreeing is not. The floor of 40 keeps every published
    trail actionable - this is a prioritization signal, not a second verdict - and the operator's
    own custom/static entries score full marks by definition.
    """

    if any(_ in (reference or "") for _ in ("custom", "static")):
        return 100
    return min(100, 40 + 15 * max(0, min(agreeing_sources, 4)))

def write_confidence_file(trails, duplicates):
    """
    Write the sorted trail<TAB>confidence sidecar next to TRAILS_FILE.

    Deliberately NOT a column in trails.csv: that file's format is a cross-version contract with
    deployed sensors, downstream UPDATE_SERVER consumers and third-party tooling, and a missing
    sidecar must degrade to "no opinion" rather than break a trail load.
    """

    path = "%s.confidence" % config.TRAILS_FILE
    tmp_file = "%s.new" % path
    try:
        with _fopen(tmp_file, "w+", codecs.open) as f:
            for key in sorted(trails.keys()):
                f.write("%s\t%d\n" % (key, confidence_score(trails[key][1], len(duplicates.get(key, ())))))
        _atomic_replace(tmp_file, path)
        return True
    except Exception as ex:
        print("[x] something went wrong during confidence file write '%s' ('%s')" % (path, ex))
        try:
            if os.path.exists(tmp_file):
                os.remove(tmp_file)
        except Exception:
            pass
        return False

def fetch_static_trails(offline=False):
    """The static trail aggregate: fetched from STATIC_TRAILS_URL, cached next to TRAILS_FILE.

    Static content lives in its own repository now, so the engine pulls one assembled file instead
    of carrying 1.6M indicators in its own git history. The cache is what makes an air-gapped or
    offline run work, and what stops a failed download from quietly producing a sensor that detects
    nothing.

    Two things keep this from being 78 MB per update per install. The payload is GZIPPED - GitHub
    serves release assets as application/octet-stream with no Content-Encoding, so nothing
    compresses it for us and 81 MB goes on the wire as 81 MB. And the published sha256 (65 bytes)
    is checked FIRST: a deployment that updates more often than the content changes transfers those
    65 bytes and stops. The hash is over the UNCOMPRESSED csv deliberately, so it identifies the
    trail set rather than one particular compression of it.
    """

    cache = "%s.static" % config.TRAILS_FILE
    stamp = "%s.sha256" % cache
    content = None

    if not config.STATIC_TRAILS_URL and not os.path.isfile(cache):
        # Matching known-bad infrastructure IS Maltrail. Without a static trail source it keeps the
        # heuristics and whatever the feeds return - a fraction of the indicators - and every
        # symptom of that looks like a quiet network. An upgrade from before the trails split is
        # the way to arrive here: the option simply is not in an older maltrail.conf.
        print("")
        print("!" * 79)
        print("!!  NO STATIC TRAIL SOURCE CONFIGURED - MALTRAIL WILL DETECT ALMOST NOTHING")
        print("!!")
        print("!!  'STATIC_TRAILS_URL' is not set, so the static trail set (the large majority of")
        print("!!  everything Maltrail matches on) will not be loaded. Heuristics and any enabled")
        print("!!  feeds still work; matching known malicious infrastructure largely will not.")
        print("!!")
        print("!!  Add this to maltrail.conf:")
        print("!!")
        print("!!      STATIC_TRAILS_URL https://github.com/stamparm/trails/releases/latest/download/trails.csv.gz")
        print("!!")
        print("!!  Upgrading from before the trails split? That option is new - the static trails")
        print("!!  moved to their own repository and are fetched instead of shipped.")
        print("!" * 79)
        print("")

    def _cached_sha():
        try:
            with open(stamp, "r") as f:
                return f.read().strip()
        except (OSError, IOError):
            return None

    def _read_cache():
        try:
            with open(cache, "rb") as f:
                return f.read().decode(UNICODE_ENCODING)
        except (OSError, IOError):
            return None

    if not offline and config.STATIC_TRAILS_URL:
        url = config.STATIC_TRAILS_URL
        # The digest is published for the trail SET, so it is named after the uncompressed file:
        # trails.csv.gz -> trails.csv.sha256. Appending .sha256 to the url as given asks for
        # trails.csv.gz.sha256, which 404s - and a missing digest silently costs the skip, so the
        # 11 MB gets pulled on every update even when nothing changed.
        sha_url = "%s.sha256" % (url[:-len(".gz")] if url.endswith(".gz") else url)
        published = (retrieve_content(sha_url) or "").strip().split(' ')[0].strip()
        published = published if re.match(r"\A[0-9a-f]{64}\Z", published) else None

        if published and published == _cached_sha() and os.path.isfile(cache):
            print(" [o] '%s' (unchanged, %s)" % (url, published[:12]))
            content = _read_cache()
        else:
            print(" [o] '%s'" % url)
            raw = retrieve_content(url, binary=True)

            if raw[:2] == b"\x1f\x8b":       # gzip magic; a plain .csv URL still works
                try:
                    raw = gzip.GzipFile("", "rb", 9, io.BytesIO(raw)).read()
                except Exception as ex:
                    print("[x] the static trails could not be decompressed ('%s')" % ex)
                    raw = b""

            digest = hashlib.sha256(raw).hexdigest() if raw else None

            if published and digest and digest != published:
                # Refuse a payload that is not the one that was published. A truncated download is
                # the dangerous case: it parses fine and is simply missing indicators.
                print("[x] the static trails do not match their published sha256 (%s != %s) - keeping the cache" % (digest[:12], published[:12]))
            elif raw and raw.count(b',') > 1:
                content = raw.decode(UNICODE_ENCODING)
                try:
                    tmp = "%s.new" % cache
                    with open(tmp, "wb") as f:
                        f.write(raw)
                    _atomic_replace(tmp, cache)
                    if digest:
                        with open("%s.new" % stamp, "w") as f:
                            f.write(digest)
                        _atomic_replace("%s.new" % stamp, stamp)
                except (OSError, IOError) as ex:
                    print("[x] unable to cache the static trails ('%s')" % ex)
            else:
                print("[x] unable to retrieve the static trails from '%s'" % url)

    if content is None:
        content = _read_cache()
        if content is not None:
            print("[i] using the cached static trails ('%s')" % cache)

    if not content:
        # Loudly. An empty static set is 1.6M missing indicators, and every symptom of it - a
        # server that starts, a dashboard that renders, a sensor that reports healthy - looks
        # exactly like a quiet network.
        print("[!] no static trails available: '%s' could not be retrieved and there is no cache at '%s'" % (config.STATIC_TRAILS_URL or "<STATIC_TRAILS_URL unset>", cache))
        return {}

    # csv.reader, not split(','): 24 trails contain a comma of their own (regex trails such as
    # `[0-9]{2,3}\.ru`, URL trails such as `/44285,5327891204.dat`). This is the same dialect
    # load_trails() uses on trails.csv.
    retval = {}
    for row in csv.reader(io.StringIO(content), delimiter=',', quotechar='"'):
        if row and len(row) == 3:
            retval[row[0]] = (row[1], row[2])

    return retval

def fetch_provenance(offline=False):
    """Download the provenance sidecar next to TRAILS_FILE, if it has changed.

    Only the SERVER asks for this: it exists so the trail drawer can cite a detection's source, and
    a sensor never renders anything. One host paying ~18 MB when the content changes, rather than
    every deployed sensor paying it for a feature it does not have.
    """

    if offline or not config.STATIC_TRAILS_URL or config.STATIC_TRAILS_PROVENANCE is False:
        return

    # Published beside the aggregate: .../trails.csv.gz -> .../trails-provenance.bin.gz
    base = config.STATIC_TRAILS_URL
    base = base[:-len(".gz")] if base.endswith(".gz") else base
    url = "%s-provenance.bin.gz" % base[:-len(".csv")] if base.endswith(".csv") else None
    if not url:
        return

    path = "%s.provenance" % config.TRAILS_FILE
    stamp = "%s.sha256" % path
    published = (retrieve_content("%s.sha256" % url) or "").strip().split(' ')[0].strip()
    published = published if re.match(r"\A[0-9a-f]{64}\Z", published) else None

    try:
        with open(stamp, "r") as f:
            if published and f.read().strip() == published and os.path.isfile(path):
                return
    except (OSError, IOError):
        pass

    print(" [o] '%s'" % url)
    raw = retrieve_content(url, binary=True)
    if raw[:2] == b"\x1f\x8b":
        try:
            raw = gzip.GzipFile("", "rb", 9, io.BytesIO(raw)).read()
        except Exception as ex:
            print("[x] the provenance sidecar could not be decompressed ('%s')" % ex)
            return

    if not raw:
        print("[x] unable to retrieve the provenance sidecar from '%s' (source citations will be unavailable)" % url)
        return

    digest = hashlib.sha256(raw).hexdigest()
    if published and digest != published:
        print("[x] the provenance sidecar does not match its published sha256 - discarding it")
        return

    try:
        tmp = "%s.new" % path
        with open(tmp, "wb") as f:
            f.write(raw)
        _atomic_replace(tmp, path)
        with open("%s.new" % stamp, "w") as f:
            f.write(digest)
        _atomic_replace("%s.new" % stamp, stamp)
        print("[i] provenance sidecar updated (%d bytes)" % len(raw))
    except (OSError, IOError) as ex:
        print("[x] unable to store the provenance sidecar ('%s')" % ex)


def update_trails(force=False, offline=False):
    """
    Update trails from feeds
    """

    success = False
    trails = TrailsDict()
    duplicates = {}

    try:
        if not os.path.isdir(USERS_DIR):
            os.makedirs(USERS_DIR, 0o755)
    except Exception as ex:
        sys.exit("[!] something went wrong during creation of directory '%s' ('%s')" % (USERS_DIR, ex))

    _chown(USERS_DIR)

    if config.UPDATE_SERVER:
        print("[i] retrieving trails from provided 'UPDATE_SERVER' server...")

        etag_file = "%s.etag" % config.TRAILS_FILE
        etag = _stored_etag(etag_file)

        headers = {"User-agent": USER_AGENT, "Accept-encoding": "gzip, deflate"}
        if etag:
            headers[HTTP_HEADER.IF_NONE_MATCH] = etag

        response = {}
        content = retrieve_content(config.UPDATE_SERVER, headers=headers, response=response)

        if response.get("code") == NOT_MODIFIED:
            # The server says the set we already hold is current, so the ~84 MB is not sent and
            # not rebuilt. _stored_etag() only offers a validator while that set is still on disk,
            # so this branch cannot leave us with nothing.
            print("[i] trails from '%s' are unchanged" % config.UPDATE_SERVER)
            trails = load_trails()
        elif not content or content.count(',') < 2:
            print("[x] unable to retrieve data from '%s'" % config.UPDATE_SERVER)
        else:
            tmp_trails_file = "%s.new" % config.TRAILS_FILE
            with _fopen(tmp_trails_file, "w+", codecs.open) as f:
                f.write(content)
            _atomic_replace(tmp_trails_file, config.TRAILS_FILE)
            # A downloaded set carries no provenance, so any sidecar from a previous self-update
            # describes a different trail set now; drop it rather than serve stale scores.
            try:
                if os.path.exists("%s.confidence" % config.TRAILS_FILE):
                    os.remove("%s.confidence" % config.TRAILS_FILE)
            except Exception:
                pass
            # Written only after the trails it describes are in place. The other order would
            # leave a validator on disk for a set we failed to store, and the next poll would be
            # told it is current.
            _store_etag(etag_file, (response.get("headers") or {}).get("etag"))
            trails = load_trails()

    else:
        trail_files = set()
        for dirpath, dirnames, filenames in os.walk(os.path.abspath(os.path.join(ROOT_DIR, "feeds"))):
            for filename in filenames:
                trail_files.add(os.path.abspath(os.path.join(dirpath, filename)))

        for _ in LOCAL_STATIC_TRAIL_FILES:
            _ = os.path.abspath(os.path.join(ROOT_DIR, "data", _))
            if os.path.isfile(_):
                trail_files.add(_)

        if config.CUSTOM_TRAILS_DIR:
            for dirpath, dirnames, filenames in os.walk(os.path.abspath(os.path.join(ROOT_DIR, os.path.expanduser(config.CUSTOM_TRAILS_DIR)))):
                for filename in filenames:
                    trail_files.add(os.path.abspath(os.path.join(dirpath, filename)))

        if not trails and (force or not os.path.isfile(config.TRAILS_FILE) or (time.time() - os.stat(config.TRAILS_FILE).st_mtime) >= config.UPDATE_PERIOD or os.stat(config.TRAILS_FILE).st_size == 0 or any(os.stat(_).st_mtime > os.stat(config.TRAILS_FILE).st_mtime for _ in trail_files)):
            if not config.offline:
                print("[i] updating trails (this might take a while)...")
            else:
                print("[i] checking trails...")

            if not offline and (force or config.USE_FEED_UPDATES):
                _ = os.path.abspath(os.path.join(ROOT_DIR, "feeds"))
                if _ not in sys.path:
                    sys.path.append(_)

                filenames = sorted(glob.glob(os.path.join(_, "*.py")))
            else:
                filenames = []

            filenames = [_ for _ in filenames if "__init__.py" not in _]

            # DISABLED_FEEDS names FEEDS. `custom` and `static` used to be appended to this same
            # list and filtered by it, so `DISABLED_FEEDS static` silently dropped all 1.6M static
            # trails and nothing said so. They are explicit phases below now, and unreachable from
            # here.
            if config.DISABLED_FEEDS:
                filenames = [filename for filename in filenames if os.path.splitext(os.path.split(filename)[-1])[0] not in re.split(r"[^\w]+", config.DISABLED_FEEDS)]

            empty_feeds = []

            def _merge(results):
                """Merge one source's {trail: (info, reference)} into `trails`.

                ONE rule, used by feeds, custom and static alike. It used to live inside the feed
                loop, which is why static and custom had to masquerade as feeds to reach it; where
                a source comes from must not change which of two labels an indicator ends up with.
                """

                for item in results.items():
                    if item[0].startswith("www.") and '/' not in item[0]:
                        item = [item[0][len("www."):], item[1]]
                    if item[0] in trails:
                        if item[0] not in duplicates:
                            duplicates[item[0]] = set((trails[item[0]][1],))
                        duplicates[item[0]].add(item[1][1])
                    if not (item[0] in trails and (any(_ in item[1][0] for _ in LOW_PRIORITY_INFO_KEYWORDS) or trails[item[0]][1] in HIGH_PRIORITY_REFERENCES)) or (item[1][1] in HIGH_PRIORITY_REFERENCES and "history" not in item[1][0]) or any(_ in item[1][0] for _ in HIGH_PRIORITY_INFO_KEYWORDS):
                        trails[item[0]] = item[1]

            for i in xrange(len(filenames)):
                filename = filenames[i]

                try:
                    module = __import__(os.path.basename(filename).split(".py")[0])
                except (ImportError, SyntaxError) as ex:
                    print("[x] something went wrong during import of feed file '%s' ('%s')" % (filename, ex))
                    continue

                for name, function in inspect.getmembers(module, inspect.isfunction):
                    if name == "fetch":
                        url = module.__url__  # Note: to prevent "SyntaxError: can not delete variable 'module' referenced in nested scope"

                        print(" [o] '%s'%s" % (url, " " * 20 if len(url) < 20 else ""))
                        sys.stdout.write("[?] progress: %d/%d (%d%%)\r" % (i, len(filenames), i * 100 // len(filenames)))
                        sys.stdout.flush()

                        if config.DISABLED_TRAILS_INFO_REGEX and re.search(config.DISABLED_TRAILS_INFO_REGEX, getattr(module, "__info__", "")):
                            continue

                        try:
                            results = function()
                            _merge(results)
                            # A feed that yields nothing is reported, whatever the host. This used
                            # to skip abuse.ch and cobaltstrike URLs, presumably because a tracker
                            # with no live C2s legitimately returns an empty list - but the
                            # exemption also silenced feeds whose service had been RETIRED, and six
                            # of them (Palevo Tracker, Ransomware Tracker x3, ZeuS Tracker x2) sat
                            # in the tree fetching dead hosts for years with nothing ever saying so.
                            # Being told about a feed that is briefly empty is much cheaper than not
                            # being told about one that is permanently dead.
                            if not results:
                                empty_feeds.append(url)
                                print("[!] no indicators from '%s' (empty response, or the feed's format changed)" % url)
                        except Exception as ex:
                            print("[x] something went wrong during processing of feed file '%s' ('%s')" % (filename, ex))

                try:
                    sys.modules.pop(module.__name__)
                    del module
                except Exception:
                    pass

            # One list at the end, because a per-feed line scrolls past in a run this long. A feed
            # that is empty on every update is dead and should be removed, not tolerated.
            if empty_feeds:
                print("[!] %d feed(s) produced no indicators this run:" % len(empty_feeds))
                for url in empty_feeds:
                    print("[!]     %s" % url)

            # Custom, then static - in THAT order, because it is the order the merge rule above
            # was written against: `static` was the last entry appended to the feed list, and for
            # a key listed by two sources the rule's outcome depends on which it sees first.
            print(" [o] '(custom)'%s" % (" " * 20))
            _merge(custom_trails.fetch())

            print(" [o] '(static)'%s" % (" " * 20))
            _merge(fetch_static_trails(offline))

            # The engine's own static lists. They merge AFTER the aggregate, which is where they
            # merged before the split - the content tree's root was read after suspicious/ and
            # before malware/ - and that ordering is what keeps 192.64.119.0/24, listed by both
            # mass_scanner_cidr.txt and suspicious/parking_site.txt, labelled 'mass scanner cidr'.
            for _ in LOCAL_STATIC_TRAIL_FILES:
                _ = os.path.abspath(os.path.join(ROOT_DIR, "data", _))
                if os.path.isfile(_):
                    _merge(assemble.merge_file(_, {}))
                else:
                    print("[!] '%s' is missing - those trails will not be loaded" % _)

            # custom trails from remote location
            if config.CUSTOM_TRAILS_URL:
                print(" [o] '(remote custom)'%s" % (" " * 20))
                for url in re.split(r"[;,]", config.CUSTOM_TRAILS_URL):
                    url = url.strip()
                    if not url:
                        continue

                    url = ("http://%s" % url) if "//" not in url else url
                    content = retrieve_content(url)

                    if not content:
                        print("[x] unable to retrieve data (or empty response) from '%s'" % url)
                    else:
                        __info__ = "blacklisted"
                        __reference__ = "(remote custom)"  # urlparse.urlsplit(url).netloc
                        for line in content.split('\n'):
                            line = line.strip()
                            if not line or line.startswith('#'):
                                continue
                            line = re.sub(r"\s*#.*", "", line)
                            if '://' in line:
                                line = re.search(r"://(.*)", line).group(1)
                            line = line.rstrip('/')

                            if line in trails and any(_ in trails[line][1] for _ in ("custom", "static")):
                                continue

                            if '/' in line:
                                trails[line] = (__info__, __reference__)
                                line = line.split('/')[0]
                            elif re.search(r"\A\d+\.\d+\.\d+\.\d+\Z", line):
                                trails[line] = (__info__, __reference__)
                            else:
                                trails[line.strip('.')] = (__info__, __reference__)

                        for match in re.finditer(r"(\d+\.\d+\.\d+\.\d+)/(\d+)", content):
                            prefix, mask = match.groups()
                            mask = int(mask)
                            if mask > 32:
                                continue
                            start_int = addr_to_int(prefix) & make_mask(mask)
                            end_int = start_int | ((1 << 32 - mask) - 1)
                            if 0 <= end_int - start_int <= 1024:
                                address = start_int
                                while start_int <= address <= end_int:
                                    trails[int_to_addr(address)] = (__info__, __reference__)
                                    address += 1

            print("[i] post-processing trails (this might take a while)...")

            disabled_info_regex = re.compile(config.DISABLED_TRAILS_INFO_REGEX) if config.DISABLED_TRAILS_INFO_REGEX else None
            ip_minimum_feeds = config.get("IP_MINIMUM_FEEDS", 3)

            # basic cleanup
            for key in list(trails.keys()):
                if key not in trails:
                    continue

                if disabled_info_regex is not None:
                    if disabled_info_regex.search(trails[key][0]):
                        del trails[key]
                        continue

                if _is_ascii(key):
                    # NAMEPREP (the only effect of idna on an already-ASCII name) just lowercases it, so skip the
                    # ~20x slower idna codec for the ~all-ASCII majority; non-ASCII names (e.g. IDN phishing) still go through idna
                    _key = key.lower()
                    if _key != key:
                        trails[_key] = trails[key]
                        del trails[key]
                        key = _key
                else:
                    try:
                        _key = key.decode(UNICODE_ENCODING) if isinstance(key, bytes) else key
                        _key = _key.encode("idna")
                        _key = _key.decode(UNICODE_ENCODING)
                        if _key != key:  # for domains with non-ASCII letters (e.g. phishing)
                            trails[_key] = trails[key]
                            del trails[key]
                            key = _key
                    except Exception:
                        pass

                if not key or _ALPHA_ONLY_REGEX.search(key) and not any(_ in trails[key][1] for _ in ("custom", "static")):
                    del trails[key]
                    continue

                if _IPV4_REGEX.search(key):
                    if any(_ in trails[key][0] for _ in ("parking site", "sinkhole")) and key in duplicates:    # Note: delete (e.g.) junk custom trails if static trail is a sinkhole
                        del duplicates[key]

                    if trails[key][0] == "malware":
                        trails[key] = ("potential malware site", trails[key][1])

                    if ip_minimum_feeds > 1:
                        if (key not in duplicates or len(duplicates[key]) < ip_minimum_feeds) and _CUSTOM_STATIC_REGEX.search(trails[key][1]) is None:
                            del trails[key]
                            continue

                    if any(int(_) > 255 for _ in key.split('.')):
                        del trails[key]
                        continue

                if trails[key][0] == "ransomware":
                    trails[key] = ("ransomware (malware)", trails[key][1])

                if key.startswith("www.") and '/' not in key:
                    _ = trails[key]
                    del trails[key]
                    key = key[len("www."):]
                    if key:
                        trails[key] = _

                if '?' in key and not key.startswith('/'):
                    _ = trails[key]
                    del trails[key]
                    key = key.split('?')[0]
                    if key:
                        trails[key] = _

                if '//' in key:
                    _ = trails[key]
                    del trails[key]
                    key = key.replace('//', '/')
                    trails[key] = _

                if key != key.lower():
                    _ = trails[key]
                    del trails[key]
                    key = key.lower()
                    trails[key] = _

                if key in duplicates:
                    _ = trails[key]
                    others = sorted(duplicates[key] - set((_[1],)))
                    if others and " (+" not in _[1]:
                        trails[key] = (_[0], "%s (+%s)" % (_[1], ','.join(others)))

            read_whitelist()

            for key in list(trails.keys()):
                # leading_ipv4(), not a `\b`-bounded prefix match: `\b` also matches the dot of a digit-leading
                # DOMAIN, so a reverse-DNS style trail was judged by its first four labels. Two static trails
                # (`10.53.154.104.bc.googleusercontent.com`, `224.185.60.34...`) were deleted from every build
                # as bogons, while their neighbours with a routable leading quad survived - a detection lost to
                # a filter meant for address trails.
                address = leading_ipv4(key)
                if check_whitelisted(key) or any(key.startswith(_) for _ in BAD_TRAIL_PREFIXES):
                    del trails[key]
                elif address and (bogon_ip(address) or cdn_ip(address)) and not any(_ in trails[key][0] for _ in ("parking", "sinkhole")):
                    del trails[key]
                else:
                    try:
                        key.decode("utf8") if hasattr(key, "decode") else key.encode("utf8")
                        trails[key][0].decode("utf8") if hasattr(trails[key][0], "decode") else trails[key][0].encode("utf8")
                        trails[key][1].decode("utf8") if hasattr(trails[key][1], "decode") else trails[key][1].encode("utf8")
                    except UnicodeError:
                        del trails[key]

            tmp_trails_file = "%s.new" % config.TRAILS_FILE
            try:
                if trails:
                    with _fopen(tmp_trails_file, "w+", codecs.open) as f:
                        writer = csv.writer(f, delimiter=',', quotechar='\"', quoting=csv.QUOTE_MINIMAL)
                        for trail in trails:
                            row = (trail, trails[trail][0], trails[trail][1])
                            writer.writerow(row)

                    _atomic_replace(tmp_trails_file, config.TRAILS_FILE)
                    write_confidence_file(trails, duplicates)
                    success = True
            except Exception as ex:
                print("[x] something went wrong during trails file write '%s' ('%s')" % (config.TRAILS_FILE, ex))
            finally:
                # NOTE: a write that failed mid-way leaves a partial temp file behind; the original TRAILS_FILE is
                # left untouched (and keeps its old mtime, so the next update cycle retries instead of being suppressed)
                try:
                    if os.path.exists(tmp_trails_file):
                        os.remove(tmp_trails_file)
                except Exception:
                    pass

            print("[i] update finished%s" % (40 * " "))

            if success:
                print("[i] trails stored to '%s'" % config.TRAILS_FILE)

    return trails

def update_drop(force=False):
    """
    Refresh the Spamhaus DROP netblocks into USERS_DIR. Same shape as update_ipcat/update_geo:
    staleness-gated, best-effort (a failed fetch leaves the previous file in place), atomic write.
    The bundled data/drop.txt is the air-gap/first-run seed.

    Short cadence on purpose - Spamhaus republishes continuously, and the whole point of listing a
    hijacked netblock is that it was hijacked recently.

    DROP is an ANNOTATION, surfaced by /check_ip next to worst_asns. It is deliberately not merged
    into the trail set: 1,700 netblocks cover millions of addresses, and every one of them would be
    either inert (a CIDR key matches no address) or, expanded, a false-positive surface far larger
    than anything anyone observed.
    """

    try:
        if not os.path.isdir(USERS_DIR):
            os.makedirs(USERS_DIR, 0o755)
    except Exception as ex:
        sys.exit("[!] something went wrong during creation of directory '%s' ('%s')" % (USERS_DIR, ex))

    _chown(USERS_DIR)

    if not (force or not os.path.isfile(DROP_FILE)
            or (time.time() - os.stat(DROP_FILE).st_mtime) >= FRESH_DROP_DELTA_DAYS * 24 * 3600):
        return

    print("[i] updating Spamhaus DROP list...")

    entries = []
    for url in (DROP_URL, DROP6_URL):
        try:
            resp = _urllib.request.urlopen(url)
            try:
                payload = resp.read()
            finally:
                resp.close()
        except Exception as ex:
            print("[x] something went wrong during retrieval of '%s' ('%s')" % (url, ex))
            return                                  # keep whatever is cached over a partial list

        for line in payload.decode(UNICODE_ENCODING, "replace").split('\n'):
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except ValueError:
                continue
            # the last record is metadata, not a netblock
            if isinstance(record, dict) and record.get("cidr"):
                entries.append("%s # %s" % (record["cidr"], record.get("sblid", "")))

    # A DROP list that came back tiny is a failure that answered 200; the cached copy is better.
    if len(entries) < 100:
        print("[x] Spamhaus DROP returned %d netblock(s) - keeping the previous list" % len(entries))
        return

    tmp = "%s.new" % DROP_FILE
    try:
        with open(tmp, "w+b") as f:
            f.write(("# Spamhaus DROP + DROPv6, (c) The Spamhaus Project SLU\n"
                     "# https://www.spamhaus.org/blocklists/do-not-route-or-peer/\n\n").encode(UNICODE_ENCODING))
            f.write(("\n".join(entries) + "\n").encode(UNICODE_ENCODING))
        os.replace(tmp, DROP_FILE)                  # atomic; the old copy survives until this
        _chown(DROP_FILE)
        print("[i] %d Spamhaus DROP netblock(s)" % len(entries))
    except Exception as ex:
        print("[x] something went wrong while writing '%s' ('%s')" % (DROP_FILE, ex))
        try:
            if os.path.exists(tmp):
                os.remove(tmp)
        except OSError:
            pass

    read_drop()

def update_ipcat(force=False):
    try:
        if not os.path.isdir(USERS_DIR):
            os.makedirs(USERS_DIR, 0o755)
    except Exception as ex:
        sys.exit("[!] something went wrong during creation of directory '%s' ('%s')" % (USERS_DIR, ex))

    _chown(USERS_DIR)

    if force or not os.path.isfile(IPCAT_CSV_FILE) or not os.path.isfile(IPCAT_SQLITE_FILE) or (time.time() - os.stat(IPCAT_CSV_FILE).st_mtime) >= FRESH_IPCAT_DELTA_DAYS * 24 * 3600 or os.stat(IPCAT_SQLITE_FILE).st_size == 0:
        print("[i] updating ipcat database...")

        # Download to a temporary file and swap it in, rather than truncating the cached copy and
        # writing into it. Opening IPCAT_CSV_FILE "w+b" first meant a network failure - or a
        # download that died halfway - left a truncated file behind with a fresh mtime, so the
        # freshness check below then skipped the update and the empty file stayed. This is the
        # pattern the static-trail and provenance fetches in this file already use.
        tmp_ipcat = "%s.new" % IPCAT_CSV_FILE
        try:
            resp = _urllib.request.urlopen(IPCAT_URL)
            try:
                payload = resp.read()
            finally:
                resp.close()

            if not payload.strip():
                raise ValueError("empty response")   # keep the cached copy over nothing

            with open(tmp_ipcat, "wb") as f:
                f.write(payload)
            os.replace(tmp_ipcat, IPCAT_CSV_FILE)    # atomic; the old copy survives until this
        except Exception as ex:
            try:
                if os.path.exists(tmp_ipcat):
                    os.remove(tmp_ipcat)
            except OSError:
                pass
            print("[x] something went wrong during retrieval of '%s' ('%s')" % (IPCAT_URL, ex))

        else:
            try:
                if os.path.exists(IPCAT_SQLITE_FILE):
                    os.remove(IPCAT_SQLITE_FILE)

                with sqlite3.connect(IPCAT_SQLITE_FILE, isolation_level=None, check_same_thread=False) as con:
                    cur = con.cursor()
                    cur.execute("BEGIN TRANSACTION")
                    cur.execute("CREATE TABLE ranges (start_int INT, end_int INT, name TEXT)")

                    with open(IPCAT_CSV_FILE) as f:
                        for row in f:
                            if not row.startswith('#') and not row.startswith('start'):
                                row = row.strip().split(",")
                                cur.execute("INSERT INTO ranges VALUES (?, ?, ?)", (addr_to_int(row[0]), addr_to_int(row[1]), row[2]))

                    cur.execute("COMMIT")
                    cur.close()
                    con.commit()
            except Exception as ex:
                print("[x] something went wrong during ipcat database update ('%s')" % ex)

    _chown(IPCAT_CSV_FILE)
    _chown(IPCAT_SQLITE_FILE)

def _ip6_to_int(text):
    value = 0
    for byte in bytearray(socket.inet_pton(socket.AF_INET6, text)):
        value = (value << 8) | byte
    return value

def _geo_rows(records):
    """records = list of (start_int, end_int, CC) -> sorted rows of (start_int, CC) with empty-CC gap sentinels."""

    records.sort()
    merged = []  # collapse adjacent same-country ranges
    for start, end, cc in records:
        if merged and merged[-1][2] == cc and start <= merged[-1][1] + 1:
            merged[-1][1] = max(merged[-1][1], end)
        else:
            merged.append([start, end, cc])

    rows, prev = [], -1
    for start, end, cc in merged:
        if prev < start - 1:  # gap -> unallocated -> resolves to None on lookup
            rows.append((prev + 1 if prev >= 0 else 0, ""))
        rows.append((start, cc)); prev = end
    rows.append((prev + 1, ""))
    return rows

def _write_geo(path, rows, family=4):
    """Write a geo table in the hex-delta format core/geo.py reads (see its STORAGE note)."""

    shift = 64 if family == 6 else 0     # every RIR IPv6 allocation is coarser than a /64
    lines = ["%s:%d" % (GEO_DELTA_MAGIC, family)]
    previous = 0
    for start, cc in rows:
        value = start >> shift
        lines.append("%x,%s" % (value - previous, cc))
        previous = value

    tmp = path + ".tmp"
    with gzip.open(tmp, "wb") as f:
        f.write("\n".join(lines).encode("latin-1"))
    try:
        os.replace(tmp, path)  # atomic (py3.3+)
    except AttributeError:
        if os.path.exists(path):
            os.remove(path)
        os.rename(tmp, path)
    _chown(path)

def update_geo(force=False):
    """
    Refresh the attack-map's IP -> country tables from the public-domain RIR delegation stats into USERS_DIR (the bundled
    data/ IPv4 snapshot remains the air-gap/first-run seed; IPv6 is runtime-only). Same shape as update_ipcat:
    staleness-gated, best-effort (a failed fetch leaves the previous tables in place), atomic writes. Country allocations
    move slowly, hence the long FRESH_GEO_DELTA_DAYS cadence.
    """

    try:
        if not os.path.isdir(USERS_DIR):
            os.makedirs(USERS_DIR, 0o755)
    except Exception as ex:
        sys.exit("[!] something went wrong during creation of directory '%s' ('%s')" % (USERS_DIR, ex))

    _chown(USERS_DIR)

    if not (force or not os.path.isfile(GEO_IP2CC_FILE) or (time.time() - os.stat(GEO_IP2CC_FILE).st_mtime) >= FRESH_GEO_DELTA_DAYS * 24 * 3600):
        _chown(GEO_IP2CC_FILE)
        return

    print("[i] updating geolocation (IP->country) database...")

    v4, v6 = [], []
    try:
        for url in RIR_DELEGATED_URLS:
            content = retrieve_content(url)
            if not content:
                raise Exception("empty response from '%s'" % url)
            if isinstance(content, bytes):
                content = content.decode("latin-1", "ignore")
            for line in content.splitlines():
                parts = line.split('|')
                if len(parts) < 7 or parts[2] not in ("ipv4", "ipv6") or parts[6] not in ("allocated", "assigned"):
                    continue
                cc = parts[1]
                if len(cc) != 2 or not cc.isalpha():
                    continue
                try:
                    if parts[2] == "ipv4":
                        start = addr_to_int(parts[3]); v4.append((start, start + int(parts[4]) - 1, cc.upper()))
                    else:  # ipv6: parts[4] is the prefix length
                        start = _ip6_to_int(parts[3]); v6.append((start, start + (1 << (128 - int(parts[4]))) - 1, cc.upper()))
                except Exception:
                    continue
    except Exception as ex:
        print("[x] something went wrong during retrieval of RIR delegation stats ('%s')" % ex)
        return

    try:
        _write_geo(GEO_IP2CC_FILE, _geo_rows(v4), family=4)
        if v6:
            _write_geo(GEO_IP2CC6_FILE, _geo_rows(v6), family=6)
    except Exception as ex:
        print("[x] something went wrong during geolocation database update ('%s')" % ex)
        return

    print("[i] ...%d IPv4 + %d IPv6 country ranges" % (len(v4), len(v6)))

def main():
    if "-c" in sys.argv:
        read_config(sys.argv[sys.argv.index("-c") + 1])

    try:
        offline = "--offline" in sys.argv
        update_trails(force=True, offline=offline)
        if not offline:
            update_ipcat()
            update_geo()
            update_drop()
    except KeyboardInterrupt:
        print("\r[x] Ctrl-C pressed")
    else:
        if "-r" in sys.argv:
            results = []
            with _fopen(config.TRAILS_FILE, 'r', codecs.open) as f:
                for line in f:
                    if line and line[0].isdigit():
                        items = line.split(',', 2)
                        if re.search(r"\A[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\Z", items[0]):
                            ip = items[0]
                            reputation = 1
                            lists = items[-1]
                            if '+' in lists:
                                reputation = 2 + lists.count(',')
                            if "(custom)" in lists:
                                reputation -= 1
                            if "(static)" in lists:
                                reputation -= 1
                            reputation -= max(0, lists.count("prox") + lists.count("maxmind") + lists.count("spys.ru") + lists.count("rosinstrument") - 1)      # remove duplicate proxy hits
                            reputation -= max(0, lists.count("blutmagie") + lists.count("torproject") - 1)                                                      # remove duplicate tor hits
                            if reputation > 0:
                                results.append((ip, reputation))
            results = sorted(results, key=lambda _: _[1], reverse=True)
            for result in results:
                sys.stderr.write("%s\t%s\n" % (result[0], result[1]))
                sys.stderr.flush()

        if "--console" in sys.argv:
            with _fopen(config.TRAILS_FILE, 'r', codecs.open) as f:
                for line in f:
                    sys.stdout.write(line)

if __name__ == "__main__":
    main()
