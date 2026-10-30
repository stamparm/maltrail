#!/usr/bin/env python

"""
Copyright (c) 2014-present Maltrail developers (https://github.com/stamparm/maltrail/)
See the file 'LICENSE' for copying permission
"""

import atexit
import codecs
from array import array
import csv
import glob
import heapq
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
from core.addr import canonical_ip_trail
from core.addr import int_to_addr
from core.addr import leading_ipv4
from core.addr import make_mask
from core import assemble
from core import custom_trails
from core.common import bogon_ip
from core.common import cdn_ip
from core.common import check_whitelisted
from core.common import retrieve_content
from core.common import retrieve_to_file
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

# seconds to wait before each attempt at a feed that came back empty or raised
FEED_RETRY_DELAYS = (0, 10, 30)


def _fetch_feed(function, filename):
    """
    A feed's results, or None if every attempt raised.

    Retried in place, not at the end of the run: the merge rule depends on order, so a late retry
    would build a different set than a clean run. The first live run lost sslbl (cert + JA3) and
    Tor exits for a whole day to one network blip - all three fetched fine moments later.
    """

    results = None
    for delay in FEED_RETRY_DELAYS:
        if delay:
            time.sleep(delay)
        try:
            results = function()
        except Exception as ex:
            print("[x] something went wrong during processing of feed file '%s' ('%s')" % (filename, ex))
            continue
        if results:
            break
    return results

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
    if 'w' in mode:
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

    items = trails.sorted_items() if hasattr(trails, "sorted_items") else ((_, trails[_]) for _ in sorted(trails.keys()))
    return _write_scores((key, confidence_score(value[1], len(duplicates.get(key, ())))) for key, value in items)


def _write_scores(scores):
    """Write (trail, confidence) pairs, already sorted by trail, as the confidence sidecar."""

    path = "%s.confidence" % config.TRAILS_FILE
    tmp_file = "%s.new" % path
    try:
        with _fopen(tmp_file, "w", codecs.open) as f:     # "w", not "w+": a read/write text file resets its encoder on every write
            for key, score in scores:
                f.write("%s\t%s\n" % (key, score))
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

    def _usable(path):
        # what `content.count(',') > 1` asked of the whole payload, without holding it
        try:
            with open(path, "rb") as f:
                commas = 0
                for chunk in iter(lambda: f.read(1 << 16), b""):
                    commas += chunk.count(b',')
                    if commas > 1:
                        return True
        except (OSError, IOError):
            pass
        return False

    usable = False

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
            usable = _usable(cache)
        else:
            print(" [o] '%s'" % url)
            raw = retrieve_content(url, binary=True)

            # Decompressed straight to disk and hashed on the way. The payload is ~87 MB unpacked,
            # and holding it (plus a decoded copy, plus the dict built from it) is what used to put
            # a trail update past the memory of a small box.
            tmp = "%s.new" % cache
            sha = hashlib.sha256()
            size = 0
            try:
                with open(tmp, "wb") as f:
                    source = gzip.GzipFile("", "rb", 9, io.BytesIO(raw)) if raw[:2] == b"\x1f\x8b" else io.BytesIO(raw)  # gzip magic; a plain .csv URL still works
                    raw = None
                    try:
                        for chunk in iter(lambda: source.read(1 << 20), b""):
                            sha.update(chunk)
                            f.write(chunk)
                            size += len(chunk)
                    except Exception as ex:
                        print("[x] the static trails could not be decompressed ('%s')" % ex)
                        size = 0
            except (OSError, IOError) as ex:
                print("[x] unable to cache the static trails ('%s')" % ex)
                size = 0

            digest = sha.hexdigest() if size else None

            if published and digest and digest != published:
                # Refuse a payload that is not the one that was published. A truncated download is
                # the dangerous case: it parses fine and is simply missing indicators.
                print("[x] the static trails do not match their published sha256 (%s != %s) - keeping the cache" % (digest[:12], published[:12]))
            elif size and _usable(tmp):
                try:
                    _atomic_replace(tmp, cache)
                    usable = True
                    if digest:
                        with open("%s.new" % stamp, "w") as f:
                            f.write(digest)
                        _atomic_replace("%s.new" % stamp, stamp)
                except (OSError, IOError) as ex:
                    print("[x] unable to cache the static trails ('%s')" % ex)
            else:
                print("[x] unable to retrieve the static trails from '%s'" % url)

            try:
                if os.path.exists(tmp):
                    os.remove(tmp)
            except (OSError, IOError):
                pass

    if not usable and os.path.isfile(cache):
        usable = _usable(cache)
        if usable:
            print("[i] using the cached static trails ('%s')" % cache)

    if not usable:
        # Loudly. An empty static set is 1.6M missing indicators, and every symptom of it - a
        # server that starts, a dashboard that renders, a sensor that reports healthy - looks
        # exactly like a quiet network.
        print("[!] no static trails available: '%s' could not be retrieved and there is no cache at '%s'" % (config.STATIC_TRAILS_URL or "<STATIC_TRAILS_URL unset>", cache))
        return {}

    return _StaticTrails(cache)

class _StaticTrails(object):
    """
    The cached static aggregate as the {trail: (info, reference)} mapping _merge() consumes, read
    from disk row by row instead of built as a 1.7M-entry dict first. The aggregate is published with
    unique keys, so streaming it merges exactly what the dict did.
    """

    def __init__(self, path):
        self.path = path

    def items(self):
        # csv.reader, not split(','): 24 trails contain a comma of their own (regex trails such as
        # `[0-9]{2,3}\.ru`, URL trails such as `/44285,5327891204.dat`). This is the same dialect
        # load_trails() uses on trails.csv.
        with io.open(self.path, "r", encoding=UNICODE_ENCODING, newline="") as f:
            for row in csv.reader(f, delimiter=',', quotechar='"'):
                if row and len(row) == 3:
                    yield row[0], (row[1], row[2])

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


def _available_memory():
    """
    Bytes this process could still allocate: MemAvailable, capped by the cgroup limit of every
    cgroup (v2 or v1) it sits in - a container or a systemd MemoryMax= is the limit that kills it,
    and /proc/meminfo knows nothing about either. None when neither can be read (non-Linux).
    """

    candidates = []
    try:
        with open("/proc/meminfo") as f:
            for line in f:
                if line.startswith("MemAvailable:"):
                    candidates.append(int(line.split()[1]) * 1024)
    except (OSError, IOError, ValueError):
        pass

    def _read(path):
        try:
            with open(path) as f:
                value = f.read().strip()
            return None if value in ("", "max") else int(value)
        except (OSError, IOError, ValueError):
            return None

    def _cache(path, field):
        # page cache is charged to the cgroup but given back under pressure, so it is not "used"
        try:
            with open(path) as f:
                for line in f:
                    if line.split()[0] == field:
                        return int(line.split()[1])
        except (OSError, IOError, ValueError, IndexError):
            pass
        return 0

    try:
        with open("/proc/self/cgroup") as f:
            entries = [line.strip().split(':', 2) for line in f if line.strip()]
    except (OSError, IOError):
        entries = []

    for hierarchy, controllers, path in (_ for _ in entries if len(_) == 3):
        if hierarchy == "0":
            root, limit_name, usage_name, cache_field = "/sys/fs/cgroup", "memory.max", "memory.current", "file"
        elif "memory" in controllers.split(','):
            root, limit_name, usage_name, cache_field = "/sys/fs/cgroup/memory", "memory.limit_in_bytes", "memory.usage_in_bytes", "total_cache"
        else:
            continue
        # every ancestor's limit applies; inside a container the namespace root is the own cgroup
        parts = [_ for _ in path.split('/') if _]
        for i in xrange(len(parts), -1, -1):
            directory = os.path.join(root, *parts[:i])
            limit, usage = _read(os.path.join(directory, limit_name)), _read(os.path.join(directory, usage_name))
            if limit is not None and usage is not None and limit < (1 << 60):
                candidates.append(max(0, limit - usage + _cache(os.path.join(directory, "memory.stat"), cache_field)))

    return min(candidates) if candidates else None

def _low_memory():
    """Whether update_trails() builds with `_StreamBuild` rather than in one dict.

    One dict of 1.9M trails peaks at ~230 MB on a 64-bit host and ~160 MB on 32-bit ARM, about 2.6
    and 1.8 times the static aggregate's size; the streaming build needs a few tens of MB. A host
    that can spend three quarters of its available memory on the dict gets the dict, the fastest
    build. Not half: on a Pi Zero next to a running sensor, 226 MB is available and most of the rest
    is the sensor's mapped trail store - clean page cache the kernel drops and re-reads - and half
    sent it to the 27-minute streaming build instead of the 13-minute dict.
    """

    available = _available_memory()
    if not available:
        return False
    try:
        size = os.path.getsize("%s.static" % config.TRAILS_FILE)
    except OSError:
        size = 100 * 1024 * 1024
    return size * (2.6 if sys.maxsize > 2 ** 32 else 1.8) > available * 3 // 4


# Why the last update_trails() kept the existing trails.csv instead of writing its build, or None.
last_refusal = None


# Answers per distinct string. ~3,100 distinct (info, reference) pairs carry 1.9M trails, so the
# keyword scans below were asked the same question about the same string hundreds of times each.
_ANY_CACHE = {}


def _has_any(text, needles):
    """`any(_ in text for _ in needles)`, remembered per (text, needles)."""

    key = (text, needles)
    answer = _ANY_CACHE.get(key)
    if answer is None:
        answer = _ANY_CACHE[key] = any(_ in text for _ in needles)
    return answer


_ENCODABLE_CACHE = {}


def _encodable(value):
    """Whether both strings of an (info, reference) value encode as UTF-8, remembered per value."""

    answer = _ENCODABLE_CACHE.get(value)
    if answer is None:
        try:
            for _ in value[:2]:
                _.decode("utf8") if hasattr(_, "decode") else _.encode("utf8")
            answer = True
        except UnicodeError:
            answer = False
        _ENCODABLE_CACHE[value] = answer
    return answer


_SLASH_RUN_REGEX = re.compile(r"/+")
_LEADING_WWW_REGEX = re.compile(r"\A(?:www\.|\.)+")


def _group(key):
    """The key every ASCII rename in the post-processing can turn `key` into, or a coarser one.

    update_trails() looks at one key at a time, except where it renames one (lower case, "www.",
    "?query", "//"). Two keys with the same group may meet; two with different groups never do, so
    a group seen once can be built on its own. A non-ASCII key is also renamed by idna, which does
    not commute with the rest (it encodes a whole label, '/' and '?' included) - so _StreamBuild
    never streams one, and holds back both groups it could reach (`_idn_groups()`).
    """

    key = key.lower()
    if '/' in key or '?' in key:
        key = _SLASH_RUN_REGEX.sub('/', key.split('?')[0])
    # every leading "www." and dot at once, in whatever order they come, then trailing dots
    return _LEADING_WWW_REGEX.sub("", key).rstrip('.')


def _idn_groups(key):
    """The groups a non-ASCII key can reach: the one its ASCII renames keep, and - when idna takes
    it, which the post-processing tries first - the one of the name idna gives it."""

    groups = set((_group(key),))
    try:
        groups.add(_group(key.encode("idna").decode(UNICODE_ENCODING)))
    except Exception:
        pass
    return groups


class _Shard(object):
    """One shard of the trail build: a plain dict, plus each entry's place in the global order when
    there is more than one shard (`stamps`), so the shards' outputs can be merged back into the
    exact order one dict would have produced."""

    def __init__(self, stamped):
        self.store = {}
        self.pairs = {}
        self.duplicates = {}
        self.stamps = {} if stamped else None
        self.now = 0

    def put(self, key, value):
        pair = (value[0], value[1])
        pair = self.pairs.setdefault(pair, pair)
        store = self.store
        if self.stamps is not None and key not in store:
            self.stamps[key] = self.now
            self.now += 1
        store[key] = pair

    def delete(self, key):
        del self.store[key]
        if self.stamps is not None:
            del self.stamps[key]

    def apply(self, op, key, value, check=None):
        """One source row. 'M': the merge rule every source goes through. 'R': a remote custom
        trail, which never displaces a custom or static one (`check` is the form it is checked as).
        'S': set unconditionally."""

        get = self.store.get
        if op == 'M':
            current = get(key)
            if current is not None:
                seen = self.duplicates.get(key)
                if seen is None:
                    seen = self.duplicates[key] = set((current[1],))
                seen.add(value[1])
            info = value[0]
            if not (current is not None and (_has_any(info, LOW_PRIORITY_INFO_KEYWORDS) or current[1] in HIGH_PRIORITY_REFERENCES)) or (value[1] in HIGH_PRIORITY_REFERENCES and "history" not in info) or _has_any(info, HIGH_PRIORITY_INFO_KEYWORDS):
                self.put(key, value)
        elif op == 'R':
            current = get(check)
            if current is not None and _has_any(current[1], ("custom", "static")):
                return
            self.put(key, value)
        else:
            self.put(key, value)

    def post_process(self, disabled_info_regex, ip_minimum_feeds):
        """The basic cleanup and the whitelist/bogon pass, on this shard."""

        get, put, delete, duplicates = self.store.get, self.put, self.delete, self.duplicates
        stamped = self.stamps is not None
        # Re-insertions during the cleanup go to the end, in the order the walk makes them: after
        # every entry the merge left, ordered by the entry being visited, then by step.
        late = 1 << 62

        # basic cleanup - `value` is the current key's value, held instead of looked up again
        # at every step (it was up to nine lookups per trail)
        for key in list(self.store):
            value = get(key)
            if value is None:
                continue
            if stamped:
                self.now = late + (self.stamps[key] << 4)

            if disabled_info_regex is not None:
                if disabled_info_regex.search(value[0]):
                    delete(key)
                    continue

            if _is_ascii(key):
                # NAMEPREP (the only effect of idna on an already-ASCII name) just lowercases it, so skip the
                # ~20x slower idna codec for the ~all-ASCII majority; non-ASCII names (e.g. IDN phishing) still go through idna
                _key = key.lower()
                if _key != key:
                    put(_key, value)
                    delete(key)
                    key = _key
            else:
                try:
                    _key = key.decode(UNICODE_ENCODING) if isinstance(key, bytes) else key
                    _key = _key.encode("idna")
                    _key = _key.decode(UNICODE_ENCODING)
                    if _key != key:  # for domains with non-ASCII letters (e.g. phishing)
                        put(_key, value)
                        delete(key)
                        key = _key
                except Exception:
                    pass

            if not key or _ALPHA_ONLY_REGEX.search(key) and not _has_any(value[1], ("custom", "static")):
                delete(key)
                continue

            if _IPV4_REGEX.search(key):
                if _has_any(value[0], ("parking site", "sinkhole")) and key in duplicates:    # Note: delete (e.g.) junk custom trails if static trail is a sinkhole
                    del duplicates[key]

                if value[0] == "malware":
                    value = ("potential malware site", value[1])
                    put(key, value)

                if ip_minimum_feeds > 1:
                    if (key not in duplicates or len(duplicates[key]) < ip_minimum_feeds) and _CUSTOM_STATIC_REGEX.search(value[1]) is None:
                        delete(key)
                        continue

                if any(int(_) > 255 for _ in key.split('.')):
                    delete(key)
                    continue

            if value[0] == "ransomware":
                value = ("ransomware (malware)", value[1])
                put(key, value)

            if key.startswith("www.") and '/' not in key:
                delete(key)
                key = key[len("www."):]
                if key:
                    put(key, value)

            if '?' in key and not key.startswith('/'):
                delete(key)
                key = key.split('?')[0]
                if key:
                    put(key, value)

            if '//' in key:
                delete(key)
                key = key.replace('//', '/')
                put(key, value)

            if key != key.lower():
                delete(key)
                key = key.lower()
                put(key, value)

            if key in duplicates:
                others = sorted(duplicates[key] - set((value[1],)))
                if others and " (+" not in value[1]:
                    put(key, (value[0], "%s (+%s)" % (value[1], ','.join(others))))

        for key in list(self.store):
            # leading_ipv4(), not a `\b`-bounded prefix match: `\b` also matches the dot of a digit-leading
            # DOMAIN, so a reverse-DNS style trail was judged by its first four labels. Two static trails
            # (`10.53.154.104.bc.googleusercontent.com`, `224.185.60.34...`) were deleted from every build
            # as bogons, while their neighbours with a routable leading quad survived - a detection lost to
            # a filter meant for address trails.
            address = leading_ipv4(key)
            if check_whitelisted(key) or key.startswith(BAD_TRAIL_PREFIXES):
                delete(key)
            elif address and (bogon_ip(address) or cdn_ip(address)) and not _has_any(get(key)[0], ("parking", "sinkhole")):
                delete(key)
            else:
                try:
                    key.decode("utf8") if hasattr(key, "decode") else key.encode("utf8")
                    if not _encodable(get(key)):
                        delete(key)
                except UnicodeError:
                    delete(key)

    def rows(self):
        """(order, trail, info, reference) in this shard's order. The order is fixed-width hex, so
        rows from several shards compare correctly as the strings they are read back as."""

        stamps = self.stamps
        for key, value in self.store.items():
            yield ("%016x" % stamps[key] if stamps is not None else ""), key, value[0], value[1]

    def scores(self):
        """(trail, confidence) sorted by trail."""

        cache = {}
        for key in sorted(self.store):
            value = self.store[key]
            agreeing = len(self.duplicates.get(key, ()))
            score = cache.get((value[1], agreeing))
            if score is None:
                score = cache[(value[1], agreeing)] = confidence_score(value[1], agreeing)
            yield key, score


class _TrailBuild(object):
    """The trail set update_trails() builds, in one dict: the fastest way, for every host that has
    the memory. A smaller host gets `_StreamBuild`, the same rules in a fraction of the memory."""

    def __init__(self):
        self.one = _Shard(stamped=False)

    def merge(self, results):
        """Merge one source's {trail: (info, reference)}: ONE rule for feeds, custom and static
        alike - where a source comes from must not change which of two labels a trail ends up with."""

        apply = self.one.apply
        for key, value in results.items():
            # one address, one key: an IPv6 trail spelled any other way than the sensor
            # renders it never matched, and two spellings would not have merged here
            if ':' in key:
                key = canonical_ip_trail(key)
            if key.startswith("www.") and '/' not in key:
                key = key[len("www."):]
            apply('M', key, value)

    def remote(self, key, value, check):
        self.one.apply('R', key, value, check)

    def set(self, key, value):
        self.one.apply('S', key, value)

    def size(self):
        return len(self.one.store)

    def build(self, disabled_info_regex, ip_minimum_feeds):
        """Post-process. Returns (rows, scores): every (order, trail, info, reference) in the order
        trails.csv is written, and every (trail, confidence) sorted by trail."""

        self.one.post_process(disabled_info_regex, ip_minimum_feeds)
        return self.one.rows(), self.one.scores()

    def close(self):
        pass


class _StreamBuild(object):
    """The trail build with a cheap miss and an expensive hit.

    Almost every row the merge sees is a trail it has not seen before: 1,762,779 of 1,763,354 on the
    real set. So nothing is stored on the way in: the sources are kept as they are (the static set
    is a file read again, the rest are small) and a bit filter over the rows' groups (`_group()`, two
    bits per group in 4 MB) notes the groups seen more than once - the real repeats and ~0.2% false
    positives. Then the repeated groups, a few thousand trails, are built in one small dict, and
    every other row - a group seen once cannot meet any other row - is built in batches and streamed
    out, merged with the small dict's rows by order stamp. Same `_Shard` rules, so the result is
    byte for byte the one-dict build.
    """

    FILTER_BITS = 1 << 25
    BATCH = 50000
    RUN = 100000

    def __init__(self, prefix):
        self.prefix = prefix
        self.sources = []
        self.seq = 0
        self.bits = bytearray(self.FILTER_BITS >> 3)
        self.repeat = set()
        # each row's group hash, 32 bits: the later passes ask `hashes[seq] in repeat` instead of
        # computing the group again. A collision only sends a singleton down the exact path.
        self.hashes = array('I')
        self.runs = []
        self.late_path = prefix + ".late"
        # an updater stopped mid-build (Ctrl-C, or the sensor that ran it dying) still cleans up
        atexit.register(self.close)

    def _seen(self, key):
        h = hash(_group(key))
        mask = self.FILTER_BITS - 1
        a, b = h & mask, (h >> 32) & mask
        self.hashes.append(h & 0xFFFFFFFF)
        if not _is_ascii(key):
            # never streamed, and nothing it can be renamed onto is streamed either
            for group in _idn_groups(key):
                self.repeat.add(hash(group) & 0xFFFFFFFF)
        bits = self.bits
        if (bits[a >> 3] >> (a & 7)) & (bits[b >> 3] >> (b & 7)) & 1:
            self.repeat.add(h & 0xFFFFFFFF)
        else:
            bits[a >> 3] |= 1 << (a & 7)
            bits[b >> 3] |= 1 << (b & 7)
        self.seq += 1

    def _rows(self):
        """Every source row again, in the order and with the sequence numbers of the first pass."""

        seq = 0
        for source in self.sources:
            if source[0] == 'M':
                for key, value in source[1].items():
                    if ':' in key:
                        key = canonical_ip_trail(key)
                    if key.startswith("www.") and '/' not in key:
                        key = key[len("www."):]
                    yield seq, 'M', key, value, None
                    seq += 1
            else:
                yield seq, source[0], source[1], source[2], source[3]
                seq += 1

    def merge(self, results):
        """Merge one source's {trail: (info, reference)}: ONE rule for feeds, custom and static
        alike - where a source comes from must not change which of two labels a trail ends up with."""

        self.sources.append(('M', results))
        for key in (_[0] for _ in results.items()):
            if ':' in key:
                key = canonical_ip_trail(key)
            if key.startswith("www.") and '/' not in key:
                key = key[len("www."):]
            self._seen(key)

    def remote(self, key, value, check):
        # Checked in one form, stored in another: always the exact path, whatever the groups. A
        # remote custom list is short.
        self.sources.append(('R', key, value, check))
        self._seen(key)
        self.repeat.add(self.hashes[-1])

    def set(self, key, value):
        self.sources.append(('S', key, value, None))
        self._seen(key)

    def build(self, disabled_info_regex, ip_minimum_feeds):
        self.bits = None
        repeat = self.repeat
        late_mark = "%016x" % (1 << 62)
        scores = []

        def run_out():
            if scores:
                scores.sort()
                path = "%s.run%d" % (self.prefix, len(self.runs))
                with io.open(path, "w", encoding=UNICODE_ENCODING, newline="") as f:
                    csv.writer(f).writerows(scores)
                self.runs.append(path)
                del scores[:]

        def finish(shard):
            shard.post_process(disabled_info_regex, ip_minimum_feeds)
            scores.extend(shard.scores())
            if len(scores) >= self.RUN:
                run_out()
            return shard.rows()

        # the expensive path: every row of a repeated group, in one dict
        repeated = _Shard(stamped=True)
        hashes = self.hashes
        for seq, op, key, value, check in self._rows():
            if hashes[seq] in repeat:
                repeated.now = seq
                repeated.apply(op, key, value, check)
        held = sorted(finish(repeated))
        del repeated

        def rows():
            # the cheap path: groups seen once, in batches, merged with `held` by stamp. Rows a
            # rename moved to the end come after every other row, so they wait in a file.
            pending = iter(held)
            nxt = next(pending, None)
            late = io.open(self.late_path, "w", encoding=UNICODE_ENCODING, newline="")
            late_writer = csv.writer(late)
            batch = _Shard(stamped=True)

            def drain(shard):
                for row in finish(shard):
                    if row[0] >= late_mark:
                        late_writer.writerow(row)
                    else:
                        yield row

            for seq, op, key, value, check in self._rows():
                if hashes[seq] in repeat:
                    continue
                batch.now = seq
                batch.apply(op, key, value, check)
                if len(batch.store) >= self.BATCH:
                    for row in drain(batch):
                        while nxt is not None and nxt[0] < row[0] and nxt[0] < late_mark:
                            yield nxt
                            nxt = next(pending, None)
                        yield row
                    batch = _Shard(stamped=True)
            for row in drain(batch):
                while nxt is not None and nxt[0] < row[0] and nxt[0] < late_mark:
                    yield nxt
                    nxt = next(pending, None)
                yield row
            late.close()
            run_out()

            def late_rows():
                with io.open(self.late_path, "r", encoding=UNICODE_ENCODING, newline="") as f:
                    for row in csv.reader(f):
                        yield tuple(row)

            rest = ([nxt] if nxt is not None else []) + list(pending)
            for row in heapq.merge(late_rows(), rest):
                yield row

        def all_scores():
            for row in heapq.merge(*[_csv_rows(_) for _ in self.runs]):
                yield row

        return rows(), all_scores()

    def size(self):
        return self.seq

    def close(self):
        for path in [self.late_path] + self.runs:
            try:
                os.remove(path)
            except OSError:
                pass


def _csv_rows(path):
    with io.open(path, "r", encoding=UNICODE_ENCODING, newline="") as f:
        for row in csv.reader(f):
            yield row


def update_trails(force=False, offline=False):
    """
    Update trails from feeds
    """

    global last_refusal
    last_refusal = None
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
        tmp_trails_file = "%s.new" % config.TRAILS_FILE
        # Streamed to disk: the set is ~100 MB, and a small sensor box is exactly the deployment
        # that pulls it from a server instead of building it.
        size = retrieve_to_file(config.UPDATE_SERVER, tmp_trails_file, headers=headers, response=response)

        def _usable(path):
            try:
                with open(path, "rb") as f:
                    commas = 0
                    for chunk in iter(lambda: f.read(1 << 16), b""):
                        commas += chunk.count(b',')
                        if commas >= 2:
                            return True
            except (OSError, IOError):
                pass
            return False

        if response.get("code") == NOT_MODIFIED:
            # The server says the set we already hold is current, so the ~84 MB is not sent and
            # not rebuilt. _stored_etag() only offers a validator while that set is still on disk,
            # so this branch cannot leave us with nothing.
            print("[i] trails from '%s' are unchanged" % config.UPDATE_SERVER)
        elif not size or not _usable(tmp_trails_file):
            print("[x] unable to retrieve data from '%s'" % config.UPDATE_SERVER)
        else:
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
            print("[i] trails stored to '%s'" % config.TRAILS_FILE)

        try:
            if os.path.exists(tmp_trails_file):
                os.remove(tmp_trails_file)
        except OSError:
            pass

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

            if _low_memory():
                print("[i] %d MB of memory available - building the trail set streamed" % ((_available_memory() or 0) // (1024 * 1024)))
                build = _StreamBuild("%s.build" % config.TRAILS_FILE)
            else:
                build = _TrailBuild()
            _merge = build.merge

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

                        # A feed whose provider wants a key nobody configured is not a dead feed:
                        # say once how to enable it, and keep it out of the "no indicators" list
                        required = getattr(module, "__requires__", None)
                        if required and not (config.get(required) or "").strip():
                            print("[i] feed skipped: '%s' is not set (%s)" % (required, getattr(module, "__requires_hint__", "see 'maltrail.conf'")))
                            continue

                        results = _fetch_feed(function, filename)
                        if results is not None:
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
            static = fetch_static_trails(offline)
            # {} is fetch_static_trails() saying "configured, but neither downloadable nor cached".
            static_missing = isinstance(static, dict) and not static and bool(config.STATIC_TRAILS_URL)
            _merge(static)

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
                            line = canonical_ip_trail(line.rstrip('/'))

                            # never displaces a custom or static trail of the same name
                            if '/' in line or re.search(r"\A\d+\.\d+\.\d+\.\d+\Z", line):
                                build.remote(line, (__info__, __reference__), line)
                            else:
                                build.remote(line.strip('.'), (__info__, __reference__), line)

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
                                    build.set(int_to_addr(address), (__info__, __reference__))
                                    address += 1

            print("[i] post-processing trails (this might take a while)...")

            disabled_info_regex = re.compile(config.DISABLED_TRAILS_INFO_REGEX) if config.DISABLED_TRAILS_INFO_REGEX else None
            ip_minimum_feeds = config.get("IP_MINIMUM_FEEDS", 3)

            read_whitelist()
            rows, scores = build.build(disabled_info_regex, ip_minimum_feeds)

            tmp_trails_file = "%s.new" % config.TRAILS_FILE
            # Without the static trails this build is feeds and custom only - a few percent of the
            # set. Writing it would replace a working trails.csv with that, and from there it goes
            # to every sensor that pulls from this server; each would then look healthy while
            # matching almost nothing. Keep the file that works, unchanged and with its old mtime,
            # so the next cycle tries again.
            keep_current = static_missing and os.path.isfile(config.TRAILS_FILE) and os.path.getsize(config.TRAILS_FILE) > 0
            if keep_current:
                message = "the static trails are unavailable, so '%s' was NOT replaced with a feeds-only build (%d trails); keeping the current one" % (config.TRAILS_FILE, build.size())
                last_refusal = message
                print("[x] %s" % message)
                try:
                    from core.log import log_error
                    log_error(message)
                except Exception:
                    pass
            try:
                if build.size() and not keep_current:
                    written = 0
                    with _fopen(tmp_trails_file, "w", codecs.open) as f:
                        writer = csv.writer(f, delimiter=',', quotechar='\"', quoting=csv.QUOTE_MINIMAL)
                        for _, trail, info, reference in rows:
                            writer.writerow((trail, info, reference))
                            written += 1

                    # an empty build never replaces the trails a deployment has
                    if written:
                        _atomic_replace(tmp_trails_file, config.TRAILS_FILE)
                        _write_scores(scores)
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

            build.close()
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
