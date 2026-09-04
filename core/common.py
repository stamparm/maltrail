#!/usr/bin/env python

"""
Copyright (c) 2014-2026 Maltrail developers (https://github.com/stamparm/maltrail/)
See the file 'LICENSE' for copying permission
"""


import bisect
import csv
import gzip
import io
import json
import os
import re
import socket
import sqlite3
import sys
import threading
import time
import zipfile
import zlib

from core import trailsbin
from core.addr import addr_to_int
from core.addr import int_to_addr
from core.compat import xrange
from core.datatype import LRUDict
from core.settings import config
from core.settings import BOGON_IPS
from core.settings import BOGON_RANGES
from core.settings import CHECK_CONNECTION_URL
from core.settings import CDN_RANGES
from core.settings import IPCAT_SQLITE_FILE
from core.settings import IS_WIN
from core.settings import MAX_CACHE_ENTRIES
from core.settings import MAX_HELP_OPTION_LENGTH
from core.settings import STATIC_IPCAT_LOOKUPS
from core.settings import TIMEOUT
from core.settings import UNICODE_ENCODING
from core.settings import USER_AGENT
from core.settings import WHITELIST
from core.settings import WHITELIST_RANGES
from core.settings import DROP6_RANGES
from core.settings import DROP_RANGES
from core.settings import WORST_ASNS
from core.trailsdict import TrailsDict
import urllib.error
import urllib.parse
import urllib.request
import urllib.response
import urllib as _urllib
import http.cookiejar as _cookiejar

_ipcat_cache = {}  # NOTE: holds the (bounded, config-sized) static IPCAT seed
_ipcat_dynamic_cache = LRUDict(MAX_CACHE_ENTRIES)  # NOTE: bounds per-IP SQLite lookups so they can't grow without bound on a busy server

try:
    import fcntl
except ImportError:
    fcntl = None

# The shared, memory-mapped trail store (one physical copy across all worker processes instead of one heap copy
# each) is used where the platform supports it: POSIX with flock + an OS that shares mmap'd file pages. On Windows
# (where the sensor runs single-process anyway) the in-heap finalize() path is used instead.
USE_MMAP_TRAILS = bool(fcntl) and not IS_WIN

_WILDCARD_TRAIL_REGEX = re.compile(r"[\].][*+]|\[[a-z0-9_.\-]+\]", re.I)

def retrieve_content(url, data=None, headers=None, binary=False, response=None):
    """
    Retrieves page content from given URL

    `binary=True` returns the raw bytes instead of decoded text, for a payload that is not text -
    the gzipped trail aggregate. Decoding that with errors="replace" would corrupt it silently.

    `response`, when a dict is passed, is filled with the status code and the reply headers (keys
    lower-cased). The body alone cannot express a conditional fetch: a 304 raises out of urlopen()
    and its body is empty, which is indistinguishable from the failure this function deliberately
    reports as empty content. Callers that do not pass it are unaffected, which is what keeps the
    43 feed modules out of this.
    """

    def _record(code, hdrs):
        if response is None:
            return
        response["code"] = code
        response["headers"] = dict((k.lower(), v) for k, v in dict(hdrs or {}).items())

    # Cookies, kept for the duration of this one call. urlopen() has no cookie support, so a site
    # that answers the first request with "307 + Set-Cookie -> same URL with a token" is
    # unreachable: the redirect is followed WITHOUT the cookie, the challenge is re-issued, and
    # urllib gives up with HTTPError 307. That is not a dead feed and not user-agent blocking -
    # cybercrime-tracker.net does exactly this, which is why its three feeds returned nothing
    # while the same links opened fine in a browser (issue #19545). A fresh jar per call keeps
    # this a transport detail: nothing is carried between feeds or between updates.
    try:
        # NOTE: percent-encode spaces only in the query string (chars after the first '?'); if there's no '?', encode them all.
        # (Was an O(n^2) char-by-char comprehension that recomputed url.find('?') for every character.)
        _ = url.find('?')
        url = url.replace(' ', "%20") if _ == -1 else url[:_ + 1] + url[_ + 1:].replace(' ', "%20")
        req = _urllib.request.Request(url, data, headers or {"User-agent": USER_AGENT, "Accept-encoding": "gzip, deflate"})
        opener = _urllib.request.build_opener(_urllib.request.HTTPCookieProcessor(_cookiejar.CookieJar()))
        resp = opener.open(req, timeout=TIMEOUT)
        retval = resp.read()
        encoding = resp.headers.get("Content-Encoding")
        _record(resp.getcode(), resp.headers)
        resp.close()

        if encoding:
            if encoding.lower() == "deflate":
                data = io.BytesIO(zlib.decompress(retval, -15))
                retval = data.read()
            elif encoding.lower() == "gzip":
                data = gzip.GzipFile("", "rb", 9, io.BytesIO(retval))
                retval = data.read()
            # NOTE: any other Content-Encoding (e.g. "identity") leaves retval as the raw response body
    except Exception as ex:
        retval = ex.read() if hasattr(ex, "read") else (get_ex_message(ex) or "")
        _record(getattr(ex, "code", None), getattr(ex, "headers", None))

        if url.startswith("https://") and isinstance(retval, str) and "handshake failure" in retval:
            return retrieve_content(url.replace("https://", "http://"), data, headers, binary, response)

        # NOTE: on failure return EMPTY, never the error body/message. Feeds gate parsing on a `__check__` substring and a
        # few have no guard at all - returning an HTTP error page / WAF block / timeout string here let that text get parsed
        # into bogus "trails" (feed poisoning). Empty content makes feeds yield nothing and update_trails report the failure.
        retval = b""

    retval = retval or b""

    if binary:
        return retval if isinstance(retval, bytes) else retval.encode(UNICODE_ENCODING)

    if isinstance(retval, bytes):
        retval = retval.decode(UNICODE_ENCODING, errors="replace")

    return retval

def fetch_headers(url, timeout=10):
    class _NoRedirect(_urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            return None  # prevents following; urllib raises HTTPError for 3xx

    _NO_REDIRECT_OPENER = _urllib.request.build_opener(_NoRedirect())

    req = _urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    req.get_method = lambda: "HEAD"  # NOTE: portable way to force HEAD; Request(method=...) is Python 3.3+ only

    try:
        resp = _NO_REDIRECT_OPENER.open(req, timeout=timeout)  # NOTE: urllib responses are not context managers on Python 2
        try:
            return dict(resp.headers.items())
        finally:
            resp.close()
    except _urllib.error.HTTPError as e:
        if e.code in (301, 302, 303, 307, 308):
            return dict(e.headers.items())
        raise

RIPE_LOOKUP_URLS = {
    "geo": "https://stat.ripe.net/data/geoloc/data.json?resource=%s",
    "asn": "https://stat.ripe.net/data/network-info/data.json?resource=%s",
}
RIPE_LOOKUP_TIMEOUT = 5             # a dashboard request must not hang on RIPEstat; TIMEOUT (30s) is for feed downloads
RIPE_LOOKUP_TTL = 7 * 24 * 3600     # geolocation and ASN allocation move on a scale of months
RIPE_LOOKUP_MISS_TTL = 600          # air-gapped/blocked: remember the failure briefly instead of re-dialling per request
RIPE_LOOKUP_MAX_ENTRIES = MAX_CACHE_ENTRIES

_ripe_cache = {}                    # (kind, address) -> (expires_at, payload or None)
_ripe_lock = threading.Lock()

def ripe_lookup(kind, address):
    """
    Server-side RIPEstat lookup for the dashboard's country flags and ASN tooltips.

    This used to be done by the browser, with a `<script>` per IP pointed at stat.ripe.net (RIPEstat
    speaks JSONP, and `connect-src 'self'` forbids fetch()) - which is why the shipped CSP had to
    allow `script-src ... https://stat.ripe.net`. That is third-party code executing in the page
    that renders the operator's alerts, trusted for as long as the policy says so; the enrichment it
    buys is two decorations. Doing the lookup here puts `script-src` back to `'self'`, replaces N
    `<script>` nodes per page with same-origin fetches, and lets one cache serve every analyst
    instead of one per browser profile.

    `kind` is a key of `RIPE_LOOKUP_URLS`; `address` must already be validated by the caller (it is
    interpolated into a fixed URL, so an unvalidated value is the SSRF here). Returns a payload dict,
    or None when the lookup is unavailable - which is also cached briefly, so an air-gapped server
    answers instantly rather than making every page wait out a connect timeout.

    Set `DISABLE_RIPE_LOOKUPS true` in maltrail.conf on a server that must make no outbound
    requests; the frontend degrades exactly as it does on a network where RIPEstat is unreachable.
    """

    if kind not in RIPE_LOOKUP_URLS or not address:
        return None

    if config.DISABLE_RIPE_LOOKUPS:
        return None

    key = (kind, address)
    now = time.time()

    with _ripe_lock:
        if key in _ripe_cache:
            expires, payload = _ripe_cache[key]
            if expires > now:
                return payload
            del _ripe_cache[key]

    payload = None

    try:
        req = _urllib.request.Request(RIPE_LOOKUP_URLS[kind] % _urllib.parse.quote(address, safe=''),
                                      headers={"User-Agent": USER_AGENT, "Accept": "application/json"})
        resp = _urllib.request.urlopen(req, timeout=RIPE_LOOKUP_TIMEOUT)   # NOTE: not retrieve_content() - that one is for feeds and waits TIMEOUT (30s)
        try:
            body = resp.read(1 << 20)
        finally:
            resp.close()

        data = json.loads(body.decode(UNICODE_ENCODING, errors="replace")).get("data") or {}

        if kind == "geo":
            country = ""
            for resource in (data.get("located_resources") or []):
                for location in (resource.get("locations") or []):
                    country = (location.get("country") or "").split('-')[0].strip().lower()
                    if country:
                        break
                if country:
                    break
            payload = {"cc": country if re.match(r"\A[a-z]{2}\Z", country) else ""}
        else:
            asns = data.get("asns") or []
            payload = {"asn": "AS%s" % asns[0] if asns else "", "holder": ""}
    except Exception:
        payload = None   # NOTE: unreachable, rate-limited, HTML error page, malformed JSON - all the same non-answer

    with _ripe_lock:
        if len(_ripe_cache) >= RIPE_LOOKUP_MAX_ENTRIES:
            # Cheapest bounded eviction: drop whatever expires first. This cache is an optimisation,
            # so evicting a live entry costs one extra lookup, never a wrong answer.
            for stale in sorted(_ripe_cache, key=lambda _: _ripe_cache[_][0])[:RIPE_LOOKUP_MAX_ENTRIES // 4 or 1]:
                _ripe_cache.pop(stale, None)
        _ripe_cache[key] = (now + (RIPE_LOOKUP_TTL if payload else RIPE_LOOKUP_MISS_TTL), payload)

    return payload

def ipcat_lookup(address):
    if not address:
        return None

    if not _ipcat_cache:
        for name in STATIC_IPCAT_LOOKUPS:
            for value in STATIC_IPCAT_LOOKUPS[name]:
                if "-" in value:
                    start, end = value.split('-')
                    start_int, end_int = addr_to_int(start), addr_to_int(end)
                    current = start_int
                    while start_int <= current <= end_int:
                        _ipcat_cache[int_to_addr(current)] = name
                        current += 1
                else:
                    _ipcat_cache[value] = name

    if address in _ipcat_cache:
        retval = _ipcat_cache[address]
    elif address in _ipcat_dynamic_cache:
        retval = _ipcat_dynamic_cache[address]
    else:
        retval = ""

        if os.path.isfile(IPCAT_SQLITE_FILE):
            with sqlite3.connect(IPCAT_SQLITE_FILE, isolation_level=None) as conn:
                cursor = conn.cursor()
                try:
                    _ = addr_to_int(address)
                    cursor.execute("SELECT name FROM ranges WHERE start_int <= ? AND end_int >= ?", (_, _))
                    _ = cursor.fetchone()
                    retval = str(_[0]) if _ else retval
                except Exception:
                    raise ValueError("[x] invalid IP address '%s'" % address)

                _ipcat_dynamic_cache[address] = retval

    return retval

def worst_asns(address):
    if not address:
        return None

    try:
        _ = addr_to_int(address)
        for prefix, mask, name in WORST_ASNS.get(address.split('.')[0], {}):
            if _ & mask == prefix:
                return name
    except (IndexError, ValueError):
        pass

    return None

def cdn_ip(address):
    if not address:
        return False

    try:
        _ = addr_to_int(address)
        for prefix, mask in CDN_RANGES.get(address.split('.')[0], {}):
            if _ & mask == prefix:
                return True
    except (IndexError, ValueError):
        pass

    return False

def bogon_ip(address):
    if not address:
        return False

    try:
        _ = addr_to_int(address)
        for prefix, mask in BOGON_RANGES.get(address.split('.')[0], {}):
            if _ & mask == prefix:
                return True
    except (IndexError, ValueError):
        pass

    if address in BOGON_IPS:
        return True

    return False

def check_sudo():
    """
    Checks for root privileges
    """

    check = None

    if not IS_WIN:
        if getattr(os, "geteuid"):
            check = os.geteuid() == 0
    else:
        import ctypes
        check = ctypes.windll.shell32.IsUserAnAdmin()

    return check

PUBLISHED_PEM_FINGERPRINTS = {
    "9395629637a4fc48290286313b60ae26fb6bdcd8018db45894ab54c273d1a2c3": "private key",
    "2905a63fd3399bda47f286dac449edf734cdbdbe51b5d7d5cf241d2f74ea58c1": "certificate",
}   # NOTE: DER-SHA256 of the two blocks of misc/server.pem as of commit f32c991^ ('git show f32c991^:misc/server.pem' reproduces them)

def uses_published_key(pem_path, fingerprints=None):
    """
    Whether an SSL_PEM file contains the key (or certificate) that Maltrail itself published.

    misc/server.pem shipped inside this repository from February 2020 until commit f32c991. A
    private key in a public repository is a private key everybody has: TLS with it protects
    nothing, and anybody can impersonate the server or decrypt a session. Deleting the file from
    the tree does NOT undo that - the blob is still in this repository's git history, in every
    clone, fork and mirror of it, and above all in the /etc/maltrail directories of operators who
    copied it years ago. That last group is the only one a code change can help, so the check is
    on the file the server is actually told to use, by content rather than by name (renaming it,
    or generating a fresh certificate around the same key, changes nothing about who has it).

    Compared as SHA-256 over the DER inside each PEM block, so whitespace, block order, extra
    blocks and the surrounding filename are all irrelevant.

    Returns True (refuse), False (fine), or None when the file cannot be read or parsed.
    """

    PUBLISHED = fingerprints if fingerprints is not None else PUBLISHED_PEM_FINGERPRINTS

    try:
        import base64
        import hashlib

        with open(pem_path, "rb") as f:
            content = f.read().decode(UNICODE_ENCODING, errors="replace")

        found = False

        for match in re.finditer(r"-----BEGIN ([A-Z0-9 ]+)-----(.*?)-----END \1-----", content, re.S):
            try:
                der = base64.b64decode(re.sub(r"\s+", "", match.group(2)))
            except Exception:
                continue
            if hashlib.sha256(der).hexdigest() in PUBLISHED:
                found = True

        return found
    except Exception:
        return None

def extract_zip(filename, path=None):
    _ = zipfile.ZipFile(filename, 'r')
    _.extractall(path)

def get_regex(items):
    r"""
    Builds a single compact regular expression matching any of the given items (via a
    character trie, collapsing common prefixes and contiguous character ranges)

    >>> get_regex(["cat", "car"])
    'ca(?:r|t)'
    >>> get_regex(["ab", "ac", "ad"])
    'a(?:b|c|d)'
    >>> get_regex([str(_) for _ in range(10)])
    '(?:\\d)'
    >>> get_regex(["1.2.3.4"])
    '1\\.2\\.3\\.4'
    """

    head = {}

    for item in sorted(items):
        current = head
        for char in item:
            if char not in current:
                current[char] = {}
            current = current[char]
        current[""] = {}

    def process(current):
        if not current:
            return ""

        if not any(current[_] for _ in current):
            if len(current) > 1:
                items = []
                previous = None
                start = None
                for _ in sorted(current) + [chr(65535)]:
                    if previous is not None:
                        if ord(_) == ord(previous) + 1:
                            pass
                        else:
                            if start != previous:
                                if start == '0' and previous == '9':
                                    items.append(r"\d")
                                else:
                                    items.append("%s-%s" % (re.escape(start), re.escape(previous)))
                            else:
                                items.append(re.escape(previous))
                            start = _
                    if start is None:
                        start = _
                    previous = _

                return ("[%s]" % "".join(items)) if len(items) > 1 or '-' in items[0] else "".join(items)
            else:
                return re.escape(list(current.keys())[0])
        else:
            return ("(?:%s)" if len(current) > 1 else "%s") % ('|'.join("%s%s" % (re.escape(_), process(current[_])) for _ in sorted(current))).replace('|'.join(str(_) for _ in xrange(10)), r"\d")

    regex = process(head).replace(r"(?:|\d)", r"\d?")

    return regex

def check_connection():
    return len(retrieve_content(CHECK_CONNECTION_URL) or "") > 0

def check_whitelisted(trail):
    if trail in WHITELIST:
        return True

    # Only range-match a BARE IPv4 trail. addr_to_int() reads just the first 4 dotted parts, so the old
    # `trail[0].isdigit()` guard let a domain like "10.0.0.1.evil.com" be range-matched as 10.0.0.1 -> a
    # whitelist bypass / detection-evasion vector (register <whitelisted-ip-prefix>.attacker.com to be ignored).
    if trail and re.match(r"\A(?:\d{1,3}\.){3}\d{1,3}\Z", trail):
        try:
            _ = addr_to_int(trail)
            for prefix, mask in WHITELIST_RANGES:
                if _ & mask == prefix:
                    return True
        except (IndexError, ValueError):
            pass

    return False

def spamhaus_drop(address):
    """Is this address inside a Spamhaus DROP netblock?

    Same job as worst_asns() and deliberately the same shape - an ANNOTATION for /check_ip, never a
    trail. DROP is 1,700-odd netblocks covering millions of addresses; as trails they would either
    match nothing (a "1.2.3.0/24" key is not what an address renders as) or, expanded, bury the
    trail set under space nobody observed doing anything.

    Bisect over sorted intervals rather than the leading-octet buckets worst_asns() uses: DROP
    prefixes reach /12, which would land in sixteen buckets, and the v6 list has no leading octet.
    """

    if not address:
        return False

    try:
        if ':' in address:
            ranges = DROP6_RANGES
            value = int.from_bytes(socket.inet_pton(socket.AF_INET6, address), "big")
        else:
            ranges = DROP_RANGES
            value = addr_to_int(address)
    except (AttributeError, IndexError, ValueError, socket.error):
        return False

    if not ranges:
        return False

    index = bisect.bisect_right(ranges, (value, float("inf"))) - 1
    return index >= 0 and ranges[index][0] <= value <= ranges[index][1]

def build_trails_regex(trails):
    """
    (Re)builds the named-group alternation regex (TrailsDict._regex) of wildcard/regex static trails used by the
    sensor's packet matching fallback. Must run on every (re)load - including worker process trail reloads -
    otherwise wildcard/regex trail detection is silently lost after the first reload (TrailsDict.update() copies
    over the empty _regex of a freshly loaded TrailsDict).
    """

    if trails._frozen is not None:      # keys are gone; _regex was already built before finalize()
        return trails

    regex = ""

    for trail in trails:
        if "static" in trails[trail][1]:
            if re.search(r"[\].][*+]|\[[a-z0-9_.\-]+\]", trail, re.I):
                try:
                    re.compile(trail)
                except re.error:
                    continue
                if re.escape(trail) != trail:
                    index = regex.count("(?P<g")
                    if index < 100:  # Reference: https://stackoverflow.com/questions/478458/python-regular-expressions-with-more-than-100-groups
                        regex += "|(?P<g%s>%s)" % (index, trail)

    trails._regex = regex.strip('|')

    return trails

def load_trails(quiet=False, freeze=False):
    if not quiet:
        print("[i] loading trails...")

    retval = TrailsDict()

    if os.path.isfile(config.TRAILS_FILE):
        try:
            with open(config.TRAILS_FILE, "r") as f:
                reader = csv.reader(f, delimiter=',', quotechar='\"')
                for row in reader:
                    if row and len(row) == 3:
                        trail, info, reference = row
                        if not check_whitelisted(trail):
                            retval[trail] = (info, reference)

        except Exception as ex:
            sys.exit("[!] something went wrong during trails file read '%s' ('%s')" % (config.TRAILS_FILE, ex))

    build_trails_regex(retval)

    if freeze:
        retval.finalize()   # compact to the read-only hash-array form (drops key strings); see TrailsDict.finalize()

    if not quiet:
        _ = len(retval)
        try:
            _ = '{0:,}'.format(_)
        except Exception:
            pass
        print("[i] %s trails loaded" % _)

    return retval

def trails_bin_path():
    return "%s.bin" % config.TRAILS_FILE

def _trails_bin_from_items(items_factory, n_hint, out_path):
    """
    Core builder shared by build_trails_bin() (reads the CSV) and write_trails_bin() (reads an in-memory dict).
    'items_factory' is a callable returning a fresh iterator of (trail, info, reference); 'n_hint' is an upper
    bound on the entry count (for table sizing).

    It streams the trails STRAIGHT into the open-addressing arrays - it never materialises the whole (hash, index)
    set nor retains the trail key strings, so its peak RSS is ~10x below building the set in a dict first. The
    interned (info, reference) pairs and the wildcard regex are tiny. A 64-bit hash collision between two distinct
    trails (never observed across 1.6M real trails) is handled exactly: on detection, the table is rebuilt once
    with the colliding hashes excluded and those keys kept verbatim in a side dict - so the read path stays simple.
    """

    pairs = {}
    pair_list = []
    regex = ""
    regex_groups = 0
    hi, lo, val, mask, cap = trailsbin.new_table(n_hint)
    colliding = set()
    n = 0

    for trail, info, reference in items_factory():
        if "static" in reference and _WILDCARD_TRAIL_REGEX.search(trail) and regex_groups < 100:  # mirror build_trails_regex()
            try:
                re.compile(trail)
            except re.error:
                pass
            else:
                if re.escape(trail) != trail:
                    regex += "|(?P<g%s>%s)" % (regex_groups, trail)
                    regex_groups += 1

        pair = (info, reference)
        pi = pairs.get(pair)
        if pi is None:
            pi = len(pair_list)
            pairs[pair] = pi
            pair_list.append(pair)

        if trailsbin.table_insert(hi, lo, val, mask, trailsbin.stable_hash(trail), pi):
            n += 1
        else:
            colliding.add(trailsbin.stable_hash(trail))

    collisions = {}
    if colliding:
        # rare: rebuild the table from scratch with the colliding hashes left out, and keep those keys verbatim
        hi, lo, val, mask, cap = trailsbin.new_table(n_hint)
        n = 0
        for trail, info, reference in items_factory():
            h = trailsbin.stable_hash(trail)
            if h in colliding:
                collisions[trail] = (info, reference)
            elif trailsbin.table_insert(hi, lo, val, mask, h, pairs[(info, reference)]):
                n += 1

    trailsbin.write_table(out_path, cap, n, hi, lo, val, pair_list, collisions, regex.strip('|'))

def build_trails_bin(csv_path=None, bin_path=None):
    """
    Builds the binary trail store from the trails CSV (applying the runtime whitelist, exactly like load_trails).
    Streams directly into the table (low peak RSS); the caller that owns this build runs it - worker processes
    never do, they only mmap the result.
    """

    csv_path = csv_path or config.TRAILS_FILE
    bin_path = bin_path or trails_bin_path()

    def _items():
        with open(csv_path, "r") as f:
            for row in csv.reader(f, delimiter=',', quotechar='\"'):
                if row and len(row) == 3 and not check_whitelisted(row[0]):
                    yield row[0], row[1], row[2]

    line_count = 0          # cheap upper bound for table sizing (no retention)
    with open(csv_path, "r") as f:
        for _ in f:
            line_count += 1

    _trails_bin_from_items(_items, line_count, bin_path)

def write_trails_bin(trails, bin_path=None):
    """
    Builds the binary trail store from an already-built in-memory TrailsDict (the one update_trails just wrote to
    the CSV), reusing that dict so no extra full copy is materialised.
    """

    bin_path = bin_path or trails_bin_path()

    def _items():
        for key in trails:
            value = trails[key]
            yield key, value[0], value[1]

    _trails_bin_from_items(_items, len(trails), bin_path)

def trails_bin_stale(bin_path=None):
    bin_path = bin_path or trails_bin_path()
    if not os.path.isfile(config.TRAILS_FILE):
        return False
    if not os.path.isfile(bin_path):
        return True
    try:
        return os.stat(bin_path).st_mtime < os.stat(config.TRAILS_FILE).st_mtime
    except OSError:
        return True

def load_trails_mmap(quiet=False):
    """
    Returns a TrailsDict backed by the shared, memory-mapped binary store. If the bin is missing or older than the
    CSV it is (re)built from the CSV first - under an flock so that, of all the processes that may call this at
    once, exactly one builds and the rest wait then mmap the finished file.
    """

    bin_path = trails_bin_path()
    retval = TrailsDict()

    if not os.path.isfile(config.TRAILS_FILE):
        retval.finalize()       # no trails file yet -> empty (in-heap) frozen store
        return retval

    def _rebuild_locked(force=False):
        lock_handle = open("%s.lock" % bin_path, "w")
        try:
            fcntl.flock(lock_handle, fcntl.LOCK_EX)
            if force or trails_bin_stale(bin_path):     # re-check now that we hold the lock
                build_trails_bin(config.TRAILS_FILE, bin_path)
        finally:
            try:
                fcntl.flock(lock_handle, fcntl.LOCK_UN)
            except Exception:
                pass
            lock_handle.close()

    if trails_bin_stale(bin_path):
        _rebuild_locked()

    try:
        retval.open_mmap(bin_path)
    except Exception:
        # corrupt / truncated / foreign-format (e.g. an older magic after an upgrade) bin -> rebuild and retry once
        _rebuild_locked(force=True)
        retval.open_mmap(bin_path)

    if not quiet:
        _ = len(retval)
        try:
            _ = '{0:,}'.format(_)
        except Exception:
            pass
        print("[i] %s trails loaded (shared)" % _)

    return retval

def get_text(value):
    """
    Returns the textual (unicode) representation of the given value

    >>> get_text("abc")
    'abc'
    >>> get_text(b"abc")
    'abc'
    """

    retval = value

    if isinstance(value, bytes):
        retval = value.decode(UNICODE_ENCODING, errors="replace")

    return retval

def get_ex_message(ex):
    """
    Returns the human-readable message carried by an exception

    >>> get_ex_message(Exception("boom"))
    'boom'
    >>> get_ex_message(ValueError("bad value"))
    'bad value'
    """

    retval = None

    if getattr(ex, "message", None):
        retval = ex.message
    elif getattr(ex, "msg", None):
        retval = ex.msg
    elif getattr(ex, "args", None):
        for candidate in ex.args[::-1]:
            if isinstance(candidate, str):
                retval = candidate
                break

    if retval is None:
        retval = str(ex)

    return retval

def is_local(address):
    """
    Checks if the given IPv4 address belongs to a local/private range

    >>> is_local("127.0.0.1")
    True
    >>> is_local("10.0.0.5")
    True
    >>> is_local("192.168.1.1")
    True
    >>> is_local("8.8.8.8")
    False
    >>> is_local(None)
    False
    >>> is_local("172.20.5.5")
    True
    >>> is_local("172.31.255.255")
    True
    >>> is_local("172.15.0.1")
    False
    >>> is_local("172.32.0.1")
    False
    """

    # 172.16.0.0/12 -> second octet 16-31. (The old [13][0-9] matched 10-19,30-39: it flagged 172.20-29 public
    # and 172.10-15/172.32-39 local.)
    return re.search(r"\A(127|10|172\.(1[6-9]|2[0-9]|3[01])|192\.168)\.", address or "") is not None

def patch_parser(parser):
    # Dirty hack to display longer options without breaking into two lines
    if hasattr(parser, "formatter"):
        def _(self, *args):
            retval = parser.formatter._format_option_strings(*args)
            if len(retval) > MAX_HELP_OPTION_LENGTH:
                retval = ("%%.%ds.." % (MAX_HELP_OPTION_LENGTH - parser.formatter.indent_increment)) % retval
            return retval.capitalize()

        parser.formatter._format_option_strings = parser.formatter.format_option_strings
        parser.formatter.format_option_strings = type(parser.formatter.format_option_strings)(_, parser)
    else:
        def _format_action_invocation(self, action):
            retval = self.__format_action_invocation(action)
            if len(retval) > MAX_HELP_OPTION_LENGTH:
                retval = ("%%.%ds.." % (MAX_HELP_OPTION_LENGTH - self._indent_increment)) % retval
            return retval.capitalize()

        parser.formatter_class.__format_action_invocation = parser.formatter_class._format_action_invocation
        parser.formatter_class._format_action_invocation = _format_action_invocation
