#!/usr/bin/env python

"""
Copyright (c) 2014-2026 Maltrail developers (https://github.com/stamparm/maltrail/)
See the file 'LICENSE' for copying permission
"""

from __future__ import print_function

import csv
import gzip
import io
import os
import re
import sqlite3
import sys
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
from core.settings import WORST_ASNS
from core.trailsdict import TrailsDict
from thirdparty import six
from thirdparty.six.moves import urllib as _urllib

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

def retrieve_content(url, data=None, headers=None):
    """
    Retrieves page content from given URL
    """

    try:
        # NOTE: percent-encode spaces only in the query string (chars after the first '?'); if there's no '?', encode them all.
        # (Was an O(n^2) char-by-char comprehension that recomputed url.find('?') for every character.)
        _ = url.find('?')
        url = url.replace(' ', "%20") if _ == -1 else url[:_ + 1] + url[_ + 1:].replace(' ', "%20")
        req = _urllib.request.Request(url, data, headers or {"User-agent": USER_AGENT, "Accept-encoding": "gzip, deflate"})
        resp = _urllib.request.urlopen(req, timeout=TIMEOUT)
        retval = resp.read()
        encoding = resp.headers.get("Content-Encoding")
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

        if url.startswith("https://") and isinstance(retval, str) and "handshake failure" in retval:
            return retrieve_content(url.replace("https://", "http://"), data, headers)

        # NOTE: on failure return EMPTY, never the error body/message. Feeds gate parsing on a `__check__` substring and a
        # few have no guard at all - returning an HTTP error page / WAF block / timeout string here let that text get parsed
        # into bogus "trails" (feed poisoning). Empty content makes feeds yield nothing and update_trails report the failure.
        retval = b""

    retval = retval or b""

    if six.PY3 and isinstance(retval, bytes):
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
                for _ in sorted(current) + [six.unichr(65535)]:
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

    if trail and trail[0].isdigit():
        try:
            _ = addr_to_int(trail)
            for prefix, mask in WHITELIST_RANGES:
                if _ & mask == prefix:
                    return True
        except (IndexError, ValueError):
            pass

    return False

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

def _trails_bin_from_items(items, out_path):
    """
    Core builder shared by build_trails_bin() (reads the CSV) and write_trails_bin() (reads an in-memory dict).
    'items' yields (trail, info, reference). Computes the wildcard alternation regex, interns the (info, reference)
    pairs, detects (and keeps verbatim) the rare hash collisions, and writes the file atomically (tmp + rename).
    """

    pairs = {}
    pair_list = []
    by_hash = {}
    regex = ""
    regex_groups = 0

    for trail, info, reference in items:
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

        h = trailsbin.stable_hash(trail)
        existing = by_hash.get(h)
        if existing is None:
            by_hash[h] = (trail, pi)
        elif type(existing) is list:                # already a collision bucket
            for j in xrange(len(existing)):
                if existing[j][0] == trail:         # duplicate key row -> overwrite, not a collision
                    existing[j] = (trail, pi)
                    break
            else:
                existing.append((trail, pi))
        elif existing[0] == trail:                  # duplicate key row -> overwrite
            by_hash[h] = (trail, pi)
        else:                                       # genuine hash collision between two distinct trails
            by_hash[h] = [existing, (trail, pi)]

    entries = []
    collisions = {}
    for h, entry in by_hash.items():
        if type(entry) is list:
            for trail, pi in entry:
                collisions[trail] = pair_list[pi]
        else:
            entries.append((h, entry[1]))

    tmp_path = "%s.%d.tmp" % (out_path, os.getpid())
    trailsbin.write_bin(tmp_path, entries, pair_list, collisions, regex.strip('|'))
    (os.replace if hasattr(os, "replace") else os.rename)(tmp_path, out_path)  # atomic publish

def build_trails_bin(csv_path=None, bin_path=None):
    """
    Builds the binary trail store from the trails CSV (applying the runtime whitelist, exactly like load_trails).
    Transiently materialises the full hash set, so the caller that owns the (already-paid) build peak runs this -
    worker processes never do; they only mmap the result.
    """

    csv_path = csv_path or config.TRAILS_FILE
    bin_path = bin_path or trails_bin_path()

    def _items():
        with open(csv_path, "r") as f:
            for row in csv.reader(f, delimiter=',', quotechar='\"'):
                if row and len(row) == 3 and not check_whitelisted(row[0]):
                    yield row[0], row[1], row[2]

    _trails_bin_from_items(_items(), bin_path)

def write_trails_bin(trails, bin_path=None):
    """
    Builds the binary trail store from an already-built in-memory TrailsDict (the one update_trails just wrote to
    the CSV), reusing that dict so no additional build peak is incurred.
    """

    bin_path = bin_path or trails_bin_path()

    def _items():
        for key in trails:
            value = trails[key]
            yield key, value[0], value[1]

    _trails_bin_from_items(_items(), bin_path)

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

    if six.PY2:
        try:
            retval = str(retval)
        except Exception:
            pass
    else:
        if isinstance(value, six.binary_type):
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
            if isinstance(candidate, six.string_types):
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
    """

    return re.search(r"\A(127|10|172\.[13][0-9]|192\.168)\.", address or "") is not None

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
