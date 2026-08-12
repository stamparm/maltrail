#!/usr/bin/env python

"""
Copyright (c) 2014-2026 Maltrail developers (https://github.com/stamparm/maltrail/)
See the file 'LICENSE' for copying permission
"""

import datetime
import glob
import gzip
import hashlib
import io
import json
import mimetypes
import os
import re
import select
import socket
import subprocess
import sys
import threading
import time
import traceback

from core.addr import addr_to_int
from core.addr import int_to_addr
from core.addr import make_mask
from core.addr import resolve_address
from core.attribdict import AttribDict
from core import log as _log
from core import trailsbin
from core.common import get_regex
from core.common import trails_bin_path
from core.common import ipcat_lookup
from core.common import worst_asns
from core.compat import xrange
from core.enums import HTTP_HEADER
from core.geo import ip_to_country
from core.geo import event_country
from core import meta
from core.settings import config
from core.settings import CONTENT_EXTENSIONS_EXCLUSIONS
from core.settings import DATE_FORMAT
from core.settings import DISABLED_CONTENT_EXTENSIONS
from core.settings import DISPOSED_NONCES
from core.settings import HTML_DIR
from core.settings import ROOT_DIR
from core.settings import HUNT_MAX_DAYS
from core.settings import HUNT_TIME_BUDGET
from core.settings import HUNT_MAX_SAMPLES
from core.settings import HUNT_MIN_QUERY
from core.settings import HTTP_TIME_FORMAT
from core.settings import IS_WIN
from core.settings import MAX_NOFILE
from core.settings import NAME
from core.settings import PING_RESPONSE
from core.settings import SESSION_COOKIE_NAME
from core.settings import SESSION_COOKIE_FLAG_SAMESITE
from core.settings import SESSION_EXPIRATION_HOURS
from core.settings import SESSION_ID_LENGTH
from core.settings import SESSIONS
from core.settings import UNAUTHORIZED_SLEEP_TIME
from core.settings import CEF_FORMAT
from core.settings import HOSTNAME
from core.settings import UNICODE_ENCODING
from core.settings import VERSION
import http.server as _BaseHTTPServer
import http.client as _http_client
import socketserver as _socketserver
import urllib.error
import urllib.parse
import urllib.request
import urllib.response
import urllib as _urllib

try:
    # Reference: https://bugs.python.org/issue7980
    # Reference: http://code-trick.com/python-bug-attribute-error-_strptime/
    import _strptime
except ImportError:
    pass

try:
    import resource
    resource.setrlimit(resource.RLIMIT_NOFILE, (MAX_NOFILE, MAX_NOFILE))
except Exception:
    pass

_fail2ban_cache = None
_fail2ban_key = None
# Memory-mapped trail store for /check, opened once and re-opened when trails.csv.bin changes.
# ACCESS_READ, so the table stays a shared mapping rather than becoming a heap copy in the server:
# the point of answering single-key lookups here is that it costs no memory to do so.
_trails_bin = None
_trails_bin_stamp = None
_trails_bin_lock = threading.Lock()

def _trails_bin_handles():
    """Read handles for the memory-mapped trail store, or None when there is no usable one.

    Re-opened when the file changes, so a trail update is picked up without restarting the server.
    A missing or half-written .bin is not an error worth failing a request over - the sensor
    rebuilds it on its own timer - so the caller gets None and reports the store as unavailable.
    """
    global _trails_bin, _trails_bin_stamp

    path = trails_bin_path()
    try:
        stamp = os.stat(path)
        stamp = (stamp.st_mtime, stamp.st_size)
    except OSError:
        return None

    if _trails_bin is not None and _trails_bin_stamp == stamp:
        return _trails_bin

    with _trails_bin_lock:
        if _trails_bin is not None and _trails_bin_stamp == stamp:
            return _trails_bin
        try:
            handles = trailsbin.open_bin(path)
        except Exception:
            return None
        previous = _trails_bin
        _trails_bin, _trails_bin_stamp = handles, stamp
        if previous is not None:
            try:
                previous["mmap"].close()
            except Exception:
                pass
        return _trails_bin


_blacklist_cache = None
_blacklist_key = None
_version_cache = None
_counts_cache = {}  # NOTE: per daily-log event count keyed by filepath -> (mtime, size, count); past-day logs are immutable so they're read once, not on every poll
_geo_cache = {}  # NOTE: per daily-log country aggregation keyed by filepath -> running {mtime,size,offset,counts,mapped,unmapped}; grows INCREMENTALLY (only new bytes are scanned) so a live/growing current-day log stays cheap
_geo_lock = threading.Lock()  # NOTE: the incremental read-modify-write must be serialized (concurrent /geo for the same day would otherwise double-count)
MAX_REQUEST_THREADS = 100       # concurrent request handlers; excess connections get 503 without a thread
MAX_LIVE_STREAMS = 30           # of those, how many may be held open by /live at once

def _limit(value, default):
    """Coerce a configured concurrency limit, falling back to `default`.

    Both defaults suit one operator on one dashboard. A large console wants more streams, and a
    small appliance wants fewer threads than 100 x 1 MB of stack; neither should have to patch
    the source. Anything unparsable or <= 0 falls back to the compiled-in default rather than
    disabling the limit, because "0" here would mean "refuse every request".

    Takes the value, not the option name: tests/test_options.py finds configuration reads by
    scanning for the literal attribute access, so a lookup through a variable would be invisible
    to it and the option could drift out of maltrail.conf unnoticed.
    """

    try:
        value = int(value)
    except (TypeError, ValueError):
        return default
    return value if value > 0 else default
_live_streams = [0]
_live_streams_lock = threading.Lock()

def _live_slot():
    """Claim one of the /live budget, or return False.

    A /live stream is held open for as long as the tab is, so it occupies a request thread
    indefinitely - and the thread cap counts it like any other handler. Without a separate,
    smaller budget the streams simply eat the pool: 120 open dashboards saturated all 100 slots
    and every ordinary request got a 503. That is a cheaper denial of service than the one the
    cap was added to prevent, and it needs nothing but a browser.

    Capping streams below the thread cap keeps at least MAX_REQUEST_THREADS - MAX_LIVE_STREAMS
    handlers available for ordinary traffic. A refused stream is answered 204, which the frontend
    already treats as "no SSE here" and falls back to Range polling (see openSSE in main.js), so
    the dashboard stays live either way - just at poll latency.
    """

    with _live_streams_lock:
        if _live_streams[0] >= _limit(getattr(config, "MAX_LIVE_STREAMS", None), MAX_LIVE_STREAMS):
            return False
        _live_streams[0] += 1
        return True

def _live_release():
    with _live_streams_lock:
        _live_streams[0] = max(0, _live_streams[0] - 1)

LOGIN_FAILURE_THRESHOLD = 5     # consecutive failures from one IP before its attempts are refused unevaluated
_login_failures = {}            # client IP -> [consecutive failures, epoch the window expires]
_login_failures_lock = threading.Lock()
MAX_LOGIN_FAILURE_ENTRIES = 4096

def _login_refused(ip):
    """Has `ip` failed enough times in a row, recently enough, to have its attempts refused?

    Replaces an unconditional `time.sleep(UNAUTHORIZED_SLEEP_TIME)` on the failure path. That
    sleep delayed the RESPONSE without delaying the ATTEMPT: 200 concurrent requests were all
    evaluated, each parking a request thread for five seconds. Measured on the stock
    configuration, 200 concurrent failed logins took the server from 1 thread to 172 and 600
    took it to 316, unauthenticated and from one host. Capping threads alone does not fix it -
    100 handlers each sleeping five seconds saturates the cap just as well, and then legitimate
    users get the 503s.

    A THRESHOLD, not a blanket cooldown. Refusing on the first failure would have been strictly
    worse than the sleep it replaced: the reporting interface is routinely reached through one
    NAT address, so one fat-fingered password would lock out everyone behind it, and an attacker
    could hold an office out of its own console by failing a login every five seconds. Five
    consecutive failures is well clear of ordinary mistyping and still bounds a brute-force run
    to five guesses per window, against the unbounded concurrent evaluation it replaces.

    A successful login clears the counter, so a user who mistypes twice and then succeeds carries
    nothing forward.
    """

    now = time.time()
    with _login_failures_lock:
        if len(_login_failures) >= MAX_LOGIN_FAILURE_ENTRIES:   # bounded: the key is attacker-chosen
            for key in [_ for _, entry in _login_failures.items() if entry[1] <= now]:
                del _login_failures[key]
            if len(_login_failures) >= MAX_LOGIN_FAILURE_ENTRIES:
                return True     # saturated -> refuse rather than grow; fail closed
        entry = _login_failures.get(ip)
        if entry is None:
            return False
        if now >= entry[1]:     # window elapsed -> the streak is over
            del _login_failures[ip]
            return False
        return entry[0] >= LOGIN_FAILURE_THRESHOLD

def _login_failed(ip):
    """Count one failure for `ip` and (re)start its window."""

    now = time.time()
    with _login_failures_lock:
        entry = _login_failures.get(ip)
        count = entry[0] + 1 if entry is not None and now < entry[1] else 1
        _login_failures[ip] = [count, now + UNAUTHORIZED_SLEEP_TIME]

def _login_succeeded(ip):
    """Clear `ip`'s failure streak: the credentials were right, so it was not an attack."""

    with _login_failures_lock:
        _login_failures.pop(ip, None)

CUSTOM_TRAIL_MARKER = b",(custom)"  # the reference column of a trails-file row sourced from trails/custom
_public_trails_cache = None  # the trails file with every custom row removed, for the last _public_trails_key
_public_trails_key = None    # (mtime, size) of the trails file the cached copy was derived from
_reference_cache = {}  # trail -> (reference, source_relpath): on-demand static-trails scan result; bounded
_REFERENCE_CACHE_MAX = 8192
_REFERENCE_TIME_BUDGET = 2.0
_STATIC_TRAILS_DIR = os.path.join(ROOT_DIR, "trails", "static")

def _public_trails(content, key):
    """`content` with every trails-file row that came from trails/custom removed.

    Row-wise on bytes rather than through csv: the file is millions of rows and this runs on a
    polled endpoint. The reference column is written unquoted by update_trails() (csv.writer with
    QUOTE_MINIMAL, and "(custom)" contains no delimiter or quote), so a custom row is exactly one
    that ends with ",(custom)" - and the caller already checked that at least one exists before
    paying for the split.

    Cached on `key`, the (mtime, size) of the very handle `content` was read from - NOT a fresh
    stat() here. update_trails() swaps the file atomically underneath a reader, so stat-ing again
    could pair the OLD bytes with the NEW file's key and pin a stale trail set in the cache until
    the update after next.
    """

    global _public_trails_cache
    global _public_trails_key

    if key is not None and _public_trails_key == key and _public_trails_cache is not None:
        return _public_trails_cache

    # splitlines(True) keeps each row's terminator, so the rows that survive are byte-identical to
    # the ones the sensor would have parsed from the file itself.
    retval = b"".join(line for line in content.splitlines(True) if not line.rstrip(b"\r\n").endswith(CUSTOM_TRAIL_MARKER))

    if key is not None:
        _public_trails_cache = retval
        _public_trails_key = key

    return retval

def _lookup_trail_reference(trail):
    """On demand, find which static-trails pile a trail sits in and return that pile's '# Reference:' header
    (the real source citation, e.g. an abuse.ch URL) plus the file. No index / no stored bytes: the static
    trail files ship with the code, so they're scanned only when an analyst actually asks - result cached.
    The reference is per-PILE (a '# Reference:' line then its trails), so we locate the trail's line and take
    the nearest preceding header. Bounded by a time budget so a miss can't stall the request."""
    cached = _reference_cache.get(trail)
    if cached is not None:
        return cached
    result = ("", "")
    try:
        # the event/stored trail is a NORMALISED form of the file line (the loader strips the scheme and a leading
        # dot, and adds/trims a trailing slash), so match the core tolerantly: optional http(s):// prefix, optional
        # leading dot, optional trailing slash - still anchored at a line boundary so it's not a loose substring.
        core = trail.rstrip("/")
        core_b = core if isinstance(core, bytes) else core.encode("latin-1", "replace")
        needle = re.compile(b"(?m)^(?:https?://)?\\.?" + re.escape(core_b) + b"(?:[/\\s#]|$)")
        deadline = time.time() + _REFERENCE_TIME_BUDGET
        found = False
        for root, _dirs, files in os.walk(_STATIC_TRAILS_DIR):   # os.walk: py2/py3-safe (glob recursive is py3-only)
            if found or time.time() > deadline:
                break
            for name in files:
                if not (name.endswith(".txt") or name.endswith(".csv")):
                    continue
                try:
                    with open(os.path.join(root, name), "rb") as f:
                        data = f.read()
                except (OSError, IOError):
                    continue
                m = needle.search(data)
                if m:
                    ref = ""
                    rp = data.rfind(b"\n# Reference:", 0, m.start())   # nearest pile header above the match
                    if rp >= 0:
                        end = data.find(b"\n", rp + 1)
                        parts = data[rp + 1:end if end >= 0 else len(data)].split(b":", 1)
                        if len(parts) == 2:
                            ref = parts[1].strip().decode("latin-1", "replace")
                    result = (ref, os.path.relpath(os.path.join(root, name), ROOT_DIR).replace(os.sep, "/"))
                    found = True
                    break
    except Exception:
        if config.SHOW_DEBUG:
            traceback.print_exc()
    if len(_reference_cache) < _REFERENCE_CACHE_MAX:
        _reference_cache[trail] = result
    return result
_statics_cache = None  # NOTE: (5-min-bucket, latest-static-trail-date); avoids re-globbing the static malware dir on every page render
MAX_POST_SIZE = 10 * 1024 * 1024  # NOTE: cap request body (real Maltrail POSTs are tiny); rejects absurd Content-Length up-front to bound memory
REQUEST_TIMEOUT = 60  # NOTE: per-socket-operation timeout; frees worker threads stuck on stalled/slowloris connections (active, progressing clients are unaffected)

_sessions_lock = threading.Lock()  # NOTE: SESSIONS is mutated from worker threads (ThreadingMixIn)
_sessions_reaped = [0]             # last-reap timestamp (list holder to avoid a global statement)
SESSION_REAP_PERIOD = 60

def _reap_sessions():
    """
    Drops expired sessions (and closes any file handle they pinned). Time-gated so it sweeps at most once a minute
    regardless of request rate. Without this, sessions that are created and never revisited live forever - a slow
    memory leak that also leaks a file descriptor per session that opened an event-log range handle.
    """

    now = time.time()
    if now - _sessions_reaped[0] < SESSION_REAP_PERIOD:
        return
    _sessions_reaped[0] = now

    with _sessions_lock:
        for _ in list(SESSIONS.keys()):
            session = SESSIONS.get(_)
            if session is not None and session.expiration <= now:
                handle = getattr(session, "range_handle", None)
                if handle is not None:
                    try:
                        handle.close()
                    except Exception:
                        pass
                SESSIONS.pop(_, None)


class _ConcatenatedFiles(io.RawIOBase):
    """
    Read-only seekable view over the concatenation of several files.

    Used to serve multi-day event logs without loading them (potentially many GBs) into memory at once.
    Wrap in io.BufferedReader for efficient read()/readline()/iteration.
    """

    def __init__(self, paths):
        io.RawIOBase.__init__(self)
        self._paths = list(paths)
        self._sizes = [os.path.getsize(_) for _ in self._paths]
        self._total = sum(self._sizes)
        self._pos = 0
        self._index = -1
        self._handle = None

    def readable(self):
        return True

    def seekable(self):
        return True

    def seek(self, offset, whence=io.SEEK_SET):
        if whence == io.SEEK_SET:
            self._pos = offset
        elif whence == io.SEEK_CUR:
            self._pos += offset
        elif whence == io.SEEK_END:
            self._pos = self._total + offset
        return self._pos

    def tell(self):
        return self._pos

    def readinto(self, b):
        if self._pos >= self._total:
            return 0

        pos, index = self._pos, 0
        while index < len(self._sizes) and pos >= self._sizes[index]:
            pos -= self._sizes[index]
            index += 1

        if index >= len(self._paths):
            return 0

        if index != self._index:
            if self._handle is not None:
                self._handle.close()
            self._handle = open(self._paths[index], "rb")
            self._index = index

        self._handle.seek(pos)
        chunk = self._handle.read(min(len(b), self._sizes[index] - pos))
        b[:len(chunk)] = chunk
        self._pos += len(chunk)
        return len(chunk)

    def close(self):
        if self._handle is not None:
            self._handle.close()
            self._handle = None
        io.RawIOBase.close(self)


COUNTS_PROBE_SIZE = 32 * 1024  # bytes read per sampling point when estimating a large log's event count
COUNTS_PROBES = 8              # number of evenly-spaced sampling points

def estimate_event_count(filepath, size):
    """
    Approximate the number of events (= lines) in a daily log WITHOUT reading it whole - a busy day's log can be
    100s of MB. Small logs are counted exactly. Large logs are sampled at COUNTS_PROBES points spread evenly across
    the file; the file size is divided by the mean line length derived from the samples.

    Event-line length is not uniform (trail/info/reference field widths vary, and the log's composition drifts over
    the day), so the previous head-only sample was biased - and that bias got multiplied by ~(size / sample). Spacing
    the probes evenly by BYTE offset makes sampled_lines/sampled_bytes an unbiased estimator of the whole file's
    lines-per-byte regardless of that drift; more probes just lower the variance. Reads stay O(1) - at most
    COUNTS_PROBES * COUNTS_PROBE_SIZE regardless of file size. Rounded to the nearest 100 so repeated polls of a
    growing current-day log don't jitter.
    """

    if size <= COUNTS_PROBES * COUNTS_PROBE_SIZE:
        with open(filepath, "rb") as f:
            return f.read().count(b'\n')

    sampled_bytes, sampled_lines = 0, 0
    step = (size - COUNTS_PROBE_SIZE) / float(COUNTS_PROBES - 1)  # first probe at 0, last ending at EOF
    with open(filepath, "rb") as f:
        for i in range(COUNTS_PROBES):
            f.seek(int(i * step))
            chunk = f.read(COUNTS_PROBE_SIZE)
            sampled_bytes += len(chunk)
            sampled_lines += chunk.count(b'\n')

    mean_line = 1.0 * sampled_bytes / max(1, sampled_lines)  # max(1,..) guards the degenerate no-newline case
    return int(round(size / mean_line / 100.0) * 100)

def _geo_home():
    """Optional HOME_LAT/HOME_LON from config as {"lat","lon"} for the attack map's arcs, or None (air-gap can't auto-locate)."""

    try:
        lat, lon = config.get("HOME_LAT"), config.get("HOME_LON")
        if lat not in (None, "") and lon not in (None, ""):
            return {"lat": float(lat), "lon": float(lon)}
    except Exception:
        pass
    return None

_cleared_cache = (None, {})

def _cleared_sources():
    """IPs an operator has marked as remediated, and the moment they were marked.

    `LOG_DIR/cleared.txt`, one entry per line:

        10.13.13.37                       # cleared as of this file's last modification
        10.13.13.99 2026-08-11 09:30:00   # cleared as of an explicit moment

    Both /blacklist and /fail2ban are derived from the CURRENT DAY's events, so a host that was
    flagged once stays on the list until midnight. Until now the only way off it was
    USER_WHITELIST, which is permanent - it also suppresses every FUTURE detection for that host,
    which is the opposite of what someone who has just cleaned a machine wants (issue #19053).

    Clearing is time-bounded instead: events BEFORE the mark are ignored, and any event after it
    puts the host straight back on the list. Remediate, clear, and the host is still watched.

    Cached on the file's (mtime, size), so an edit takes effect on the next request.
    """
    global _cleared_cache

    path = os.path.join(config.LOG_DIR, "cleared.txt")
    try:
        stat = os.stat(path)
        stamp = (stat.st_mtime, stat.st_size)
    except OSError:
        _cleared_cache = (None, {})
        return {}

    if _cleared_cache[0] == stamp:
        return _cleared_cache[1]

    retval = {}
    try:
        with open(path) as f:
            for line in f:
                line = re.sub(r"\s*#.*", "", line).strip()
                if not line:
                    continue
                parts = line.split(None, 1)
                ip = parts[0]
                when = stat.st_mtime
                if len(parts) > 1:
                    try:
                        when = time.mktime(time.strptime(parts[1].strip()[:19], "%Y-%m-%d %H:%M:%S"))
                    except ValueError:
                        pass                 # unparseable stamp -> fall back to the file's mtime
                retval[ip] = when
    except (OSError, IOError):
        return {}

    _cleared_cache = (stamp, retval)
    return retval


def _event_precedes_clear(line, ip, cleared):
    """Should this event line be ignored because `ip` was cleared after it happened?

    The timestamp is only parsed for an IP that is actually in the cleared map, which is empty on
    virtually every deployment - so this costs nothing on the common path.

    >>> _event_precedes_clear('"2026-08-11 09:00:00.0" s 10.0.0.5 1 2.2.2.2 2 TCP IP x y z', "10.0.0.5", {})
    False
    """

    when = cleared.get(ip)
    if when is None:
        return False
    match = re.match(r'\A"([^"]{19})', line)
    if not match:
        return False
    try:
        return time.mktime(time.strptime(match.group(1), "%Y-%m-%d %H:%M:%S")) <= when
    except ValueError:
        return False


def _sanitize_auth_field(value):
    """Make a client-supplied value safe to put in a log line.

    The username on a failed login is whatever the attacker POSTed. Written verbatim into a
    syslog record it is a log-injection vector: an embedded newline lets them append a line of
    their choosing - including a convincing "Accepted password for admin from ..." - to the very
    audit trail meant to catch them. Control characters are replaced rather than dropped so the
    attempt is still visible, and the length is bounded so one request cannot flood the log.

    >>> _sanitize_auth_field("admin" + chr(10) + "Accepted password for root")
    'admin?Accepted password for root'
    >>> _sanitize_auth_field(None)
    '-'
    >>> _sanitize_auth_field("")
    '-'
    >>> len(_sanitize_auth_field("A" * 500))
    64
    """

    if not value:
        return '-'
    value = "".join(c if ' ' <= c < '\x7f' else '?' for c in str(value))
    return value[:64] or '-'


def start_httpd(address=None, port=None, join=False, pem=None):
    """
    Starts HTTP server
    """

    # Thread stacks are RESERVED address space, and glibc's default is 8 MB - so a cap of
    # MAX_REQUEST_THREADS handlers quietly authorises ~800 MB of it. Bounding the thread count
    # without bounding the per-thread reservation leaves the dimension that containers and
    # `ulimit -v` actually enforce unbounded; the suite's own 1.2 GB cap caught this.
    # An HTTP handler here parses a request, reads a file and writes a response - it does not
    # recurse - so 1 MB is ample and brings the same 100 threads under ~100 MB.
    try:
        threading.stack_size(1024 * 1024)
    except (ValueError, RuntimeError):
        pass    # platform refused the size; the default is merely wasteful, not wrong

    class ThreadingServer(_socketserver.ThreadingMixIn, _BaseHTTPServer.HTTPServer):
        daemon_threads = True  # long-lived SSE (/live) streams must not block server shutdown

        # ThreadingMixIn spawns one thread per connection with no ceiling, so concurrency was
        # whatever a client chose to open. A bounded pool turns "the server falls over" into
        # "some requests get 503", which is a service decision rather than an outage. The
        # rejection is written from the ACCEPT thread: refusing a connection must not itself
        # cost the thread the cap exists to protect.
        _active = 0
        _active_lock = threading.Lock()

        def process_request(self, request, client_address):
            with ThreadingServer._active_lock:
                if ThreadingServer._active >= _limit(getattr(config, "MAX_REQUEST_THREADS", None), MAX_REQUEST_THREADS):
                    over = True
                else:
                    ThreadingServer._active += 1
                    over = False

            if over:
                try:
                    request.sendall(b"HTTP/1.1 503 Service Unavailable\r\nConnection: close\r\n"
                                    b"Retry-After: 1\r\nContent-Length: 0\r\n\r\n")
                except Exception:
                    pass
                self.shutdown_request(request)
                return

            try:
                _socketserver.ThreadingMixIn.process_request(self, request, client_address)
            except Exception:
                # the handler thread never started, so nothing will decrement for us
                with ThreadingServer._active_lock:
                    ThreadingServer._active -= 1
                raise

        def process_request_thread(self, request, client_address):
            try:
                _socketserver.ThreadingMixIn.process_request_thread(self, request, client_address)
            finally:
                with ThreadingServer._active_lock:
                    ThreadingServer._active -= 1

        def server_bind(self):
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            _BaseHTTPServer.HTTPServer.server_bind(self)

        def finish_request(self, *args, **kwargs):
            try:
                _BaseHTTPServer.HTTPServer.finish_request(self, *args, **kwargs)
            except Exception:
                if config.SHOW_DEBUG:
                    traceback.print_exc()

    class SSLThreadingServer(ThreadingServer):
        def __init__(self, server_address, pem, HandlerClass):
            import ssl

            ThreadingServer.__init__(self, server_address, ReqHandler)
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(pem, pem)
            self.socket = ctx.wrap_socket(socket.socket(self.address_family, self.socket_type), server_side=True)
            self.server_bind()
            self.server_activate()

        def shutdown_request(self, request):
            try:
                request.shutdown()
            except Exception:
                pass

    class ReqHandler(_BaseHTTPServer.BaseHTTPRequestHandler):
        timeout = REQUEST_TIMEOUT  # NOTE: StreamRequestHandler applies this as a socket timeout -> stalled connections drop instead of pinning a thread forever

        def do_GET(self):
            path, query = self.path.split('?', 1) if '?' in self.path else (self.path, "")
            params = {}
            content = None
            skip = False

            if hasattr(self, "data"):
                params.update(_urllib.parse.parse_qs(self.data))

            if query:
                params.update(_urllib.parse.parse_qs(query))

            for key in params:
                if params[key]:
                    params[key] = params[key][-1]

            if path == '/':
                path = "index.html"

            path = path.strip('/')
            extension = os.path.splitext(path)[-1].lower()

            splitpath = path.split('/', 1)
            # dispatch ONLY to the designated URL endpoints. The old `hasattr(self, "_<seg>")` also matched internal /
            # display helpers (_version, _logo, _assetver, _tzoffset, _statics, _format, _build_netfilters, _filter_events)
            # whose signature is NOT (self, params), so e.g. "GET /version" -> self._version(params) -> uncaught TypeError
            # (request crash) reachable by any client. Endpoints are an explicit allowlist, not "any _-prefixed method".
            if splitpath[0] in ("login", "logout", "whoami", "check_ip", "check", "trails", "ping", "blacklist", "fail2ban", "events", "live", "counts", "geo", "hunt", "meta", "reference"):
                if len(splitpath) > 1:
                    params["subpath"] = splitpath[1]
                content = getattr(self, "_%s" % splitpath[0])(params)

            else:
                path = path.replace('/', os.path.sep)
                path = os.path.abspath(os.path.join(HTML_DIR, path)).strip()

                if not os.path.isfile(path) and os.path.isfile("%s.html" % path):
                    path = "%s.html" % path

                if any((config.IP_ALIASES,)) and self.path.split('?')[0] == "/js/main.js":
                    with open(path, 'r') as f:
                        content = f.read()
                    # Build the JS object via json.dumps so alias keys/values are properly escaped: a stray '"' used to
                    # produce invalid JS (-> main.js SyntaxError -> dead frontend), and a '\' was interpreted as a regex
                    # backreference in the replacement string (-> re.error -> the main.js request crashed). The lambda
                    # replacement keeps re.sub from re-interpreting backslashes in the (now JSON-escaped) value.
                    _aliases = {}
                    for _ in config.IP_ALIASES:
                        _parts = _.split(':', 1)
                        _aliases[_parts[0].strip()] = _parts[-1].strip()
                    _replacement = "var IP_ALIASES = %s;" % json.dumps(_aliases)
                    content = re.sub(r"\bvar IP_ALIASES =.+", lambda _m: _replacement, content)

                if ".." not in os.path.relpath(path, HTML_DIR) and os.path.isfile(path) and (extension not in DISABLED_CONTENT_EXTENSIONS or os.path.split(path)[-1] in CONTENT_EXTENSIONS_EXCLUSIONS):
                    mtime = time.gmtime(os.path.getmtime(path))
                    if_modified_since = self.headers.get(HTTP_HEADER.IF_MODIFIED_SINCE)

                    if if_modified_since and extension not in (".htm", ".html"):
                        try:
                            if_modified_since = [_ for _ in if_modified_since.split(';') if _.upper().endswith("GMT")][0]
                            not_modified = time.mktime(mtime) <= time.mktime(time.strptime(if_modified_since, HTTP_TIME_FORMAT))
                        except (IndexError, ValueError, OverflowError):
                            not_modified = False   # malformed/non-standard If-Modified-Since (client-controlled header) -> serve full content instead of crashing the whole request with an uncaught IndexError/ValueError
                        if not_modified:
                            self.send_response(_http_client.NOT_MODIFIED)
                            self.send_header(HTTP_HEADER.CONNECTION, "close")
                            skip = True

                    if not skip:
                        if not content:
                            with open(path, "rb") as f:
                                content = f.read()
                        last_modified = time.strftime(HTTP_TIME_FORMAT, mtime)
                        self.send_response(_http_client.OK)
                        self.send_header(HTTP_HEADER.CONNECTION, "close")
                        self.send_header(HTTP_HEADER.CONTENT_TYPE, mimetypes.guess_type(path)[0] or "application/octet-stream")
                        self.send_header(HTTP_HEADER.LAST_MODIFIED, last_modified)

                        # For CSP policy directives see: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/
                        self.send_header(HTTP_HEADER.CONTENT_SECURITY_POLICY, "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src * blob:; script-src 'self' 'unsafe-eval' https://stat.ripe.net; frame-src *; object-src 'none'; block-all-mixed-content;")

                        if os.path.basename(path) == "index.html":
                            # demo.js exists for the public static demo, and main.js turns DEMO on
                            # from its mere presence (`typeof window.getDemoCSV === "function"`).
                            # So if this strip ever misses, a real operator is served FABRICATED
                            # events and nothing says so - the dashboard looks entirely normal.
                            #
                            # The old pattern required the exact shipped spelling: double quotes,
                            # one space, no attributes. `src='js/demo.js'` or a space before the
                            # `>` slipped straight through. Match the tag however it is written,
                            # then CHECK, and drop the whole line if anything survived - failing
                            # closed here costs a static demo page, failing open costs trust in
                            # every number on the screen.
                            content = re.sub(br'\s*<script\b[^>]*\bsrc\s*=\s*["\']?[^"\'>]*\bdemo\.js[^>]*>\s*</script\s*>',
                                             b'', content, flags=re.I)
                            if b"demo.js" in content:
                                content = b"\n".join(_ for _ in content.split(b"\n") if b"demo.js" not in _)

                        if extension not in (".htm", ".html"):
                            self.send_header(HTTP_HEADER.EXPIRES, "Sun, 17-Jan-2038 19:14:07 GMT")        # Reference: http://blog.httpwatch.com/2007/12/10/two-simple-rules-for-http-caching/
                            self.send_header(HTTP_HEADER.CACHE_CONTROL, "max-age=3600, must-revalidate")  # Reference: http://stackoverflow.com/a/5084555
                        else:
                            self.send_header(HTTP_HEADER.CACHE_CONTROL, "no-cache")

                else:
                    self.send_response(_http_client.NOT_FOUND)
                    self.send_header(HTTP_HEADER.CONNECTION, "close")
                    # HTML-escape the reflected request path: unescaped it allowed (a) reflected HTML injection and
                    # (b) a "<!name!>" path to survive into the token-substitution loop below and invoke an internal
                    # self._<name>() handler -> e.g. "/<!login!>" calls _login() with no args -> uncaught TypeError
                    _safe_path = self.path.split('?')[0].replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                    content = '<!DOCTYPE html><html lang="en"><head><title>404 Not Found</title></head><body><h1>Not Found</h1><p>The requested URL %s was not found on this server.</p></body></html>' % _safe_path

            if content is not None:
                if isinstance(content, str):
                    content = content.encode(UNICODE_ENCODING)

                for match in re.finditer(b"<\\!(\\w+)\\!>", content):
                    name = match.group(1).decode(UNICODE_ENCODING)
                    # only substitute the known no-arg DISPLAY tokens. Without this allowlist the loop would
                    # getattr(self, "_<name>") for ANY token, so a "<!login!>"/"<!events!>"-style token reaching
                    # `content` (a reflected path, an injected IP_ALIASES value, ...) would invoke a request handler
                    # that needs `params` -> uncaught TypeError. Tokens are a fixed template vocabulary, not a method dispatch.
                    if name.lower() not in ("version", "logo", "assetver", "tzoffset", "statics"):
                        continue
                    _ = getattr(self, "_%s" % name.lower(), None)
                    if _:
                        content = self._format(content, **{name: _()})

                if "gzip" in self.headers.get(HTTP_HEADER.ACCEPT_ENCODING, ""):
                    self.send_header(HTTP_HEADER.CONTENT_ENCODING, "gzip")
                    _ = io.BytesIO()
                    compress = gzip.GzipFile("", "w+b", 9, _)
                    compress._stream = _
                    compress.write(content)
                    compress.flush()
                    compress.close()
                    content = compress._stream.getvalue()

                self.send_header(HTTP_HEADER.CONTENT_LENGTH, str(len(content)))

            self.end_headers()

            try:
                if content:
                    self.wfile.write(content)

                self.wfile.flush()
            except Exception:
                pass

        def do_POST(self):
            try:
                length = int(self.headers.get(HTTP_HEADER.CONTENT_LENGTH) or 0)
            except (TypeError, ValueError):
                length = 0
            if length > MAX_POST_SIZE:  # NOTE: reject oversized bodies before buffering them
                self.send_response(_http_client.REQUEST_ENTITY_TOO_LARGE)
                self.send_header(HTTP_HEADER.CONNECTION, "close")
                self.end_headers()
                return
            data = self.rfile.read(length).decode(UNICODE_ENCODING, "replace") if length > 0 else ""   # tolerate invalid UTF-8 in a (pre-auth, client-controlled) POST body instead of raising an uncaught UnicodeDecodeError out of do_POST; matches the defensive decoding used elsewhere
            data = _urllib.parse.unquote_plus(data)
            self.data = data
            self.do_GET()

        def get_session(self):
            retval = None
            cookie = self.headers.get(HTTP_HEADER.COOKIE)

            _reap_sessions()

            if cookie:
                match = re.search(r"%s\s*=\s*([^;]+)" % SESSION_COOKIE_NAME, cookie)
                if match:
                    session = match.group(1)
                    _ = SESSIONS.get(session)  # fetch once: a concurrent reap/delete must not turn check-then-fetch into a KeyError
                    if _ is not None:
                        if _.client_ip != self.client_address[0]:
                            pass
                        elif _.expiration > time.time():
                            retval = _
                        else:
                            SESSIONS.pop(session, None)

            if retval is None and not config.USERS:
                retval = AttribDict({"username": "?"})

            return retval

        def delete_session(self):
            cookie = self.headers.get(HTTP_HEADER.COOKIE)

            if cookie:
                match = re.search(r"%s\s*=\s*([^;]+)" % SESSION_COOKIE_NAME, cookie)   # stop at ';' like get_session; the old greedy "(.+)" swallowed trailing cookies ("sessid=abc; theme=dark") -> wrong id -> logout never invalidated the server-side session
                if match:
                    session = match.group(1)
                    SESSIONS.pop(session, None)

        def version_string(self):
            return "%s/%s" % (NAME, self._version())

        def end_headers(self):
            if not hasattr(self, "_headers_ended"):
                _BaseHTTPServer.BaseHTTPRequestHandler.end_headers(self)
                self._headers_ended = True

        def log_message(self, format, *args):
            return

        def finish(self):
            try:
                _BaseHTTPServer.BaseHTTPRequestHandler.finish(self)
            except Exception:
                if config.SHOW_DEBUG:
                    traceback.print_exc()

        def _version(self):
            global _version_cache

            if _version_cache is None:
                version = VERSION

                try:
                    with open(os.path.join(os.path.dirname(__file__), "settings.py"), 'r') as f:
                        for line in f:
                            match = re.search(r'VERSION = "([^"]*)', line)
                            if match:
                                version = match.group(1)
                                break
                except Exception:
                    pass

                _version_cache = version

            return _version_cache

        def _statics(self):
            global _statics_cache
            key = int(time.time()) // 300  # NOTE: static trails change ~daily (on update); a 5-min TTL avoids globbing+stat-ing hundreds of files on every page render
            if _statics_cache is not None and _statics_cache[0] == key:
                return _statics_cache[1]

            files = glob.glob(os.path.join(os.path.dirname(__file__), "..", "trails", "static", "malware", "*.txt"))
            if not files:
                return ""
            latest = max(files, key=os.path.getmtime)
            content = "/%s" % datetime.datetime.fromtimestamp(os.path.getmtime(latest)).strftime(DATE_FORMAT)
            _statics_cache = (key, content)
            return content

        def _logo(self):
            if config.HEADER_LOGO:
                retval = config.HEADER_LOGO
            else:
                retval = '<img src="images/mlogo.png" style="width: 25px">altrail'

            return retval

        def _assetver(self):
            # cache-busting token = newest mtime of the cacheable assets, so updated JS/CSS land immediately
            # (index.html is served no-cache, so a changed token forces the browser to refetch the new files)
            try:
                latest = 0
                for rel in ("js/main.js", "css/main.css"):
                    p = os.path.join(HTML_DIR, rel)
                    if os.path.isfile(p):
                        latest = max(latest, int(os.path.getmtime(p)))
                return str(latest or int(time.time()))
            except Exception:
                return self._version()

        def _tzoffset(self):
            # minutes EAST of UTC for the server's local time. Maltrail writes log timestamps in sensor-local time,
            # so the frontend uses this to render correct "x ago" / spans regardless of the viewer's timezone.
            try:
                if time.daylight and time.localtime().tm_isdst > 0:
                    offset_seconds = -time.altzone
                else:
                    offset_seconds = -time.timezone
                return str(offset_seconds // 60)
            except Exception:
                return "0"

        def _format(self, content, **params):
            if content:
                for key, value in params.items():
                    content = content.replace(b"<!%s!>" % key.encode(UNICODE_ENCODING), value.encode(UNICODE_ENCODING))

            return content

        def _login(self, params):
            valid = False

            # Threshold check BEFORE any credential work: see _login_refused. A hammering IP gets
            # the same 401 it would have got anyway, immediately, and its guess is not evaluated.
            if _login_refused(self.client_address[0]):
                self.send_response(_http_client.UNAUTHORIZED)
                self.send_header(HTTP_HEADER.CONNECTION, "close")
                self.send_header(HTTP_HEADER.CONTENT_TYPE, "text/plain")
                self.__log_auth(False, params.get("username"))
                return "Login failed"

            if params.get("username") and params.get("hash") and params.get("nonce"):
                if params.get("nonce") not in DISPOSED_NONCES:
                    DISPOSED_NONCES[params.get("nonce")] = True
                    for entry in (config.USERS or []):
                        entry = re.sub(r"\s", "", entry)
                        # maxsplit=3: the netfilter (last field) may itself contain ':' (e.g. an IPv6 "::" = "all"), which
                        # a plain split(':') would over-split into >4 parts -> ValueError that crashes EVERY login. Skip a
                        # genuinely malformed line (wrong field count) rather than letting one bad USERS entry lock everyone out.
                        parts = entry.split(':', 3)
                        if len(parts) != 4:
                            continue
                        username, stored_hash, uid, netfilter = parts

                        try:
                            uid = int(uid)
                        except ValueError:
                            uid = None

                        if username == params.get("username"):
                            try:
                                if params.get("hash") == hashlib.sha256((stored_hash.strip() + params.get("nonce")).encode(UNICODE_ENCODING)).hexdigest():
                                    valid = True
                                    break
                            except Exception:
                                if config.SHOW_DEBUG:
                                    traceback.print_exc()

            if valid:
                _login_succeeded(self.client_address[0])
                _ = os.urandom(SESSION_ID_LENGTH)
                session_id = _.hex() if hasattr(_, "hex") else _.encode("hex")
                expiration = time.time() + 3600 * SESSION_EXPIRATION_HOURS

                self.send_response(_http_client.OK)
                self.send_header(HTTP_HEADER.CONNECTION, "close")

                cookie = "%s=%s; expires=%s; path=/; HttpOnly" % (SESSION_COOKIE_NAME, session_id, time.strftime(HTTP_TIME_FORMAT, time.gmtime(expiration)))
                if config.USE_SSL:
                    cookie += "; Secure"
                if SESSION_COOKIE_FLAG_SAMESITE:
                    cookie += "; SameSite=strict"
                self.send_header(HTTP_HEADER.SET_COOKIE, cookie)

                if netfilter in ("", '*', "::", "0.0.0.0/0"):
                    netfilters = None
                else:
                    addresses = set()
                    netmasks = set()

                    for item in set(re.split(r"[;,]", netfilter)):
                        item = item.strip()
                        if '/' in item:
                            # only accept a well-formed IPv4 CIDR (dotted-quad prefix + mask 0..32). Otherwise skip it:
                            # a mask > 32 made make_mask() do `1 << (32-bits)` -> ValueError (negative shift), and an
                            # IPv6/garbage prefix made addr_to_int() raise -> both crashed the login request uncaught.
                            # (Skipping also keeps such junk out of `netmasks`, where _filter_events would re-crash on it.)
                            prefix, _, bits = item.partition('/')
                            prefix = prefix.strip()
                            if bits.isdigit() and int(bits) <= 32 and re.match(r"\A\d+\.\d+\.\d+\.\d+\Z", prefix):
                                if int(bits) >= 16:
                                    mask = make_mask(int(bits))
                                    lower = addr_to_int(prefix) & mask   # mask the prefix: a non-aligned CIDR (e.g. 10.0.5.0/16) must expand from the network base (10.0.0.0), else the low part of the subnet is silently excluded
                                    upper = lower | (0xffffffff ^ mask)
                                    while lower <= upper:
                                        addresses.add(int_to_addr(lower))
                                        lower += 1
                                else:
                                    netmasks.add(item)
                        elif '-' in item:
                            # require exactly two IPv4 endpoints + a bounded span (mirrors the /16 cap on the CIDR
                            # branch above); a malformed (multi-dash / non-IP) or oversized range is skipped, never
                            # crashed on the tuple-unpack nor expanded into a multi-million-address set (OOM/hang)
                            _ = [x.strip() for x in item.split('-')]
                            if len(_) == 2 and all(re.match(r"\A\d+\.\d+\.\d+\.\d+\Z", x) for x in _):
                                lower, upper = addr_to_int(_[0]), addr_to_int(_[1])
                                if 0 <= upper - lower <= 65536:
                                    while lower <= upper:
                                        addresses.add(int_to_addr(lower))
                                        lower += 1
                        elif re.search(r"\d+\.\d+\.\d+\.\d+", item):
                            addresses.add(item)

                    netfilters = netmasks
                    if addresses:
                        netfilters.add(get_regex(addresses))

                SESSIONS[session_id] = AttribDict({"username": username, "uid": uid, "netfilters": netfilters, "mask_custom": bool(config.ENABLE_MASK_CUSTOM and uid is not None and uid >= 1000), "expiration": expiration, "client_ip": self.client_address[0]})
            else:
                _login_failed(self.client_address[0])
                self.send_response(_http_client.UNAUTHORIZED)
                self.send_header(HTTP_HEADER.CONNECTION, "close")

            self.send_header(HTTP_HEADER.CONTENT_TYPE, "text/plain")
            content = "Login %s" % ("success" if valid else "failed")

            self.__log_auth(valid, params.get("username"))

            return content

        def __log_auth(self, valid, username):
            """Record a login attempt locally and, if configured, at a remote collector.

            Brute force against the reporting interface is the one attack on Maltrail that
            Maltrail could not see. Locally this was already written in sshd's shape
            ("Accepted/Failed password for <user> from <ip> port <port>"), which journald and
            rsyslog pick up and fail2ban can parse; it is now also forwarded to SYSLOG_SERVER
            and LOGSTASH_SERVER so a SIEM sees it without shell access to the box (issue #19080).

            The local write no longer forks. It used to run `logger` through
            subprocess.check_output on EVERY attempt and wait for it - one process spawn per
            login, on the exact code path an attacker hammers. The stdlib syslog module writes
            to the same auth facility through a socket with no child process at all.
            """
            username = _sanitize_auth_field(username)
            ip, port = self.client_address[0], self.client_address[1]
            outcome = "Accepted" if valid else "Failed"
            message = "%s password for %s from %s port %s" % (outcome, username, ip, port)

            if not IS_WIN:
                try:
                    import syslog
                    syslog.openlog("%s[%d]" % (NAME.lower(), os.getpid()), 0, syslog.LOG_AUTH)
                    syslog.syslog(syslog.LOG_INFO, message)
                except Exception:
                    if config.SHOW_DEBUG:
                        traceback.print_exc()

            try:
                if getattr(config, "SYSLOG_SERVER", None):
                    extension = "src=%s spt=%s duser=%s outcome=%s" % (ip, port, _log._cef_escape(username, True), outcome.lower())
                    payload = CEF_FORMAT.format(
                        syslog_time=time.strftime("%b %d %H:%M:%S", time.localtime()), host=HOSTNAME,
                        device_vendor=NAME, device_product="server", device_version=VERSION,
                        signature_id="auth", name=_log._cef_escape("login %s" % ("success" if valid else "failure")),
                        severity=1 if valid else 2, extension=extension).encode(UNICODE_ENCODING)
                    for endpoint in _log._endpoints(config.SYSLOG_SERVER):
                        _log._send_datagram(endpoint, payload)

                if getattr(config, "LOGSTASH_SERVER", None):
                    payload = json.dumps({"timestamp": int(time.time()), "sensor": HOSTNAME, "type": "auth",
                                          "outcome": "success" if valid else "failure", "username": username,
                                          "src_ip": ip, "src_port": port}).encode(UNICODE_ENCODING)
                    for endpoint in _log._endpoints(config.LOGSTASH_SERVER):
                        _log._send_datagram(endpoint, payload)
            except Exception:
                if config.SHOW_DEBUG:
                    traceback.print_exc()

        def _logout(self, params):
            self.delete_session()
            self.send_response(_http_client.FOUND)
            self.send_header(HTTP_HEADER.CONNECTION, "close")
            self.send_header(HTTP_HEADER.LOCATION, "/")

        def _whoami(self, params):
            session = self.get_session()
            username = session.username if session else ""

            self.send_response(_http_client.OK)
            self.send_header(HTTP_HEADER.CONNECTION, "close")
            self.send_header(HTTP_HEADER.CONTENT_TYPE, "text/plain")

            return username

        def _check_ip(self, params):
            session = self.get_session()

            if session is None:
                self.send_response(_http_client.UNAUTHORIZED)
                self.send_header(HTTP_HEADER.CONNECTION, "close")
                return None

            self.send_response(_http_client.OK)
            self.send_header(HTTP_HEADER.CONNECTION, "close")
            self.send_header(HTTP_HEADER.CONTENT_TYPE, "text/plain")

            try:
                result_worst = worst_asns(params.get("address"))
                if result_worst:
                    result_ipcat = result_worst
                else:
                    _ = (ipcat_lookup(params.get("address")) or "").lower().split(' ')
                    result_ipcat = _[1] if _[0] == 'the' else _[0]
                payload = json.dumps({"ipcat": result_ipcat, "worst_asns": str(result_worst is not None).lower(), "country": ip_to_country(params.get("address")) or ""})  # country from the local RIR table (works air-gapped)
                # NOTE: only wrap in a JSONP callback if it is a bare JS identifier. The callback is reflected into a
                # script-executable body, so an unvalidated value (e.g. "alert(1)//") is a JSONP-XSS vector. The current
                # frontend uses fetch() (no callback), so nothing legitimate needs an arbitrary callback here.
                callback = params.get("callback")
                if callback and re.match(r"\A[\w.$]{1,64}\Z", callback):
                    return "%s(%s)" % (callback, payload)
                return payload
            except Exception:
                if config.SHOW_DEBUG:
                    traceback.print_exc()

        def _meta(self, params):
            # Condensed observable store lookup: "have I ever seen this domain/ip, since when, how often".
            # O(1) PK lookup against meta.sqlite. Returns the aggregate row, or {} if never observed.
            session = self.get_session()

            if session is None:
                self.send_response(_http_client.UNAUTHORIZED)
                self.send_header(HTTP_HEADER.CONNECTION, "close")
                return None

            # Per-user network scope, and the one endpoint where it cannot be applied: the
            # observables table is (observable, flags, first_seen, last_seen, count) with no
            # network dimension at all, so there is nothing to filter on. An answer here is
            # necessarily about the WHOLE estate - "something, somewhere, talked to this, N times
            # since T" - which is exactly what a restricted analyst is not entitled to.
            #
            # Refused rather than answered with {}: an empty body would read as "never observed",
            # which is a different and worse thing to tell an analyst than "not yours to ask".
            # Unrestricted users (and every deployment without USERS) are unaffected.
            if getattr(session, "netfilters", None) is not None:
                self.send_response(_http_client.FORBIDDEN)
                self.send_header(HTTP_HEADER.CONNECTION, "close")
                return None

            self.send_response(_http_client.OK)
            self.send_header(HTTP_HEADER.CONNECTION, "close")
            self.send_header(HTTP_HEADER.CONTENT_TYPE, "application/json")

            try:
                observable = (params.get("observable") or "").strip()
                row = meta.lookup(observable) if observable else None
                if row and row.get("kind") == "ip":
                    # automatic enrichment: same category/reputation/country the /check_ip tooltip uses (air-gap safe).
                    # wrapped so an enrichment hiccup never breaks the first-seen/count payload.
                    try:
                        worst = worst_asns(observable)
                        if worst:
                            cat = worst
                        else:
                            _ = (ipcat_lookup(observable) or "").lower().split(' ')
                            cat = _[1] if _[0] == 'the' else _[0]
                        row["category"] = cat or ""
                        row["reputation"] = "bad" if worst else ""
                        row["country"] = ip_to_country(observable) or ""
                    except Exception:
                        pass
                payload = json.dumps(row if row else {})
                callback = params.get("callback")
                if callback and re.match(r"\A[\w.$]{1,64}\Z", callback):   # same JSONP-XSS guard as _check_ip
                    return "%s(%s)" % (callback, payload)
                return payload
            except Exception:
                if config.SHOW_DEBUG:
                    traceback.print_exc()

        def _reference(self, params):
            # On-demand source citation for a trail: the '# Reference:' header of the static-trails pile it
            # belongs to (e.g. the abuse.ch/feed URL that flagged it). Scanned from the shipped trail files
            # only when asked, so nothing is stored per-trail and it works whether or not a sensor is co-located.
            session = self.get_session()

            if session is None:
                self.send_response(_http_client.UNAUTHORIZED)
                self.send_header(HTTP_HEADER.CONNECTION, "close")
                return None

            self.send_response(_http_client.OK)
            self.send_header(HTTP_HEADER.CONNECTION, "close")
            self.send_header(HTTP_HEADER.CONTENT_TYPE, "application/json")

            try:
                trail = (params.get("trail") or "").strip()
                if not trail or len(trail) > 256:
                    return json.dumps({})
                ref, src = _lookup_trail_reference(trail)
                payload = json.dumps({"reference": ref, "source": src})
                callback = params.get("callback")
                if callback and re.match(r"\A[\w.$]{1,64}\Z", callback):   # same JSONP-XSS guard as _check_ip/_meta
                    return "%s(%s)" % (callback, payload)
                return payload
            except Exception:
                if config.SHOW_DEBUG:
                    traceback.print_exc()

        def _trails(self, params):
            """The whole trail set, as CSV. This is how a sensor pulls from UPDATE_SERVER.

            Custom trails are stripped for anyone who is not entitled to see them. update_trails()
            merges trails/custom into the SAME file as the public sources (core/update.py), so
            serving the file verbatim handed every caller the operator's private indicators -
            internal hostnames, internal addresses, an ongoing investigation's IOCs - while
            /check and /events go to real trouble to mask exactly those. It was the one place the
            masking was simply absent.

            Entitlement is the rule /check already uses, so there is one definition of "may see
            custom trails" rather than two: a session that is not mask_custom. With USERS unset
            get_session() returns the anonymous session, so an unauthenticated deployment - which
            is the usual UPDATE_SERVER setup - still gets the complete set and nothing changes
            for it.
            """

            session = self.get_session()
            reveal_custom = session is not None and not getattr(session, "mask_custom", False)

            self.send_response(_http_client.OK)
            self.send_header(HTTP_HEADER.CONNECTION, "close")
            self.send_header(HTTP_HEADER.CONTENT_TYPE, "text/plain")

            # NOTE: TRAILS_FILE may not exist yet (fresh server with USE_SERVER_UPDATE_TRAILS off, or a first
            # update that produced no trails). A bare open() would raise -> 500 + traceback, and a sensor pulling
            # from UPDATE_SERVER would fail. Return an empty body instead; the sensor then keeps its current trails.
            if not os.path.isfile(config.TRAILS_FILE):
                return b""

            with open(config.TRAILS_FILE, "rb") as f:
                content = f.read()
                try:    # from THIS handle, so the cache key always describes the bytes just read
                    _ = os.fstat(f.fileno())
                    key = (_.st_mtime, _.st_size)
                except OSError:
                    key = None

            if reveal_custom or CUSTOM_TRAIL_MARKER not in content:
                return content

            return _public_trails(content, key)

        def _check(self, params):
            """Is one observable in the trail set? GET /check?q=<domain|ip|url>

            Requested for years (issue #17742) so that other tooling can ask Maltrail about a
            single indicator instead of downloading and grepping the whole set.

            Unauthenticated for the PUBLIC trail set only. /trails already serves that to anyone
            who asks - it is how a sensor pulls from UPDATE_SERVER - so a single-key lookup over
            static and feed trails discloses strictly less than what is already on the same port.
            (Contrast /blacklist, gated because it reads the EVENT LOG and reveals which of your
            own hosts were flagged. Trail data is the input; event data is the finding.)

            CUSTOM trails are the exception and require a session that is allowed to see them.
            They are the operator's own indicators, not public data, and the server already
            treats their names as sensitive: ENABLE_MASK_CUSTOM (default on) redacts them from
            authenticated non-admin users in /events. An unauthenticated endpoint that answered
            "yes, that internal hostname is in your private list" would bypass a control this
            server deliberately applies to logged-in analysts - so it does not answer, and a
            custom-only match is reported exactly as a miss rather than as a masked hit, since
            confirming membership IS the disclosure here.

            Reads through the memory-mapped trail store, so the answer costs no heap: the table
            is the same shared mapping the sensor uses, not a copy loaded into this process.
            """
            self.send_response(_http_client.OK)
            self.send_header(HTTP_HEADER.CONNECTION, "close")
            self.send_header(HTTP_HEADER.CONTENT_TYPE, "application/json")

            query = (params.get("q") or params.get("query") or "").strip().lower()

            # Bounded, and no wildcard characters: this is an exact-key lookup, not a search.
            if not query or len(query) > 256:
                return json.dumps({"query": query[:256], "found": False, "error": "missing or oversized 'q'"})

            try:
                handles = _trails_bin_handles()
            except Exception:
                if config.SHOW_DEBUG:
                    traceback.print_exc()
                handles = None

            if handles is None:
                return json.dumps({"query": query, "found": False, "error": "trail store unavailable"})

            # A URL is checked as host/path and then as the bare host, which is how the sensor
            # matches URL trails; a domain additionally matches when any PARENT domain is listed,
            # the same walk _check_domain_member() does, so a subdomain of a listed domain is
            # reported rather than missed.
            candidates = []
            probe = re.sub(r"\A[a-z]{2,10}://", "", query).rstrip('/')
            if probe:
                candidates.append(probe)
            host = probe.split('/')[0]
            if host and host != probe:
                candidates.append(host)
            if host and '.' in host and not re.search(r"\A\d+\.\d+\.\d+\.\d+\Z", host):
                parts = host.split('.')
                for i in xrange(1, len(parts) - 1):
                    candidates.append('.'.join(parts[i:]))

            # Admins and, when no USERS are configured, everyone; the same rule /events applies.
            session = self.get_session()
            reveal_custom = session is not None and not getattr(session, "mask_custom", False)

            seen = set()
            for candidate in candidates:
                if candidate in seen:
                    continue
                seen.add(candidate)
                result = trailsbin.lookup(handles, candidate)
                if result:
                    if "(custom)" in (result[1] or "") and not reveal_custom:
                        continue
                    return json.dumps({"query": query, "found": True, "trail": candidate,
                                       "info": result[0], "reference": result[1]})

            return json.dumps({"query": query, "found": False})

        def _ping(self, params):
            self.send_response(_http_client.OK)
            self.send_header(HTTP_HEADER.CONNECTION, "close")
            self.send_header(HTTP_HEADER.CONTENT_TYPE, "text/plain")

            return PING_RESPONSE

        def __is_allowlisted(self, *options):
            """Is the caller's IP in the first configured allowlist among `options`?

            Deny when none of them is set: these endpoints hand out source IPs from the event log,
            so an unset allowlist has to mean "nobody", not "everybody".
            """
            allowlist = None
            for option in options:
                allowlist = getattr(config, option, None)
                if allowlist:
                    break
            if not allowlist:
                return False  # secure by default

            # allowlist can be multi-line AttribDict list or string
            if isinstance(allowlist, (list, tuple, set)):
                items = []
                for entry in allowlist:
                    items.extend([_.strip() for _ in re.split(r"[,\s;]+", str(entry)) if _.strip()])
            else:
                items = [_.strip() for _ in re.split(r"[,\s;]+", str(allowlist)) if _.strip()]

            if not items:
                return False

            ip = self.client_address[0]

            # IPv6? deny (low-hustle choice; avoids false-allow)
            if ':' in ip and '.' not in ip:
                return False

            try:
                ip_int = addr_to_int(ip)
            except Exception:
                return False

            for item in items:
                if not item:
                    continue

                # exact IPv4
                if re.search(r"\A\d+\.\d+\.\d+\.\d+\Z", item):
                    if ip == item:
                        return True
                    continue

                # IPv4 CIDR
                m = re.match(r"\A(\d+\.\d+\.\d+\.\d+)/(\d+)\Z", item)
                if m:
                    prefix, bits = m.group(1), int(m.group(2))
                    if 0 <= bits <= 32:
                        try:
                            if ip_int & make_mask(bits) == addr_to_int(prefix) & make_mask(bits):
                                return True
                        except Exception:
                            pass

            return False

        def _fail2ban(self, params):
            global _fail2ban_cache
            global _fail2ban_key

            if not self.__is_allowlisted("FAIL2BAN_ALLOWLIST"):
                self.send_response(_http_client.NOT_FOUND)
                self.send_header(HTTP_HEADER.CONNECTION, "close")
                return None

            self.send_response(_http_client.OK)
            self.send_header(HTTP_HEADER.CONNECTION, "close")
            self.send_header(HTTP_HEADER.CONTENT_TYPE, "text/plain")

            content = ""
            # Load the cleared list FIRST: it is part of the cache key, so reading the key before
            # refreshing it would serve the stale answer for up to 8 seconds after an edit - which
            # looks exactly like the feature not working.
            cleared = _cleared_sources()
            key = (int(time.time()) >> 3, _cleared_cache[0])

            if config.FAIL2BAN_REGEX:
                try:
                    re.compile(config.FAIL2BAN_REGEX)
                except re.error:
                    content = "invalid regular expression used in option FAIL2BAN_REGEX"
                else:
                    if key == _fail2ban_key:
                        content = _fail2ban_cache
                    else:
                        result = set()
                        _ = os.path.join(config.LOG_DIR, "%s.log" % datetime.datetime.now().strftime("%Y-%m-%d"))
                        if os.path.isfile(_):
                            with open(_, "r") as f:
                                for line in f:
                                    if re.search(config.FAIL2BAN_REGEX, line, re.I):
                                        parts = line.split()
                                        if len(parts) > 3 and not _event_precedes_clear(line, parts[3], cleared):
                                            result.add(parts[3])

                        content = "\n".join(result)

                        _fail2ban_cache = content
                        _fail2ban_key = key
            else:
                content = "configuration option FAIL2BAN_REGEX not set"

            return content

        def _blacklist(self, params):
            global _blacklist_cache
            global _blacklist_key

            # Access control. This returns the SOURCE IPs of logged events matching the operator's
            # BLACKLIST rules - the same class of data /fail2ban returns, and that every other
            # log-reading endpoint (/events, /counts, /hunt, /meta, /geo) gates behind a session.
            # It was the one endpoint with neither control, which was an oversight rather than a
            # decision: an unauthenticated caller could learn which internal hosts had been flagged.
            #
            # Gated like /fail2ban rather than by session alone, because nothing in the reporting
            # UI calls this - it exists to be pulled by firewall automation, which has no session
            # to present. An authenticated operator is still allowed through, so a logged-in admin
            # can fetch it from anywhere; with USERS unset, get_session() returns the anonymous
            # session and behaviour is unchanged for deployments that run without authentication.
            #
            # BLACKLIST_ALLOWLIST falls back to FAIL2BAN_ALLOWLIST so that existing installs, whose
            # shipped configuration already allowlists loopback and the RFC1918 ranges, keep working
            # without a configuration change. 404, not 401, to match the sibling endpoint.
            session = self.get_session()

            if session is None and not self.__is_allowlisted("BLACKLIST_ALLOWLIST", "FAIL2BAN_ALLOWLIST"):
                self.send_response(_http_client.NOT_FOUND)
                self.send_header(HTTP_HEADER.CONNECTION, "close")
                return None

            # Per-user network scope. The rules select events; the response is the SOURCE address
            # of each - so a restricted analyst was handed flagged hosts from networks they cannot
            # see in /events. An allowlisted, unauthenticated puller (firewall automation) has no
            # session and therefore no scope: unchanged, it still gets everything.
            scope = self._scope(session)
            if scope is None:   # malformed netfilters -> fail closed
                self.send_response(_http_client.INTERNAL_SERVER_ERROR)
                self.send_header(HTTP_HEADER.CONNECTION, "close")
                return None
            restricted, addresses, netmasks, regex = scope

            self.send_response(_http_client.OK)
            self.send_header(HTTP_HEADER.CONNECTION, "close")
            self.send_header(HTTP_HEADER.CONTENT_TYPE, "text/plain")

            bl_name = ""
            if 'subpath' in params:
                bl_name = "_%s" % params['subpath'].split('/')[0].upper()

            content = ""
            cleared = _cleared_sources()   # before the key: see the note in _fail2ban
            key = (bl_name, int(time.time()) >> 3, _cleared_cache[0], self._scope_key(session))  # NOTE: bl_name MUST be part of the key - the single global cache is shared across every /blacklist/<subpath>, so keying on time alone returns one blacklist's results for another within the TTL. The scope key is here for the same reason: one shared cache, results that differ per user.

            if "BLACKLIST%s" % bl_name in config:
                try:
                    blacklist = []
                    for bl in config["BLACKLIST%s" % bl_name]:
                        rules = []
                        for e in bl.split(' and '):
                            f, n, p = e.strip().split(' ', 2)
                            regexp = [
                                [
                                    '',
                                    '',
                                    '',
                                    'src_ip',
                                    'src_port',
                                    'dst_ip',
                                    'dst_port',
                                    'protocol',
                                    'type',
                                    'trail',
                                    'filter'
                                ].index(f),
                                (n[0] == '!'),
                                re.compile(p, re.I)
                            ]
                            rules.append(regexp)
                        blacklist.append(rules)
                except Exception:
                    content = "invalid rule in option BLACKLIST%s" % bl_name
                else:
                    if key == _blacklist_key:
                        content = _blacklist_cache
                    else:
                        result = set()
                        _ = os.path.join(config.LOG_DIR, "%s.log" % datetime.datetime.now().strftime("%Y-%m-%d"))
                        if os.path.isfile(_):
                            with open(_, "r") as f_log:
                                for raw in f_log:
                                    line = raw.split(' ', 10)
                                    if len(line) < 11:
                                        continue
                                    if _event_precedes_clear(raw, line[3], cleared):
                                        continue
                                    if restricted and not self._line_in_scope(raw, addresses, netmasks, regex)[0]:
                                        continue
                                    for bl in blacklist:
                                        failed = False
                                        for f, n, r in bl:
                                            if not (
                                                (r.search(line[f]) is not None) ^ n
                                                    ):
                                                failed = True
                                                break
                                        if not failed:
                                            result.add(line[3])
                                            break

                        content = "\n".join(result)

                        _blacklist_cache = content
                        _blacklist_key = key
            else:
                content = "configuration option BLACKLIST%s not set" % bl_name
            return content

        def _build_netfilters(self, session):
            addresses, netmasks, regex = set(), [], ""

            for netfilter in session.netfilters or []:
                if not netfilter:
                    continue
                if '/' in netfilter:
                    netmasks.append(netfilter)
                elif re.search(r"\A[\d.]+\Z", netfilter):
                    addresses.add(netfilter)
                elif "\\." in netfilter:
                    regex = r"\b(%s)\b" % netfilter
                else:
                    print("[!] invalid network filter '%s'" % netfilter)
                    return None

            return addresses, netmasks, regex

        def _line_in_scope(self, line, addresses, netmasks, regex):
            """(visible, matched_ip) for one raw event line under a session's netfilters.

            The single definition of "is this event inside the analyst's networks". It used to
            live inline in _filter_events, which meant /events and /hunt enforced the scope and
            /counts, /geo, /blacklist and /meta - all of which read the same logs - did not. A
            restricted analyst could read the global picture out of the endpoints that had no
            copy of this logic. One definition, called from all of them.

            `addresses` is mutated as a memo, exactly as before: an address proven to be inside a
            netmask is remembered so the next line costs a set lookup instead of the CIDR walk.
            """

            display = False
            ip = None

            if regex:
                match = re.search(regex, line)
                if match:
                    ip = match.group(1)
                    display = True

            if not display and (addresses or netmasks):
                for match in re.finditer(r"\b(\d+\.\d+\.\d+\.\d+)\b", line):
                    if not display:
                        ip = match.group(1)
                    else:
                        break

                    if ip in addresses:
                        display = True
                        break
                    elif netmasks:
                        for _ in netmasks:
                            prefix, mask = _.split('/')
                            # NOTE: mask BOTH sides - a non-network-aligned CIDR (e.g. 10.0.5.0/16, as operators often write) would otherwise never match its own subnet, silently hiding events the analyst is entitled to (consistent with the fail2ban allowlist matching)
                            if addr_to_int(ip) & make_mask(int(mask)) == addr_to_int(prefix) & make_mask(int(mask)):
                                addresses.add(ip)
                                display = True
                                break

            return display, ip

        def _scope(self, session):
            """(restricted, addresses, netmasks, regex) for `session`.

            `restricted` is False for a session that may see everything, which is the fast path
            every unrestricted deployment takes. Returns None if the netfilters are malformed -
            callers must FAIL CLOSED on that, never fall through to unfiltered data.
            """

            if session is None or getattr(session, "netfilters", None) is None:
                return False, set(), [], ""

            built = self._build_netfilters(session)
            if built is None:
                return None

            addresses, netmasks, regex = built
            return True, addresses, netmasks, regex

        def _scope_key(self, session):
            """Cache-key component identifying a session's scope.

            Any cache holding scope-filtered results MUST include this. The caches here are
            module-global and shared across users, so keying an unrestricted analyst's result and
            then serving it to a restricted one is the same disclosure by another route - which is
            precisely how the first attempt at this fix would have failed.
            """

            netfilters = getattr(session, "netfilters", None) if session is not None else None
            return None if netfilters is None else frozenset(netfilters)

        def _filter_events(self, handle, session, addresses, netmasks, regex):
            for line in handle:
                line = line.decode(UNICODE_ENCODING, "ignore")

                if session.netfilters is None:
                    display, ip = True, None
                else:
                    display, ip = self._line_in_scope(line, addresses, netmasks, regex)

                if session.mask_custom and "(custom)" in line:
                    line = re.sub(r'("[^"]+"|[^ ]+) \(custom\)', "- (custom)", line)

                if display:
                    if ip is not None and (",%s" % ip in line or "%s," % ip in line):
                        line = re.sub(r" ([\d.,]+,)?%s(,[\d.,]+)? " % re.escape(ip), " %s " % ip, line)
                    yield line

        def _events(self, params):
            session = self.get_session()

            if session is None:
                self.send_response(_http_client.UNAUTHORIZED)
                self.send_header(HTTP_HEADER.CONNECTION, "close")
                return None

            start, end, size, total = None, None, -1, None
            content = None
            log_exists = False
            dates = params.get("date", "")

            if ".." in dates:
                pass
            elif '_' not in dates:
                try:
                    date = datetime.datetime.strptime(dates, "%Y-%m-%d").strftime("%Y-%m-%d")
                    event_log_path = os.path.join(config.LOG_DIR, "%s.log" % date)
                    if os.path.exists(event_log_path):
                        range_handle = open(event_log_path, "rb")
                        log_exists = True
                except ValueError:
                    print("[!] invalid date format in request")
                    log_exists = False
            else:
                date_interval = dates.split("_", 1)
                try:
                    start_date = datetime.datetime.strptime(date_interval[0], "%Y-%m-%d").date()
                    end_date = datetime.datetime.strptime(date_interval[1], "%Y-%m-%d").date()
                    paths = []
                    for i in xrange(int((end_date - start_date).days) + 1):
                        date = start_date + datetime.timedelta(i)
                        event_log_path = os.path.join(config.LOG_DIR, "%s.log" % date.strftime("%Y-%m-%d"))
                        if os.path.exists(event_log_path):
                            paths.append(event_log_path)

                    range_handle = io.BufferedReader(_ConcatenatedFiles(paths))
                    log_exists = True
                except ValueError:
                    print("[!] invalid date format in request")
                    log_exists = False

            if log_exists:
                range_handle.seek(0, 2)
                total = range_handle.tell()
                range_handle.seek(0)

                if self.headers.get(HTTP_HEADER.RANGE):
                    # RFC 7233 byte-range forms. This used to be `bytes=(\d+)-(\d+)` only, so an
                    # END WAS MANDATORY - and the natural way to tail a growing log, `bytes=N-`,
                    # matched nothing, fell through, and got 200 with the WHOLE FILE. A client
                    # polling a 100MB day log every few seconds re-downloaded all of it every
                    # time, and had no way to tell from the status code that its range had been
                    # ignored. html/js/main.js knew and worked around it by sending a huge
                    # explicit end (LIVE_MAX_END); nothing else could be expected to.
                    #
                    #   bytes=N-M   an explicit span, as before
                    #   bytes=N-    N to EOF
                    #   bytes=-S    the last S bytes
                    header = self.headers[HTTP_HEADER.RANGE]
                    match = re.search(r"bytes=(\d*)-(\d*)", header)
                    if match and (match.group(1) or match.group(2)):
                        if not match.group(1):                      # suffix form: last S bytes
                            suffix = int(match.group(2))
                            start = max(0, total - suffix) if suffix else total
                            end = max(0, total - 1)
                        else:
                            start = int(match.group(1))
                            end = int(match.group(2)) if match.group(2) else max(0, total - 1)
                        # A caught-up tail-follower asking `bytes=<total>-` gets 416, which is
                        # what RFC 7233 says for a first-byte-pos at or past the length. Clients
                        # must read that as "nothing new yet", not as an error worth reloading on.
                        if end < start or start > total:  # NOTE: reject inverted/out-of-bounds ranges; otherwise a negative size makes read(-n) return the whole file
                            self.send_response(_http_client.REQUESTED_RANGE_NOT_SATISFIABLE)
                            self.send_header(HTTP_HEADER.CONNECTION, "close")
                            self.send_header(HTTP_HEADER.CONTENT_RANGE, "bytes */%d" % total)
                            return content
                        max_size = end - start + 1
                        end = min(total - 1, end)
                        size = end - start + 1

                        if start == 0 or not session.range_handle:
                            if session.range_handle and session.range_handle is not range_handle:
                                try: session.range_handle.close()   # close the previously-held handle before adopting a new one (fresh start=0 / refresh / day-switch); otherwise that fd leaks on every reload -> eventual "too many open files"
                                except Exception: pass
                            session.range_handle = range_handle
                        elif range_handle is not session.range_handle:
                            range_handle.close()

                        if session.netfilters is None and not session.mask_custom:
                            session.range_handle.seek(start)
                            self.send_response(_http_client.PARTIAL_CONTENT)
                            self.send_header(HTTP_HEADER.CONNECTION, "close")
                            self.send_header(HTTP_HEADER.CONTENT_TYPE, "text/plain")
                            self.send_header(HTTP_HEADER.CONTENT_RANGE, "bytes %d-%d/%d" % (start, end, total))
                            content = session.range_handle.read(size)
                        else:
                            self.send_response(_http_client.OK)
                            self.send_header(HTTP_HEADER.CONNECTION, "close")
                            self.send_header(HTTP_HEADER.CONTENT_TYPE, "text/plain")

                            _ = self._build_netfilters(session)
                            if _ is None:
                                return content
                            addresses, netmasks, regex = _

                            buffer = io.StringIO()
                            for line in self._filter_events(session.range_handle, session, addresses, netmasks, regex):
                                buffer.write(line)
                                if buffer.tell() >= max_size:
                                    break

                            content = buffer.getvalue()
                            end = start + len(content) - 1
                            self.send_header(HTTP_HEADER.CONTENT_RANGE, "bytes %d-%d/%d" % (start, end, end + 1 + max_size * (len(content) >= max_size)))

                        if len(content) < max_size:
                            session.range_handle.close()
                            session.range_handle = None

                if size == -1:
                    self.send_response(_http_client.OK)
                    self.send_header(HTTP_HEADER.CONNECTION, "close")
                    self.send_header(HTTP_HEADER.CONTENT_TYPE, "text/plain")
                    self.end_headers()

                    if session.netfilters is None and not session.mask_custom:
                        with range_handle as f:
                            while True:
                                data = f.read(io.DEFAULT_BUFFER_SIZE)
                                if not data:
                                    break
                                else:
                                    self.wfile.write(data)
                    else:
                        # NOTE: per-user netfilter restriction and mask_custom redaction must be enforced here too;
                        # otherwise a restricted user could retrieve the full unfiltered log by omitting (or malforming) the Range header
                        _ = self._build_netfilters(session)
                        with range_handle as f:
                            if _ is not None:
                                addresses, netmasks, regex = _
                                for line in self._filter_events(f, session, addresses, netmasks, regex):
                                    self.wfile.write(line.encode(UNICODE_ENCODING))

            else:
                self.send_response(_http_client.OK)  # instead of _http_client.NO_CONTENT (compatibility reasons)
                self.send_header(HTTP_HEADER.CONNECTION, "close")
                if self.headers.get(HTTP_HEADER.RANGE):
                    self.send_header(HTTP_HEADER.CONTENT_RANGE, "bytes 0-0/0")

            return content

        def _live(self, params):
            # Server-Sent Events: push appended log lines in near real time so the UI updates instantly
            # (no 15s poll). EventSource is same-origin -> allowed by CSP connect-src 'self'. Threaded server
            # (ThreadingMixIn) so a held-open stream doesn't block other requests. Restricted/filtered sessions
            # get 204 and the client falls back to Range polling. Each event carries id=<byte offset> so a
            # reconnect (Last-Event-ID) resumes exactly, with no duplicate or skipped lines.
            session = self.get_session()
            if session is None:
                self.send_response(_http_client.UNAUTHORIZED)
                self.send_header(HTTP_HEADER.CONNECTION, "close")
                return None
            if session.netfilters is not None or session.mask_custom:
                self.send_response(_http_client.NO_CONTENT)  # per-user redaction can't be byte-streamed -> client polls
                self.send_header(HTTP_HEADER.CONNECTION, "close")
                return None
            try:
                date = datetime.datetime.strptime(params.get("date", ""), "%Y-%m-%d").strftime("%Y-%m-%d")
            except ValueError:
                self.send_response(_http_client.BAD_REQUEST)
                self.send_header(HTTP_HEADER.CONNECTION, "close")
                return None
            event_log_path = os.path.join(config.LOG_DIR, "%s.log" % date)

            # Budget check before the response line: a refused stream must look exactly like the
            # restricted-session case above, which the client already handles.
            if not _live_slot():
                self.send_response(_http_client.NO_CONTENT)
                self.send_header(HTTP_HEADER.CONNECTION, "close")
                return None

            pos = None
            leid = self.headers.get("Last-Event-ID")
            if leid and leid.isdigit():
                pos = int(leid)
            elif params.get("pos") and ("%s" % params.get("pos")).isdigit():
                pos = int(params.get("pos"))

            self.send_response(_http_client.OK)
            self.send_header(HTTP_HEADER.CONNECTION, "close")
            self.send_header(HTTP_HEADER.CONTENT_TYPE, "text/event-stream")
            self.send_header(HTTP_HEADER.CACHE_CONTROL, "no-cache")
            self.send_header("X-Accel-Buffering", "no")  # disable proxy (nginx) response buffering
            self.end_headers()

            def _w(s):
                self.wfile.write(s.encode(UNICODE_ENCODING) if isinstance(s, str) else s)

            try:
                cur = os.path.getsize(event_log_path) if os.path.exists(event_log_path) else 0
                if pos is None or pos > cur:
                    pos = cur  # default: tail only NEW lines (never replay the whole file); also recover if file shrank
                _w(": connected\n\n"); self.wfile.flush()
                idle = 0
                while True:
                    size = os.path.getsize(event_log_path) if os.path.exists(event_log_path) else 0
                    if size < pos:        # log rotated / truncated -> resync from start
                        pos = 0
                    if size > pos:
                        with open(event_log_path, "rb") as f:
                            f.seek(pos)
                            data = f.read(size - pos)
                        nl = data.rfind(b"\n")
                        if nl >= 0:
                            off = pos
                            for line in data[:nl + 1].split(b"\n"):
                                off += len(line) + 1
                                if line.strip():
                                    _w("id: %d\ndata: %s\n\n" % (off, line.decode(UNICODE_ENCODING, "replace")))
                            pos += nl + 1   # leave any partial trailing line to be re-read next pass
                            self.wfile.flush()
                            idle = 0
                            continue
                    # Notice a closed tab NOW rather than at the next write. Without this the
                    # handler sits in sleep() until the 15s heartbeat fails, and its stream slot
                    # stays claimed that whole time - with a small MAX_LIVE_STREAMS that is the
                    # difference between a budget and a queue. A closed peer reads as EOF.
                    try:
                        if select.select([self.connection], [], [], 0)[0]:
                            if not self.connection.recv(1, socket.MSG_PEEK):
                                break
                    except Exception:
                        pass    # e.g. an SSL socket that will not peek; the heartbeat still catches it
                    idle += 1
                    if idle >= 25:          # ~ every 25 * 0.6s = 15s: heartbeat keeps the conn alive + surfaces disconnects
                        _w(": ping\n\n"); self.wfile.flush(); idle = 0
                    time.sleep(0.6)
            except Exception:
                pass  # client disconnected (write failed) or transient I/O -> end the stream; EventSource will reconnect
            finally:
                _live_release()
            return None

        def _counts(self, params):
            counts = {}

            session = self.get_session()

            if session is None:
                self.send_response(_http_client.UNAUTHORIZED)
                self.send_header(HTTP_HEADER.CONNECTION, "close")
                return None

            # Per-user network scope. /events has always honoured it; this endpoint reported the
            # GLOBAL daily totals to every authenticated user, so a analyst restricted to one
            # network could read the size of the whole estate's activity off the chart. Same logs,
            # same session, so the same rule applies here.
            scope = self._scope(session)
            if scope is None:   # malformed netfilters -> fail closed, never fall back to global counts
                self.send_response(_http_client.INTERNAL_SERVER_ERROR)
                self.send_header(HTTP_HEADER.CONNECTION, "close")
                return None
            restricted, addresses, netmasks, regex = scope
            scope_key = self._scope_key(session)

            self.send_response(_http_client.OK)
            self.send_header(HTTP_HEADER.CONNECTION, "close")
            self.send_header(HTTP_HEADER.CONTENT_TYPE, "application/json")

            match = re.search(r"\d+\-\d+\-\d+", params.get("from", ""))
            if match:
                min_ = datetime.datetime.strptime(match.group(0), DATE_FORMAT)
            else:
                min_ = datetime.datetime.fromtimestamp(0)

            match = re.search(r"\d+\-\d+\-\d+", params.get("to", ""))
            if match:
                max_ = datetime.datetime.strptime(match.group(0), DATE_FORMAT)
            else:
                max_ = datetime.datetime.now()

            min_ = min_.replace(hour=0, minute=0, second=0, microsecond=0)
            max_ = max_.replace(hour=23, minute=59, second=59, microsecond=999999)

            for filepath in sorted(glob.glob(os.path.join(config.LOG_DIR, "*.log"))):
                filename = os.path.basename(filepath)
                if not re.search(r"\A\d{4}-\d{2}-\d{2}\.log\Z", filename):
                    continue
                try:
                    current = datetime.datetime.strptime(os.path.splitext(filename)[0], DATE_FORMAT)
                except Exception:
                    if config.SHOW_DEBUG:
                        traceback.print_exc()
                else:
                    if min_ <= current <= max_:
                        daystr = os.path.splitext(filename)[0]  # key by the log's date ("YYYY-MM-DD"); the client maps it directly, no timezone/DST math
                        size = os.path.getsize(filepath)
                        mtime = os.path.getmtime(filepath)
                        # NOTE: scope_key is part of the cache key. This cache is a module global
                        # shared by every request, so keying it on the filepath alone would let an
                        # unrestricted user's total be served to a restricted one (and vice versa)
                        # - reintroducing the very disclosure through the cache.
                        cache_key = (filepath, scope_key)
                        cached = _counts_cache.get(cache_key)
                        if cached and cached[0] == mtime and cached[1] == size:  # immutable (past-day) log -> reuse, skip the open+read
                            counts[daystr] = cached[2]
                        else:
                            if restricted:
                                # No estimating here: the estimate extrapolates from a sample of
                                # the file, and a scoped count has to be of the lines the analyst
                                # may actually see. Exact, and cached like the rest.
                                count = 0
                                try:
                                    with open(filepath, "rb") as f_log:
                                        for raw in f_log:
                                            if self._line_in_scope(raw.decode(UNICODE_ENCODING, "ignore"), addresses, netmasks, regex)[0]:
                                                count += 1
                                except (OSError, IOError):
                                    count = 0
                            else:
                                count = estimate_event_count(filepath, size)
                            counts[daystr] = count
                            _counts_cache[cache_key] = (mtime, size, count)

            return json.dumps(counts)

        def _geo(self, params):
            # Per-country event density for one day's log, for the world map. Which IP to place depends on the trail
            # type (IP vs domain-URL vs inbound-scan heuristic vs DNS), so the per-event decision lives in
            # core.geo.event_country() - it places the external malicious endpoint and honestly leaves DNS /
            # internal-only events unmapped. Result is cached per immutable past-day log, like _counts.
            session = self.get_session()

            if session is None:
                self.send_response(_http_client.UNAUTHORIZED)
                self.send_header(HTTP_HEADER.CONNECTION, "close")
                return None

            # Per-user network scope, as in /events and /counts. Without it the map showed a
            # restricted analyst every country the WHOLE estate talked to - a coarse picture, but
            # still the global one, and derived from log lines they may not read.
            scope = self._scope(session)
            if scope is None:   # malformed netfilters -> fail closed
                self.send_response(_http_client.INTERNAL_SERVER_ERROR)
                self.send_header(HTTP_HEADER.CONNECTION, "close")
                return None
            restricted, addresses, netmasks, regex = scope
            scope_key = self._scope_key(session)

            self.send_response(_http_client.OK)
            self.send_header(HTTP_HEADER.CONNECTION, "close")
            self.send_header(HTTP_HEADER.CONTENT_TYPE, "application/json")

            result = {"counts": {}, "mapped": 0, "unmapped": 0}
            match = re.search(r"\d{4}-\d{2}-\d{2}", params.get("date", ""))
            filepath = os.path.join(config.LOG_DIR, "%s.log" % match.group(0)) if match else None

            if filepath and os.path.exists(filepath):
                with _geo_lock:
                    size = os.path.getsize(filepath)
                    mtime = os.path.getmtime(filepath)
                    cache_key = (filepath, scope_key)   # NOTE: shared global cache - see the note in _counts
                    c = _geo_cache.get(cache_key)
                    if c and c["size"] == size and c["mtime"] == mtime:
                        counts, mapped, unmapped = c["counts"], c["mapped"], c["unmapped"]  # unchanged -> reuse
                    else:
                        if c and size > c["size"]:                                          # grew (append) -> scan only new bytes
                            counts, mapped, unmapped, start = dict(c["counts"]), c["mapped"], c["unmapped"], c["offset"]
                        else:                                                               # new / rotated / shrank -> full scan
                            counts, mapped, unmapped, start = {}, 0, 0, 0
                        offset = start
                        try:
                            with open(filepath, "rb") as f:
                                f.seek(start)
                                pending = b""
                                while True:
                                    buf = f.read(1024 * 1024)   # 1 MB chunks -> bounded memory even on a huge full scan
                                    if not buf:
                                        break
                                    pending += buf
                                    nl = pending.rfind(b"\n")
                                    if nl < 0:
                                        continue
                                    chunk, pending = pending[:nl + 1], pending[nl + 1:]     # only COMPLETE lines; keep a partial tail for next time
                                    offset += len(chunk)
                                    for line in chunk.split(b"\n"):
                                        cut = line.find(b'" ')  # end of the quoted leading timestamp
                                        if cut < 0:
                                            continue
                                        parts = line[cut + 2:].split(b' ')  # sensor,src,sport,dst,dport,proto,type,TRAIL,...
                                        if len(parts) <= 7:
                                            continue
                                        if restricted and not self._line_in_scope(line.decode(UNICODE_ENCODING, "ignore"), addresses, netmasks, regex)[0]:
                                            continue
                                        # place the external malicious endpoint per trail type (see core.geo.event_country)
                                        cc = event_country(parts[6].decode("latin-1"), parts[1].decode("latin-1"), parts[3].decode("latin-1"), parts[7].decode("latin-1"))
                                        if cc:
                                            counts[cc] = counts.get(cc, 0) + 1
                                            mapped += 1
                                        else:
                                            unmapped += 1
                        except Exception:
                            if config.SHOW_DEBUG:
                                traceback.print_exc()
                        _geo_cache[cache_key] = {"mtime": mtime, "size": size, "offset": offset, "counts": counts, "mapped": mapped, "unmapped": unmapped}
                    result = {"counts": counts, "mapped": mapped, "unmapped": unmapped}

            out = dict(result)
            out["home"] = _geo_home()  # config, not part of the per-day cache: cheap and may change on reload
            return json.dumps(out)

        def _hunt(self, params):
            # Retro-hunt: sweep historical daily logs for an IOC and return per-day hit counts + capped sample lines.
            # HARD-bounded so a broad query can't self-DoS: newest-first, streamed, and it stops at whichever of
            # {HUNT_MAX_DAYS, HUNT_TIME_BUDGET, HUNT_MAX_SAMPLES} trips first (reporting truncated=true). Scope is
            # enforced per session by reusing _filter_events, identical to /events (a restricted analyst only ever
            # hunts within their own netmasks). Matching is IOC-shaped only (IP/CIDR or literal substring) - no
            # user-supplied regex, so there's no ReDoS surface.
            session = self.get_session()

            if session is None:
                self.send_response(_http_client.UNAUTHORIZED)
                self.send_header(HTTP_HEADER.CONNECTION, "close")
                return None

            self.send_response(_http_client.OK)
            self.send_header(HTTP_HEADER.CONNECTION, "close")
            self.send_header(HTTP_HEADER.CONTENT_TYPE, "application/json")

            query = (params.get("q") or "").strip()
            if len(query) < HUNT_MIN_QUERY:
                return json.dumps({"error": "query too short (min %d chars)" % HUNT_MIN_QUERY, "counts": {}, "samples": [], "truncated": False, "scanned": 0})

            q_lower = query.lower()
            q_prefix = q_mask = None   # IP/CIDR fast-path (integer match); otherwise literal substring
            ipm = re.match(r"\A(\d+\.\d+\.\d+\.\d+)(?:/(\d{1,2}))?\Z", query)
            if ipm:
                try:
                    q_mask = make_mask(int(ipm.group(2)) if ipm.group(2) else 32)
                    q_prefix = addr_to_int(ipm.group(1)) & q_mask
                except Exception:
                    q_prefix = q_mask = None

            def _bound(name):
                mm = re.search(r"\d{4}-\d{2}-\d{2}", params.get(name, ""))
                return mm.group(0) if mm else None
            lo, hi = _bound("from"), _bound("to")

            files = []
            for filepath in glob.glob(os.path.join(config.LOG_DIR, "*.log")):
                base = os.path.basename(filepath)
                if not re.search(r"\A\d{4}-\d{2}-\d{2}\.log\Z", base):
                    continue
                daystr = base[:-4]
                if (lo and daystr < lo) or (hi and daystr > hi):
                    continue
                files.append((daystr, filepath))
            files.sort(reverse=True)          # newest-first: most relevant, and the cap keeps recent history
            files = files[:HUNT_MAX_DAYS]

            addresses, netmasks, regex = self._build_netfilters(session)
            counts, samples, truncated = {}, [], False
            # Config may raise or lower the budget: the default suits local SSD, and a deployment
            # whose event logs live on network storage reasonably wants longer before a hunt
            # starts returning partial answers.
            try:
                budget = float(config.HUNT_TIME_BUDGET)
            except (TypeError, ValueError):
                budget = HUNT_TIME_BUDGET
            deadline = time.time() + (budget if budget > 0 else HUNT_TIME_BUDGET)

            scanned = 0        # days scanned TO COMPLETION, which is what a per-day count can be trusted for
            partial = None     # the one day the budget cut short, if any
            for daystr, filepath in files:
                if time.time() > deadline:
                    truncated = True
                    break
                hits, seen, cut_short = 0, 0, False
                try:
                    with open(filepath, "rb") as f:
                        for line in self._filter_events(f, session, addresses, netmasks, regex):  # scope-enforced, same as /events
                            seen += 1
                            if (seen & 0x3FFF) == 0 and time.time() > deadline:   # periodic budget check inside a huge day
                                truncated = True
                                cut_short = True
                                break
                            hit = False
                            if q_prefix is not None:
                                for im in re.finditer(r"\b(\d+\.\d+\.\d+\.\d+)\b", line):
                                    try:
                                        if addr_to_int(im.group(1)) & q_mask == q_prefix:
                                            hit = True
                                            break
                                    except Exception:
                                        pass
                            elif q_lower in line.lower():
                                hit = True
                            if hit:
                                hits += 1
                                if len(samples) < HUNT_MAX_SAMPLES:
                                    samples.append({"date": daystr, "line": line.strip()[:500]})
                except Exception:
                    if config.SHOW_DEBUG:
                        traceback.print_exc()
                # A day the budget cut short has a count that is NOT the day's total, and nothing
                # in the response used to say so: `counts` reported it exactly like a finished
                # day. Measured on three 40k-line days with a small budget, the middle day came
                # back as 16383 hits against a true 40000 - a 59% undercount an analyst would
                # read straight off the chart as that day's answer. `truncated` was set, but it
                # said only "something was cut", not which day was short.
                #
                # Undercounting a retro-hunt is the wrong direction to be wrong in, so the
                # partial day is reported separately instead of being passed off as complete.
                if cut_short:
                    partial = {"date": daystr, "hits": hits, "note": "budget expired mid-file; not a complete count"}
                elif hits:
                    counts[daystr] = hits
                    scanned += 1
                else:
                    scanned += 1
                if truncated:
                    break

            # `scanned` used to be len(files) - the number of logs SELECTED, not the number read.
            # On the run above it said 3 when one day was never opened at all.
            return json.dumps({"counts": counts, "samples": samples, "truncated": truncated,
                               "scanned": scanned, "selected": len(files), "partial": partial,
                               "capped_samples": len(samples) >= HUNT_MAX_SAMPLES})

    class SSLReqHandler(ReqHandler):
        def setup(self):
            self.connection = self.request
            self.rfile = socket._fileobject(self.request, "rb", self.rbufsize)
            self.wfile = socket._fileobject(self.request, "wb", self.wbufsize)

    # IPv6 support
    if ':' in (address or ""):
        address = address.strip("[]")

        _BaseHTTPServer.HTTPServer.address_family = socket.AF_INET6
        _address = resolve_address(address, port)
    else:
        _address = (address or '', int(port) if str(port or "").isdigit() else 0)

    try:
        if pem:
            server = SSLThreadingServer(_address, pem, SSLReqHandler)
        else:
            server = ThreadingServer(_address, ReqHandler)
    except Exception as ex:
        if "Address already in use" in str(ex):
            sys.exit("[!] another instance already running")
        elif "Name or service not known" in str(ex):
            sys.exit("[!] invalid configuration value for 'HTTP_ADDRESS' ('%s')" % config.HTTP_ADDRESS)
        elif "Cannot assign requested address" in str(ex):
            sys.exit("[!] can't use configuration value for 'HTTP_ADDRESS' ('%s')" % config.HTTP_ADDRESS)
        else:
            raise

    print("[i] starting HTTP%s server at http%s://%s:%d/" % ('S' if pem else "", 's' if pem else "", server.server_address[0], server.server_address[1]))

    print("[^] running...")

    if join:
        server.serve_forever()
    else:
        thread = threading.Thread(target=server.serve_forever)
        thread.daemon = True
        thread.start()
