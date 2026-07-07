#!/usr/bin/env python

"""
Copyright (c) 2014-2026 Maltrail developers (https://github.com/stamparm/maltrail/)
See the file 'LICENSE' for copying permission
"""
from __future__ import print_function

import datetime
import glob
import gzip
import hashlib
import io
import json
import mimetypes
import os
import re
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
from core.common import get_regex
from core.common import ipcat_lookup
from core.common import worst_asns
from core.compat import xrange
from core.enums import HTTP_HEADER
from core.settings import config
from core.settings import CONTENT_EXTENSIONS_EXCLUSIONS
from core.settings import DATE_FORMAT
from core.settings import DISABLED_CONTENT_EXTENSIONS
from core.settings import DISPOSED_NONCES
from core.settings import HTML_DIR
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
from core.settings import UNICODE_ENCODING
from core.settings import VERSION
from thirdparty import six
from thirdparty.six.moves import BaseHTTPServer as _BaseHTTPServer
from thirdparty.six.moves import http_client as _http_client
from thirdparty.six.moves import socketserver as _socketserver
from thirdparty.six.moves import urllib as _urllib

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
_blacklist_cache = None
_blacklist_key = None
_version_cache = None
_counts_cache = {}  # NOTE: per daily-log event count keyed by filepath -> (mtime, size, count); past-day logs are immutable so they're read once, not on every poll
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

def start_httpd(address=None, port=None, join=False, pem=None):
    """
    Starts HTTP server
    """

    class ThreadingServer(_socketserver.ThreadingMixIn, _BaseHTTPServer.HTTPServer):
        daemon_threads = True  # long-lived SSE (/live) streams must not block server shutdown
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
            if six.PY2:
                import OpenSSL  # pyopenssl

                ThreadingServer.__init__(self, server_address, HandlerClass)
                for method in ("TLSv1_2_METHOD", "TLSv1_1_METHOD", "TLSv1_METHOD", "TLS_METHOD", "SSLv23_METHOD", "SSLv2_METHOD"):
                    if hasattr(OpenSSL.SSL, method):
                        ctx = OpenSSL.SSL.Context(getattr(OpenSSL.SSL, method))
                        break
                ctx.use_privatekey_file(pem)
                ctx.use_certificate_file(pem)
                self.socket = OpenSSL.SSL.Connection(ctx, socket.socket(self.address_family, self.socket_type))
                self.server_bind()
                self.server_activate()
            else:
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
            if splitpath[0] in ("login", "logout", "whoami", "check_ip", "trails", "ping", "blacklist", "fail2ban", "events", "live", "counts"):
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
                            content = re.sub(b'\\s*<script[^>]+src="js/demo\\.js"></script>', b'', content)

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
                if isinstance(content, six.text_type):
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
                    _ = six.BytesIO()
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
                time.sleep(UNAUTHORIZED_SLEEP_TIME)
                self.send_response(_http_client.UNAUTHORIZED)
                self.send_header(HTTP_HEADER.CONNECTION, "close")

            self.send_header(HTTP_HEADER.CONTENT_TYPE, "text/plain")
            content = "Login %s" % ("success" if valid else "failed")

            if not IS_WIN:
                try:
                    subprocess.check_output(["logger", "-p", "auth.info", "-t", "%s[%d]" % (NAME.lower(), os.getpid()), "%s password for %s from %s port %s" % ("Accepted" if valid else "Failed", params.get("username"), self.client_address[0], self.client_address[1])], stderr=subprocess.STDOUT, shell=False)
                except Exception:
                    if config.SHOW_DEBUG:
                        traceback.print_exc()

            return content

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
                payload = json.dumps({"ipcat": result_ipcat, "worst_asns": str(result_worst is not None).lower()})
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

        def _trails(self, params):
            self.send_response(_http_client.OK)
            self.send_header(HTTP_HEADER.CONNECTION, "close")
            self.send_header(HTTP_HEADER.CONTENT_TYPE, "text/plain")

            # NOTE: TRAILS_FILE may not exist yet (fresh server with USE_SERVER_UPDATE_TRAILS off, or a first
            # update that produced no trails). A bare open() would raise -> 500 + traceback, and a sensor pulling
            # from UPDATE_SERVER would fail. Return an empty body instead; the sensor then keeps its current trails.
            if os.path.isfile(config.TRAILS_FILE):
                with open(config.TRAILS_FILE, "rb") as f:
                    return f.read()

            return b""

        def _ping(self, params):
            self.send_response(_http_client.OK)
            self.send_header(HTTP_HEADER.CONNECTION, "close")
            self.send_header(HTTP_HEADER.CONTENT_TYPE, "text/plain")

            return PING_RESPONSE

        def __is_fail2ban_allowed(self):
            allowlist = getattr(config, "FAIL2BAN_ALLOWLIST", None)
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

            if not self.__is_fail2ban_allowed():
                self.send_response(_http_client.NOT_FOUND)
                self.send_header(HTTP_HEADER.CONNECTION, "close")
                return None

            self.send_response(_http_client.OK)
            self.send_header(HTTP_HEADER.CONNECTION, "close")
            self.send_header(HTTP_HEADER.CONTENT_TYPE, "text/plain")

            content = ""
            key = int(time.time()) >> 3

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
                                        if len(parts) > 3:
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

            self.send_response(_http_client.OK)
            self.send_header(HTTP_HEADER.CONNECTION, "close")
            self.send_header(HTTP_HEADER.CONTENT_TYPE, "text/plain")

            bl_name = ""
            if 'subpath' in params:
                bl_name = "_%s" % params['subpath'].split('/')[0].upper()

            content = ""
            key = (bl_name, int(time.time()) >> 3)  # NOTE: bl_name MUST be part of the key - the single global cache is shared across every /blacklist/<subpath>, so keying on time alone returns one blacklist's results for another within the TTL

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
                                for line in f_log:
                                    line = line.split(' ', 10)
                                    if len(line) < 11:
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

        def _filter_events(self, handle, session, addresses, netmasks, regex):
            for line in handle:
                display = session.netfilters is None
                ip = None
                line = line.decode(UNICODE_ENCODING, "ignore")

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
                    match = re.search(r"bytes=(\d+)-(\d+)", self.headers[HTTP_HEADER.RANGE])
                    if match:
                        start, end = int(match.group(1)), int(match.group(2))
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
                    idle += 1
                    if idle >= 25:          # ~ every 25 * 0.6s = 15s: heartbeat keeps the conn alive + surfaces disconnects
                        _w(": ping\n\n"); self.wfile.flush(); idle = 0
                    time.sleep(0.6)
            except Exception:
                pass  # client disconnected (write failed) or transient I/O -> end the stream; EventSource will reconnect
            return None

        def _counts(self, params):
            counts = {}

            session = self.get_session()

            if session is None:
                self.send_response(_http_client.UNAUTHORIZED)
                self.send_header(HTTP_HEADER.CONNECTION, "close")
                return None

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
                        cached = _counts_cache.get(filepath)
                        if cached and cached[0] == mtime and cached[1] == size:  # immutable (past-day) log -> reuse, skip the open+read
                            counts[daystr] = cached[2]
                        else:
                            count = estimate_event_count(filepath, size)
                            counts[daystr] = count
                            _counts_cache[filepath] = (mtime, size, count)

            return json.dumps(counts)

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
