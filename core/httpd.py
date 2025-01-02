#!/usr/bin/env python

"""
Copyright (c) 2014-2025 Maltrail developers (https://github.com/stamparm/maltrail/)
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
except:
    pass

_fail2ban_cache = None
_fail2ban_key = None
_blacklist_cache = None
_blacklist_key = None


def start_httpd(address=None, port=None, join=False, pem=None):
    """
    Starts HTTP server
    """

    class ThreadingServer(_socketserver.ThreadingMixIn, _BaseHTTPServer.HTTPServer):
        def server_bind(self):
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            _BaseHTTPServer.HTTPServer.server_bind(self)

        def finish_request(self, *args, **kwargs):
            try:
                _BaseHTTPServer.HTTPServer.finish_request(self, *args, **kwargs)
            except:
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
            except:
                pass

    class ReqHandler(_BaseHTTPServer.BaseHTTPRequestHandler):
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
            if hasattr(self, "_%s" % splitpath[0]):
                if len(splitpath) > 1:
                    params["subpath"] = splitpath[1]
                content = getattr(self, "_%s" % splitpath[0])(params)

            else:
                path = path.replace('/', os.path.sep)
                path = os.path.abspath(os.path.join(HTML_DIR, path)).strip()

                if not os.path.isfile(path) and os.path.isfile("%s.html" % path):
                    path = "%s.html" % path

                if any((config.IP_ALIASES,)) and self.path.split('?')[0] == "/js/main.js":
                    content = open(path, 'r').read()
                    content = re.sub(r"\bvar IP_ALIASES =.+", "var IP_ALIASES = {%s};" % ", ".join('"%s": "%s"' % (_.split(':', 1)[0].strip(), _.split(':', 1)[-1].strip()) for _ in config.IP_ALIASES), content)

                if ".." not in os.path.relpath(path, HTML_DIR) and os.path.isfile(path) and (extension not in DISABLED_CONTENT_EXTENSIONS or os.path.split(path)[-1] in CONTENT_EXTENSIONS_EXCLUSIONS):
                    mtime = time.gmtime(os.path.getmtime(path))
                    if_modified_since = self.headers.get(HTTP_HEADER.IF_MODIFIED_SINCE)

                    if if_modified_since and extension not in (".htm", ".html"):
                        if_modified_since = [_ for _ in if_modified_since.split(';') if _.upper().endswith("GMT")][0]
                        if time.mktime(mtime) <= time.mktime(time.strptime(if_modified_since, HTTP_TIME_FORMAT)):
                            self.send_response(_http_client.NOT_MODIFIED)
                            self.send_header(HTTP_HEADER.CONNECTION, "close")
                            skip = True

                    if not skip:
                        content = content or open(path, "rb").read()
                        last_modified = time.strftime(HTTP_TIME_FORMAT, mtime)
                        self.send_response(_http_client.OK)
                        self.send_header(HTTP_HEADER.CONNECTION, "close")
                        self.send_header(HTTP_HEADER.CONTENT_TYPE, mimetypes.guess_type(path)[0] or "application/octet-stream")
                        self.send_header(HTTP_HEADER.LAST_MODIFIED, last_modified)

                        # For CSP policy directives see: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/
                        self.send_header(HTTP_HEADER.CONTENT_SECURITY_POLICY, "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src * blob:; script-src 'self' 'unsafe-eval' https://stat.ripe.net; frame-src *; object-src 'none'; block-all-mixed-content;")

                        if os.path.basename(path) == "index.html":
                            content = re.sub(b'\s*<script[^>]+src="js/demo.js"></script>', b'', content)

                        if extension not in (".htm", ".html"):
                            self.send_header(HTTP_HEADER.EXPIRES, "Sun, 17-Jan-2038 19:14:07 GMT")        # Reference: http://blog.httpwatch.com/2007/12/10/two-simple-rules-for-http-caching/
                            self.send_header(HTTP_HEADER.CACHE_CONTROL, "max-age=3600, must-revalidate")  # Reference: http://stackoverflow.com/a/5084555
                        else:
                            self.send_header(HTTP_HEADER.CACHE_CONTROL, "no-cache")

                else:
                    self.send_response(_http_client.NOT_FOUND)
                    self.send_header(HTTP_HEADER.CONNECTION, "close")
                    content = '<!DOCTYPE html><html lang="en"><head><title>404 Not Found</title></head><body><h1>Not Found</h1><p>The requested URL %s was not found on this server.</p></body></html>' % self.path.split('?')[0]

            if content is not None:
                if isinstance(content, six.text_type):
                    content = content.encode(UNICODE_ENCODING)

                for match in re.finditer(b"<\\!(\\w+)\\!>", content):
                    name = match.group(1).decode(UNICODE_ENCODING)
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
            except:
                pass

        def do_POST(self):
            length = self.headers.get(HTTP_HEADER.CONTENT_LENGTH)
            data = self.rfile.read(int(length)).decode(UNICODE_ENCODING)
            data = _urllib.parse.unquote_plus(data)
            self.data = data
            self.do_GET()

        def get_session(self):
            retval = None
            cookie = self.headers.get(HTTP_HEADER.COOKIE)

            if cookie:
                match = re.search(r"%s\s*=\s*([^;]+)" % SESSION_COOKIE_NAME, cookie)
                if match:
                    session = match.group(1)
                    if session in SESSIONS:
                        if SESSIONS[session].client_ip != self.client_address[0]:
                            pass
                        elif SESSIONS[session].expiration > time.time():
                            retval = SESSIONS[session]
                        else:
                            del SESSIONS[session]

            if retval is None and not config.USERS:
                retval = AttribDict({"username": "?"})

            return retval

        def delete_session(self):
            cookie = self.headers.get(HTTP_HEADER.COOKIE)

            if cookie:
                match = re.search(r"%s=(.+)" % SESSION_COOKIE_NAME, cookie)
                if match:
                    session = match.group(1)
                    if session in SESSIONS:
                        del SESSIONS[session]

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
            except:
                if config.SHOW_DEBUG:
                    traceback.print_exc()

        def _version(self):
            version = VERSION

            try:
                for line in open(os.path.join(os.path.dirname(__file__), "settings.py"), 'r'):
                    match = re.search(r'VERSION = "([^"]*)', line)
                    if match:
                        version = match.group(1)
                        break
            except:
                pass

            return version

        def _statics(self):
            latest = max(glob.glob(os.path.join(os.path.dirname(__file__), "..", "trails", "static", "malware", "*.txt")), key=os.path.getmtime)
            return "/%s" % datetime.datetime.fromtimestamp(os.path.getmtime(latest)).strftime(DATE_FORMAT)

        def _logo(self):
            if config.HEADER_LOGO:
                retval = config.HEADER_LOGO
            else:
                retval = '<img src="images/mlogo.png" style="width: 25px">altrail'

            return retval

        def _format(self, content, **params):
            if content:
                for key, value in params.items():
                    content = content.replace(b"<!%s!>" % key.encode(UNICODE_ENCODING), value.encode(UNICODE_ENCODING))

            return content

        def _login(self, params):
            valid = False

            if params.get("username") and params.get("hash") and params.get("nonce"):
                if params.get("nonce") not in DISPOSED_NONCES:
                    DISPOSED_NONCES.add(params.get("nonce"))
                    for entry in (config.USERS or []):
                        entry = re.sub(r"\s", "", entry)
                        username, stored_hash, uid, netfilter = entry.split(':')

                        try:
                            uid = int(uid)
                        except ValueError:
                            uid = None

                        if username == params.get("username"):
                            try:
                                if params.get("hash") == hashlib.sha256((stored_hash.strip() + params.get("nonce")).encode(UNICODE_ENCODING)).hexdigest():
                                    valid = True
                                    break
                            except:
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
                            _ = item.split('/')[-1]
                            if _.isdigit() and int(_) >= 16:
                                lower = addr_to_int(item.split('/')[0])
                                mask = make_mask(int(_))
                                upper = lower | (0xffffffff ^ mask)
                                while lower <= upper:
                                    addresses.add(int_to_addr(lower))
                                    lower += 1
                            else:
                                netmasks.add(item)
                        elif '-' in item:
                            _ = item.split('-')
                            lower, upper = addr_to_int(_[0]), addr_to_int(_[1])
                            while lower <= upper:
                                addresses.add(int_to_addr(lower))
                                lower += 1
                        elif re.search(r"\d+\.\d+\.\d+\.\d+", item):
                            addresses.add(item)

                    netfilters = netmasks
                    if addresses:
                        netfilters.add(get_regex(addresses))

                SESSIONS[session_id] = AttribDict({"username": username, "uid": uid, "netfilters": netfilters, "mask_custom": config.ENABLE_MASK_CUSTOM and uid >= 1000, "expiration": expiration, "client_ip": self.client_address[0]})
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
                return ("%s" if not params.get("callback") else "%s(%%s)" % params.get("callback")) % json.dumps({"ipcat": result_ipcat, "worst_asns": str(result_worst is not None).lower()})
            except:
                if config.SHOW_DEBUG:
                    traceback.print_exc()

        def _trails(self, params):
            self.send_response(_http_client.OK)
            self.send_header(HTTP_HEADER.CONNECTION, "close")
            self.send_header(HTTP_HEADER.CONTENT_TYPE, "text/plain")

            return open(config.TRAILS_FILE, "rb").read()

        def _ping(self, params):
            self.send_response(_http_client.OK)
            self.send_header(HTTP_HEADER.CONNECTION, "close")
            self.send_header(HTTP_HEADER.CONTENT_TYPE, "text/plain")

            return PING_RESPONSE

        def _fail2ban(self, params):
            global _fail2ban_cache
            global _fail2ban_key

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
                            for line in open(_, "r"):
                                if re.search(config.FAIL2BAN_REGEX, line, re.I):
                                    result.add(line.split()[3])

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
            key = int(time.time()) >> 3

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
                except e:
                    content = "invalid rule in option BLACKLIST%s" % bl_name
                else:
                    if key == _blacklist_key:
                        content = _blacklist_cache
                    else:
                        result = set()
                        _ = os.path.join(config.LOG_DIR, "%s.log" % datetime.datetime.now().strftime("%Y-%m-%d"))
                        if os.path.isfile(_):
                            for line in open(_, "r"):
                                line = line.split(' ', 10)
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
                logs_data = ""
                date_interval = dates.split("_", 1)
                try:
                    start_date = datetime.datetime.strptime(date_interval[0], "%Y-%m-%d").date()
                    end_date = datetime.datetime.strptime(date_interval[1], "%Y-%m-%d").date()
                    for i in xrange(int((end_date - start_date).days) + 1):
                        date = start_date + datetime.timedelta(i)
                        event_log_path = os.path.join(config.LOG_DIR, "%s.log" % date.strftime("%Y-%m-%d"))
                        if os.path.exists(event_log_path):
                            log_handle = open(event_log_path, "rb")
                            logs_data += log_handle.read()
                            log_handle.close()

                    range_handle = io.BytesIO(logs_data)
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
                        max_size = end - start + 1
                        end = min(total - 1, end)
                        size = end - start + 1

                        if start == 0 or not session.range_handle:
                            session.range_handle = range_handle

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

                            buffer, addresses, netmasks, regex = io.StringIO(), set(), [], ""
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
                                    return

                            for line in session.range_handle:
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
                                                if addr_to_int(ip) & make_mask(int(mask)) == addr_to_int(prefix):
                                                    addresses.add(ip)
                                                    display = True
                                                    break

                                if session.mask_custom and "(custom)" in line:
                                    line = re.sub(r'("[^"]+"|[^ ]+) \(custom\)', "- (custom)", line)

                                if display:
                                    if ",%s" % ip in line or "%s," % ip in line:
                                        line = re.sub(r" ([\d.,]+,)?%s(,[\d.,]+)? " % re.escape(ip), " %s " % ip, line)
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

                    with range_handle as f:
                        while True:
                            data = f.read(io.DEFAULT_BUFFER_SIZE)
                            if not data:
                                break
                            else:
                                self.wfile.write(data)

            else:
                self.send_response(_http_client.OK)  # instead of _http_client.NO_CONTENT (compatibility reasons)
                self.send_header(HTTP_HEADER.CONNECTION, "close")
                if self.headers.get(HTTP_HEADER.RANGE):
                    self.send_header(HTTP_HEADER.CONTENT_RANGE, "bytes 0-0/0")

            return content

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
                except:
                    if config.SHOW_DEBUG:
                        traceback.print_exc()
                else:
                    if min_ <= current <= max_:
                        timestamp = int(time.mktime(current.timetuple()))
                        size = os.path.getsize(filepath)
                        with open(filepath, "rb") as f:
                            content = f.read(io.DEFAULT_BUFFER_SIZE)
                            if size >= io.DEFAULT_BUFFER_SIZE:
                                total = 1.0 * (1 + content.count(b'\n')) * size / io.DEFAULT_BUFFER_SIZE
                                counts[timestamp] = int(round(total / 100.0) * 100)
                            else:
                                counts[timestamp] = content.count(b'\n')

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

        # Reference: https://github.com/squeaky-pl/zenchmarks/blob/master/vendor/twisted/internet/tcp.py
        _AI_NUMERICSERV = getattr(socket, "AI_NUMERICSERV", 0)
        _NUMERIC_ONLY = socket.AI_NUMERICHOST | _AI_NUMERICSERV

        _address = socket.getaddrinfo(address, int(port) if str(port or "").isdigit() else 0, 0, 0, 0, _NUMERIC_ONLY)[0][4]
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
