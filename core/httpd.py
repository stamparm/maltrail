#!/usr/bin/env python

"""
Copyright (c) 2014-2016 Miroslav Stampar (@stamparm)
See the file 'LICENSE' for copying permission
"""

import BaseHTTPServer
import cStringIO
import datetime
import httplib
import glob
import gzip
import hashlib
import io
import json
import mimetypes
import os
import re
import socket
import SocketServer
import subprocess
import threading
import time
import traceback
import urllib
import urlparse

from core.addr import addr_to_int
from core.addr import int_to_addr
from core.addr import make_mask
from core.attribdict import AttribDict
from core.common import get_regex
from core.common import ipcat_lookup
from core.common import worst_asns
from core.enums import HTTP_HEADER
from core.settings import config
from core.settings import CONTENT_EXTENSIONS_EXCLUSIONS
from core.settings import DATE_FORMAT
from core.settings import DISABLED_CONTENT_EXTENSIONS
from core.settings import DISPOSED_NONCES
from core.settings import HTML_DIR
from core.settings import HTTP_TIME_FORMAT
from core.settings import MAX_NOFILE
from core.settings import NAME
from core.settings import PING_RESPONSE
from core.settings import SERVER_HEADER
from core.settings import SESSION_COOKIE_NAME
from core.settings import SESSION_EXPIRATION_HOURS
from core.settings import SESSION_ID_LENGTH
from core.settings import SESSIONS
from core.settings import TRAILS_FILE
from core.settings import UNAUTHORIZED_SLEEP_TIME
from core.settings import VERSION

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

def start_httpd(address=None, port=None, join=False, pem=None):
    """
    Starts HTTP server
    """

    class ThreadingServer(SocketServer.ThreadingMixIn, BaseHTTPServer.HTTPServer):
        def server_bind(self):
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            BaseHTTPServer.HTTPServer.server_bind(self)

        def finish_request(self, *args, **kwargs):
            try:
                BaseHTTPServer.HTTPServer.finish_request(self, *args, **kwargs)
            except:
                if config.SHOW_DEBUG:
                    traceback.print_exc()

    class SSLThreadingServer(ThreadingServer):
        def __init__(self, server_address, pem, HandlerClass):
            import OpenSSL  # python-openssl

            ThreadingServer.__init__(self, server_address, HandlerClass)
            ctx = OpenSSL.SSL.Context(OpenSSL.SSL.TLSv1_METHOD)
            ctx.use_privatekey_file(pem)
            ctx.use_certificate_file(pem)
            self.socket = OpenSSL.SSL.Connection(ctx, socket.socket(self.address_family, self.socket_type))
            self.server_bind()
            self.server_activate()

        def shutdown_request(self, request):
            try:
                request.shutdown()
            except:
                if config.SHOW_DEBUG:
                    traceback.print_exc()

    class ReqHandler(BaseHTTPServer.BaseHTTPRequestHandler):
        def do_GET(self):
            path, query = self.path.split('?', 1) if '?' in self.path else (self.path, "")
            params = {}
            content = None
            skip = False

            if hasattr(self, "data"):
                params.update(urlparse.parse_qs(self.data))

            if query:
                params.update(urlparse.parse_qs(query))

            for key in params:
                if params[key]:
                    params[key] = params[key][-1]

            if path == '/':
                path = "index.html"

            path = path.strip('/')
            extension = os.path.splitext(path)[-1].lower()

            if hasattr(self, "_%s" % path):
                content = getattr(self, "_%s" % path)(params)

            else:
                path = path.replace('/', os.path.sep)
                path = os.path.abspath(os.path.join(HTML_DIR, path)).strip()

                if not os.path.isfile(path) and os.path.isfile("%s.html" % path):
                    path = "%s.html" % path

                if ".." not in os.path.relpath(path, HTML_DIR) and os.path.isfile(path) and (extension not in DISABLED_CONTENT_EXTENSIONS or os.path.split(path)[-1] in CONTENT_EXTENSIONS_EXCLUSIONS):
                    mtime = time.gmtime(os.path.getmtime(path))
                    if_modified_since = self.headers.get(HTTP_HEADER.IF_MODIFIED_SINCE)

                    if if_modified_since and extension not in (".htm", ".html"):
                        if_modified_since = [_ for _ in if_modified_since.split(';') if _.upper().endswith("GMT")][0]
                        if time.mktime(mtime) <= time.mktime(time.strptime(if_modified_since, HTTP_TIME_FORMAT)):
                            self.send_response(httplib.NOT_MODIFIED)
                            self.send_header(HTTP_HEADER.CONNECTION, "close")
                            skip = True

                    if not skip:
                        content = open(path, "rb").read()
                        last_modified = time.strftime(HTTP_TIME_FORMAT, mtime)
                        self.send_response(httplib.OK)
                        self.send_header(HTTP_HEADER.CONNECTION, "close")
                        self.send_header(HTTP_HEADER.CONTENT_TYPE, mimetypes.guess_type(path)[0] or "application/octet-stream")
                        self.send_header(HTTP_HEADER.LAST_MODIFIED, last_modified)
                        if extension not in (".htm", ".html"):
                            self.send_header(HTTP_HEADER.EXPIRES, "Sun, 17-Jan-2038 19:14:07 GMT")        # Reference: http://blog.httpwatch.com/2007/12/10/two-simple-rules-for-http-caching/
                            self.send_header(HTTP_HEADER.CACHE_CONTROL, "max-age=3600, must-revalidate")  # Reference: http://stackoverflow.com/a/5084555
                        else:
                            self.send_header(HTTP_HEADER.CACHE_CONTROL, "no-cache")

                else:
                    self.send_response(httplib.NOT_FOUND)
                    self.send_header(HTTP_HEADER.CONNECTION, "close")
                    content = '<!DOCTYPE html><html lang="en"><head><title>404 Not Found</title></head><body><h1>Not Found</h1><p>The requested URL %s was not found on this server.</p></body></html>' % self.path.split('?')[0]

            if content is not None:
                for match in re.finditer(r"<\!(\w+)\!>", content):
                    name = match.group(1)
                    _ = getattr(self, "_%s" % name.lower(), None)
                    if _:
                        content = self._format(content, **{ name: _() })

                if "gzip" in self.headers.getheader(HTTP_HEADER.ACCEPT_ENCODING, ""):
                    self.send_header(HTTP_HEADER.CONTENT_ENCODING, "gzip")
                    _ = cStringIO.StringIO()
                    compress = gzip.GzipFile("", "w+b", 9, _)
                    compress._stream = _
                    compress.write(content)
                    compress.flush()
                    compress.close()
                    content = compress._stream.getvalue()

                self.send_header(HTTP_HEADER.CONTENT_LENGTH, str(len(content)))

            self.end_headers()

            if content:
                self.wfile.write(content)

            self.wfile.flush()
            self.wfile.close()

        def do_POST(self):
            length = self.headers.getheader(HTTP_HEADER.CONTENT_LENGTH)
            data = self.rfile.read(int(length))
            data = urllib.unquote_plus(data)
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
                        if SESSIONS[session].client_ip != self.client_address[0] or SESSIONS[session].client_ua != self.headers.get(HTTP_HEADER.USER_AGENT):
                            pass
                        elif SESSIONS[session].expiration > time.time():
                            retval = SESSIONS[session]
                        else:
                            del SESSIONS[session]

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
            return SERVER_HEADER

        def end_headers(self):
            if not hasattr(self, "_headers_ended"):
                BaseHTTPServer.BaseHTTPRequestHandler.end_headers(self)
                self._headers_ended = True

        def log_message(self, format, *args):
            return

        def finish(self):
            try:
                BaseHTTPServer.BaseHTTPRequestHandler.finish(self)
            except:
                if config.SHOW_DEBUG:
                    traceback.print_exc()

        def _version(self):
            return VERSION

        def _format(self, content, **params):
            if content:
                for key, value in params.items():
                    content = content.replace("<!%s!>" % key, value)

            return content

        def _login(self, params):
            valid = False

            if params.get("username") and params.get("hash") and params.get("nonce"):
                if params.get("nonce") not in DISPOSED_NONCES:
                    DISPOSED_NONCES.add(params.get("nonce"))
                    for entry in (config.USERS or []):
                        entry = re.sub(r"\s", "", entry)
                        username, stored_hash, uid, netfilter = entry.split(':')
                        if username == params.get("username"):
                            try:
                                if params.get("hash") == hashlib.sha256(stored_hash.strip() + params.get("nonce")).hexdigest():
                                    valid = True
                                    break
                            except:
                                if config.SHOW_DEBUG:
                                    traceback.print_exc()

            if valid:
                session_id = os.urandom(SESSION_ID_LENGTH).encode("hex")
                expiration = time.time() + 3600 * SESSION_EXPIRATION_HOURS

                self.send_response(httplib.OK)
                self.send_header(HTTP_HEADER.CONNECTION, "close")
                self.send_header(HTTP_HEADER.SET_COOKIE, "%s=%s; expires=%s; path=/; HttpOnly" % (SESSION_COOKIE_NAME, session_id, time.strftime(HTTP_TIME_FORMAT, time.gmtime(expiration))))

                if netfilter in ("", "0.0.0.0/0"):
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

                SESSIONS[session_id] = AttribDict({"username": username, "uid": uid, "netfilters": netfilters, "expiration": expiration, "client_ip": self.client_address[0], "client_ua": self.headers.get(HTTP_HEADER.USER_AGENT)})
            else:
                time.sleep(UNAUTHORIZED_SLEEP_TIME)
                self.send_response(httplib.UNAUTHORIZED)
                self.send_header(HTTP_HEADER.CONNECTION, "close")

            self.send_header(HTTP_HEADER.CONTENT_TYPE, "text/plain")
            content = "Login %s" % ("success" if valid else "failed")

            if not subprocess.mswindows:
                try:
                    subprocess.check_output("logger -p auth.info -t \"%s[%d]\" \"%s password for %s from %s port %s\"" % (NAME.lower(), os.getpid(), "Accepted" if valid else "Failed", params.get("username"), self.client_address[0], self.client_address[1]), stderr=subprocess.STDOUT, shell=True)
                except Exception:
                    if config.SHOW_DEBUG:
                        traceback.print_exc()

            return content

        def _logout(self, params):
            self.delete_session()
            self.send_response(httplib.FOUND)
            self.send_header(HTTP_HEADER.CONNECTION, "close")
            self.send_header(HTTP_HEADER.LOCATION, "/")

        def _whoami(self, params):
            session = self.get_session()
            username = session.username if session else ""

            self.send_response(httplib.OK)
            self.send_header(HTTP_HEADER.CONNECTION, "close")
            self.send_header(HTTP_HEADER.CONTENT_TYPE, "text/plain")

            return username

        def _check_ip(self, params):
            session = self.get_session()

            if session is None:
                self.send_response(httplib.UNAUTHORIZED)
                self.send_header(HTTP_HEADER.CONNECTION, "close")
                return None

            self.send_response(httplib.OK)
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
            self.send_response(httplib.OK)
            self.send_header(HTTP_HEADER.CONNECTION, "close")
            self.send_header(HTTP_HEADER.CONTENT_TYPE, "text/plain")

            return open(TRAILS_FILE, "rb").read()

        def _ping(self, params):
            self.send_response(httplib.OK)
            self.send_header(HTTP_HEADER.CONNECTION, "close")
            self.send_header(HTTP_HEADER.CONTENT_TYPE, "text/plain")

            return PING_RESPONSE

        def _events(self, params):
            session = self.get_session()

            if session is None:
                self.send_response(httplib.UNAUTHORIZED)
                self.send_header(HTTP_HEADER.CONNECTION, "close")
                return None

            start, end, size, total = None, None, -1, None
            content = None
            event_log_path = os.path.join(config.LOG_DIR, "%s.log" % params.get("date", ""))

            if os.path.exists(event_log_path):
                total = os.stat(event_log_path).st_size

                if self.headers.get(HTTP_HEADER.RANGE):
                    match = re.search(r"bytes=(\d+)-(\d+)", self.headers[HTTP_HEADER.RANGE])
                    if match:
                        start, end = int(match.group(1)), int(match.group(2))
                        max_size = end - start + 1
                        end = min(total - 1, end)
                        size = end - start + 1

                        if start == 0 or not session.range_handle:
                            session.range_handle = open(event_log_path, "rb")

                        if session.netfilters is None:
                            session.range_handle.seek(start)
                            self.send_response(httplib.PARTIAL_CONTENT)
                            self.send_header(HTTP_HEADER.CONNECTION, "close")
                            self.send_header(HTTP_HEADER.CONTENT_TYPE, "text/plain")
                            self.send_header(HTTP_HEADER.CONTENT_RANGE, "bytes %d-%d/%d" % (start, end, total))
                            content = session.range_handle.read(size)
                        else:
                            self.send_response(httplib.OK)
                            self.send_header(HTTP_HEADER.CONNECTION, "close")
                            self.send_header(HTTP_HEADER.CONTENT_TYPE, "text/plain")

                            buffer, addresses, netmasks, regex = cStringIO.StringIO(), set(), [], ""
                            for netfilter in session.netfilters:
                                if not netfilter:
                                    continue
                                if '/' in netfilter:
                                    netmasks.append(netfilter)
                                elif re.search(r"\A[\d.]+\Z", netfilter):
                                    addresses.add(netfilter)
                                elif '\.' in netfilter:
                                    regex = r" %s " % netfilter
                                else:
                                    print "[!] invalid network filter '%s'" % netfilter
                                    return

                            for line in session.range_handle:
                                display = False

                                if regex and re.search(regex, line):
                                    display = True
                                elif addresses or netmasks:
                                    for match in re.finditer(r" (\d+\.\d+\.\d+\.\d+) ", line):
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

                                if display:
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
                    self.send_response(httplib.OK)
                    self.send_header(HTTP_HEADER.CONNECTION, "close")
                    self.send_header(HTTP_HEADER.CONTENT_TYPE, "text/plain")
                    self.end_headers()

                    with open(event_log_path, "rb") as f:
                        while True:
                            data = f.read(io.DEFAULT_BUFFER_SIZE)
                            if not data:
                                break
                            else:
                                self.wfile.write(data)

            else:
                self.send_response(httplib.OK)  # instead of httplib.NO_CONTENT (compatibility reasons)
                self.send_header(HTTP_HEADER.CONNECTION, "close")
                if self.headers.get(HTTP_HEADER.RANGE):
                    self.send_header(HTTP_HEADER.CONTENT_RANGE, "bytes 0-0/0")

            return content

        def _counts(self, params):
            counts = {}

            session = self.get_session()

            if session is None:
                self.send_response(httplib.UNAUTHORIZED)
                self.send_header(HTTP_HEADER.CONNECTION, "close")
                return None

            self.send_response(httplib.OK)
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
                                total = 1.0 * content.count('\n') * size / io.DEFAULT_BUFFER_SIZE
                                counts[timestamp] = int(round(total / 100) * 100)
                            else:
                                counts[timestamp] = content.count('\n')

            return json.dumps(counts)

    class SSLReqHandler(ReqHandler):
        def setup(self):
            self.connection = self.request
            self.rfile = socket._fileobject(self.request, "rb", self.rbufsize)
            self.wfile = socket._fileobject(self.request, "wb", self.wbufsize)

    try:
        if pem:
            server = SSLThreadingServer((address or '', int(port) if str(port or "").isdigit() else 0), pem, SSLReqHandler)
        else:
            server = ThreadingServer((address or '', int(port) if str(port or "").isdigit() else 0), ReqHandler)
    except Exception as ex:
        if "Address already in use" in str(ex):
            exit("[!] another instance already running")
        elif "Name or service not known" in str(ex):
            exit("[!] invalid configuration value for 'HTTP_ADDRESS' ('%s')" % config.HTTP_ADDRESS)
        elif "Cannot assign requested address" in str(ex):
            exit("[!] can't use configuration value for 'HTTP_ADDRESS' ('%s')" % config.HTTP_ADDRESS)
        else:
            raise

    print "[i] starting HTTP%s server at 'http%s://%s:%d/'" % ('S' if pem else "", 's' if pem else "", server.server_address[0], server.server_address[1])

    print "[o] running..."

    if join:
        server.serve_forever()
    else:
        thread = threading.Thread(target=server.serve_forever)
        thread.daemon = True
        thread.start()
