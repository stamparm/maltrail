#!/usr/bin/env python

"""
Copyright (c) 2014-2015 Miroslav Stampar (@stamparm)
See the file 'LICENSE' for copying permission
"""

import BaseHTTPServer
import datetime
import httplib
import glob
import io
import json
import mimetypes
import os
import re
import shlex
import socket
import SocketServer
import subprocess
import sys
import threading
import time
import traceback
import urllib
import urlparse
import zlib

from core.attribdict import AttribDict
from core.common import addr_to_int
from core.common import int_to_addr
from core.common import make_mask
from core.pbkdf2 import pbkdf2
from core.settings import config
from core.settings import DATE_FORMAT
from core.settings import DEBUG
from core.settings import DEFLATE_COMPRESS_LEVEL
from core.settings import DISABLED_CONTENT_EXTENSIONS
from core.settings import HTML_DIR
from core.settings import HTTP_TIME_FORMAT
from core.settings import SERVER_HEADER
from core.settings import SESSION_EXPIRATION_HOURS
from core.settings import SESSION_ID_LENGTH
from core.settings import SESSIONS
from core.settings import TRAILS_FILE
from core.settings import UNAUTHORIZED_SLEEP_TIME

def start_httpd(address=None, port=None, join=False, pem=None):
    """
    Starts HTTP server
    """

    class ThreadingServer(SocketServer.ThreadingMixIn, BaseHTTPServer.HTTPServer):
        def finish_request(self, *args, **kwargs):
            try:
                BaseHTTPServer.HTTPServer.finish_request(self, *args, **kwargs)
            except:
                if DEBUG:
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
                if DEBUG:
                    traceback.print_exc()

    class ReqHandler(BaseHTTPServer.BaseHTTPRequestHandler):
        def do_GET(self):
            path, query = self.path.split('?', 1) if '?' in self.path else (self.path, "")
            params = {}
            content = None

            if hasattr(self, "data"):
                params.update(urlparse.parse_qs(self.data))

            if query:
                params.update(urlparse.parse_qs(query))

            for key in params:
                if params[key]:
                    params[key] = params[key][-1]

            if os.path.dirname(path).lower() == "/cgi-bin":
                path = path.strip('/').lower()
                cgi_path = os.path.join(HTML_DIR, "cgi-bin", os.path.basename(path))

                if not os.path.isfile(cgi_path):
                    self.send_response(httplib.NOT_FOUND)
                    self.send_header("Connection", "close")
                    return

                args = " ".join("--%s=\'%s\'" % (_[0], _[1]) for _ in params.items())
                args = re.sub(r"(?i)='true'", "", args)
                cmd = "%s %s %s" % (sys.executable, os.path.join(HTML_DIR, "cgi-bin", os.path.basename(path)), args)
                process = subprocess.Popen(shlex.split(cmd, posix=not subprocess.mswindows), shell=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

                self.send_response(httplib.OK)
                self.send_header("Connection", "close")
                self.send_header("Content-Type", "text/plain")

                compress = None
                if "deflate" in self.headers.getheader("Accept-Encoding", ""):
                    self.send_header("Content-Encoding", "deflate")
                    self.end_headers()
                    compress = zlib.compressobj(DEFLATE_COMPRESS_LEVEL)
                else:
                    self.end_headers()

                while True:
                    data = process.stdout.read(io.DEFAULT_BUFFER_SIZE)
                    if not data:
                        break
                    else:
                        self.wfile.write(compress.compress(data) if compress else data)

                if compress:
                    self.wfile.write(compress.flush())

                content = None

            else:
                if path == '/':
                    path = "index.html"

                path = path.strip('/')

                if hasattr(self, "_%s" % path):
                    content = getattr(self, "_%s" % path)(params)

                else:
                    path = path.replace('/', os.path.sep)
                    path = os.path.abspath(os.path.join(HTML_DIR, path)).strip()

                    if ".." not in os.path.relpath(path, HTML_DIR) and os.path.isfile(path) and not path.endswith(DISABLED_CONTENT_EXTENSIONS):
                        mtime = time.gmtime(os.path.getmtime(path))
                        if_modified_since = self.headers.get("If-Modified-Since")

                        if if_modified_since:
                            if time.mktime(mtime) <= time.mktime(time.strptime(if_modified_since, HTTP_TIME_FORMAT)):
                                self.send_response(httplib.NOT_MODIFIED)
                                self.send_header("Connection", "close")
                                return

                        content = open(path, "rb").read()
                        last_modified = time.strftime(HTTP_TIME_FORMAT, mtime)
                        self.send_response(httplib.OK)
                        self.send_header("Connection", "close")
                        self.send_header("Content-Type", mimetypes.guess_type(path)[0] or "application/octet-stream")
                        self.send_header("Last-Modified", last_modified)
                        self.send_header("Expires", "Sun, 17-Jan-2038 19:14:07 GMT")   # Reference: http://blog.httpwatch.com/2007/12/10/two-simple-rules-for-http-caching/
                        self.send_header("Cache-Control", "must-revalidate, private")  # Reference: http://stackoverflow.com/a/5084555

                    else:
                        self.send_response(httplib.NOT_FOUND)
                        self.send_header("Connection", "close")
                        return

            if content is not None:
                length = len(content)

                if "deflate" in self.headers.getheader("Accept-Encoding", ""):
                    self.send_header("Content-Encoding", "deflate")
                    content = zlib.compress(content, DEFLATE_COMPRESS_LEVEL)

                self.send_header("Content-Length", str(length))
                self.end_headers()
                self.wfile.write(content)
                self.wfile.flush()

        def do_POST(self):
            length = self.headers.getheader("Content-Length")
            data = self.rfile.read(int(length))
            data = urllib.unquote_plus(data)
            self.data = data
            self.do_GET()

        def get_session(self):
            retval = None
            cookie = self.headers.get("Cookie")

            if cookie:
                match = re.search(r"session=(.+)", cookie)
                if match:
                    session = match.group(1)
                    if session in SESSIONS:
                        if SESSIONS[session].expiration > time.time():
                            retval = SESSIONS[session]
                        else:
                            del SESSIONS[session]

            return retval

        def delete_session(self):
            cookie = self.headers.get("Cookie")

            if cookie:
                match = re.search(r"session=(.+)", cookie)
                if match:
                    session = match.group(1)
                    if session in SESSIONS:
                        del SESSIONS[session]

        def version_string(self):
            return SERVER_HEADER

        def log_message(self, format, *args):
            return

        def finish(self):
            try:
                BaseHTTPServer.BaseHTTPRequestHandler.finish(self)
            except:
                if DEBUG:
                    traceback.print_exc()

        def _login(self, params):
            valid = False

            if params.get("username") and params.get("password"):
                for entry in (config.USERS or []):
                    entry = re.sub(r"\s", "", entry)
                    username, stored_hash, uid, netfilter = entry.split(':')
                    hash_parts = stored_hash.split('$')
                    if username == params.get("username"):
                        try:
                            if (pbkdf2(params.get("password"), hash_parts[1].decode("hex"), int(hash_parts[2])).encode("hex") == hash_parts[3]):
                                valid = True
                                break
                        except:
                            if DEBUG:
                                traceback.print_exc()

            if valid:
                session_id = os.urandom(SESSION_ID_LENGTH).encode("hex")
                expiration = time.time() + 3600 * SESSION_EXPIRATION_HOURS
                self.send_response(httplib.OK)
                self.send_header("Connection", "close")
                self.send_header("Set-Cookie", "session=%s; expires=%s; path=/; HttpOnly" % (session_id, time.strftime(HTTP_TIME_FORMAT, time.gmtime(expiration))))
                if '/' in netfilter:
                    _ = netfilter.split('/')[-1]
                    if _.isdigit() and int(_) >= 20:
                        lower = addr_to_int(netfilter.split('/')[0])
                        mask = make_mask(int(_))
                        upper = lower | (0xffffffff ^ mask)
                        _ = []
                        for i in xrange(lower, upper + 1):
                            _.append(int_to_addr(i))
                        netfilter = ','.join(_)
                SESSIONS[session_id] = AttribDict({"username": username, "uid": uid, "netfilter": netfilter, "expiration": expiration})
            else:
                time.sleep(UNAUTHORIZED_SLEEP_TIME)
                self.send_response(httplib.UNAUTHORIZED)
                self.send_header("Connection", "close")

            self.send_header("Content-Type", "text/plain")
            content = "Login %s" % ("success" if valid else "failed")

            return content

        def _logout(self, params):
            self.delete_session()
            self.send_response(httplib.FOUND)
            self.send_header("Connection", "close")
            self.send_header("Location", "/")

        def _whoami(self, params):
            session = self.get_session()
            username = session.username if session else ""

            self.send_response(httplib.OK)
            self.send_header("Connection", "close")
            self.send_header("Content-Type", "text/plain")

            return username

        def _trails(self, params):
            self.send_response(httplib.OK)
            self.send_header("Connection", "close")
            self.send_header("Content-Type", "text/plain")

            return open(TRAILS_FILE, "rb").read()

        def _events(self, params):
            session = self.get_session()

            if session is None:
                self.send_response(httplib.UNAUTHORIZED)
                self.send_header("Connection", "close")
                self.end_headers()
                return None

            start, end, size, total = None, None, -1, None
            content = None
            log_path = os.path.join(config.LOG_DIRECTORY, "%s.log" % params.get("date", ""))

            if os.path.exists(log_path):
                total = os.stat(log_path).st_size

                if self.headers.get("Range"):
                    match = re.search(r"bytes=(\d+)-(\d+)", self.headers["Range"])
                    if match:
                        start, end = int(match.group(1)), int(match.group(2))
                        max_size = end - start + 1
                        end = min(total - 1, end)
                        size = end - start + 1

                        if start == 0 or not session.range_handle:
                            session.range_handle = open(log_path, "rb")

                        self.send_response(httplib.OK)
                        self.send_header("Connection", "close")
                        self.send_header("Content-Type", "text/plain")

                        if session.netfilter in (None, "", "0.0.0.0/0"):
                            session.range_handle.seek(start)
                            self.send_response(httplib.PARTIAL_CONTENT)
                            self.send_header("Content-Range", "bytes %d-%d/%d" % (start, end, total))
                            content = session.range_handle.read(size)
                        else:
                            content, addresses, netmasks = "", set(), []
                            for _ in set(re.split(r"[;,]", session.netfilter)):
                                _ = _.strip()
                                if not _:
                                    continue
                                if '/' in _:
                                    netmasks.append(_)
                                elif re.search(r"\A[\d.]+\Z", _):
                                    addresses.add(_)
                                elif re.search(r"\A([\d.]+)\s*-\s*([\d.]+)\Z", _):
                                    _ = _.replace(" ", "")
                                    start_address, end_address = _.split('-')
                                    for address in xrange(addr_to_int(start_address), addr_to_int(end_address) + 1):
                                        addresses.add(int_to_addr(address))
                                else:
                                    print "[!] invalid network filter '%s'" % _
                                    return

                            for line in session.range_handle.xreadlines():
                                display = False
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
                                    content += line
                                    if len(content) >= max_size:
                                        break

                            end = start + len(content) - 1
                            self.send_header("Content-Range", "bytes %d-%d/%d" % (start, end, end + 1 + max_size * (len(content) >= max_size)))

                        if len(content) < max_size:
                            session.range_handle.close()
                            session.range_handle = None

                if size == -1:
                    self.send_response(httplib.OK)
                    self.send_header("Connection", "close")
                    self.send_header("Content-Type", "text/plain")
                    self.end_headers()

                    with open(log_path, "rb") as f:
                        while True:
                            data = f.read(io.DEFAULT_BUFFER_SIZE)
                            if not data:
                                break
                            else:
                                self.wfile.write(data)

            return content

        def _counts(self, params):
            counts = {}

            session = self.get_session()

            if session is None:
                self.send_response(httplib.UNAUTHORIZED)
                self.send_header("Connection", "close")
                self.end_headers()
                return None

            self.send_response(httplib.OK)
            self.send_header("Connection", "close")
            self.send_header("Content-Type", "application/json")

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

            for filename in sorted(glob.glob(os.path.join(config.LOG_DIRECTORY, "*.log"))):
                try:
                    current = datetime.datetime.strptime(os.path.splitext(os.path.basename(filename))[0], DATE_FORMAT)
                except:
                    if DEBUG:
                        traceback.print_exc()
                else:
                    if min_ <= current <= max_:
                        timestamp = int(time.mktime(current.timetuple()))
                        size = os.path.getsize(filename)
                        with open(filename, "rb") as f:
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

    if pem:
        server = SSLThreadingServer((address or '', int(port) if port else None), pem, SSLReqHandler)
    else:
        server = ThreadingServer((address or '', int(port) if port else None), ReqHandler)

    print "[i] running HTTP%s server at '%s:%d'" % ('S' if pem else "", server.server_address[0], server.server_address[1])

    if join:
        server.serve_forever()
    else:
        thread = threading.Thread(target=server.serve_forever)
        thread.daemon = True
        thread.start()
