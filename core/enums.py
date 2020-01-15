#!/usr/bin/env python

"""
Copyright (c) 2014-2020 Maltrail developers (https://github.com/stamparm/maltrail/)
See the file 'LICENSE' for copying permission
"""

import sys

from thirdparty import six

class _(type):
   def __getattr__(self, attr):
     return attr

@six.add_metaclass(_)
class TRAIL(object):
    pass

if sys.version_info >= (3, 0):
    class BLOCK_MARKER:
        NOP = 0x00
        READ = 0x01
        WRITE = 0x02
        END = 0xff
else:
    class BLOCK_MARKER:
        NOP = b'\x00'
        READ = b'\x01'
        WRITE = b'\x02'
        END = b'\xff'

class PROTO:
    TCP = "TCP"
    UDP = "UDP"
    ICMP = "ICMP"

class HTTP_HEADER:
    ACCEPT = "Accept"
    ACCEPT_CHARSET = "Accept-Charset"
    ACCEPT_ENCODING = "Accept-Encoding"
    ACCEPT_LANGUAGE = "Accept-Language"
    AUTHORIZATION = "Authorization"
    CACHE_CONTROL = "Cache-Control"
    CONNECTION = "Connection"
    CONTENT_ENCODING = "Content-Encoding"
    CONTENT_LENGTH = "Content-Length"
    CONTENT_RANGE = "Content-Range"
    CONTENT_TYPE = "Content-Type"
    CONTENT_SECURITY_POLICY = "Content-Security-Policy"
    COOKIE = "Cookie"
    EXPIRES = "Expires"
    HOST = "Host"
    IF_MODIFIED_SINCE = "If-Modified-Since"
    LAST_MODIFIED = "Last-Modified"
    LOCATION = "Location"
    PRAGMA = "Pragma"
    PROXY_AUTHORIZATION = "Proxy-Authorization"
    PROXY_CONNECTION = "Proxy-Connection"
    RANGE = "Range"
    REFERER = "Referer"
    SERVER = "Server"
    SET_COOKIE = "Set-Cookie"
    TRANSFER_ENCODING = "Transfer-Encoding"
    URI = "URI"
    USER_AGENT = "User-Agent"
    VIA = "Via"
    X_POWERED_BY = "X-Powered-By"

class CACHE_TYPE:
    DOMAIN = 0
    USER_AGENT = 1
    PATH = 2
    POST_DATA = 3
    DOMAIN_WHITELISTED = 4
