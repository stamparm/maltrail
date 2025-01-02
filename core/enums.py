#!/usr/bin/env python

"""
Copyright (c) 2014-2025 Maltrail developers (https://github.com/stamparm/maltrail/)
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
    LOCAL_PREFIX = 4

class COLOR:
    BLUE = "\033[34m"
    BOLD_MAGENTA = "\033[35;1m"
    BOLD_GREEN = "\033[32;1m"
    BOLD_LIGHT_MAGENTA = "\033[95;1m"
    LIGHT_GRAY = "\033[37m"
    BOLD_RED = "\033[31;1m"
    BOLD_LIGHT_GRAY = "\033[37;1m"
    YELLOW = "\033[33m"
    DARK_GRAY = "\033[90m"
    BOLD_CYAN = "\033[36;1m"
    LIGHT_RED = "\033[91m"
    CYAN = "\033[36m"
    MAGENTA = "\033[35m"
    LIGHT_MAGENTA = "\033[95m"
    LIGHT_GREEN = "\033[92m"
    RESET = "\033[0m"
    BOLD_DARK_GRAY = "\033[90;1m"
    BOLD_LIGHT_YELLOW = "\033[93;1m"
    BOLD_LIGHT_RED = "\033[91;1m"
    BOLD_LIGHT_GREEN = "\033[92;1m"
    LIGHT_YELLOW = "\033[93m"
    BOLD_LIGHT_BLUE = "\033[94;1m"
    BOLD_LIGHT_CYAN = "\033[96;1m"
    LIGHT_BLUE = "\033[94m"
    BOLD_WHITE = "\033[97;1m"
    LIGHT_CYAN = "\033[96m"
    BLACK = "\033[30m"
    BOLD_YELLOW = "\033[33;1m"
    BOLD_BLUE = "\033[34;1m"
    GREEN = "\033[32m"
    WHITE = "\033[97m"
    BOLD_BLACK = "\033[30;1m"
    RED = "\033[31m"
    UNDERLINE = "\033[4m"

class BACKGROUND:
    BLUE = "\033[44m"
    LIGHT_GRAY = "\033[47m"
    YELLOW = "\033[43m"
    DARK_GRAY = "\033[100m"
    LIGHT_RED = "\033[101m"
    CYAN = "\033[46m"
    MAGENTA = "\033[45m"
    LIGHT_MAGENTA = "\033[105m"
    LIGHT_GREEN = "\033[102m"
    RESET = "\033[0m"
    LIGHT_YELLOW = "\033[103m"
    LIGHT_BLUE = "\033[104m"
    LIGHT_CYAN = "\033[106m"
    BLACK = "\033[40m"
    GREEN = "\033[42m"
    WHITE = "\033[107m"
    RED = "\033[41m"

class SEVERITY:
    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
