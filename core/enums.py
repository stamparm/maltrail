#!/usr/bin/env python

"""
Copyright (c) 2014-present Maltrail developers (https://github.com/stamparm/maltrail/)
See the file 'LICENSE' for copying permission
"""


class _(type):
    def __getattr__(self, attr):
        return attr

class TRAIL(object, metaclass=_):
    pass

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
    ETAG = "ETag"
    EXPIRES = "Expires"
    HOST = "Host"
    IF_MODIFIED_SINCE = "If-Modified-Since"
    IF_NONE_MATCH = "If-None-Match"
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
    VARY = "Vary"
    VIA = "Via"
    X_POWERED_BY = "X-Powered-By"

class CACHE_TYPE:
    DOMAIN = 0
    USER_AGENT = 1
    PATH = 2
    POST_DATA = 3
    DOMAIN_WHITELISTED = 4
    LOCAL_PREFIX = 5

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
    OLIVE = "\033[48;5;100m"   # 256-colour; the 8-colour backgrounds are all spoken for
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
