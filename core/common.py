#!/usr/bin/env python

"""
Copyright (c) 2014-2025 Maltrail developers (https://github.com/stamparm/maltrail/)
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

from core.addr import addr_to_int
from core.addr import int_to_addr
from core.compat import xrange
from core.settings import config
from core.settings import BOGON_IPS
from core.settings import BOGON_RANGES
from core.settings import CHECK_CONNECTION_URL
from core.settings import CDN_RANGES
from core.settings import IPCAT_SQLITE_FILE
from core.settings import IS_WIN
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

_ipcat_cache = {}

def retrieve_content(url, data=None, headers=None):
    """
    Retrieves page content from given URL
    """

    try:
        req = _urllib.request.Request("".join(url[i].replace(' ', "%20") if i > url.find('?') else url[i] for i in xrange(len(url))), data, headers or {"User-agent": USER_AGENT, "Accept-encoding": "gzip, deflate"})
        resp = _urllib.request.urlopen(req, timeout=TIMEOUT)
        retval = resp.read()
        encoding = resp.headers.get("Content-Encoding")

        if encoding:
            if encoding.lower() == "deflate":
                data = io.BytesIO(zlib.decompress(retval, -15))
            elif encoding.lower() == "gzip":
                data = gzip.GzipFile("", "rb", 9, io.BytesIO(retval))
            retval = data.read()
    except Exception as ex:
        retval = ex.read() if hasattr(ex, "read") else (get_ex_message(ex) or "")

        if url.startswith("https://") and isinstance(retval, str) and "handshake failure" in retval:
            return retrieve_content(url.replace("https://", "http://"), data, headers)

    retval = retval or b""

    if six.PY3 and isinstance(retval, bytes):
        retval = retval.decode(UNICODE_ENCODING, errors="replace")

    return retval

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
                except:
                    raise ValueError("[x] invalid IP address '%s'" % address)

                _ipcat_cache[address] = retval

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

def load_trails(quiet=False):
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

    if not quiet:
        _ = len(retval)
        try:
            _ = '{0:,}'.format(_)
        except:
            pass
        print("[i] %s trails loaded" % _)

    return retval

def get_text(value):
    retval = value

    if six.PY2:
        try:
            retval = str(retval)
        except:
            pass
    else:
        if isinstance(value, six.binary_type):
            retval = value.decode(UNICODE_ENCODING, errors="replace")

    return retval

def get_ex_message(ex):
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
