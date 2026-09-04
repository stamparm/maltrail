#!/usr/bin/env python

"""
Copyright (c) 2014-present Maltrail developers (https://github.com/stamparm/maltrail/)
See the file 'LICENSE' for copying permission
"""

import sys

if sys.version_info >= (3, 0):
    xrange = range
else:
    xrange = xrange


def is_decimal(value):
    """True if `value` is something int() will actually accept, using isdigit()'s notion of shape.

    `str.isdigit()` is NOT an int() guard, and was being used as one all over this codebase.
    isdigit() is true for 128 characters int() rejects, including the latin-1 superscripts
    U+00B2/B3/B9 - single bytes, so they survive the latin-1 decoding http.server applies to
    header values. That is how `Last-Event-ID: \xb2` reached int() and raised ValueError inside a
    request handler, and how `UPDATE_PERIOD \xb2` tracebacked out of read_config() instead of
    being reported as a bad value.

    The shape test stays isdigit(), NOT an ASCII-only check: int() accepts every Unicode decimal
    digit, so `HTTP_PORT \u0661\u0662\u0663` has always meant port 123 and still does. Narrowing to
    ASCII here would have silently rejected 670 characters that used to work - a behaviour change
    dressed up as a bug fix. Accepting exactly what int() accepts is the whole point.
    """

    text = value if isinstance(value, str) else "%s" % value
    if not text.isdigit():
        return False
    try:
        int(text)
        return True
    except ValueError:      # isdigit() is true for 128 characters int() refuses
        return False
