#!/usr/bin/env python

"""
Copyright (c) 2014-2026 Maltrail developers (https://github.com/stamparm/maltrail/)
See the file 'LICENSE' for copying permission
"""

# Reading an event log line, whichever format it is written in.
#
# LOCAL_LOG_FORMAT (issue #19130) lets an operator write the event log as JSON so a SIEM can read
# it without a bespoke decoder. That makes a LOG_DIR a mixed directory: flip the option on Tuesday
# and Monday's text logs sit next to Tuesday's JSON, and every reader has to cope with both or the
# history silently becomes unreadable - which would be a worse bug than the one being fixed.
#
# So format is decided PER LINE, not from the configuration. The configuration says what to write;
# what to read is whatever is actually there.
#
# Every reader goes through fields() and sees the same eleven values in the same order the text
# format has always used, so nothing downstream of this module has to know which format it came
# from.

import json

FIELDS = ("time", "sensor", "src_ip", "src_port", "dst_ip", "dst_port", "proto", "type", "trail", "info", "reference")

def is_json_line(line):
    """Is this line a JSON event?

    A text event line starts with the timestamp, which safe_value() quotes because it contains a
    space - so it begins with '"'. A JSON object begins with '{'. Nothing else can start a valid
    line of either kind, which is what makes one character enough.
    """

    if isinstance(line, bytes):
        return line[:1] == b"{"
    return line[:1] == "{"

def split_text_line(line):
    """Split a text event line the way `core/log.py:safe_value()` quoted it.

    Kept here rather than imported from core/index.py so that module can depend on this one and
    not the reverse; core/index.py keeps its own copy for the hot indexing loop.
    """

    fields = []
    parts = []
    quoted = False
    i = 0
    while i < len(line):
        ch = line[i]
        if quoted:
            if ch == '"':
                if line[i + 1:i + 2] == '"':
                    parts.append('"')
                    i += 2
                    continue
                quoted = False
            else:
                parts.append(ch)
        elif ch == '"':
            quoted = True
        elif ch == ' ':
            fields.append("".join(parts))
            parts = []
        elif ch in "\r\n":
            break
        else:
            parts.append(ch)
        i += 1
    fields.append("".join(parts))
    return fields

def fields(line):
    """The eleven event fields of `line`, in FIELDS order, or None if it is not an event line.

    Values are text in both formats: a JSON port is a number and a text port is a string, and a
    caller comparing against "22" must not have to care which it got.
    """

    if isinstance(line, bytes):
        try:
            line = line.decode("utf8", "replace")
        except Exception:
            return None

    if not is_json_line(line):
        values = split_text_line(line)
        return values[:len(FIELDS)] if len(values) >= len(FIELDS) else None

    try:
        obj = json.loads(line)
    except Exception:
        return None
    if not isinstance(obj, dict):
        return None

    out = []
    for name in FIELDS:
        value = obj.get(name)
        if value is None and name == "time":
            # a JSON line written by LOGSTASH_SERVER rather than by the local log has no "time";
            # falling back to the epoch keeps such a line readable instead of discarding it
            value = obj.get("timestamp")
        if value is None:
            return None
        out.append(value if isinstance(value, str) else str(value))
    return out

def severity_of_line(line):
    """The severity a JSON line carries, or None for a text line (which has never had one)."""

    if not is_json_line(line):
        return None
    try:
        obj = json.loads(line if not isinstance(line, bytes) else line.decode("utf8", "replace"))
    except Exception:
        return None
    return obj.get("severity") if isinstance(obj, dict) else None

def redact_json(line, mask_custom, ip):
    """The JSON equivalent of the two rewrites `_filter_events` performs on a text line.

    Both of those are regexes over the raw text, and neither survives contact with JSON:

    * the custom-trail mask, `("[^"]+"|[^ ]+) \\(custom\\)` -> `- (custom)`, matches
      `"supersecretname (custom)` INSIDE the JSON string and leaves `"info": - (custom)"`. The
      secret does go, so this is not a disclosure - but the line stops being valid JSON and the
      reader that has to parse it gets nothing at all.
    * the address-list collapse expects spaces around the list, which JSON does not have, so it
      silently does nothing and a restricted analyst sees the other addresses in the list.

    Doing it on the parsed object is both correct and shorter. Key order is preserved so the line
    still reads like the one that was written.
    """

    try:
        obj = json.loads(line, object_pairs_hook=_ordered)
    except Exception:
        return line     # not parseable: hand it on untouched rather than lose the event
    if not isinstance(obj, dict):
        return line

    changed = False

    # `info` is where a custom trail's NAME appears ("supersecretname (custom)"); the trail field
    # itself is the address or domain and is not the secret.
    if mask_custom and obj.get("reference") == "(custom)" and obj.get("info") != "-":
        obj["info"] = "-"
        changed = True

    if ip:
        for key in ("src_ip", "dst_ip"):
            value = obj.get(key)
            if isinstance(value, str) and ',' in value and ip in value.split(','):
                obj[key] = ip
                changed = True

    return json.dumps(obj) if changed else line

try:
    from collections import OrderedDict as _ordered
except ImportError:      # pragma: no cover
    _ordered = dict
