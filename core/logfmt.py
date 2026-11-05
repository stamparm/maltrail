#!/usr/bin/env python

"""
Copyright (c) 2014-present Maltrail developers (https://github.com/stamparm/maltrail/)
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

import csv
import json
import re

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

    safe_value() quotes a field holding a space or a quote and doubles the quotes inside, which
    is exactly csv's dialect with a space for a delimiter - so the C reader does it, in a third
    of the time the character loop below took. That loop was 9.7 s of a 1M-event day's first
    /fail2ban (and every /blacklist and /hunt scan), with the interpreter lock held throughout.
    The loop stays as the fallback for what csv refuses (an oversized field, a NUL byte): the
    reader must never lose an event the writer produced.
    """

    try:
        return next(csv.reader([line.partition("\n")[0].partition("\r")[0]], delimiter=" ", quotechar='"', doublequote=True, strict=False))
    except (csv.Error, StopIteration):
        return _split_text_line_slow(line)


def _split_text_line_slow(line):
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

_MORE = re.compile(r" \(\+(\d+) more\)\Z")


def events_in(line):
    """How many events one log line stands for - html/js/engine.js:rowWeight, so the day picker's
    count and the dashboard's agree. A throttled or condensed line writes each field its events
    differed in as a comma list (one source port per connection) and the overflow as "(+N more)".

    >>> events_in(b'"2026-11-04 00:04:02.1" s 1.2.3.4 32788,32814,53170 10.0.0.1 80 TCP IP 1.2.3.4 "known attacker" (static)')
    3
    >>> events_in('"2026-11-04 00:04:02.1" s 1.2.3.4 1 10.0.0.1 53 UDP DNS x.biz "long domain (suspicious) (+5 more)" (heuristic)')
    6
    >>> events_in('"2026-11-04 00:04:02.1" s 1.2.3.4 1 10.0.0.1 80 TCP PATH "/a, /b, /c" "web scanning, maybe" (heuristic)')
    1
    """

    probe = line if isinstance(line, bytes) else line.encode("utf8", "replace")
    # A text line opens with a quoted "date time", then sensor, src, sport, dst, dport, proto - none
    # of which can contain a space - so the four list-carrying fields are tokens 4-7, read without
    # parsing the line. Parsing every line made /counts 12x slower: almost every reputation hit has a
    # comma in its reference ("abuseipdb.com (+blocklist.de,dshield.org)").
    parts = probe.split(b" ", 8)
    if len(parts) == 9 and parts[0][:1] == b'"' and parts[1][-1:] == b'"' and parts[2][:1] != b'"':
        weight = max(1, max(_.count(b",") + 1 for _ in parts[4:8]))
        if b" more)" not in parts[8]:
            return weight
    elif b"," not in probe and b"more)" not in probe:
        return 1
    values = fields(line)
    if values is None:
        return 1
    weight = max(1, max(len(_.split(",")) for _ in values[3:7]))
    match = _MORE.search(values[9].rstrip())
    return weight + (int(match.group(1)) if match else 0)


# The lines events_in() may weigh above 1: a comma in sport/dst/dport/proto (the 4 tokens after
# "date time", sensor, src), a "(+N more)", or a JSON line. Found by the regex engine and bytes.find,
# so a file costs a newline count plus its condensed lines - parsing every line in Python made /counts
# 12x slower, and one regex scanning each line to its end for "more)" was no better.
# Anchored on a literal "\n" rather than ^ with re.M: the engine then skips from line to line instead
# of trying every byte, which halved its time (0.52 s for a million lines).
_LISTED = re.compile(br'\n"[^"\n]*" [^ \n]+ [^ \n]+ (?:[^ \n]+ ){0,3}[^ \n]*,')


def count_events(handle):
    """events_in() summed over a binary file handle.

    >>> import io
    >>> count_events(io.BytesIO(b'"2026-11-04 00:04:02.1" s 1.2.3.4 1,2,3 10.0.0.1 80 TCP IP 1.2.3.4 "known attacker" "a (+b,c)"\\n'
    ...                         b'"2026-11-04 00:04:03.1" s 1.2.3.4 9 10.0.0.1 53 UDP DNS x.biz "long domain (+2 more)" (h)\\n'
    ...                         b'{"src_port": "7,8", "info": "x"}\\n'))
    7
    """

    count = 0
    while True:
        chunk = handle.read(1024 * 1024)
        if not chunk:
            return count
        if not chunk.endswith(b"\n"):
            chunk += handle.readline()      # never split a line between two chunks
        count += chunk.count(b"\n") + (0 if chunk.endswith(b"\n") else 1)
        # scanned with a "\n" in front, so a match's start IS its line's start in `chunk`
        starts = set(match.start() for match in _LISTED.finditer(b"\n" + chunk))
        if chunk[:1] == b"{":
            starts.add(0)
        for needle, back in ((b"\n{", False), (b" more)", True)):
            at = chunk.find(needle)
            while at != -1:
                starts.add(chunk.rfind(b"\n", 0, at) + 1 if back else at + 1)
                at = chunk.find(needle, at + 1)
        for start in starts:
            end = chunk.find(b"\n", start)
            count += events_in(chunk[start:end if end != -1 else len(chunk)]) - 1


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
