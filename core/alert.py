#!/usr/bin/env python

"""
Copyright (c) 2014-present Maltrail developers (https://github.com/stamparm/maltrail/)
See the file 'LICENSE' for copying permission
"""

import csv
import json
import os
import threading
import time
import traceback

from core import logfmt
from core.common import retrieve_content
from core.log import log_error
from core.log import severity_of
from core.settings import config
from core.settings import ALERT_POLL_PERIOD
from core.settings import ALERT_SEVERITY_ORDER
from core.settings import MAX_ALERT_THROTTLE_KEYS
from core.settings import UNICODE_ENCODING

# Outbound notification for events worth waking someone up for.
#
# It tails the daily event log rather than hooking the event path, because there is no single event
# path to hook: a local Rust sensor writes its own log file, a remote one arrives as a UDP datagram
# handled in log.py, and core/log.py:log_event() - which already feeds SYSLOG_SERVER and
# LOGSTASH_SERVER - is only reached by the retired Python sensor. The log file is the one place every
# event passes through, whoever produced it.
#
# Severity comes from REMOTE_SEVERITY_REGEX, the same classification SYSLOG_SERVER and
# LOGSTASH_SERVER already use, so an operator tunes one regex, not two.

_throttle = {}
_throttle_lock = threading.Lock()

# The event log's fields after the leading quoted timestamp. safe_value() writes them CSV-style with
# a space delimiter, so a value containing a space (an info like "apt darkhotel (malware)") is
# quoted - which is why this parses with csv rather than str.split().
_FIELDS = ("time", "sensor", "src_ip", "src_port", "dst_ip", "dst_port", "proto", "type", "trail", "info", "reference")


def parse_event_line(line):
    """One event-log line -> dict, or None when it is not one.

    >>> event = parse_event_line('"2026-01-01 10:00:00.000000" box 10.0.0.5 4421 8.8.8.8 53 UDP DNS evil.biz "apt x (malware)" (static)')
    >>> event["src_ip"], event["type"], event["trail"], event["info"]
    ('10.0.0.5', 'DNS', 'evil.biz', 'apt x (malware)')
    >>> parse_event_line("garbage") is None
    True

    A JSON line (LOCAL_LOG_FORMAT json) reads the same way:

    >>> event = parse_event_line('{"timestamp": 1767261600, "time": "2026-01-01 10:00:00.000000", "sensor": "box", "severity": "medium", "src_ip": "10.0.0.5", "src_port": 4421, "dst_ip": "8.8.8.8", "dst_port": 53, "proto": "UDP", "type": "DNS", "trail": "evil.biz", "info": "apt x (malware)", "reference": "(static)"}')
    >>> event["src_ip"], event["type"], event["trail"], event["info"]
    ('10.0.0.5', 'DNS', 'evil.biz', 'apt x (malware)')
    """

    values = logfmt.fields(line.rstrip("\r\n"))
    if values is None:
        return None

    event = dict(zip(_FIELDS, values))
    # A JSON line carries the severity the writer computed. Prefer it: recomputing here would use
    # THIS process's REMOTE_SEVERITY_REGEX, which is not necessarily the one the event was rated
    # with, and an alert threshold is exactly where that difference would show up.
    event["severity"] = logfmt.severity_of_line(line) or severity_of(event["info"], event.get("reference", ""))
    # A time that does not start with a digit already falls back to 0; one that starts with a
    # digit but does not parse ("2026-13-45 ...") used to raise ValueError instead, out of a
    # function whose contract is "-> dict, or None when it is not one". Same fallback for both.
    try:
        event["timestamp"] = (int(time.mktime(time.strptime(event["time"].split('.')[0], "%Y-%m-%d %H:%M:%S")))
                              if event["time"][:1].isdigit() else 0)
    except (ValueError, OverflowError):
        event["timestamp"] = 0
    return event


def wanted(event):
    """Is this event at or above the configured severity threshold?"""

    minimum = (config.ALERT_SEVERITY or "high").strip().lower()
    if minimum not in ALERT_SEVERITY_ORDER:
        minimum = "high"
    return ALERT_SEVERITY_ORDER.index(event["severity"]) >= ALERT_SEVERITY_ORDER.index(minimum)


def throttled(event, now=None):
    """True when the same (source, trail) pair was already sent inside ALERT_THROTTLE seconds.

    A beacon checking in every 30 seconds is one message an interval, not 2,880 a day. Keyed on the
    pair rather than the whole line so a changing port or timestamp does not defeat it.
    """

    try:
        period = int(config.ALERT_THROTTLE)
    except (TypeError, ValueError):
        period = 0
    if period <= 0:
        return False

    now = time.time() if now is None else now
    key = (event["src_ip"], event["trail"])

    with _throttle_lock:
        last = _throttle.get(key)
        if last is not None and now - last < period:
            return True

        # Bounded: an estate under a scan storm must not turn this dict into the process's memory
        # ceiling. Oldest first, same shape as the event-throttle table in the sensor.
        if len(_throttle) >= MAX_ALERT_THROTTLE_KEYS:
            for old in sorted(_throttle, key=_throttle.get)[:len(_throttle) // 4 or 1]:
                del _throttle[old]

        _throttle[key] = now
        return False


def body(event):
    """The request body, from ALERT_FORMAT.

    A format string rather than a fixed structure, for the same reason CEF_FORMAT is one: there is
    no webhook standard. Slack, Mattermost, Rocket.Chat and Google Chat take {"text": ...}, Discord
    takes {"content": ...}, Teams wants an Adaptive Card, and a SIEM wants the event itself.
    """

    template = config.ALERT_FORMAT or ""
    fields = dict(event)
    fields["json"] = json_line(event)
    try:
        return template % fields
    except (KeyError, TypeError, ValueError) as ex:
        log_error("invalid 'ALERT_FORMAT' ('%s')" % ex, single=True)
        return None


def json_line(event):
    """The event as LOGSTASH_SERVER sends it, so anything already parsing that keeps working."""

    from collections import OrderedDict
    return json.dumps(OrderedDict((key, event.get(key, "")) for key in
                                  ("timestamp", "sensor", "severity", "src_ip", "src_port", "dst_ip",
                                   "dst_port", "proto", "type", "trail", "info", "reference")))


def send(event):
    """POST one event. Never raises: a webhook outage must not stop the server or the tailer."""

    payload = body(event)
    if payload is None:
        return False

    try:
        retrieve_content(config.ALERT_WEBHOOK_URL, data=payload.encode(UNICODE_ENCODING),
                         headers={"Content-Type": "application/json"})
        return True
    except Exception as ex:
        log_error("alert webhook POST failed ('%s')" % ex, single=True)
        return False


def process(line):
    """Filter, throttle and send one log line. Returns True when a message went out."""

    event = parse_event_line(line)
    if event is None or not wanted(event) or throttled(event):
        return False
    return send(event)


def _log_path(sec=None):
    localtime = time.localtime(time.time() if sec is None else sec)
    return os.path.join(config.LOG_DIR, "%d-%02d-%02d.log" % (localtime.tm_year, localtime.tm_mon, localtime.tm_mday))


def _tail_once(state):
    """Read whatever is new in today's log. `state` is a dict of {path, offset}."""

    path = _log_path()
    if path != state.get("path"):
        # A new day, or the first pass. Start at the END on the first pass: a restart must not
        # replay a day's worth of events as a day's worth of pages.
        state["offset"] = os.path.getsize(path) if (state.get("path") is None and os.path.isfile(path)) else 0
        state["path"] = path
        state["inode"] = None

    try:
        stat = os.stat(path)
    except OSError:
        return 0                    # not created yet today

    # Rotation, two shapes. `mv log log.1 && touch log` keeps the size but changes the INODE;
    # truncating in place keeps the inode but shrinks the size. Checking only one of them loses
    # events after the other. (A truncate that lands on exactly the same size is undetectable
    # from metadata and is not defended against.)
    if state.get("inode") not in (None, stat.st_ino):
        state["offset"] = 0
    state["inode"] = stat.st_ino

    size = stat.st_size
    if size < state["offset"]:
        state["offset"] = 0
    if size == state["offset"]:
        return 0

    sent = 0
    with open(path, "rb") as f:
        f.seek(state["offset"])
        data = f.read(size - state["offset"])
    cut = data.rfind(b'\n')
    if cut < 0:
        return 0                    # a partial line; wait for the rest
    state["offset"] += cut + 1

    for raw in data[:cut].split(b'\n'):
        if not raw:
            continue
        try:
            if process(raw.decode(UNICODE_ENCODING, "replace")):
                sent += 1
        except Exception:
            if config.SHOW_DEBUG:
                traceback.print_exc()

    return sent


def start(join=False):
    """Start the alert tailer. No-op unless ALERT_WEBHOOK_URL is set."""

    if not config.ALERT_WEBHOOK_URL:
        return False

    print("[i] alerting on '%s' events to '%s'" % (config.ALERT_SEVERITY or "high", config.ALERT_WEBHOOK_URL))

    def run():
        state = {"path": None, "offset": 0}
        while True:
            try:
                _tail_once(state)
            except Exception:
                if config.SHOW_DEBUG:
                    traceback.print_exc()
            time.sleep(ALERT_POLL_PERIOD)

    if join:
        run()
    else:
        thread = threading.Thread(target=run)
        thread.daemon = True
        thread.start()

    return True
