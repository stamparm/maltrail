#!/usr/bin/env python

"""
Copyright (c) 2014-present Maltrail developers (https://github.com/stamparm/maltrail/)
See the file 'LICENSE' for copying permission
"""

import collections
import csv
import json
import os
import re
import threading
import time
import traceback
import urllib.request

from core import logfmt
from core.log import log_error
from core.log import severity_of
from core.settings import config
from core.settings import ALERT_POLL_PERIOD
from core.settings import ALERT_TIMEOUT
from core.settings import MAX_ALERT_QUEUE
from core.settings import ALERT_SEVERITY_ORDER
from core.settings import MAX_ALERT_THROTTLE_KEYS
from core.settings import UNICODE_ENCODING

# Outbound notification for events worth waking someone up for.
#
# It tails the daily event log rather than hooking the event path, because there is no single event
# path to hook: a local Rust sensor writes its own log file, and a remote one arrives as a UDP datagram
# handled in log.py. The log file is the one place every event passes through, whoever produced it.
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


# An alert is about a THREAT, the unit the dashboard shows: html/js/engine.js:aggregateRows groups
# events by this key, and threat_uid() is the 8-hex id it displays (and its search finds). Keyed on
# the raw (source, trail) instead, every heuristic or alias spelling of one threat - "(a8f3k).com",
# "(b91x).com" - was a message of its own: 8,978 at ALERT_SEVERITY low over a week of a home
# network, 2,427 threats. A flood is the one grouping left out: whether a trail is one depends on
# the whole day, which an alert sent as the event happens cannot know.
_PATH_LIST_RE = re.compile(r"\A/\S*(?:, /\S*){2,}\Z")
_MORE_RE = re.compile(r" \(\+\d+ more\)\Z")


def threat_key(event):
    """The dashboard's threat_text for one event (engine.js: normTrail, infoKey, the ttext ladder).

    >>> threat_key({"src_ip": "10.0.0.5", "trail": "(api).ipify.org", "info": "ipinfo (suspicious)", "reference": "(static)"})
    '10.0.0.5~>ipify.org'
    >>> threat_key({"src_ip": "10.0.0.5", "trail": "(a8f3k).com", "info": "long domain (suspicious)", "reference": "(heuristic)"})
    '10.0.0.5~>comlong domain (suspicious)'
    """

    src, info, ref = event.get("src_ip", ""), event.get("info", ""), event.get("reference", "")
    trail = event.get("trail", "")
    trail = "*" if _PATH_LIST_RE.match(trail) else re.sub(r"\([^)]+\)", "", trail).strip(" ").strip(".")
    ikey = _MORE_RE.sub("", info)
    if " dns exhaustion " in info:
        return "%s~>%s" % (ikey, trail)
    if " dga " in info:
        return "%s~>%s" % (src, ikey)
    if "heuristic" in ref:
        return "%s~>%s%s" % (src, trail, ikey)
    return "%s~>%s" % (src, trail)


def _murmur3(text, seed=13):
    # engine.js:murmur3 hashes the low byte of each UTF-16 code unit, so this does too
    data = bytearray(text.encode("utf-16-le")[0::2])
    c1, c2, h1, n = 0xcc9e2d51, 0x1b873593, seed, len(data)
    rotl = lambda x, r: ((x << r) | (x >> (32 - r))) & 0xffffffff
    for i in range(0, n - n % 4, 4):
        k1 = data[i] | data[i + 1] << 8 | data[i + 2] << 16 | data[i + 3] << 24
        k1 = (rotl((k1 * c1) & 0xffffffff, 15) * c2) & 0xffffffff
        h1 = (rotl(h1 ^ k1, 13) * 5 + 0xe6546b64) & 0xffffffff
    k1, tail = 0, n - n % 4
    for j in reversed(range(n % 4)):
        k1 = k1 << 8 | data[tail + j]
    if n % 4:
        h1 ^= (rotl((k1 * c1) & 0xffffffff, 15) * c2) & 0xffffffff
    h1 ^= n
    h1 ^= h1 >> 16
    h1 = (h1 * 0x85ebca6b) & 0xffffffff
    h1 ^= h1 >> 13
    h1 = (h1 * 0xc2b2ae35) & 0xffffffff
    return h1 ^ (h1 >> 16)


def threat_uid(event):
    """The threat id the dashboard shows for this event's threat (engine.js:threatUID)."""

    key, info = threat_key(event), event.get("info", "")
    hexed = "%x" % _murmur3(key)
    if " dns exhaustion " in info:
        return hexed.zfill(6)[:6] + "N0"
    if " dga " in info:
        return hexed.zfill(6)[:6] + "D0"
    return hexed.zfill(8)


def wanted(event):
    """Is this event at or above the configured severity threshold?"""

    minimum = (config.ALERT_SEVERITY or "high").strip().lower()
    if minimum not in ALERT_SEVERITY_ORDER:
        minimum = "high"
    return ALERT_SEVERITY_ORDER.index(event["severity"]) >= ALERT_SEVERITY_ORDER.index(minimum)


def throttled(event, now=None):
    """True when the same threat, on the same day, was already sent inside ALERT_THROTTLE seconds.

    Keyed on the threat (threat_key), not the line, so a changing port, timestamp or heuristic
    spelling does not defeat it; and on the day, because that is what the dashboard shows - a
    threat still going after midnight is a threat of the new day there, and gets a message here.
    """

    try:
        period = int(config.ALERT_THROTTLE)
    except (TypeError, ValueError):
        period = 0
    if period <= 0:
        return False

    now = time.time() if now is None else now
    key = (str(event.get("time", ""))[:10], threat_key(event))

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
    fields["threat"] = threat_uid(event)
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


# Alerts waiting for the webhook, oldest first. Delivery is its own thread: a POST used to run on
# the tailer with a 30 s timeout, so a slow webhook held every later alert back by that much each.
_queue = collections.deque()
_queue_cond = threading.Condition()
_deliverer = []
_delivery = {"sent": 0, "dropped": 0, "failures": 0, "last_error": None, "last_sent": None}

# How long a failing webhook waits before the next attempt, doubling up to the cap.
RETRY_MIN, RETRY_MAX = 1, 60
# A webhook that keeps failing is reported at most this often, not once per attempt.
FAILURE_REPORT_PERIOD = 3600


def send(event):
    """Queue one event for the webhook. Never raises: an outage must not stop the server or the tailer."""

    payload = body(event)
    if payload is None:
        return False

    with _queue_cond:
        if len(_queue) >= MAX_ALERT_QUEUE:
            _queue.popleft()
            _delivery["dropped"] += 1
        _queue.append(payload)
        _queue_cond.notify()
        if not _deliverer:
            thread = threading.Thread(target=_deliver)
            thread.daemon = True
            thread.start()
            _deliverer.append(thread)
    return True


def post(payload):
    """POST one payload. Returns None on a 2xx answer, otherwise why it failed.

    This used to go through retrieve_content(), which swallows every error and returns empty
    bytes - so a 404, a 500, a refused connection and a timeout all looked like a delivered
    alert, and the "failed" branch could not run.
    """

    request = urllib.request.Request(config.ALERT_WEBHOOK_URL, data=payload.encode(UNICODE_ENCODING),
                                     headers={"Content-Type": "application/json"})
    try:
        response = urllib.request.urlopen(request, timeout=ALERT_TIMEOUT)  # nosec B310
        try:
            code = response.getcode()
        finally:
            response.close()
    except Exception as ex:     # HTTPError (4xx/5xx) included
        return "%s" % (getattr(ex, "code", None) and "HTTP %s" % ex.code or ex)
    return None if 200 <= (code or 0) < 300 else "HTTP %s" % code


def _deliver():
    """Send queued alerts in order; on failure keep the alert and retry with a growing delay."""

    delay = RETRY_MIN
    failing_since, reported = None, 0
    while True:
        with _queue_cond:
            while not _queue:
                _queue_cond.wait()
            payload = _queue[0]

        error = post(payload)
        now = time.time()
        if error is None:
            with _queue_cond:
                if _queue and _queue[0] is payload:
                    _queue.popleft()
                _delivery["sent"] += 1
                _delivery["last_sent"] = now
            if failing_since is not None:
                log_error("alert webhook delivering again after %d failed attempt(s)" % _delivery["failures"])
                failing_since, _delivery["failures"] = None, 0
            delay = RETRY_MIN
            continue

        _delivery["failures"] += 1
        _delivery["last_error"] = error
        if failing_since is None:
            failing_since = now
        if now - reported >= FAILURE_REPORT_PERIOD:
            reported = now
            log_error("alert webhook POST failed (%s); %d alert(s) waiting, retrying" % (error, len(_queue)))
        time.sleep(delay)
        delay = min(delay * 2, RETRY_MAX)


def delivery_status():
    """Counters for the webhook: sent, dropped (queue full), consecutive failures, last error."""

    with _queue_cond:
        return dict(_delivery, queued=len(_queue))


def process(line):
    """Filter, throttle and queue one log line. Returns True when a message was queued."""

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
