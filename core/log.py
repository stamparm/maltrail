#!/usr/bin/env python

"""
Copyright (c) 2014-2026 Maltrail developers (https://github.com/stamparm/maltrail/)
See the file 'LICENSE' for copying permission
"""

import binascii
import datetime
import hashlib
import hmac
import json
import os
import re
import signal
import socket
import sys
import threading
import time
import traceback

from core.addr import parse_host_port
from core.addr import resolve_address
from core.common import check_whitelisted
from core.common import check_sudo
from core.compat import xrange
from core.enums import TRAIL
from core.settings import CEF_FORMAT
from core.settings import config
from core.settings import CONDENSE_ON_INFO_KEYWORDS
from core.settings import CONDENSED_EVENTS_FLUSH_PERIOD
from core.settings import MAX_CONDENSED_EVENTS
from core.settings import DEFAULT_ERROR_LOG_PERMISSIONS
from core.settings import DEFAULT_EVENT_LOG_PERMISSIONS
from core.settings import HOSTNAME
from core.settings import NAME
from core.settings import TIME_FORMAT
from core.settings import UNICODE_ENCODING
from core.settings import VERSION
from core.ignore import ignore_event
from collections import OrderedDict
import socketserver as _socketserver

_condensed_events = {}
_condensing_thread = None
_condensing_lock = threading.Lock()
_single_messages = set()
_thread_data = threading.local()

def create_log_directory():
    if not os.path.isdir(config.LOG_DIR):
        if not config.DISABLE_CHECK_SUDO and check_sudo() is False:
            sys.exit("[!] please rerun with sudo/Administrator privileges")
        os.makedirs(config.LOG_DIR, 0o755)
    print("[i] using '%s' for log storage" % config.LOG_DIR)

def get_event_log_handle(sec, flags=os.O_APPEND | os.O_CREAT | os.O_WRONLY, reuse=True):
    retval = None
    localtime = time.localtime(sec)

    _ = os.path.join(config.LOG_DIR, "%d-%02d-%02d.log" % (localtime.tm_year, localtime.tm_mon, localtime.tm_mday))

    if not reuse:
        if not os.path.exists(_):
            open(_, "w+").close()
            os.chmod(_, DEFAULT_EVENT_LOG_PERMISSIONS)

        retval = os.open(_, flags)
    else:
        if _ != getattr(_thread_data, "event_log_path", None):
            if getattr(_thread_data, "event_log_handle", None):
                try:
                    os.close(_thread_data.event_log_handle)
                except OSError:
                    pass

            if not os.path.exists(_):
                open(_, "w+").close()
                os.chmod(_, DEFAULT_EVENT_LOG_PERMISSIONS)

            _thread_data.event_log_path = _
            _thread_data.event_log_handle = os.open(_thread_data.event_log_path, flags)

        retval = _thread_data.event_log_handle

    return retval

def get_error_log_handle(flags=os.O_APPEND | os.O_CREAT | os.O_WRONLY):
    if not hasattr(_thread_data, "error_log_handle"):
        _ = os.path.join(config.get("LOG_DIR") or os.curdir, "error.log")
        if not os.path.exists(_):
            open(_, "w+").close()
            os.chmod(_, DEFAULT_ERROR_LOG_PERMISSIONS)
        _thread_data.error_log_path = _
        _thread_data.error_log_handle = os.open(_thread_data.error_log_path, flags)
    return _thread_data.error_log_handle

def safe_value(value):
    r"""
    Renders a single event-log field safely (CSV-style quoting/escaping; newlines flattened to spaces)

    >>> safe_value("hello")
    'hello'
    >>> safe_value("")
    '-'
    >>> safe_value(None)
    '-'
    >>> safe_value("a b")
    '"a b"'
    >>> safe_value('a"b')
    '"a""b"'
    >>> safe_value("line\nbreak")
    '"line break"'
    """

    retval = str(value or '-')
    retval = re.sub(r"[\x0a\x0d]", " ", retval)   # flatten CR/LF FIRST: doing it after the quote check let a newline-only value emit an unquoted space -> the field split into two on re-parse (column corruption / log injection)
    if any(_ in retval for _ in (' ', '"')):
        retval = "\"%s\"" % retval.replace('"', '""')
    return retval

def flush_condensed_events(single=False):
    while True:
        if not single:
            time.sleep(CONDENSED_EVENTS_FLUSH_PERIOD)

        with _condensing_lock:
            snapshot = list(_condensed_events.items())
            _condensed_events.clear()

        # NOTE: the (blocking) log_event I/O below runs OUTSIDE the lock, so a flush can't stall the threads condensing new events
        for key, events in snapshot:
            condensed = False

            first_event = events[0]
            condensed_event = list(first_event)

            for i in xrange(1, len(events)):
                current_event = events[i]
                for j in xrange(3, 7):  # src_port, dst_ip, dst_port, proto
                    if current_event[j] != condensed_event[j]:
                        condensed = True
                        if not isinstance(condensed_event[j], set):
                            condensed_event[j] = set((condensed_event[j],))
                        condensed_event[j].add(current_event[j])

            if condensed:
                for i in xrange(len(condensed_event)):
                    if isinstance(condensed_event[i], set):
                        condensed_event[i] = ','.join(str(_) for _ in sorted(condensed_event[i]))

            log_event(condensed_event, skip_condensing=True)

        if single:
            break

_endpoints_cache = {}

def _endpoints(value):
    """
    Splits a remote-logging option into its endpoints, so one option can name several targets:

        SYSLOG_SERVER 192.168.1.15:514, 192.168.1.16:514

    Requested for redundant SIEM/collector targets (issue #15164). Separating inside the existing
    option rather than adding SYSLOG_SERVER_1, _2, ... keeps every configuration that names a
    single endpoint working unchanged, and matches how the other list-valued options in
    maltrail.conf (e.g. FAIL2BAN_ALLOWLIST) are already written.

    Memoized: log_event calls this per event, and the split is pure string work over a value that
    never changes.

    >>> _endpoints("1.2.3.4:514")
    ['1.2.3.4:514']
    >>> _endpoints("1.2.3.4:514, 5.6.7.8:514")
    ['1.2.3.4:514', '5.6.7.8:514']
    >>> _endpoints("[::1]:514 1.2.3.4:514")
    ['[::1]:514', '1.2.3.4:514']
    >>> _endpoints("")
    []
    """

    retval = _endpoints_cache.get(value)
    if retval is None:
        retval = [_ for _ in re.split(r"[,;\s]+", value or "") if _]
        _endpoints_cache[value] = retval
    return retval

_endpoint_cache = {}

def _endpoint_address(value):
    """
    Returns (socket family, sockaddr) for a remote-logging endpoint, IPv4/IPv6-safe.
    IPv4 addresses / hostnames keep the (host, port) form (sendto resolves them); IPv6 literals are resolved up-front.

    NOTE: memoized per endpoint string - log_event runs this for every event, and the IPv6 branch calls getaddrinfo
    (a potentially blocking DNS round-trip). Endpoints are stable config values, so resolve once instead of per event.
    """

    retval = _endpoint_cache.get(value)
    if retval is None:
        host, port = parse_host_port(value)
        if ':' in host:
            retval = (socket.AF_INET6, resolve_address(host, port))
        else:
            retval = (socket.AF_INET, (host, port))
        _endpoint_cache[value] = retval
    return retval

_socket_cache = {}                  # family -> a reused UDP socket (one datagram socket serves any destination of that family)
_signature_id_cache = [None, 0.0]   # (cached CEF signature_id, time computed); refreshed lazily, not stat-ed per event

def _send_datagram(endpoint, data):
    """
    Sends a UDP datagram to a remote-logging endpoint, reusing a per-family socket instead of creating and closing
    one for every event. On a send error the cached socket is dropped and recreated once (e.g. a transient fd issue).
    """

    family, address = _endpoint_address(endpoint)
    sock = _socket_cache.get(family)
    if sock is None:
        sock = _socket_cache[family] = socket.socket(family, socket.SOCK_DGRAM)
    try:
        sock.sendto(data, address)
    except socket.error:
        try:
            sock.close()
        except Exception:
            pass
        try:
            sock = _socket_cache[family] = socket.socket(family, socket.SOCK_DGRAM)
            sock.sendto(data, address)
        except socket.error:
            pass

def _trails_signature_id():
    """
    The CEF signature_id is the trails-file date - it changes at most daily (or when trails are rebuilt), so cache
    it and refresh ~every 5 min instead of stat-ing TRAILS_FILE (os.path.getctime) on every single event.
    """

    now = time.time()
    if _signature_id_cache[0] is None or now - _signature_id_cache[1] >= 300:
        try:
            _signature_id_cache[0] = time.strftime("%Y-%m-%d", time.localtime(os.path.getctime(config.TRAILS_FILE)))
        except OSError:
            _signature_id_cache[0] = time.strftime("%Y-%m-%d")
        _signature_id_cache[1] = now
    return _signature_id_cache[0]

def _cef_escape(value, extension=False):
    # CEF (ArcSight) escaping: '\' and '|' in the header fields (e.g. name); '\' and '=' in extension VALUES.
    # newlines terminate a syslog record, so they must never appear inside a field. Output is byte-identical
    # when the value has no special chars, so well-behaved trails are unaffected; a trail/info with '='/'|'
    # (e.g. a URL trail "host/?a=b") would otherwise emit a malformed CEF line the SIEM mis-parses.
    retval = str(value).replace("\\", "\\\\")
    retval = retval.replace("=", "\\=") if extension else retval.replace("|", "\\|")
    return retval.replace("\r", " ").replace("\n", " ")

def log_event(event_tuple, packet=None, skip_write=False, skip_condensing=False):
    global _condensing_thread

    if _condensing_thread is None:
        with _condensing_lock:
            if _condensing_thread is None:  # NOTE: double-checked under lock so concurrent first events can't spawn two flush threads
                _condensing_thread = threading.Thread(target=flush_condensed_events)
                _condensing_thread.daemon = True
                _condensing_thread.start()

    try:
        sec, usec, src_ip, src_port, dst_ip, dst_port, proto, trail_type, trail, info, reference = event_tuple
        if ignore_event(event_tuple):
            return

        if not (any(check_whitelisted(_) for _ in (src_ip, dst_ip)) and trail_type != TRAIL.DNS):  # DNS requests/responses can't be whitelisted based on src_ip/dst_ip
            if not skip_write:
                localtime = "%s.%06d" % (time.strftime(TIME_FORMAT, time.localtime(int(sec))), usec)

                if not skip_condensing:
                    if any(_ in info for _ in CONDENSE_ON_INFO_KEYWORDS):
                        with _condensing_lock:
                            key = (src_ip, trail)
                            if key not in _condensed_events:
                                _condensed_events[key] = []
                            if len(_condensed_events[key]) < MAX_CONDENSED_EVENTS:
                                _condensed_events[key].append(event_tuple)

                        return

                current_bucket = sec // config.PROCESS_COUNT
                if getattr(_thread_data, "log_bucket", None) != current_bucket:  # log throttling
                    _thread_data.log_bucket = current_bucket
                    _thread_data.log_trails = set()
                else:
                    if any(_ in _thread_data.log_trails for _ in ((src_ip, trail), (dst_ip, trail))):
                        return
                    else:
                        _thread_data.log_trails.add((src_ip, trail))
                        _thread_data.log_trails.add((dst_ip, trail))

                event = "%s %s %s\n" % (safe_value(localtime), safe_value(config.SENSOR_NAME), " ".join(safe_value(_) for _ in event_tuple[2:]))
                if not config.DISABLE_LOCAL_LOG_STORAGE:
                    # LOCAL_LOG_FORMAT changes the FILE and nothing else: LOG_SERVER is a wire
                    # protocol other deployments parse, and the console line is meant to be read
                    # by a person, so both keep the text form regardless.
                    if (config.LOCAL_LOG_FORMAT or "").strip().lower() in ("json", "ndjson"):
                        local_line = "%s\n" % event_json(event_tuple, severity_of(info, reference), config.SENSOR_NAME, localtime)
                    else:
                        local_line = event
                    handle = get_event_log_handle(sec)
                    os.write(handle, local_line.encode(UNICODE_ENCODING))

                if config.LOG_SERVER:
                    _payload = ("%s %s" % (sec, event)).encode(UNICODE_ENCODING)
                    _send_datagram(config.LOG_SERVER, mts_sign(getattr(config, "LOG_SERVER_SECRET", None), _payload))

                if config.SYSLOG_SERVER or config.LOGSTASH_SERVER:
                    severity = severity_of(info, reference)

                    if config.SYSLOG_SERVER:
                        extension = "src=%s spt=%s dst=%s dpt=%s trail=%s ref=%s" % (src_ip, src_port, dst_ip, dst_port, _cef_escape(trail, True), _cef_escape(reference, True))
                        _ = CEF_FORMAT.format(syslog_time=time.strftime("%b %d %H:%M:%S", time.localtime(int(sec))), host=HOSTNAME, device_vendor=NAME, device_product="sensor", device_version=VERSION, signature_id=_trails_signature_id(), name=_cef_escape(info), severity={"low": 0, "medium": 1, "high": 2}.get(severity), extension=extension)
                        _ = _.encode(UNICODE_ENCODING)
                        for endpoint in _endpoints(config.SYSLOG_SERVER):
                            _send_datagram(endpoint, _)

                    if config.LOGSTASH_SERVER:
                        _ = event_json(event_tuple, severity, HOSTNAME).encode(UNICODE_ENCODING)
                        for endpoint in _endpoints(config.LOGSTASH_SERVER):
                            _send_datagram(endpoint, _)

                if (config.DISABLE_LOCAL_LOG_STORAGE and not any((config.LOG_SERVER, config.SYSLOG_SERVER))) or config.console:
                    sys.stderr.write(event)
                    sys.stderr.flush()

    except (OSError, IOError):
        if config.SHOW_DEBUG:
            traceback.print_exc()

def event_json(event_tuple, severity, sensor, localtime=None):
    """One event as a JSON object, the form LOGSTASH_SERVER has always sent.

    Extracted so there is exactly one definition of what an event looks like in JSON. It is also
    what `LOCAL_LOG_FORMAT json` writes, so a file on disk and a datagram on the wire describe an
    event the same way - and `sensor/src/output.rs` renders it byte-for-byte identically, which
    `sensor/tests/vectors.rs` pins against this function's output.

    `localtime` adds the "time" field and is what makes the on-disk form LOSSLESS. The wire form
    carries `timestamp` in whole seconds, which is fine for a datagram but would quietly drop the
    microseconds every text log line has always recorded. Passing it is therefore what the local
    log does and what LOGSTASH_SERVER does not - adding the field unconditionally would change a
    wire format that existing consumers are already parsing.
    """

    sec, _, src_ip, src_port, dst_ip, dst_port, proto, trail_type, trail, info, reference = event_tuple
    fields = [("timestamp", sec)]
    if localtime is not None:
        fields.append(("time", localtime))
    fields.extend((
        ("sensor", sensor),
        ("severity", severity),
        ("src_ip", src_ip),
        ("src_port", src_port),
        ("dst_ip", dst_ip),
        ("dst_port", dst_port),
        ("proto", proto),
        ("type", trail_type),
        ("trail", trail),
        ("info", info),
        ("reference", reference),
    ))
    return json.dumps(OrderedDict(fields))

def severity_of(info, reference=""):
    """"low" / "medium" / "high" for an event, per REMOTE_SEVERITY_REGEX.

    Matched against "<info> <reference>", not the info alone. Whether a verdict was CORROBORATED
    lives in the reference - "(heuristic)" is the sensor's own guess, "(static)" is a feed hit -
    and the dashboard has ranked guesses below feed hits since 307e0e8. With only the info to look
    at, that rule was inexpressible here, so the two disagreed on ten of the shipped verdicts:
    "long domain (suspicious)" read LOW on the dashboard and alerted as MEDIUM. Appending the
    reference cannot break an existing custom regex - re.search is unanchored, so a longer subject
    only ever matches more.

    Shared by the SYSLOG_SERVER / LOGSTASH_SERVER senders above and by core/alert.py, so an operator
    tunes one regex and every outbound channel agrees. Unmatched is "medium": the shipped regex names
    the extremes (malware/ransomware/adversary high, scanner/reputation/attacker low) and leaves the
    middle - exploit kits, web skimmers - implicit.

    No doctest: the answer depends on the configured REMOTE_SEVERITY_REGEX, and with none loaded
    every info is "medium". tests/test_alert.py asserts the classification against the regex
    maltrail.conf actually ships.
    """

    retval = "medium"

    if config.REMOTE_SEVERITY_REGEX:
        match = re.search(config.REMOTE_SEVERITY_REGEX, "%s %s" % (info or "", reference or ""))
        if match:
            groups = match.groupdict()   # NOTE: groupdict().get() (not match.group(name)) - a custom REMOTE_SEVERITY_REGEX that omits a low/medium/high group would otherwise raise IndexError ("no such group") per event, escaping log_event's handler and breaking syslog forwarding
            for _ in ("low", "medium", "high"):
                if groups.get(_):
                    retval = _
                    break

    return retval


def log_error(msg, single=False):
    if single:
        if msg in _single_messages:
            return
        else:
            _single_messages.add(msg)

    try:
        handle = get_error_log_handle()
        os.write(handle, ("%s %s\n" % (time.strftime(TIME_FORMAT, time.localtime()), msg)).encode(UNICODE_ENCODING))
    except (OSError, IOError):
        if config.SHOW_DEBUG:
            traceback.print_exc()

# ---- authenticated event datagrams (LOG_SERVER_SECRET) ----
#
# The UDP listener below is unauthenticated by protocol design: anything that can reach the port
# can append to the log an operator reasons from, and that /events, /counts and /fail2ban parse.
# Forged detections are a worse problem for an IDS than eavesdropping, and the newline-collapsing
# defence further down only limits what one forged datagram can do, not who may send one.
#
# With LOG_SERVER_SECRET set on both ends every datagram carries a MAC over its exact payload and
# the receiver drops whatever does not verify. The frame is:
#
#     MTS1 <32 hex chars> <payload>
#
# where <payload> is byte-for-byte what an unsigned sender would have put on the wire, so the
# parser underneath is untouched and one wire format serves both modes.
#
# HMAC-SHA256 truncated to 128 bits (RFC 2104 section 5), hex-encoded so a datagram stays greppable
# text like everything else on this path. The frame costs 38 bytes on a ~110-byte event - about a
# third - which is far more than compressing the payload could ever save: gzip on a single event of
# this size makes it BIGGER, and raw deflate wins 9%. That is the clearest evidence that bandwidth
# is not the constraint here. In absolute terms it is 11.8 Mbit/s instead of 8.7 at 10,000 events a
# second, which is a rate no deployment sustains.
#
# This authenticates; it does not encrypt. The event is still readable to anyone on the path. That
# is a deliberate scope: forgery is the attack that corrupts the evidence, and confidentiality is
# better bought with WireGuard or IPsec than with a bespoke scheme here.
#
# Replay is BOUNDED, not eliminated. The signed payload leads with the event's epoch second and a
# datagram outside LOG_SERVER_SKEW of now is dropped, so yesterday's traffic cannot be replayed
# forever. Inside that window a captured datagram can be replayed, which duplicates one real event.
# Inventing an event that never happened - the attack worth stopping - needs the secret.

MTS_PREFIX = b"MTS1 "
MTS_MAC_HEX = 32                       # 16 raw bytes, hex-encoded
LOG_SERVER_SKEW = 900                  # default seconds of clock skew and delivery delay tolerated


def _skew_window():
    """How far from the server's clock a signed event may be, in seconds. 0 disables the check.

    Timezones are NOT what this is for: the signed field is an epoch second, which is absolute, so
    a sensor in Tokyo and a server in Zagreb agree on it exactly. This is clock SKEW - a host with
    no NTP, a board with no RTC that boots before the network, a VM resumed from a snapshot.

    Configurable because the failure is total rather than partial: a sensor whose clock is wrong
    has EVERY event refused, and 900 seconds is a judgement about how well-synchronised a fleet is,
    which is the operator's to make and not ours.
    """

    # `or` would be wrong here: 0 is the documented way to switch the check off, and `0 or 900`
    # is 900 - the setting would silently do the opposite of what it says.
    value = getattr(config, "LOG_SERVER_SKEW", None)
    if value is None or value == "":
        return LOG_SERVER_SKEW
    try:
        return max(0, int(value))
    except (TypeError, ValueError):
        return LOG_SERVER_SKEW


def _mts_drop(reason):
    """Say why a datagram was refused, when debugging is on.

    Every rejection here is silent by necessity - the sender is unauthenticated, so there is
    nobody to tell - and that produces the worst failure this project has: a sensor that looks
    healthy while its events never arrive. A skewed clock or a mismatched secret drops EVERY
    event, and without this line the only symptom is an empty log.
    """

    if getattr(config, "SHOW_DEBUG", False):
        sys.stderr.write("[x] dropped an event datagram: %s\n" % reason)
    return None


def _mts_mac(secret, payload):
    if not isinstance(secret, bytes):
        secret = secret.encode(UNICODE_ENCODING)
    return binascii.hexlify(hmac.new(secret, payload, hashlib.sha256).digest()[:16])


def mts_sign(secret, payload):
    """Frame and sign a payload. Returns the payload unchanged when there is no secret."""

    if not secret:
        return payload
    return MTS_PREFIX + _mts_mac(secret, payload) + b" " + payload


def mts_open(secret, data, now=None):
    """The payload carried by a datagram, or None if it must be dropped.

    With a secret the frame is REQUIRED and verified, which is what closes the injection hole.

    Without a secret a frame is stripped but not checked. That is deliberate: a sensor already
    given the secret, pointed at a server that has not been, still records its events instead of
    writing "MTS1 <mac> ..." into the log as if it were an event. The two ends can then be
    upgraded in either order, which matters when they are different machines owned by different
    people.
    """

    framed = data.startswith(MTS_PREFIX)

    if not secret:
        if not framed:
            return data
        rest = data[len(MTS_PREFIX):]
        return rest[MTS_MAC_HEX + 1:] if len(rest) > MTS_MAC_HEX else None

    if not framed:
        return _mts_drop("unsigned, but 'LOG_SERVER_SECRET' is set (sender not configured with it?)")

    rest = data[len(MTS_PREFIX):]
    if len(rest) <= MTS_MAC_HEX or rest[MTS_MAC_HEX:MTS_MAC_HEX + 1] != b" ":
        return _mts_drop("malformed frame")

    given, payload = rest[:MTS_MAC_HEX], rest[MTS_MAC_HEX + 1:]
    if not hmac.compare_digest(given, _mts_mac(secret, payload)):
        return _mts_drop("bad MAC (the two ends disagree on 'LOG_SERVER_SECRET')")

    head = payload.split(b" ", 1)[0]
    if not head.isdigit():
        return _mts_drop("signed payload does not start with an epoch second")

    window = _skew_window()
    skew = (time.time() if now is None else now) - int(head)
    if window and abs(skew) > window:
        return _mts_drop("timestamp is %ds away, outside the %ds 'LOG_SERVER_SKEW' window (sender "
                         "clock skew, or an offline replay of an old capture - use "
                         "'--timestamps wallclock' for that)" % (skew, window))

    return payload


def start_logd(address=None, port=None, join=False):
    # ONE receive loop, not a thread per datagram.
    #
    # This used to be a ThreadingUDPServer, so every event from every remote sensor cost a fresh thread -
    # and because that thread was fresh, get_event_log_handle()'s thread-local fd cache could never hit, so
    # each event also cost an open() and a close(). Measured against the real server on loopback, paced:
    #
    #     500/s  0% loss     5,000/s   0% loss
    #   1,000/s  0% loss    10,000/s  23.9% loss
    #   2,000/s  0% loss    (unpaced 337k/s: 2.3% delivered)
    #
    # A sensor with DISABLE_LOCAL_LOG_STORAGE sends every event here, and a scan burst on a busy link is
    # well past 10k/s - so the loss lands exactly when there is most to see. The handler only parses a line
    # and appends it, which is the wrong shape for concurrency in the first place: N threads appending to one
    # file contend on it, and the external review's "unbounded threads" note was about this constructor.
    # Sequential receive keeps `reuse=True` viable (one long-lived thread, one cached fd, still rotated by
    # the day-path comparison) and removes both costs.
    class LogUDPServer(_socketserver.UDPServer):
        def server_bind(self):
            # The default receive buffer holds ~2k of these datagrams, so a burst overruns it while the loop
            # is still writing. This asks for 8 MB, but the kernel CLAMPS it to net.core.rmem_max without
            # error - which on a stock box is the 208 KB default, i.e. no change at all. So it is not where
            # the numbers above come from; those are the thread and the open()/close(). It is here because it
            # is one line and it does help on a host whose operator has raised rmem_max for exactly this.
            try:
                self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 8 * 1024 * 1024)
            except Exception:
                pass
            _socketserver.UDPServer.server_bind(self)

    class UDPHandler(_socketserver.BaseRequestHandler):
        def handle(self):
            try:
                data, _ = self.request

                # Authenticate before parsing. With LOG_SERVER_SECRET set this is what makes the
                # listener refuse events it cannot attribute; without it, behaviour is unchanged.
                data = mts_open(getattr(config, "LOG_SERVER_SECRET", None), data)
                if data is None:
                    return

                if data[0:1].isdigit():     # Note: regular format with timestamp in front
                    sec, event = data.split(b' ', 1)
                else:                       # Note: naive format without timestamp in front
                    event_date = datetime.datetime.strptime(data[1:data.find(b'.')].decode(UNICODE_ENCODING), TIME_FORMAT)
                    sec = int(time.mktime(event_date.timetuple()))
                    event = data

                # One datagram is one record. A sensor never sends an embedded newline, so the
                # only way to get one here is a forged datagram - and this listener is
                # unauthenticated by protocol design, so anyone who can reach the port could
                # append arbitrary extra "events" to the log by putting '\n' in the middle of
                # one. That is evidence tampering in an IDS: the log is what an operator
                # reasons from and what /events, /counts and /fail2ban parse.
                #
                # Collapse the interior newlines rather than dropping the datagram, so a
                # malformed-but-honest sender still gets its event recorded, on one line.
                event = event.rstrip(b'\r\n').replace(b'\r', b' ').replace(b'\n', b' ') + b'\n'

                # reuse=True: one receive loop means one thread, so the thread-local handle is a real cache
                # instead of a miss on every datagram. It is reopened when the day's path changes.
                os.write(get_event_log_handle(int(sec)), event)
            except Exception:
                if config.SHOW_DEBUG:
                    traceback.print_exc()

    # IPv6 support
    if ':' in (address or ""):
        address = address.strip("[]")

        LogUDPServer.address_family = socket.AF_INET6
        _address = resolve_address(address, port)
    else:
        _address = (address or '', int(port) if str(port or "").isdigit() else 0)

    server = LogUDPServer(_address, UDPHandler)

    print("[i] running UDP server at '%s:%d'" % (server.server_address[0], server.server_address[1]))

    if join:
        server.serve_forever()
    else:
        thread = threading.Thread(target=server.serve_forever)
        thread.daemon = True
        thread.start()

def set_sigterm_handler():
    def handler(signum, frame):
        log_error("SIGTERM")
        raise SystemExit

    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, handler)

if __name__ != "__main__":
    set_sigterm_handler()
