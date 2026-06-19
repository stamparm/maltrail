#!/usr/bin/env python

"""
Copyright (c) 2014-2026 Maltrail developers (https://github.com/stamparm/maltrail/)
See the file 'LICENSE' for copying permission
"""
from __future__ import print_function

import datetime
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
from thirdparty.odict import OrderedDict
from thirdparty.six.moves import socketserver as _socketserver

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
    'line break'
    """

    retval = str(value or '-')
    if any(_ in retval for _ in (' ', '"')):
        retval = "\"%s\"" % retval.replace('"', '""')
    retval = re.sub(r"[\x0a\x0d]", " ", retval)
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
                    handle = get_event_log_handle(sec)
                    os.write(handle, event.encode(UNICODE_ENCODING))

                if config.LOG_SERVER:
                    _family, _address = _endpoint_address(config.LOG_SERVER)
                    s = socket.socket(_family, socket.SOCK_DGRAM)
                    try:
                        s.sendto(("%s %s" % (sec, event)).encode(UNICODE_ENCODING), _address)
                    finally:
                        s.close()

                if config.SYSLOG_SERVER or config.LOGSTASH_SERVER:
                    severity = "medium"

                    if config.REMOTE_SEVERITY_REGEX:
                        match = re.search(config.REMOTE_SEVERITY_REGEX, info)
                        if match:
                            for _ in ("low", "medium", "high"):
                                if match.group(_):
                                    severity = _
                                    break

                    if config.SYSLOG_SERVER:
                        extension = "src=%s spt=%s dst=%s dpt=%s trail=%s ref=%s" % (src_ip, src_port, dst_ip, dst_port, trail, reference)
                        _ = CEF_FORMAT.format(syslog_time=time.strftime("%b %d %H:%M:%S", time.localtime(int(sec))), host=HOSTNAME, device_vendor=NAME, device_product="sensor", device_version=VERSION, signature_id=time.strftime("%Y-%m-%d", time.localtime(os.path.getctime(config.TRAILS_FILE))), name=info, severity={"low": 0, "medium": 1, "high": 2}.get(severity), extension=extension)
                        _family, _address = _endpoint_address(config.SYSLOG_SERVER)
                        s = socket.socket(_family, socket.SOCK_DGRAM)
                        try:
                            s.sendto(_.encode(UNICODE_ENCODING), _address)
                        finally:
                            s.close()

                    if config.LOGSTASH_SERVER:
                        _ = OrderedDict((("timestamp", sec), ("sensor", HOSTNAME), ("severity", severity), ("src_ip", src_ip), ("src_port", src_port), ("dst_ip", dst_ip), ("dst_port", dst_port), ("proto", proto), ("type", trail_type), ("trail", trail), ("info", info), ("reference", reference)))
                        _family, _address = _endpoint_address(config.LOGSTASH_SERVER)
                        s = socket.socket(_family, socket.SOCK_DGRAM)
                        try:
                            s.sendto(json.dumps(_).encode(UNICODE_ENCODING), _address)
                        finally:
                            s.close()

                if (config.DISABLE_LOCAL_LOG_STORAGE and not any((config.LOG_SERVER, config.SYSLOG_SERVER))) or config.console:
                    sys.stderr.write(event)
                    sys.stderr.flush()

            if config.plugin_functions:
                for _ in config.plugin_functions:
                    try:
                        _(event_tuple, packet)
                    except Exception:
                        if config.SHOW_DEBUG:
                            traceback.print_exc()
    except (OSError, IOError):
        if config.SHOW_DEBUG:
            traceback.print_exc()

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

def start_logd(address=None, port=None, join=False):
    class ThreadingUDPServer(_socketserver.ThreadingMixIn, _socketserver.UDPServer):
        pass

    class UDPHandler(_socketserver.BaseRequestHandler):
        def handle(self):
            try:
                data, _ = self.request

                if data[0:1].isdigit():     # Note: regular format with timestamp in front
                    sec, event = data.split(b' ', 1)
                else:                       # Note: naive format without timestamp in front
                    event_date = datetime.datetime.strptime(data[1:data.find(b'.')].decode(UNICODE_ENCODING), TIME_FORMAT)
                    sec = int(time.mktime(event_date.timetuple()))
                    event = data

                if not event.endswith(b'\n'):
                    event = b"%s\n" % event

                handle = get_event_log_handle(int(sec), reuse=False)
                try:
                    os.write(handle, event)
                finally:
                    os.close(handle)
            except Exception:
                if config.SHOW_DEBUG:
                    traceback.print_exc()

    # IPv6 support
    if ':' in (address or ""):
        address = address.strip("[]")

        _socketserver.UDPServer.address_family = socket.AF_INET6
        _address = resolve_address(address, port)
    else:
        _address = (address or '', int(port) if str(port or "").isdigit() else 0)

    server = ThreadingUDPServer(_address, UDPHandler)

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
