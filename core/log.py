#!/usr/bin/env python

"""
Copyright (c) 2014-2016 Miroslav Stampar (@stamparm)
See the file 'LICENSE' for copying permission
"""

import os
import signal
import socket
import SocketServer
import sys
import threading
import time
import traceback

from core.common import check_sudo
from core.settings import config
from core.settings import CONDENSE_ON_TRAIL_KEYWORDS
from core.settings import CONDENSED_EVENTS_FLUSH_PERIOD
from core.settings import DEFAULT_ERROR_LOG_PERMISSIONS
from core.settings import DEFAULT_EVENT_LOG_PERMISSIONS
from core.settings import TIME_FORMAT
from core.settings import WHITELIST

_thread_data = threading.local()

def create_log_directory():
    if not os.path.isdir(config.LOG_DIR):
        if check_sudo() is False:
            exit("[!] please run with sudo/Administrator privileges")
        os.makedirs(config.LOG_DIR)
    print("[i] using '%s' for log storage" % config.LOG_DIR)

def get_event_log_handle(sec, flags=os.O_APPEND | os.O_CREAT | os.O_WRONLY):
    localtime = time.localtime(sec)
    _ = os.path.join(config.LOG_DIR, "%d-%02d-%02d.log" % (localtime.tm_year, localtime.tm_mon, localtime.tm_mday))
    if _ != getattr(_thread_data, "event_log_path", None):
        if not os.path.exists(_):
            open(_, "w+").close()
            os.chmod(_, DEFAULT_EVENT_LOG_PERMISSIONS)
        _thread_data.event_log_path = _
        _thread_data.event_log_handle = os.open(_thread_data.event_log_path, flags)
    return _thread_data.event_log_handle

def get_error_log_handle(flags=os.O_APPEND | os.O_CREAT | os.O_WRONLY):
    if not hasattr(_thread_data, "error_log_handle"):
        _ = os.path.join(config.LOG_DIR, "error.log")
        if not os.path.exists(_):
            open(_, "w+").close()
            os.chmod(_, DEFAULT_ERROR_LOG_PERMISSIONS)
        _thread_data.error_log_path = _
        _thread_data.error_log_handle = os.open(_thread_data.error_log_path, flags)
    return _thread_data.error_log_handle

def safe_value(value):
    retval = str(value or '-')
    if any(_ in retval for _ in (' ', '"')):
        retval = "\"%s\"" % retval.replace('"', '""')
    return retval

def log_event(event_tuple, packet=None, skip_write=False, skip_condensing=False, localtime=None):
    try:
        sec, usec, src_ip, src_port, dst_ip, dst_port, proto, trail_type, trail, info = event_tuple[:10]
        if not any(_ in WHITELIST for _ in (src_ip, dst_ip)):
            if not skip_write:
                localtime = localtime or "%s.%06d" % (time.strftime(TIME_FORMAT, time.localtime(int(sec))), usec)

                if not skip_condensing:
                    if (sec - getattr(_thread_data, "condensed_events_flush_sec", 0)) > CONDENSED_EVENTS_FLUSH_PERIOD:
                        _thread_data.condensed_events_flush_sec = sec

                        for key in getattr(_thread_data, "condensed_events", []):
                            condensed = False

                            _ = _thread_data.condensed_events[key][0]
                            condensed_localtime, condensed_event = [_[0]], list(_[1])

                            for i in xrange(1, len(_thread_data.condensed_events[key])):
                                _ = _thread_data.condensed_events[key][i]
                                for j in xrange(2, 7):  # src_ip, src_port, dst_ip, dst_port, proto
                                    condensed_localtime.append(_[0])
                                    if _[1][j] != condensed_event[j]:
                                        condensed = True
                                        if not isinstance(condensed_event[j], list):
                                            condensed_event[j] = i * [condensed_event[j]]
                                        condensed_event[j].append(_[1][j])

                            if condensed:
                                for i in xrange(len(condensed_event)):
                                    if isinstance(condensed_event[i], list):
                                        condensed_event[i] = ','.join(str(_) for _ in condensed_event[i])

                            log_event(condensed_event, skip_condensing=True, localtime=','.join(condensed_localtime))

                        _thread_data.condensed_events = {}

                    if any(_ in info for _ in CONDENSE_ON_TRAIL_KEYWORDS):
                        if not hasattr(_thread_data, "condensed_events"):
                            _thread_data.condensed_events = {}
                        if trail not in _thread_data.condensed_events:
                            _thread_data.condensed_events[trail] = []
                        _thread_data.condensed_events[trail].append((localtime, event_tuple))
                        return

                event = "%s %s %s\n" % (safe_value(localtime), safe_value(config.SENSOR_NAME), " ".join(safe_value(_) for _ in event_tuple[2:]))
                if not config.DISABLE_LOCAL_LOG_STORAGE:
                    handle = get_event_log_handle(sec)
                    os.write(handle, event)
                if config.LOG_SERVER:
                    remote_host, remote_port = config.LOG_SERVER.split(':')
                    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    s.sendto("%s %s" % (sec, event), (remote_host, int(remote_port)))
                if config.DISABLE_LOCAL_LOG_STORAGE and not config.LOG_SERVER or config.console:
                    sys.stderr.write(event)
                    sys.stderr.flush()
            if config.plugin_functions:
                for _ in config.plugin_functions:
                    _(event_tuple, packet)
    except (OSError, IOError):
        if config.SHOW_DEBUG:
            traceback.print_exc()

def log_error(msg):
    try:
        handle = get_error_log_handle()
        os.write(handle, "%s %s\n" % (time.strftime(TIME_FORMAT, time.localtime()), msg))
    except (OSError, IOError):
        if config.SHOW_DEBUG:
            traceback.print_exc()

def start_logd(address=None, port=None, join=False):
    class ThreadingUDPServer(SocketServer.ThreadingMixIn, SocketServer.UDPServer):
        pass

    class UDPHandler(SocketServer.BaseRequestHandler):
        def handle(self):
            try:
                data, _ = self.request
                sec, event = data.split(" ", 1)
                handle = get_event_log_handle(int(sec))
                os.write(handle, event)
            except:
                if config.SHOW_DEBUG:
                    traceback.print_exc()

    server = ThreadingUDPServer((address, port), UDPHandler)

    print "[i] running UDP server at '%s:%d'" % (server.server_address[0], server.server_address[1])

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
