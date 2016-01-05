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

def log_event(event_tuple):
    try:
        sec, usec, src_ip, dst_ip = event_tuple[0], event_tuple[1], event_tuple[2], event_tuple[4]
        if not any(_ in WHITELIST for _ in (src_ip, dst_ip)):
            localtime = "%s.%06d" % (time.strftime(TIME_FORMAT, time.localtime(int(sec))), usec)
            event = "%s %s %s\n" % (safe_value(localtime), safe_value(config.SENSOR_NAME), " ".join(safe_value(_) for _ in event_tuple[2:]))
            if not config.DISABLE_LOCAL_LOG_STORAGE:
                handle = get_event_log_handle(sec)
                os.write(handle, event)
            if config.LOG_SERVER:
                remote_host, remote_port = config.LOG_SERVER.split(':')
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.sendto("%s %s" % (sec, event), (remote_host, int(remote_port)))
            if config.DISABLE_LOCAL_LOG_STORAGE and not config.LOG_SERVER:
                sys.stdout.write(event)
                sys.stdout.flush()
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
