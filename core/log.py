#!/usr/bin/env python

"""
Copyright (c) 2014-2015 Miroslav Stampar (@stamparm)
See the file 'LICENSE' for copying permission
"""

import os
import socket
import SocketServer
import threading
import time

from core.common import check_sudo
from core.settings import config
from core.settings import DEFAULT_LOG_PERMISSIONS
from core.settings import TIME_FORMAT

_thread_data = threading.local()

def create_log_directory():
    if not os.path.isdir(config.LOG_DIRECTORY):
        if check_sudo() is False:
            exit("[x] please run with sudo/Administrator privileges")
        os.makedirs(config.LOG_DIRECTORY)
    print("[i] using '%s' for log storage" % config.LOG_DIRECTORY)

def get_log_handle(sec, flags=os.O_APPEND | os.O_CREAT | os.O_WRONLY):
    localtime = time.localtime(sec)
    _ = os.path.join(config.LOG_DIRECTORY, "%d-%02d-%02d.log" % (localtime.tm_year, localtime.tm_mon, localtime.tm_mday))
    if _ != getattr(_thread_data, "log_path", None):
        if not os.path.exists(_):
            open(_, "w+").close()
            os.chmod(_, DEFAULT_LOG_PERMISSIONS)
        _thread_data.log_path = _
        _thread_data.log_handle = os.open(_thread_data.log_path, flags)
    return _thread_data.log_handle

def safe_value(value):
    retval = str(value or '-')
    if ' ' in retval:
        retval = "\"%s\"" % retval
    return retval

def log_event(event_tuple):
    sec, usec = event_tuple[0], event_tuple[1]
    localtime = "%s.%06d" % (time.strftime(TIME_FORMAT, time.localtime(int(sec))), usec)
    event = "%s %s %s\n" % (safe_value(localtime), safe_value(config.SENSOR_NAME), " ".join(safe_value(_) for _ in event_tuple[2:]))
    if config.LOG_SERVER:
        remote_host, remote_port = config.LOG_SERVER.split(':')
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.sendto("%s %s" % (sec, event), (remote_host, int(remote_port)))
    else:
        handle = get_log_handle(sec)
        os.write(handle, event)

def start_logd(address=None, port=None, join=False):
    class ThreadingUDPServer(SocketServer.ThreadingMixIn, SocketServer.UDPServer):
        pass

    class UDPHandler(SocketServer.BaseRequestHandler):
        def handle(self):
            data, _ = self.request
            sec, event = data.split(" ", 1)
            handle = get_log_handle(int(sec))
            os.write(handle, event)

    server = SocketServer.UDPServer((address, port), UDPHandler)

    print "[i] running UDP server at '%s:%d'" % (server.server_address[0], server.server_address[1])

    if join:
        server.serve_forever()
    else:
        thread = threading.Thread(target=server.serve_forever)
        thread.daemon = True
        thread.start()
