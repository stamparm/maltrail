#!/usr/bin/env python

"""
Copyright (c) 2014-2015 Miroslav Stampar (@stamparm)
See the file 'LICENSE' for copying permission
"""

import sqlite3
import threading

from core.settings import *

_thread_data = threading.local()
_history_file = HISTORY_FILE

def set_db(filepath):
    global _history_file
    _history_file = filepath

def get_cursor():
    if not hasattr(_thread_data, "cursor"):
        _thread_data.connection = sqlite3.connect(_history_file, isolation_level=None)
        _thread_data.cursor = _thread_data.connection.cursor()
        _thread_data.cursor.execute(HISTORY_CREATE_TABLE)
    return _thread_data.cursor

def store_db(sec, usec, src, dst, type_, trail, info, reference):
    get_cursor().execute("INSERT INTO history VALUES(%s, %s, '%s', '%s', '%s', '%s', '%s', '%s')" % (sec, usec, src, dst, type_, trail, info, reference))

def close_db():
    if hasattr(_thread_data, "cursor"):
        _thread_data.connection.commit()
        _thread_data.cursor.close()
        _thread_data.connection.close()