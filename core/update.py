#!/usr/bin/env python

"""
Copyright (c) 2014-2016 Miroslav Stampar (@stamparm)
See the file 'LICENSE' for copying permission
"""

import csv
import glob
import inspect
import os
import sqlite3
import subprocess
import sys
import time
import urllib

sys.dont_write_bytecode = True
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))  # to enable calling from current directory too

from core.addr import addr_to_int
from core.common import load_trails
from core.common import retrieve_content
from core.settings import config
from core.settings import read_whitelist
from core.settings import BAD_TRAIL_PREFIXES
from core.settings import FRESH_IPCAT_DELTA_DAYS
from core.settings import LOW_PRIORITY_INFO_KEYWORDS
from core.settings import HIGH_PRIORITY_INFO_KEYWORDS
from core.settings import HIGH_PRIORITY_REFERENCES
from core.settings import IPCAT_CSV_FILE
from core.settings import IPCAT_SQLITE_FILE
from core.settings import IPCAT_URL
from core.settings import ROOT_DIR
from core.settings import TRAILS_FILE
from core.settings import USERS_DIR
from core.settings import WHITELIST

def _chown(filepath):
    if not subprocess.mswindows and os.path.exists(filepath):
        try:
            os.chown(filepath, int(os.environ.get("SUDO_UID", -1)), int(os.environ.get("SUDO_GID", -1)))
        except Exception, ex:
            print "[x] '%s'" % ex

def _fopen_trails(mode):
    retval = open(TRAILS_FILE, mode)
    if "w+" in mode:
        _chown(TRAILS_FILE)
    return retval

def update_trails(server=None, force=False):
    """
    Update trails from feeds
    """

    trails = {}
    duplicates = {}

    if server:
        print "[i] retrieving trails from provided 'UPDATE_SERVER' server..."
        _ = retrieve_content(server)
        if not _:
            exit("[!] unable to retrieve data from '%s'" % server)
        else:
            with _fopen_trails("w+b") as f:
                f.write(_)
            trails = load_trails()

    trail_files = []
    for dirpath, dirnames, filenames in os.walk(os.path.abspath(os.path.join(ROOT_DIR, "trails"))) :
        for filename in filenames:
            trail_files.append(os.path.abspath(os.path.join(dirpath, filename)))

    if config.CUSTOM_TRAILS_DIR:
        for dirpath, dirnames, filenames in os.walk(os.path.abspath(os.path.join(ROOT_DIR, os.path.expanduser(config.CUSTOM_TRAILS_DIR)))) :
            for filename in filenames:
                trail_files.append(os.path.abspath(os.path.join(dirpath, filename)))

    try:
        if not os.path.isdir(USERS_DIR):
            os.makedirs(USERS_DIR, 0755)
    except Exception, ex:
        exit("[!] something went wrong during creation of directory '%s' ('%s')" % (USERS_DIR, ex))

    _chown(USERS_DIR)

    if not trails and (force or not os.path.isfile(TRAILS_FILE) or (time.time() - os.stat(TRAILS_FILE).st_mtime) >= config.UPDATE_PERIOD or os.stat(TRAILS_FILE).st_size == 0 or any(os.stat(_).st_mtime > os.stat(TRAILS_FILE).st_mtime for _ in trail_files)):
        print "[i] updating trails (this might take a while)..."

        if force or config.USE_FEED_UPDATES:
            sys.path.append(os.path.abspath(os.path.join(ROOT_DIR, "trails", "feeds")))
            filenames = sorted(glob.glob(os.path.join(sys.path[-1], "*.py")))
        else:
            filenames = []

        sys.path.append(os.path.abspath(os.path.join(ROOT_DIR, "trails")))
        filenames += [os.path.join(sys.path[-1], "static")]
        filenames += [os.path.join(sys.path[-1], "custom")]

        filenames = [_ for _ in filenames if "__init__.py" not in _]

        for i in xrange(len(filenames)):
            filename = filenames[i]

            try:
                module = __import__(os.path.basename(filename).split(".py")[0])
            except (ImportError, SyntaxError), ex:
                print "[x] something went wrong during import of feed file '%s' ('%s')" % (filename, ex)
                continue

            for name, function in inspect.getmembers(module, inspect.isfunction):
                if name == "fetch":
                    print(" [o] '%s'%s" % (module.__url__, " " * 20 if len(module.__url__) < 20 else ""))
                    sys.stdout.write("[?] progress: %d/%d (%d%%)\r" % (i, len(filenames), i * 100 / len(filenames)))
                    sys.stdout.flush()
                    try:
                        results = function()
                        for item in results.items():
                            if item[0] in trails:
                                if item[0] not in duplicates:
                                    duplicates[item[0]] = set((trails[item[0]][1],))
                                duplicates[item[0]].add(item[1][1])
                            if not (item[0] in trails and (any(_ in item[1][0] for _ in LOW_PRIORITY_INFO_KEYWORDS) or trails[item[0]][1] in HIGH_PRIORITY_REFERENCES)) or item[1][1] in HIGH_PRIORITY_REFERENCES or any(_ in item[1][0] for _ in HIGH_PRIORITY_INFO_KEYWORDS):
                                trails[item[0]] = item[1]
                        if not results and "abuse.ch" not in module.__url__:
                            print "[x] something went wrong during remote data retrieval ('%s')" % module.__url__
                    except Exception, ex:
                        print "[x] something went wrong during processing of feed file '%s' ('%s')" % (filename, ex)

        # basic cleanup
        for key in trails.keys():
            if key not in trails:
                continue
            if '?' in key:
                _ = trails[key]
                del trails[key]
                key = key.split('?')[0]
                trails[key] = _
            if '//' in key:
                _ = trails[key]
                del trails[key]
                key = key.replace('//', '/')
                trails[key] = _
            if key != key.lower():
                _ = trails[key]
                del trails[key]
                key = key.lower()
                trails[key] = _
            if key in duplicates:
                _ = trails[key]
                trails[key] = (_[0], "%s (+%s)" % (_[1], ','.join(sorted(duplicates[key] - set((_[1],))))))

        read_whitelist()

        for key in trails.keys():
            if key in WHITELIST or any(key.startswith(_) for _ in BAD_TRAIL_PREFIXES):
                del trails[key]
            else:
                try:
                    key.decode("utf8")
                    trails[key][0].decode("utf8")
                    trails[key][1].decode("utf8")
                except UnicodeDecodeError:
                    del trails[key]

        try:
            if trails:
                with _fopen_trails("w+b") as f:
                    writer = csv.writer(f, delimiter=',', quotechar='\"', quoting=csv.QUOTE_MINIMAL)
                    for trail in trails:
                        writer.writerow((trail, trails[trail][0], trails[trail][1]))

        except Exception, ex:
            print "[x] something went wrong during trails file write '%s' ('%s')" % (TRAILS_FILE, ex)

    return trails

def update_ipcat(force=False):
    try:
        if not os.path.isdir(USERS_DIR):
            os.makedirs(USERS_DIR, 0755)
    except Exception, ex:
        exit("[!] something went wrong during creation of directory '%s' ('%s')" % (USERS_DIR, ex))

    _chown(USERS_DIR)

    if force or not os.path.isfile(IPCAT_CSV_FILE) or not os.path.isfile(IPCAT_SQLITE_FILE) or (time.time() - os.stat(IPCAT_CSV_FILE).st_mtime) >= FRESH_IPCAT_DELTA_DAYS * 24 * 3600 or os.stat(IPCAT_SQLITE_FILE).st_size == 0:
        print "[i] updating ipcat database..."

        try:
            urllib.urlretrieve(IPCAT_URL, IPCAT_CSV_FILE)
        except Exception, ex:
            print "[x] something went wrong during retrieval of '%s' ('%s')" % (IPCAT_URL, ex)

        else:
            try:
                if os.path.exists(IPCAT_SQLITE_FILE):
                    os.remove(IPCAT_SQLITE_FILE)

                with sqlite3.connect(IPCAT_SQLITE_FILE, isolation_level=None, check_same_thread=False) as con:
                    cur = con.cursor()
                    cur.execute("BEGIN TRANSACTION")
                    cur.execute("CREATE TABLE ranges (start_int INT, end_int INT, name TEXT)")

                    with open(IPCAT_CSV_FILE) as f:
                        for row in f:
                            if not row.startswith('#') and not row.startswith('start'):
                                row = row.strip().split(",")
                                cur.execute("INSERT INTO ranges VALUES (?, ?, ?)", (addr_to_int(row[0]), addr_to_int(row[1]), row[2]))

                    cur.execute("COMMIT")
                    cur.close()
                    con.commit()
            except Exception, ex:
                print "[x] something went wrong during ipcat database update ('%s')" % ex

    _chown(IPCAT_CSV_FILE)
    _chown(IPCAT_SQLITE_FILE)

def main():
    try:
        update_trails(force=True)
        update_ipcat()
    except KeyboardInterrupt:
        print "\r[x] Ctrl-C pressed"

if __name__ == "__main__":
    main()
