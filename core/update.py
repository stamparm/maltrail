#!/usr/bin/env python

"""
Copyright (c) 2014-2015 Miroslav Stampar (@stamparm)
See the file 'LICENSE' for copying permission
"""

import csv
import glob
import inspect
import os
import subprocess
import sys
import time

sys.dont_write_bytecode = True
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))  # to enable calling from current directory too

from core.common import load_trails
from core.common import retrieve_content
from core.settings import config
from core.settings import read_whitelist
from core.settings import BAD_TRAIL_PREFIXES
from core.settings import LOW_PRIORITY_INFO_KEYWORDS
from core.settings import ROOT_DIR
from core.settings import TRAILS_FILE
from core.settings import USERS_DIRECTORY
from core.settings import WHITELIST

def _fopen_trails(mode):
    retval = open(TRAILS_FILE, mode)
    if "w+" in mode and not subprocess.mswindows:
        try:
            os.chown(TRAILS_FILE, int(os.environ.get("SUDO_UID", -1)), int(os.environ.get("SUDO_GID", -1)))
        except Exception, ex:
            print "[x] '%s'" % ex
    return retval

def update(server=None):
    """
    Update trails from feeds
    """

    trails = {}

    if server:
        print "[i] retrieving trails from provided 'UPDATE_SERVER' server..."
        _ = retrieve_content(server)
        if not _:
            print "[!] unable to retrieve data from '%s'" % server
        else:
            with _fopen_trails("w+b") as f:
                f.write(_)
            trails = load_trails()

    if not trails and ((not os.path.isfile(TRAILS_FILE) or (time.time() - os.stat(TRAILS_FILE).st_mtime) >= config.UPDATE_PERIOD or os.stat(TRAILS_FILE).st_size == 0)):
        try:
            if not os.path.isdir(USERS_DIRECTORY):
                os.makedirs(USERS_DIRECTORY, 0755)
        except Exception, ex:
            exit("[!] something went wrong during creation of directory '%s' ('%s')" % (USERS_DIRECTORY, ex))

        print "[i] updating trails..."

        sys.path.append(os.path.abspath(os.path.join(ROOT_DIR, "trails", "feeds")))
        filenames = glob.glob(os.path.join(sys.path[-1], "*.py"))

        sys.path.append(os.path.abspath(os.path.join(ROOT_DIR, "trails")))
        filenames += [os.path.join(sys.path[-1], "static")]
        filenames += [os.path.join(sys.path[-1], "custom")]

        for filename in filenames:
            try:
                module = __import__(os.path.basename(filename).split(".py")[0])
            except (ImportError, SyntaxError), ex:
                print "[!] something went wrong during import of feed file '%s' ('%s')" % (filename, ex)
                continue

            for name, function in inspect.getmembers(module, inspect.isfunction):
                if name == "fetch":
                    print(" [o] '%s'" % module.__url__)
                    results = function()
                    for item in results.items():
                        if not (any(_ in item[1][0] for _ in LOW_PRIORITY_INFO_KEYWORDS) and item[0] in trails):
                            trails[item[0]] = item[1]
                    if not results:
                        print "[!] something went wrong during remote data retrieval ('%s')" % module.__url__

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
                    for trail in sorted(trails.keys()):
                        writer.writerow((trail, trails[trail][0], trails[trail][1]))

        except Exception, ex:
            print "[!] something went wrong during trails file write '%s' ('%s')" % (TRAILS_FILE, ex)

    return trails

def main():
    update()

if __name__ == "__main__":
    main()
