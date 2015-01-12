#!/usr/bin/env python

from __future__ import print_function

import glob
import inspect
import pickle
import os
import sys
import time
import zlib

from core.common import *
from core.settings import *

def load_blacklists(verbose=True):
    """
    Loads blacklists
    """

    retval = {}

    if not verbose:
        def _(*args, **kwargs):
            pass
        __builtins__.original_print = __builtins__.print
        __builtins__.print = _

    retval = dict((getattr(BLACKLIST, _), {}) for _ in dir(BLACKLIST) if _ == _.upper())

    if not os.path.isfile(CACHE_FILE) or (time.time() - os.stat(CACHE_FILE).st_mtime) / 3600 / 24 > FRESH_LISTS_DELTA_DAYS or os.stat(CACHE_FILE).st_size == 0:
        print("[i] %s blacklists..." % ("updating" if os.path.isfile(CACHE_FILE) else "retrieving"))

        try:
            if not os.path.isdir(STORAGE_DIRECTORY):
                os.makedirs(STORAGE_DIRECTORY, 0755)
            with open(CACHE_FILE, "w+b") as f:
                pass
        except Exception, ex:
            exit("[!] something went wrong during cache file write '%s' ('%s')" % (CACHE_FILE, ex))

        sys.path.append(os.path.abspath(os.path.join(ROOT_DIR, "feeds")))
        for filename in glob.glob(os.path.join(ROOT_DIR, "feeds", "*.py")):
            try:
                module = __import__(os.path.basename(filename).split(".py")[0])
            except (ImportError, SyntaxError), ex:
                print("[!] something went wrong during import of feed file '%s' ('%s')" % (filename, ex))

            for name, function in inspect.getmembers(module, inspect.isfunction):
                if name == "fetch":
                    print(" [o] '%s'" % module.__url__)
                    found = False
                    results = function()
                    for key in results:
                        if results[key]:
                            found = True
                            retval[key].update(results[key])
                    if not found:
                        print("[!] something went wrong during remote data retrieval ('%s')" % module.__url__)

        try:
            with open(CACHE_FILE, "w+b") as f:
                f.write(zlib.compress(pickle.dumps(retval)))
        except Exception, ex:
            print("[!] something went wrong during cache file write '%s' ('%s')" % (CACHE_FILE, ex))

    if not max(len(_) for _ in retval.values()):
        print("[i] loading cache...")
        try:
            with open(CACHE_FILE, "rb") as f:
                retval = pickle.loads(zlib.decompress(f.read()))
        except Exception, ex:
            exit("[x] something went wrong during cache file read '%s' ('%s')" % (CACHE_FILE, ex))

    for type_ in retval:
        print("[i] %d blacklisted %s entries loaded" % (len(retval[type_]), type_))

    if not verbose:
        __builtins__.print = __builtins__.original_print

    return retval
