#!/usr/bin/env python

"""
Copyright (c) 2014-2025 Maltrail developers (https://github.com/stamparm/maltrail/)
See the file 'LICENSE' for copying permission
"""
from __future__ import print_function

import codecs
import csv
import glob
import inspect
import os
import re
import sqlite3
import sys
import time

sys.dont_write_bytecode = True
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))  # to enable calling from current directory too

from core.addr import addr_to_int
from core.addr import int_to_addr
from core.addr import make_mask
from core.common import bogon_ip
from core.common import cdn_ip
from core.common import check_whitelisted
from core.common import load_trails
from core.common import retrieve_content
from core.compat import xrange
from core.settings import config
from core.settings import read_config
from core.settings import read_whitelist
from core.settings import BAD_TRAIL_PREFIXES
from core.settings import FRESH_IPCAT_DELTA_DAYS
from core.settings import LOW_PRIORITY_INFO_KEYWORDS
from core.settings import HIGH_PRIORITY_INFO_KEYWORDS
from core.settings import HIGH_PRIORITY_REFERENCES
from core.settings import IPCAT_CSV_FILE
from core.settings import IPCAT_SQLITE_FILE
from core.settings import IPCAT_URL
from core.settings import IS_WIN
from core.settings import ROOT_DIR
from core.settings import UNICODE_ENCODING
from core.settings import USERS_DIR
from core.trailsdict import TrailsDict
from thirdparty import six
from thirdparty.six.moves import urllib as _urllib

# patch for self-signed certificates (e.g. CUSTOM_TRAILS_URL)
try:
    import ssl
    ssl._create_default_https_context = ssl._create_unverified_context
except (ImportError, AttributeError):
    pass

def _chown(filepath):
    if not IS_WIN and os.path.exists(filepath):
        try:
            os.chown(filepath, int(os.environ.get("SUDO_UID", -1)), int(os.environ.get("SUDO_GID", -1)))
        except Exception as ex:
            print("[!] chown problem with '%s' ('%s')" % (filepath, ex))

def _fopen(filepath, mode="rb", opener=open):
    retval = opener(filepath, mode)
    if "w+" in mode:
        _chown(filepath)
    return retval

def update_trails(force=False, offline=False):
    """
    Update trails from feeds
    """

    success = False
    trails = TrailsDict()
    duplicates = {}

    try:
        if not os.path.isdir(USERS_DIR):
            os.makedirs(USERS_DIR, 0o755)
    except Exception as ex:
        sys.exit("[!] something went wrong during creation of directory '%s' ('%s')" % (USERS_DIR, ex))

    _chown(USERS_DIR)

    if config.UPDATE_SERVER:
        print("[i] retrieving trails from provided 'UPDATE_SERVER' server...")
        content = retrieve_content(config.UPDATE_SERVER)
        if not content or content.count(',') < 2:
            print("[x] unable to retrieve data from '%s'" % config.UPDATE_SERVER)
        else:
            with _fopen(config.TRAILS_FILE, "w+b" if six.PY2 else "w+", open if six.PY2 else codecs.open) as f:
                f.write(content)
            trails = load_trails()

    else:
        trail_files = set()
        for dirpath, dirnames, filenames in os.walk(os.path.abspath(os.path.join(ROOT_DIR, "trails"))):
            for filename in filenames:
                trail_files.add(os.path.abspath(os.path.join(dirpath, filename)))

        if config.CUSTOM_TRAILS_DIR:
            for dirpath, dirnames, filenames in os.walk(os.path.abspath(os.path.join(ROOT_DIR, os.path.expanduser(config.CUSTOM_TRAILS_DIR)))):
                for filename in filenames:
                    trail_files.add(os.path.abspath(os.path.join(dirpath, filename)))

        if not trails and (force or not os.path.isfile(config.TRAILS_FILE) or (time.time() - os.stat(config.TRAILS_FILE).st_mtime) >= config.UPDATE_PERIOD or os.stat(config.TRAILS_FILE).st_size == 0 or any(os.stat(_).st_mtime > os.stat(config.TRAILS_FILE).st_mtime for _ in trail_files)):
            if not config.offline:
                print("[i] updating trails (this might take a while)...")
            else:
                print("[i] checking trails...")

            if not offline and (force or config.USE_FEED_UPDATES):
                _ = os.path.abspath(os.path.join(ROOT_DIR, "trails", "feeds"))
                if _ not in sys.path:
                    sys.path.append(_)

                filenames = sorted(glob.glob(os.path.join(_, "*.py")))
            else:
                filenames = []

            _ = os.path.abspath(os.path.join(ROOT_DIR, "trails"))
            if _ not in sys.path:
                sys.path.append(_)

            filenames += [os.path.join(_, "custom")]
            filenames += [os.path.join(_, "static")]    # Note: higher priority than previous one because of dummy user trails (FE)

            filenames = [_ for _ in filenames if "__init__.py" not in _]

            if config.DISABLED_FEEDS:
                filenames = [filename for filename in filenames if os.path.splitext(os.path.split(filename)[-1])[0] not in re.split(r"[^\w]+", config.DISABLED_FEEDS)]

            for i in xrange(len(filenames)):
                filename = filenames[i]

                try:
                    module = __import__(os.path.basename(filename).split(".py")[0])
                except (ImportError, SyntaxError) as ex:
                    print("[x] something went wrong during import of feed file '%s' ('%s')" % (filename, ex))
                    continue

                for name, function in inspect.getmembers(module, inspect.isfunction):
                    if name == "fetch":
                        url = module.__url__  # Note: to prevent "SyntaxError: can not delete variable 'module' referenced in nested scope"

                        print(" [o] '%s'%s" % (url, " " * 20 if len(url) < 20 else ""))
                        sys.stdout.write("[?] progress: %d/%d (%d%%)\r" % (i, len(filenames), i * 100 // len(filenames)))
                        sys.stdout.flush()

                        if config.DISABLED_TRAILS_INFO_REGEX and re.search(config.DISABLED_TRAILS_INFO_REGEX, getattr(module, "__info__", "")):
                            continue

                        try:
                            results = function()
                            for item in results.items():
                                if item[0].startswith("www.") and '/' not in item[0]:
                                    item = [item[0][len("www."):], item[1]]
                                if item[0] in trails:
                                    if item[0] not in duplicates:
                                        duplicates[item[0]] = set((trails[item[0]][1],))
                                    duplicates[item[0]].add(item[1][1])
                                if not (item[0] in trails and (any(_ in item[1][0] for _ in LOW_PRIORITY_INFO_KEYWORDS) or trails[item[0]][1] in HIGH_PRIORITY_REFERENCES)) or (item[1][1] in HIGH_PRIORITY_REFERENCES and "history" not in item[1][0]) or any(_ in item[1][0] for _ in HIGH_PRIORITY_INFO_KEYWORDS):
                                    trails[item[0]] = item[1]
                            if not results and not any(_ in url for _ in ("abuse.ch", "cobaltstrike")):
                                print("[x] something went wrong during remote data retrieval ('%s')" % url)
                        except Exception as ex:
                            print("[x] something went wrong during processing of feed file '%s' ('%s')" % (filename, ex))

                try:
                    sys.modules.pop(module.__name__)
                    del module
                except Exception:
                    pass

            # custom trails from remote location
            if config.CUSTOM_TRAILS_URL:
                print(" [o] '(remote custom)'%s" % (" " * 20))
                for url in re.split(r"[;,]", config.CUSTOM_TRAILS_URL):
                    url = url.strip()
                    if not url:
                        continue

                    url = ("http://%s" % url) if "//" not in url else url
                    content = retrieve_content(url)

                    if not content:
                        print("[x] unable to retrieve data (or empty response) from '%s'" % url)
                    else:
                        __info__ = "blacklisted"
                        __reference__ = "(remote custom)"  # urlparse.urlsplit(url).netloc
                        for line in content.split('\n'):
                            line = line.strip()
                            if not line or line.startswith('#'):
                                continue
                            line = re.sub(r"\s*#.*", "", line)
                            if '://' in line:
                                line = re.search(r"://(.*)", line).group(1)
                            line = line.rstrip('/')

                            if line in trails and any(_ in trails[line][1] for _ in ("custom", "static")):
                                continue

                            if '/' in line:
                                trails[line] = (__info__, __reference__)
                                line = line.split('/')[0]
                            elif re.search(r"\A\d+\.\d+\.\d+\.\d+\Z", line):
                                trails[line] = (__info__, __reference__)
                            else:
                                trails[line.strip('.')] = (__info__, __reference__)

                        for match in re.finditer(r"(\d+\.\d+\.\d+\.\d+)/(\d+)", content):
                            prefix, mask = match.groups()
                            mask = int(mask)
                            if mask > 32:
                                continue
                            start_int = addr_to_int(prefix) & make_mask(mask)
                            end_int = start_int | ((1 << 32 - mask) - 1)
                            if 0 <= end_int - start_int <= 1024:
                                address = start_int
                                while start_int <= address <= end_int:
                                    trails[int_to_addr(address)] = (__info__, __reference__)
                                    address += 1

            print("[i] post-processing trails (this might take a while)...")

            # basic cleanup
            for key in list(trails.keys()):
                if key not in trails:
                    continue

                if config.DISABLED_TRAILS_INFO_REGEX:
                    if re.search(config.DISABLED_TRAILS_INFO_REGEX, trails[key][0]):
                        del trails[key]
                        continue

                try:
                    _key = key.decode(UNICODE_ENCODING) if isinstance(key, bytes) else key
                    _key = _key.encode("idna")
                    if six.PY3:
                        _key = _key.decode(UNICODE_ENCODING)
                    if _key != key:  # for domains with non-ASCII letters (e.g. phishing)
                        trails[_key] = trails[key]
                        del trails[key]
                        key = _key
                except:
                    pass

                if not key or re.search(r"(?i)\A\.?[a-z]+\Z", key) and not any(_ in trails[key][1] for _ in ("custom", "static")):
                    del trails[key]
                    continue

                if re.search(r"\A\d+\.\d+\.\d+\.\d+\Z", key):
                    if any(_ in trails[key][0] for _ in ("parking site", "sinkhole")) and key in duplicates:    # Note: delete (e.g.) junk custom trails if static trail is a sinkhole
                        del duplicates[key]

                    if trails[key][0] == "malware":
                        trails[key] = ("potential malware site", trails[key][1])

                    if config.get("IP_MINIMUM_FEEDS", 3) > 1:
                        if (key not in duplicates or len(duplicates[key]) < config.get("IP_MINIMUM_FEEDS", 3)) and re.search(r"\b(custom|static)\b", trails[key][1]) is None:
                            del trails[key]
                            continue

                    if any(int(_) > 255 for _ in key.split('.')):
                        del trails[key]
                        continue

                if trails[key][0] == "ransomware":
                    trails[key] = ("ransomware (malware)", trails[key][1])

                if key.startswith("www.") and '/' not in key:
                    _ = trails[key]
                    del trails[key]
                    key = key[len("www."):]
                    if key:
                        trails[key] = _

                if '?' in key and not key.startswith('/'):
                    _ = trails[key]
                    del trails[key]
                    key = key.split('?')[0]
                    if key:
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
                    others = sorted(duplicates[key] - set((_[1],)))
                    if others and " (+" not in _[1]:
                        trails[key] = (_[0], "%s (+%s)" % (_[1], ','.join(others)))

            read_whitelist()

            for key in list(trails.keys()):
                match = re.search(r"\A(\d+\.\d+\.\d+\.\d+)\b", key)
                if check_whitelisted(key) or any(key.startswith(_) for _ in BAD_TRAIL_PREFIXES):
                    del trails[key]
                elif match and (bogon_ip(match.group(1)) or cdn_ip(match.group(1))) and not any(_ in trails[key][0] for _ in ("parking", "sinkhole")):
                    del trails[key]
                else:
                    try:
                        key.decode("utf8") if hasattr(key, "decode") else key.encode("utf8")
                        trails[key][0].decode("utf8") if hasattr(trails[key][0], "decode") else trails[key][0].encode("utf8")
                        trails[key][1].decode("utf8") if hasattr(trails[key][1], "decode") else trails[key][1].encode("utf8")
                    except UnicodeError:
                        del trails[key]

            try:
                if trails:
                    with _fopen(config.TRAILS_FILE, "w+b" if six.PY2 else "w+", open if six.PY2 else codecs.open) as f:
                        writer = csv.writer(f, delimiter=',', quotechar='\"', quoting=csv.QUOTE_MINIMAL)
                        for trail in trails:
                            row = (trail, trails[trail][0], trails[trail][1])
                            writer.writerow(row)

                    success = True
            except Exception as ex:
                print("[x] something went wrong during trails file write '%s' ('%s')" % (config.TRAILS_FILE, ex))

            print("[i] update finished%s" % (40 * " "))

            if success:
                print("[i] trails stored to '%s'" % config.TRAILS_FILE)

    return trails

def update_ipcat(force=False):
    try:
        if not os.path.isdir(USERS_DIR):
            os.makedirs(USERS_DIR, 0o755)
    except Exception as ex:
        sys.exit("[!] something went wrong during creation of directory '%s' ('%s')" % (USERS_DIR, ex))

    _chown(USERS_DIR)

    if force or not os.path.isfile(IPCAT_CSV_FILE) or not os.path.isfile(IPCAT_SQLITE_FILE) or (time.time() - os.stat(IPCAT_CSV_FILE).st_mtime) >= FRESH_IPCAT_DELTA_DAYS * 24 * 3600 or os.stat(IPCAT_SQLITE_FILE).st_size == 0:
        print("[i] updating ipcat database...")

        try:
            with open(IPCAT_CSV_FILE, "w+b") as f:
                f.write(_urllib.request.urlopen(IPCAT_URL).read())
        except Exception as ex:
            print("[x] something went wrong during retrieval of '%s' ('%s')" % (IPCAT_URL, ex))

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
            except Exception as ex:
                print("[x] something went wrong during ipcat database update ('%s')" % ex)

    _chown(IPCAT_CSV_FILE)
    _chown(IPCAT_SQLITE_FILE)

def main():
    if "-c" in sys.argv:
        read_config(sys.argv[sys.argv.index("-c") + 1])

    try:
        offline = "--offline" in sys.argv
        update_trails(force=True, offline=offline)
        if not offline:
            update_ipcat()
    except KeyboardInterrupt:
        print("\r[x] Ctrl-C pressed")
    else:
        if "-r" in sys.argv:
            results = []
            with _fopen(config.TRAILS_FILE, "rb" if six.PY2 else 'r', open if six.PY2 else codecs.open) as f:
                for line in f:
                    if line and line[0].isdigit():
                        items = line.split(',', 2)
                        if re.search(r"\A[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\Z", items[0]):
                            ip = items[0]
                            reputation = 1
                            lists = items[-1]
                            if '+' in lists:
                                reputation = 2 + lists.count(',')
                            if "(custom)" in lists:
                                reputation -= 1
                            if "(static)" in lists:
                                reputation -= 1
                            reputation -= max(0, lists.count("prox") + lists.count("maxmind") + lists.count("spys.ru") + lists.count("rosinstrument") - 1)      # remove duplicate proxy hits
                            reputation -= max(0, lists.count("blutmagie") + lists.count("torproject") - 1)                                                      # remove duplicate tor hits
                            if reputation > 0:
                                results.append((ip, reputation))
            results = sorted(results, key=lambda _: _[1], reverse=True)
            for result in results:
                sys.stderr.write("%s\t%s\n" % (result[0], result[1]))
                sys.stderr.flush()

        if "--console" in sys.argv:
            with _fopen(config.TRAILS_FILE, "rb" if six.PY2 else 'r', open if six.PY2 else codecs.open) as f:
                for line in f:
                    sys.stdout.write(line)

if __name__ == "__main__":
    main()
