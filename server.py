#!/usr/bin/env python

"""
Copyright (c) 2014-2026 Maltrail developers (https://github.com/stamparm/maltrail/)
See the file 'LICENSE' for copying permission
"""


import sys

sys.dont_write_bytecode = True

import argparse
import errno
import os
import platform
import threading
import time
import traceback

from core import alert
from core.common import check_connection
from core.common import check_sudo
from core.common import get_ex_message
from core.common import patch_parser
from core.common import uses_published_key
from core.httpd import start_httpd
from core import meta
from core.log import create_log_directory
from core.log import log_error
from core.log import start_logd
from core.settings import config
from core.settings import read_config
from core.settings import CHECK_CONNECTION_MAX_RETRIES
from core.settings import CONFIG_FILE
from core.settings import HOMEPAGE
from core.settings import IS_WIN
from core.settings import META_DB_FILENAME
from core.settings import NAME
from core.settings import VERSION
from core.update import update_geo
from core.update import update_ipcat
from core.update import fetch_provenance
from core.update import update_trails

def main():
    print("%s (server) #v%s {%s}\n" % (NAME, VERSION, HOMEPAGE))

    if "--version" in sys.argv:
        raise SystemExit

    parser = argparse.ArgumentParser()
    parser.add_argument("--version", action="version", version=VERSION)
    parser.add_argument("-c", dest="config_file", default=CONFIG_FILE, help="configuration file (default: '%s')" % os.path.split(CONFIG_FILE)[-1])
    parser.add_argument("--debug", dest="debug", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--smoke-test", dest="smoke_test", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--detect-test", dest="detect_test", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--keep", dest="keep", default=None, metavar="DIR", help="with --detect-test: keep the generated events in DIR (and replay the parity corpus into it) instead of deleting them")
    parser.add_argument("--serve", dest="serve", action="store_true", help="with --detect-test --keep: start the web server on the generated events")
    parser.add_argument("--doctor", dest="doctor", action="store_true", help="validate the deployment (log dir, trails age, USERS, TLS, ports) and exit")
    parser.add_argument("--rebuild-index", dest="rebuild_index", action="store_true", help="(re)build the per-day event-log sidecar index (LOG_DIR/index/) and exit")

    patch_parser(parser)

    options = parser.parse_args()

    if options.smoke_test:
        from core.testing import smoke_test
        raise SystemExit(0 if smoke_test() else 1)

    if options.detect_test:
        from core.testing import detect_test
        raise SystemExit(0 if detect_test(keep=options.keep, serve=options.serve) else 1)

    if options.serve or options.keep:
        sys.exit("[!] '--keep' and '--serve' only apply together with '--detect-test'")

    print("[*] starting @ %s\n" % time.strftime("%X /%Y-%m-%d/"))

    read_config(options.config_file)

    if options.debug:
        config.SHOW_DEBUG = True

    if options.doctor:
        from core.doctor import run as doctor_run
        raise SystemExit(doctor_run())

    if options.rebuild_index:
        import glob as _glob
        import re as _re
        from core import index as _index
        built = 0
        for filepath in sorted(_glob.glob(os.path.join(config.LOG_DIR, "*.log"))):
            day = os.path.splitext(os.path.basename(filepath))[0]
            if not _re.search(r"\A\d{4}-\d{2}-\d{2}\Z", day):
                continue
            ok = _index.prepare(day)
            print("[%s] %s" % ("+" if ok else "x", filepath))
            built += 1 if ok else 0
        reaped = _index.sweep()
        print("[i] indexed %d day(s)%s" % (built, ", removed %d stale sidecar(s)" % reaped if reaped else ""))
        raise SystemExit(0 if built or not _glob.glob(os.path.join(config.LOG_DIR, "*.log")) else 1)

    # NOTE: this validation used to live inside an `if six.PY2 and config.USE_SSL:` block, so on
    # Python 3 it never ran and a missing/invalid SSL_PEM only failed later, inside the server
    # thread. It is a plain USE_SSL check now.
    if config.USE_SSL:
        hint = "openssl req -new -x509 -keyout %s -out %s -days 365 -nodes -subj '/O=%s CA/C=EU'" % (config.SSL_PEM or "server.pem", config.SSL_PEM or "server.pem", NAME)
        if not config.SSL_PEM or not os.path.isfile(config.SSL_PEM):
            sys.exit("[!] invalid configuration value for 'SSL_PEM' ('%s')\n[?] (hint: \"%s\")" % (config.SSL_PEM, hint))

        # The key Maltrail used to ship in misc/server.pem is public - it sat in a public
        # repository from 2020 and is still in its git history - so TLS with it protects nothing.
        # Anyone who copied it once keeps serving HTTPS that anybody can impersonate or decrypt,
        # and nothing tells them: the padlock looks identical. Refuse instead of pretending.
        if uses_published_key(config.SSL_PEM):
            sys.exit("[!] 'SSL_PEM' ('%s') is the key %s published in misc/server.pem, which is public and provides no protection\n[?] (hint: \"%s\")" % (config.SSL_PEM, NAME, hint))

    def update_timer():
        retries = 0
        while retries < CHECK_CONNECTION_MAX_RETRIES and not check_connection():
            sys.stdout.write("[!] can't update because of lack of Internet connection (waiting..." if not retries else '.')
            sys.stdout.flush()
            time.sleep(10)
            retries += 1

        if retries:
            print(")")

        if retries == CHECK_CONNECTION_MAX_RETRIES:
            print("[x] going to continue without online update")
            _ = update_trails(offline=True)
        else:
            _ = update_trails()
            fetch_provenance()
            update_ipcat()
            update_geo()
            update_drop()

        # Sidecars are only dropped by index.prepare(), which runs for a day someone asks about,
        # so a log rotated away leaves its sidecar behind for good. Reap them with the rest of the
        # periodic maintenance.
        try:
            from core import index as _index
            reaped = _index.sweep()
            if reaped:
                print("[i] removed %d event index sidecar(s) whose log is gone" % reaped)
        except Exception:
            pass        # a cache cleanup must never take the update timer down

        thread = threading.Timer(config.UPDATE_PERIOD, update_timer)
        thread.daemon = True
        thread.start()

    if config.UDP_ADDRESS and config.UDP_PORT:
        if config.UDP_PORT <= 1024 and not config.DISABLE_CHECK_SUDO and check_sudo() is False:
            sys.exit("[!] please run '%s' with root privileges when using 'UDP_ADDRESS' configuration value" % __file__)

        create_log_directory()
        start_logd(address=config.UDP_ADDRESS, port=config.UDP_PORT, join=False)

    # configure the condensed observable store for read-side /meta lookups + prune (the sensor writes it)
    meta.configure(os.path.join(config.LOG_DIR, META_DB_FILENAME), enabled=False)

    alert.start()   # no-op unless ALERT_WEBHOOK_URL is set

    try:
        if config.USE_SERVER_UPDATE_TRAILS:
            update_timer()

        start_httpd(address=config.HTTP_ADDRESS, port=config.HTTP_PORT, pem=config.SSL_PEM if config.USE_SSL else None, join=True)
    except KeyboardInterrupt:
        print("\r[x] stopping (Ctrl-C pressed)")

if __name__ == "__main__":
    code = 0

    try:
        main()
    except SystemExit as ex:
        if isinstance(get_ex_message(ex), str) and get_ex_message(ex).strip('0'):
            print(get_ex_message(ex))
            code = 1
    # NOTE: this used to be a bare `except IOError`, and IOError is an alias of OSError - so EVERY OSError
    # raised anywhere in main() was reported as "session abruptly terminated", which log_error() writes to
    # the log file and never prints. `server.py --smoke-test` on a tree with a root-owned __pycache__ was
    # the demonstration: PermissionError from py_compile, no output whatsoever, exit 1. A tool that fails
    # silently sends the operator looking in the wrong place. Only a broken pipe is handled quietly, and
    # only because there is nowhere left to print to.
    except OSError as ex:
        if getattr(ex, "errno", None) in (errno.EPIPE, errno.ESHUTDOWN):
            log_error("\n\n[!] session abruptly terminated\n[?] (hint: \"https://stackoverflow.com/a/20997655\")")
            code = 1
        else:
            msg = "\r[!] unhandled exception occurred ('%s')" % ex
            msg += "\n[x] please report the following details at 'https://github.com/stamparm/maltrail/issues':\n---\n'%s'\n---" % traceback.format_exc()
            log_error("\n\n%s" % msg.replace("\r", ""))

            print(msg)
            code = 1
    except Exception:
        msg = "\r[!] unhandled exception occurred ('%s')" % sys.exc_info()[1]
        msg += "\n[x] please report the following details at 'https://github.com/stamparm/maltrail/issues':\n---\n'%s'\n---" % traceback.format_exc()
        log_error("\n\n%s" % msg.replace("\r", ""))

        print(msg)
        code = 1
    finally:
        if not any(_ in sys.argv for _ in ("--version", "-h", "--help")):
            print("\n[*] ending @ %s" % time.strftime("%X /%Y-%m-%d/"))

        # os._exit() skips interpreter cleanup, which includes flushing stdout/stderr. When
        # stdout is not a terminal it is block-buffered, so without this every line printed
        # during the run is silently discarded (`server.py --version | cat` printed nothing).
        # _exit() itself is deliberate: a worker parked in a blocking read can hold the stdio
        # lock, and a normal exit() would block forever trying to flush it.
        try:
            sys.stdout.flush()
            sys.stderr.flush()
        except Exception:
            pass

        os._exit(code)
