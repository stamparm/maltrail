#!/usr/bin/env python

"""
Copyright (c) 2014-2015 Miroslav Stampar (@stamparm)
See the file 'LICENSE' for copying permission
"""

from __future__ import print_function  # Requires: Python >= 2.6

import sys

sys.dont_write_bytecode = True

import core.versioncheck

import optparse
import os
import threading
import traceback

from core.httpd import start_httpd
from core.log import start_logd
from core.settings import config
from core.settings import read_config
from core.settings import CONFIG_FILE
from core.settings import NAME
from core.settings import VERSION
from core.update import update_ipcat
from core.update import update_trails

def main():

    print("%s (server) #v%s\n" % (NAME, VERSION))

    parser = optparse.OptionParser(version=VERSION)
    parser.add_option("-c", dest="config_file", default=CONFIG_FILE, help="Configuration file (default: '%s')" % os.path.split(CONFIG_FILE)[-1])
    options, _ = parser.parse_args()

    read_config(options.config_file)

    if config.USE_SSL:
        try:
            import OpenSSL
        except ImportError:
            import platform
            if (platform.linux_distribution()[0].lower() == 'fedora' or 'centos'):
                exit("[!] please install pyopenssl ('sudo yum install pyOpenSSL')")
            else:
                exit("[!] please install pyopenssl (e.g. 'sudo apt-get install python-openssl')")

        if not config.SSL_PEM or not os.path.isfile(config.SSL_PEM):
            hint = "openssl req -new -x509 -keyout %s -out %s -days 365 -nodes -subj '/O=%s CA/C=EU'" % (config.SSL_PEM or "server.pem", config.SSL_PEM or "server.pem", NAME)
            exit("[!] invalid configuration value for 'SSL_PEM' ('%s')\n[o] (hint: \"%s\")" % (config.SSL_PEM, hint))

    def update_timer():
        if config.USE_SERVER_UPDATE_TRAILS:
            update_trails()

        update_ipcat()

        thread = threading.Timer(config.UPDATE_PERIOD, update_timer)
        thread.daemon = True
        thread.start()

    if config.UDP_ADDRESS and config.UDP_PORT:
        start_logd(address=config.UDP_ADDRESS, port=config.UDP_PORT, join=False)

    try:
        update_timer()
        start_httpd(address=config.HTTP_ADDRESS, port=config.HTTP_PORT, pem=config.SSL_PEM if config.USE_SSL else None, join=True)
    except KeyboardInterrupt:
        print("\r[x] stopping (Ctrl-C pressed)")

if __name__ == "__main__":
    try:
        main()
    except Exception:
        print("\r[!] unhandled exception occurred ('%s')" % sys.exc_info()[1])
        print("\r[x] please report the following details at 'https://github.com/stamparm/maltrail/issues':\n---\n'%s'\n---" % traceback.format_exc())

    os._exit(0)
