#!/usr/bin/env python

"""
Copyright (c) 2014-2015 Miroslav Stampar (@stamparm)
See the file 'LICENSE' for copying permission
"""

import optparse
import os
import sys
import threading
import traceback

sys.dont_write_bytecode = True

from core.httpd import start_httpd
from core.log import start_logd
from core.settings import config
from core.settings import read_config
from core.settings import CONFIG_FILE
from core.settings import NAME
from core.settings import VERSION
from core.update import update

def main():

    print "%s (server) #v%s\n" % (NAME, VERSION)

    parser = optparse.OptionParser(version=VERSION)
    parser.add_option("-c", dest="config_file", default=CONFIG_FILE, help="Configuration file (default: '%s')" % os.path.split(CONFIG_FILE)[-1])
    options, _ = parser.parse_args()

    read_config(options.config_file)

    if config.USE_SSL:
        try:
            import OpenSSL
        except ImportError:
            exit("[!] please install pyopenssl (e.g. 'apt-get install python-openssl')")

        if not config.SSL_PEM or not os.path.isfile(config.SSL_PEM):
            hint = "openssl req -new -x509 -keyout %s -out %s -days 365 -nodes -subj '/O=%s CA/C=EU'" % (config.SSL_PEM or "server.pem", config.SSL_PEM or "server.pem", NAME)
            exit("[!] invalid configuration value for 'SSL_PEM' ('%s')\n[i] hint: \"%s\"" % (config.SSL_PEM, hint))

    def update_timer():
        update()

        thread = threading.Timer(config.UPDATE_PERIOD, update_timer)
        thread.daemon = True
        thread.start()

    if config.UDP_ADDRESS and config.UDP_PORT:
        start_logd(address=config.UDP_ADDRESS, port=config.UDP_PORT, join=False)

    try:
        if config.USE_SERVER_UPDATE_TRAILS:
            update_timer()
        start_httpd(address=config.HTTP_ADDRESS, port=config.HTTP_PORT, pem=config.SSL_PEM if config.USE_SSL else None, join=True)
    except KeyboardInterrupt:
        print "\r[x] stopping (Ctrl-C pressed)"

if __name__ == "__main__":
    try:
        main()
    except Exception, ex:
        print "\r[!] Unhandled exception occurred ('%s')" % ex
        print "\r[x] Please report the following details at 'https://github.com/stamparm/maltrail/issues':\n---\n'%s'\n---" % traceback.format_exc()

    os._exit(0)
