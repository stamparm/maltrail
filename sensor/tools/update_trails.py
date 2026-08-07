#!/usr/bin/env python3
# coding: utf-8
"""Trail update entry point for the Rust sensor.

This is deliberately a thin wrapper around Maltrail's OWN updater
(`core.update.update_trails`) rather than a reimplementation: there is exactly one trail-update
mechanism in this repository, and both sensors use it. The Rust sensor invokes this script at
startup and on every `UPDATE_PERIOD`, mirroring `sensor.py:init():update_timer()`.

    python3 sensor/tools/update_trails.py -c maltrail.conf [--offline]

`--offline` rebuilds `TRAILS_FILE` from the bundled static/custom trails without touching the
network (exactly what `sensor.py --offline` does — note that it still *refreshes* the file).
Without it, the feeds are pulled first, falling back to offline mode when there is no
connectivity, and `ipcat` is refreshed too.

Exit status: 0 on success, 1 on failure (the sensor keeps running with whatever trails it has).
"""

import argparse
import os
import sys
import time

ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
sys.path.insert(0, ROOT)
sys.dont_write_bytecode = True


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("-c", dest="config_file", required=True, help="Maltrail configuration file")
    parser.add_argument("--offline", action="store_true", help="do not use the network (static/custom only)")
    options = parser.parse_args()

    from core.settings import config, read_config
    read_config(options.config_file)
    config.offline = options.offline

    from core.common import check_connection
    from core.settings import CHECK_CONNECTION_MAX_RETRIES
    from core.update import update_ipcat, update_trails

    offline = options.offline
    if not offline:
        retries = 0
        while retries < CHECK_CONNECTION_MAX_RETRIES and not check_connection():
            sys.stdout.write("[!] can't update because of lack of Internet connection (waiting..."
                             if not retries else '.')
            sys.stdout.flush()
            time.sleep(10)
            retries += 1
        if retries:
            print(")")
        if retries == CHECK_CONNECTION_MAX_RETRIES:
            print("[x] going to continue without online update")
            offline = True

    try:
        if offline:
            update_trails(offline=True)
        else:
            update_trails()
            update_ipcat()
    except KeyboardInterrupt:
        print("[x] trail update interrupted")
        return 1
    except Exception as ex:
        print("[!] trail update failed (%s)" % ex)
        return 1

    trails_file = config.TRAILS_FILE
    if not os.path.isfile(trails_file):
        print("[!] trail update produced no '%s'" % trails_file)
        return 1
    print("[i] trails stored to '%s'" % trails_file)
    return 0


if __name__ == "__main__":
    sys.exit(main())
