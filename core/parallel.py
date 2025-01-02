#!/usr/bin/env python

"""
Copyright (c) 2014-2025 Maltrail developers (https://github.com/stamparm/maltrail/)
See the file 'LICENSE' for copying permission
"""

import os
import struct
import threading
import time

from core.common import load_trails
from core.enums import BLOCK_MARKER
from core.settings import BLOCK_LENGTH
from core.settings import config
from core.settings import LOAD_TRAILS_RETRY_SLEEP_TIME
from core.settings import REGULAR_SENSOR_SLEEP_TIME
from core.settings import SHORT_SENSOR_SLEEP_TIME
from core.settings import trails

_timer = None

def read_block(buffer, i):
    offset = i * BLOCK_LENGTH % config.CAPTURE_BUFFER

    while True:
        if buffer[offset] == BLOCK_MARKER.END:
            return None

        while buffer[offset] == BLOCK_MARKER.WRITE:
            time.sleep(SHORT_SENSOR_SLEEP_TIME)

        buffer[offset] = BLOCK_MARKER.READ
        buffer.seek(offset + 1)

        length = struct.unpack("=H", buffer.read(2))[0]
        retval = buffer.read(length)

        if buffer[offset] == BLOCK_MARKER.READ:
            break

    buffer[offset] = BLOCK_MARKER.NOP
    return retval

def write_block(buffer, i, block, marker=None):
    offset = i * BLOCK_LENGTH % config.CAPTURE_BUFFER

    while buffer[offset] == BLOCK_MARKER.READ:
        time.sleep(SHORT_SENSOR_SLEEP_TIME)

    buffer[offset] = BLOCK_MARKER.WRITE
    buffer.seek(offset + 1)
    buffer.write(struct.pack("=H", len(block)) + block)
    buffer[offset] = marker or BLOCK_MARKER.NOP

def worker(buffer, n, offset, mod, process_packet):
    """
    Worker process used in multiprocessing mode
    """

    def update_timer():
        global _timer

        if (time.time() - os.stat(config.TRAILS_FILE).st_mtime) >= config.UPDATE_PERIOD:
            _ = None
            while True:
                _ = load_trails(True)
                if _:
                    trails.clear()
                    trails.update(_)
                    break
                else:
                    time.sleep(LOAD_TRAILS_RETRY_SLEEP_TIME)

        _timer = threading.Timer(config.UPDATE_PERIOD, update_timer)
        _timer.start()

    update_timer()

    count = 0
    while True:
        try:
            if (count % mod) == offset:
                if count >= n.value:
                    time.sleep(REGULAR_SENSOR_SLEEP_TIME)
                    continue

                content = read_block(buffer, count)

                if content is None:
                    break

                elif len(content) < 12:
                    continue

                sec, usec, ip_offset = struct.unpack("=III", content[:12])
                packet = content[12:]
                process_packet(packet, sec, usec, ip_offset)

            count += 1

        except KeyboardInterrupt:
            break

    if _timer:
        _timer.cancel()
