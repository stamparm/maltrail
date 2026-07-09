#!/usr/bin/env python

"""
Copyright (c) 2014-2026 Maltrail developers (https://github.com/stamparm/maltrail/)
See the file 'LICENSE' for copying permission
"""

import os
import struct
import threading
import time

from core import common
from core import meta
from core.common import load_trails
from core.enums import BLOCK_MARKER
from core.settings import BLOCK_LENGTH
from core.settings import config
from core.settings import LOAD_TRAILS_RETRY_SLEEP_TIME
from core.settings import REGULAR_SENSOR_SLEEP_TIME
from core.settings import SHORT_SENSOR_SLEEP_TIME
from core.settings import trails
from core.trailsdict import TrailsDict

_timer = None

def read_block(buffer, i):
    offset = i * BLOCK_LENGTH % config.CAPTURE_BUFFER

    while True:
        marker = buffer[offset]
        if marker == BLOCK_MARKER.END:
            return None

        while marker == BLOCK_MARKER.WRITE:
            time.sleep(SHORT_SENSOR_SLEEP_TIME)
            marker = buffer[offset]

        if marker == BLOCK_MARKER.END:
            return None

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

    bin_path = common.trails_bin_path()

    def _bin_sig():
        # (inode, mtime, size): an atomic rename always changes the inode, so this detects a rebuild even if the
        # mtime did not advance (coarse-granularity filesystems, or two rebuilds within the same second)
        try:
            st = os.stat(bin_path)
            return (st.st_ino, st.st_mtime, st.st_size)
        except OSError:
            return None

    last_bin_sig = [_bin_sig()]  # the shared bin this worker inherited (mmap'd) from the parent

    def update_timer():
        global _timer
        try:
            if common.USE_MMAP_TRAILS:
                # workers NEVER (re)build the trail set - the parent process owns that (and its build peak). A worker
                # only re-mmap()s the shared bin when the parent has rebuilt it, so its trail RAM stays a shared copy.
                sig = _bin_sig()
                if sig is not None and sig != last_bin_sig[0]:
                    fresh = TrailsDict()
                    fresh.open_mmap(bin_path)
                    trails.adopt(fresh)  # atomic swap to the new shared mapping
                    last_bin_sig[0] = sig
            elif (time.time() - os.stat(config.TRAILS_FILE).st_mtime) >= config.UPDATE_PERIOD:
                while True:
                    _ = load_trails(True, freeze=True)
                    if _:
                        trails.adopt(_)  # atomic swap (was clear()+update(), which raced the worker's hot-path lookups)
                        break
                    time.sleep(LOAD_TRAILS_RETRY_SLEEP_TIME)
        except Exception:
            pass  # never let a reload failure kill the worker's timer / stop processing
        finally:
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

    meta.flush()   # persist this worker's condensed-observable tail on exit (no-op if disabled/empty)

    if _timer:
        _timer.cancel()
