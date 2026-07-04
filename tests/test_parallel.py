# coding: utf-8
"""Unit tests for core/parallel.read_block / write_block -- the lock-free mmap ring buffer that carries
captured packets from the capture thread to the worker processes in a multiprocessing sensor run. A bug
here silently drops or corrupts packets between capture and detection. Uses an anonymous mmap (same
indexing/seek/read/write interface as the real shared buffer) for a single-threaded roundtrip; the
BLOCK_MARKER bytes are typed per-runtime so this works on py2 and py3."""
import os
import sys
import mmap
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from core.settings import config, BLOCK_LENGTH
from core.enums import BLOCK_MARKER
from core.parallel import read_block, write_block


class TestRingBuffer(unittest.TestCase):
    def setUp(self):
        config.CAPTURE_BUFFER = BLOCK_LENGTH * 4          # small ring: 4 slots
        self.buf = mmap.mmap(-1, config.CAPTURE_BUFFER)   # anonymous, zero-filled (== BLOCK_MARKER.NOP)

    def tearDown(self):
        self.buf.close()

    def test_write_read_roundtrip(self):
        block = b"\x01\x02packet-payload\xff"
        write_block(self.buf, 0, block)
        self.assertEqual(read_block(self.buf, 0), block)

    def test_distinct_slots_independent(self):
        write_block(self.buf, 0, b"AAA")
        write_block(self.buf, 1, b"BBBB")
        write_block(self.buf, 2, b"C")
        self.assertEqual(read_block(self.buf, 0), b"AAA")
        self.assertEqual(read_block(self.buf, 1), b"BBBB")
        self.assertEqual(read_block(self.buf, 2), b"C")

    def test_end_marker_returns_none(self):
        write_block(self.buf, 0, b"last", marker=BLOCK_MARKER.END)
        self.assertIsNone(read_block(self.buf, 0), "END marker must stop the worker (return None)")

    def test_ring_wraps_by_modulo(self):
        # slot index past the ring wraps via `i * BLOCK_LENGTH % CAPTURE_BUFFER` (4 slots -> index 4 == 0)
        write_block(self.buf, 0, b"first")
        self.assertEqual(read_block(self.buf, 0), b"first")
        write_block(self.buf, 4, b"wrapped")             # 4 % 4 == 0 -> same physical slot
        self.assertEqual(read_block(self.buf, 4), b"wrapped")


if __name__ == "__main__":
    unittest.main()
