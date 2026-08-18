# coding: utf-8
"""End-to-end test for core/log.start_logd -- the UDP receiver that a CENTRAL server uses to collect
events from remote sensors (multi-sensor / air-gapped deployments: sensors set LOG_SERVER=<server>).
Wire format is "<epoch_sec> <event...>" (regular, epoch prefix) OR a quoted-localtime line (naive, no
prefix). A bug here means remote sensor events silently never land on the server -- exactly the
"something is off across sensors" symptom. Boots the real UDP server on localhost and verifies both
formats write the event to the correct day's log file. Skips cleanly if it can't bind."""
import os
import sys
import time
import socket
import tempfile
import threading
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import core.log as L
from core.settings import config, TIME_FORMAT

SEC = 1700000000                                   # fixed epoch -> deterministic day-log filename
_lt = time.localtime(SEC)
DATELOG = "%d-%02d-%02d.log" % (_lt.tm_year, _lt.tm_mon, _lt.tm_mday)
LOCALTIME = time.strftime(TIME_FORMAT, _lt) + ".000000"


def _free_udp_port():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0)); p = s.getsockname()[1]; s.close(); return p


class TestLogd(unittest.TestCase):
    started = False
    port = None
    tmp = None

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="mt_logd_")
        config.LOG_DIR = cls.tmp
        config.SHOW_DEBUG = False
        cls.port = _free_udp_port()
        cls.threads_before = threading.active_count()
        try:
            L.start_logd(address="127.0.0.1", port=cls.port, join=False)   # daemon thread
            time.sleep(0.5)
            cls.started = True
        except EnvironmentError as ex:
            # ONLY a bind/permission failure is a legitimate skip (sandbox, port in use). Any other
            # exception is a bug in core/log.py, and skipping on it means the suite goes green on a
            # server that cannot start - which is how a NameError in start_logd() passed as "OK
            # (skipped=4)" while this very change was being written.
            cls._skip = "could not bind: %s" % ex

    def setUp(self):
        if not type(self).started:
            self.skipTest(getattr(type(self), "_skip", "logd not started"))

    def _send(self, payload):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.sendto(payload, ("127.0.0.1", self.port))
        s.close()

    def _wait_for(self, needle, timeout=5.0):
        path = os.path.join(self.tmp, DATELOG)
        deadline = time.time() + timeout
        while time.time() < deadline:
            if os.path.isfile(path):
                with open(path, "rb") as f:
                    data = f.read()
                if needle in data:
                    return data
            time.sleep(0.05)
        return b""

    def test_regular_format_epoch_prefixed(self):
        # "<sec> <event>" -> the server strips the epoch prefix and writes the event to <sec>'s day log
        event = '"%s" sensorX 10.0.0.5 4444 66.66.66.66 80 TCP IP 66.66.66.66 "malware (x)" (ref)\n' % LOCALTIME
        self._send(("%d %s" % (SEC, event)).encode("utf-8"))
        data = self._wait_for(b"66.66.66.66")
        self.assertIn(b"66.66.66.66", data, "remote sensor event must land in the server's day log")
        self.assertIn(b"sensorX", data)
        self.assertNotIn(b"%d %d" % (SEC, SEC), data)     # epoch prefix stripped, not doubled into the line

    def test_naive_format_quoted_localtime(self):
        # no epoch prefix: line starts with a quoted localtime; server derives the day from it
        line = '"%s" sensorY 10.0.0.9 5555 5.5.5.5 443 TCP IP 5.5.5.5 "badnet (y)" (ref2)\n' % LOCALTIME
        self._send(line.encode("utf-8"))
        data = self._wait_for(b"5.5.5.5")
        self.assertIn(b"5.5.5.5", data, "naive-format (prefixless) event must also be stored")
        self.assertIn(b"sensorY", data)

    def test_embedded_newline_cannot_forge_extra_records(self):
        # This listener is unauthenticated by protocol design - a sensor just sends a datagram. The
        # handler wrote the payload to the day log byte for byte, so anyone able to reach the port
        # could put '\n' in the middle of one datagram and append arbitrary extra "events": evidence
        # tampering in an IDS, and the forged lines are indistinguishable to /events and /fail2ban.
        # One datagram is one record; interior newlines are collapsed, not honoured.
        real = '"%s" sensorFORGE 10.0.0.11 1111 7.7.7.7 80 TCP IP 7.7.7.7 "real (f)" (ref)' % LOCALTIME
        forged = '"%s" sensorFORGE 10.0.0.12 2222 8.8.4.4 80 TCP IP 8.8.4.4 "forged (f)" (ref)' % LOCALTIME
        self._send(("%d %s\n%s\n" % (SEC, real, forged)).encode("utf-8"))
        data = self._wait_for(b"sensorFORGE")
        self.assertIn(b"sensorFORGE", data, "positive control: the datagram was accepted and stored")
        self.assertEqual(len([_ for _ in data.splitlines() if b"sensorFORGE" in _]), 1,
                         "one datagram must produce exactly one log record, not two")

    def test_garbage_datagram_ignored(self):
        # malformed input must not crash the server thread (later valid events must still be stored)
        self._send(b"\xff\xfe not a valid event at all")
        self._send(b"")
        event = '"%s" sensorZ 10.0.0.7 111 9.9.9.9 53 UDP IP 9.9.9.9 "x (z)" (r)\n' % LOCALTIME
        self._send(("%d %s" % (SEC, event)).encode("utf-8"))
        self.assertIn(b"sensorZ", self._wait_for(b"sensorZ"), "server must survive garbage and keep storing")


class TestIntakeShape(unittest.TestCase):
    """The receiver used to be a ThreadingUDPServer, so each event cost a fresh THREAD - and because the
    thread was fresh, get_event_log_handle()'s thread-local fd cache always missed, so each event also cost an
    open() and a close(). Paced against the real server, that capped clean intake at 5,000 events/s (23.9%
    loss at 10,000/s); one sequential loop with a cached handle holds 20,000/s with no loss.

    Rates are not asserted here - that would be flaky on a shared runner. What is asserted is the SHAPE that
    produced them: N datagrams must cost ONE open() of the day's log, not N. Counting the opens is the only
    assertion that discriminates. Three that do NOT, all tried first and all passing against the OLD design:
    a 200-datagram burst arriving intact (200 fit in the socket buffer either way), the thread count after the
    burst (per-datagram threads are already gone by then) and the open-descriptor count (reuse=False closed
    each one, so the answer was zero). A test that cannot fail is not a test."""

    @classmethod
    def setUpClass(cls):
        if not TestLogd.started:                     # this class sorts BEFORE TestLogd, so start it here
            TestLogd.setUpClass()

    def setUp(self):
        if not TestLogd.started:
            self.skipTest(getattr(TestLogd, "_skip", "logd not started"))

    def test_a_burst_costs_one_open_not_one_per_datagram(self):
        path = os.path.join(TestLogd.tmp, DATELOG)
        payload = b'%d "burst" h 10.0.0.1 1 2.2.2.2 2 TCP IP 2.2.2.2 "m" (s)' % SEC
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        sock.sendto(payload, ("127.0.0.1", TestLogd.port))       # warm the day's handle first
        self._wait_for_lines(path, 1)

        opens = []
        real_open = L.os.open

        def counting_open(*args, **kwargs):
            if isinstance(args[0], str) and args[0].endswith(".log"):
                opens.append(args[0])
            return real_open(*args, **kwargs)

        before = self._count_lines(path)
        L.os.open = counting_open
        try:
            for _ in range(200):
                sock.sendto(payload, ("127.0.0.1", TestLogd.port))
            self._wait_for_lines(path, before + 200)
        finally:
            L.os.open = real_open
            sock.close()

        self.assertEqual(self._count_lines(path) - before, 200, "datagrams were dropped in a 200-packet burst")
        self.assertLessEqual(len(opens), 1,
                             "the event-log handle is reopened per datagram (%d opens for 200 events)" % len(opens))

    def _count_lines(self, path):
        if not os.path.isfile(path):
            return 0
        with open(path, "rb") as f:
            return sum(1 for _ in f)

    def _wait_for_lines(self, path, target, timeout=10.0):
        deadline = time.time() + timeout
        while time.time() < deadline:
            if self._count_lines(path) >= target:
                return True
            time.sleep(0.05)
        return False


if __name__ == "__main__":
    unittest.main()
