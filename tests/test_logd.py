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
        try:
            L.start_logd(address="127.0.0.1", port=cls.port, join=False)   # daemon thread
            time.sleep(0.5)
            cls.started = True
        except Exception as ex:
            cls._skip = "could not start logd: %s" % ex

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

    def test_garbage_datagram_ignored(self):
        # malformed input must not crash the server thread (later valid events must still be stored)
        self._send(b"\xff\xfe not a valid event at all")
        self._send(b"")
        event = '"%s" sensorZ 10.0.0.7 111 9.9.9.9 53 UDP IP 9.9.9.9 "x (z)" (r)\n' % LOCALTIME
        self._send(("%d %s" % (SEC, event)).encode("utf-8"))
        self.assertIn(b"sensorZ", self._wait_for(b"sensorZ"), "server must survive garbage and keep storing")


if __name__ == "__main__":
    unittest.main()
