# coding: utf-8
"""End-to-end test for core/log.start_logd -- the UDP receiver that a CENTRAL server uses to collect
events from remote sensors (multi-sensor / air-gapped deployments: sensors set LOG_SERVER=<server>).
Wire format is "<epoch_sec> <event...>" (regular, epoch prefix) OR a quoted-localtime line (naive, no
prefix). A bug here means remote sensor events silently never land on the server -- exactly the
"something is off across sensors" symptom. Boots the real UDP server on localhost and verifies both
formats write the event to the correct day's log file. Skips cleanly if it can't bind."""
import binascii
import os
import shutil
import sys
import time
import socket
import subprocess
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

    def test_a_heartbeat_is_recorded_and_never_reaches_the_event_log(self):
        # Exactly what sensor/src/output.rs:heartbeat_payload() puts on the wire.
        sec = int(time.time())
        self._send(b"%d !HB probe-alpha 3.4 4242" % sec)
        deadline = time.time() + 5.0
        while time.time() < deadline:
            found = [_ for _ in L.sensor_status() if _["sensor"] == "probe-alpha"]
            if found:
                break
            time.sleep(0.05)
        self.assertTrue(found, "a heartbeat datagram left no trace in the sensor status")
        self.assertEqual(found[0]["version"], "3.4")
        self.assertEqual(found[0]["uptime"], 4242)
        self.assertEqual(found[0]["address"], "127.0.0.1")
        self.assertGreaterEqual(found[0]["last_seen"], sec)

        # Liveness is not a detection: in the log it would show up in /events, /counts and /fail2ban.
        self.assertNotIn(b"!HB", self._wait_for(b"probe-alpha", timeout=1.0))

    def test_an_event_is_not_mistaken_for_a_heartbeat(self):
        event = '"%s" sensorHB 10.0.0.5 4444 3.3.3.3 80 TCP IP 3.3.3.3 "malware (x)" (ref)\n' % LOCALTIME
        self._send(("%d %s" % (SEC, event)).encode("utf-8"))
        self.assertIn(b"3.3.3.3", self._wait_for(b"3.3.3.3"), "an event stopped being written once heartbeats existed")
        self.assertEqual([], [_ for _ in L.sensor_status() if _["sensor"] == "sensorHB"])

    def test_a_forged_sensor_name_cannot_carry_markup_or_grow_without_bound(self):
        # Without LOG_SERVER_SECRET anything that can reach the port may invent sensors, and the
        # names end up in a JSON document the dashboard renders.
        self._send(b"%d !HB <img/src=x> 3.4 1" % int(time.time()))
        time.sleep(0.3)
        for status in L.sensor_status():
            self.assertNotIn("<", status["sensor"])
            self.assertLessEqual(len(status["sensor"]), L.MAX_SENSOR_FIELD)

        for i in range(L.MAX_SENSOR_STATUS + 50):
            L.heartbeat_event(b"0 !HB flood%d 3.4 1" % i, "10.0.0.1")
        self.assertLessEqual(len(L.sensor_status()), L.MAX_SENSOR_STATUS,
                             "an unauthenticated flood of invented names grew the status table without bound")


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
        # The receive loop is served IN this process here, so its open() calls can be counted: the
        # receiver start_logd() runs is a child process, where patching os.open would see nothing
        # and this test would pass whatever the loop did.
        server = L._LogUDPServer(("127.0.0.1", 0), L._UDPHandler)
        thread = threading.Thread(target=server.serve_forever)
        thread.daemon = True
        thread.start()
        self.addCleanup(server.shutdown)
        port = server.server_address[1]

        path = os.path.join(TestLogd.tmp, DATELOG)
        # The day's log is shared with TestLogd, whose receiver is still running and can land a late
        # line mid-burst (seen as "201 != 200"). Count only this test's own lines.
        marker = b"burst-%s" % binascii.hexlify(os.urandom(4))
        payload = b'%d "' % SEC + marker + b'" h 10.0.0.1 1 2.2.2.2 2 TCP IP 2.2.2.2 "m" (s)'
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        sock.sendto(payload, ("127.0.0.1", port))       # warm the day's handle first
        self._wait_for_lines(path, 1, marker=marker)

        opens = []
        real_open = L.os.open

        def counting_open(*args, **kwargs):
            if isinstance(args[0], str) and args[0].endswith(".log"):
                opens.append(args[0])
            return real_open(*args, **kwargs)

        before = self._count_lines(path, marker)
        L.os.open = counting_open
        try:
            for _ in range(200):
                sock.sendto(payload, ("127.0.0.1", port))
            self._wait_for_lines(path, before + 200, marker=marker)
        finally:
            L.os.open = real_open
            sock.close()

        self.assertEqual(self._count_lines(path, marker) - before, 200, "datagrams were dropped in a 200-packet burst")
        self.assertLessEqual(len(opens), 1,
                             "the event-log handle is reopened per datagram (%d opens for 200 events)" % len(opens))

    def test_intake_keeps_up_while_this_interpreter_is_busy(self):
        # The receiver shared this process's interpreter lock with the HTTP handlers and the trail
        # update, and got it only between their 5 ms slices: with one CPU-bound thread running,
        # 98% of 5,000 datagrams/s were lost in the socket buffer. Its own process loses none. The
        # bar is set far below that so a loaded runner cannot fail it, and far above what the old
        # design delivered (~2%) so it still discriminates.
        path = os.path.join(TestLogd.tmp, DATELOG)
        marker = b"busy-%d" % int(time.time() * 1000)
        before = self._count_lines(path)
        stop = []

        def spin():
            while not stop:
                pass

        spinner = threading.Thread(target=spin)
        spinner.daemon = True
        spinner.start()
        # The sender is another process: one in this interpreter would be held back by the busy
        # thread exactly as much as the receiver used to be, and the two would keep pace.
        sender = ("import socket, sys, time\n"
                  "s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)\n"
                  "started = time.time()\n"
                  "for i in range(4000):\n"
                  "    s.sendto(sys.argv[2].encode(), ('127.0.0.1', int(sys.argv[1])))\n"
                  "    delay = started + (i + 1) / 2000.0 - time.time()\n"
                  "    if delay > 0:\n"
                  "        time.sleep(delay)\n")
        line = '%d "%s" h 10.0.0.1 1 2.2.2.2 2 TCP IP 2.2.2.2 "m" (s)' % (SEC, marker.decode())
        try:
            subprocess.check_call([sys.executable, "-c", sender, str(TestLogd.port), line])
            self._wait_for_lines(path, before + 4000, timeout=5.0)
        finally:
            stop.append(True)

        got = self._count_lines(path) - before
        self.assertGreaterEqual(got, 3200, "only %d of 4000 datagrams arrived while another thread was busy" % got)

    def _count_lines(self, path, marker=None):
        if not os.path.isfile(path):
            return 0
        with open(path, "rb") as f:
            return sum(1 for line in f if marker is None or marker in line)

    def _wait_for_lines(self, path, target, timeout=10.0, marker=None):
        deadline = time.time() + timeout
        while time.time() < deadline:
            if self._count_lines(path, marker) >= target:
                return True
            time.sleep(0.05)
        return False


def _today_log():
    """The day-log filename for now.

    The tests above pin a fixed 2023 epoch so the filename is deterministic. The signed tests
    cannot: LOG_SERVER_SECRET bounds replay by the timestamp inside the payload, so an event has
    to carry a CURRENT one to be accepted at all, and it therefore lands in today's file.
    """
    lt = time.localtime()
    return "%d-%02d-%02d.log" % (lt.tm_year, lt.tm_mon, lt.tm_mday)


class TestLogServerSecret(unittest.TestCase):
    """LOG_SERVER_SECRET authenticates the event datagrams.

    The listener is otherwise open by protocol design: anything that can reach the port can append
    to the log an operator reasons from, and that /events, /counts and /fail2ban parse. Forged
    detections are evidence tampering, which is worse for an IDS than being read.

    These drive the real receiver over a real socket, because the property that matters is what the
    listener WRITES, not what a helper returns.
    """

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="mt_logd_sec_")
        cls.started = False
        config.LOG_DIR = cls.tmp
        config.SHOW_DEBUG = False
        config.LOG_SERVER_SECRET = "unit-test-secret"  # nosec B105
        cls.port = _free_udp_port()
        try:
            L.start_logd(address="127.0.0.1", port=cls.port, join=False)
            time.sleep(0.5)
            cls.started = True
        except EnvironmentError as ex:
            cls._skip = "could not bind: %s" % ex

    @classmethod
    def tearDownClass(cls):
        config.LOG_SERVER_SECRET = None

    def setUp(self):
        if not type(self).started:
            self.skipTest(getattr(type(self), "_skip", "logd not started"))

    def _send(self, payload):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.sendto(payload, ("127.0.0.1", self.port))
        s.close()

    def _log(self, settle=0.6):
        time.sleep(settle)
        path = os.path.join(self.tmp, _today_log())
        if not os.path.isfile(path):
            return b""
        with open(path, "rb") as f:
            return f.read()

    def _event(self, marker):
        sec = int(time.time())
        return ("%d \"%s\" box 10.0.0.5 4421 8.8.8.8 53 UDP DNS %s \"malware (x)\" (static)\n"
                % (sec, time.strftime(TIME_FORMAT) + ".000000", marker)).encode("utf8")

    def test_a_signed_event_is_recorded(self):
        payload = self._event("signed-ok.example")
        self._send(L.mts_sign(config.LOG_SERVER_SECRET, payload))
        self.assertIn(b"signed-ok.example", self._log(),
                      "a correctly signed event was not written")

    def test_an_unsigned_event_is_dropped(self):
        # This is the hole: before the secret existed, this datagram was accepted from anyone.
        self._send(self._event("unsigned-forgery.example"))
        self.assertNotIn(b"unsigned-forgery.example", self._log(),
                         "an unauthenticated datagram was written to the event log")

    def test_a_wrong_secret_is_dropped(self):
        payload = self._event("wrong-key.example")
        self._send(L.mts_sign("not-the-secret", payload))
        self.assertNotIn(b"wrong-key.example", self._log(),
                         "a datagram signed with the wrong key was accepted")

    def test_a_refused_sender_is_counted_and_says_why(self):
        # A sensor with the wrong secret has every event and every heartbeat refused, so the
        # sensor table never hears of it: this count is the only trace it leaves.
        def refused():
            return [_ for _ in L.rejected_status() if _["address"] == "127.0.0.1" and "bad MAC" in _.get("reason", "")]

        before = sum(_["count"] for _ in refused())
        for _ in range(3):
            self._send(L.mts_sign("not-the-secret", self._event("counted-refusal.example")))
        deadline = time.time() + 5.0
        while time.time() < deadline and sum(_["count"] for _ in refused()) < before + 3:
            time.sleep(0.05)
        self.assertEqual(sum(_["count"] for _ in refused()), before + 3, "refused datagrams were not counted per sender")

        # The control: an accepted datagram is not a refusal.
        self._send(L.mts_sign(config.LOG_SERVER_SECRET, self._event("accepted-control.example")))
        self.assertIn(b"accepted-control.example", self._log())
        self.assertEqual(sum(_["count"] for _ in refused()), before + 3)

    def test_a_tampered_payload_is_dropped(self):
        # The MAC stays valid-looking; the event under it is edited in flight.
        signed = L.mts_sign(config.LOG_SERVER_SECRET, self._event("tamper-src.example"))
        tampered = signed.replace(b"tamper-src.example", b"tamper-dst.example")
        self.assertNotEqual(signed, tampered, "the test did not actually modify the payload")
        self._send(tampered)
        self.assertNotIn(b"tamper-dst.example", self._log(),
                         "an edited payload passed verification")

    def test_the_window_is_configurable(self):
        # The failure this guards is total - a skewed sensor loses EVERY event - so an operator who
        # cannot keep a fleet synchronised has to be able to widen it, or switch it off with 0.
        old = int(time.time()) - 4000
        payload = ("%d \"%s\" box 10.0.0.5 1 8.8.8.8 53 UDP DNS widened-window.example \"m (x)\" (static)\n"
                   % (old, time.strftime(TIME_FORMAT) + ".000000")).encode("utf8")
        self.assertIsNone(L.mts_open(config.LOG_SERVER_SECRET, L.mts_sign(config.LOG_SERVER_SECRET, payload)),
                          "4000s should be outside the 900s default")
        config.LOG_SERVER_SKEW = 7200
        try:
            self.assertIsNotNone(L.mts_open(config.LOG_SERVER_SECRET, L.mts_sign(config.LOG_SERVER_SECRET, payload)),
                                 "a widened window did not take effect")
            config.LOG_SERVER_SKEW = 0
            ancient = ("%d \"%s\" box 10.0.0.5 1 8.8.8.8 53 UDP DNS no-window.example \"m (x)\" (static)\n"
                       % (int(time.time()) - 10 ** 7, time.strftime(TIME_FORMAT) + ".000000")).encode("utf8")
            self.assertIsNotNone(L.mts_open(config.LOG_SERVER_SECRET, L.mts_sign(config.LOG_SERVER_SECRET, ancient)),
                                 "0 should disable the window entirely")
        finally:
            config.LOG_SERVER_SKEW = None

    def test_a_timezone_difference_is_not_skew(self):
        # The signed field is an epoch second, so a sensor and a server in different zones agree on
        # it exactly. Signing under one TZ and verifying under another must change nothing.
        payload = self._event("across-timezones.example")
        signed = L.mts_sign(config.LOG_SERVER_SECRET, payload)
        before = os.environ.get("TZ")
        try:
            os.environ["TZ"] = "Asia/Tokyo"; time.tzset()
            tokyo = L.mts_open(config.LOG_SERVER_SECRET, signed)
            os.environ["TZ"] = "Pacific/Kiritimati"; time.tzset()
            kiritimati = L.mts_open(config.LOG_SERVER_SECRET, signed)
            self.assertEqual(tokyo, payload, "a signed event was refused under one timezone")
            self.assertEqual(kiritimati, payload, "a signed event was refused under another")
        finally:
            if before is None:
                os.environ.pop("TZ", None)
            else:
                os.environ["TZ"] = before
            time.tzset()

    def test_a_signed_heartbeat_is_accepted_and_an_unsigned_one_is_not(self):
        # A heartbeat leads with the epoch second precisely so mts_open() will verify it: a
        # sensor whose liveness datagrams are silently refused looks dead, which is the one
        # conclusion this feature must never reach by accident.
        self._send(L.mts_sign(config.LOG_SERVER_SECRET, b"%d !HB signed-probe 3.4 7" % int(time.time())))
        self._send(b"%d !HB unsigned-probe 3.4 7" % int(time.time()))
        time.sleep(0.6)

        names = [_["sensor"] for _ in L.sensor_status()]
        self.assertIn("signed-probe", names, "a correctly signed heartbeat was refused")
        self.assertNotIn("unsigned-probe", names, "an unauthenticated sensor could invent itself")
        self.assertNotIn(b"!HB", self._log(), "a heartbeat was written to the event log")

    def test_a_stale_datagram_is_dropped(self):
        # Replay is bounded by the timestamp the payload is signed with.
        old = int(time.time()) - (L.LOG_SERVER_SKEW + 60)
        payload = ("%d \"%s\" box 10.0.0.5 1 8.8.8.8 53 UDP DNS stale-replay.example \"m (x)\" (static)\n"
                   % (old, time.strftime(TIME_FORMAT) + ".000000")).encode("utf8")
        self._send(L.mts_sign(config.LOG_SERVER_SECRET, payload))
        self.assertNotIn(b"stale-replay.example", self._log(),
                         "a datagram older than the accepted window was replayed in")


class TestLogServerSecretUnset(unittest.TestCase):
    """With no secret configured, nothing changes for an existing deployment.

    Including the upgrade-ordering case: a sensor that already has the secret, pointed at a server
    that does not yet, must still get its events recorded rather than writing "MTS1 <mac> ..." into
    the log as though the framing were part of the event.
    """

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="mt_logd_plain_")
        cls.started = False
        config.LOG_DIR = cls.tmp
        config.SHOW_DEBUG = False
        config.LOG_SERVER_SECRET = None
        cls.port = _free_udp_port()
        try:
            L.start_logd(address="127.0.0.1", port=cls.port, join=False)
            time.sleep(0.5)
            cls.started = True
        except EnvironmentError as ex:
            cls._skip = "could not bind: %s" % ex

    def setUp(self):
        if not type(self).started:
            self.skipTest(getattr(type(self), "_skip", "logd not started"))

    def _send_and_read(self, payload, settle=0.6):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.sendto(payload, ("127.0.0.1", self.port))
        s.close()
        time.sleep(settle)
        path = os.path.join(self.tmp, _today_log())
        if not os.path.isfile(path):
            return b""
        with open(path, "rb") as f:
            return f.read()

    def test_an_unsigned_event_still_works(self):
        sec = int(time.time())
        payload = ("%d \"%s\" box 10.0.0.5 1 8.8.8.8 53 UDP DNS plain-mode.example \"m (x)\" (static)\n"
                   % (sec, time.strftime(TIME_FORMAT) + ".000000")).encode("utf8")
        self.assertIn(b"plain-mode.example", self._send_and_read(payload),
                      "an unsigned datagram stopped working when no secret is configured")

    def test_a_signed_event_has_its_framing_stripped(self):
        sec = int(time.time())
        payload = ("%d \"%s\" box 10.0.0.5 1 8.8.8.8 53 UDP DNS half-upgraded.example \"m (x)\" (static)\n"
                   % (sec, time.strftime(TIME_FORMAT) + ".000000")).encode("utf8")
        data = self._send_and_read(L.mts_sign("some-secret", payload))
        self.assertIn(b"half-upgraded.example", data, "a signed event was lost against a server with no secret")
        self.assertNotIn(b"MTS1", data, "the framing was written into the event log as if it were data")


class TestEventLogWriteFailure(unittest.TestCase):
    """A write the receiver cannot make (LOG_DIR unwritable, disk full) used to vanish into an
    `except Exception` shown only under SHOW_DEBUG: nothing in error.log, an empty dashboard, a green
    sensor. Worse, a failed open() left the day's path cached with a closed descriptor, so every
    later event for that day failed too, long after the directory was writable again."""

    def setUp(self):
        if hasattr(os, "geteuid") and os.geteuid() == 0:
            self.skipTest("root ignores directory permissions, so chmod cannot inject the failure")
        self.saved = config.LOG_DIR
        self.tmp = config.LOG_DIR = tempfile.mkdtemp(prefix="mt_logw_")
        open(os.path.join(self.tmp, "error.log"), "w").close()     # it exists on a running server
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.addCleanup(os.chmod, self.tmp, 0o755)
        self.server = L._LogUDPServer(("127.0.0.1", 0), L._UDPHandler)
        thread = threading.Thread(target=self.server.serve_forever)
        thread.daemon = True
        thread.start()

    def tearDown(self):
        self.server.shutdown()
        config.LOG_DIR = self.saved

    def _send(self, sec, marker):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.sendto(b'%d "x" %s 10.0.0.1 1 2.2.2.2 2 TCP IP 2.2.2.2 "m" (s)' % (sec, marker), self.server.server_address)
        s.close()

    def _logged(self, sec, marker, timeout=3.0):
        lt = time.localtime(sec)
        path = os.path.join(self.tmp, "%d-%02d-%02d.log" % (lt.tm_year, lt.tm_mon, lt.tm_mday))
        deadline = time.time() + timeout
        while time.time() < deadline:
            if os.path.isfile(path):
                with open(path, "rb") as f:
                    if marker in f.read():
                        return True
            time.sleep(0.05)
        return False

    def test_a_failed_write_is_reported_counted_and_recovers(self):
        dropped = L.write_status()["dropped"]
        self._send(SEC, b"control")
        self.assertTrue(self._logged(SEC, b"control"), "positive control: an event is logged when all is fine")

        os.chmod(self.tmp, 0o555)                   # the next day's file cannot be created
        self._send(SEC + 86400, b"lost")
        self.assertFalse(self._logged(SEC + 86400, b"lost", timeout=0.5))
        self.assertEqual(L.write_status()["dropped"], dropped + 1, "the dropped event was not counted")
        with open(os.path.join(self.tmp, "error.log")) as f:
            errors = f.read()
        self.assertIn("DROPPED", errors, "a failed event-log write left nothing in error.log")
        self.assertIn("Permission denied", errors)

        os.chmod(self.tmp, 0o755)
        # The original day first: the failed switch had closed its descriptor but left its path cached.
        self._send(SEC, b"same-day")
        self.assertTrue(self._logged(SEC, b"same-day"), "the day whose handle was closed by the failed switch stayed blind")
        self._send(SEC + 86400, b"again")
        self.assertTrue(self._logged(SEC + 86400, b"again"), "the receiver stayed blind after the directory was fixed")
        with open(os.path.join(self.tmp, "error.log")) as f:
            self.assertIn("writing again", f.read(), "recovery was not reported")

    def test_a_log_renamed_away_is_reopened(self):
        # logrotate-style `mv`: the cached descriptor follows the old inode, so events went to the
        # renamed file until midnight and /events showed nothing.
        sec = int(time.time())
        self._send(sec, b"before")
        self.assertTrue(self._logged(sec, b"before"))
        lt = time.localtime(sec)
        path = os.path.join(self.tmp, "%d-%02d-%02d.log" % (lt.tm_year, lt.tm_mon, lt.tm_mday))
        os.rename(path, path + ".1")
        time.sleep(1.1)
        self._send(sec, b"after")
        self.assertTrue(self._logged(sec, b"after"), "an event went to the renamed file, not the day's log")


class TestSensorStatusFile(unittest.TestCase):
    """LOG_DIR/sensors.json: a restart must remember which sensors should be reporting, and a bad
    file must cost the memory, never the server."""

    def setUp(self):
        import shutil
        self.tmp = tempfile.mkdtemp(prefix="mt_sensors_")
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self._saved = (config.LOG_DIR, dict(L._sensor_status), dict(L._receiver_status))
        config.LOG_DIR = self.tmp
        L._sensor_status.clear()
        L._receiver_status.clear()

    def tearDown(self):
        config.LOG_DIR = self._saved[0]
        L._sensor_status.clear(); L._sensor_status.update(self._saved[1])
        L._receiver_status.clear(); L._receiver_status.update(self._saved[2])

    def _write(self, text):
        with open(os.path.join(self.tmp, L.SENSOR_STATUS_FILE), "w") as f:
            f.write(text)

    def test_round_trip(self):
        rows = [{"sensor": "a", "version": "1", "uptime": 1, "address": "10.0.0.1", "last_seen": 100},
                {"sensor": "b", "version": "1", "uptime": 2, "address": "10.0.0.2", "last_seen": 200}]
        L.save_sensor_status(rows, {"a"})
        self.assertFalse(os.path.exists(os.path.join(self.tmp, L.SENSOR_STATUS_FILE + ".tmp")))
        self.assertEqual(L.sensor_status(), [], "the control: the table starts empty")
        self.assertEqual(L.load_sensor_status(), {"a"})
        self.assertEqual(L.sensor_status(), rows)

    def test_a_fresher_heartbeat_wins_over_the_file(self):
        L.heartbeat_event(b"0 !HB a 2.0 9", "10.0.0.7")
        L.save_sensor_status([{"sensor": "a", "address": "10.0.0.1", "last_seen": 1}], set())
        L.load_sensor_status()
        self.assertEqual(L.sensor_status()[0]["address"], "10.0.0.7")

    def test_missing_or_corrupt_is_an_empty_start(self):
        self.assertEqual(L.load_sensor_status(), set())
        for text in ("{not json", "[]", "null", '{"sensors": [1, "x", null]}', '{"sensors": [{"sensor": 5, "last_seen": "x"}]}', "\x00" * 10):
            self._write(text)
            self.assertEqual(L.load_sensor_status(), set(), text)
            self.assertEqual(L.sensor_status(), [], text)

    def test_bounded(self):
        L.save_sensor_status([{"sensor": "s%d" % i, "last_seen": i} for i in range(L.MAX_SENSOR_STATUS + 10)], set())
        L.load_sensor_status()
        self.assertEqual(len(L.sensor_status()), L.MAX_SENSOR_STATUS)
        self.assertEqual(L.sensor_status()[-1]["sensor"], "s%d" % (L.MAX_SENSOR_STATUS + 9), "the freshest are kept")


if __name__ == "__main__":
    unittest.main()
