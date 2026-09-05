# coding: utf-8
"""The seam between the sensor that WRITES the event log and the server that READS it.

Both halves are well covered and neither covers this. `tests/test_httpd.py` drives 120 tests at
the HTTP contract, and its fixture writes the log itself - its own comment says "write lines
EXACTLY as log_event does", which is the assumption, not a check of it. `tests/test_logfmt.py`
decodes both log formats from lines Python constructed. So every existing test asks the Python
side whether it agrees with the Python side.

Nothing took bytes the RUST sensor actually emitted and asked the server to parse them. If the two
ever drift - a field added, quoting changed, a severity column moved - both suites stay green and
the dashboard silently shows nothing.

That is not hypothetical. The compatibility matrix said "sensor runs" for nineteen platforms on
the strength of `-T`, which parses a configuration and never opens a capture handle; the released
Linux sensor could not capture at all and no row could show it. This file exists so the same shape
of assumption cannot hide on the seam that carries every detection to an analyst.

Needs a sensor binary, and skips without one - CI's sensor gate builds it, so it runs there.
"""

import hashlib
import os
import socket
import subprocess
import sys
import tempfile
import time
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

from core import logfmt
from core.testing import _dns_query, _udp, _write_pcap, find_sensor

PW = "seamtest"
STORED = hashlib.sha256(PW.encode()).hexdigest()

TRAIL_DOMAIN = "seam-probe.com"
TRAIL_INFO = "malware (seam)"
SRC = "10.0.0.77"
DST = "192.0.2.53"


def _free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _http(port, method, path, cookie=None, timeout=15, body=None):
    req = "%s %s HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n" % (method, path)
    if cookie:
        req += "Cookie: %s\r\n" % cookie
    payload = (body or "").encode("utf-8")
    if body is not None:
        req += ("Content-Type: application/x-www-form-urlencoded\r\n"
                "Content-Length: %d\r\n" % len(payload))
    req += "\r\n"
    sock = socket.create_connection(("127.0.0.1", port), timeout=timeout)
    sock.sendall(req.encode("utf-8") + (payload if body is not None else b""))
    data = b""
    try:
        while True:
            chunk = sock.recv(65536)
            if not chunk:
                break
            data += chunk
    finally:
        sock.close()
    head, _, rest = data.partition(b"\r\n\r\n")
    text = head.decode("latin-1")
    status = int(text.split(" ", 2)[1]) if text.startswith("HTTP/") else 0
    return status, text, rest


class SensorToServer(unittest.TestCase):
    """One detection, produced by the real sensor, read back through the real server."""

    tmp = None
    proc = None
    port = None
    lines = None

    @classmethod
    def setUpClass(cls):
        binary = find_sensor()
        if binary is None:
            raise unittest.SkipTest("no sensor binary (CI's sensor gate builds one)")

        cls.tmp = tempfile.mkdtemp(prefix="mt_seam_")
        log_dir = cls.log_dir = os.path.join(cls.tmp, "logs")
        os.makedirs(log_dir)

        # A DNS query for a trail domain: the smallest packet that produces a full event with a
        # non-empty trail, type and info - which is what the server has to take apart.
        pcap = os.path.join(cls.tmp, "seam.pcap")
        # _udp already returns a complete ethernet frame - it wraps through _ipv4 and _eth itself.
        packet = _udp(SRC, DST, 40000, 53, _dns_query(TRAIL_DOMAIN))
        # _write_pcap takes (timestamp, bytes). Today's date, so the event lands in the log the
        # server is asked for below.
        _write_pcap(pcap, [(int(time.time()), packet)])

        trails = os.path.join(cls.tmp, "trails.csv")
        with open(trails, "w") as handle:
            handle.write("%s,%s,(static)\n" % (TRAIL_DOMAIN, TRAIL_INFO))

        conf = os.path.join(cls.tmp, "sensor.conf")
        with open(conf, "w") as handle:
            handle.write("\n".join(("MONITOR_INTERFACE any", "CAPTURE_BUFFER 10%", "USE_HEURISTICS true",
                                    "DISABLE_CHECK_SUDO true", "DISABLE_TRAIL_UPDATES true",
                                    "UPDATE_PERIOD 999999999", "USE_FEED_UPDATES false",
                                    "SENSOR_NAME seam-sensor",
                                    "LOG_DIR %s" % log_dir, "TRAILS_FILE %s" % trails, "")))

        run = subprocess.Popen([binary, "-r", pcap, "-c", conf],
                               stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        output = run.communicate()[0].decode("utf-8", "replace")

        cls.lines = []
        for name in sorted(os.listdir(log_dir)):
            if name.endswith(".log") and name != "error.log":
                with open(os.path.join(log_dir, name)) as handle:
                    cls.lines += [l for l in handle.read().splitlines() if l.strip()]
        if not cls.lines:
            raise AssertionError("the sensor wrote no event; there is no seam to test.\n%s" % output)

        # The server, on the directory the SENSOR filled - not one this test wrote.
        cls.port = _free_port()
        cfg = os.path.join(cls.tmp, "server.conf")
        with open(cfg, "w") as handle:
            handle.write("HTTP_ADDRESS 127.0.0.1\nHTTP_PORT %d\n" % cls.port)
            handle.write("USERS\n    admin:%s:0:\n" % STORED)
            handle.write("USE_SERVER_UPDATE_TRAILS false\nMONITOR_INTERFACE any\nCAPTURE_BUFFER 10MB\n")
            handle.write("LOG_DIR %s\nTRAILS_FILE %s\nUPDATE_PERIOD 86400\n"
                         "SENSOR_NAME seam\nDISABLE_CHECK_SUDO true\n" % (log_dir, trails))
        cls.proc = subprocess.Popen([sys.executable, "server.py", "-c", cfg], cwd=REPO,
                                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        for _ in range(60):
            try:
                socket.create_connection(("127.0.0.1", cls.port), timeout=1).close()
                break
            except Exception:
                time.sleep(0.5)
        else:
            cls.proc.terminate()
            try:
                why = cls.proc.communicate(timeout=10)[0].decode("utf-8", "replace")
            except Exception:
                why = "(no output)"
            raise AssertionError("the server never came up. Its output:\n%s" % why)

    @classmethod
    def tearDownClass(cls):
        if cls.proc:
            cls.proc.terminate()
            try:
                cls.proc.wait(timeout=15)
            except Exception:
                cls.proc.kill()
        if cls.tmp:
            import shutil
            shutil.rmtree(cls.tmp, ignore_errors=True)

    def _login(self):
        import binascii
        nonce = binascii.hexlify(os.urandom(16)).decode()
        digest = hashlib.sha256((STORED + nonce).encode()).hexdigest()
        body = "username=admin&nonce=%s&hash=%s" % (nonce, digest)
        status, head, _ = _http(self.port, "POST", "/login", body=body)
        self.assertEqual(status, 200, "login failed")
        cookies = [l for l in head.split("\r\n") if l.lower().startswith("set-cookie:")]
        self.assertTrue(cookies, "login set no session cookie")
        return cookies[0].split(":", 1)[1].split(";", 1)[0].strip()

    def test_the_server_parses_what_the_sensor_wrote(self):
        """Real sensor bytes through the server's own decoder, field by field.

        `logfmt.fields` is what every reader in core/ goes through - /events, /counts, /fail2ban.
        Handing it a line Python built proves those readers agree with Python.
        """
        for line in self.lines:
            fields = logfmt.fields(line)
            self.assertIsNotNone(fields, "the server cannot parse a line its own sensor wrote: %r" % line)
            self.assertEqual(len(fields), 11,
                             "expected 11 fields, got %d from a real sensor line: %r" % (len(fields), line))

        decoded = [logfmt.fields(l) for l in self.lines]
        match = [f for f in decoded if f[8] == TRAIL_DOMAIN]
        self.assertTrue(match, "no parsed line carries the trail; got trails %r" % [f[8] for f in decoded])
        row = match[0]
        self.assertEqual(row[1], "seam-sensor", "sensor name did not survive: %r" % (row,))
        self.assertEqual(row[2], SRC, "source address did not survive: %r" % (row,))
        self.assertEqual(row[4], DST, "destination address did not survive: %r" % (row,))
        self.assertEqual(row[5], "53", "destination port did not survive: %r" % (row,))
        self.assertEqual(row[7], "DNS", "protocol/type did not survive: %r" % (row,))
        self.assertEqual(row[9], TRAIL_INFO, "trail info did not survive: %r" % (row,))

    def test_the_dashboard_can_fetch_it(self):
        """The whole contract: a packet the sensor saw comes back out of /events."""
        cookie = self._login()
        day = time.strftime("%Y-%m-%d")
        status, _, body = _http(self.port, "GET", "/events?date=%s" % day, cookie=cookie)
        self.assertEqual(status, 200, "/events did not answer 200")
        text = body.decode("utf-8", "replace")
        self.assertIn(TRAIL_DOMAIN, text,
                      "the sensor detected %s and wrote it to the log, but /events does not "
                      "return it - the two halves disagree about the log they share" % TRAIL_DOMAIN)
        self.assertIn(TRAIL_INFO, text, "the trail's info is missing from what /events served")


if __name__ == "__main__":
    unittest.main()
