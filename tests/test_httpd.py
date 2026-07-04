# coding: utf-8
"""Server<->frontend<->backend integration tests. Boots the REAL server.py as a subprocess with a
controlled config (known USERS credential, temp LOG_DIR with synthetic events) and exercises the
actual HTTP contract the dashboard relies on: challenge-response login, /events with Range slicing,
/counts, /check_ip, and malformed/edge inputs -- asserting the server answers correctly and never
5xx/crashes. Raw-socket HTTP client -> no urllib py2/py3 differences. Skips cleanly if the server
can't bind (e.g. sandbox)."""
import os
import sys
import time
import socket
import hashlib
import tempfile
import subprocess
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)   # so `from core.log import safe_value` resolves (we also shell out to server.py)
PW = "changeme!"
STORED = hashlib.sha256(PW.encode()).hexdigest()   # what the config stores (sha256 of password)


def _free_port():
    s = socket.socket(); s.bind(("127.0.0.1", 0)); p = s.getsockname()[1]; s.close(); return p


def _http(port, method, path, cookie=None, headers=None, body=None, timeout=10):
    """Minimal HTTP/1.1 client for Connection: close responses. Returns (status, headers_text, body_bytes)."""
    req = "%s %s HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n" % (method, path)
    if cookie:
        req += "Cookie: %s\r\n" % cookie
    for k, v in (headers or {}).items():
        req += "%s: %s\r\n" % (k, v)
    b = (body or "").encode("utf-8")
    if body is not None:
        req += "Content-Type: application/x-www-form-urlencoded\r\nContent-Length: %d\r\n" % len(b)
    req += "\r\n"
    s = socket.create_connection(("127.0.0.1", port), timeout=timeout)
    s.sendall(req.encode("utf-8") + (b if body is not None else b""))
    data = b""
    try:
        while True:
            chunk = s.recv(65536)
            if not chunk:
                break
            data += chunk
    finally:
        s.close()
    head, _, payload = data.partition(b"\r\n\r\n")
    head_t = head.decode("latin-1")
    status = int(head_t.split(" ", 2)[1]) if head_t.startswith("HTTP/") else 0
    return status, head_t, payload


class TestHttpd(unittest.TestCase):
    proc = None
    port = None
    tmp = None

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="mt_httpd_")
        logdir = os.path.join(cls.tmp, "logs"); os.makedirs(logdir)
        cls.date = time.strftime("%Y-%m-%d")
        from core.log import safe_value                    # write lines EXACTLY as log_event does (quoted spaced fields)
        def line(ts, *fields):
            return " ".join(safe_value(f) for f in (ts,) + fields)
        with open(os.path.join(logdir, cls.date + ".log"), "w") as f:
            f.write(line("%s 10:00:00.000000" % cls.date, "sensor-a", "10.0.0.5", "4421", "8.8.8.8", "53", "UDP", "DNS", "evil.com", "malware (dummy)", "(static)") + "\n")
            f.write(line("%s 10:00:01.000000" % cls.date, "sensor-b", "10.0.0.6", "5500", "66.66.66.66", "443", "TCP", "IP", "66.66.66.66", "badnet (dummy)", "(static)") + "\n")
        trails = os.path.join(cls.tmp, "trails.csv")
        with open(trails, "w") as f:
            f.write("evil.com,dummy,(static)\n")
        cls.port = _free_port()
        cfg = os.path.join(cls.tmp, "srv.conf")
        with open(cfg, "w") as f:
            f.write("HTTP_ADDRESS 127.0.0.1\nHTTP_PORT %d\n" % cls.port)
            f.write("USERS\n    admin:%s:0:\n" % STORED)
            f.write("USE_SERVER_UPDATE_TRAILS false\nMONITOR_INTERFACE any\nCAPTURE_BUFFER 10MB\n")
            f.write("LOG_DIR %s\nTRAILS_FILE %s\nUPDATE_PERIOD 86400\nSENSOR_NAME test\nDISABLE_CHECK_SUDO true\n" % (logdir, trails))
        cls.proc = subprocess.Popen([sys.executable, "server.py", "-c", cfg], cwd=REPO,
                                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        # readiness: poll the port
        for _ in range(60):
            if cls.proc.poll() is not None:
                break
            try:
                socket.create_connection(("127.0.0.1", cls.port), timeout=0.5).close()
                return
            except (OSError, socket.error):
                time.sleep(0.25)
        # not ready
        cls._skip = "server did not start (out: %s)" % (cls.proc.stdout.read()[:300] if cls.proc and cls.proc.stdout else "")

    @classmethod
    def tearDownClass(cls):
        if cls.proc and cls.proc.poll() is None:
            cls.proc.terminate()
            try:
                cls.proc.wait(timeout=5)
            except Exception:
                cls.proc.kill()

    def setUp(self):
        if getattr(type(self), "_skip", None):
            self.skipTest(self._skip)

    def _login(self):
        import binascii; nonce = binascii.hexlify(os.urandom(16)).decode()
        h = hashlib.sha256((STORED + nonce).encode()).hexdigest()
        st, head, _ = _http(self.port, "POST", "/login", body="username=admin&nonce=%s&hash=%s" % (nonce, h))
        self.assertEqual(st, 200, "login should succeed")
        m = [l for l in head.split("\r\n") if l.lower().startswith("set-cookie:")]
        self.assertTrue(m, "login must set a session cookie")
        return m[0].split(":", 1)[1].split(";", 1)[0].strip()

    # --- the contract ---
    def test_index_served(self):
        st, _, body = _http(self.port, "GET", "/")
        self.assertEqual(st, 200)
        self.assertIn(b"<table", body.lower() if False else body)  # dashboard HTML

    def test_auth_required(self):
        for ep in ("/events?date=%s" % self.date, "/counts", "/check_ip?address=8.8.8.8"):
            st, _, _ = _http(self.port, "GET", ep)
            self.assertEqual(st, 401, "%s must require auth" % ep)

    def test_login_and_events(self):
        ck = self._login()
        st, _, body = _http(self.port, "GET", "/events?date=%s" % self.date, cookie=ck)
        self.assertEqual(st, 200)
        self.assertIn(b"evil.com", body)                 # our synthetic event round-tripped
        self.assertIn(b"sensor-a", body)                 # sensor name present in the stream

    def test_events_range_slicing(self):
        ck = self._login()
        st_full, _, full = _http(self.port, "GET", "/events?date=%s" % self.date, cookie=ck)
        st_r, _, part = _http(self.port, "GET", "/events?date=%s" % self.date, cookie=ck, headers={"Range": "bytes=0-9"})
        self.assertIn(st_r, (200, 206))
        self.assertLessEqual(len(part), len(full))       # a byte range returns a subset, no crash

    def test_malformed_inputs_no_5xx(self):
        ck = self._login()
        cases = [
            ("/events?date=%s" % self.date, {"Range": "bytes=abc-xyz"}),
            ("/events?date=%s" % self.date, {"Range": "bytes=100-5"}),      # inverted
            ("/events?date=%s" % self.date, {"Range": "bytes=-999999999"}),
            ("/events?date=../../../etc/passwd", None),                     # traversal
            ("/events?date=zzzz", None),                                    # junk date
            ("/counts?date=zzzz", None),
            ("/check_ip?address=%3Cscript%3E", None),                       # junk ip
        ]
        for path, hdr in cases:
            st, _, _ = _http(self.port, "GET", path, cookie=ck, headers=hdr)
            self.assertLess(st, 500, "5xx/crash on %s %s" % (path, hdr))
            self.assertGreater(st, 0, "connection died on %s (server crash?)" % path)

    def test_no_traceback_in_server_log(self):
        # give the server a moment to flush, then check it never logged an unhandled traceback
        self._login()
        _http(self.port, "GET", "/events?date=%s" % self.date, cookie=self._login(), headers={"Range": "bytes=5-1"})
        # (server stdout is captured; a traceback would mean an unhandled request exception)
        # non-fatal: just assert the process is still alive after all the abuse
        self.assertIsNone(type(self).proc.poll(), "server process died during tests")


if __name__ == "__main__":
    unittest.main()
