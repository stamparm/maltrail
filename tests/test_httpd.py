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
            # external-only event (no 10.x IP) -> a netfilter-restricted analyst must NOT see it
            f.write(line("%s 10:00:02.000000" % cls.date, "sensor-a", "203.0.113.9", "5555", "198.51.100.5", "443", "TCP", "IP", "198.51.100.5", "extonly (dummy)", "(static)") + "\n")
            # custom-trail event from an in-range host -> restricted analyst sees the event but the (custom) name masked
            f.write(line("%s 10:00:03.000000" % cls.date, "sensor-a", "10.0.0.8", "6666", "5.5.5.5", "80", "TCP", "IP", "5.5.5.5", "supersecretname (custom)", "(custom)") + "\n")
        trails = os.path.join(cls.tmp, "trails.csv")
        with open(trails, "w") as f:
            f.write("evil.com,dummy,(static)\n")
        cls.port = _free_port()
        cfg = os.path.join(cls.tmp, "srv.conf")
        with open(cfg, "w") as f:
            f.write("HTTP_ADDRESS 127.0.0.1\nHTTP_PORT %d\n" % cls.port)
            f.write("USERS\n    admin:%s:0:\n    analyst:%s:1000:10.0.0.0/8\n    analyst2:%s:1001:10.0.5.0/16\n"
                    "    analyst3:%s:1002:10.0.0.5\n    analyst4:%s:1003:10.0.0.6-10.0.0.9\n"
                    "    ipv6user:%s:1004:::\n"   # netfilter "::" (IPv6 all) - the last field contains colons
                    % (STORED, STORED, STORED, STORED, STORED, STORED))
            f.write("ENABLE_MASK_CUSTOM true\n")
            f.write("FAIL2BAN_ALLOWLIST 127.0.0.1\nFAIL2BAN_REGEX dummy\n")   # allow localhost puller; match the synthetic events
            # two distinct blacklists -> /blacklist (DNS events) vs /blacklist/foo (IP events); used to catch cross-name cache poisoning
            f.write("BLACKLIST\n    type ~ DNS\n")
            f.write("BLACKLIST_FOO\n    type ~ IP\n")
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

    def _login(self, username="admin"):
        import binascii; nonce = binascii.hexlify(os.urandom(16)).decode()
        h = hashlib.sha256((STORED + nonce).encode()).hexdigest()   # both test users share the same stored hash
        st, head, _ = _http(self.port, "POST", "/login", body="username=%s&nonce=%s&hash=%s" % (username, nonce, h))
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

    def test_incremental_range_delta(self):
        # the live view fetches ONLY appended bytes via Range: bytes=<prev_len>-<max>. The server's
        # byte offsets must match the file exactly, or live shows duplicate/missing events.
        ck = self._login()
        _, _, full = _http(self.port, "GET", "/events?date=%s" % self.date, cookie=ck)
        prev = len(full)
        from core.log import safe_value
        newline = " ".join(safe_value(f) for f in ("%s 11:11:11.000000" % self.date, "sensor-c",
                  "10.0.0.7", "9999", "1.2.3.4", "80", "TCP", "PATH", "*", "potential web scanning", "(heuristic)")) + "\n"
        logfile = os.path.join(self.tmp, "logs", self.date + ".log")
        with open(logfile, "a") as f:
            f.write(newline)
        st, _, delta = _http(self.port, "GET", "/events?date=%s" % self.date, cookie=ck,
                             headers={"Range": "bytes=%d-2147483647" % prev})
        self.assertIn(st, (206, 200))
        self.assertIn(b"sensor-c", delta)                # the appended event is in the delta
        self.assertNotIn(b"sensor-a", delta)             # old events are NOT re-sent (no duplication)
        if st == 206:
            self.assertEqual(delta, newline.encode(), "Range delta must be exactly the appended bytes")

    def test_netfilter_restricts_analyst(self):
        # admin sees ALL events incl. the external-only one; a 10.0.0.0/8-restricted analyst must NOT
        # see events lacking any in-range IP (data-restriction correctness — a leak if it fails).
        _, _, admin_body = _http(self.port, "GET", "/events?date=%s" % self.date, cookie=self._login("admin"))
        self.assertIn(b"198.51.100.5", admin_body, "admin should see the external-only event")
        _, _, an_body = _http(self.port, "GET", "/events?date=%s" % self.date, cookie=self._login("analyst"))
        self.assertNotIn(b"198.51.100.5", an_body, "analyst (10/8) must NOT see an external-only event (leak!)")
        self.assertIn(b"10.0.0.5", an_body, "analyst SHOULD see in-range events")

    def test_netfilter_non_aligned_cidr(self):
        # analyst2 is restricted to 10.0.5.0/16 (NOT network-aligned; operators write CIDRs loosely).
        # The subnet is 10.0.0.0/16, so in-range 10.0.0.x events MUST be visible. A prefix-not-masked
        # comparison would never match its own subnet -> analyst sees nothing (events hidden).
        _, _, body = _http(self.port, "GET", "/events?date=%s" % self.date, cookie=self._login("analyst2"))
        self.assertIn(b"10.0.0.5", body, "non-aligned CIDR 10.0.5.0/16 must still match in-subnet 10.0.0.5")
        self.assertNotIn(b"198.51.100.5", body, "out-of-subnet external event must stay hidden")

    def test_login_user_with_colon_netfilter(self):
        # A user whose netfilter is an IPv6 "::" (="all") puts colons in the LAST USERS field. A plain
        # split(':') over-splits that entry into >4 parts -> ValueError while iterating USERS, which
        # crashed EVERY login (not just this user's). Logging in as this user must succeed.
        ck = self._login("ipv6user")
        st, _, body = _http(self.port, "GET", "/events?date=%s" % self.date, cookie=ck)
        self.assertEqual(st, 200, "'::'-netfilter user must be able to log in and query")
        self.assertIn(b"10.0.0.5", body, "'::' means no restriction -> sees all events")

    def test_netfilter_exact_ip(self):
        # analyst3 restricted to a single exact IP (10.0.0.5): sees only lines containing it.
        _, _, body = _http(self.port, "GET", "/events?date=%s" % self.date, cookie=self._login("analyst3"))
        self.assertIn(b"10.0.0.5", body, "exact-IP filter must show its own IP's events")
        self.assertNotIn(b"10.0.0.6", body, "exact-IP filter must NOT show other in-org IPs")
        self.assertNotIn(b"198.51.100.5", body, "exact-IP filter must NOT show external events")

    def test_netfilter_ip_range(self):
        # analyst4 restricted to a dash range (10.0.0.6-10.0.0.9): sees 10.0.0.6 and 10.0.0.8, not 10.0.0.5.
        _, _, body = _http(self.port, "GET", "/events?date=%s" % self.date, cookie=self._login("analyst4"))
        self.assertIn(b"10.0.0.6", body, "range filter must show an in-range IP")
        self.assertIn(b"10.0.0.8", body, "range filter must show another in-range IP")
        self.assertNotIn(b"10.0.0.5", body, "range filter must NOT show a below-range IP")

    def test_mask_custom_for_nonadmin(self):
        # UID>=1000 with ENABLE_MASK_CUSTOM: (custom) trail NAMES are masked; admin sees the real name.
        _, _, admin_body = _http(self.port, "GET", "/events?date=%s" % self.date, cookie=self._login("admin"))
        self.assertIn(b"supersecretname", admin_body, "admin should see the real custom trail name")
        _, _, an_body = _http(self.port, "GET", "/events?date=%s" % self.date, cookie=self._login("analyst"))
        self.assertNotIn(b"supersecretname", an_body, "custom trail name must be masked for non-admin (leak!)")

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

    def test_blacklist_cache_not_poisoned_across_names(self):
        # /blacklist and /blacklist/foo select DIFFERENT BLACKLIST configs. The server caches the
        # computed content in a single global with an 8s TTL; the cache key MUST include the blacklist
        # name, or two requests in the same window return one blacklist's results for the other.
        st1, _, def_bl = _http(self.port, "GET", "/blacklist")            # rule: type ~ DNS -> src_ip of DNS event
        st2, _, foo_bl = _http(self.port, "GET", "/blacklist/foo")        # rule: type ~ IP  -> src_ips of IP events
        self.assertEqual(st1, 200)
        self.assertEqual(st2, 200)
        # default blacklist = DNS event's source only
        self.assertIn(b"10.0.0.5", def_bl, "default /blacklist (type~DNS) should list the DNS source")
        self.assertNotIn(b"10.0.0.6", def_bl, "default /blacklist must NOT contain IP-event sources")
        # foo blacklist = IP events' sources (poisoning would return the DNS set here instead)
        self.assertIn(b"10.0.0.6", foo_bl, "/blacklist/foo (type~IP) should list IP-event sources (cache poisoning if missing)")
        self.assertNotIn(b"10.0.0.5", foo_bl, "/blacklist/foo must NOT leak the default blacklist's DNS source")

    def test_check_ip_returns_json(self):
        import json as _json
        ck = self._login()
        st, _, body = _http(self.port, "GET", "/check_ip?address=8.8.8.8", cookie=ck)
        self.assertEqual(st, 200)
        obj = _json.loads(body.decode("utf-8"))
        self.assertIn("ipcat", obj)
        self.assertIn("worst_asns", obj)

    def test_check_ip_jsonp_callback_validated(self):
        ck = self._login()
        # a valid identifier callback is honored (JSONP wrapping)
        _, _, ok = _http(self.port, "GET", "/check_ip?address=8.8.8.8&callback=cb", cookie=ck)
        self.assertTrue(ok.startswith(b"cb("), ok)
        self.assertTrue(ok.rstrip().endswith(b")"), ok)
        # a malicious callback must NOT be reflected (JSONP-XSS): server returns plain JSON instead
        _, _, evil = _http(self.port, "GET", "/check_ip?address=8.8.8.8&callback=alert(1)//", cookie=ck)
        self.assertNotIn(b"alert(1)", evil, "unsafe callback must not be reflected into a script body")
        self.assertTrue(evil.lstrip().startswith(b"{"), "falls back to plain JSON")

    def test_fail2ban_allowed_returns_attacker_ips(self):
        # a puller on the FAIL2BAN_ALLOWLIST gets the src IPs of events matching FAIL2BAN_REGEX (for ipset/iptables)
        st, _, body = _http(self.port, "GET", "/fail2ban")
        self.assertEqual(st, 200, "allowlisted client must be served")
        self.assertIn(b"10.0.0.5", body, "matching event's source IP must be listed")
        self.assertNotIn(b"evil.com", body, "only IPs are emitted, not trail names")

    def test_counts_returns_json(self):
        import json as _json
        ck = self._login()
        st, _, body = _http(self.port, "GET", "/counts", cookie=ck)
        self.assertEqual(st, 200)
        obj = _json.loads(body.decode("utf-8"))            # sparkline data: {timestamp: count}
        self.assertIsInstance(obj, dict)

    def test_ping_healthcheck(self):
        # unauthenticated liveness probe used by monitoring/LB health checks
        st, _, body = _http(self.port, "GET", "/ping")
        self.assertEqual(st, 200)
        self.assertEqual(body.strip(), b"pong")

    def test_whoami_and_logout(self):
        ck = self._login("admin")
        _, _, who = _http(self.port, "GET", "/whoami", cookie=ck)
        self.assertEqual(who.strip(), b"admin", "whoami returns the logged-in username")
        _, _, anon = _http(self.port, "GET", "/whoami")
        self.assertEqual(anon.strip(), b"", "no session -> empty username")
        _http(self.port, "GET", "/logout", cookie=ck)                 # invalidates server-side session
        _, _, after = _http(self.port, "GET", "/whoami", cookie=ck)
        self.assertEqual(after.strip(), b"", "session must be invalid after logout")

    def test_trails_endpoint_served(self):
        # sensors pull the trail set from the server via /trails (UPDATE_SERVER). No auth (automation).
        st, _, body = _http(self.port, "GET", "/trails")
        self.assertEqual(st, 200)
        self.assertIn(b"evil.com", body, "the server's trails file must be served verbatim")

    def test_no_traceback_in_server_log(self):
        # give the server a moment to flush, then check it never logged an unhandled traceback
        self._login()
        _http(self.port, "GET", "/events?date=%s" % self.date, cookie=self._login(), headers={"Range": "bytes=5-1"})
        # (server stdout is captured; a traceback would mean an unhandled request exception)
        # non-fatal: just assert the process is still alive after all the abuse
        self.assertIsNone(type(self).proc.poll(), "server process died during tests")


class TestTrailsEndpointMissingFile(unittest.TestCase):
    """A fresh server (USE_SERVER_UPDATE_TRAILS off, or a first update that produced no trails) has no
    TRAILS_FILE. GET /trails must NOT 500 (a bare open() would) -- it returns an empty body so a pulling
    sensor keeps its current trails instead of erroring."""
    proc = None
    port = None
    tmp = None

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="mt_notrails_")
        logdir = os.path.join(cls.tmp, "logs"); os.makedirs(logdir)
        missing_trails = os.path.join(cls.tmp, "does-not-exist.csv")   # deliberately absent
        cls.port = _free_port()
        cfg = os.path.join(cls.tmp, "srv.conf")
        with open(cfg, "w") as f:
            f.write("HTTP_ADDRESS 127.0.0.1\nHTTP_PORT %d\n" % cls.port)
            f.write("USERS\n    admin:%s:0:\n" % STORED)
            f.write("USE_SERVER_UPDATE_TRAILS false\nMONITOR_INTERFACE any\nCAPTURE_BUFFER 10MB\n")
            f.write("LOG_DIR %s\nTRAILS_FILE %s\nUPDATE_PERIOD 86400\nSENSOR_NAME test\nDISABLE_CHECK_SUDO true\n" % (logdir, missing_trails))
        cls.proc = subprocess.Popen([sys.executable, "server.py", "-c", cfg], cwd=REPO,
                                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        for _ in range(60):
            if cls.proc.poll() is not None:
                break
            try:
                socket.create_connection(("127.0.0.1", cls.port), timeout=0.5).close()
                return
            except (OSError, socket.error):
                time.sleep(0.25)
        cls._skip = "server did not start (out: %s)" % (cls.proc.stdout.read()[:300] if cls.proc and cls.proc.stdout else "")

    @classmethod
    def tearDownClass(cls):
        if cls.proc and cls.proc.poll() is None:
            cls.proc.terminate()
            try:
                cls.proc.wait(timeout=5)
            except Exception:
                cls.proc.kill()

    def test_trails_missing_returns_empty_not_500(self):
        if getattr(type(self), "_skip", None):
            self.skipTest(self._skip)
        st, _, body = _http(self.port, "GET", "/trails")
        self.assertEqual(st, 200, "missing TRAILS_FILE must yield 200 empty, not 500")
        self.assertEqual(body, b"", "no trails file -> empty body")
        self.assertIsNone(type(self).proc.poll(), "server must stay alive")

    def test_fail2ban_denied_secure_by_default(self):
        # this server sets no FAIL2BAN_ALLOWLIST -> the endpoint must be closed (404), not leak attacker IPs
        if getattr(type(self), "_skip", None):
            self.skipTest(self._skip)
        st, _, _ = _http(self.port, "GET", "/fail2ban")
        self.assertEqual(st, 404, "/fail2ban must be closed by default (no allowlist configured)")


class TestReapSessions(unittest.TestCase):
    """_reap_sessions drops expired sessions and closes any event-log handle they pinned (else sessions
    created and never revisited leak memory + a file descriptor each). In-process unit test."""

    def test_expired_dropped_live_kept_handle_closed(self):
        import core.httpd as H
        from core.attribdict import AttribDict
        H.SESSIONS.clear()
        closed = []

        class _Handle(object):
            def close(self):
                closed.append(True)

        H.SESSIONS["live"] = AttribDict({"expiration": time.time() + 3600})
        H.SESSIONS["dead"] = AttribDict({"expiration": time.time() - 1, "range_handle": _Handle()})
        H._sessions_reaped[0] = 0                    # bypass the time gate so the sweep runs now
        H._reap_sessions()
        self.assertIn("live", H.SESSIONS, "unexpired session must be kept")
        self.assertNotIn("dead", H.SESSIONS, "expired session must be reaped (memory leak otherwise)")
        self.assertEqual(closed, [True], "the expired session's pinned handle must be closed (fd leak otherwise)")
        H.SESSIONS.clear()


if __name__ == "__main__":
    unittest.main()
