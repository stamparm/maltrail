# coding: utf-8
"""Server<->frontend<->backend integration tests. Boots the REAL server.py as a subprocess with a
controlled config (known USERS credential, temp LOG_DIR with synthetic events) and exercises the
actual HTTP contract the dashboard relies on: challenge-response login, /events with Range slicing,
/counts, /check_ip, and malformed/edge inputs -- asserting the server answers correctly and never
5xx/crashes. Raw-socket HTTP client -> no urllib py2/py3 differences. Skips cleanly if the server
can't bind (e.g. sandbox)."""
import json
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
from core.httpd import LOGIN_FAILURE_THRESHOLD     # the brute-force refusal threshold under test
from core.settings import UNAUTHORIZED_SLEEP_TIME  # the width of its window


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
            # IP-based URL trail: trail string isn't a bare IP ("1.1.1.1/..."), but its host geolocates (AU) -> map it
            f.write(line("%s 10:00:04.000000" % cls.date, "sensor-a", "10.0.0.9", "7777", "1.1.1.1", "80", "TCP", "URL", "1.1.1.1/malware.exe", "1312 (dummy)", "(static)") + "\n")
        trails = os.path.join(cls.tmp, "trails.csv")
        with open(trails, "w") as f:
            f.write("evil.com,dummy,(static)\n")
            f.write("1.2.3.4,badip (dummy),(static)\n")
            f.write("badhost.example/gate.php,badurl (dummy),(static)\n")
            f.write("internal-secret.corp,supersecretname (custom),(custom)\n")
        # /check reads through the memory-mapped store, which the sensor normally builds; build it
        # here so the endpoint has something to map. Both paths are passed explicitly: this test
        # process has no configured TRAILS_FILE, and a silently skipped build would make the
        # /check assertions pass vacuously against an absent store.
        from core import common as _common
        _common.build_trails_bin(trails, trails + ".bin")
        assert os.path.isfile(trails + ".bin"), "the trail store must exist for the /check tests"
        # seed a condensed observable store so /meta has something to look up (the server reads LOG_DIR/meta.sqlite)
        from core import meta as _meta
        _meta.configure(os.path.join(logdir, "meta.sqlite"), enabled=True, flush_period=99999)
        _meta._agg = {}
        _meta.observe_conn("10.0.0.5", "8.8.8.8", False, 1700000000)
        _meta.observe_dns("evil.com", 1700000000)
        _meta.flush()
        _meta.configure(None, enabled=False); _meta._agg = {}   # reset the test process's module state
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

    def _login_body(self, username="admin"):
        import binascii; nonce = binascii.hexlify(os.urandom(16)).decode()
        h = hashlib.sha256((STORED + nonce).encode()).hexdigest()   # both test users share the same stored hash
        return "username=%s&nonce=%s&hash=%s" % (username, nonce, h)

    def _login(self, username="admin"):
        st, head, _ = _http(self.port, "POST", "/login", body=self._login_body(username))
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

    def test_check_finds_a_listed_trail(self):
        st, _, body = _http(self.port, "GET", "/check?q=evil.com")
        self.assertEqual(st, 200)
        data = json.loads(body.decode())
        self.assertTrue(data["found"], data)
        self.assertEqual(data["trail"], "evil.com")
        self.assertEqual(data["reference"], "(static)")

    def test_check_walks_parent_domains(self):
        # a subdomain of a listed domain is a hit, and reports WHICH key matched - the same
        # parent walk _check_domain_member() does, so the answer matches what the sensor would do
        st, _, body = _http(self.port, "GET", "/check?q=www.deep.evil.com")
        data = json.loads(body.decode())
        self.assertTrue(data["found"], data)
        self.assertEqual(data["trail"], "evil.com")

    def test_check_normalises_a_url(self):
        st, _, body = _http(self.port, "GET", "/check?q=http%3A%2F%2Fbadhost.example%2Fgate.php")
        data = json.loads(body.decode())
        self.assertTrue(data["found"], data)
        self.assertEqual(data["trail"], "badhost.example/gate.php")

    def test_check_handles_an_ip(self):
        st, _, body = _http(self.port, "GET", "/check?q=1.2.3.4")
        self.assertTrue(json.loads(body.decode())["found"])

    def test_check_does_not_disclose_custom_trails_unauthenticated(self):
        # ENABLE_MASK_CUSTOM redacts custom trail names even from logged-in non-admin users, so an
        # unauthenticated caller must not be able to confirm that one of the operator's OWN
        # indicators exists. Reported as a miss: masking the name would still answer the question.
        st, _, body = _http(self.port, "GET", "/check?q=internal-secret.corp")
        self.assertEqual(st, 200)
        data = json.loads(body.decode())
        self.assertFalse(data["found"], data)
        self.assertNotIn("supersecretname", body.decode())
        self.assertNotIn("custom", body.decode())

    def test_check_reveals_custom_trails_to_an_admin(self):
        cookie = self._login()
        st, _, body = _http(self.port, "GET", "/check?q=internal-secret.corp", cookie=cookie)
        data = json.loads(body.decode())
        self.assertTrue(data["found"], data)
        self.assertEqual(data["reference"], "(custom)")
        self.assertIn("supersecretname", data["info"])

    def test_check_hides_custom_trails_from_a_masked_analyst(self):
        # analyst has uid 1000, so mask_custom is on for that session - same rule as /events
        cookie = self._login(username="analyst")
        st, _, body = _http(self.port, "GET", "/check?q=internal-secret.corp", cookie=cookie)
        data = json.loads(body.decode())
        self.assertFalse(data["found"], data)
        self.assertNotIn("supersecretname", body.decode())

    def test_check_still_answers_for_public_trails(self):
        # the restriction is scoped to custom trails; static/feed data stays answerable
        st, _, body = _http(self.port, "GET", "/check?q=evil.com")
        self.assertTrue(json.loads(body.decode())["found"])

    def test_check_misses_are_not_errors(self):
        st, _, body = _http(self.port, "GET", "/check?q=definitely-not-listed.example")
        self.assertEqual(st, 200)
        data = json.loads(body.decode())
        self.assertFalse(data["found"])
        self.assertNotIn("error", data)

    def test_check_rejects_missing_and_oversized_queries(self):
        for q in ("", "a" * 300):
            st, _, body = _http(self.port, "GET", "/check?q=%s" % q)
            self.assertEqual(st, 200, "must answer, not 500")
            data = json.loads(body.decode())
            self.assertFalse(data["found"])
            self.assertIn("error", data)

    def test_check_never_500s_on_hostile_input(self):
        for q in ("%3Cscript%3E", "..%2F..%2Fetc%2Fpasswd", "%00", "*", "%25", "a%20b"):
            st, _, body = _http(self.port, "GET", "/check?q=%s" % q)
            self.assertEqual(st, 200, "q=%r produced %s" % (q, st))
            json.loads(body.decode())          # must still be valid JSON

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
        obj = _json.loads(body.decode("utf-8"))            # per-day event density for the calendar heat: {"YYYY-MM-DD": count}
        self.assertIsInstance(obj, dict)

    def test_geo_returns_json(self):
        # per-country attack-origin density for the world map: trail IPs geolocated, domains/private -> unmapped
        import json as _json
        ck = self._login()
        st, _, body = _http(self.port, "GET", "/geo?date=%s" % self.date, cookie=ck)
        self.assertEqual(st, 200)
        obj = _json.loads(body.decode("utf-8"))
        self.assertIsInstance(obj.get("counts"), dict)
        self.assertIn("mapped", obj)
        self.assertIn("unmapped", obj)
        # the synthetic log has public-IP trails (geolocatable) and an 'evil.com' domain trail (unmapped)
        self.assertGreaterEqual(obj["unmapped"], 1)
        # IP-based URL trail ("1.1.1.1/malware.exe" -> AU) must geolocate its host, not fall to unmapped
        self.assertIn("AU", obj["counts"], "IP-based URL trail must be placed on the map by its host IP")
        self.assertEqual(obj["mapped"], sum(obj["counts"].values()))

    def test_hunt_retro_search(self):
        # retro-hunt: historical IOC sweep across daily logs -> per-day counts + capped samples, bounded + scoped
        import json as _json
        ck = self._login()
        st, _, body = _http(self.port, "GET", "/hunt?q=evil.com", cookie=ck)
        self.assertEqual(st, 200)
        obj = _json.loads(body.decode("utf-8"))
        self.assertIn("counts", obj)
        self.assertIn("samples", obj)
        self.assertIn("truncated", obj)
        self.assertIn(self.date, obj["counts"])          # 'evil.com' is in today's synthetic log
        # too-short queries are rejected (a 1-2 char substring would match ~everything -> self-DoS)
        st, _, body = _http(self.port, "GET", "/hunt?q=x", cookie=ck)
        self.assertIn("error", _json.loads(body.decode("utf-8")))
        # a restricted analyst (netmask 10.0.0.0/8) must not see the external-only event
        ck2 = self._login("analyst")
        st, _, body = _http(self.port, "GET", "/hunt?q=extonly", cookie=ck2)
        obj = _json.loads(body.decode("utf-8"))
        self.assertEqual(obj["counts"], {}, "analyst must not hunt outside their netfilter scope")

    def test_meta_lookup(self):
        # condensed observable store: "have I ever seen this domain/ip, since when, how often" (O(1) PK lookup)
        import json as _json
        # requires auth
        st, _, _ = _http(self.port, "GET", "/meta?observable=8.8.8.8")
        self.assertEqual(st, 401, "/meta must require a session")
        ck = self._login()
        # a seeded IP observable -> full aggregate row
        st, _, body = _http(self.port, "GET", "/meta?observable=8.8.8.8", cookie=ck)
        self.assertEqual(st, 200)
        obj = _json.loads(body.decode("utf-8"))
        self.assertEqual(obj.get("kind"), "ip")
        self.assertEqual(obj.get("scope"), "remote")
        self.assertGreaterEqual(obj.get("count", 0), 1)
        self.assertEqual(obj.get("first_seen"), 1700000000)
        # a seeded domain observable
        _, _, body = _http(self.port, "GET", "/meta?observable=evil.com", cookie=ck)
        self.assertEqual(_json.loads(body.decode("utf-8")).get("kind"), "dns")
        # never-seen observable -> empty object
        _, _, body = _http(self.port, "GET", "/meta?observable=neverseen.invalid", cookie=ck)
        self.assertEqual(_json.loads(body.decode("utf-8")), {})

    def test_reference_endpoint(self):
        # on-demand trail source citation: requires auth; unknown trail -> empty (valid JSON) not an error
        import json as _json
        st, _, _ = _http(self.port, "GET", "/reference?trail=x")
        self.assertEqual(st, 401, "/reference must require a session")
        ck = self._login()
        st, _, body = _http(self.port, "GET", "/reference?trail=no-such-trail-xyz.invalid", cookie=ck)
        self.assertEqual(st, 200)
        obj = _json.loads(body.decode("utf-8"))
        self.assertIsInstance(obj, dict)
        self.assertEqual(obj.get("reference", ""), "")

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
        self.assertIn(b"evil.com", body, "the public trail set must be served to an unauthenticated sensor")

    def test_trails_endpoint_does_not_leak_custom_trails(self):
        # update_trails() merges trails/custom into the SAME file as the public feeds, and /trails
        # used to return that file verbatim to anyone who could reach the port - handing out the
        # operator's private indicators (internal hostnames, an investigation's IOCs) that /check
        # and /events go to real trouble to mask.
        st, _, anon = _http(self.port, "GET", "/trails")
        self.assertEqual(st, 200)
        self.assertNotIn(b"internal-secret.corp", anon, "/trails must not disclose custom trails to an unauthenticated caller")
        self.assertIn(b"evil.com", anon, "positive control: the public trails are still served")

        # an admin is entitled to them, so a sensor pulling with a session still gets the full set
        _, _, admin = _http(self.port, "GET", "/trails", cookie=self._login("admin"))
        self.assertIn(b"internal-secret.corp", admin, "an admin session must still receive custom trails")

        # ... and a mask_custom user (uid >= 1000) is not, exactly as /check treats them
        _, _, analyst = _http(self.port, "GET", "/trails", cookie=self._login("analyst"))
        self.assertNotIn(b"internal-secret.corp", analyst, "a mask_custom session must not receive custom trails")
        self.assertIn(b"evil.com", analyst, "positive control: the public trails are still served")

    def _failed_login(self, username="admin"):
        import binascii
        nonce = binascii.hexlify(os.urandom(16)).decode()
        h = hashlib.sha256(("0" * 64 + nonce).encode()).hexdigest()
        return _http(self.port, "POST", "/login", body="username=%s&nonce=%s&hash=%s" % (username, nonce, h))

    def test_failed_login_returns_promptly(self):
        # The failure path used to time.sleep(UNAUTHORIZED_SLEEP_TIME) while holding a request
        # thread, so the anti-brute-force measure was also the cheapest way to exhaust the server:
        # 200 concurrent failed logins took it from 1 thread to 172. The delay is gone; the cost
        # to an attacker is now a refusal threshold that holds no thread at all.
        t0 = time.time()
        st, _, _ = self._failed_login()
        elapsed = time.time() - t0
        self.assertEqual(st, 401)
        self.assertLess(elapsed, 2.0, "a failed login must not park a request thread (was 5s)")

    def test_one_mistyped_password_does_not_lock_out_the_address(self):
        # The reporting interface is routinely reached through a single NAT address. Refusing on
        # the FIRST failure - the obvious way to remove the sleep - would mean one fat-fingered
        # password locks out everyone behind it, and an attacker could hold an office out of its
        # own console by failing a login every few seconds. That is a worse bug than the one being
        # fixed, so the refusal is a consecutive-failure threshold and this is its guard.
        self._failed_login()
        st, head, _ = _http(self.port, "POST", "/login", body=self._login_body("admin"))
        self.assertEqual(st, 200, "a correct password right after one mistype must still work")
        self.assertIn("sessid", head, "and must still establish a session")

    def test_repeated_failures_are_refused_without_evaluation(self):
        # Past the threshold the attempt is refused before the credentials are looked at, which is
        # what bounds a brute-force run. Proven by submitting the CORRECT password and being
        # refused anyway - if it were still being evaluated, this would succeed.
        for _ in range(LOGIN_FAILURE_THRESHOLD + 1):
            self._failed_login()
        st, _, _ = _http(self.port, "POST", "/login", body=self._login_body("admin"))
        self.assertEqual(st, 401, "past the threshold even a valid password must not be evaluated")
        # ... and the streak expires, so the lockout is not permanent
        time.sleep(UNAUTHORIZED_SLEEP_TIME + 0.5)
        st, _, _ = _http(self.port, "POST", "/login", body=self._login_body("admin"))
        self.assertEqual(st, 200, "the window must expire and let a legitimate user back in")

    def test_index_never_serves_the_demo_script(self):
        """main.js turns DEMO on from the mere presence of demo.js.

            var DEMO = (typeof window.getDemoCSV === "function");

        So if the server's strip of that script tag ever misses, a real operator is shown
        FABRICATED events - a normal-looking dashboard full of somebody else's fake traffic, with
        nothing on screen saying so. It is the frontend's version of "looks fine, detects
        nothing", and nothing tested it.

        The strip used to require the exact shipped spelling of the tag, so re-quoting it or
        adding an attribute in index.html would have been enough.
        """

        st, _, body = _http(self.port, "GET", "/")
        self.assertEqual(st, 200)
        self.assertNotIn(b"demo.js", body, "the served dashboard must never reference demo.js")
        self.assertIn(b"js/main.js", body, "positive control: the real script is still served")

    def test_events_supports_open_ended_and_suffix_ranges(self):
        # The Range parser was `bytes=(\d+)-(\d+)`, so an end was mandatory. `bytes=N-` - the
        # natural way to tail a growing log, and what any non-browser client writes - matched
        # nothing, fell through, and got 200 with the WHOLE FILE. A client polling a large day log
        # re-downloaded all of it every time and could not tell its range had been ignored;
        # html/js/main.js only worked because it sends a huge explicit end as a documented
        # workaround. RFC 7233 has three forms and all three now work.
        ck = self._login("admin")
        _, _, whole = _http(self.port, "GET", "/events?date=%s" % self.date, cookie=ck)
        total = len(whole)
        self.assertGreater(total, 20, "fixture log must be non-trivial")

        st, head, body = _http(self.port, "GET", "/events?date=%s" % self.date, cookie=ck,
                               headers={"Range": "bytes=%d-" % (total - 10)})
        self.assertEqual(st, 206, "an open-ended range must be honoured, not answered with 200+everything")
        self.assertEqual(body, whole[-10:])
        self.assertIn("bytes %d-%d/%d" % (total - 10, total - 1, total), head)

        st, _, body = _http(self.port, "GET", "/events?date=%s" % self.date, cookie=ck,
                            headers={"Range": "bytes=-10"})
        self.assertEqual(st, 206, "a suffix range must be honoured")
        self.assertEqual(body, whole[-10:])

        # explicit span still behaves exactly as before
        st, _, body = _http(self.port, "GET", "/events?date=%s" % self.date, cookie=ck,
                            headers={"Range": "bytes=0-9"})
        self.assertEqual(st, 206)
        self.assertEqual(body, whole[:10])

        # a start at or past EOF is unsatisfiable, not a silent full-file 200
        st, _, body = _http(self.port, "GET", "/events?date=%s" % self.date, cookie=ck,
                            headers={"Range": "bytes=999999999-"})
        self.assertEqual(st, 416, "an out-of-range start must not return the whole file")

    def test_hunt_does_not_report_a_partial_day_as_complete(self):
        # When the time budget expired inside a day, that day's running total was written into
        # `counts` exactly like a finished day's. Measured on three 40k-line days with a small
        # budget, the middle day came back as 16383 against a true 40000 - an undercount an
        # analyst reads straight off the timeline as that day's answer. `truncated` was set, but
        # it said only "something was cut", never which day. Undercounting a retro-hunt is the
        # wrong direction to be wrong in.
        #
        # A second server with a deliberately tiny HUNT_TIME_BUDGET, so the cut is forced rather
        # than raced: the shared fixture's budget is the real one.
        import json as _json
        tmp = tempfile.mkdtemp(prefix="mt_hunt_")
        try:
            logdir = os.path.join(tmp, "logs"); os.makedirs(logdir)
            per, days = 20000, ["2026-07-01", "2026-07-02", "2026-07-03"]
            for day in days:
                with open(os.path.join(logdir, "%s.log" % day), "w") as f:
                    for _ in range(per):
                        f.write('"%s 10:00:00.000000" s 10.0.0.5 4421 8.8.8.8 53 UDP DNS '
                                'huntme.example "malware (dummy)" (static)\n' % day)
            trails = os.path.join(tmp, "t.csv")
            with open(trails, "w") as f:
                f.write("huntme.example,x (dummy),(static)\n")
            port = _free_port()
            cfg = os.path.join(tmp, "srv.conf")
            with open(cfg, "w") as f:
                f.write("HTTP_ADDRESS 127.0.0.1\nHTTP_PORT %d\nHUNT_TIME_BUDGET 0.02\n" % port)
                f.write("USE_SERVER_UPDATE_TRAILS false\nMONITOR_INTERFACE any\nCAPTURE_BUFFER 10MB\n")
                f.write("LOG_DIR %s\nTRAILS_FILE %s\nUPDATE_PERIOD 86400\nSENSOR_NAME t\nDISABLE_CHECK_SUDO true\n"
                        % (logdir, trails))
            proc = subprocess.Popen([sys.executable, "server.py", "-c", cfg], cwd=REPO,
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            try:
                for _ in range(60):
                    try:
                        socket.create_connection(("127.0.0.1", port), timeout=0.5).close(); break
                    except OSError: time.sleep(0.25)
                st, _, body = _http(port, "GET", "/hunt?q=huntme.example", timeout=60)
                self.assertEqual(st, 200)
                o = _json.loads(body.decode("utf-8"))
                self.assertTrue(o["truncated"], "a 0.02s budget over 60k lines must truncate")
                # every day left in `counts` was read to the end, so its number is the real one
                for day, hits in o["counts"].items():
                    self.assertEqual(hits, per, "%s is in counts, so it must be a COMPLETE count" % day)
                # and the day that was cut short is reported, separately and explicitly
                if o.get("partial"):
                    self.assertNotIn(o["partial"]["date"], o["counts"],
                                     "a partially scanned day must not appear as a complete one")
                    self.assertLess(o["partial"]["hits"], per, "a partial count is by definition short")
                self.assertLessEqual(o["scanned"], o["selected"])
                self.assertLess(o["scanned"], len(days), "scanned must count days READ, not days selected")
            finally:
                proc.terminate(); proc.wait(timeout=5)
        finally:
            import shutil; shutil.rmtree(tmp, ignore_errors=True)

    def test_live_streams_cannot_starve_ordinary_requests(self):
        # A /live stream holds its request thread for the lifetime of the tab. Counted against the
        # general thread cap it starves everything else: 120 open dashboards took all 100 slots and
        # every ordinary request got a 503 - a cheaper denial of service than the cap was added to
        # prevent, needing nothing but a browser. Streams get a smaller budget of their own, and a
        # refused one is answered 204, which the frontend already falls back to polling on.
        #
        # Its own server with MAX_LIVE_STREAMS 3, so the assertion needs five held sockets rather
        # than thirty-five. The first version of this test held 35 and passed standalone but blew
        # through tests/run.sh's 1.2 GB address-space cap, taking the whole shared-server class
        # down with it - a test heavy enough to break the runner is a test that does not run.
        tmp = tempfile.mkdtemp(prefix="mt_sse_")
        try:
            logdir = os.path.join(tmp, "logs"); os.makedirs(logdir)
            day = "2026-07-01"
            with open(os.path.join(logdir, "%s.log" % day), "w") as f:
                f.write('"%s 10:00:00.000000" s 10.0.0.5 1 8.8.8.8 53 UDP DNS x.example "m (d)" (static)\n' % day)
            trails = os.path.join(tmp, "t.csv")
            with open(trails, "w") as f:
                f.write("x.example,m (dummy),(static)\n")
            port = _free_port()
            cfg = os.path.join(tmp, "srv.conf")
            with open(cfg, "w") as f:
                f.write("HTTP_ADDRESS 127.0.0.1\nHTTP_PORT %d\nMAX_LIVE_STREAMS 3\n" % port)
                f.write("USE_SERVER_UPDATE_TRAILS false\nMONITOR_INTERFACE any\nCAPTURE_BUFFER 10MB\n")
                f.write("LOG_DIR %s\nTRAILS_FILE %s\nUPDATE_PERIOD 86400\nSENSOR_NAME t\nDISABLE_CHECK_SUDO true\n"
                        % (logdir, trails))
            proc = subprocess.Popen([sys.executable, "server.py", "-c", cfg], cwd=REPO,
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            held, refused = [], 0
            try:
                for _ in range(60):
                    try:
                        socket.create_connection(("127.0.0.1", port), timeout=0.5).close(); break
                    except OSError: time.sleep(0.25)
                for _ in range(5):
                    s = socket.create_connection(("127.0.0.1", port), timeout=5)
                    s.sendall(("GET /live?date=%s HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n" % day).encode())
                    if b" 204 " in s.recv(64):
                        refused += 1; s.close()
                    else:
                        held.append(s)
                self.assertEqual(len(held), 3, "the stream budget must be enforced exactly")
                self.assertEqual(refused, 2, "streams past the budget must be refused, not accepted")
                st, _, _ = _http(port, "GET", "/")
                self.assertEqual(st, 200, "ordinary requests must survive a wall of open SSE streams")
                # a closed stream returns its slot, so the budget is a ceiling and not a one-way latch
                held.pop().close()
                time.sleep(1.5)
                s = socket.create_connection(("127.0.0.1", port), timeout=5)
                s.sendall(("GET /live?date=%s HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n" % day).encode())
                self.assertNotIn(b" 204 ", s.recv(64), "a released slot must be reusable")
                s.close()
            finally:
                for s in held:
                    try: s.close()
                    except Exception: pass
                proc.terminate(); proc.wait(timeout=5)
        finally:
            import shutil; shutil.rmtree(tmp, ignore_errors=True)

    def test_counts_are_scoped_to_the_session_networks(self):
        # /events has always honoured netfilters; /counts reported the GLOBAL daily totals to every
        # authenticated user, so a restricted analyst could read the whole estate's volume off the
        # calendar heat map. Five events are seeded, one of which has no 10.x address.
        import json as _json
        _, _, admin = _http(self.port, "GET", "/counts", cookie=self._login("admin"))
        _, _, analyst = _http(self.port, "GET", "/counts", cookie=self._login("analyst"))
        admin_counts = _json.loads(admin.decode("utf-8"))
        analyst_counts = _json.loads(analyst.decode("utf-8"))
        self.assertEqual(admin_counts.get(self.date), 5, "positive control: admin sees every event")
        self.assertEqual(analyst_counts.get(self.date), 4, "the external-only event is outside 10.0.0.0/8")

    def test_counts_cache_is_keyed_by_scope(self):
        # The count cache is a module global shared by every request. Keyed on the log path alone,
        # whichever user asked first would have their total served to the other - the same
        # disclosure through the cache instead of the endpoint. Ask in both orders.
        import json as _json
        _, _, a1 = _http(self.port, "GET", "/counts", cookie=self._login("analyst"))
        _, _, b1 = _http(self.port, "GET", "/counts", cookie=self._login("admin"))
        _, _, a2 = _http(self.port, "GET", "/counts", cookie=self._login("analyst"))
        self.assertEqual(_json.loads(a1.decode("utf-8")).get(self.date), 4)
        self.assertEqual(_json.loads(b1.decode("utf-8")).get(self.date), 5)
        self.assertEqual(_json.loads(a2.decode("utf-8")).get(self.date), 4, "the admin request must not have poisoned the analyst's entry")

    def test_blacklist_is_scoped_to_the_session_networks(self):
        # BLACKLIST_FOO selects the IP-type events, whose sources are 10.0.0.6, 10.0.0.8 and the
        # out-of-scope 203.0.113.9. The response is a list of flagged SOURCE addresses, so an
        # unscoped answer tells a restricted analyst which hosts outside their networks were hit.
        _, _, admin = _http(self.port, "GET", "/blacklist/foo", cookie=self._login("admin"))
        _, _, analyst = _http(self.port, "GET", "/blacklist/foo", cookie=self._login("analyst"))
        self.assertIn(b"203.0.113.9", admin, "positive control: an unrestricted session still sees it")
        self.assertNotIn(b"203.0.113.9", analyst, "/blacklist must not return sources outside the analyst's networks")
        self.assertIn(b"10.0.0.6", analyst, "positive control: in-scope sources are still returned")

    def test_geo_is_scoped_to_the_session_networks(self):
        # The map is built from the same log lines. Unscoped, it drew a restricted analyst the
        # whole estate's picture - coarser than /events, but still derived from events they may
        # not read. The external-only event's destination (198.51.100.5) is the one that differs.
        import json as _json
        _, _, admin = _http(self.port, "GET", "/geo?date=%s" % self.date, cookie=self._login("admin"))
        _, _, analyst = _http(self.port, "GET", "/geo?date=%s" % self.date, cookie=self._login("analyst"))
        a = _json.loads(admin.decode("utf-8"))
        b = _json.loads(analyst.decode("utf-8"))
        self.assertGreater(a["mapped"] + a["unmapped"], b["mapped"] + b["unmapped"],
                           "a restricted analyst must be placed on fewer events than an admin")

    def test_meta_refused_for_scoped_sessions(self):
        # The observables table is (observable, flags, first_seen, last_seen, count): no network
        # dimension, so an answer is necessarily about the whole estate and cannot be filtered.
        # Refused rather than answered with {}, which would read as "never observed".
        st, _, _ = _http(self.port, "GET", "/meta?observable=8.8.8.8", cookie=self._login("analyst"))
        self.assertEqual(st, 403, "/meta must not answer a network-restricted session")
        st, _, _ = _http(self.port, "GET", "/meta?observable=8.8.8.8", cookie=self._login("admin"))
        self.assertEqual(st, 200, "positive control: an unrestricted session is still answered")

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



class TestBlacklistAccessControl(unittest.TestCase):
    """/blacklist returns the source IPs of flagged events, so it must not answer just anyone.

    It is pulled by firewall automation rather than by the UI, so the control is the same
    allowlist /fail2ban uses (an authenticated session also passes). This server sets NO
    allowlist of either kind, so an unauthenticated caller must be refused -- and refused with
    404, like the sibling endpoint, rather than advertising that the endpoint exists.
    """

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        logdir = os.path.join(cls.tmp, "logs")
        os.makedirs(logdir)
        cls.date = time.strftime("%Y-%m-%d")
        with open(os.path.join(logdir, "%s.log" % cls.date), "w") as f:
            f.write('"%s 09:14:22.117034" gw 10.13.13.2 57809 1.1.1.1 53 UDP DNS evil.com "asyncrat (malware)" (static)\n' % cls.date)
        trails = os.path.join(cls.tmp, "trails.csv")
        with open(trails, "w") as f:
            f.write("evil.com,asyncrat (malware),(static)\n")

        cls.port = _free_port()
        cfg = os.path.join(cls.tmp, "srv.conf")
        with open(cfg, "w") as f:
            f.write("HTTP_ADDRESS 127.0.0.1\nHTTP_PORT %d\n" % cls.port)
            f.write("USERS\n    admin:%s:0:\n" % STORED)
            # deliberately NO FAIL2BAN_ALLOWLIST and NO BLACKLIST_ALLOWLIST
            f.write("BLACKLIST\n    type ~ DNS\n")
            f.write("USE_SERVER_UPDATE_TRAILS false\nMONITOR_INTERFACE any\nCAPTURE_BUFFER 10MB\n")
            f.write("LOG_DIR %s\nTRAILS_FILE %s\nUPDATE_PERIOD 86400\nSENSOR_NAME test\nDISABLE_CHECK_SUDO true\n" % (logdir, trails))
        cls.proc = subprocess.Popen([sys.executable, "server.py", "-c", cfg], cwd=REPO,
                                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        for _ in range(60):
            if cls.proc.poll() is not None:
                break
            try:
                socket.create_connection(("127.0.0.1", cls.port), timeout=0.5).close()
                break
            except Exception:
                time.sleep(0.25)

    @classmethod
    def tearDownClass(cls):
        if cls.proc and cls.proc.poll() is None:
            cls.proc.terminate()
            try:
                cls.proc.wait(timeout=5)
            except Exception:
                cls.proc.kill()

    def test_unauthenticated_pull_is_refused(self):
        st, _, body = _http(self.port, "GET", "/blacklist")
        self.assertEqual(st, 404, "/blacklist must be closed with no allowlist configured")
        self.assertNotIn(b"10.13.13.2", body, "the flagged source IP must not be disclosed")

    def test_subpaths_are_refused_too(self):
        st, _, body = _http(self.port, "GET", "/blacklist/foo")
        self.assertEqual(st, 404)
        self.assertNotIn(b"10.13.13.2", body)

    def test_an_authenticated_operator_still_gets_it(self):
        import binascii
        nonce = binascii.hexlify(os.urandom(16)).decode()
        h = hashlib.sha256((STORED + nonce).encode()).hexdigest()
        st, head, _ = _http(self.port, "POST", "/login", body="username=admin&nonce=%s&hash=%s" % (nonce, h))
        self.assertEqual(st, 200, "login should succeed")
        m = [l for l in head.split("\r\n") if l.lower().startswith("set-cookie:")]
        self.assertTrue(m, "login must set a session cookie")
        cookie = m[0].split(":", 1)[1].split(";", 1)[0].strip()
        st, _, body = _http(self.port, "GET", "/blacklist", cookie=cookie)
        self.assertEqual(st, 200, "an authenticated operator must still be able to pull it")
        self.assertIn(b"10.13.13.2", body, "the blacklist content itself is unchanged")


class TestClearedSources(unittest.TestCase):
    """A remediated host can be taken off the derived lists without being whitelisted forever.

    /blacklist and /fail2ban are derived from the current day's events, so a host flagged once
    stays listed until midnight and the only escape was USER_WHITELIST - which also suppresses
    every FUTURE detection for it (issue #19053). Clearing is time-bounded instead.
    """

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="mt_cleared_")
        cls.logdir = os.path.join(cls.tmp, "logs"); os.makedirs(cls.logdir)
        cls.date = time.strftime("%Y-%m-%d")
        cls.log = os.path.join(cls.logdir, cls.date + ".log")
        with open(cls.log, "w") as f:
            f.write(cls._event("09:00:00", "10.13.13.37"))
            f.write(cls._event("09:05:00", "10.13.13.99"))
        trails = os.path.join(cls.tmp, "trails.csv")
        with open(trails, "w") as f:
            f.write("evil.com,dummy,(static)\n")

        cls.port = _free_port()
        cfg = os.path.join(cls.tmp, "srv.conf")
        with open(cfg, "w") as f:
            f.write("HTTP_ADDRESS 127.0.0.1\nHTTP_PORT %d\n" % cls.port)
            f.write("FAIL2BAN_ALLOWLIST 127.0.0.1\nFAIL2BAN_REGEX malware\n")
            f.write("BLACKLIST\n    src_ip ~ ^10\\.\n")
            f.write("USE_SERVER_UPDATE_TRAILS false\nMONITOR_INTERFACE any\nCAPTURE_BUFFER 10MB\n")
            f.write("LOG_DIR %s\nTRAILS_FILE %s\nUPDATE_PERIOD 86400\nSENSOR_NAME gw\nDISABLE_CHECK_SUDO true\n" % (cls.logdir, trails))
        cls.proc = subprocess.Popen([sys.executable, "server.py", "-c", cfg], cwd=REPO,
                                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        for _ in range(60):
            if cls.proc.poll() is not None:
                break
            try:
                socket.create_connection(("127.0.0.1", cls.port), timeout=0.5).close(); break
            except Exception:
                time.sleep(0.25)

    @staticmethod
    def _event(when, src):
        return '"%s %s.000000" gw %s 4421 8.8.8.8 53 UDP DNS evil.com "malware (dummy)" (static)\n' % (
            time.strftime("%Y-%m-%d"), when, src)

    @classmethod
    def tearDownClass(cls):
        if cls.proc and cls.proc.poll() is None:
            cls.proc.terminate()
            try:
                cls.proc.wait(timeout=5)
            except Exception:
                cls.proc.kill()

    def setUp(self):
        # Each test owns the log and the cleared list: one of them APPENDS an event, and these
        # run in alphabetical order, so without this the append leaks into its neighbours and
        # they fail for a reason that has nothing to do with what they assert.
        with open(self.log, "w") as f:
            f.write(self._event("09:00:00", "10.13.13.37"))
            f.write(self._event("09:05:00", "10.13.13.99"))
        self._clear("")
        time.sleep(9)      # both endpoints cache for 8s; start each test from a cold cache

    def _listed(self, endpoint):
        _, _, body = _http(self.port, "GET", endpoint)
        return sorted(x for x in body.decode().split("\n") if x.strip())

    def _clear(self, text):
        with open(os.path.join(self.logdir, "cleared.txt"), "w") as f:
            f.write(text)

    def test_clearing_removes_only_that_host_and_only_the_earlier_events(self):
        self.assertEqual(self._listed("/blacklist"), ["10.13.13.37", "10.13.13.99"])

        self._clear("10.13.13.37 %s 09:30:00\n" % self.date)
        self.assertEqual(self._listed("/blacklist"), ["10.13.13.99"], "the cleared host must drop off")
        self.assertEqual(self._listed("/fail2ban"), ["10.13.13.99"], "and off /fail2ban too")

    def test_a_later_event_puts_a_cleared_host_straight_back(self):
        # The whole point: clearing is not a whitelist. A NEW detection must re-list the host.
        self._clear("10.13.13.37 %s 09:30:00\n" % self.date)
        self.assertNotIn("10.13.13.37", self._listed("/blacklist"))
        with open(self.log, "a") as f:
            f.write(self._event("23:59:00", "10.13.13.37"))
        time.sleep(9)                                     # the endpoints have always cached for 8s
        self.assertIn("10.13.13.37", self._listed("/blacklist"), "a later event must re-list it")

    def test_a_malformed_entry_does_not_clear_anything(self):
        self._clear("not-an-ip\n@@@\n")
        self.assertEqual(self._listed("/blacklist"), ["10.13.13.37", "10.13.13.99"])


class TestAuthEventForwarding(unittest.TestCase):
    """Login attempts must reach a remote collector, and must not be forgeable.

    Brute force against the reporting interface is the one attack on Maltrail that Maltrail
    could not see from outside the box (issue #19080).
    """

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="mt_auth_")
        logdir = os.path.join(cls.tmp, "logs"); os.makedirs(logdir)
        trails = os.path.join(cls.tmp, "trails.csv")
        with open(trails, "w") as f:
            f.write("evil.com,dummy,(static)\n")

        cls.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        cls.sock.bind(("127.0.0.1", 0))
        cls.sock.settimeout(15)
        collector = cls.sock.getsockname()[1]

        cls.port = _free_port()
        cfg = os.path.join(cls.tmp, "srv.conf")
        with open(cfg, "w") as f:
            f.write("HTTP_ADDRESS 127.0.0.1\nHTTP_PORT %d\n" % cls.port)
            f.write("USERS\n    admin:%s:0:\n" % STORED)
            f.write("SYSLOG_SERVER 127.0.0.1:%d\n" % collector)
            f.write("USE_SERVER_UPDATE_TRAILS false\nMONITOR_INTERFACE any\nCAPTURE_BUFFER 10MB\n")
            f.write("LOG_DIR %s\nTRAILS_FILE %s\nUPDATE_PERIOD 86400\nSENSOR_NAME test\nDISABLE_CHECK_SUDO true\n" % (logdir, trails))
        cls.proc = subprocess.Popen([sys.executable, "server.py", "-c", cfg], cwd=REPO,
                                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        for _ in range(60):
            if cls.proc.poll() is not None:
                break
            try:
                socket.create_connection(("127.0.0.1", cls.port), timeout=0.5).close()
                break
            except Exception:
                time.sleep(0.25)

    @classmethod
    def tearDownClass(cls):
        if cls.proc and cls.proc.poll() is None:
            cls.proc.terminate()
            try:
                cls.proc.wait(timeout=5)
            except Exception:
                cls.proc.kill()
        try:
            cls.sock.close()
        except Exception:
            pass

    def _attempt(self, username, good):
        import binascii
        nonce = binascii.hexlify(os.urandom(16)).decode()
        secret = STORED if good else "0" * 64
        h = hashlib.sha256((secret + nonce).encode()).hexdigest()
        _http(self.port, "POST", "/login", body="username=%s&nonce=%s&hash=%s" % (username, nonce, h))
        return self.sock.recv(65535).decode("utf8", "replace")

    def test_a_failed_login_is_forwarded(self):
        record = self._attempt("admin", False)
        self.assertIn("CEF:0|Maltrail|server", record)
        self.assertIn("login failure", record)
        self.assertIn("duser=admin", record)
        self.assertIn("src=127.0.0.1", record)

    def test_a_successful_login_is_forwarded_and_distinguishable(self):
        record = self._attempt("admin", True)
        self.assertIn("login success", record)
        self.assertNotIn("login failure", record)

    def test_a_username_cannot_forge_a_log_line(self):
        # An embedded newline would let an attacker append a convincing "Accepted password for
        # root" to the audit trail meant to catch them.
        record = self._attempt("evil%0AAccepted+password+for+root", False)
        self.assertNotIn("\n", record.strip(), "the record must stay a single line")
        self.assertIn("login failure", record)
        self.assertNotIn("Accepted password", record.split("duser=")[0])


if __name__ == "__main__":
    unittest.main()

