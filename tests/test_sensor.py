# coding: utf-8
"""General Maltrail sensor tests: the real detection path.

Drives sensor._check_domain / sensor._process_packet against a controlled `trails` store with a
captured `log_event`, then asserts the detections (DNS, IP, IP:port, UDP) Maltrail would record.
Also locks the DLT-offset heuristic learner. Importing sensor is side-effect free (main() is
__main__-guarded); it needs pcapy (pcapy-ng) importable.
"""
import os
import sys
import struct
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _pcapgen as G

import sensor
from core.enums import TRAIL, PROTO


class _Trails(dict):
    """Stand-in for Maltrail's trails store: dict of key -> (info, reference), with a ._regex attr."""
    _regex = ""


def _dns_query(name, qtype=1, qclass=1, flags=0x0100):
    """Minimal DNS query message: header + one question (QTYPE/QCLASS)."""
    hdr = struct.pack("!HHHHHH", 0x1234, flags, 1, 0, 0, 0)
    q = b""
    for label in name.split('.'):
        q += struct.pack("!B", len(label)) + label.encode()
    q += b"\x00" + struct.pack("!HH", qtype, qclass)
    return hdr + q


class _SensorTestBase(unittest.TestCase):
    def setUp(self):
        self.events = []
        self._orig_log = sensor.log_event
        self._orig_trails = sensor.trails
        sensor.log_event = lambda event, packet=None, **kw: self.events.append(event)
        self.trails = _Trails()
        sensor.trails = self.trails
        sensor.WHITELIST = set()
        sensor._result_cache = {}
        # deterministic: no heuristics, no plugin pre-pass, host-domain check on
        sensor.config.USE_HEURISTICS = False
        sensor.config.plugin_functions = None
        sensor.config.CHECK_HOST_DOMAINS = True
        sensor.config.DISABLED_HEURISTICS = ""       # all heuristics enabled by default
        sensor._disabled_heuristics_cache[0] = None  # force re-read of DISABLED_HEURISTICS per test
        sensor.config.SCAN_WINDOW = 30
        sensor._scan_window_start = 0
        sensor._scan_alerted = set()
        sensor._path_alerted = set()
        sensor._connect_src_dst = {}
        sensor._connect_src_details = {}
        sensor._path_src_dst = {}
        sensor._path_src_dst_details = {}
        sensor._udp_scan = {}
        sensor._udp_scan_details = {}
        sensor._udp_alerted = set()
        # reset burst-suppression globals so each test's first packet is processed
        for g in ("_last_syn", "_last_logged_syn", "_last_udp", "_last_logged_udp"):
            setattr(sensor, g, None)

    def tearDown(self):
        sensor.log_event = self._orig_log
        sensor.trails = self._orig_trails

    def _trail_of(self, event):
        # event tuple layout: (sec, usec, src_ip, src_port, dst_ip, dst_port, proto, type, trail, info, ref)
        return event[8]

    def _type_of(self, event):
        return event[7]


class TestCheckDomain(_SensorTestBase):
    def test_domain_member(self):
        self.assertTrue(sensor._check_domain_member("www.evil.com", set(["evil.com"])))
        self.assertTrue(sensor._check_domain_member("a.b.example.com", set(["example.com"])))
        self.assertFalse(sensor._check_domain_member("good.com", set(["evil.com"])))

    def test_exact_domain_hit(self):
        self.trails["evil.com"] = ("malware (dummy)", "ref")
        sensor._check_domain("evil.com", 1, 0, "10.0.0.1", 5555, "8.8.8.8", 53, PROTO.UDP)
        self.assertEqual(len(self.events), 1)
        self.assertEqual(self._type_of(self.events[0]), TRAIL.DNS)
        self.assertEqual(self._trail_of(self.events[0]), "evil.com")

    def test_subdomain_hit_marks_parent(self):
        self.trails["evil.com"] = ("malware (dummy)", "ref")
        sensor._check_domain("www.evil.com", 1, 0, "10.0.0.1", 5555, "8.8.8.8", 53, PROTO.UDP)
        self.assertEqual(len(self.events), 1)
        self.assertEqual(self._trail_of(self.events[0]), "(www).evil.com")

    def test_onion_via_tor2web(self):
        # a .onion reached through a tor2web-style gateway (badsite.onion.to): the known onion trail
        # must still fire, with the gateway suffix bracketed off.
        self.trails["badsite.onion"] = ("malware (dummy)", "ref")
        sensor._check_domain("badsite.onion.to", 1, 0, "10.0.0.1", 5555, "8.8.8.8", 53, PROTO.UDP)
        self.assertEqual(len(self.events), 1, self.events)
        self.assertEqual(self._trail_of(self.events[0]), "badsite.onion(.to)")

    def test_ip_adress_com_relation(self):
        # <name>.ip-adress.com lookups map back to the <name> trail (VT relation), formatted <name>(.ip-adress.com).
        self.trails["evil"] = ("malware (dummy)", "ref")
        sensor._check_domain("evil.ip-adress.com", 1, 0, "10.0.0.1", 5555, "8.8.8.8", 53, PROTO.UDP)
        self.assertEqual(len(self.events), 1, self.events)
        self.assertEqual(self._trail_of(self.events[0]), "evil(.ip-adress.com)")

    def test_whitelisted_suppressed(self):
        self.trails["evil.com"] = ("malware (dummy)", "ref")
        sensor.WHITELIST = set(["evil.com"])
        sensor._check_domain("evil.com", 1, 0, "10.0.0.1", 5555, "8.8.8.8", 53, PROTO.UDP)
        self.assertEqual(self.events, [])

    def test_clean_domain_no_event(self):
        self.trails["evil.com"] = ("malware (dummy)", "ref")
        sensor._check_domain("good.com", 1, 0, "10.0.0.1", 5555, "8.8.8.8", 53, PROTO.UDP)
        self.assertEqual(self.events, [])

    def test_ip_literal_ignored(self):
        sensor._check_domain("1.2.3.4", 1, 0, "10.0.0.1", 5555, "8.8.8.8", 53, PROTO.UDP)
        self.assertEqual(self.events, [])


class TestProcessPacket(_SensorTestBase):
    def test_dns_query_to_bad_domain(self):
        self.trails["evil.com"] = ("malware (dummy)", "ref")
        pkt = G.ipv4(17, "10.0.0.5", "8.8.8.8", G.udp(40000, 53, _dns_query("evil.com")))
        sensor._process_packet(pkt, 1, 0, 0)
        dns = [e for e in self.events if self._type_of(e) == TRAIL.DNS]
        self.assertTrue(any(self._trail_of(e) == "evil.com" for e in dns), self.events)

    def test_dns_query_clean_domain(self):
        self.trails["evil.com"] = ("malware (dummy)", "ref")
        pkt = G.ipv4(17, "10.0.0.5", "8.8.8.8", G.udp(40000, 53, _dns_query("example.com")))
        sensor._process_packet(pkt, 1, 0, 0)
        self.assertEqual(self.events, [])

    def test_tcp_syn_to_bad_ip(self):
        self.trails["66.66.66.66"] = ("badnet (dummy)", "ref")
        pkt = G.ipv4(6, "10.0.0.5", "66.66.66.66", G.tcp(50000, 443, 0x02, b""))   # SYN only
        sensor._process_packet(pkt, 1, 0, 0)
        ip_ev = [e for e in self.events if self._type_of(e) == TRAIL.IP]
        self.assertEqual(len(ip_ev), 1, self.events)
        self.assertEqual(self._trail_of(ip_ev[0]), "66.66.66.66")

    def test_tcp_syn_ipport_trail(self):
        self.trails["66.66.66.66:4444"] = ("c2 (dummy)", "ref")
        pkt = G.ipv4(6, "10.0.0.5", "66.66.66.66", G.tcp(50000, 4444, 0x02, b""))
        sensor._process_packet(pkt, 1, 0, 0)
        ev = [e for e in self.events if self._type_of(e) == TRAIL.IPORT]
        self.assertEqual(len(ev), 1, self.events)
        self.assertEqual(self._trail_of(ev[0]), "66.66.66.66:4444")

    def test_udp_non_dns_to_bad_ip(self):
        self.trails["66.66.66.66"] = ("suspicious (dummy)", "ref")
        pkt = G.ipv4(17, "10.0.0.5", "66.66.66.66", G.udp(40000, 1900, b"\x00" * 8))
        sensor._process_packet(pkt, 1, 0, 0)
        ev = [e for e in self.events if self._type_of(e) == TRAIL.IP]
        self.assertEqual(len(ev), 1, self.events)
        self.assertEqual(self._trail_of(ev[0]), "66.66.66.66")

    def test_clean_traffic_silent(self):
        self.trails["evil.com"] = ("malware (dummy)", "ref")
        pkt = G.ipv4(6, "10.0.0.5", "1.1.1.1", G.tcp(50000, 443, 0x02, b""))
        sensor._process_packet(pkt, 1, 0, 0)
        self.assertEqual(self.events, [])

    def test_malformed_dns_no_crash_no_blind(self):
        # Truncated/garbage DNS on port 53 must be dropped as an EXPECTED struct.error (silent), never
        # reach the generic "unhandled exception" handler (which would mean the DNS path can crash and
        # a malformed-packet flood could blind the sensor). A real air-gapped failure mode.
        self.trails["evil.com"] = ("malware (dummy)", "ref")
        errors = []
        orig = sensor.log_error
        sensor.log_error = lambda *a, **k: errors.append(a)
        try:
            payloads = [
                struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0),                       # header claims 1 question, no body
                struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0) + b"\x04evil\x03com",  # QNAME truncated (no null, no QTYPE/QCLASS)
                struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0) + b"\x3f" + b"A" * 5,  # label length (63) overruns the buffer
                b"\x00\x01\x02",                                                          # shorter than a DNS header
            ]
            for p in payloads:
                pkt = G.ipv4(17, "10.0.0.5", "8.8.8.8", G.udp(40000, 53, p))
                sensor._process_packet(pkt, 1, 0, 0)                                      # must not raise
        finally:
            sensor.log_error = orig
        self.assertEqual(errors, [], "malformed DNS must NOT hit the unhandled-exception handler")
        self.assertEqual([e for e in self.events if self._type_of(e) == TRAIL.DNS], [], "no DNS event from garbage")

    def test_dns_response_empty_answer_section_no_crash(self):
        # A DNS RESPONSE (recursion-available/no-error) whose answer section is absent/truncated used to
        # hit an UnboundLocalError ('ptr') in the answer walk -- NOT caught by the inner IndexError
        # handler, so it surfaced as an "unhandled exception". Must be handled cleanly (no error log).
        errors = []
        orig = sensor.log_error
        sensor.log_error = lambda *a, **k: errors.append(a)
        try:
            sensor.config.USE_HEURISTICS = True
            hdr = struct.pack("!HHHHHH", 0x1234, 0x8080, 1, 1, 0, 0)     # response, an=1 claimed but absent
            q = b"\x04evil\x03com\x00" + struct.pack("!HH", 1, 1)
            pkt = G.ipv4(17, "8.8.8.8", "10.0.0.5", G.udp(53, 40000, hdr + q))   # src port 53 -> response
            sensor._process_packet(pkt, 1, 0, 0)                          # must not raise / log unhandled
        finally:
            sensor.log_error = orig
        self.assertEqual(errors, [], "empty-answer DNS response must not hit the unhandled-exception handler")

    def test_ipv4_with_options_header_length(self):
        # IPv4 header with options (IHL=6 -> 24-byte header). iph_length must be derived from IHL, else
        # the TCP header is read at the wrong offset and the SYN/bad-IP detection silently breaks.
        import socket as _s
        self.trails["66.66.66.66"] = ("badnet (dummy)", "ref")
        src, dst = _s.inet_aton("10.0.0.5"), _s.inet_aton("66.66.66.66")
        ip = struct.pack("!BBHHHBBH4s4s", 0x46, 0, 0, 0, 0, 64, 6, 0, src, dst) + b"\x00\x00\x00\x00"  # IHL=6 + 4 option bytes
        tcp = struct.pack("!HHLLBBHHH", 50000, 443, 0, 0, 0, 0x02, 0, 0, 0)                            # SYN
        sensor._process_packet(ip + tcp, 1, 0, 0)
        ip_ev = [e for e in self.events if self._type_of(e) == TRAIL.IP]
        self.assertEqual(len(ip_ev), 1, self.events)
        self.assertEqual(self._trail_of(ip_ev[0]), "66.66.66.66")

    def test_non_ip_offset_no_crash(self):
        # A misaligned offset (e.g. from the DLT heuristic) lands on a non-IP byte -> version 0.
        # Must drop cleanly, not KeyError on LOCALHOST_IP[ip_version] (which the outer handler
        # would log as an "unhandled exception").
        errors = []
        orig = sensor.log_error
        sensor.log_error = lambda *a, **k: errors.append(a)
        try:
            sensor._process_packet(b"\x00" * 64, 1, 0, 0)        # leading 0x00 -> ip_version 0
            sensor._process_packet(b"\x30" * 64, 1, 0, 0)        # version 3 -> also not IP
        finally:
            sensor.log_error = orig
        self.assertEqual(errors, [])
        self.assertEqual(self.events, [])


class TestHTTPDetection(_SensorTestBase):
    """HTTP request parsing / Host-based detection (a core detection path, previously untested).
    A plaintext HTTP request on port 80 is parsed for its request line + Host header."""
    REQ = b"GET /x HTTP/1.1\r\nHost: evil.com\r\n\r\n"

    def _http_pkt(self, payload, dst="66.66.66.66", sport=50000):
        return G.ipv4(6, "10.0.0.5", dst, G.tcp(sport, 80, 0x18, payload))   # PSH+ACK + HTTP payload

    def test_http_host_matches_bad_domain(self):
        # Host: evil.com where evil.com is a trail -> DNS-type detection on the Host value
        self.trails["evil.com"] = ("malware (dummy)", "ref")
        sensor._process_packet(self._http_pkt(self.REQ), 1, 0, 0)
        dns = [e for e in self.events if self._type_of(e) == TRAIL.DNS]
        self.assertTrue(any(self._trail_of(e) == "evil.com" for e in dns), self.events)

    def test_http_to_bad_dst_ip_annotates_host(self):
        # dst_ip is a bad IP trail and the request carries a Host -> IP event annotated with the host
        self.trails["66.66.66.66"] = ("badnet (dummy)", "ref")
        sensor._process_packet(self._http_pkt(self.REQ), 1, 0, 0)
        ip_ev = [e for e in self.events if self._type_of(e) == TRAIL.IP]
        self.assertEqual(len(ip_ev), 1, self.events)
        self.assertEqual(self._trail_of(ip_ev[0]), "66.66.66.66 (evil.com)")

    def test_http_missing_host_header_heuristic(self):
        # CHECK_MISSING_HOST: a request with no Host header is flagged (potential FP source, opt-in)
        sensor.config.USE_HEURISTICS = True
        sensor.config.CHECK_MISSING_HOST = True
        try:
            req = b"GET /admin.php HTTP/1.1\r\nAccept: */*\r\n\r\n"
            sensor._process_packet(self._http_pkt(req, sport=50001), 1, 0, 0)
        finally:
            sensor.config.CHECK_MISSING_HOST = False
        http = [e for e in self.events if self._type_of(e) == TRAIL.HTTP]
        self.assertTrue(any("missing host" in e[9] for e in http), self.events)
        self.assertTrue(any(self._trail_of(e) == "66.66.66.66/admin.php" for e in http), self.events)

    def test_http_clean_host_silent(self):
        # a clean Host to a clean dst produces no event
        self.trails["evil.com"] = ("malware (dummy)", "ref")
        req = b"GET / HTTP/1.1\r\nHost: good.example\r\n\r\n"
        sensor._process_packet(self._http_pkt(req, dst="1.1.1.1", sport=50002), 1, 0, 0)
        self.assertEqual(self.events, [])


class TestDNSExhaustion(_SensorTestBase):
    """DNS-exhaustion heuristic: many DISTINCT subdomains of one domain within the window -> one alert
    (potential DNS-based data exfil / tunneling). Threshold lowered here to keep the test small."""

    def setUp(self):
        _SensorTestBase.setUp(self)
        sensor.config.USE_HEURISTICS = True
        sensor._subdomains = {}
        sensor._subdomains_sec = None
        sensor._dns_exhausted_domains = set()
        self._orig_thr = sensor.DNS_EXHAUSTION_THRESHOLD
        sensor.DNS_EXHAUSTION_THRESHOLD = 3

    def tearDown(self):
        sensor.DNS_EXHAUSTION_THRESHOLD = self._orig_thr
        _SensorTestBase.tearDown(self)

    def _q(self, name, sec):
        pkt = G.ipv4(17, "10.0.0.5", "8.8.8.8", G.udp(40000, 53, _dns_query(name)))
        sensor._process_packet(pkt, sec, 0, 0)

    def test_exhaustion_fires_once_over_threshold(self):
        labels = ["alpha", "bravo", "charlie", "delta", "echo"]
        for i, lbl in enumerate(labels):
            self._q("%s.evil.com" % lbl, 100 + i)          # distinct subdomains, within the 60s window
        exh = [e for e in self.events if "dns exhaustion" in e[9]]
        self.assertEqual(len(exh), 1, "exactly one exhaustion alert past threshold (not one per query): %s" % self.events)

    def test_no_exhaustion_below_threshold(self):
        for i, lbl in enumerate(["one", "two"]):            # below threshold (3)
            self._q("%s.evil.com" % lbl, 100 + i)
        self.assertEqual([e for e in self.events if "dns exhaustion" in e[9]], [])


class TestICMPDetection(_SensorTestBase):
    """ICMP detection: only echo REQUESTS (type 0x08) to/from a bad IP are logged (proto ICMP)."""

    def test_icmp_echo_to_bad_ip(self):
        self.trails["66.66.66.66"] = ("badnet (dummy)", "ref")
        icmp = b"\x08\x00" + b"\x00" * 6                      # echo request
        sensor._process_packet(G.ipv4(1, "10.0.0.5", "66.66.66.66", icmp), 1, 0, 0)
        ev = [e for e in self.events if self._type_of(e) == TRAIL.IP]
        self.assertEqual(len(ev), 1, self.events)
        self.assertEqual(ev[0][6], PROTO.ICMP)
        self.assertEqual(self._trail_of(ev[0]), "66.66.66.66")

    def test_icmp_echo_reply_ignored(self):
        # a non-echo-request (e.g. echo reply, type 0x00) to a bad IP must NOT be logged
        self.trails["66.66.66.66"] = ("badnet (dummy)", "ref")
        icmp = b"\x00\x00" + b"\x00" * 6                      # echo reply
        sensor._process_packet(G.ipv4(1, "10.0.0.5", "66.66.66.66", icmp), 1, 0, 0)
        self.assertEqual(self.events, [])

    def test_icmp_clean_ip_silent(self):
        icmp = b"\x08\x00" + b"\x00" * 6
        sensor._process_packet(G.ipv4(1, "10.0.0.5", "1.1.1.1", icmp), 1, 0, 0)
        self.assertEqual(self.events, [])


class TestNXDomainCounterBounded(_SensorTestBase):
    """NO_SUCH_NAME_COUNTERS (NXDOMAIN/DGA heuristic) is hour-bucketed but was never pruned, so under DGA
    traffic (many unique failed domains) it grew without bound -> slow OOM on long-running sensors. Stale
    (previous-hour) entries must be dropped when a new-hour NXDOMAIN arrives."""

    def _nxdomain(self, name):
        hdr = struct.pack("!HHHHHH", 0x1234, 0x8083, 1, 0, 0, 0)   # DNS response, "no such name" (0x83)
        q = b""
        for lbl in name.split('.'):
            q += struct.pack("!B", len(lbl)) + lbl.encode()
        q += b"\x00" + struct.pack("!HH", 1, 1)
        # response: resolver -> NON-local client (203.0.113.5) so the counter path runs
        return G.ipv4(17, "8.8.8.8", "203.0.113.5", G.udp(53, 40000, hdr + q))

    def setUp(self):
        _SensorTestBase.setUp(self)
        sensor.config.USE_HEURISTICS = True
        sensor.NO_SUCH_NAME_COUNTERS.clear()
        sensor._no_such_name_hour = None
        sensor._dns_exhausted_domains = set()

    def test_stale_hour_entries_pruned(self):
        H1 = 3600
        for i in range(5):
            sensor._process_packet(self._nxdomain("dga%d.com" % i), H1 + i, 0, 0)   # distinct sec (same hour)
        self.assertEqual(len(sensor.NO_SUCH_NAME_COUNTERS), 5, sensor.NO_SUCH_NAME_COUNTERS)
        # a new-hour NXDOMAIN must prune ALL of the previous hour's entries
        sensor._process_packet(self._nxdomain("fresh.com"), 7200, 0, 0)
        keys = sorted(sensor.NO_SUCH_NAME_COUNTERS.keys())
        self.assertEqual(keys, ["fresh.com"], "previous-hour entries must be pruned (bounded memory)")


class TestWebScanHeuristicFP(_SensorTestBase):
    """The web-scanning heuristic must NOT fire on internal<->internal traffic (docker/proxy/monitoring
    routinely hit many paths on an internal host) but MUST still fire for external->internal scans."""

    def _run_sweep(self, pairs):
        # pairs: {(src,dst): n_distinct_paths}; populate the path-tracking state and trigger the
        # per-second sweep by processing a packet whose sec is past the last connect_sec.
        sensor.config.USE_HEURISTICS = True
        sensor._connect_sec = 0
        sensor._connect_src_dst = {}
        sensor._connect_src_details = {}
        sensor._path_src_dst = dict((k, set("p%d" % i for i in range(n))) for k, n in pairs.items())
        sensor._path_src_dst_details = dict((k, set([(1, 0, 1234, 80, "/x")])) for k in pairs)
        sensor._process_packet(b"\x00" * 8, 10, 0, 0)   # sec=10 > connect_sec=0 -> sweep runs
        return [e for e in self.events if self._type_of(e) == TRAIL.PATH]

    def test_internal_to_internal_suppressed(self):
        ev = self._run_sweep({("172.21.0.1", "172.21.0.4"): 11})   # both RFC1918 (docker)
        self.assertEqual(ev, [], "internal<->internal web-scan must be suppressed")

    def test_external_to_internal_flagged(self):
        # isolate the local guard from Maltrail's built-in WHITELIST_RANGES (which whitelists
        # public infra like 8.8.8.8) by neutralizing check_whitelisted for this case.
        orig = sensor.check_whitelisted
        sensor.check_whitelisted = lambda ip: False
        try:
            ev = self._run_sweep({("203.0.113.7", "172.21.0.4"): 11})   # external src -> local server
        finally:
            sensor.check_whitelisted = orig
        self.assertEqual(len(ev), 1, "external->internal web-scan must still fire")
        self.assertEqual(ev[0][4], "172.21.0.4")                        # dst_ip

    def test_whitelisted_source_suppressed(self):
        orig = sensor.check_whitelisted
        sensor.check_whitelisted = lambda ip: ip == "203.0.113.7"       # whitelist the external src
        try:
            ev = self._run_sweep({("203.0.113.7", "172.21.0.4"): 11})
        finally:
            sensor.check_whitelisted = orig
        self.assertEqual(ev, [], "whitelisted source must be suppressed")


class TestScanHeuristicsSoundness(_SensorTestBase):
    """Logic soundness of the SYN-based scan heuristics (port scan / infection), independent of the
    local-traffic FP guards."""

    def _sweep(self):
        sensor.config.USE_HEURISTICS = True
        sensor._connect_sec = 0
        sensor._path_src_dst = {}
        sensor._path_src_dst_details = {}
        sensor._process_packet(b"\x00" * 8, 10, 0, 0)   # sec=10 > connect_sec -> sweep

    def test_infection_fires_despite_retry_duplicate(self):
        # 40 distinct dst IPs on an infection port + one retry (duplicate dst). The old
        # len(list)==len(set) gate suppressed the whole detection on that single duplicate.
        src, port = "10.0.0.5", 445
        dsts = ["10.9.9.%d" % i for i in range(40)]
        sensor._connect_src_dst = {(src, port): set(dsts)}
        details = set((1, 0, 30000 + i, d) for i, d in enumerate(dsts))
        details.add((2, 0, 55555, dsts[0]))             # retry to an already-seen dst
        sensor._connect_src_details = {(src, port): details}
        orig = sensor._get_local_prefix
        sensor._get_local_prefix = lambda: "10.0.0."
        try:
            self._sweep()
        finally:
            sensor._get_local_prefix = orig
        ev = [e for e in self.events if self._type_of(e) == TRAIL.PORT]
        self.assertEqual(len(ev), 1, "infection must fire despite a retry duplicate dst")
        self.assertEqual(ev[0][5], port)                # dst_port

    def test_port_scan_logs_once_not_per_port(self):
        src, dst = "203.0.113.9", "10.0.0.4"            # external scanner (not whitelisted) -> local
        ports = list(range(1000, 1050))                 # 50 ports -> old code emitted 50 events
        sensor._connect_src_dst = {(src, dst): set(ports)}
        sensor._connect_src_details = {(src, dst): set((1, 0, 40000 + i, p) for i, p in enumerate(ports))}
        self._sweep()
        ev = [e for e in self.events if self._type_of(e) == TRAIL.IP and e[8] == src]
        self.assertEqual(len(ev), 1, "port scan must log once per (scanner,target), not per port")

    def test_port_scan_internal_recon_is_detected(self):
        # internal->internal port scan = lateral recon, a real TP. Must NOT be locality-suppressed
        # (the lab showed a both-local guard silently kills it). Mute via DISABLED_HEURISTICS instead.
        src, dst = "172.21.0.1", "172.21.0.4"           # both RFC1918 (internal recon)
        ports = list(range(1000, 1050))
        sensor._connect_src_dst = {(src, dst): set(ports)}
        sensor._connect_src_details = {(src, dst): set((1, 0, 40000 + i, p) for i, p in enumerate(ports))}
        self._sweep()
        ev = [e for e in self.events if self._type_of(e) == TRAIL.IP and e[8] == src]
        self.assertEqual(len(ev), 1, "internal recon (lateral port scan) must be detected")


class TestSrcHashAffinity(unittest.TestCase):
    """_src_hash underpins source-affinity routing: same source IP -> same value (whole scan lands
    on one worker); different sources spread across workers (load balance)."""

    def setUp(self):
        sys.argv = ["x"]
        import sensor
        self.sensor = sensor

    def _pkt(self, src):
        return G.eth() + G.ipv4(6, src, "8.8.8.8", G.tcp(40000, 80, 0x02, b""))

    def test_deterministic_same_source(self):
        a = self.sensor._src_hash(self._pkt("203.0.113.9"), 14)
        b = self.sensor._src_hash(self._pkt("203.0.113.9"), 14)
        self.assertEqual(a, b)

    def test_distinct_sources_spread(self):
        # across many sources, routing to (hash % 15) workers should hit most lanes (no degenerate
        # collapse to one worker)
        lanes = set(self.sensor._src_hash(self._pkt("10.0.%d.%d" % (i // 256, i % 256)), 14) % 15
                    for i in range(300))
        self.assertGreaterEqual(len(lanes), 12)

    def test_non_ip_safe(self):
        self.assertEqual(self.sensor._src_hash(b"\x00" * 8, 14), 0)


class TestDisabledHeuristics(_SensorTestBase):
    """DISABLED_HEURISTICS mutes a named heuristic without disabling USE_HEURISTICS wholesale."""

    def test_mute_port_scanning(self):
        sensor.config.DISABLED_HEURISTICS = "port_scanning, dns_exhaustion"
        sensor._disabled_heuristics_cache[0] = None
        self.assertFalse(sensor._heuristic_enabled("port_scanning"))
        self.assertFalse(sensor._heuristic_enabled("dns_exhaustion"))
        self.assertTrue(sensor._heuristic_enabled("web_scanning"))      # the valuable one stays on

    def test_default_all_enabled(self):
        self.assertTrue(sensor._heuristic_enabled("port_scanning"))
        self.assertTrue(sensor._heuristic_enabled("web_scanning"))

    def test_muted_port_scan_emits_nothing(self):
        sensor.config.USE_HEURISTICS = True
        sensor.config.DISABLED_HEURISTICS = "port_scanning"
        sensor._disabled_heuristics_cache[0] = None
        sensor._connect_sec = 0
        sensor._path_src_dst = {}
        sensor._path_src_dst_details = {}
        src, dst = "203.0.113.9", "10.0.0.4"
        ports = list(range(1000, 1050))
        sensor._connect_src_dst = {(src, dst): set(ports)}
        sensor._connect_src_details = {(src, dst): set((1, 0, 40000 + i, p) for i, p in enumerate(ports))}
        sensor._process_packet(b"\x00" * 8, 10, 0, 0)
        self.assertEqual([e for e in self.events if self._type_of(e) == TRAIL.IP], [])


class TestSlidingWindowAndStealth(_SensorTestBase):
    """The sliding window (slow scans no longer evade the old ~1s clear) and stealth-scan coverage
    (NULL/FIN/XMAS), driven through the real _process_packet over simulated time."""

    EXT_SRC = "203.0.113.9"      # non-whitelisted external scanner
    EXT_DST = "198.51.100.7"

    def _feed_scan(self, n_ports, flags, step=1.0):
        """Feed n_ports probes (one per port) at `step` seconds apart, then a tick to flush."""
        sensor.config.USE_HEURISTICS = True
        for i in range(n_ports):
            pkt = G.eth() + G.ipv4(6, self.EXT_SRC, self.EXT_DST, G.tcp(40000 + i, 1000 + i, flags, b""))
            sensor._process_packet(pkt, int(i * step), 0, 14)
        # flush tick (UDP) a couple seconds after the last probe -> triggers the final sweep
        tick = G.eth() + G.ipv4(17, self.EXT_SRC, "192.0.2.2", G.udp(1, 2, b"\x00" * 8))
        sensor._process_packet(tick, int(n_ports * step) + 2, 0, 14)
        return [e for e in self.events if self._type_of(e) == TRAIL.IP and e[8] == self.EXT_SRC]

    def test_slow_syn_scan_detected(self):
        # 20 ports, one per second over 20s -> never >10 in any single second, but the sliding
        # window accumulates them. (Old ~1s clear would have MISSED this entirely.)
        ev = self._feed_scan(20, 0x02, step=1.0)
        self.assertEqual(len(ev), 1, "slow SYN scan must be detected by the sliding window")

    def test_alerts_once_per_window_not_per_second(self):
        # a 20s scan must produce exactly ONE event, not one per second of the window
        ev = self._feed_scan(20, 0x02, step=1.0)
        self.assertEqual(len(ev), 1, "must alert once per window, not flood per second")

    def test_stealth_fin_null_xmas_detected(self):
        for flags, name in ((0x01, "FIN"), (0x00, "NULL"), (0x29, "XMAS")):
            self.setUp()
            ev = self._feed_scan(20, flags, step=0.01)
            self.assertEqual(len(ev), 1, "stealth %s scan must be detected" % name)

    def test_ack_scan_not_flagged(self):
        # bare ACK is normal mid-connection traffic -> must NOT be treated as a scan (FP guard)
        ev = self._feed_scan(20, 0x10, step=0.01)
        self.assertEqual(ev, [], "ACK must not be flagged as a scan (would be an FP cannon)")

    def test_udp_scan_detected(self):
        sensor.config.USE_HEURISTICS = True
        for i in range(20):                                  # 20 UDP ports, one host, 1/sec (slow)
            pkt = G.eth() + G.ipv4(17, self.EXT_SRC, self.EXT_DST, G.udp(40000 + i, 1000 + i, b"\x00" * 8))
            sensor._process_packet(pkt, i, 0, 14)
        tick = G.eth() + G.ipv4(17, self.EXT_SRC, "192.0.2.2", G.udp(1, 2, b"\x00" * 8))
        sensor._process_packet(tick, 25, 0, 14)
        ev = [e for e in self.events if self._type_of(e) == TRAIL.IP and e[6] == PROTO.UDP and e[8] == self.EXT_SRC]
        self.assertEqual(len(ev), 1, "UDP scan (nmap -sU) must be detected")

    def test_udp_benign_no_fp(self):
        # QUIC-like: one UDP port (443) to many hosts -> each key has 1 port -> must stay CLEAN
        sensor.config.USE_HEURISTICS = True
        for i in range(40):
            pkt = G.eth() + G.ipv4(17, self.EXT_SRC, "198.51.100.%d" % (i % 50), G.udp(40000, 443, b"\x00" * 8))
            sensor._process_packet(pkt, 0, 0, 14)
        tick = G.eth() + G.ipv4(17, self.EXT_SRC, "192.0.2.2", G.udp(1, 2, b"\x00" * 8))
        sensor._process_packet(tick, 25, 0, 14)
        self.assertEqual([e for e in self.events if self._type_of(e) == TRAIL.IP], [], "benign UDP must not FP")


class TestScanTrackMemoryBound(unittest.TestCase):
    def setUp(self):
        sys.argv = ["x"]
        import sensor
        self.sensor = sensor

    def test_per_key_and_total_caps(self):
        store, details = {}, {}
        for p in range(self.sensor._SCAN_TRACK_PER_KEY * 4):
            self.sensor._scan_track(store, details, ("1.2.3.4", "5.6.7.8"), p, (0, 0, p, p))
        self.assertLessEqual(len(store[("1.2.3.4", "5.6.7.8")]), self.sensor._SCAN_TRACK_PER_KEY)
        store2, details2 = {}, {}
        for i in range(self.sensor._SCAN_MAX_KEYS + 5000):
            self.sensor._scan_track(store2, details2, ("k", i), 80, (0, 0, 80, 80))
        self.assertLessEqual(len(store2), self.sensor._SCAN_MAX_KEYS)


class TestIPv6AndFragment(_SensorTestBase):
    """Detection on IPv6 traffic and correct handling of IPv4 fragments (must not crash / must skip
    non-first fragments, which lack transport headers)."""

    def test_ipv6_syn_to_bad_ip(self):
        self.trails["dead::beef"] = ("badnet (dummy)", "ref")
        pkt = G.ipv6(6, "dead::1", "dead::beef", G.tcp(50000, 443, 0x02, b""))   # IPv6 SYN
        sensor._process_packet(pkt, 1, 0, 0)
        ev = [e for e in self.events if self._type_of(e) == TRAIL.IP]
        self.assertEqual(len(ev), 1, self.events)
        self.assertEqual(self._trail_of(ev[0]), "dead::beef")

    def test_ipv6_dns_to_bad_domain(self):
        self.trails["evil.com"] = ("malware (dummy)", "ref")
        dns = _dns_query("evil.com")
        pkt = G.ipv6(17, "dead::1", "dead::2", G.udp(40000, 53, dns))
        sensor._process_packet(pkt, 1, 0, 0)
        self.assertTrue(any(self._type_of(e) == TRAIL.DNS and self._trail_of(e) == "evil.com" for e in self.events), self.events)

    def test_fragment_skipped_no_crash(self):
        # a non-first IPv4 fragment has a nonzero fragment offset and NO transport header -> must be
        # skipped cleanly (parsing its "ports" would read garbage). Set the frag-offset field.
        self.trails["66.66.66.66"] = ("badnet (dummy)", "ref")
        pkt = bytearray(G.ipv4(6, "10.0.0.5", "66.66.66.66", G.tcp(50000, 443, 0x02, b"")))
        pkt[6:8] = struct.pack("!H", 0x0001)   # fragment_offset = 1 (non-first fragment)
        errors = []
        orig = sensor.log_error; sensor.log_error = lambda *a, **k: errors.append(a)
        try:
            sensor._process_packet(bytes(pkt), 1, 0, 0)
        finally:
            sensor.log_error = orig
        self.assertEqual(self.events, [], "non-first fragment must not produce detections")
        self.assertEqual(errors, [], "fragment handling must not raise/log an error")


class TestDLTLearner(unittest.TestCase):
    def setUp(self):
        sensor._dlt_learn.clear()

    def test_locks_after_two_agreeing(self):
        pkt = G.eth() + G.ipv4(17, "10.0.0.5", "8.8.8.8", G.udp(1, 53, b"\x00" * 8))
        UNKNOWN = 9999
        self.assertEqual(sensor._guess_dlt_ip_offset(UNKNOWN, pkt), 14)   # provisional
        self.assertNotIn(UNKNOWN, [k for k in sensor._dlt_learn if isinstance(k, int)])
        self.assertEqual(sensor._guess_dlt_ip_offset(UNKNOWN, pkt), 14)   # second agreement locks
        self.assertEqual(sensor._dlt_learn.get(UNKNOWN), 14)
        self.assertEqual(sensor._guess_dlt_ip_offset(UNKNOWN, pkt), 14)   # served from cache

    def test_non_ip_returns_none(self):
        self.assertIsNone(sensor._guess_dlt_ip_offset(8888, b"\x00" * 60))


if __name__ == "__main__":
    unittest.main()
