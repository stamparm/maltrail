#!/usr/bin/env python3
# coding: utf-8

"""Generate real, varied, adversarial traffic to shadow-test the sensors (ROADMAP Gate 2.3).

A corpus proves the sensors agree on traffic somebody thought to synthesize. This produces
traffic from real client stacks — the kernel's TCP, a real resolver, real HTTP framing — driven
by indicators sampled from the operator's ACTUAL trails.csv, so the comparison covers packets
nobody hand-wrote.

    python3 sensor/tools/adversarial_traffic.py --seconds 600
    python3 sensor/tools/adversarial_traffic.py --seconds 60 --no-dns   # fully local

OUTBOUND CONTACT. By default this exercises IP and IP:port trails for real: a TCP connect with a
short timeout, which puts a SYN on the wire and nothing else. No payload is ever sent, so this is
what any port scanner does to a host that is almost certainly long dead. Authorised deliberately
by the operator — it is their network and their sensor. `--safe` restores the conservative mode:

  * DNS trails are exercised by RESOLVING the name. A lookup, not contact, and the single most
    common Maltrail detection. Suppress with --no-dns.
  * HTTP host / URL / path / user-agent trails go to a LOCAL listener started by this script.
    Maltrail reads those from the request bytes, so detection is identical with no packet leaving
    the host — worth keeping local even in the permissive mode, since the payloads are exploit
    strings and sending those anywhere real would be an actual attack.
  * IP and IP:port trails are dialled unless --safe is given.
  * Scan / DGA / NXDOMAIN heuristics run against localhost and the reserved .invalid TLD.

Run it while capturing; the sensor is measured on the capture afterwards.
"""

import argparse
import http.server
import os
import random
import socket
import string
import sys
import threading
import time

ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))

# Trails whose reference marks them as coming from a feed the operator actually loaded.
WANT_KINDS = ("dns_domain", "http_host", "url_path", "host_path", "user_agent")


def _is_ipv4(text):
    parts = text.split('.')
    if len(parts) != 4:
        return False
    for part in parts:
        if not part.isdigit() or not 0 <= int(part) <= 255:
            return False
    return True


def classify(trail):
    """Which exercise, if any, a trail row can drive."""
    if '/' in trail:
        head = trail.split('/')[0]
        if head and not head[0].isdigit() and '.' in head:
            return "host_path"
        if trail.startswith('/'):
            return "url_path"
        return None
    if ':' in trail:
        addr, _, port = trail.rpartition(':')
        if _is_ipv4(addr) and port.isdigit() and 0 < int(port) < 65536:
            return "ipv4_port"
        return None                      # IPv6, or something else entirely
    if _is_ipv4(trail):
        return "ipv4"
    if '.' in trail and ' ' not in trail:
        return "dns_domain"
    return None


def sample_trails(path, per_kind, rng):
    """Reservoir-sample real trails of each usable kind, one streaming pass."""
    picked = dict((k, []) for k in ("dns_domain", "host_path", "url_path", "ipv4", "ipv4_port"))
    seen = dict((k, 0) for k in picked)
    if not os.path.isfile(path):
        return picked
    with open(path, "r", errors="replace") as f:
        for line in f:
            trail = line.split(',', 1)[0].strip().strip('"')
            if not trail or len(trail) > 180:
                continue
            kind = classify(trail)
            if kind not in picked:
                continue
            seen[kind] += 1
            if len(picked[kind]) < per_kind:
                picked[kind].append(trail)
            else:
                j = rng.randrange(seen[kind])
                if j < per_kind:
                    picked[kind][j] = trail
    return picked


class QuietHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *_args):
        pass


def start_local_http():
    server = http.server.HTTPServer(("127.0.0.1", 0), QuietHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def http_request(port, host_header, path, user_agent):
    """One real HTTP request to the local listener, carrying the indicator in its headers."""
    try:
        s = socket.create_connection(("127.0.0.1", port), timeout=2)
        request = "GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\nConnection: close\r\n\r\n" % (
            path, host_header, user_agent)
        s.sendall(request.encode("utf-8", "replace"))
        s.recv(256)
        s.close()
        return True
    except Exception:
        return False


def resolve(name, timeout=1.0):
    """A real DNS query through the system resolver. Failure is fine — the query is the point."""
    try:
        socket.setdefaulttimeout(timeout)
        socket.getaddrinfo(name, None)
    except Exception:
        pass


def random_label(rng, n):
    return ''.join(rng.choice(string.ascii_lowercase + string.digits) for _ in range(n))


def tcp_connect(host, port, timeout=0.15):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect_ex((host, port))
        s.close()
    except Exception:
        pass


def udp_probe(host, port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(0.05)
        s.sendto(b"\x00" * 8, (host, port))
        s.close()
    except Exception:
        pass


def main():
    parser = argparse.ArgumentParser(description="adversarial traffic generator for shadow testing")
    parser.add_argument("--seconds", type=int, default=300, help="how long to run (default 300)")
    parser.add_argument("--trails", default=os.path.expanduser("~/.maltrail/trails.csv"))
    parser.add_argument("--per-kind", type=int, default=400, help="trails sampled per kind")
    parser.add_argument("--seed", type=int, default=1337, help="deterministic trail selection")
    parser.add_argument("--no-dns", action="store_true", help="skip all real DNS resolution")
    parser.add_argument("--safe", action="store_true",
                        help="do not dial IP / IP:port trails (SYN only, no payload, otherwise)")
    parser.add_argument("--connect-timeout", type=float, default=0.25,
                        help="how long to wait on an outbound SYN (default 0.25s; these hosts are mostly dead)")
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args()

    rng = random.Random(args.seed)
    trails = sample_trails(args.trails, args.per_kind, rng)
    say = (lambda *a: None) if args.quiet else (lambda *a: print(*a, flush=True))

    say("[i] sampled from %s:" % args.trails)
    for kind, items in sorted(trails.items()):
        say("[i]   %-12s %d" % (kind, len(items)))
    if not any(trails.values()):
        say("[!] no usable trails found — is trails.csv present?")

    if not args.safe:
        say("[i] IP/IP:port trails WILL be dialled: one SYN each, %.2fs timeout, no payload" % args.connect_timeout)
    else:
        say("[i] --safe: no outbound connections to trail addresses")

    server = start_local_http()
    port = server.server_address[1]
    say("[i] local HTTP listener on 127.0.0.1:%d (malicious hosts/paths/UAs go here, never outbound)" % port)
    if args.no_dns:
        say("[i] DNS resolution disabled")

    bad_uas = [
        "sqlmap/1.7", "Mozilla/5.0 zgrab/0.x", "masscan/1.3", "python-requests/2.31",
        "curl/7.88.1", "Wget/1.21", "CobaltStrike", "() { :;}; /bin/bash",
    ]
    stats = dict(dns=0, http=0, scan=0, dga=0, benign=0, ipdial=0)
    deadline = time.time() + args.seconds
    tick = 0

    while time.time() < deadline:
        tick += 1
        roll = rng.random()

        # --- known-bad DNS names: the most common detection Maltrail makes -----------------
        if roll < 0.34 and trails["dns_domain"] and not args.no_dns:
            name = rng.choice(trails["dns_domain"])
            resolve(name)
            stats["dns"] += 1

        # --- malicious HTTP host / path / user agent, all to the local listener -----------
        elif roll < 0.62:
            host = rng.choice(trails["dns_domain"]) if trails["dns_domain"] else "example.com"
            path = "/"
            if trails["host_path"] and rng.random() < 0.5:
                hp = rng.choice(trails["host_path"])
                host, _, tail = hp.partition('/')
                path = "/" + tail
            elif trails["url_path"] and rng.random() < 0.5:
                path = rng.choice(trails["url_path"])
            ua = rng.choice(bad_uas) if rng.random() < 0.4 else "Mozilla/5.0 (X11; Linux x86_64)"
            http_request(port, host, path, ua)
            stats["http"] += 1

        # --- real IP / IP:port trails: one SYN, no payload --------------------------------
        elif roll < 0.72 and not args.safe and (trails["ipv4"] or trails["ipv4_port"]):
            if trails["ipv4_port"] and rng.random() < 0.5:
                addr, _, port = rng.choice(trails["ipv4_port"]).rpartition(':')
                tcp_connect(addr, int(port), args.connect_timeout)
            elif trails["ipv4"]:
                # Ports Maltrail's default CAPTURE_FILTER actually watches.
                tcp_connect(rng.choice(trails["ipv4"]), rng.choice([80, 443, 8080, 8000, 3128]),
                            args.connect_timeout)
            stats["ipdial"] += 1

        # --- scanning heuristics: many ports, one source, against localhost ---------------
        elif roll < 0.80:
            base = rng.randrange(1, 60000)
            for i in range(rng.randrange(12, 30)):
                tcp_connect("127.0.0.1", (base + i * rng.randrange(1, 7)) % 65535 or 1)
            for i in range(rng.randrange(5, 15)):
                udp_probe("127.0.0.1", (base + i) % 65535 or 1)
            stats["scan"] += 1

        # --- DGA / NXDOMAIN bursts, in the reserved .invalid TLD --------------------------
        elif roll < 0.90:
            if not args.no_dns:
                for _ in range(rng.randrange(4, 12)):
                    resolve("%s.%s.invalid" % (random_label(rng, rng.randrange(8, 24)), random_label(rng, 6)), 0.4)
            stats["dga"] += 1

        # --- benign background, so a false positive has somewhere to show up --------------
        else:
            http_request(port, "www.example.com", "/index.html", "Mozilla/5.0 (X11; Linux x86_64)")
            if not args.no_dns:
                resolve(rng.choice(["localhost", "example.com", "www.google.com", "github.com"]))
            stats["benign"] += 1

        if tick % 100 == 0:
            say("[i] %ds left — %s" % (int(deadline - time.time()),
                                       ', '.join("%s=%d" % kv for kv in sorted(stats.items()))))
        time.sleep(rng.uniform(0.0, 0.05))

    server.shutdown()
    say("[i] done: %s" % ', '.join("%s=%d" % kv for kv in sorted(stats.items())))
    return 0


if __name__ == "__main__":
    sys.exit(main())
