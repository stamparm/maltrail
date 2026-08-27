#!/usr/bin/env python

"""
Copyright (c) 2014-2026 Maltrail developers (https://github.com/stamparm/maltrail/)
See the file 'LICENSE' for copying permission

`server.py --doctor`: validate a deployment BEFORE the events matter.

The sensor got `-T/--test-config` for exactly this reason (docs/COMPATIBILITY.md #17): the only
way to learn that LOG_DIR is unwritable or the trails file is months old used to be to start
capturing and watch. A server has the same failure modes - plus its own: the reporting port taken
by another process, an empty USERS table nobody can log into, an intake address the dashboard can
never reach. Every finding here is something that otherwise surfaces as a silent half-working
server hours or days after the operator walked away.

Usage: server.py --doctor [-c maltrail.conf]. Exits 0 when healthy, 1 when any [x] problem was
found; [!] warnings do not change the exit code.
"""

import os
import shutil
import socket
import sys
import time

from core.settings import config

OK = 0
WARN = 1
FAIL = 2


def _free_bytes(path):
    try:
        return shutil.disk_usage(path).free
    except OSError:
        return None


def check_log_dir():
    """Exists, writable, and enough headroom for daily event logs."""
    findings = []
    path = config.LOG_DIR
    if not os.path.isdir(path):
        return [(FAIL, "LOG_DIR '%s' does not exist%s" % (path, "" if os.path.exists(os.path.dirname(path)) else " (and neither does its parent)"))]
    if not os.access(path, os.W_OK):
        findings.append((FAIL, "LOG_DIR '%s' is not writable by the current user" % path))
    free = _free_bytes(path)
    if free is not None:
        gb = free / (1024 ** 3)
        if gb < 0.1:
            findings.append((FAIL, "LOG_DIR '%s' has %.0f MiB free - event logs will be truncated mid-write" % (path, free / (1024 ** 2))))
        elif gb < 1:
            findings.append((WARN, "LOG_DIR '%s' has less than 1 GiB free (%.0f MiB)" % (path, free / (1024 ** 2))))
    return findings


def check_trails_freshness():
    """A stale trails.csv looks perfectly healthy while quietly missing every new IOC."""
    path = config.TRAILS_FILE
    if not os.path.isfile(path):
        return [(FAIL, "trails file '%s' does not exist (run once online, or 'python3 sensor/tools/update_trails.py')" % path)]
    age_days = (time.time() - os.path.getmtime(path)) / 86400.0
    period = int(config.UPDATE_PERIOD or 0)
    if period <= 0 or age_days * 86400 <= 4 * period:
        return []
    message = "trails file '%s' is %s old (UPDATE_PERIOD %s s) - detections stop at IOCs published since then" % (path, _human_age(age_days), period)
    if config.DISABLE_TRAIL_UPDATES:
        message += " (DISABLE_TRAIL_UPDATES is on - intentional?)"
    return [(WARN, message)]


def check_users():
    """An empty USERS array means a running server nobody can log into."""
    users = config.USERS or []
    if not users:
        return [(FAIL, "USERS table is empty - the web UI will reject every login")]
    return [(OK, "%d user account(s) configured" % len(users))]


def check_ssl_pem():
    """Same refusal as startup: a PEM that does not exist, or the one published key, protects nothing."""
    if not config.USE_SSL:
        return []
    from core.common import uses_published_key
    pem = config.SSL_PEM
    hint = "openssl req -new -x509 -keyout %s -out %s -days 365 -nodes -subj '/O=Maltrail CA/C=EU'" % (pem or "server.pem", pem or "server.pem")
    if not pem or not os.path.isfile(pem):
        return [(FAIL, "USE_SSL is on but SSL_PEM ('%s') is missing\n[?] (hint: \"%s\")" % (pem, hint))]
    if uses_published_key(pem):
        return [(FAIL, "SSL_PEM ('%s') is the public key shipped in misc/server.pem - TLS with it protects nothing\n[?] (hint: \"%s\")" % (pem, hint))]
    return [(OK, "SSL_PEM '%s' present and not a known-public key" % pem)]


def _port_free(kind, family, address, port):
    """True when a listening socket can still be bound to address:port (the usual port-taken diagnosis)."""
    try:
        s = socket.socket(family, kind)
        try:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((address, port))
            return None
        finally:
            s.close()
    except OSError as ex:
        if ex.errno == 13:  # EACCES: privileged port, or a sandbox - not "in use"
            return "binding port %d requires privileges (or is blocked here)" % port
        return "%s endpoint %s:%d is not bindable (%s) - is another instance running?" % (kind, address, port, ex.strerror or str(ex))


def check_http_endpoint():
    if config.HTTP_ADDRESS in (None, "0.0.0.0"):
        family = socket.AF_INET
    elif ":" in str(config.HTTP_ADDRESS):
        family = socket.AF_INET6
    else:
        family = socket.AF_INET
    problem = _port_free(socket.SOCK_STREAM, family, str(config.HTTP_ADDRESS or "0.0.0.0"), int(config.HTTP_PORT or 0))
    return [] if problem is None else [(WARN, problem)]


def check_udp_intake():
    """The sensor ships events to UDP_ADDRESS:UDP_PORT - if nothing can bind there, the dashboard stays empty."""
    if not (config.UDP_ADDRESS and config.UDP_PORT):
        return []
    family = socket.AF_INET6 if ":" in str(config.UDP_ADDRESS) else socket.AF_INET
    problem = _port_free(socket.SOCK_DGRAM, family, str(config.UDP_ADDRESS), int(config.UDP_PORT))
    return [] if problem is None else [(WARN, problem)]


def check_update_reachability():
    """Only a TCP connect, not a fetch: answers 'will tonight's update work' without downloading anything."""
    if not config.USE_SERVER_UPDATE_TRAILS:
        return []
    host = "www.github.com"
    try:
        s = socket.create_connection((host, 443), timeout=5)
        s.close()
    except OSError as ex:
        return [(WARN, "update source %s:443 unreachable (%s) - trail updates will fall back to offline mode" % (host, ex.strerror or str(ex)))]
    return []


def check_static_trails():
    """Is there a source for the static trail set at all?

    Matching known-bad infrastructure is the point of Maltrail, and the static set is the large
    majority of what it matches on. A deployment without a source for it starts, serves a
    dashboard, reports healthy and detects a fraction of what the operator thinks it does - so this
    is a FAILURE, not a warning.
    """

    if config.STATIC_TRAILS_URL:
        return []

    cache = "%s.static" % config.TRAILS_FILE
    hint = "https://github.com/stamparm/trails/releases/latest/download/trails.csv.gz"

    if os.path.isfile(cache):
        return [(WARN, "'STATIC_TRAILS_URL' is not set - running on the cached static trails at '%s', which will never be refreshed\n[?] (hint: \"STATIC_TRAILS_URL %s\")" % (cache, hint))]

    return [(FAIL, "'STATIC_TRAILS_URL' is not set and there is no cache - the static trail set will not be loaded and detection is a fraction of what it should be\n[?] (hint: \"STATIC_TRAILS_URL %s\")" % hint)]


CHECKS = (
    ("log directory", check_log_dir),
    ("static trail source", check_static_trails),
    ("trails freshness", check_trails_freshness),
    ("USERS table", check_users),
    ("TLS certificate", check_ssl_pem),
    ("reporting endpoint", check_http_endpoint),
    ("event intake (UDP)", check_udp_intake),
    ("feed reachability", check_update_reachability),
)


def run(out=sys.stdout):
    """Run every check; print findings; return the process exit code."""
    print("[i] diagnosing configuration for the web server (sensor equivalent: 'maltrail-sensor -T')\n", file=out)
    failures = 0
    warnings = 0
    for label, check in CHECKS:
        findings = check()
        if not findings:
            print("[i] %-20s ok" % label, file=out)
            continue
        worst = max(level for level, _ in findings)
        failures += 1 if worst == FAIL else 0
        warnings += 1 if worst == WARN else 0
        for level, message in findings:
            prefix = {OK: "[i]", WARN: "[!]", FAIL: "[x]"}[level]
            print("%s %-20s %s" % (prefix, label, message), file=out)
    print(file=out)
    if failures:
        print("[x] %d problem(s), %d warning(s) found" % (failures, warnings), file=out)
    else:
        print("[i] no problems found%s" % (", %d warning(s)" % warnings if warnings else ""), file=out)
    return 1 if failures else 0


def _human_age(days):
    if days >= 365:
        return "%.1f years" % (days / 365.0)
    if days >= 1:
        return "%.0f days" % days
    return "%.0f hours" % (days * 24)
