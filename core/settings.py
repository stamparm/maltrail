#!/usr/bin/env python

"""
Copyright (c) 2014-2016 Miroslav Stampar (@stamparm)
See the file 'LICENSE' for copying permission
"""

import os
import re
import socket
import stat
import subprocess
import sys

from core.addr import addr_to_int
from core.addr import make_mask
from core.attribdict import AttribDict
from core.trailsdict import TrailsDict

config = AttribDict()
trails = TrailsDict()

NAME = "Maltrail"
VERSION = "0.9.19"
SERVER_HEADER = "%s/%s" % (NAME, VERSION)
DATE_FORMAT = "%Y-%m-%d"
ROTATING_CHARS = ('\\', '|', '|', '/', '-')
TIMEOUT = 30
FRESH_IPCAT_DELTA_DAYS = 10
USERS_DIR = os.path.join(os.path.expanduser("~"), ".%s" % NAME.lower())
TRAILS_FILE = os.path.join(USERS_DIR, "trails.csv")
IPCAT_CSV_FILE = os.path.join(USERS_DIR, "ipcat.csv")
IPCAT_SQLITE_FILE = os.path.join(USERS_DIR, "ipcat.sqlite")
IPCAT_URL = "https://raw.githubusercontent.com/client9/ipcat/master/datacenters.csv"
TIME_FORMAT = "%Y-%m-%d %H:%M:%S"
HTTP_DEFAULT_PORT = 8338
HTTP_TIME_FORMAT = "%a, %d %b %Y %H:%M:%S GMT"  # Reference: http://stackoverflow.com/a/225106
SESSION_COOKIE_NAME = "%s_sessid" % NAME.lower()
SNAP_LEN = 2000
BLOCK_LENGTH = 1 + 2 + 4 + 4 + SNAP_LEN  # primitive mutex + short for packet size + int for sec + int for usec + max packet size
SHORT_SENSOR_SLEEP_TIME = 0.00001
REGULAR_SENSOR_SLEEP_TIME = 0.001
LOAD_TRAILS_RETRY_SLEEP_TIME = 60
UNAUTHORIZED_SLEEP_TIME = 5
NO_SUCH_NAME_PER_HOUR_THRESHOLD = 20
CHECK_MEMORY_SIZE = 384 * 1024 * 1024
NO_BLOCK = -1
END_BLOCK = -2
ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
HTML_DIR = os.path.join(ROOT_DIR, "html")
DISPOSED_NONCES = set()
PING_RESPONSE = "pong"
MAX_NOFILE = 65000
CAPTURE_TIMEOUT = 100  # ms
CONFIG_FILE = os.path.join(ROOT_DIR, "maltrail.conf")
SYSTEM_LOG_DIR = "/var/log" if not subprocess.mswindows else "C:\\Windows\\Logs"
DEFAULT_EVENT_LOG_PERMISSIONS = stat.S_IREAD | stat.S_IWRITE | stat.S_IRGRP | stat.S_IROTH
DEFAULT_ERROR_LOG_PERMISSIONS = stat.S_IREAD | stat.S_IWRITE | stat.S_IRGRP | stat.S_IWGRP | stat.S_IROTH | stat.S_IWOTH
HOSTNAME = socket.gethostname()
DISABLED_CONTENT_EXTENSIONS = (".py", ".pyc", ".md", ".txt", ".bak", ".conf", ".zip", "~")
CONTENT_EXTENSIONS_EXCLUSIONS = ("robots.txt",)
LOW_PRIORITY_INFO_KEYWORDS = ("reputation", "attacker", "spammer", "abuser", "malicious", "dnspod", "nicru", "crawler", "compromised")
HIGH_PRIORITY_INFO_KEYWORDS = ("mass scanner",)
HIGH_PRIORITY_REFERENCES = ("bambenekconsulting.com", "(custom)",)
BAD_TRAIL_PREFIXES = ("127.", "192.168.", "localhost")
LOCALHOST_IP = "127.0.0.1"
IGNORE_DNS_QUERY_SUFFIXES = (".arpa", ".local")
SUSPICIOUS_DIRECT_DOWNLOAD_EXTENSIONS = set((".apk", ".exe", ".scr"))
WHITELIST_DIRECT_DOWNLOAD_KEYWORDS = ("cgi", "/scripts/", "/_vti_bin/", "/bin/")
SUSPICIOUS_FILENAMES = set(("gate.php",))
SUSPICIOUS_HTTP_REQUEST_REGEX = r"(?i)information_schema|\b(AND|OR|SELECT)\b.*/\*.*\*/|/\*.*\*/.*\b(AND|OR|SELECT)\b|\b(AND|OR)[^\w]+\d+['\") ]?[=><]['\"( ]?\d+|(alert|confirm|prompt)\((\d+|document\.|[^\w]*XSS)|\bping -[nc] \d+|floor\(rand\(|ORDER BY \d+|sysdatabases|(\.\./){3,}(?!images)|\bSELECT\b.*\bFROM\b.*\b(WHERE|GROUP|ORDER)\b|\bSELECT \w+ FROM \w+|<script.*?>|\balert\(|xp_cmdshell|/etc/(passwd|shadow|issue|hostname)|\b((boot|system|win)\.ini|system32|cmd\.exe|2>&1|(cat|ls) /|nc -l -p \d+)|>\s*/dev/null|<\?php|\b(pg_)?sleep\(|\bWAITFOR[^\w]+DELAY\b|\bCONVERT\(|VARCHAR\(|\bUNION\s+(ALL\s+)?SELECT\b|\bCOUNT\(\*\)|\b(UPDATEXML|EXTRACTVALUE)\(|\bCASE[^\w]+WHEN.*THEN\b|imei=\d{15}|\[<!ENTITY|\(\|\(\w+=\*|/text\(\)='|\$_(REQUEST|GET|POST)\[|\.htaccess|\.htpasswd|\bwp-config\.php"
SUSPICIOUS_HTTP_REQUEST_FORCE_ENCODE_CHARS = "( )"
SUSPICIOUS_UA_REGEX = ""
WORST_ASNS = {}
WHITELIST_HTTP_REQUEST_KEYWORDS = ("fql", "yql", "ads", "../images/", "../scripts/", "../assets/", "../core/", "../js/")
WHITELIST_UA_KEYWORDS = ("62691CB3BF62DAF233FB2C02782E7BD2", "AntiVir-NGUpd", "TMSPS", "AVGSETUP", "SDDS", "Sophos", "internal dummy connection")
WHITELIST_LONG_DOMAIN_NAME_KEYWORDS = ("blogspot",)
SUSPICIOUS_UA_LENGTH_THRESHOLD = 10
SESSIONS = {}
NO_SUCH_NAME_COUNTERS = {}  # this won't be (expensive) shared in multiprocessing run (hence, the threshold will effectively be n-times higher)
SESSION_ID_LENGTH = 16
SESSION_EXPIRATION_HOURS = 24
IPPROTO_LUT = dict(((getattr(socket, _), _.replace("IPPROTO_", "")) for _ in dir(socket) if _.startswith("IPPROTO_")))
DEFLATE_COMPRESS_LEVEL = 9
PORT_SCANNING_THRESHOLD = 10
MAX_RESULT_CACHE_ENTRIES = 10000
MMAP_ZFILL_CHUNK_LENGTH = 1024 * 1024
SUSPICIOUS_DOMAIN_LENGTH_THRESHOLD = 24
SUSPICIOUS_DOMAIN_CONSONANT_THRESHOLD = 7
SUSPICIOUS_DOMAIN_ENTROPY_THRESHOLD = 3.8
WHITELIST = set()
STATIC_IPCAT_LOOKUPS = {"shadowserver.org": ("184.105.139.66-184.105.139.126", "184.105.247.194-184.105.247.254", "74.82.47.1-74.82.47.63", "216.218.206.66-216.218.206.126"), "labs.rapid7.com": ("71.6.216.32-71.6.216.63",), "shodan.io": ("66.240.192.138", "66.240.236.119", "71.6.135.131", "71.6.165.200", "71.6.167.142", "82.221.105.6", "82.221.105.7", "85.25.43.94", "85.25.103.50", "93.120.27.62", "104.131.0.69", "104.236.198.48", "162.159.244.38", "188.138.9.50", "198.20.69.74", "198.20.69.98", "198.20.70.114", "198.20.99.130", "208.180.20.97"), "eecs.umich.edu": ("141.212.121.0-141.212.121.255", "141.212.122.0-141.212.122.255"), "netsec.colostate.edu": ("129.82.138.12", "129.82.138.31", "129.82.138.32", "129.82.138.33", "129.82.138.34", "129.82.138.44"), "ant.isi.edu": ("128.9.168.98", "203.178.148.18", "203.178.148.19"), "eecs.berkeley.edu": ("169.229.3.89", "169.229.3.90", "169.229.3.91", "169.229.3.92", "169.229.3.93", "169.229.3.94"), "openresolverproject.org": ("204.42.253.2", "204.42.254.5"), "opensnmpproject.org": ("204.42.253.130",), "openntpproject.org": ("204.42.253.131",), "openssdpproject.org": ("204.42.253.132",), "projectblindferret.com": ("107.150.52.82-107.150.52.86",)}

# Reference: https://gist.github.com/ryanwitt/588678
DLT_OFFSETS = { 0: 4, 1: 14, 6: 22, 7: 6, 8: 16, 9: 4, 10: 21, 117: 48, 18: 4, 12 if sys.platform.find('openbsd') != -1 else 108: 4, 14 if sys.platform.find('openbsd') != -1 else 12: 0, 113: 16 }

def _get_total_physmem():
    retval = None

    try:
        if subprocess.mswindows:
            import ctypes

            kernel32 = ctypes.windll.kernel32
            c_ulong = ctypes.c_ulong
            class MEMORYSTATUS(ctypes.Structure):
                _fields_ = [
                    ('dwLength', c_ulong),
                    ('dwMemoryLoad', c_ulong),
                    ('dwTotalPhys', c_ulong),
                    ('dwAvailPhys', c_ulong),
                    ('dwTotalPageFile', c_ulong),
                    ('dwAvailPageFile', c_ulong),
                    ('dwTotalVirtual', c_ulong),
                    ('dwAvailVirtual', c_ulong)
                ]

            memory_status = MEMORYSTATUS()
            memory_status.dwLength = ctypes.sizeof(MEMORYSTATUS)
            kernel32.GlobalMemoryStatus(ctypes.byref(memory_status))

            retval = memory_status.dwTotalPhys
        else:
            retval = 1024 * int(re.search(r"(?i)MemTotal:\s+(\d+)\skB", open("/proc/meminfo").read()).group(1))
    except:
        pass

    if not retval:
        try:
            import psutil
            retval = psutil.virtual_memory().total
        except:
            pass

    if not retval:
        try:
            retval = int(re.search(r"real mem(ory)?\s*=\s*(\d+) ", open("/var/run/dmesg.boot").read()).group(2))
        except:
            pass

    if not retval:
        try:
            retval = int(re.search(r"hw\.(physmem|memsize):\s*(\d+)", subprocess.check_output("sysctl hw", shell=True, stderr=subprocess.STDOUT)).group(2))
        except:
            pass

    if not retval:
        try:
            retval = 1024 * int(re.search(r"\s+(\d+) K total memory", subprocess.check_output("vmstat -s", shell=True, stderr=subprocess.STDOUT)).group(1))
        except:
            pass

    if not retval:
        try:
            retval = int(re.search(r"Mem:\s+(\d+)", subprocess.check_output("free -b", shell=True, stderr=subprocess.STDOUT)).group(1))
        except:
            pass

    if not retval:
        try:
            retval = 1024 * int(re.search(r"KiB Mem:\s*\x1b[^\s]+\s*(\d+)", subprocess.check_output("top -n 1", shell=True, stderr=subprocess.STDOUT)).group(1))
        except:
            pass

    return retval

def check_memory():
    print "[?] at least %dMB of free memory required" % (CHECK_MEMORY_SIZE / 1024 / 1024)
    try:
        _ = '0' * CHECK_MEMORY_SIZE
    except MemoryError:
        exit("[!] not enough memory")

def read_config(config_file):
    global config

    if not os.path.isfile(config_file):
        exit("[!] missing configuration file '%s'" % config_file)
    else:
        print "[i] using configuration file '%s'" % config_file

    config.clear()

    try:
        array = None
        content = open(config_file, "rb").read()

        for line in content.split("\n"):
            line = line.strip('\r')
            line = re.sub(r"\s*#.+", "", line)
            if not line.strip():
                continue

            if line.count(' ') == 0:
                if re.search(r"[^\w]", line):
                    if array == "USERS":
                        exit("[!] invalid USERS entry '%s'\n[?] (hint: add whitespace at start of line)" % line)
                    else:
                        exit("[!] invalid configuration (line: '%s')" % line)
                array = line.upper()
                config[array] = []
                continue

            if array and line.startswith(' '):
                config[array].append(line.strip())
                continue
            else:
                array = None
                try:
                    name, value = line.strip().split(' ', 1)
                except ValueError:
                    name = line
                    value = ""
                finally:
                    name = name.strip().upper()
                    value = value.strip("'\"").strip()

            if any(name.startswith(_) for _ in ("USE_", "SET_", "CHECK_", "ENABLE_", "SHOW_", "DISABLE_")):
                value = value.lower() in ("1", "true")
            elif value.isdigit():
                value = int(value)
            else:
                for match in re.finditer(r"\$([A-Z0-9_]+)", value):
                    if match.group(1) in globals():
                        value = value.replace(match.group(0), globals()[match.group(1)])
                    else:
                        value = value.replace(match.group(0), os.environ.get(match.group(1), match.group(0)))
                if subprocess.mswindows and "://" not in value:
                    value = value.replace("/", "\\")

            config[name] = value

    except (IOError, OSError):
        pass

    for option in ("MONITOR_INTERFACE", "CAPTURE_BUFFER", "LOG_DIR"):
        if not option in config:
            exit("[!] missing mandatory option '%s' in configuration file '%s'" % (option, config_file))

    for entry in (config.USERS or []):
        if len(entry.split(':')) != 4:
            exit("[!] invalid USERS entry '%s'" % entry)
        if re.search(r"\$\d+\$", entry):
            exit("[!] invalid USERS entry '%s'\n[?] (hint: please update PBKDF2 hashes to SHA256 in your configuration file)" % entry)

    if config.SSL_PEM:
        config.SSL_PEM = config.SSL_PEM.replace('/', os.sep)

    if config.USER_WHITELIST:
        for value in config.USER_WHITELIST.split(','):
            WHITELIST.add(value.strip())

    if config.DISABLE_LOCAL_LOG_STORAGE and not config.LOG_SERVER:
        print("[x] configuration switch 'DISABLE_LOCAL_LOG_STORAGE' turned on and option 'LOG_SERVER' not set. Falling back to console output of event data")

    if config.UDP_ADDRESS is not None and config.UDP_PORT is None:
        exit("[!] usage of configuration value 'UDP_ADDRESS' requires also usage of 'UDP_PORT'")

    if config.UDP_ADDRESS is None and config.UDP_PORT is not None:
        exit("[!] usage of configuration value 'UDP_PORT' requires also usage of 'UDP_ADDRESS'")

    if not str(config.HTTP_PORT or "").isdigit():
        exit("[!] invalid configuration value for 'HTTP_PORT' ('%s')" % config.HTTP_PORT)

    if config.USE_MULTIPROCESSING and subprocess.mswindows:
        print "[x] multiprocessing is currently not supported on Windows OS"
        config.USE_MULTIPROCESSING = False

    if config.CAPTURE_BUFFER:
        if str(config.CAPTURE_BUFFER or "").isdigit():
            config.CAPTURE_BUFFER = int(config.CAPTURE_BUFFER)
        elif re.search(r"\d+\s*[kKmMgG]B", config.CAPTURE_BUFFER):
            match = re.search(r"(\d+)\s*([kKmMgG])B", config.CAPTURE_BUFFER)
            config.CAPTURE_BUFFER = int(match.group(1)) * {"K": 1024, "M": 1024 ** 2, "G": 1024 ** 3}[match.group(2).upper()]
        elif re.search(r"\d+%", config.CAPTURE_BUFFER):
            physmem = _get_total_physmem()

            if physmem:
                config.CAPTURE_BUFFER = physmem * int(re.search(r"(\d+)%", config.CAPTURE_BUFFER).group(1)) / 100
            else:
                exit("[!] unable to determine total physical memory. Please use absolute value for 'CAPTURE_BUFFER'")
        else:
            exit("[!] invalid configuration value for 'CAPTURE_BUFFER' ('%s')" % config.CAPTURE_BUFFER)

        config.CAPTURE_BUFFER = config.CAPTURE_BUFFER / BLOCK_LENGTH * BLOCK_LENGTH

def read_whitelist():
    WHITELIST.clear()

    _ = os.path.abspath(os.path.join(ROOT_DIR, "misc", "whitelist.txt"))
    if os.path.isfile(_):
        with open(_, "r") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                else:
                    WHITELIST.add(line)

def read_ua():
    global SUSPICIOUS_UA_REGEX

    SUSPICIOUS_UA_REGEX = ""
    items = []

    _ = os.path.abspath(os.path.join(ROOT_DIR, "misc", "ua.txt"))
    if os.path.isfile(_):
        with open(_, "r") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                else:
                    items.append(line)

    if items:
        SUSPICIOUS_UA_REGEX = "(?i)%s" % '|'.join(items)

def read_worst_asn():
    _ = os.path.abspath(os.path.join(ROOT_DIR, "misc", "worst_asns.txt"))
    if os.path.isfile(_):
        with open(_, "r") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                else:
                    key = line.split('.')[0]
                    if key not in WORST_ASNS:
                        WORST_ASNS[key] = []
                    prefix, mask, name = re.search(r"([\d.]+)/(\d+),(.+)", line).groups()
                    WORST_ASNS[key].append((addr_to_int(prefix), make_mask(int(mask)), name))

if __name__ != "__main__":
    read_whitelist()
    read_ua()
    read_worst_asn()
