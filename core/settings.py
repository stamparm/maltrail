#!/usr/bin/env python

"""
Copyright (c) 2014-2025 Maltrail developers (https://github.com/stamparm/maltrail/)
See the file 'LICENSE' for copying permission
"""
from __future__ import print_function

import os
import re
import socket
import stat
import struct
import subprocess
import sys

from core.addr import addr_to_int
from core.addr import expand_range
from core.addr import make_mask
from core.attribdict import AttribDict
from core.colorized import init_output
from core.trailsdict import TrailsDict
from thirdparty.six.moves import urllib as _urllib

NAME = "Maltrail"
VERSION = "0.79"
HOMEPAGE = "https://maltrail.github.io"
PLATFORM = os.name
IS_WIN = PLATFORM == "nt"
IS_SENSOR = "sensor" in sys.argv[0]
USER_AGENT = "%s/%s (%s/py%s/x%d)" % (NAME, VERSION, re.sub(r"\d$", "", sys.platform), sys.version.split(' ')[0], struct.calcsize('P') * 8)
DATE_FORMAT = "%Y-%m-%d"
ROTATING_CHARS = ('\\', '|', '|', '/', '-')
TIMEOUT = 30
UNICODE_ENCODING = "utf8"
FRESH_IPCAT_DELTA_DAYS = 10
USERS_DIR = os.path.join(os.path.expanduser("~"), ".%s" % NAME.lower())
DEFAULT_TRAILS_FILE = os.path.join(USERS_DIR, "trails.csv")
IPCAT_CSV_FILE = os.path.join(USERS_DIR, "ipcat.csv")
IPCAT_SQLITE_FILE = os.path.join(USERS_DIR, "ipcat.sqlite")
IPCAT_URL = "https://raw.githubusercontent.com/growlfm/ipcat/master/datacenters.csv"
CHECK_CONNECTION_URL = "https://www.github.com"
CHECK_CONNECTION_MAX_RETRIES = 3
TIME_FORMAT = "%Y-%m-%d %H:%M:%S"
HTTP_DEFAULT_PORT = 8338
HTTP_TIME_FORMAT = "%a, %d %b %Y %H:%M:%S GMT"  # Reference: http://stackoverflow.com/a/225106
CEF_FORMAT = "{syslog_time} {host} CEF:0|{device_vendor}|{device_product}|{device_version}|{signature_id}|{name}|{severity}|{extension}"
SESSION_COOKIE_NAME = "%s_sessid" % NAME.lower()
SESSION_COOKIE_FLAG_SAMESITE = True
SNAP_LEN = 2000
BLOCK_LENGTH = 1 + 2 + 4 + 4 + 4 + SNAP_LEN  # primitive mutex + short for packet size + int for sec + int for usec + int for IP offset + max packet size
SHORT_SENSOR_SLEEP_TIME = 0.00001
REGULAR_SENSOR_SLEEP_TIME = 0.001
LOAD_TRAILS_RETRY_SLEEP_TIME = 60
UNAUTHORIZED_SLEEP_TIME = 5
NO_SUCH_NAME_PER_HOUR_THRESHOLD = 20
NO_BLOCK = -1
END_BLOCK = -2
ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
HTML_DIR = os.path.join(ROOT_DIR, "html")
DISPOSED_NONCES = set()
PING_RESPONSE = "pong"
MAX_NOFILE = 65000
CAPTURE_TIMEOUT = 100  # ms
MAX_HELP_OPTION_LENGTH = 18
CONFIG_FILE = os.path.join(ROOT_DIR, "maltrail.conf")
SYSTEM_LOG_DIR = "/var/log" if not IS_WIN else "C:\\Windows\\Logs"
DEFAULT_EVENT_LOG_PERMISSIONS = stat.S_IREAD | stat.S_IWRITE | stat.S_IRGRP | stat.S_IROTH
DEFAULT_ERROR_LOG_PERMISSIONS = stat.S_IREAD | stat.S_IWRITE | stat.S_IRGRP | stat.S_IWGRP | stat.S_IROTH | stat.S_IWOTH
HOSTNAME = socket.gethostname()
PROXIES = {}
DISABLED_CONTENT_EXTENSIONS = (".py", ".pyc", ".md", ".txt", ".bak", ".conf", ".zip", "~")
CONTENT_EXTENSIONS_EXCLUSIONS = ("robots.txt",)
CONDENSE_ON_INFO_KEYWORDS = ("attacker", "reputation", "scanner", "user agent", "tor exit", "port scanning", "potential infection")
CONDENSED_EVENTS_FLUSH_PERIOD = 10
LOW_PRIORITY_INFO_KEYWORDS = ("reputation", "attacker", "spammer", "abuser", "malicious", "dnspod", "nicru", "crawler", "compromised", "bad history")
HIGH_PRIORITY_INFO_KEYWORDS = ("mass scanner", "ipinfo")
HIGH_PRIORITY_REFERENCES = ("(static)", "(custom)")
CONSONANTS = "bcdfghjklmnpqrstvwxyz"
BAD_TRAIL_PREFIXES = ("127.", "192.168.", "localhost")
LOCALHOST_IP = {4: "127.0.0.1", 6: "::1"}
POTENTIAL_INFECTION_PORTS = (135, 139, 445, 1433, 3389, 6379, 6892, 6893, 6901)
IGNORE_DNS_QUERY_SUFFIXES = set(("arpa", "local", "guest", "intranet", "int", "corp", "home", "lan", "intra", "intran", "workgroup", "localdomain", "url", "alienvault", "dev", "example", "internal", "localnet", "test"))
VALID_DNS_NAME_REGEX = r"\A[a-zA-Z0-9.-]*\.[a-zA-Z0-9-]+\Z"  # Reference: http://stackoverflow.com/a/3523068
SUSPICIOUS_CONTENT_TYPES = ("application/vnd.ms-htmlhelp", "application/x-bsh", "application/x-chm", "application/x-ms-shortcut", "application/x-sh", "application/x-shellscript", "application/hta", "text/x-scriptlet", "text/x-sh", "text/x-shellscript")
SUSPICIOUS_DIRECT_DOWNLOAD_EXTENSIONS = set((".apk", ".bin", ".class", ".chm", ".dll", ".egg", ".exe", ".hta", ".hwp", ".lnk", ".msi", ".pif", ".ps1", ".scr", ".sct", ".wbk", ".xpi"))
WHITELIST_DIRECT_DOWNLOAD_KEYWORDS = ("cgi", "/scripts/", "/_vti_bin/", "/bin/", "/pub/softpaq/", "/bios/", "/pc-axis/")
SUSPICIOUS_HTTP_REQUEST_REGEXES = (
    ("potential sql injection", r"information_schema|sysdatabases|sysusers|floor\(rand\(|ORDER BY \d+|\bUNION\s+(ALL\s+)?SELECT\b|\b(UPDATEXML|EXTRACTVALUE)\(|\bCASE[^\w]+WHEN.*THEN\b|\bWAITFOR[^\w]+DELAY\b|\bCONVERT\(|VARCHAR\(|\bCOUNT\(\*\)|\b(pg_)?sleep\(|\bSELECT\b.*\bFROM\b.*\b(WHERE|GROUP|ORDER)\b|\bSELECT \w+ FROM \w+|\b(AND|OR|SELECT)\b.*/\*.*\*/|/\*.*\*/.*\b(AND|OR|SELECT)\b|\b(AND|OR)[^\w]+\d+['\") ]?[=><]['\"( ]?\d+|ODBC;DRIVER|\bINTO\s+(OUT|DUMP)FILE"),
    ("potential xml injection", r"/text\(\)='"),
    ("potential php injection", r"<\?php|php://input"),
    ("potential ldap injection", r"\(\|\(\w+=\*"),
    ("potential xss injection", r"<script.*?>|\balert\(|(alert|confirm|prompt)\((\d+|document\.|response\.write\(|[^\w]*XSS)|on(mouseover|error|focus|transitionend)=[^&;\n]+\("),
    ("potential xxe injection", r"\[<!ENTITY"),
    ("potential ssti injection", r"\${[^&]+\}|\$\{\{[^&]+\}\}"),
    ("potential data leakage", r"im[es]i=\d{15}|iccid=[a-zA-Z0-9]{18,22}|(mac([aA]ddress)?|sid)=([0-9a-f]{2}:){5}[0-9a-f]{2}|sim=\d{20}|([a-z0-9_.+-]+@[a-z0-9-.]+\.[a-z]+\b.{0,100}){4}|(telnum|telcompany)=[a-zA-Z0-9-]+"),
    ("config file access", r"\.ht(access|passwd)|\bwp-config\.php"),
    ("potential remote code execution", r"\$_(REQUEST|GET|POST)\[|xp_cmdshell|shell_exec|exec_code|shell:::\{|oscmd\(|\bping(\.exe)? -[nc] \d+|timeout(\.exe)? /T|tftp -|wget http|curl -O|sh /tmp/|touch /tmp/|cmd\.exe|/bin/(ba)?sh\b|/sbin/launchd\b|2>&1|\b(cat|ls) /|chmod [0-7]{3,4}\b|chmod +x\b|base64 -d|nc -l -p \d+|>\s*/dev/null|-d (allow_url_include|safe_mode|auto_prepend_file)|ms-msdt:|mhtml:ftp:|jndi:(corba|dns|http|iiop|n(d|i)s|ldap[s]?|rmi):?|base64:JHtqbmRp|ipconfig|net (config|view)|nltest|netsh (firewall|wlan)|\$\{IFS\}|getRuntime\(\)\.exec\("),
    ("potential directory traversal", r"(\.{2,}[/\\]+){3,}|/etc/(group|passwd|shadow|issue|hostname|hosts|sudoers)|[/\\](boot|system|win)\.ini|[/\\]system32\b|%SYSTEMROOT%"),
    ("potential web scan", r"(acunetix|injected_by)_wvs_|SomeCustomInjectedHeader|some_inexistent_file_with_long_name|testasp\.vulnweb\.com/t/fit\.txt|www\.acunetix\.tst|\.bxss\.me|thishouldnotexistandhopefullyitwillnot|OWASP%\d+ZAP|chr\(122\)\.chr\(97\)\.chr\(112\)|Vega-Inject|VEGA123|vega\.invalid|PUT-putfile|w00tw00t|muieblackcat"),
    ("potential dns changer", r"\b(dhcpPriDns|dhcpSecDns|staticPriDns|staticSecDns|staticThiDns|PriDnsv6|SecDnsv6|ThiDnsv6|staticPriDnsv6|staticSecDnsv6|staticThiDnsv6|dnsipv4|dns2ipv4|dnsipv6|dns2ipv6|pppoePriDns|pppoeSecDns|wan_dns1|wan_dns2|dnsPrimary|dnsSecondary|dnsDynamic|dnsRefresh|DNS_FST|DNS_SND|dhcpPriDns|dhcpSecDns|dnsserver|dnsserver1|dnsserver2|dns_server_ip_1|dns_server_ip_2|dns_server_ip_3|dns_server_ip_4|dns1|dns2|dns3|dns4|dns1_1|dns1_2|dns1_3|dns1_4|dns2_1|dns2_2|dns2_3|dns2_4|wan_dns_x|wan_dns1_x|wan_dns2_x|wan_dns3_x|wan_dns4_x|wan_dnsenable_x|dns_status|p_DNS|a_DNS|uiViewDns1Mark|uiViewDns2Mark|uiViewDNSRelay|is_router_as_dns|Enable_DNSFollowing|domainserverip|DSEN|DNSEN|dnsmode|dns%5Bserver1%5D|dns%5Bserver2%5D)=")
)
SUSPICIOUS_HTTP_PATH_REGEXES = (
    ("non-existent page", r"defaultwebpage\.cgi"),
    ("potential web scan", r"inexistent_file_name\.inexistent|test-for-some-inexistent-file|long_inexistent_path|some-inexistent-website\.acu")
)
SUSPICIOUS_HTTP_REQUEST_PRE_CONDITION = ("?", "..", ".ht", "=", " ", "'")
SUSPICIOUS_DIRECT_IP_URL_REGEX = r"\A[\w./-]*/[\w.]*\b(aarch|amd64\b|arm(\b|v?\d)|arcle-(750d|hs38)|exploit|m68k?\b|m[i1]ps\w{0,4}\b|mpsl\w?\b|pcc|powerp{1,2}c|pp-?c|riscv\w{0,3}\b|root|s390\w?\b|x86|x32|x64|i\d{1,2}\b|i386|i486|i586|i686|sparc|sh\b|wtf|yarn|zte)\Z"
SUSPICIOUS_PROXY_PROBE_PRE_CONDITION = ("probe", "proxy", "echo", "check")
SUSPICIOUS_HTTP_REQUEST_FORCE_ENCODE_CHARS = dict((_, _urllib.parse.quote(_)) for _ in "( )\r\n")
SUSPICIOUS_UA_REGEX = ""
OBSOLETE_UA_REGEX = r"(?i)windows NT [3-5]\.\d+|windows (3\.\d+|95|98|xp)|MSIE [1-6]\.\d+|Navigator/|Safari/[1-4]|Opera/[1-3]|Firefox/1?[0-9]\.|Android [1-3]\.\d+|iPhone OS [1-4]_\d+|Mac OS X 10\.[0-4]\.|Chrome/[1-2]?\d\.|BlackBerry ?[0-7]"
GENERIC_SINKHOLE_REGEX = r"(?im)^(X-Sinkhole|Server): (malware-?)?sinkhole|\bSinkholed? by |^(X-Sinkholed?(-Domain)?|X-Zinkhole|X-Sinkhole):| a malware sinkhole|\bSinkhole( Project)?</title>|This is a sinkhole|bots party hard|computers connecting to this sinkhole| Sinkhole by |^Set-Cookie: snkz=|^Server: Apache [0-9.]+/SinkSoft|^Location:[^\n]+\.sinkdns\.org:80"
WORST_ASNS = {}
BOGON_IPS = {"::1"}
BOGON_RANGES = {}
CDN_RANGES = {}
WHITELIST_HTTP_REQUEST_PATHS = ("fql", "yql", "ads", "../images/", "../themes/", "../design/", "../scripts/", "../assets/", "../core/", "../js/", "/gwx/")
WHITELIST_UA_REGEX = r"AntiVir\-NGUpd|TMSPS|AVGSETUP|SDDS|Sophos|Symantec|internal dummy connection|Microsoft\-CryptoAPI"
WHITELIST_LONG_DOMAIN_NAME_KEYWORDS = ("blogspot",)
LOCAL_SUBDOMAIN_LOOKUPS = ("wpad", "autodiscover", "_ldap._tcp")
SESSIONS = {}
NO_SUCH_NAME_COUNTERS = {}  # this won't be (expensive) shared in multiprocessing run (hence, the threshold will effectively be n-times higher)
SESSION_ID_LENGTH = 16
SESSION_EXPIRATION_HOURS = 24
IPPROTO_LUT = dict(((getattr(socket, _), _.replace("IPPROTO_", "")) for _ in dir(socket) if _.startswith("IPPROTO_")))
DEFLATE_COMPRESS_LEVEL = 9
PORT_SCANNING_THRESHOLD = 10
WEB_SCANNING_THRESHOLD = 10
INFECTION_SCANNING_THRESHOLD = 32
MAX_CACHE_ENTRIES = 1000
MMAP_ZFILL_CHUNK_LENGTH = 1024 * 1024
HOURLY_SECS = 1 * 60 * 60
DAILY_SECS = 24 * 60 * 60
DNS_EXHAUSTION_THRESHOLD = 1000
SUSPICIOUS_DOMAIN_LENGTH_THRESHOLD = 24
SUSPICIOUS_DOMAIN_CONSONANT_THRESHOLD = 9
SUSPICIOUS_DOMAIN_ENTROPY_THRESHOLD = 3.5
WHITELIST = set()
WHITELIST_RANGES = set()
IGNORE_EVENTS = set()
STATIC_IPCAT_LOOKUPS = {"shadowserver.org": ("184.105.139.66-184.105.139.126", "184.105.247.194-184.105.247.254", "74.82.47.1-74.82.47.63", "216.218.206.66-216.218.206.126"), "labs.rapid7.com": ("71.6.216.32-71.6.216.63",), "shodan.io": ("66.240.192.138", "66.240.236.119", "71.6.135.131", "71.6.165.200", "71.6.167.142", "82.221.105.6", "82.221.105.7", "85.25.43.94", "85.25.103.50", "93.120.27.62", "104.131.0.69", "104.236.198.48", "162.159.244.38", "188.138.9.50", "198.20.69.74", "198.20.69.98", "198.20.70.114", "198.20.87.98", "198.20.99.130", "208.180.20.97", "209.126.110.38"), "eecs.umich.edu": ("141.212.121.0-141.212.121.255", "141.212.122.0-141.212.122.255"), "netsec.colostate.edu": ("129.82.138.12", "129.82.138.31", "129.82.138.32", "129.82.138.33", "129.82.138.34", "129.82.138.44"), "ant.isi.edu": ("128.9.168.98", "203.178.148.18", "203.178.148.19"), "eecs.berkeley.edu": ("169.229.3.89", "169.229.3.90", "169.229.3.91", "169.229.3.92", "169.229.3.93", "169.229.3.94"), "openresolverproject.org": ("204.42.253.2", "204.42.254.5"), "opensnmpproject.org": ("204.42.253.130",), "openntpproject.org": ("204.42.253.131",), "openssdpproject.org": ("204.42.253.132",), "projectblindferret.com": ("107.150.52.82-107.150.52.86",), "kudelskisecurity.com": ("185.35.62.0-185.35.62.255",), "riskiq.com": ("64.125.239.0-64.125.239.255",), "comsys.rwth-aachen.de": ("137.226.113.0-137.226.113.63",), "sba-research.org": ("98.189.26.18",)}

# Reference: https://gist.github.com/ryanwitt/588678
DLT_OFFSETS = {0: 4, 1: 14, 6: 22, 7: 6, 8: 16, 9: 4, 10: 21, 117: 48, 18: 4, 12 if sys.platform.find('openbsd') != -1 else 108: 4, 14 if sys.platform.find('openbsd') != -1 else 12: 0, 113: 16}

try:
    import multiprocessing
    CPU_CORES = multiprocessing.cpu_count()
except ImportError:
    CPU_CORES = 1

config = AttribDict({"TRAILS_FILE": DEFAULT_TRAILS_FILE})
trails = TrailsDict()

def _get_total_physmem():
    retval = None

    try:
        if IS_WIN:
            output = subprocess.check_output(['wmic', 'computersystem', 'get', 'TotalPhysicalMemory'], universal_newlines=True)
            retval = int(output.strip().splitlines()[-1].strip())
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

def read_config(config_file):
    global config

    if not os.path.isfile(config_file):
        sys.exit("[!] missing configuration file '%s'" % config_file)
    else:
        print("[i] using configuration file '%s'" % config_file)

    config.clear()

    try:
        array = None
        content = open(config_file, "r").read()

        for line in content.split("\n"):
            line = line.strip('\r')
            line = re.sub(r"\s*#.*", "", line)
            if not line.strip():
                continue

            if line.count(' ') == 0:
                if re.search(r"[^\w]", line):
                    if array == "USERS":
                        sys.exit("[!] invalid USERS entry '%s'\n[?] (hint: add whitespace at start of line)" % line)
                    else:
                        sys.exit("[!] invalid configuration (line: '%s')" % line)
                array = line.upper()
                config[array] = []
                continue

            if array and line.startswith(' '):
                line = line.strip()
                if array == "IP_ALIASES" and any(_ in line.split(':')[0] for _ in ('/', '-')):
                    for addr in expand_range(line.split(':')[0]):
                        config[array].append("%s:%s" % (addr, line.split(':', 1)[-1]))
                else:
                    config[array].append(line)

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

            _ = os.environ.get("%s_%s" % (NAME.upper(), name))
            if _:
                value = _

            if any(name.startswith(_) for _ in ("USE_", "SET_", "CHECK_", "ENABLE_", "SHOW_", "DISABLE_")):
                value = value.lower() in ("1", "true")
            elif value.isdigit():
                value = int(value)
            else:
                for match in re.finditer(r"\$([A-Z0-9_]+)", value):
                    if match.group(1) in globals():
                        value = value.replace(match.group(0), str(globals()[match.group(1)]))
                    else:
                        value = value.replace(match.group(0), os.environ.get(match.group(1), match.group(0)))
                if name.endswith("_DIR"):
                    value = os.path.realpath(os.path.join(ROOT_DIR, os.path.expanduser(value)))

            config[name] = value

    except (IOError, OSError):
        pass

    for option in ("MONITOR_INTERFACE", "CAPTURE_BUFFER", "LOG_DIR"):
        if option not in config:
            sys.exit("[!] missing mandatory option '%s' in configuration file '%s'" % (option, config_file))

    for entry in (config.USERS or []):
        if len(entry.split(':')) != 4:
            sys.exit("[!] invalid USERS entry '%s'" % entry)
        if re.search(r"\$\d+\$", entry):
            sys.exit("[!] invalid USERS entry '%s'\n[?] (hint: please update PBKDF2 hashes to SHA256 in your configuration file)" % entry)

    if config.SSL_PEM:
        config.SSL_PEM = config.SSL_PEM.replace('/', os.sep)

    if config.USER_WHITELIST:
        if ',' in config.USER_WHITELIST:
            print("[x] configuration value 'USER_WHITELIST' has been changed. Please use it to set location of whitelist file")
        elif not os.path.isfile(config.USER_WHITELIST):
            sys.exit("[!] missing 'USER_WHITELIST' file '%s'" % config.USER_WHITELIST)
        else:
            read_whitelist()

    if config.USER_IGNORELIST:
        if not os.path.isfile(config.USER_IGNORELIST):
            sys.exit("[!] missing 'USER_IGNORELIST' file '%s'" % config.USER_IGNORELIST)
        else:
            read_ignorelist()

    config.PROCESS_COUNT = int(config.PROCESS_COUNT or CPU_CORES)

    if config.USE_MULTIPROCESSING:
        print("[x] configuration switch 'USE_MULTIPROCESSING' is deprecated. Please use 'PROCESS_COUNT' instead")

    if config.DISABLE_LOCAL_LOG_STORAGE and not any((config.LOG_SERVER, config.SYSLOG_SERVER)):
        print("[x] configuration switch 'DISABLE_LOCAL_LOG_STORAGE' turned on and neither option 'LOG_SERVER' nor 'SYSLOG_SERVER' are set. Falling back to console output of event data")

    if config.UDP_ADDRESS is not None and config.UDP_PORT is None:
        sys.exit("[!] usage of configuration value 'UDP_ADDRESS' requires also usage of 'UDP_PORT'")

    if config.UDP_ADDRESS is None and config.UDP_PORT is not None:
        sys.exit("[!] usage of configuration value 'UDP_PORT' requires also usage of 'UDP_ADDRESS'")

    if not str(config.HTTP_PORT or "").isdigit() and not IS_SENSOR:
        sys.exit("[!] invalid configuration value for 'HTTP_PORT' ('%s')" % ("" if config.HTTP_PORT is None else config.HTTP_PORT))

    if not str(config.UPDATE_PERIOD or "").isdigit():
        sys.exit("[!] invalid configuration value for 'UPDATE_PERIOD' ('%s')" % ("" if config.UPDATE_PERIOD is None else config.UPDATE_PERIOD))

    if config.PROCESS_COUNT and IS_WIN:
        print("[x] multiprocessing is currently not supported on Windows OS")
        config.PROCESS_COUNT = 1

    if config.CAPTURE_BUFFER:
        if str(config.CAPTURE_BUFFER or "").isdigit():
            config.CAPTURE_BUFFER = int(config.CAPTURE_BUFFER)
        elif re.search(r"\d+\s*[kKmMgG]B", config.CAPTURE_BUFFER):
            match = re.search(r"(\d+)\s*([kKmMgG])B", config.CAPTURE_BUFFER)
            config.CAPTURE_BUFFER = int(match.group(1)) * {"K": 1024, "M": 1024 ** 2, "G": 1024 ** 3}[match.group(2).upper()]
        elif re.search(r"\d+%", config.CAPTURE_BUFFER):
            physmem = _get_total_physmem()

            if physmem:
                config.CAPTURE_BUFFER = physmem * int(re.search(r"(\d+)%", config.CAPTURE_BUFFER).group(1)) // 100
            else:
                sys.exit("[!] unable to determine total physical memory. Please use absolute value for 'CAPTURE_BUFFER'")
        else:
            sys.exit("[!] invalid configuration value for 'CAPTURE_BUFFER' ('%s')" % config.CAPTURE_BUFFER)

        config.CAPTURE_BUFFER = config.CAPTURE_BUFFER // BLOCK_LENGTH * BLOCK_LENGTH

    if config.PROXY_ADDRESS:
        PROXIES.update({"http": config.PROXY_ADDRESS, "https": config.PROXY_ADDRESS})
        opener = _urllib.request.build_opener(_urllib.request.ProxyHandler(PROXIES))
        _urllib.request.install_opener(opener)

    if not config.TRAILS_FILE:
        config.TRAILS_FILE = DEFAULT_TRAILS_FILE
    else:
        config.TRAILS_FILE = os.path.abspath(os.path.expanduser(config.TRAILS_FILE))

    if int(os.environ.get("MALTRAIL_DREI", 0)) > 0:
        config.SHOW_DEBUG = True

def read_whitelist():
    WHITELIST.clear()
    WHITELIST_RANGES.clear()

    _ = os.path.abspath(os.path.join(ROOT_DIR, "misc", "whitelist.txt"))
    if os.path.isfile(_):
        with open(_, "r") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                elif re.search(r"\A\d+\.\d+\.\d+\.\d+/\d+\Z", line):
                    try:
                        prefix, mask = line.split('/')
                        WHITELIST_RANGES.add((addr_to_int(prefix), make_mask(int(mask))))
                    except (IndexError, ValueError):
                        WHITELIST.add(line)
                else:
                    WHITELIST.add(line)

    if config.USER_WHITELIST and os.path.isfile(config.USER_WHITELIST):
        with open(config.USER_WHITELIST, "r") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                elif re.search(r"\A\d+\.\d+\.\d+\.\d+/\d+\Z", line):
                    try:
                        prefix, mask = line.split('/')
                        WHITELIST_RANGES.add((addr_to_int(prefix), make_mask(int(mask))))
                    except (IndexError, ValueError):
                        WHITELIST.add(line)
                else:
                    WHITELIST.add(line)

# add rules to ignore event list from passed file
def add_ignorelist(filepath):
    if filepath and os.path.isfile(filepath):
        with open(filepath, "r") as f:
            for line in f:
                line = re.sub(r"\s+", "", line)

                if not line or line.startswith('#'):
                    continue
                elif line.count(';') == 3:
                    src_ip, src_port, dst_ip, dst_port = line.split(';')
                    IGNORE_EVENTS.add((src_ip, src_port, dst_ip, dst_port))

def read_ignorelist():
    IGNORE_EVENTS.clear()

    _ = os.path.abspath(os.path.join(ROOT_DIR, "misc", "ignore_events.txt"))
    add_ignorelist(_)

    if config.USER_IGNORELIST and os.path.isfile(config.USER_IGNORELIST):
        add_ignorelist(config.USER_IGNORELIST)

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
                elif " (compatible" in line:
                    line = re.escape(line)
                else:
                    try:
                        re.compile(line)
                    except:
                        line = re.escape(line)

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

def read_cdn_ranges():
    _ = os.path.abspath(os.path.join(ROOT_DIR, "misc", "cdn_ranges.txt"))
    if os.path.isfile(_):
        with open(_, "r") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                else:
                    key = line.split('.')[0]
                    if key not in CDN_RANGES:
                        CDN_RANGES[key] = []
                    prefix, mask = line.split('/')
                    CDN_RANGES[key].append((addr_to_int(prefix), make_mask(int(mask))))

def read_bogon_ranges():
    _ = os.path.abspath(os.path.join(ROOT_DIR, "misc", "bogon_ranges.txt"))
    if os.path.isfile(_):
        with open(_, "r") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                else:
                    key = line.split('.')[0]
                    if key not in BOGON_RANGES:
                        BOGON_RANGES[key] = []
                    prefix, mask = line.split('/')
                    BOGON_RANGES[key].append((addr_to_int(prefix), make_mask(int(mask))))

def check_deprecated():
    if "--no-updates" in sys.argv:
        print("[!] switch '--no-updates' was renamed to '--offline'")
        sys.argv = [(_ if _ != "--no-updates" else "--offline") for _ in sys.argv]

    if "-i" in sys.argv:
        print("[x] option '-i' was renamed to '-r'")
        sys.argv = [(_ if _ != "-i" else "-r") for _ in sys.argv]

if __name__ != "__main__":
    init_output()
    read_whitelist()
    read_ignorelist()
    read_ua()
    read_worst_asn()
    read_cdn_ranges()
    read_bogon_ranges()
    check_deprecated()
