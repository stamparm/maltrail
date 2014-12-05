import logging, pickle, optparse, os, re, socket, subprocess, tempfile, time, urllib2, zipfile, zlib

NAME, VERSION, AUTHOR, LICENSE = "DNScrutinize", "0.1e", "Miroslav Stampar (@stamparm)", "Public domain (FREE)"

try:
    logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

    from scapy.all import *
except ImportError:
    exit("[!] please install Scapy (e.g. '%s')" % ("sudo apt-get install scapy" if not subprocess.mswindows else "http://www.secdev.org/projects/scapy/doc/installation.html#windows"))

TIMEOUT = 30
FRESH_LISTS_DELTA_DAYS = 1
DOMAINS_FILE = "domains.bin"
OUTPUT_FORMAT = "|{0:^15s}|{1:^40s}|{2:^17s}|{3:^15s}|{4:^20s}|"

MALWAREDOMAINLIST_URL = "http://www.malwaredomainlist.com/hostslist/hosts.txt"
MALWAREDOMAINS_URL = "http://malwaredomains.lehigh.edu/files/domains.txt"
ZEUS_ABUSECH_URL = "https://zeustracker.abuse.ch/blocklist.php?download=domainblocklist"

_console_width = None
_domains = {}

def _retrieve_content(url, data=None):
    try:
        req = urllib2.Request("".join(url[i].replace(' ', "%20") if i > url.find('?') else url[i] for i in xrange(len(url))), data, {"User-agent": NAME})
        retval = urllib2.urlopen(req, timeout=TIMEOUT).read()
    except Exception, ex:
        retval = ex.read() if hasattr(ex, "read") else getattr(ex, "msg", str())
    return retval or ""

def _check_sudo():
    check = None

    if not subprocess.mswindows:
        if getattr(os, "geteuid"):
            check = os.geteuid() == 0
    else:
        import ctypes
        check = ctypes.windll.shell32.IsUserAnAdmin()

    if check is False:
        exit("[x] please run with sudo/Administrator privileges")

def _get_console_width(default=80):
    width = None

    if os.getenv("COLUMNS", "").isdigit():
        width = int(os.getenv("COLUMNS"))
    else:
        try:
            try:
                FNULL = open(os.devnull, 'w')
            except IOError:
                FNULL = None
            process = subprocess.Popen("stty size", shell=True, stdout=subprocess.PIPE, stderr=FNULL or subprocess.PIPE)
            stdout, _ = process.communicate()
            items = stdout.split()

            if len(items) == 2 and items[1].isdigit():
                width = int(items[1])
        except OSError:
            pass

    if width is None:
        try:
            import curses

            stdscr = curses.initscr()
            _, width = stdscr.getmaxyx()
            curses.endwin()
        except:
            pass

    return width or default

def _trim_output(value):
    global _console_width

    _console_width = _console_width or _get_console_width()

    return value[:_console_width]

def load_domains(list_file=None):
    global _domains

    if list_file:
        content = open(list_file)
        for line in content.split('\n'):
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            _domains[line] = ("suspicious", "custom")

    if not os.path.isfile(DOMAINS_FILE) or (time.time() - os.stat(DOMAINS_FILE).st_mtime) / 3600 / 24 > FRESH_LISTS_DELTA_DAYS:
        print "[i] %s domain lists..." % ("updating" if os.path.isfile(DOMAINS_FILE) else "retrieving")

        print " [o] '%s'" % ZEUS_ABUSECH_URL
        content = _retrieve_content(ZEUS_ABUSECH_URL)
        if "ZeuS" not in content:
            print "[!] something went wrong during remote data retrieval ('%s')" % ZEUS_ABUSECH_URL

        for line in content.split('\n'):
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            _domains[line] = ("ZeuS", "abuse.ch")

        print " [o] '%s'" % MALWAREDOMAINS_URL
        content = _retrieve_content(MALWAREDOMAINS_URL)
        if "safebrowsing.clients.google.com" not in content:
            print "[!] something went wrong during remote data retrieval ('%s')" % MALWAREDOMAINS_URL

        for line in content.split('\n'):
            line = line.strip('\r')
            if not line or line.startswith('#'):
                continue
            items = line.split('\t')
            _domains[items[2]] = (items[3], items[4].split('/')[0] if '/' in items[4] else items[4])   # (type, original_reference-why_it_was_listed)

        print " [o] '%s'" % MALWAREDOMAINLIST_URL
        content = _retrieve_content(MALWAREDOMAINLIST_URL)
        if "127.0.0.1" not in content:
            print "[!] something went wrong during remote data retrieval ('%s')" % MALWAREDOMAINLIST_URL

        for line in content.split('\n'):
            line = line.strip('\r')
            if not line or line.startswith('#'):
                continue
            items = line.split('\s+')
            if items[0] == "127.0.0.1" and items[1] != "localhost":
                _domains[items[1]] = ("malware", "MDL")

        with open(DOMAINS_FILE, "w+b") as f:
            f.write(zlib.compress(pickle.dumps(_domains)))

    if not _domains:
        print "[i] loading cache..."
        with open(DOMAINS_FILE, "rb") as f:
            _domains = pickle.loads(zlib.decompress(f.read()))

    print "[i] %d suspicious domain names loaded" % len(_domains)

def inspect_dns(interface):
    def sniff_callback(packet):
        if packet.haslayer(DNSQR):
            request = packet.getlayer(DNSQR)
            if request.qtype == 1:
                domain = request.qname.strip('.')
                parts = domain.split('.')
                for i in xrange(0, len(parts) - 1):
                    _ = '.'.join(parts[i:])
                    if _ in _domains:
                        print _trim_output(OUTPUT_FORMAT.format(packet.getlayer(IP).src, _, time.strftime("%d/%m/%y %H:%M:%S"), _domains[_][0], _domains[_][1]))
                        break

    try:
        print "[i] inspecting DNS traffic...\n"
        _ = _trim_output(OUTPUT_FORMAT.format("ip", "domain lookup", "time", "type", "reference"))
        print "%s\n%s\n%s" % ("-" * len(_), _, "-" * len(_))
        sniff(iface=interface, prn=sniff_callback, filter="udp dst port 53", store=0)
    except KeyboardInterrupt:
        print "\r[x] Ctrl-C pressed"
    except socket.error, ex:
        if "permitted" in str(ex):
            exit("\n[x] please run with sudo/Administrator privileges")
        elif "No such device" in str(ex):
            exit("\n[x] no such device '%s'" % interface)
        else:
            raise

if __name__ == "__main__":
    print "%s #v%s\n by: %s\n" % (NAME, VERSION, AUTHOR)
    parser = optparse.OptionParser(version=VERSION)
    parser.add_option("-i", dest="interface", help="listen DNS traffic on interface (e.g. eth0)")
    parser.add_option("-l", dest="custom", help="custom domain list file (optional)")
    options, _ = parser.parse_args()
    if options.interface:
        _check_sudo()
        load_domains(options.custom)
        inspect_dns(options.interface)
    else:
        parser.print_help()
