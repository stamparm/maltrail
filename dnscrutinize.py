import logging, pickle, optparse, os, re, socket, subprocess, sys, tempfile, time, traceback, urllib2, zipfile, zlib

NAME, VERSION, AUTHOR, LICENSE = "DNScrutinize", "0.1h", "Miroslav Stampar (@stamparm)", "Public domain (FREE)"

try:
    logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

    from scapy.all import *
except ImportError:
    exit("[!] please install Scapy (e.g. '%s')" % ("sudo apt-get install scapy" if not subprocess.mswindows else "http://www.secdev.org/projects/scapy/doc/installation.html#windows"))

ROTATING_CHARS = ('\\', '|', '|', '/', '-')
TIMEOUT = 30
FRESH_LISTS_DELTA_DAYS = 2
DOMAINS_FILE = "domains.bin"
OUTPUT_FORMAT = "|{0:^15s}|{1:^40s}|{2:^17s}|{3:^15s}|{4:^21s}|"

MALWAREDOMAINLIST_URL = "http://www.malwaredomainlist.com/hostslist/hosts.txt"
MALWAREDOMAINS_URL = "http://malwaredomains.lehigh.edu/files/domains.txt"
ZEUS_ABUSECH_URL = "https://zeustracker.abuse.ch/blocklist.php?download=domainblocklist"
EMERGING_THREATS_URL = "https://rules.emergingthreats.net/open/suricata/rules/emerging-dns.rules"

_header = None
_console_width = None
_domains = {}
_cached_results = {}

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

def _print_details(ip, domain_lookup, time, type, reference):
    global _header

    if not _header:
        _header = _trim_output(OUTPUT_FORMAT.format("ip", "domain lookup", "time", "type", "reference"))
        print " \n%s\n%s\n%s" % ("-" * len(_header), _header, "-" * len(_header))

    print _trim_output(OUTPUT_FORMAT.format(ip, domain_lookup, time, type, reference))

def load_domains(bulkfile=None):
    """
    Loads suspicious/malicious domain lists
    """

    global _domains

    if bulkfile:
        if not os.path.isfile(bulkfile):
            exit("[x] file '%s' does not exist" % bulkfile)

        content = open(bulkfile, "rb").read()
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

        print " [o] '%s'" % EMERGING_THREATS_URL
        content = _retrieve_content(EMERGING_THREATS_URL)
        if "Emerging Threats" not in content:
            print "[!] something went wrong during remote data retrieval ('%s')" % EMERGING_THREATS_URL

        for match in re.finditer(r"(?i)Suspicious \*?\.([^\s]+) domain", content):
            _domains[match.group(1)] = ("suspicious", "emergingthreats.net")

        for match in re.finditer(r"(?i)C2 Domain \.?([^\s\"]+)", content):
            _domains[match.group(1)] = ("C&C", "emergingthreats.net")

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

        try:
            with open(DOMAINS_FILE, "w+b") as f:
                f.write(zlib.compress(pickle.dumps(_domains)))
        except IOError, ex:
            print "[!] something went wrong during cache file write '%s' ('%s')" % (DOMAINS_FILE, ex)

    if not _domains:
        print "[i] loading cache..."
        with open(DOMAINS_FILE, "rb") as f:
            _domains = pickle.loads(zlib.decompress(f.read()))

    print "[i] %d suspicious domain names loaded" % len(_domains)

def inspect_packet(packet):
    """
    Processes packet and prints formatted result if found to be suspicious/malicious
    """

    if packet.haslayer(DNSQR) and not packet.haslayer(DNSRR):
        request = packet.getlayer(DNSQR)
        if request.qtype == 1:
            result = None
            domain = request.qname.strip('.')

            if domain in _cached_results:
                if _cached_results[domain]:
                    result = True
                    _print_details(packet.getlayer(IP).src, domain, time.strftime("%d/%m/%y %H:%M:%S", time.localtime(_cached_results[domain][0])), _cached_results[domain][1], _cached_results[domain][2])
                else:
                    result = False
            else:
                parts = domain.split('.')
                for i in xrange(0, len(parts) - 1):
                    _ = '.'.join(parts[i:])
                    if _ in _domains:
                        result = True
                        _print_details(packet.getlayer(IP).src, domain, time.strftime("%d/%m/%y %H:%M:%S", time.localtime(packet.time)), _domains[_][0], _domains[_][1])
                        _cached_results[domain] = (packet.time, _domains[_][0], _domains[_][1])
                        break

            if result == False and domain not in _cached_results:
                _cached_results[domain] = None

def process_pcap(pcapfile):
    """
    Reads .pcap file and processes packets from it
    """

    print "[i] reading packets from '%s'..." % pcapfile

    if not os.path.isfile(pcapfile):
        exit("[x] file '%s' does not exist" % pcapfile)
    try:
        packets = PcapReader(pcapfile)
    except Exception, ex:
        if "Not a pcap capture file" in traceback.format_exc():
            ex = "Not a pcap capture file"
        exit("[x] there has been a problem with reading file '%s' ('%s')" % (pcapfile, ex))

    count = 0
    for packet in packets:
        count += 1
        sys.stdout.write('%s\r' % ROTATING_CHARS[count % len(ROTATING_CHARS)])
        inspect_packet(packet)
    if not _header:
        print "[i] no suspicious domain lookups found"

def monitor_interface(interface):
    """
    Sniffs/monitors given interface and processes DNS packets found on it
    """

    print "[i] monitoring interface '%s'..." % interface

    try:
        sniff(iface=interface, prn=inspect_packet, filter="udp dst port 53", store=0)
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
    parser.add_option("-r", dest="pcapfile", help="read packets from (.pcap) file")
    parser.add_option("-l", dest="bulkfile", help="load domain list from file (optional)")
    options, _ = parser.parse_args()
    if any((options.interface, options.pcapfile)):
        if options.interface:
            _check_sudo()
        load_domains(options.bulkfile)
        if options.pcapfile:
            process_pcap(options.pcapfile)
        elif options.interface:
            monitor_interface(options.interface)
        if _header:
            print "-" * len(_header)
    else:
        parser.print_help()
