import logging, pickle, optparse, os, re, socket, subprocess, tempfile, time, urllib2, zipfile, zlib

NAME, VERSION, AUTHOR, LICENSE = "DNScrutinize", "0.1c", "Miroslav Stampar (@stamparm)", "Public domain (FREE)"

try:
    logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

    from scapy.all import *
except ImportError:
    exit("[!] please install Scapy (e.g. '%s')" % ("sudo apt-get install scapy" if not subprocess.mswindows else "http://www.secdev.org/projects/scapy/doc/installation.html#windows"))

TIMEOUT = 30
FRESH_LISTS_DELTA_DAYS = 2
DOMAINS_FILE = "domains.bin"
OUTPUT_FORMAT = "|{0:^16}|{1:^19s}|{2:^40s}|{3:^15s}|{4:^20s}|"

MALWAREDOMAINLIST_URL = "http://www.malwaredomainlist.com/hostslist/hosts.txt"
MALWAREDOMAINS_URL = "http://malwaredomains.lehigh.edu/files/domains.txt"
ZEUS_ABUSECH_URL = "https://zeustracker.abuse.ch/blocklist.php?download=domainblocklist"

_domains = {}

def _retrieve_content(url, data=None):
    try:
        req = urllib2.Request("".join(url[i].replace(' ', "%20") if i > url.find('?') else url[i] for i in xrange(len(url))), data, {"User-agent": NAME})
        retval = urllib2.urlopen(req, timeout=TIMEOUT).read()
    except Exception, ex:
        retval = ex.read() if hasattr(ex, "read") else getattr(ex, "msg", str())
    return retval or ""

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
        print "[i] %s suspicious domains..." % ("updating" if os.path.isfile(DOMAINS_FILE) else "retrieving")

        content = _retrieve_content(ZEUS_ABUSECH_URL)
        if "ZeuS" not in content:
            print "[!] something went wrong during remote data retrieval ('%s')" % ZEUS_ABUSECH_URL

        for line in content.split('\n'):
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            _domains[line] = ("ZeuS", "abuse.ch")

        content = _retrieve_content(MALWAREDOMAINS_URL)
        if "safebrowsing.clients.google.com" not in content:
            print "[!] something went wrong during remote data retrieval ('%s')" % MALWAREDOMAINS_URL

        for line in content.split('\n'):
            line = line.strip('\r')
            if not line or line.startswith('#'):
                continue
            items = line.split('\t')
            _domains[items[2]] = (items[3], items[4].split('/')[0] if '/' in items[4] else items[4])   # (type, original_reference-why_it_was_listed)

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
        print "[i] loading..."
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
                        print OUTPUT_FORMAT.format(packet.getlayer(IP).src, time.strftime("%d/%m/%y %H:%M:%S"), _, _domains[_][0], _domains[_][1])
                        break

    try:
        print "[i] inspecting DNS traffic...\n"
        _ = OUTPUT_FORMAT.format("source", "datetime", "domain", "type", "reference")
        print "%s\n%s\n%s" % ("-" * len(_), _, "-" * len(_))
        sniff(iface=interface, prn=sniff_callback, filter="udp dst port 53", store=0)
    except KeyboardInterrupt:
        print "\r[x] Ctrl-C pressed"
    except socket.error, ex:
        if "permitted" in str(ex):
            print "\n[x] please run with sudo/Administrator privileges"
        elif "No such device" in str(ex):
            print "\n[x] no such device '%s'" % interface
        else:
            raise

if __name__ == "__main__":
    print "%s #v%s\n by: %s\n" % (NAME, VERSION, AUTHOR)
    parser = optparse.OptionParser(version=VERSION)
    parser.add_option("-i", dest="interface", help="listen DNS traffic on interface (e.g. eth0)")
    parser.add_option("-l", dest="custom", help="custom domain list file (optional)")
    options, _ = parser.parse_args()
    if options.interface:
        load_domains(options.custom)
        inspect_dns(options.interface)
    else:
        parser.print_help()
