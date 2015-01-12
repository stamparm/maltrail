# Maltrail

**Maltrail** is a malicious traffic monitoring tool, utilizing publicly available blacklists containing malicious (or generally suspicious) domains, URLs and IPs. It uses [Pcapy](http://corelabs.coresecurity.com/index.php?module=Wiki&action=view&type=tool&name=Pcapy) library for traffic capturing and [dpkt](https://code.google.com/p/dpkt/) for packet parsing. Also, it runs in multiprocessing mode (depending on # of CPU cores) to maximize the packet processing performance.

![Report](http://i.imgur.com/k7JlIjC.png)

## Sample runs

```
# python maltrail.py -h
Usage: maltrail.py [options]

Options:
  --version     show program's version number and exit
  -h, --help    show this help message and exit
  -i INTERFACE  listen DNS traffic on interface (e.g. eth0)
  -r PCAPFILE   read packets from (.pcap) file
```

```
# python maltrail.py -i eth0
[i] retrieving blacklists...
 [o] 'http://cinsscore.com/list/ci-badguys.txt'
 [o] 'http://lists.blocklist.de/lists/all.txt'
 [o] 'https://www.autoshun.org/files/shunlist.csv'
 [o] 'https://check.torproject.org/cgi-bin/TorBulkExitList.py?ip=1.1.1.1'
 [o] 'http://www.openbl.org/lists/base.txt'
 [o] 'http://rules.emergingthreats.net/open/suricata/rules/compromised-ips.txt'
 [o] 'http://www.nothink.org/blacklist/blacklist_malware_irc.txt'
 [o] 'http://danger.rulez.sk/projects/bruteforceblocker/blist.php'
 [o] 'https://www.maxmind.com/en/anonymous_proxies'
 [o] 'http://malwared.malwaremustdie.org/rss.php'
 [o] 'http://rules.emergingthreats.net/open/suricata/rules/botcc.rules'
 [o] 'https://myip.ms/files/blacklist/htaccess/latest_blacklist.txt'
 [o] 'https://openphish.com/feed.txt'
 [o] 'https://lists.malwarepatrol.net/cgi/getfile?receipt=f1417692233&product=8&list=dansguardian'
 [o] 'http://vxvault.siri-urz.net/URL_List.php'
 [o] 'http://www.dshield.org/feeds/suspiciousdomains_High.txt'
 [o] 'http://malc0de.com/rss/'
 [o] 'http://www.malwaredomainlist.com/hostslist/hosts.txt'
 [o] 'http://malwaredomains.lehigh.edu/files/domains.txt'
 [o] 'https://zeustracker.abuse.ch/blocklist.php?download=domainblocklist'
 [o] 'https://rules.emergingthreats.net/open/suricata/rules/emerging-dns.rules'
[i] 43422 blacklisted URL entries loaded
[i] 41587 blacklisted IP entries loaded
[i] 33284 blacklisted DNS entries loaded
[i] starting 3 more processes (4 CPU cores detected)
[i] using address '*:8338' for HTTP reporting
[i] monitoring interface 'eth0'...
```

## Requirements

[Python](http://www.python.org/download/) version **2.6.x** or **2.7.x** is required for running this program, along with [Pcapy](http://corelabs.coresecurity.com/index.php?module=Wiki&action=view&type=tool&name=Pcapy) and [dpkt](https://code.google.com/p/dpkt/) (e.g. sample installation on Debian-like systems: `sudo apt-get install python-pcapy python-dpkt`).

## License

Maltrail is available under the [MIT license](LICENSE).