MalTrail
============

**MalTrail** is a malicious traffic monitoring tool originally designed for malware tracking purposes, utilizing publicly available specialized lists for malicious (or generally suspicious) domains, URLs and/or IPs. Preferably it should be run on a (Linux) box connected to the router's [port mirroring](http://en.wikipedia.org/wiki/Port_mirroring) interface or [network tap](http://en.wikipedia.org/wiki/Network_tap) device. It uses [Pcapy](http://corelabs.coresecurity.com/index.php?module=Wiki&action=view&type=tool&name=Pcapy) library for sniffing purposes. Also, it runs in multiprocessing mode (depending on # of CPU cores) to maximize the packet processing performance.

![Report](http://i.imgur.com/k7JlIjC.png)

Sample runs
----

```
# python maltrail.py -h
MalTrail #v0.2c
 by: Miroslav Stampar (@stamparm)

Usage: maltrail.py [options]

Options:
  --version     show program's version number and exit
  -h, --help    show this help message and exit
  --quiet       turn off program's console output
  -i INTERFACE  listen DNS traffic on interface (e.g. eth0)
  -r PCAPFILE   read packets from (.pcap) file
  -l BULKFILE   load domain list from file (optional)
```

```
# python maltrail.py -i eth0
MalTrail #v0.2c
 by: Miroslav Stampar (@stamparm)

[i] updating blacklists...
 [o] 'http://cinsscore.com/list/ci-badguys.txt'
 [o] 'http://lists.blocklist.de/lists/all.txt'
 [o] 'https://www.autoshun.org/files/shunlist.csv'
 [o] 'https://check.torproject.org/cgi-bin/TorBulkExitList.py?ip=1.1.1.1'
 [o] 'http://www.openbl.org/lists/base.txt'
 [o] 'http://danger.rulez.sk/projects/bruteforceblocker/blist.php'
 [o] 'https://www.maxmind.com/en/anonymous_proxies'
 [o] 'https://myip.ms/files/blacklist/htaccess/latest_blacklist.txt'
 [o] 'https://openphish.com/feed.txt'
 [o] 'http://www.dshield.org/feeds/suspiciousdomains_High.txt'
 [o] 'http://malc0de.com/rss/'
 [o] 'http://www.malwaredomainlist.com/hostslist/hosts.txt'
 [o] 'http://malwaredomains.lehigh.edu/files/domains.txt'
 [o] 'https://zeustracker.abuse.ch/blocklist.php?download=domainblocklist'
 [o] 'https://rules.emergingthreats.net/open/suricata/rules/emerging-dns.rules'
[i] 10449 blacklisted URL entries loaded
[i] 44089 blacklisted IP entries loaded
[i] 25790 blacklisted DNS entries loaded
[i] starting 3 more processes (4 total)
[i] using address '*:8338' for HTTP reporting
[i] monitoring interface 'eth0'...
```

Requirements
----

[Python](http://www.python.org/download/) version **2.6.x** or **2.7.x** is required for running this program, along with [Pcapy](http://corelabs.coresecurity.com/index.php?module=Wiki&action=view&type=tool&name=Pcapy) and [dpkt](https://code.google.com/p/dpkt/) (e.g. sample installation on Debian-like systems: `sudo apt-get install python-pcapy python-dpkt`).
