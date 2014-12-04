DNScrutinize
============

**DNScrutinize** is a passive DNS monitoring tool designed for malware traffic detection, utilizing publicly available specialized lists for malicious (or generally suspicious) domains: [MDL](http://www.malwaredomainlist.com/hostslist/hosts.txt), [MalwareDomains](http://malwaredomains.lehigh.edu/files/domains.txt) and [abuse.ch](https://zeustracker.abuse.ch/blocklist.php?download=domainblocklist). Preferably it should be run on a box connected to the router's [port mirroring](http://en.wikipedia.org/wiki/Port_mirroring) interface. It uses [Scapy](http://www.secdev.org/projects/scapy/) for sniffing functionality which means that you can expect decent performance.

Sample runs
----

```
$ python dnscrutinize.py -h
DNScrutinize #v0.1b
 by: Miroslav Stampar (@stamparm)

Usage: dnscrutinize.py [options]

Options:
  --version     show program's version number and exit
  -h, --help    show this help message and exit
  -i INTERFACE  listen DNS traffic on interface (e.g. eth0)
  -l LIST_FILE  custom domain list file (optional)
```

Requirements
----

Python v2.6 or v2.7 is required for running this program, along with [Scapy](http://www.secdev.org/projects/scapy/).
