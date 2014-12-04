DNScrutinize
============

DNScrutinize is a passive DNS traffic analyzer specially designed for malware detection. It uses specialized lists containing malicious domains: [MDL](http://www.malwaredomainlist.com/hostslist/hosts.txt), [MalwareDomains](http://malwaredomains.lehigh.edu/files/domains.txt) and [abuse.ch](https://zeustracker.abuse.ch/blocklist.php?download=domainblocklist).

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
