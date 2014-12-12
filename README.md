MalTrail
============

**MalTrail** is a malicious traffic monitoring tool designed for malware tracking purposes, utilizing publicly available specialized lists for malicious (or generally suspicious) domains: [MDL](http://www.malwaredomainlist.com/hostslist/hosts.txt), [MalwareDomains](http://malwaredomains.lehigh.edu/files/domains.txt), [abuse.ch](https://zeustracker.abuse.ch/blocklist.php?download=domainblocklist) and [Emerging Threats](https://rules.emergingthreats.net/open/suricata/rules/emerging-dns.rules). Preferably it should be run on a (Linux) box connected to the router's [port mirroring](http://en.wikipedia.org/wiki/Port_mirroring) interface or [network tap](http://en.wikipedia.org/wiki/Network_tap) device. It uses [Scapy](http://www.secdev.org/projects/scapy/) library for sniffing purposes, which means that you can expect solid performance.

Sample runs
----

```
$ python maltrail.py -h
MalTrail #v0.1h
 by: Miroslav Stampar (@stamparm)

Usage: maltrail.py [options]

Options:
  --version     show program's version number and exit
  -h, --help    show this help message and exit
  -i INTERFACE  listen DNS traffic on interface (e.g. eth0)
  -r PCAPFILE   read packets from (.pcap) file
  -l BULKFILE   load domain list from file (optional)
```

```
$ sudo python maltrail.py -i eth0
MalTrail #v0.1h
 by: Miroslav Stampar (@stamparm)

[i] retrieving domain lists...
 [o] 'http://www.malwaredomainlist.com/hostslist/hosts.txt'
 [o] 'http://malwaredomains.lehigh.edu/files/domains.txt'
 [o] 'https://zeustracker.abuse.ch/blocklist.php?download=domainblocklist'
 [o] 'https://rules.emergingthreats.net/open/suricata/rules/emerging-dns.rules'
[i] 20817 suspicious domain names loaded
[i] monitoring interface 'any'...

-----------------------------------------------------------------------------------------------------------------
|      ip       |             domain lookup              |      time       |     type      |     reference      |
-----------------------------------------------------------------------------------------------------------------
| 192.168.1.13  |                4btc.cc                 |05/12/14 10:57:46|     zeus      |zeustracker.abuse.ch|
| 192.168.1.13  |        qberkwtglfmswhwkhmdh.com        |05/12/14 10:58:40|   pwnedlist   |   pwnedlist.com    |
| 192.168.1.13  |              dajiadai.cn               |05/12/14 10:58:46|    malware    |app.webinspector.com|
| 192.168.1.13  |             www.255668.com             |05/12/14 10:58:53|   malicious   |  www.mwsl.org.cn   |

...
```

Requirements
----

[Python](http://www.python.org/download/) version **2.6.x** or **2.7.x** is required for running this program, along with [Scapy](http://www.secdev.org/projects/scapy/).
