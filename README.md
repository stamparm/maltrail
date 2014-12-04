DNScrutinize
============

**DNScrutinize** is a passive DNS monitoring tool designed for malware traffic detection, utilizing publicly available specialized lists for malicious (or generally suspicious) domains: [MDL](http://www.malwaredomainlist.com/hostslist/hosts.txt), [MalwareDomains](http://malwaredomains.lehigh.edu/files/domains.txt) and [abuse.ch](https://zeustracker.abuse.ch/blocklist.php?download=domainblocklist). Preferably it should be run on a (Linux) box connected to the router's [port mirroring](http://en.wikipedia.org/wiki/Port_mirroring) interface or [network tap](http://en.wikipedia.org/wiki/Network_tap) device. It uses [Scapy](http://www.secdev.org/projects/scapy/) library for sniffing purposes which means that you can expect solid performance.

Sample runs
----

```
$ python dnscrutinize.py -h
DNScrutinize #v0.1c
 by: Miroslav Stampar (@stamparm)

Usage: dnscrutinize.py [options]

Options:
  --version     show program's version number and exit
  -h, --help    show this help message and exit
  -i INTERFACE  listen DNS traffic on interface (e.g. eth0)
  -l CUSTOM     custom domain list file (optional)
```

```
$ sudo python dnscrutinize.py -i eth0
DNScrutinize #v0.1c
 by: Miroslav Stampar (@stamparm)

[i] loading...
[i] 20135 suspicious domain names loaded
[i] inspecting DNS traffic...

--------------------------------------------------------------------------------------------------------------------
|     source     |     datetime      |                 domain                 |     type      |     reference      |
--------------------------------------------------------------------------------------------------------------------
| 192.168.0.103  | 05/12/14 00:16:38 |        qberkwtglfmswhwkhmdh.com        |   pwnedlist   |   pwnedlist.com    |
| 192.168.0.103  | 05/12/14 00:16:51 |              dajiadai.cn               |    malware    |app.webinspector.com|
| 192.168.0.103  | 05/12/14 00:17:40 |              com-vt6.net               |    botnet     | www.spamhaus.org   |
| 192.168.0.103  | 05/12/14 00:18:17 |             www.255668.com             |   malicious   |  www.mwsl.org.cn   |
...
```

Requirements
----

Python v2.6 or v2.7 is required for running this program, along with [Scapy](http://www.secdev.org/projects/scapy/).
