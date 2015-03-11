# Maltrail

## General

**Maltrail** is a malicious traffic monitoring system, utilizing publicly available blacklists containing malicious (or generally suspicious) trails (i.e. domain names, URLs and/or IPs), along with static lists compiled from various AV reports.

![Reporting tool](http://i.imgur.com/GHQYQLe.png)

The following blacklists (i.e. feeds) are being utilized:

* http://atrack.h3x.eu/c2
* https://www.autoshun.org/files/shunlist.csv
* http://lists.blocklist.de/lists/all.txt
* http://danger.rulez.sk/projects/bruteforceblocker/blist.php
* http://cinsscore.com/list/ci-badguys.txt
* http://cybercrime-tracker.net/all.php
* http://www.dshield.org/feeds/suspiciousdomains_High.txt
* http://rules.emergingthreats.net/open/suricata/rules/botcc.rules
* http://rules.emergingthreats.net/open/suricata/rules/compromised-ips.txt
* https://rules.emergingthreats.net/open/suricata/rules/emerging-dns.rules
* https://feodotracker.abuse.ch/blocklist/?download=domainblocklist
* https://feodotracker.abuse.ch/blocklist/?download=ipblocklist
* http://malc0de.com/rss/
* http://www.malwaredomainlist.com/hostslist/hosts.txt
* http://malwaredomains.lehigh.edu/files/domains.txt
* http://malwared.malwaremustdie.org/rss.php
* https://lists.malwarepatrol.net/cgi/getfile?receipt=f1417692233&product=8&list=dansguardian
* http://malwareurls.joxeankoret.com/domains.txt
* http://malwareurls.joxeankoret.com/normal.txt
* https://www.maxmind.com/en/anonymous_proxies
* https://myip.ms/files/blacklist/htaccess/latest_blacklist.txt
* http://www.nothink.org/blacklist/blacklist_malware_irc.txt
* http://www.openbl.org/lists/base.txt
* https://openphish.com/feed.txt
* https://palevotracker.abuse.ch/blocklists.php?download=combinedblocklist
* https://check.torproject.org/cgi-bin/TorBulkExitList.py?ip=1.1.1.1
* http://vxvault.siri-urz.net/URL_List.php
* https://zeustracker.abuse.ch/blocklist.php?download=domainblocklist
* https://zeustracker.abuse.ch/blocklist.php?download=badips
* https://zeustracker.abuse.ch/monitor.php?filter=all
* https://zeustracker.abuse.ch/blocklist.php?download=compromised

As of static entries, the trails for the following malicious entries have been manually included (from various AV reports):

```
alureon, android_stealer, aridviper, axpergle, balamid, bankpatch, bedep, bubnix, carbanak, careto,
chewbacca, cleaver, computrace, conficker, cosmicduke, couponarific, crilock, cryptolocker,
cryptowall, ctblocker, cutwail, darkhotel, defru, desertfalcon, destory, dorifel, dorkbot, drixed,
duqu, dursg, dynamic_domain, dyreza, emotet, equation, expiro, fakeran, fbi_ransomware, fiexp,
fignotok, fin4, finfisher, gamarue, gauss, geodo, gholee, htran, iframeref, jenxcus, kegotip, kovter,
lollipop, luckycat, mariposa, miniduke, nettraveler, neurevt, nitol, no-ip_malware, nonbolqu, nuqel,
nymaim, palevo, pdfjsc, pift, powelike, proslikefan, pushdo, ransirac, redoctober, regin, reveton,
rustock, sality, sathurbot, scieron, sefnit, shylock, siesta, simda, sinkhole_kaspersky,
sinkhole_shadowserver, sirefef, smsfakesky, snake, snifula, sofacy, stuxnet, superfish,
suspicious_domain, suspicious_ipinfo, teerac, torpig, torrentlocker, tugspay, unruy, upatre, vawtrak,
virut, vobfus, vundo, wiper, zeroaccess, zlob
```

## Introduction

Maltrail is a system based on the sensor<->server architecture. Sensor(s) is a standalone component running on the monitoring node (i.e. workstation connected to the SPAN port) where it "sniffs" the passing traffic for "trails" (i.e. blacklisted entries). In case of a positive match, it sends the log event to the (central) server where it is stored inside the appropriate logging directory.

**TODO documentation**


## Requirements

Installed [Python](http://www.python.org/download/) **2.6.x** or **2.7.x** is required, together with [Pcapy](http://corelabs.coresecurity.com/index.php?module=Wiki&action=view&type=tool&name=Pcapy).

## License

Maltrail is available under the [MIT license](LICENSE).
