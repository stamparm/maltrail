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
alureon, android_stealer, aridviper, axpergle, balamid, bankpatch, bedep, bubnix,
carbanak, careto, chewbacca, cleaver, computrace, conficker, cosmicduke,
couponarific, crilock, cryptolocker, cryptowall, ctblocker, cutwail, darkhotel,
defru, desertfalcon, destory, dorifel, dorkbot, drixed, duqu, dursg, dynamic_domain,
dyreza, emotet, equation, expiro, fakeran, fbi_ransomware, fiexp, fignotok, fin4,
finfisher, gamarue, gauss, geodo, gholee, htran, iframeref, jenxcus, kegotip,
kovter, lollipop, luckycat, mariposa, miniduke, nettraveler, neurevt, nitol,
no-ip_malware, nonbolqu, nuqel, nymaim, palevo, pdfjsc, pift, powelike, proslikefan,
pushdo, ransirac, redoctober, regin, reveton, rustock, sality, sathurbot, scieron,
sefnit, shylock, siesta, simda, sinkhole_kaspersky, sinkhole_shadowserver, sirefef,
smsfakesky, snake, snifula, sofacy, stuxnet, superfish, suspicious_domain,
suspicious_ipinfo, teerac, torpig, torrentlocker, tugspay, unruy, upatre, vawtrak,
virut, vobfus, vundo, wiper, zeroaccess, zlob, etc.
```

## Introduction

Maltrail is based on the sensor / server / client architecture. **Sensor**(s) is a standalone component running on the monitoring node (i.e. workstation connected to the SPAN port) where it "sniffs" the passing traffic for blacklisted trails (i.e. domain names, URLs and/or IPs). In case of a positive match, it sends the log event to the (central) server where it is stored inside the appropriate logging directory. If sensor is being run on same machine as server, logs are stored directly into the logging directory, while if it is being run remotelly, it is being sent via UDP to the server.

**Server**'s primary role is to provide backend support for the reporting web application. In most cases, server and sensor will be run on the same machine. So, to prevent potential disruptions, the front-end reporting part is (chosen to be) based on the fat-client architecture. Events (i.e. log entries) for the chosen date are streamed toward the **client**, where the reporting web application is responsible for the presentation part. Data is sent toward the client in compressed chunks, where they are processed sequentially. The final report is created in highly condensed form, practically allowing presentation of unconstrained number of events.

## User's manual

**TODO documentation**

Server's configuration can be found inside the `maltrail.conf` file's section `Server`:

![Configuration server](http://i.imgur.com/o0loHDL.png)

Option `HTTP_ADDRESS` contains the web server's listening address. Use `0.0.0.0` to listen on all interfaces. Option `HTTP_PORT` contains the web server's listening port. Default listening port is set to `8338`. If option `USE_SSL` is set to `true` then `SSL/TLS` will be used for accessing the web server (e.g. https://192.168.6.10:8338/). In that case, option `SSL_PEM` should be pointing to the server's private/cert PEM file. Option `UPDATE_PERIOD` contains the number of seconds between each trail update. Default value is set to `86400` (i.e. one day). Subsection `USERS` is described further in text.

When entering the web server's user interface, user will be presented with the following authentication dialog:

![User login](http://i.imgur.com/kbaLIM9.png)

User has to enter the proper credentials that have been set by the server's administrator inside the configuration file `maltrail.conf`. Example entries are as follows:

![Configuration users](http://i.imgur.com/QN5UD12.png)

Each user entry constists of the `username:pbkdf2_hash(password):UID:filter_netmask(s)`. Utility `core/pbkdf2.py` is used to calculate the proper `pbkdf2_hash(password)` values. Value `UID` represents the unique user identifier, where it is recommended to use values lower than 1000 for administrative accounts, while higher value for non-administrative accounts. The part `filter_netmask(s)` represents the comma-delimited hard filter(s) that can be used to filter out the shown events depending on user account(s).



## Requirements

Installed [Python](http://www.python.org/download/) **2.6.x** or **2.7.x** is required, together with [Pcapy](http://corelabs.coresecurity.com/index.php?module=Wiki&action=view&type=tool&name=Pcapy).

## License

Maltrail is available under the [MIT license](LICENSE).
