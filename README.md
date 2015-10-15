# Maltrail

## General

**Maltrail** is a malicious traffic monitoring system, utilizing publicly available blacklists containing malicious (or generally suspicious) trails (i.e. domain names, URLs and/or IPs), along with static lists compiled from various AV reports and custom user defined lists.

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

As of static entries, the trails for the following malicious entities have been manually included (from various AV reports):

```
alureon, android_stealer, aridviper, axpergle, balamid, bankpatch, bedep, bubnix,
carbanak, careto, chewbacca, cleaver, computrace, conficker, cosmicduke,
couponarific, crilock, cryptolocker, cryptowall, ctblocker, darkhotel,
defru, desertfalcon, destory, dorifel, dorkbot, dursg, dynamic_domain,
dyreza, emotet, equation, expiro, fakeran, fbi_ransomware, fiexp, fignotok, fin4,
finfisher, gamarue, gauss, htran, jenxcus, kegotip,
kovter, lollipop, luckycat, mariposa, miniduke, nettraveler, neurevt, nitol,
no-ip_malware, nonbolqu, nuqel, nymaim, palevo, pdfjsc, pift, powelike, proslikefan,
pushdo, ransirac, redoctober, reveton, sality, sathurbot, scieron,
sefnit, shylock, siesta, simda, sinkhole_kaspersky, sinkhole_shadowserver,
smsfakesky, snake, snifula, sofacy, stuxnet, superfish, suspicious_domain,
suspicious_ipinfo, teerac, torpig, torrentlocker, unruy, upatre, vawtrak,
virut, vobfus, vundo, zeroaccess, zlob, etc.
```

## Introduction

Maltrail is based on the **Sensor&lt;-&gt;Server&lt;-&gt;Client** architecture. **Sensor**(s) is a standalone component running on the monitoring node (i.e. Linux box connected to the SPAN/mirroring port) where it "sniffs" the passing traffic for blacklisted trails (i.e. domain names, URLs and/or IPs). In case of a positive match, it sends the log event to the (central) server where it is being stored inside the appropriate logging directory (i.e. `LOG_DIRECTORY` described in the *Configuration* section). If sensor is being run on the same machine as server (default configuration), logs are stored directly into the logging directory, otherwise they are being sent via UDP to the remote server (i.e. `LOG_SERVER` described in the *Configuration* section).

![Architecture diagram](http://i.imgur.com/peAztNj.png)

**Server**'s primary role is to provide backend support for the reporting web application. In default configuration, server and sensor will be run on the same machine. So, to prevent potential disruptions in sensor activities, the front-end reporting part is based on the ["Fat client"](https://en.wikipedia.org/wiki/Fat_client) architecture. Events (i.e. log entries) for the chosen (24h) period are streamed toward the **Client**, where the reporting web application is solely responsible for the presentation part. Data is sent toward the client in compressed chunks, where they are processed sequentially. The final report is created in a highly condensed form, practically allowing presentation of virtually unlimited number of events.

## User's manual

### Configuration

Server's configuration can be found inside the `maltrail.conf` file's section `[Server]`:

![Server's configuration](http://i.imgur.com/o0loHDL.png)

Option `HTTP_ADDRESS` contains the web server's listening address. Use `0.0.0.0` to listen on all interfaces. Option `HTTP_PORT` contains the web server's listening port. Default listening port is set to `8338`. If option `USE_SSL` is set to `true` then `SSL/TLS` will be used for accessing the web server (e.g. https://192.168.6.10:8338/). In that case, option `SSL_PEM` should be pointing to the server's private/cert PEM file. Option `UPDATE_PERIOD` contains the number of seconds between each trail update. Default value is set to `86400` (i.e. one day). Subsection `USERS` is described further in text.

 Example entries are as follows:

![Configuration users](http://i.imgur.com/HnH7E6S.png)

Each user entry constists of the `username:pbkdf2_hash(password):UID:filter_netmask(s)`. Utility `core/pbkdf2.py` is used to calculate the proper `pbkdf2_hash(password)` values. Value `UID` represents the unique user identifier, where it is recommended to use values lower than 1000 for administrative accounts, while higher value for non-administrative accounts. The part `filter_netmask(s)` represents the comma-delimited hard filter(s) that can be used to filter out the shown events depending on the user account(s).

Sensor's configuration can be found inside the `maltrail.conf` file's section `[Sensor]`:

![Sensor's configuration](http://i.imgur.com/L4i5WD2.png)

If option `USE_MULTIPROCESSING` is set to `true` then all CPU cores will be used. One core will be used only for packet capture (with appropriate affinity, IO priority and nice level settings), while other cores will be used for packet processing. Otherwise, everything will be run on a single core. Option `USE_HEURISTICS` turns on heuristic mechanisms (e.g. `long domain name (suspicious)`, `excessive no such domain name (suspicious)`, `direct .exe download (suspicious)`, etc.), potentially introducing false positives. Option `CAPTURE_BUFFER` presents a total memory (in bytes of percentage of total physical memory) to be used in case of multiprocessing mode for storing packet capture in a ring buffer for further processing by non-capturing processes. Option `MONITOR_INTERFACE` should contain the name of the capturing interface. Use value `any` to capture from all interfaces (if OS supports this). Option `CAPTURE_FILTER` should contain the network capture (tcpdump) filter to skip the uninteresting packets and ease the capturing process. Option `SENSOR_NAME` contains the name that should be appearing inside the events `sensor_name` value, so the event from one sensor could be distinguished from the other. If option `LOG_SERVER` is set, then all events are being sent remotely to the **Server**, otherwise they are stored directly into the logging directory set with option `LOG_DIRECTORY` inside the `[Server]` section. In case that the option `UPDATE_SERVER` is set, then all the trails are being pulled from the given location, otherwise they are being updated from trails definitions located inside the installation itself.

### Reporting web server

When entering the web server's user interface, user will be presented with the following authentication dialog. User has to enter the proper credentials that have been set by the server's administrator inside the configuration file `maltrail.conf`.

![User login](http://i.imgur.com/kbaLIM9.png)

Once inside, user will be presented with the reporting interface as follows:

![Reporting interface](http://i.imgur.com/utZnwJF.png)

The top part holds a sliding timeline where user can select logs for past events (Note: mouse over event will trigger display of tooltip with number of events for current date):

![Timeline](http://i.imgur.com/IA1eGty.png)

Middle part holds a summary of displayed events. `Events` box represents total number of events in a selected 24-hour period, where red line represents IP-based events, blue line represents DNS-based events and yellow line represents URL-based events. `Sources` box represents number of events per top sources in form of a stacked column chart, with total number of sources on top. `Threats` box represents percentage of top threats in form of a pie chart (Note: gray area holds all threats having &lt;1% in total events), with total number of threats on top. `Trails` box represents percentage of top trails in form of a pie chart (Note: gray area holds all trails having &lt;1% in total events), with total number of trails on top.

![Summary](http://i.imgur.com/4aZBBTo.png)

Each of those boxes are active, hence the click on one of those will result with a more detailed graph:

![Detailed boxes](http://i.imgur.com/iGlOdaN.png)

Bottom part holds a condensed representation of logged events in form of a paginated table. Each entry holds details for a single threat (Note: uniquely identified by a pair `src_ip~trail` or `dst_ip~trail` if the `src_ip` is the same as the `trail` - as in case of attacks coming from the outside):

![Single threat](http://i.imgur.com/hyckzar.png)

Column `threat` holds threat's unique ID (e.g. `85fdb08d`) and color (Note: extruded from the threat's ID), `sensor` holds sensor name(s) where the event has been triggered (e.g. `blitvenica`), `events` holds total number of events for a current threat, `first_seen` holds time of first event in a selected (24h) period (e.g. `06th 08:21:54`), `last_seen` holds time of last event in a selected (24h) period (e.g. `06th 15:21:23`), `src_ip` holds source IP(s) of a threat (e.g. `99.102.41.102`), `src_port` holds source port(s) (e.g. `44556, 44589, 44601`), `dst_ip` holds destination IP(s) (e.g. `213.202.100.28`), `dst_port` holds destination port(s) (e.g. `80 (HTTP)`), `proto` holds protocol(s), (e.g. `TCP`), `trail` holds a blacklist entry that triggered the event(s), info holds more information about the threat/trail (e.g. `attacker` for known attacker's IP addresses or `ipinfo` for known IP information service commonly used by malware during a startup), `reference` holds a source of the blacklisted entry (e.g. `(static)` for static trails or `myip.ms` for a dynamic feed retrieved from that same source) and `tags` holds user defined tags for a given trail (e.g. `APT28`).

When moving mouse over `src_ip` and `dst_ip` table entries, information tooltip is being displayed with detailed WHOIS information:

![On mouse over IP](http://i.imgur.com/QVm3SXL.png)

Event details that differ in a same threat (e.g. `src_port`, `dst_port`, `proto`, etc.) are condensed in form of a cloud icon. Moving mouse over such icon will result in a display of an information tooltip with all held items:

![On mouse over cloud](http://i.imgur.com/nU4ZPHZ.png)

When moving mouse over a threat's trail it will result in a display of search results using the trail performed at [DuckDuckGo](https://duckduckgo.com/) search engine:

![On mouse over trail](http://i.imgur.com/rOnQbuh.png)

## Requirements

Installed [Python](http://www.python.org/download/) **2.6.x** or **2.7.x** is required, together with [Pcapy](http://corelabs.coresecurity.com/index.php?module=Wiki&action=view&type=tool&name=Pcapy).

## License

Maltrail is available under the [MIT license](LICENSE).
