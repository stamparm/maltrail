# Maltrail [![Build Status](https://api.travis-ci.org/stamparm/maltrail.svg?branch=master)](https://api.travis-ci.org/stamparm/maltrail) [![Python 2.6, 2.7](https://img.shields.io/badge/python-2.6,%202.7-blue.svg)](https://www.python.org/) [![Dependencies pcapy](https://img.shields.io/badge/dependencies-pcapy-yellow.svg)](https://github.com/CoreSecurity/pcapy) [![License](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/stamparm/maltrail#license-mit)

## General

**Maltrail** is a malicious traffic monitoring system, utilizing publicly available (black)lists containing malicious (or generally suspicious) trails (i.e. domain names, URLs and/or IPs), along with static trails compiled from various AV reports and custom user defined lists. Also, it has (optional) advanced heuristic mechanisms that can help in discovery of unknown threats (e.g. new malware).

![Reporting tool](http://i.imgur.com/JCarjiR.png)

The following (black)lists (i.e. feeds) are being utilized:

```
asprox, autoshun, bambenekconsultingc2, bambenekconsultingdga,
blocklist, botscout, bruteforceblocker, ciarmy,
cybercrimetracker, dshield, emergingthreatsbot, emergingthreatscip,
malc0de, malwaredomainlist, malwaredomains, malwaremustdie,
malwarepatrol, malwareurlsnormal, maxmind, myip, nothink,
openbl, openphish, palevotracker, torproject, vxvault,
zeustrackerdns, zeustrackerip, zeustrackermonitor, zeustrackerurl,
etc.
```

As of static entries, the trails for the following malicious entities (e.g. malware C&Cs) have been manually included (from various AV reports):

```
alureon, android_stealer, angler, aridviper, axpergle,
babar, balamid, bankpatch, bedep, black_vine, bubnix,
carbanak, careto, casper, chewbacca, cleaver, conficker,
cosmicduke, couponarific, crilock, cryptolocker, cryptowall,
ctblocker, darkhotel, defru, desertfalcon, destory,
dorifel, dorkbot, dridex, dukes, dursg, dyreza,
emotet, equation, evilbunny, expiro, fakeran, fareit,
fbi_ransomware, fiexp, fignotok, fin4, finfisher,
gamarue, gauss, htran, jenxcus, kegotip, kovter,
lollipop, lotus_blossom, luckycat, mariposa, miniduke,
nbot, nettraveler, neurevt, nitol, no-ip, nonbolqu,
nuqel, nwt, nymaim, palevo, pdfjsc, pift, plugx,
powelike, proslikefan, pushdo, ransirac, redoctober,
reveton, russian_doll, sality, sathurbot, scieron,
sefnit, shylock, siesta, simda, sinkhole_kaspersky,
sinkhole_shadowserver, skyper, smsfakesky, snake, snifula,
sofacy, stuxnet, teerac, teslacrypt, torpig,
torrentlocker, unruy, upatre, vawtrak, virut, vobfus,
volatile_cedar, vundo, waterbug, zeroaccess, zlob, etc.
```

## Introduction

Maltrail is based on the **Sensor&lt;-&gt;Server&lt;-&gt;Client** architecture. **Sensor**(s) is a standalone component running on the monitoring node (e.g. Linux box connected to the SPAN/mirroring port) where it "sniffs" the passing traffic for blacklisted items/trails (i.e. domain names, URLs and/or IPs). In case of a positive match, it sends the event details to the (central) **Server** where they are being stored inside the appropriate logging directory (i.e. `LOG_DIRECTORY` described in the *Configuration* section). If **Sensor** is being run on the same machine as **Server** (default configuration), logs are stored directly into the local logging directory. Otherwise, they are being sent via UDP messages to the remote server (i.e. `LOG_SERVER` described in the *Configuration* section).

![Architecture diagram](http://i.imgur.com/ekgKAeZ.png)

**Server**'s primary role is to store the event details and provide backend support for the reporting web application. In default configuration, server and sensor will run on the same machine. So, to prevent potential disruptions in sensor activities, the front-end reporting part is based on the ["Fat client"](https://en.wikipedia.org/wiki/Fat_client) architecture. Events (i.e. log entries) for the chosen (24h) period are transferred to the **Client**, where the reporting web application is solely responsible for the presentation part. Data is sent toward the client in compressed chunks, where they are processed sequentially. The final report is created in a highly condensed form, practically allowing presentation of virtually unlimited number of events.

Note: **Server** component can be skipped altogether, and just use the standalone **Sensor**. In such case, all events would be stored in the local logging directory, while the log entries could be examined either manually or by some CSV reading application.

## User's guide

### Configuration

Server's configuration can be found inside the `maltrail.conf` section `[Server]`:

![Server's configuration](http://i.imgur.com/o0loHDL.png)

Option `HTTP_ADDRESS` contains the web server's listening address (Note: use `0.0.0.0` to listen on all interfaces). Option `HTTP_PORT` contains the web server's listening port. Default listening port is set to `8338`. If option `USE_SSL` is set to `true` then `SSL/TLS` will be used for accessing the web server (e.g. `https://192.168.6.10:8338/`). In that case, option `SSL_PEM` should be pointing to the server's private/cert PEM file. Option `UPDATE_PERIOD` contains the number of seconds between each automatic trails update (Note: default value is set to `86400` (i.e. one day)) by using definitions inside the `trails` directory (Note: both **Sensor** and **Server** take care of the trails update).

Subsection `USERS` contains user's configuration settings. Each user entry constists of the `username:pbkdf2_hash(password):UID:filter_netmask(s)`. Utility `core/pbkdf2.py` is used to calculate the proper `pbkdf2_hash(password)` values. Value `UID` represents the unique user identifier, where it is recommended to use values lower than 1000 for administrative accounts, while higher value for non-administrative accounts. The part `filter_netmask(s)` represents the comma-delimited hard filter(s) that can be used to filter out the shown events depending on the user account(s). Example entries are as follows:

![Configuration users](http://i.imgur.com/HnH7E6S.png)

Sensor's configuration can be found inside the `maltrail.conf` file's section `[Sensor]`:

![Sensor's configuration](http://i.imgur.com/L4i5WD2.png)

If option `USE_MULTIPROCESSING` is set to `true` then all CPU cores will be used. One core will be used only for packet capture (with appropriate affinity, IO priority and nice level settings), while other cores will be used for packet processing. Otherwise, everything will be run on a single core. Option `USE_HEURISTICS` turns on heuristic mechanisms (e.g. `long domain name (suspicious)`, `excessive no such domain name (suspicious)`, `direct .exe download (suspicious)`, etc.), potentially introducing false positives. Option `CAPTURE_BUFFER` presents a total memory (in bytes of percentage of total physical memory) to be used in case of multiprocessing mode for storing packet capture in a ring buffer for further processing by non-capturing processes. Option `MONITOR_INTERFACE` should contain the name of the capturing interface. Use value `any` to capture from all interfaces (if OS supports this). Option `CAPTURE_FILTER` should contain the network capture (tcpdump) filter to skip the uninteresting packets and ease the capturing process. Option `SENSOR_NAME` contains the name that should be appearing inside the events `sensor_name` value, so the event from one sensor could be distinguished from the other. If option `LOG_SERVER` is set, then all events are being sent remotely to the **Server**, otherwise they are stored directly into the logging directory set with option `LOG_DIRECTORY` inside the `[Server]` section. In case that the option `UPDATE_SERVER` is set, then all the trails are being pulled from the given location, otherwise they are being updated from trails definitions located inside the installation itself.

### Sensor

When running the sensor (e.g. `sudo python sensor.py`) for the first time and/or after a longer period of non-running, it will automatically update the trails from trail definitions (Note: stored inside the `trails` directory). After the initialization, it will start monitoring the configured interface (option `MONITOR_INTERFACE` inside the `maltrail.conf`) and write the events to either the configured log directory (option `LOG_DIRECTORY`) or send them remotely to the logging/reporting *Server* (option `LOG_SERVER`).

![Sensor run](http://i.imgur.com/GLev7HJ.png)

Detected events are stored inside the **Server**'s logging directory (i.e. option `LOG_DIRECTORY`) in easy-to-read CSV format (Note: space is used as a delimiter) as single line entries consisting of: `time` `sensor` `src_ip` `src_port` `dst_ip` `dst_port` `proto` `trail_type` `trail` `trail_info` `reference` (e.g. `"2015-10-19 15:48:41.152513" beast 192.168.5.33 32985 8.8.8.8 53 UDP DNS 0000mps.webpreview.dsl.net malicious siteinspector.comodo.com`):

![Sample log](http://i.imgur.com/l8rxe2y.png)

### Server

Same as for **Sensor**, when running the **Server** (e.g. `python server.py`) for the first time and/or after a longer period of non-running, it will automatically update the trails from trail definitions (Note: stored inside the `trails` directory). Its basic function is to store the log entries inside the logging directory (i.e. option `LOG_DIRECTORY`) and provide the web reporting interface for presenting those same entries to the end-user (Note: there is no need install the 3rd party web server packages like Apache):

![Server run](http://i.imgur.com/16MTDXv.png)

When entering the **Server**'s reporting interface (i.e. via the address defined by options `HTTP_ADDRESS` and `HTTP_PORT`), user will be presented with the following authentication dialog. User has to enter the proper credentials that have been set by the server's administrator inside the configuration file `maltrail.conf`:

![User login](http://i.imgur.com/RRedrEF.png)

Once inside, user will be presented with the following reporting interface:

![Reporting interface](http://i.imgur.com/6ZE9oCV.png)

The top part holds a sliding timeline (Note: activated after clicking the current date label and/or the calendar icon ![Calendar icon](http://i.imgur.com/NfNore9.png)) where user can select logs for past events (Note: mouse over event will trigger display of tooltip with number of events for current date). Dates are grouped by months, where 4 months of data are displayed inside the widget itself. However, by using the provided slider (i.e. ![Timeline slider](http://i.imgur.com/SNGVSaP.png)) user can easily access also events from previous months.

![Timeline](http://i.imgur.com/zBPp6wo.png)

Middle part holds a summary of displayed events. `Events` box represents total number of events in a selected 24-hour period, where red line represents IP-based events, blue line represents DNS-based events and yellow line represents URL-based events. `Sources` box represents number of events per top sources in form of a stacked column chart, with total number of sources on top. `Threats` box represents percentage of top threats in form of a pie chart (Note: gray area holds all threats having &lt;1% in total events), with total number of threats on top. `Trails` box represents percentage of top trails in form of a pie chart (Note: gray area holds all trails having &lt;1% in total events), with total number of trails on top.

![Summary](http://i.imgur.com/4aZBBTo.png)

Each of those boxes are active, hence the click on one of those will result with a more detailed graph:

![Detailed boxes](http://i.imgur.com/iGlOdaN.png)

Bottom part holds a condensed representation of logged events in form of a paginated table. Each entry holds details for a single threat (Note: uniquely identified by a pair `src_ip~trail` or `dst_ip~trail` if the `src_ip` is the same as the `trail` - as in case of attacks coming from the outside):

![Single threat](http://i.imgur.com/ftF6icy.png)

Column `threat` holds threat's unique ID (e.g. `85fdb08d`) and color (Note: extruded from the threat's ID), `sensor` holds sensor name(s) where the event has been triggered (e.g. `blitvenica`), `events` holds total number of events for a current threat, `first_seen` holds time of first event in a selected (24h) period (e.g. `06th 08:21:54`), `last_seen` holds time of last event in a selected (24h) period (e.g. `06th 15:21:23`), `src_ip` holds source IP(s) of a threat (e.g. `99.102.41.102`), `src_port` holds source port(s) (e.g. `44556, 44589, 44601`), `dst_ip` holds destination IP(s) (e.g. `213.202.100.28`), `dst_port` holds destination port(s) (e.g. `80 (HTTP)`), `proto` holds protocol(s), (e.g. `TCP`), `trail` holds a blacklist entry that triggered the event(s), info holds more information about the threat/trail (e.g. `attacker` for known attacker's IP addresses or `ipinfo` for known IP information service commonly used by malware during a startup), `reference` holds a source of the blacklisted entry (e.g. `(static)` for static trails or `myip.ms` for a dynamic feed retrieved from that same source) and `tags` holds user defined tags for a given trail (e.g. `APT28`).

When moving mouse over `src_ip` and `dst_ip` table entries, information tooltip is being displayed with detailed WHOIS information (Note: [RIPE](http://www.ripe.net/) is the information provider):

![On mouse over IP](http://i.imgur.com/5XybnY6.png)

Event details (e.g. `src_port`, `dst_port`, `proto`, etc.) that differ inside a same threat entry are condensed in form of a cloud icon (i.e. ![Cloud ellipsis](https://raw.githubusercontent.com/stamparm/maltrail/master/html/images/ellipsis.png)). This is performed to get an usable reporting interface with as less rows as possible. Moving mouse over such icon will result in a display of an information tooltip with all items held (e.g. all port numbers being scanned by `attacker`):

![On mouse over cloud](http://i.imgur.com/ahmQGYJ.png)

When hovering the mouse pointer over the threat's trail for couple of seconds it will result in a frame consisted of results using the trail as a search term performed against [DuckDuckGo](https://duckduckgo.com/) search engine. In lots of cases, this provides basic information about the threat itself, eliminating the need for user to do the manual search for it. In upper right corner of the opened frame window there are two extra buttons. By clicking the first one (i.e. ![New tab icon](https://raw.githubusercontent.com/stamparm/maltrail/master/html/images/newtab.png)), the resulting frame will be opened inside the new browser's tab (or window), while by clicking the second one (i.e. ![Close icon](https://raw.githubusercontent.com/stamparm/maltrail/master/html/images/close.png)) will immediately close the frame (Note: the same action is achieved by moving the mouse pointer outside the frame borders):

![On mouse over trail](http://i.imgur.com/IvDOIt1.png)

## Real-life cases

### Mass scans

Mass scans is a fairly new phenomenon where individuals and/or organizations give themself a right to scan the whole 0.0.0.0/0 IP range (i.e. whole Internet) on a daily basis, with disclaimer where they say that if you don't like it then you should contact them privately to be skipped from future scans. To make stuff worse, organizations as [Shodan](https://www.shodan.io/) give all results freely available (to other attackers) through their search engine. In the following screenshots you'll see details of scans that came from that same organization in one single day.

Here is a reverse DNS lookup of the "attacker"'s address:

![Shodan 1](http://i.imgur.com/0lnXoYj.png)

When hovering the mouse over the `trail` column's content (IP address), you'll be presented with the search results from DuckDuckGo where you'll be able to find more information about the "attacker":

![Shodan 2](http://i.imgur.com/y15UU8S.png)

In the `dst_ip` column, if you have a large organization, you'll be presented with large list of IP addresses affected:
![Shodan 3](http://i.imgur.com/zwYkwxM.pngg)

In the `dst_port` column you'll be able to see all ports that have been affected by such mass scans:

![Shodan 4](http://i.imgur.com/VOKmRTy.png)

In other similar situations you'll see the same behavior, coming from previously blacklisted attacker(s) (in this case by [cinsscore.com](http://cinsscore.com/)):

![Unknown attacker](http://i.imgur.com/ubJjaq7.png)

One more common behavior is scanning of the whole 0.0.0.0/0 IP range (i.e. Internet) in search for one particular port (e.g. TCP port 443 when [Heartbleed](http://heartbleed.com/) has been found). In the following screenshot you'll find one such case for previously blacklisted attacker(s) (in this case by [autoshun.org](http://autoshun.org/)) targeting the TCP port 5060 (i.e. SIP) in search for [misconfigured VoIP devices](https://isc.sans.edu/diary/Targeting+VoIP%3A+Increase+in+SIP+Connections+on+UDP+port+5060/9193):

![SIP scan](http://i.imgur.com/6HmJLGM.png)

### Anonymous attackers

To spot the potential attackers hidden behind the [Tor](https://www.torproject.org/) anonymity network, Maltrail utilizes publicly available list of Tor exit nodes. In the following screenshot you'll see a case where unknown attacker has been utilizing the Tor network to access the web target (over HTTPS) in our organization's range in rather suspicious way (total 599 connection requests in less than 10 minutes):

![Tor attacker](http://i.imgur.com/r9I6udf.png)

### Service attackers

Fairly similar case to the previous one is when previously blacklisted attacker (in this case by [autoshun.org](http://autoshun.org/)) tries to access particular service in our organization's range in rather suspicious way (total 580 connection requests in 15 minutes):

![RDP brute force](http://i.imgur.com/JTYYHRL.png)

If we enter the `SSH attacker` to the `Filter` field, we'll be able to see all similar occurrences for that day, but in this case for port 22 (i.e. SSH):

![SSH attackers filter](http://i.imgur.com/G1W3HrQ.png)

In the following case previously blacklisted attacker (in this case by [autoshun.org](http://autoshun.org/)) has been scanning the whole organization's range in search for potentially vulnerable SSL/HTTPS service(s) (ports 443 and 8443):

![Heartbleed attacker](http://i.imgur.com/F0dG1DT.png)

### Malware

In case of connection attempts coming from infected computers inside our organization toward already known C&C servers, you'll be able to find threats similar to the following (in this case [CTBLocker](http://www.eset.co.uk/Press-Centre/News/Article/CTBLocker-Ransomware-striking-in-Europe-and-Latin-America) ransomware):

![ctblocker malware](http://i.imgur.com/LXalmDr.png)

In the following case file downloads from blacklisted (in this case by [malwarepatrol.net](https://malwarepatrol.net/)) URL(s) have occurred:

![](http://i.imgur.com/ACQOF40.png)

If we enter the particular malware name (in this case [Simda](https://www.us-cert.gov/ncas/alerts/TA15-105A)) into the `Filter` field, only threats that are known to be linked to this malware will be shown (showing you all affected internal computers):

![simda malware](http://i.imgur.com/GixcFUk.png)

More generally, if we enter the `malware` into the `Filter` field, all threats that are known to be triggered by known malware trails (e.g. `IP` addresses) will be shown:

![malware filter](http://i.imgur.com/ufQFgt9.png)

### Suspicious domain lookups

Maltrail uses the static list of TLD domains that are known to be commonly involved in suspicious activities. Most such [TLD](https://en.wikipedia.org/wiki/Top-level_domain) domains are coming from free domain registars (e.g. [Freenom](http://www.freenom.com)), hence they should be under greater scrutiny. In the following screenshot we can find a case where one such TLD domain `.cm` has been used by unknown malware using the [DGA](https://en.wikipedia.org/wiki/Domain_generation_algorithm) algorithm to contact its [C&C](https://www.trendmicro.com/vinfo/us/security/definition/command-and-control-%28c-c%29-server) server(s):

![Suspicious static domains](http://i.imgur.com/5xsvDw1.png)

There are also cases when perfectly valid TLD domains (e.g. `.ru`) are used for suspicious activities, such in this case where the domains are obviously DGA generated by unknown malware:

![Suspicious long domains](http://i.imgur.com/3T5gdgo.png)

Also, Maltrail uses static list of so called "dynamic domains" that are also often used in suspicious activities (e.g. for malware C&C servers that often change the destination's IP addresses):

![Suspicious dynamic domains](http://i.imgur.com/yrXtQ5j.png)

In case of old and/or obsolete malware that sits undetected on organization's infected internal computers, there is often a "phenomenon" where malware continuously tries to contact the long dead C&C server's domain without any DNS resolution. Hence, those kind of (potential) threats will be marked as `excessive no such domain name (suspicious)`:

![Excessive no such domain name](http://i.imgur.com/RYSnVcK.png)

![Flood](http://i.imgur.com/xIVwyw4.png)

### Suspicious ipinfo queries

![](http://i.imgur.com/RaGvvIg.png)

---

![ipinfo filter](http://i.imgur.com/TmBw0Xs.png)

### Suspicious direct .exe downloads

![](http://i.imgur.com/rQqFCV2.png)

### Suspicious HTTP requests

![](http://i.imgur.com/4xbeBF7.png)

### Potential UDP exfiltration (i.e. breach)

![UDP exfiltration 1](http://i.imgur.com/RSrjmO3.png)
![UDP exfiltration 2](http://i.imgur.com/zW1mbsP.png)

### False positives

![Google false positive 1](http://i.imgur.com/wdA1B6O.png)
![Google false positive 2](http://i.imgur.com/l0C3ATK.png)

---

![Suspicious domain false positive](http://i.imgur.com/ZzXGCo4.png)


## Requirements

To properly run the Maltrail, [Python](http://www.python.org/download/) **2.6.x** or **2.7.x** is required, together with [pcapy](http://corelabs.coresecurity.com/index.php?module=Wiki&action=view&type=tool&name=Pcapy) (e.g. `sudo apt-get install python-pcapy`). There are no other requirements, other than to run the **Sensor** component with the administrative/root privileges.

## License (MIT)

Copyright (c) 2014-2015 by Miroslav Stampar. All rights reserved.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
