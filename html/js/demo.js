/*
* Copyright (c) 2014-2016 Miroslav Stampar (@stamparm)
* See the file 'LICENSE' for copying permission
*/

function getDemoCSV() {
    return '"2015-03-10 00:16:59.893901" r2d2 100.64.0.212 46704 68.12.104.178 53 UDP IP 100.64.0.212 attacker "blocklist.de (+autoshun.org,atrack.h3x.eu)"\n' +
    '"2015-03-10 00:16:58.893914" c3p0 69.197.148.79 46704 68.12.104.178 53 UDP IP 69.197.148.79 attacker blocklist.de\n' +
    '"2015-03-10 00:16:59.893914" r2d2 69.197.148.79 46704 68.12.104.178 53 UDP IP 69.197.148.79 attacker blocklist.de\n' +
    '"2015-03-10 00:17:33.929339" r2d2 61.240.144.66 60000 68.12.104.178 1900 UDP IP 61.240.144.66 "incoming masscan detected" autoshun.org\n' +
    '"2015-03-10 00:17:33.929327" r2d2 61.240.144.66 60000 68.12.104.178 1900 UDP IP 61.240.144.66 "incoming masscan detected" autoshun.org\n' +
    '"2015-03-10 00:17:55.491309" r2d2 199.217.116.159 5232 68.12.104.178 5060 UDP IP 199.217.116.159 "sipvicious scan" autoshun.org\n' +
    '"2015-03-10 00:17:55.491297" r2d2 199.217.116.159 5232 68.12.104.178 5060 UDP IP 199.217.116.159 "sipvicious scan" autoshun.org\n' +
    '"2015-03-10 00:31:04.649215" r2d2 45.56.80.141 50171 68.12.104.178 8081 TCP IP 45.56.80.141 attacker cinsscore.com\n' +
    '"2015-03-10 00:31:04.649207" r2d2 45.56.80.141 50171 68.12.104.178 8081 TCP IP 45.56.80.141 attacker cinsscore.com\n' +
    '"2015-03-10 00:35:29.020389" r2d2 68.12.104.178 48905 68.12.99.2 53 UDP DNS (tracker.coppersurfer).tk "domain (suspicious)" (static)\n' +
    '"2015-03-10 00:35:29.020391" r2d2 68.12.104.178 48905 68.12.99.2 53 UDP DNS (tracker.coppersurfer).tk "domain (suspicious)" (static)\n' +
    '"2015-03-10 00:35:29.119574" r2d2 68.12.104.178 36015 68.12.99.2 53 UDP DNS (tracker.coppersurfer).tk "domain (suspicious)" (static)\n' +
    '"2015-03-10 00:35:29.119578" r2d2 68.12.104.178 36015 68.12.99.2 53 UDP DNS (tracker.coppersurfer).tk "domain (suspicious)" (static)\n' +
    '"2015-03-10 00:37:49.507741" r2d2 222.186.21.101 6000 68.12.104.178 1433 TCP IP 222.186.21.101 "ssh brute force" autoshun.org\n' +
    '"2015-03-10 00:37:49.507754" r2d2 222.186.21.101 6000 68.12.104.178 1433 TCP IP 222.186.21.101 "ssh brute force" autoshun.org\n' +
    '"2015-03-10 00:41:18.700342" r2d2 58.217.103.4 58352 68.12.104.178 22 TCP IP 58.217.103.4 "brute forcer" danger.rulez.sk\n' +
    '"2015-03-10 00:41:18.700346" r2d2 58.217.103.4 58352 68.12.104.178 22 TCP IP 58.217.103.4 "brute forcer" danger.rulez.sk\n' +
    '"2015-03-10 00:43:11.071573" r2d2 71.6.165.200 47802 68.12.104.178 49152 TCP IP 71.6.165.200 "supermicro bmc password disclosure attempt" autoshun.org\n' +
    '"2015-03-10 00:43:11.071588" r2d2 71.6.165.200 47802 68.12.104.178 49152 TCP IP 71.6.165.200 "supermicro bmc password disclosure attempt" autoshun.org\n' +
    '"2015-03-10 00:43:11.493753" r2d2 68.12.104.178 39091 68.12.99.2 53 UDP DNS (core.speedx).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 00:43:11.493739" r2d2 68.12.104.178 39091 68.12.99.2 53 UDP DNS (core.speedx).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 00:57:09.460932" r2d2 61.240.144.65 60000 68.12.104.178 110 TCP IP 61.240.144.65 "incoming masscan detected" autoshun.org\n' +
    '"2015-03-10 00:57:09.460921" r2d2 61.240.144.65 60000 68.12.104.178 110 TCP IP 61.240.144.65 "incoming masscan detected" autoshun.org\n' +
    '"2015-03-10 01:07:32.659245" r2d2 68.12.104.178 50655 68.12.99.2 53 UDP DNS (computermagic).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 01:07:32.659195" r2d2 68.12.104.178 50655 68.12.99.2 53 UDP DNS (computermagic).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 01:20:33.938536" r2d2 61.240.144.65 60000 68.12.104.178 5900 TCP IP 61.240.144.65 "incoming masscan detected" autoshun.org\n' +
    '"2015-03-10 01:20:33.938520" r2d2 61.240.144.65 60000 68.12.104.178 5900 TCP IP 61.240.144.65 "incoming masscan detected" autoshun.org\n' +
    '"2015-03-10 01:30:21.714726" r2d2 61.240.144.66 60000 68.12.104.178 8009 TCP IP 61.240.144.66 "incoming masscan detected" autoshun.org\n' +
    '"2015-03-10 01:30:21.714731" r2d2 61.240.144.66 60000 68.12.104.178 8009 TCP IP 61.240.144.66 "incoming masscan detected" autoshun.org\n' +
    '"2015-03-10 01:31:01.654092" r2d2 178.162.201.166 27926 68.12.104.178 5060 UDP IP 178.162.201.166 "sipvicious scan" autoshun.org\n' +
    '"2015-03-10 01:31:01.654106" r2d2 178.162.201.166 27926 68.12.104.178 5060 UDP IP 178.162.201.166 "sipvicious scan" autoshun.org\n' +
    '"2015-03-10 01:37:18.510382" r2d2 68.12.104.178 41266 68.12.99.2 53 UDP DNS (tracker.coppersurfer).tk "domain (suspicious)" (static)\n' +
    '"2015-03-10 01:37:18.510378" r2d2 68.12.104.178 41266 68.12.99.2 53 UDP DNS (tracker.coppersurfer).tk "domain (suspicious)" (static)\n' +
    '"2015-03-10 01:37:18.510703" r2d2 68.12.104.178 37135 68.12.99.2 53 UDP DNS (b.ns).tk "domain (suspicious)" (static)\n' +
    '"2015-03-10 01:37:18.510986" r2d2 68.12.104.178 40789 68.12.99.2 53 UDP DNS (a.ns).tk "domain (suspicious)" (static)\n' +
    '"2015-03-10 01:37:18.510707" r2d2 68.12.104.178 37135 68.12.99.2 53 UDP DNS (b.ns).tk "domain (suspicious)" (static)\n' +
    '"2015-03-10 01:37:18.510990" r2d2 68.12.104.178 40789 68.12.99.2 53 UDP DNS (a.ns).tk "domain (suspicious)" (static)\n' +
    '"2015-03-10 01:37:18.511286" r2d2 68.12.104.178 59616 68.12.99.2 53 UDP DNS (c.ns).tk "domain (suspicious)" (static)\n' +
    '"2015-03-10 01:37:18.511291" r2d2 68.12.104.178 59616 68.12.99.2 53 UDP DNS (c.ns).tk "domain (suspicious)" (static)\n' +
    '"2015-03-10 01:37:18.511561" r2d2 68.12.104.178 51155 68.12.99.2 53 UDP DNS (d.ns).tk "domain (suspicious)" (static)\n' +
    '"2015-03-10 01:37:18.511553" r2d2 68.12.104.178 51155 68.12.99.2 53 UDP DNS (d.ns).tk "domain (suspicious)" (static)\n' +
    '"2015-03-10 01:37:18.510703" r2d2 68.12.104.178 37135 68.12.99.2 53 UDP DNS bar(.foo) "domain (suspicious)" (static)\n' +
    '"2015-03-10 01:37:18.510986" r2d2 68.12.104.178 40789 68.12.99.2 53 UDP DNS bar(.foo2) "domain (suspicious)" (static)\n' +
    '"2015-03-10 01:37:18.676654" r2d2 68.12.104.178 58296 68.12.99.2 53 UDP DNS (tracker.coppersurfer).tk "domain (suspicious)" (static)\n' +
    '"2015-03-10 01:37:18.676647" r2d2 68.12.104.178 58296 68.12.99.2 53 UDP DNS (tracker.coppersurfer).tk "domain (suspicious)" (static)\n' +
    '"2015-03-10 01:43:22.420630" r2d2 68.12.104.178 58967 81.2.199.97 53 UDP IP 81.2.199.97 "asprox (malware)" atrack.h3x.eu\n' +
    '"2015-03-10 01:43:22.420688" r2d2 68.12.104.178 58967 81.2.199.97 53 UDP IP 81.2.199.97 "asprox (malware)" atrack.h3x.eu\n' +
    '"2015-03-10 01:48:07.571953" r2d2 68.12.104.178 41787 113.108.80.138 53 UDP IP 113.108.80.138 dnspod (custom)\n' +
    '"2015-03-10 01:48:07.571949" r2d2 68.12.104.178 41787 113.108.80.138 53 UDP IP 113.108.80.138 dnspod (custom)\n' +
    '"2015-03-10 01:56:27.269118" r2d2 115.239.248.2 6000 68.12.104.178 8080 TCP IP 115.239.248.2 "tomcat auth brute force attempt" autoshun.org\n' +
    '"2015-03-10 01:56:27.269140" r2d2 115.239.248.2 6000 68.12.104.178 8080 TCP IP 115.239.248.2 "tomcat auth brute force attempt" autoshun.org\n' +
    '"2015-03-10 02:02:33.780530" r2d2 68.12.104.178 48567 68.12.99.2 53 UDP DNS (chrisonweb.co).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 02:02:33.780533" r2d2 68.12.104.178 48567 68.12.99.2 53 UDP DNS (chrisonweb.co).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 02:12:39.463774" r2d2 68.12.104.178 35728 68.12.99.2 53 UDP DNS (ns8.starbwqinfo).xyz "domain (suspicious)" (static)\n' +
    '"2015-03-10 02:12:39.463770" r2d2 68.12.104.178 35728 68.12.99.2 53 UDP DNS (ns8.starbwqinfo).xyz "domain (suspicious)" (static)\n' +
    '"2015-03-10 02:12:39.468500" r2d2 68.12.104.178 50704 68.12.99.2 53 UDP DNS (ns9.starbwqinfo).xyz "domain (suspicious)" (static)\n' +
    '"2015-03-10 02:12:39.468496" r2d2 68.12.104.178 50704 68.12.99.2 53 UDP DNS (ns9.starbwqinfo).xyz "domain (suspicious)" (static)\n' +
    '"2015-03-10 02:13:01.963309" r2d2 68.12.104.178 40953 68.12.99.2 53 UDP DNS (ns7.starbwqinfo).xyz "domain (suspicious)" (static)\n' +
    '"2015-03-10 02:13:01.963311" r2d2 68.12.104.178 40953 68.12.99.2 53 UDP DNS (ns7.starbwqinfo).xyz "domain (suspicious)" (static)\n' +
    '"2015-03-10 02:23:04.924872" r2d2 68.12.104.178 51739 68.12.99.2 53 UDP DNS (ns5.starbwqinfo).xyz "domain (suspicious)" (static)\n' +
    '"2015-03-10 02:23:04.924878" r2d2 68.12.104.178 51739 68.12.99.2 53 UDP DNS (ns5.starbwqinfo).xyz "domain (suspicious)" (static)\n' +
    '"2015-03-10 02:24:27.547546" r2d2 220.189.205.46 6000 68.12.104.178 1433 TCP IP 220.189.205.46 attacker blocklist.de\n' +
    '"2015-03-10 02:24:27.547542" r2d2 220.189.205.46 6000 68.12.104.178 1433 TCP IP 220.189.205.46 attacker blocklist.de\n' +
    '"2015-03-10 02:38:45.048794" r2d2 222.215.230.105 6000 68.12.104.178 1433 TCP IP 222.215.230.105 attacker cinsscore.com\n' +
    '"2015-03-10 02:38:45.048776" r2d2 222.215.230.105 6000 68.12.104.178 1433 TCP IP 222.215.230.105 attacker cinsscore.com\n' +
    '"2015-03-10 02:38:47.844117" r2d2 198.12.93.194 48857 68.12.104.178 1900 UDP IP 198.12.93.194 abuser openbl.org\n' +
    '"2015-03-10 02:38:47.844115" r2d2 198.12.93.194 48857 68.12.104.178 1900 UDP IP 198.12.93.194 abuser openbl.org\n' +
    '"2015-03-10 02:49:36.735349" r2d2 61.240.144.64 60000 68.12.104.178 11211 TCP IP 61.240.144.64 "incoming masscan detected" autoshun.org\n' +
    '"2015-03-10 02:49:36.735339" r2d2 61.240.144.64 60000 68.12.104.178 11211 TCP IP 61.240.144.64 "incoming masscan detected" autoshun.org\n' +
    '"2015-03-10 02:49:36.957619" r2d2 118.244.154.224 6000 68.12.104.178 3306 TCP IP 118.244.154.224 attacker cinsscore.com\n' +
    '"2015-03-10 02:49:36.957608" r2d2 118.244.154.224 6000 68.12.104.178 3306 TCP IP 118.244.154.224 attacker cinsscore.com\n' +
    '"2015-03-10 02:51:48.629386" r2d2 71.6.167.142 18605 68.12.104.178 2404 TCP IP 71.6.167.142 "supermicro bmc password disclosure attempt" autoshun.org\n' +
    '"2015-03-10 02:51:48.629388" r2d2 71.6.167.142 18605 68.12.104.178 2404 TCP IP 71.6.167.142 "supermicro bmc password disclosure attempt" autoshun.org\n' +
    '"2015-03-10 03:04:47.089840" r2d2 68.12.104.178 46009 68.12.99.2 53 UDP DNS (tracker.coppersurfer).tk "domain (suspicious)" (static)\n' +
    '"2015-03-10 03:04:47.089844" r2d2 68.12.104.178 46009 68.12.99.2 53 UDP DNS (tracker.coppersurfer).tk "domain (suspicious)" (static)\n' +
    '"2015-03-10 03:04:49.183553" r2d2 68.12.104.178 42694 68.12.99.2 53 UDP DNS (tracker.coppersurfer).tk "domain (suspicious)" (static)\n' +
    '"2015-03-10 03:04:49.183567" r2d2 68.12.104.178 42694 68.12.99.2 53 UDP DNS (tracker.coppersurfer).tk "domain (suspicious)" (static)\n' +
    '"2015-03-10 03:16:29.374397" r2d2 61.240.144.64 60000 68.12.104.178 5800 TCP IP 61.240.144.64 "incoming masscan detected" autoshun.org\n' +
    '"2015-03-10 03:16:29.374387" r2d2 61.240.144.64 60000 68.12.104.178 5800 TCP IP 61.240.144.64 "incoming masscan detected" autoshun.org\n' +
    '"2015-03-10 03:35:06.493568" r2d2 106.240.231.227 6000 68.12.104.178 1433 TCP IP 106.240.231.227 attacker cinsscore.com\n' +
    '"2015-03-10 03:35:06.493536" r2d2 106.240.231.227 6000 68.12.104.178 1433 TCP IP 106.240.231.227 attacker cinsscore.com\n' +
    '"2015-03-10 03:41:49.027625" r2d2 68.12.104.178 48853 68.12.99.2 53 UDP DNS (ns0.starbwqinfo).xyz "domain (suspicious)" (static)\n' +
    '"2015-03-10 03:41:49.027623" r2d2 68.12.104.178 48853 68.12.99.2 53 UDP DNS (ns0.starbwqinfo).xyz "domain (suspicious)" (static)\n' +
    '"2015-03-10 03:46:49.257440" r2d2 222.186.21.208 6000 68.12.104.178 2233 TCP IP 222.186.21.208 abuser openbl.org\n' +
    '"2015-03-10 03:46:49.257439" r2d2 222.186.21.208 6000 68.12.104.178 2233 TCP IP 222.186.21.208 abuser openbl.org\n' +
    '"2015-03-10 04:04:52.509654" r2d2 68.12.104.178 43115 81.2.199.97 53 UDP IP 81.2.199.97 "asprox (malware)" atrack.h3x.eu\n' +
    '"2015-03-10 04:04:52.509652" r2d2 68.12.104.178 43115 81.2.199.97 53 UDP IP 81.2.199.97 "asprox (malware)" atrack.h3x.eu\n' +
    '"2015-03-10 04:09:00.247672" r2d2 68.12.104.178 38015 68.12.99.2 53 UDP DNS (tracker.coppersurfer).tk "domain (suspicious)" (static)\n' +
    '"2015-03-10 04:09:00.247675" r2d2 68.12.104.178 38015 68.12.99.2 53 UDP DNS (tracker.coppersurfer).tk "domain (suspicious)" (static)\n' +
    '"2015-03-10 04:09:00.346287" r2d2 68.12.104.178 37027 68.12.99.2 53 UDP DNS (tracker.coppersurfer).tk "domain (suspicious)" (static)\n' +
    '"2015-03-10 04:09:00.346276" r2d2 68.12.104.178 37027 68.12.99.2 53 UDP DNS (tracker.coppersurfer).tk "domain (suspicious)" (static)\n' +
    '"2015-03-10 04:45:32.729467" r2d2 219.239.230.215 1069 68.12.104.178 25 TCP IP 219.239.230.215 "brute forcer" danger.rulez.sk\n' +
    '"2015-03-10 04:45:32.729469" r2d2 219.239.230.215 1069 68.12.104.178 25 TCP IP 219.239.230.215 "brute forcer" danger.rulez.sk\n' +
    '"2015-03-10 04:46:29.578497" r2d2 80.82.64.116 58503 68.12.104.178 8080 TCP IP 80.82.64.116 attacker blocklist.de\n' +
    '"2015-03-10 04:46:29.578504" r2d2 80.82.64.116 58503 68.12.104.178 8080 TCP IP 80.82.64.116 attacker blocklist.de\n' +
    '"2015-03-10 04:53:32.539492" r2d2 93.158.200.116 52668 68.12.104.178 80 TCP IP 93.158.200.116 attacker cinsscore.com\n' +
    '"2015-03-10 04:53:32.539502" r2d2 93.158.200.116 52668 68.12.104.178 80 TCP IP 93.158.200.116 attacker cinsscore.com\n' +
    '"2015-03-10 05:03:36.440467" r2d2 68.12.104.178 46698 68.12.99.2 53 UDP DNS (delight).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 05:03:36.440342" r2d2 68.12.104.178 46698 68.12.99.2 53 UDP DNS (delight).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 05:14:02.401026" r2d2 37.59.205.245 43740 68.12.104.178 19 UDP IP 37.59.205.245 attacker cinsscore.com\n' +
    '"2015-03-10 05:14:02.401061" r2d2 37.59.205.245 43740 68.12.104.178 19 UDP IP 37.59.205.245 attacker cinsscore.com\n' +
    '"2015-03-10 05:16:48.965843" r2d2 184.105.139.108 43372 68.12.104.178 123 UDP IP 184.105.139.108 attacker cinsscore.com\n' +
    '"2015-03-10 05:16:48.965852" r2d2 184.105.139.108 43372 68.12.104.178 123 UDP IP 184.105.139.108 attacker cinsscore.com\n' +
    '"2015-03-10 05:22:43.807181" r2d2 68.12.104.178 48328 113.108.80.138 53 UDP IP 113.108.80.138 dnspod (custom)\n' +
    '"2015-03-10 05:22:43.807186" r2d2 68.12.104.178 48328 113.108.80.138 53 UDP IP 113.108.80.138 dnspod (custom)\n' +
    '"2015-03-10 05:35:56.752008" r2d2 68.12.104.178 46444 68.12.99.2 53 UDP DNS (tracker.coppersurfer).tk "domain (suspicious)" (static)\n' +
    '"2015-03-10 05:35:56.752011" r2d2 68.12.104.178 46444 68.12.99.2 53 UDP DNS (tracker.coppersurfer).tk "domain (suspicious)" (static)\n' +
    '"2015-03-10 05:35:56.838961" r2d2 68.12.104.178 51445 68.12.99.2 53 UDP DNS (tracker.coppersurfer).tk "domain (suspicious)" (static)\n' +
    '"2015-03-10 05:35:56.838963" r2d2 68.12.104.178 51445 68.12.99.2 53 UDP DNS (tracker.coppersurfer).tk "domain (suspicious)" (static)\n' +
    '"2015-03-10 05:42:59.262789" r2d2 68.12.104.178 50913 174.143.25.32 53 UDP IP 174.143.25.32 attacker blocklist.de\n' +
    '"2015-03-10 05:42:59.262793" r2d2 68.12.104.178 50913 174.143.25.32 53 UDP IP 174.143.25.32 attacker blocklist.de\n' +
    '"2015-03-10 05:45:20.838814" r2d2 61.240.144.65 60000 68.12.104.178 1723 TCP IP 61.240.144.65 "incoming masscan detected" autoshun.org\n' +
    '"2015-03-10 05:45:20.838826" r2d2 61.240.144.65 60000 68.12.104.178 1723 TCP IP 61.240.144.65 "incoming masscan detected" autoshun.org\n' +
    '"2015-03-10 06:07:01.226277" r2d2 68.12.104.178 46031 113.108.80.138 53 UDP IP 113.108.80.138 dnspod (custom)\n' +
    '"2015-03-10 06:07:01.226275" r2d2 68.12.104.178 46031 113.108.80.138 53 UDP IP 113.108.80.138 dnspod (custom)\n' +
    '"2015-03-10 06:07:33.576164" r2d2 61.240.144.64 60000 68.12.104.178 3389 TCP IP 61.240.144.64 "incoming masscan detected" autoshun.org\n' +
    '"2015-03-10 06:07:33.576138" r2d2 61.240.144.64 60000 68.12.104.178 3389 TCP IP 61.240.144.64 "incoming masscan detected" autoshun.org\n' +
    '"2015-03-10 06:10:24.168513" r2d2 222.186.21.208 6000 68.12.104.178 2233 TCP IP 222.186.21.208 abuser openbl.org\n' +
    '"2015-03-10 06:10:24.168624" r2d2 222.186.21.208 6000 68.12.104.178 2233 TCP IP 222.186.21.208 abuser openbl.org\n' +
    '"2015-03-10 06:13:02.217618" r2d2 68.12.104.178 41404 68.12.99.2 53 UDP DNS (infinitypositive).xyz "domain (suspicious)" (static)\n' +
    '"2015-03-10 06:13:02.217631" r2d2 68.12.104.178 41404 68.12.99.2 53 UDP DNS (infinitypositive).xyz "domain (suspicious)" (static)\n' +
    '"2015-03-10 06:16:06.042687" r2d2 202.105.183.89 20076 68.12.104.178 1433 TCP IP 202.105.183.89 attacker cinsscore.com\n' +
    '"2015-03-10 06:16:06.042676" r2d2 202.105.183.89 20076 68.12.104.178 1433 TCP IP 202.105.183.89 attacker cinsscore.com\n' +
    '"2015-03-10 06:20:19.247584" r2d2 68.12.104.178 39482 68.12.99.2 53 UDP DNS (ns9.starbwqinfo).xyz "domain (suspicious)" (static)\n' +
    '"2015-03-10 06:20:19.247587" r2d2 68.12.104.178 39482 68.12.99.2 53 UDP DNS (ns9.starbwqinfo).xyz "domain (suspicious)" (static)\n' +
    '"2015-03-10 06:20:19.252673" r2d2 68.12.104.178 39771 68.12.99.2 53 UDP DNS (ns8.starbwqinfo).xyz "domain (suspicious)" (static)\n' +
    '"2015-03-10 06:20:19.252688" r2d2 68.12.104.178 39771 68.12.99.2 53 UDP DNS (ns8.starbwqinfo).xyz "domain (suspicious)" (static)\n' +
    '"2015-03-10 06:20:41.684338" r2d2 68.12.104.178 35046 68.12.99.2 53 UDP DNS (ns7.starbwqinfo).xyz "domain (suspicious)" (static)\n' +
    '"2015-03-10 06:20:41.684327" r2d2 68.12.104.178 35046 68.12.99.2 53 UDP DNS (ns7.starbwqinfo).xyz "domain (suspicious)" (static)\n' +
    '"2015-03-10 06:23:53.989498" r2d2 68.12.104.178 35751 68.12.99.2 53 UDP DNS (easydirectory).tk "domain (suspicious)" (static)\n' +
    '"2015-03-10 06:23:53.989850" r2d2 68.12.104.178 49229 68.12.99.2 53 UDP DNS (a.ns).tk "domain (suspicious)" (static)\n' +
    '"2015-03-10 06:23:53.989496" r2d2 68.12.104.178 35751 68.12.99.2 53 UDP DNS (easydirectory).tk "domain (suspicious)" (static)\n' +
    '"2015-03-10 06:23:53.990121" r2d2 68.12.104.178 46700 68.12.99.2 53 UDP DNS (b.ns).tk "domain (suspicious)" (static)\n' +
    '"2015-03-10 06:23:53.990359" r2d2 68.12.104.178 36087 68.12.99.2 53 UDP DNS (c.ns).tk "domain (suspicious)" (static)\n' +
    '"2015-03-10 06:23:53.989826" r2d2 68.12.104.178 49229 68.12.99.2 53 UDP DNS (a.ns).tk "domain (suspicious)" (static)\n' +
    '"2015-03-10 06:23:53.990641" r2d2 68.12.104.178 42595 68.12.99.2 53 UDP DNS (d.ns).tk "domain (suspicious)" (static)\n' +
    '"2015-03-10 06:23:53.990123" r2d2 68.12.104.178 46700 68.12.99.2 53 UDP DNS (b.ns).tk "domain (suspicious)" (static)\n' +
    '"2015-03-10 06:23:53.990361" r2d2 68.12.104.178 36087 68.12.99.2 53 UDP DNS (c.ns).tk "domain (suspicious)" (static)\n' +
    '"2015-03-10 06:23:53.990638" r2d2 68.12.104.178 42595 68.12.99.2 53 UDP DNS (d.ns).tk "domain (suspicious)" (static)\n' +
    '"2015-03-10 06:24:55.043108" r2d2 213.144.202.125 58947 68.12.104.178 22 TCP IP 213.144.202.125 abuser openbl.org\n' +
    '"2015-03-10 06:24:55.043112" r2d2 213.144.202.125 58947 68.12.104.178 22 TCP IP 213.144.202.125 abuser openbl.org\n' +
    '"2015-03-10 06:24:58.025140" r2d2 213.144.202.125 58947 68.12.104.178 22 TCP IP 213.144.202.125 abuser openbl.org\n' +
    '"2015-03-10 06:24:58.025118" r2d2 213.144.202.125 58947 68.12.104.178 22 TCP IP 213.144.202.125 abuser openbl.org\n' +
    '"2015-03-10 06:25:41.533001" r2d2 68.12.104.178 38253 81.2.199.97 53 UDP IP 81.2.199.97 "asprox (malware)" atrack.h3x.eu\n' +
    '"2015-03-10 06:25:41.532669" r2d2 68.12.104.178 47869 81.2.199.97 53 UDP IP 81.2.199.97 "asprox (malware)" atrack.h3x.eu\n' +
    '"2015-03-10 06:25:41.533007" r2d2 68.12.104.178 38253 81.2.199.97 53 UDP IP 81.2.199.97 "asprox (malware)" atrack.h3x.eu\n' +
    '"2015-03-10 06:25:41.533758" r2d2 68.12.104.178 47667 81.2.199.97 53 UDP IP 81.2.199.97 "asprox (malware)" atrack.h3x.eu\n' +
    '"2015-03-10 06:25:41.534068" r2d2 68.12.104.178 39153 81.2.199.97 53 UDP IP 81.2.199.97 "asprox (malware)" atrack.h3x.eu\n' +
    '"2015-03-10 06:25:41.532700" r2d2 68.12.104.178 47869 81.2.199.97 53 UDP IP 81.2.199.97 "asprox (malware)" atrack.h3x.eu\n' +
    '"2015-03-10 06:25:41.533754" r2d2 68.12.104.178 47667 81.2.199.97 53 UDP IP 81.2.199.97 "asprox (malware)" atrack.h3x.eu\n' +
    '"2015-03-10 06:25:41.534072" r2d2 68.12.104.178 39153 81.2.199.97 53 UDP IP 81.2.199.97 "asprox (malware)" atrack.h3x.eu\n' +
    '"2015-03-10 06:30:59.614098" r2d2 68.12.104.178 37510 68.12.99.2 53 UDP DNS (ns5.starbwqinfo).xyz "domain (suspicious)" (static)\n' +
    '"2015-03-10 06:30:59.614106" r2d2 68.12.104.178 37510 68.12.99.2 53 UDP DNS (ns5.starbwqinfo).xyz "domain (suspicious)" (static)\n' +
    '"2015-03-10 06:33:50.168282" r2d2 68.12.104.178 43356 68.12.99.2 53 UDP DNS upperlowstream.ru "zeus (malware)" zeustracker.abuse.ch\n' +
    '"2015-03-10 06:33:50.168285" r2d2 68.12.104.178 43356 68.12.99.2 53 UDP DNS upperlowstream.ru "zeus (malware)" zeustracker.abuse.ch\n' +
    '"2015-03-10 06:40:43.905411" r2d2 115.231.218.23 9091 68.12.104.178 22 TCP IP 115.231.218.23 abuser openbl.org\n' +
    '"2015-03-10 06:40:43.905418" r2d2 115.231.218.23 9091 68.12.104.178 22 TCP IP 115.231.218.23 abuser openbl.org\n' +
    '"2015-03-10 06:40:55.672398" r2d2 68.12.104.178 53062 68.12.99.2 53 UDP DNS (dsds2).germansky.org "domain (suspicious)" (static)\n' +
    '"2015-03-10 06:40:55.672394" r2d2 68.12.104.178 53062 68.12.99.2 53 UDP DNS (dsds2).germansky.org "domain (suspicious)" (static)\n' +
    '"2015-03-10 06:41:10.090053" r2d2 68.12.104.178 51478 68.12.99.2 53 UDP DNS (brightlounge).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 06:41:10.090049" r2d2 68.12.104.178 51478 68.12.99.2 53 UDP DNS (brightlounge).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 06:41:16.932627" r2d2 68.12.104.178 36614 8.8.8.8 53 UDP DNS (brightlounge).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 06:41:16.932616" r2d2 68.12.104.178 36614 8.8.8.8 53 UDP DNS (brightlounge).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 06:43:44.552972" r2d2 68.12.104.178 41630 113.108.80.138 53 UDP IP 113.108.80.138 dnspod (custom)\n' +
    '"2015-03-10 06:43:44.552995" r2d2 68.12.104.178 41630 113.108.80.138 53 UDP IP 113.108.80.138 dnspod (custom)\n' +
    '"2015-03-10 06:45:50.952179" r2d2 68.12.104.178 42439 68.12.99.2 53 UDP DNS bitc1.biz fraud www.spamhaus.org\n' +
    '"2015-03-10 06:45:50.952174" r2d2 68.12.104.178 42439 68.12.99.2 53 UDP DNS bitc1.biz fraud www.spamhaus.org\n' +
    '"2015-03-10 06:49:38.817104" r2d2 68.12.104.178 57694 68.12.99.2 53 UDP DNS (mx.cloudafrica).email "domain (suspicious)" (static)\n' +
    '"2015-03-10 06:49:38.817108" r2d2 68.12.104.178 57694 68.12.99.2 53 UDP DNS (mx.cloudafrica).email "domain (suspicious)" (static)\n' +
    '"2015-03-10 06:49:38.967616" r2d2 68.12.104.178 45063 68.12.99.2 53 UDP DNS (mx01.cloudafrica).email "domain (suspicious)" (static)\n' +
    '"2015-03-10 06:49:38.967613" r2d2 68.12.104.178 45063 68.12.99.2 53 UDP DNS (mx01.cloudafrica).email "domain (suspicious)" (static)\n' +
    '"2015-03-10 06:50:05.570900" r2d2 68.12.104.178 53493 68.12.99.1 80 TCP UA "Lorem \\(test\\) ipsum dolor sit amet, consectetuer adipiscing elit. Aenean commodo ligula eget dolor" "suspicious user-agent" (heuristics)\n' +
    '"2015-03-10 06:50:05.570896" r2d2 68.12.104.178 53493 68.12.99.2 53 UDP DNS gmai.com "fake flash" www.malwaredomains.com\n' +
    '"2015-03-10 06:51:18.268502" r2d2 68.12.104.178 52841 68.12.99.2 53 UDP DNS (topcash).club "domain (suspicious)" (static)\n' +
    '"2015-03-10 06:51:18.268443" r2d2 68.12.104.178 52841 68.12.99.2 53 UDP DNS (topcash).club "domain (suspicious)" (static)\n' +
    '"2015-03-10 06:51:28.316036" r2d2 68.12.104.178 50359 68.12.99.2 53 UDP DNS (iceworld).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 06:51:28.316038" r2d2 68.12.104.178 50359 68.12.99.2 53 UDP DNS (iceworld).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 06:51:28.716900" r2d2 68.12.104.178 40556 8.8.8.8 53 UDP DNS (iceworld).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 06:51:28.716888" r2d2 68.12.104.178 40556 8.8.8.8 53 UDP DNS (iceworld).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 06:51:28.919119" r2d2 68.12.104.178 52700 8.8.4.4 53 UDP DNS (iceworld).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 06:51:28.919115" r2d2 68.12.104.178 52700 8.8.4.4 53 UDP DNS (iceworld).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 06:51:29.326221" r2d2 68.12.104.178 46913 68.12.99.2 53 UDP DNS (iceworld).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 06:51:29.326223" r2d2 68.12.104.178 46913 68.12.99.2 53 UDP DNS (iceworld).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 06:51:53.692017" r2d2 68.12.104.178 42816 68.12.99.2 53 UDP DNS (ns.denali).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 06:51:53.692343" r2d2 68.12.104.178 47994 68.12.99.2 53 UDP DNS (ns.denali).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 06:51:53.692013" r2d2 68.12.104.178 42816 68.12.99.2 53 UDP DNS (ns.denali).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 06:51:53.692348" r2d2 68.12.104.178 47994 68.12.99.2 53 UDP DNS (ns.denali).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 06:52:15.711027" r2d2 68.12.104.178 37000 68.12.99.2 53 UDP DNS (anima).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 06:52:15.711038" r2d2 68.12.104.178 37000 68.12.99.2 53 UDP DNS (anima).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 06:52:19.942554" r2d2 68.12.104.178 59539 68.12.99.2 53 UDP DNS (polin).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 06:52:19.942551" r2d2 68.12.104.178 59539 68.12.99.2 53 UDP DNS (polin).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 06:52:29.081735" r2d2 68.12.104.178 44729 68.12.99.2 53 UDP DNS (brightlounge).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 06:52:29.081732" r2d2 68.12.104.178 44729 68.12.99.2 53 UDP DNS (brightlounge).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 06:53:23.403123" r2d2 68.12.104.178 43313 113.108.80.138 53 UDP IP 113.108.80.138 dnspod (custom)\n' +
    '"2015-03-10 06:53:23.403118" r2d2 68.12.104.178 43313 113.108.80.138 53 UDP IP 113.108.80.138 dnspod (custom)\n' +
    '"2015-03-10 06:54:13.252456" r2d2 68.12.104.178 35606 68.12.99.2 53 UDP DNS (ansari).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 06:54:13.252461" r2d2 68.12.104.178 35606 68.12.99.2 53 UDP DNS (ansari).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 06:55:36.933180" r2d2 68.12.104.178 40303 68.12.99.2 53 UDP DNS (geb).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 06:55:36.933184" r2d2 68.12.104.178 40303 68.12.99.2 53 UDP DNS (geb).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 06:56:41.781078" r2d2 68.12.104.178 45641 68.12.99.2 53 UDP DNS (mx01.ha.epcom).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 06:56:41.781082" r2d2 68.12.104.178 45641 68.12.99.2 53 UDP DNS (mx01.ha.epcom).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 06:56:41.863783" r2d2 68.12.104.178 37928 113.108.80.138 53 UDP IP 113.108.80.138 dnspod (custom)\n' +
    '"2015-03-10 06:56:41.863784" r2d2 68.12.104.178 37928 113.108.80.138 53 UDP IP 113.108.80.138 dnspod (custom)\n' +
    '"2015-03-10 06:56:43.020931" r2d2 68.12.104.178 36533 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 06:56:43.020924" r2d2 68.12.104.178 36533 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 06:57:14.111729" r2d2 68.12.104.178 46006 68.12.99.2 53 UDP DNS pica.banjalucke-ljepotice.ru "palevo (malware)" (static)\n' +
    '"2015-03-10 06:57:14.111734" r2d2 68.12.104.178 46006 68.12.99.2 53 UDP DNS pica.banjalucke-ljepotice.ru "palevo (malware)" (static)\n' +
    '"2015-03-10 06:57:22.308738" r2d2 68.12.104.178 44421 68.12.99.2 53 UDP DNS (pad).installationsafe.net attackpage safebrowsing.clients.google.com\n' +
    '"2015-03-10 06:57:22.308734" r2d2 68.12.104.178 44421 68.12.99.2 53 UDP DNS (pad).installationsafe.net attackpage safebrowsing.clients.google.com\n' +
    '"2015-03-10 06:57:45.128873" r2d2 68.12.104.178 50553 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 06:57:45.128871" r2d2 68.12.104.178 50553 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 06:57:50.113130" r2d2 68.12.104.178 50552 198.58.92.228 53 UDP IP 198.58.92.228 malware cybercrime-tracker.net\n' +
    '"2015-03-10 06:57:50.113144" r2d2 68.12.104.178 50552 198.58.92.228 53 UDP IP 198.58.92.228 malware cybercrime-tracker.net\n' +
    '"2015-03-10 06:58:15.952695" r2d2 68.12.104.178 36581 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 06:58:15.952718" r2d2 68.12.104.178 36581 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 06:58:39.065793" r2d2 68.12.104.178 51249 68.12.99.2 53 UDP DNS (6y).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 06:58:39.065806" r2d2 68.12.104.178 51249 68.12.99.2 53 UDP DNS (6y).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 06:59:01.927476" r2d2 199.189.87.8 5071 68.12.104.178 5060 UDP IP 199.189.87.8 "sipvicious scan" autoshun.org\n' +
    '"2015-03-10 06:59:01.927468" r2d2 199.189.87.8 5071 68.12.104.178 5060 UDP IP 199.189.87.8 "sipvicious scan" autoshun.org\n' +
    '"2015-03-10 06:59:02.586323" r2d2 68.12.104.178 57812 113.108.80.138 53 UDP IP 113.108.80.138 dnspod (custom)\n' +
    '"2015-03-10 06:59:02.586325" r2d2 68.12.104.178 57812 113.108.80.138 53 UDP IP 113.108.80.138 dnspod (custom)\n' +
    '"2015-03-10 06:59:17.561332" r2d2 68.12.104.178 43227 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 06:59:17.561319" r2d2 68.12.104.178 43227 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 06:59:48.406072" r2d2 68.12.104.178 59796 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 06:59:48.406076" r2d2 68.12.104.178 59796 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 07:00:50.010752" r2d2 68.12.104.178 48879 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 07:00:50.010750" r2d2 68.12.104.178 48879 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 07:01:20.726929" r2d2 68.12.104.178 53228 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 07:01:20.726916" r2d2 68.12.104.178 53228 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 07:01:35.289140" r2d2 68.12.104.178 51961 68.12.99.2 53 UDP DNS (bomj).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:01:35.289213" r2d2 68.12.104.178 51961 68.12.99.2 53 UDP DNS (bomj).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:02:00.606951" r2d2 68.12.104.178 46159 68.12.99.2 53 UDP DNS digitalmind.cn "palevo (malware)" palevotracker.abuse.ch\n' +
    '"2015-03-10 07:02:00.606947" r2d2 68.12.104.178 46159 68.12.99.2 53 UDP DNS digitalmind.cn "palevo (malware)" palevotracker.abuse.ch\n' +
    '"2015-03-10 07:02:20.899095" r2d2 68.12.104.178 45504 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 07:02:20.899108" r2d2 68.12.104.178 45504 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 07:02:35.904502" r2d2 68.12.104.178 49650 68.12.99.2 53 UDP DNS (brightlounge).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:02:35.904490" r2d2 68.12.104.178 49650 68.12.99.2 53 UDP DNS (brightlounge).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:02:40.161216" r2d2 68.12.104.178 59356 173.252.223.14 53 UDP IP 173.252.223.14 c&c emergingthreats.net\n' +
    '"2015-03-10 07:02:40.161217" r2d2 68.12.104.178 59356 173.252.223.14 53 UDP IP 173.252.223.14 c&c emergingthreats.net\n' +
    '"2015-03-10 07:02:51.244088" r2d2 68.12.104.178 36351 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 07:02:51.244090" r2d2 68.12.104.178 36351 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 07:03:04.001744" r2d2 68.12.104.178 55751 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 07:03:04.001733" r2d2 68.12.104.178 55751 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 07:03:19.204332" r2d2 68.12.104.178 52947 68.12.99.2 53 UDP DNS (update.drp).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:03:19.204331" r2d2 68.12.104.178 52947 68.12.99.2 53 UDP DNS (update.drp).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:03:23.057534" r2d2 68.12.104.178 43507 68.12.99.2 53 UDP DNS (ns1.smtpblige).tk "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:03:23.057846" r2d2 68.12.104.178 41179 68.12.99.2 53 UDP DNS (ns2.smtpblige).tk "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:03:23.057842" r2d2 68.12.104.178 41179 68.12.99.2 53 UDP DNS (ns2.smtpblige).tk "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:03:23.057536" r2d2 68.12.104.178 43507 68.12.99.2 53 UDP DNS (ns1.smtpblige).tk "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:03:26.460587" r2d2 68.12.104.178 49143 68.12.99.2 53 UDP DNS (rl).ammyy.com malware malwarepatrol.net\n' +
    '"2015-03-10 07:03:26.460591" r2d2 68.12.104.178 49143 68.12.99.2 53 UDP DNS (rl).ammyy.com malware malwarepatrol.net\n' +
    '"2015-03-10 07:03:36.427698" r2d2 68.12.104.178 38449 68.12.99.2 53 UDP DNS (luxcore).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:03:36.427694" r2d2 68.12.104.178 38449 68.12.99.2 53 UDP DNS (luxcore).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:03:36.965413" r2d2 68.12.104.178 38633 68.12.99.2 53 UDP DNS (luxcore).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:03:36.965415" r2d2 68.12.104.178 38633 68.12.99.2 53 UDP DNS (luxcore).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:03:37.211722" r2d2 68.12.104.178 40556 8.8.8.8 53 UDP DNS (luxcore).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:03:37.211725" r2d2 68.12.104.178 40556 8.8.8.8 53 UDP DNS (luxcore).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:03:37.932063" r2d2 68.12.104.178 52700 8.8.4.4 53 UDP DNS (luxcore).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:03:37.932048" r2d2 68.12.104.178 52700 8.8.4.4 53 UDP DNS (luxcore).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:03:51.879020" r2d2 68.12.104.178 54198 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 07:03:51.879024" r2d2 68.12.104.178 54198 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 07:04:06.354620" r2d2 68.12.104.178 57529 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 07:04:06.354624" r2d2 68.12.104.178 57529 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 07:04:07.904405" r2d2 68.12.104.178 39341 68.12.99.2 53 UDP DNS jebena.ananikolic.su "palevo (malware)" (static)\n' +
    '"2015-03-10 07:04:07.904404" r2d2 68.12.104.178 39341 68.12.99.2 53 UDP DNS jebena.ananikolic.su "palevo (malware)" (static)\n' +
    '"2015-03-10 07:04:22.220782" r2d2 68.12.104.178 45640 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 07:04:22.220788" r2d2 68.12.104.178 45640 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 07:04:37.905693" r2d2 68.12.104.178 55201 68.12.99.2 53 UDP DNS peer.pickeklosarske.ru "palevo (malware)" (static)\n' +
    '"2015-03-10 07:04:37.905706" r2d2 68.12.104.178 55201 68.12.99.2 53 UDP DNS peer.pickeklosarske.ru "palevo (malware)" (static)\n' +
    '"2015-03-10 07:04:38.634125" r2d2 68.12.104.178 41040 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 07:04:38.634165" r2d2 68.12.104.178 41040 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 07:04:42.658417" r2d2 68.12.104.178 58414 68.12.99.2 53 UDP DNS (traffix-ads).tk "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:04:42.658420" r2d2 68.12.104.178 58414 68.12.99.2 53 UDP DNS (traffix-ads).tk "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:04:53.873131" r2d2 68.12.104.178 44289 68.12.99.2 53 UDP DNS (update).newstatsdemosrv.com malware malwareurls.joxeankoret.com\n' +
    '"2015-03-10 07:04:53.873133" r2d2 68.12.104.178 44289 68.12.99.2 53 UDP DNS (update).newstatsdemosrv.com malware malwareurls.joxeankoret.com\n' +
    '"2015-03-10 07:04:56.610959" r2d2 68.12.104.178 45273 68.12.99.2 53 UDP DNS (update).onlinegenserv.com malware malwareurls.joxeankoret.com\n' +
    '"2015-03-10 07:04:56.610963" r2d2 68.12.104.178 45273 68.12.99.2 53 UDP DNS (update).onlinegenserv.com malware malwareurls.joxeankoret.com\n' +
    '"2015-03-10 07:04:56.870921" r2d2 68.12.104.178 54342 68.12.99.2 53 UDP DNS (logs).onlinegenserv.com malware malwareurls.joxeankoret.com\n' +
    '"2015-03-10 07:04:56.870932" r2d2 68.12.104.178 54342 68.12.99.2 53 UDP DNS (logs).onlinegenserv.com malware malwareurls.joxeankoret.com\n' +
    '"2015-03-10 07:04:59.206800" r2d2 68.12.104.178 48116 68.12.99.2 53 UDP DNS (logs).newstatsdemosrv.com malware malwareurls.joxeankoret.com\n' +
    '"2015-03-10 07:04:59.206798" r2d2 68.12.104.178 48116 68.12.99.2 53 UDP DNS (logs).newstatsdemosrv.com malware malwareurls.joxeankoret.com\n' +
    '"2015-03-10 07:05:07.921064" r2d2 68.12.104.178 51999 68.12.99.2 53 UDP DNS teske.pornicarke.com "palevo (malware)" (static)\n' +
    '"2015-03-10 07:05:07.921070" r2d2 68.12.104.178 51999 68.12.99.2 53 UDP DNS teske.pornicarke.com "palevo (malware)" (static)\n' +
    '"2015-03-10 07:05:15.456950" r2d2 68.12.104.178 37478 68.12.99.2 53 UDP DNS (beta.ads).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:05:15.456946" r2d2 68.12.104.178 37478 68.12.99.2 53 UDP DNS (beta.ads).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:05:22.844796" r2d2 68.12.104.178 48199 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 07:05:22.844758" r2d2 68.12.104.178 48199 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 07:05:37.935276" r2d2 68.12.104.178 52263 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 07:05:37.935280" r2d2 68.12.104.178 52263 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 07:05:40.243380" r2d2 68.12.104.178 39333 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 07:05:40.243381" r2d2 68.12.104.178 39333 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 07:05:53.602914" r2d2 68.12.104.178 56030 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 07:05:53.602912" r2d2 68.12.104.178 56030 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 07:06:11.071251" r2d2 68.12.104.178 36280 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 07:06:11.071244" r2d2 68.12.104.178 36280 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 07:06:53.081080" r2d2 68.12.104.178 37407 68.12.99.2 53 UDP DNS (tracker.coppersurfer).tk "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:06:53.081081" r2d2 68.12.104.178 37407 68.12.99.2 53 UDP DNS (tracker.coppersurfer).tk "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:06:53.180977" r2d2 68.12.104.178 44333 68.12.99.2 53 UDP DNS (tracker.coppersurfer).tk "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:06:53.180995" r2d2 68.12.104.178 44333 68.12.99.2 53 UDP DNS (tracker.coppersurfer).tk "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:06:54.573570" r2d2 68.12.104.178 52212 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 07:06:54.573568" r2d2 68.12.104.178 52212 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 07:07:07.980807" r2d2 68.12.104.178 35610 68.12.99.2 53 UDP DNS peer.pickeklosarske.ru "palevo (malware)" (static)\n' +
    '"2015-03-10 07:07:07.980803" r2d2 68.12.104.178 35610 68.12.99.2 53 UDP DNS peer.pickeklosarske.ru "palevo (malware)" (static)\n' +
    '"2015-03-10 07:07:12.826914" r2d2 68.12.104.178 41104 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 07:07:12.826919" r2d2 68.12.104.178 41104 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 07:07:25.057958" r2d2 68.12.104.178 45548 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 07:07:25.057947" r2d2 68.12.104.178 45548 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 07:07:43.648386" r2d2 68.12.104.178 58528 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 07:07:43.648382" r2d2 68.12.104.178 58528 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 07:08:03.822813" r2d2 68.12.104.178 58541 68.12.99.2 53 UDP DNS digitalmind.cn "palevo (malware)" palevotracker.abuse.ch\n' +
    '"2015-03-10 07:08:03.822800" r2d2 68.12.104.178 58541 68.12.99.2 53 UDP DNS digitalmind.cn "palevo (malware)" palevotracker.abuse.ch\n' +
    '"2015-03-10 07:08:08.012967" r2d2 68.12.104.178 46573 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 07:08:08.012969" r2d2 68.12.104.178 46573 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 07:08:09.243153" r2d2 68.12.104.178 35660 68.12.99.2 53 UDP DNS counter.yadro.ru "zeroaccess (malware)" (static)\n' +
    '"2015-03-10 07:08:09.243151" r2d2 68.12.104.178 35660 68.12.99.2 53 UDP DNS counter.yadro.ru "zeroaccess (malware)" (static)\n' +
    '"2015-03-10 07:08:24.661896" r2d2 68.12.104.178 43468 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 07:08:24.661895" r2d2 68.12.104.178 43468 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 07:08:45.257373" r2d2 68.12.104.178 36400 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 07:08:45.257358" r2d2 68.12.104.178 36400 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 07:08:54.145145" r2d2 68.12.104.178 58295 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 07:08:54.145147" r2d2 68.12.104.178 58295 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 07:09:16.085372" r2d2 68.12.104.178 56299 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 07:09:16.085370" r2d2 68.12.104.178 56299 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 07:09:38.056575" r2d2 68.12.104.178 45692 68.12.99.2 53 UDP DNS peer.pickeklosarske.ru "palevo (malware)" (static)\n' +
    '"2015-03-10 07:09:38.056573" r2d2 68.12.104.178 45692 68.12.99.2 53 UDP DNS peer.pickeklosarske.ru "palevo (malware)" (static)\n' +
    '"2015-03-10 07:09:45.979392" r2d2 68.12.104.178 54164 68.12.99.2 53 UDP DNS (extratorrent).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:09:45.979397" r2d2 68.12.104.178 54164 68.12.99.2 53 UDP DNS (extratorrent).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:09:45.984568" r2d2 68.12.104.178 44694 68.12.99.2 53 UDP DNS (extratorrent).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:09:45.984571" r2d2 68.12.104.178 44694 68.12.99.2 53 UDP DNS (extratorrent).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:09:53.550134" r2d2 68.12.104.178 55860 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 07:09:53.550131" r2d2 68.12.104.178 55860 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 07:09:54.391551" r2d2 68.12.104.178 44282 68.12.99.2 53 UDP DNS (dict).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:09:54.391553" r2d2 68.12.104.178 44282 68.12.99.2 53 UDP DNS (dict).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:09:57.865193" r2d2 68.12.104.178 37458 68.12.99.2 53 UDP DNS (coppersurfer).tk "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:09:57.865201" r2d2 68.12.104.178 37458 68.12.99.2 53 UDP DNS (coppersurfer).tk "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:10:17.693640" r2d2 68.12.104.178 52480 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 07:10:17.693637" r2d2 68.12.104.178 52480 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 07:10:23.703802" r2d2 68.12.104.178 47102 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 07:10:23.703824" r2d2 68.12.104.178 47102 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 07:10:30.013862" r2d2 68.12.104.178 44505 68.12.99.2 53 UDP DNS barclays.com expiro (static)\n' +
    '"2015-03-10 07:10:30.013861" r2d2 68.12.104.178 44505 68.12.99.2 53 UDP DNS barclays.com expiro (static)\n' +
    '"2015-03-10 07:10:36.214576" r2d2 68.12.104.178 46104 68.12.99.2 53 UDP DNS (emw-filter).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:10:36.214578" r2d2 68.12.104.178 46104 68.12.99.2 53 UDP DNS (emw-filter).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:10:38.086626" r2d2 68.12.104.178 54356 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 07:10:38.086629" r2d2 68.12.104.178 54356 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 07:10:48.521733" r2d2 68.12.104.178 48898 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 07:10:48.521975" r2d2 68.12.104.178 48898 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 07:11:24.263531" r2d2 68.12.104.178 47816 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 07:11:24.263534" r2d2 68.12.104.178 47816 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 07:11:50.130944" r2d2 68.12.104.178 35724 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 07:11:50.130943" r2d2 68.12.104.178 35724 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 07:11:53.874217" r2d2 68.12.104.178 48555 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 07:11:53.874247" r2d2 68.12.104.178 48555 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 07:12:08.131507" r2d2 68.12.104.178 51080 68.12.99.2 53 UDP DNS peer.pickeklosarske.ru "palevo (malware)" (static)\n' +
    '"2015-03-10 07:12:08.131526" r2d2 68.12.104.178 51080 68.12.99.2 53 UDP DNS peer.pickeklosarske.ru "palevo (malware)" (static)\n' +
    '"2015-03-10 07:12:20.958707" r2d2 68.12.104.178 42373 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 07:12:20.958882" r2d2 68.12.104.178 42373 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 07:12:53.166353" r2d2 68.12.104.178 37237 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 07:12:53.166355" r2d2 68.12.104.178 37237 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 07:12:57.004860" r2d2 68.12.104.178 49838 68.12.99.2 53 UDP DNS (brightlounge).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:12:57.004848" r2d2 68.12.104.178 49838 68.12.99.2 53 UDP DNS (brightlounge).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:13:08.150853" r2d2 68.12.104.178 35586 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 07:13:08.150850" r2d2 68.12.104.178 35586 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 07:13:19.975581" r2d2 68.12.104.178 36719 68.12.99.2 53 UDP DNS (update.drp).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:13:19.975576" r2d2 68.12.104.178 36719 68.12.99.2 53 UDP DNS (update.drp).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:13:22.567495" r2d2 68.12.104.178 47251 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 07:13:22.567494" r2d2 68.12.104.178 47251 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 07:13:23.477810" r2d2 68.12.104.178 44488 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 07:13:23.477813" r2d2 68.12.104.178 44488 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 07:13:42.699360" r2d2 68.12.104.178 50627 62.76.44.111 53 UDP IP 62.76.44.111 malware cybercrime-tracker.net\n' +
    '"2015-03-10 07:13:42.699364" r2d2 68.12.104.178 50627 62.76.44.111 53 UDP IP 62.76.44.111 malware cybercrime-tracker.net\n' +
    '"2015-03-10 07:13:53.395741" r2d2 68.12.104.178 52589 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 07:13:53.395744" r2d2 68.12.104.178 52589 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 07:14:11.994026" r2d2 68.12.104.178 45875 68.12.99.2 53 UDP DNS digitalmind.cn "palevo (malware)" palevotracker.abuse.ch\n' +
    '"2015-03-10 07:14:11.994023" r2d2 68.12.104.178 45875 68.12.99.2 53 UDP DNS digitalmind.cn "palevo (malware)" palevotracker.abuse.ch\n' +
    '"2015-03-10 07:14:22.568775" r2d2 68.12.104.178 43603 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 07:14:22.568778" r2d2 68.12.104.178 43603 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 07:14:24.929582" r2d2 68.12.104.178 44688 113.108.80.138 53 UDP IP 113.108.80.138 dnspod (custom)\n' +
    '"2015-03-10 07:14:24.929585" r2d2 68.12.104.178 44688 113.108.80.138 53 UDP IP 113.108.80.138 dnspod (custom)\n' +
    '"2015-03-10 07:14:35.787501" r2d2 68.12.104.178 59208 68.12.99.2 53 UDP DNS (ns1.e-terra).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:14:35.787932" r2d2 68.12.104.178 46399 68.12.99.2 53 UDP DNS (ns2.e-terra).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:14:35.787498" r2d2 68.12.104.178 59208 68.12.99.2 53 UDP DNS (ns1.e-terra).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:14:35.787930" r2d2 68.12.104.178 46399 68.12.99.2 53 UDP DNS (ns2.e-terra).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:14:38.634571" r2d2 68.12.104.178 53437 68.12.99.2 53 UDP DNS peer.pickeklosarske.ru "palevo (malware)" (static)\n' +
    '"2015-03-10 07:14:38.634569" r2d2 68.12.104.178 53437 68.12.99.2 53 UDP DNS peer.pickeklosarske.ru "palevo (malware)" (static)\n' +
    '"2015-03-10 07:14:51.850395" r2d2 68.12.104.178 58258 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 07:14:51.850398" r2d2 68.12.104.178 58258 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 07:14:55.012557" r2d2 68.12.104.178 57979 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 07:14:55.012560" r2d2 68.12.104.178 57979 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 07:15:08.371500" r2d2 68.12.104.178 59001 68.12.99.2 53 UDP DNS teske.pornicarke.com "palevo (malware)" (static)\n' +
    '"2015-03-10 07:15:08.371496" r2d2 68.12.104.178 59001 68.12.99.2 53 UDP DNS teske.pornicarke.com "palevo (malware)" (static)\n' +
    '"2015-03-10 07:15:25.860635" r2d2 68.12.104.178 39540 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 07:15:25.860634" r2d2 68.12.104.178 39540 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 07:15:36.364223" r2d2 68.12.104.178 54423 68.12.99.2 53 UDP DNS (im1.xlab).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:15:36.364225" r2d2 68.12.104.178 54423 68.12.99.2 53 UDP DNS (im1.xlab).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:15:38.360420" r2d2 68.12.104.178 57825 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 07:15:38.360800" r2d2 68.12.104.178 57825 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 07:15:51.941041" r2d2 68.12.104.178 48544 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 07:15:51.941043" r2d2 68.12.104.178 48544 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 07:16:21.166580" r2d2 68.12.104.178 52184 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 07:16:21.166581" r2d2 68.12.104.178 52184 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 07:16:27.480392" r2d2 68.12.104.178 48143 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 07:16:27.480390" r2d2 68.12.104.178 48143 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 07:16:51.474534" r2d2 68.12.104.178 52400 68.12.99.2 53 UDP DNS counter.yadro.ru "zeroaccess (malware)" (static)\n' +
    '"2015-03-10 07:16:51.474531" r2d2 68.12.104.178 52400 68.12.99.2 53 UDP DNS counter.yadro.ru "zeroaccess (malware)" (static)\n' +
    '"2015-03-10 07:16:58.338884" r2d2 68.12.104.178 45416 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 07:16:58.338882" r2d2 68.12.104.178 45416 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 07:17:06.607773" r2d2 68.12.104.178 53541 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 07:17:06.607775" r2d2 68.12.104.178 53541 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 07:17:07.059808" r2d2 68.12.104.178 40358 68.12.99.2 53 UDP DNS unioncycler.com fraud www.spamhaus.org\n' +
    '"2015-03-10 07:17:07.059803" r2d2 68.12.104.178 40358 68.12.99.2 53 UDP DNS unioncycler.com fraud www.spamhaus.org\n' +
    '"2015-03-10 07:17:08.585681" r2d2 68.12.104.178 50990 68.12.99.2 53 UDP DNS peer.pickeklosarske.ru "palevo (malware)" (static)\n' +
    '"2015-03-10 07:17:08.585690" r2d2 68.12.104.178 50990 68.12.99.2 53 UDP DNS peer.pickeklosarske.ru "palevo (malware)" (static)\n' +
    '"2015-03-10 07:17:22.774075" r2d2 68.12.104.178 43767 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 07:17:22.774073" r2d2 68.12.104.178 43767 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 07:17:39.034534" r2d2 68.12.104.178 38189 68.12.99.2 53 UDP DNS (tracker.coppersurfer).tk "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:17:39.034538" r2d2 68.12.104.178 38189 68.12.99.2 53 UDP DNS (tracker.coppersurfer).tk "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:17:41.884023" r2d2 68.12.104.178 53244 68.12.99.2 53 UDP DNS (tracker.coppersurfer).tk "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:17:41.884195" r2d2 68.12.104.178 53244 68.12.99.2 53 UDP DNS (tracker.coppersurfer).tk "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:17:52.217604" r2d2 68.12.104.178 40337 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 07:17:52.217600" r2d2 68.12.104.178 40337 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 07:17:59.956760" r2d2 68.12.104.178 47878 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 07:17:59.956765" r2d2 68.12.104.178 47878 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 07:18:08.509993" r2d2 68.12.104.178 45705 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 07:18:08.510005" r2d2 68.12.104.178 45705 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 07:18:28.814160" r2d2 68.12.104.178 57786 68.12.99.2 53 UDP DNS (zdzupanija).dynu.com "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 07:18:28.814162" r2d2 68.12.104.178 57786 68.12.99.2 53 UDP DNS (zdzupanija).dynu.com "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 07:18:30.428365" r2d2 68.12.104.178 41845 68.12.99.2 53 UDP DNS (ns5).nlkoddos.com fraud www.spamhaus.org\n' +
    '"2015-03-10 07:18:30.429061" r2d2 68.12.104.178 42509 68.12.99.2 53 UDP DNS (ns6).nlkoddos.com fraud www.spamhaus.org\n' +
    '"2015-03-10 07:18:30.429078" r2d2 68.12.104.178 42509 68.12.99.2 53 UDP DNS (ns6).nlkoddos.com fraud www.spamhaus.org\n' +
    '"2015-03-10 07:18:30.428363" r2d2 68.12.104.178 41845 68.12.99.2 53 UDP DNS (ns5).nlkoddos.com fraud www.spamhaus.org\n' +
    '"2015-03-10 07:18:30.785236" r2d2 68.12.104.178 35383 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 07:18:30.785226" r2d2 68.12.104.178 35383 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 07:18:51.417393" r2d2 68.12.104.178 54275 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 07:18:51.417398" r2d2 68.12.104.178 54275 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 07:19:16.373469" r2d2 68.12.104.178 56528 68.12.99.2 53 UDP DNS bitc1.biz fraud www.spamhaus.org\n' +
    '"2015-03-10 07:19:16.373465" r2d2 68.12.104.178 56528 68.12.99.2 53 UDP DNS bitc1.biz fraud www.spamhaus.org\n' +
    '"2015-03-10 07:19:20.509754" r2d2 68.12.104.178 55038 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 07:19:20.509728" r2d2 68.12.104.178 55038 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 07:19:20.643841" r2d2 61.240.144.66 60000 68.12.104.178 8081 TCP IP 61.240.144.66 "incoming masscan detected" autoshun.org\n' +
    '"2015-03-10 07:19:20.643837" r2d2 61.240.144.66 60000 68.12.104.178 8081 TCP IP 61.240.144.66 "incoming masscan detected" autoshun.org\n' +
    '"2015-03-10 07:19:32.646943" r2d2 68.12.104.178 45889 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 07:19:32.646944" r2d2 68.12.104.178 45889 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 07:19:36.681422" r2d2 68.12.104.178 37179 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 07:19:36.681436" r2d2 68.12.104.178 37179 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 07:19:38.476934" r2d2 68.12.104.178 44546 68.12.99.2 53 UDP DNS peer.pickeklosarske.ru "palevo (malware)" (static)\n' +
    '"2015-03-10 07:19:38.476932" r2d2 68.12.104.178 44546 68.12.99.2 53 UDP DNS peer.pickeklosarske.ru "palevo (malware)" (static)\n' +
    '"2015-03-10 07:20:03.471885" r2d2 68.12.104.178 47062 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 07:20:03.471883" r2d2 68.12.104.178 47062 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 07:20:19.671221" r2d2 68.12.104.178 39826 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 07:20:19.671217" r2d2 68.12.104.178 39826 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 07:20:21.948193" r2d2 68.12.104.178 52675 68.12.99.2 53 UDP DNS digitalmind.cn "palevo (malware)" palevotracker.abuse.ch\n' +
    '"2015-03-10 07:20:21.948196" r2d2 68.12.104.178 52675 68.12.99.2 53 UDP DNS digitalmind.cn "palevo (malware)" palevotracker.abuse.ch\n' +
    '"2015-03-10 07:20:38.463165" r2d2 68.12.104.178 50055 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 07:20:38.463169" r2d2 68.12.104.178 50055 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 07:20:49.726470" r2d2 68.12.104.178 42595 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 07:20:49.726472" r2d2 68.12.104.178 42595 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 07:21:05.080373" r2d2 68.12.104.178 50780 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 07:21:05.080372" r2d2 68.12.104.178 50780 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 07:21:35.908684" r2d2 68.12.104.178 57456 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 07:21:35.908683" r2d2 68.12.104.178 57456 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 07:21:48.833641" r2d2 68.12.104.178 52098 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 07:21:48.833649" r2d2 68.12.104.178 52098 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 07:21:49.274763" r2d2 68.12.104.178 53952 68.12.99.2 53 UDP DNS (dns4).wanadoo.es attackpage safebrowsing.clients.google.com\n' +
    '"2015-03-10 07:21:49.274760" r2d2 68.12.104.178 53952 68.12.99.2 53 UDP DNS (dns4).wanadoo.es attackpage safebrowsing.clients.google.com\n' +
    '"2015-03-10 07:21:49.345872" r2d2 68.12.104.178 57969 68.12.99.2 53 UDP DNS (inc).wanadoo.es attackpage safebrowsing.clients.google.com\n' +
    '"2015-03-10 07:21:49.345856" r2d2 68.12.104.178 57969 68.12.99.2 53 UDP DNS (inc).wanadoo.es attackpage safebrowsing.clients.google.com\n' +
    '"2015-03-10 07:22:06.755308" r2d2 68.12.104.178 36262 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 07:22:06.755320" r2d2 68.12.104.178 36262 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 07:22:08.500011" r2d2 68.12.104.178 39880 68.12.99.2 53 UDP DNS peer.pickeklosarske.ru "palevo (malware)" (static)\n' +
    '"2015-03-10 07:22:08.500013" r2d2 68.12.104.178 39880 68.12.99.2 53 UDP DNS peer.pickeklosarske.ru "palevo (malware)" (static)\n' +
    '"2015-03-10 07:22:16.361725" r2d2 68.12.104.178 35399 68.12.99.2 53 UDP DNS download.ytdownloader.com malware malwarepatrol.net\n' +
    '"2015-03-10 07:22:16.361723" r2d2 68.12.104.178 35399 68.12.99.2 53 UDP DNS download.ytdownloader.com malware malwarepatrol.net\n' +
    '"2015-03-10 07:22:18.080652" r2d2 68.12.104.178 42683 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 07:22:18.080651" r2d2 68.12.104.178 42683 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 07:22:37.559579" r2d2 68.12.104.178 47128 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 07:22:37.559577" r2d2 68.12.104.178 47128 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 07:23:08.589606" r2d2 68.12.104.178 49930 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 07:23:08.589603" r2d2 68.12.104.178 49930 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 07:23:08.684349" r2d2 68.12.104.178 42704 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 07:23:08.684347" r2d2 68.12.104.178 42704 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 07:23:19.022542" r2d2 68.12.104.178 49611 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 07:23:19.022514" r2d2 68.12.104.178 49611 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 07:23:37.841924" r2d2 68.12.104.178 38753 68.12.99.2 53 UDP DNS (brightlounge).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:23:37.841920" r2d2 68.12.104.178 38753 68.12.99.2 53 UDP DNS (brightlounge).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:23:43.980679" r2d2 68.12.104.178 57355 8.8.8.8 53 UDP DNS (brightlounge).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:23:43.980682" r2d2 68.12.104.178 57355 8.8.8.8 53 UDP DNS (brightlounge).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:23:49.866038" r2d2 68.12.104.178 45002 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 07:23:49.866050" r2d2 68.12.104.178 45002 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 07:23:56.768095" r2d2 68.12.104.178 58266 68.12.99.2 53 UDP DNS (defend).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:23:56.768096" r2d2 68.12.104.178 58266 68.12.99.2 53 UDP DNS (defend).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:24:10.751740" r2d2 68.12.104.178 46082 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 07:24:10.751744" r2d2 68.12.104.178 46082 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 07:24:22.810466" r2d2 68.12.104.178 47191 68.12.99.2 53 UDP DNS nwpolice.org "pushdo (malware)" (static)\n' +
    '"2015-03-10 07:24:22.810478" r2d2 68.12.104.178 47191 68.12.99.2 53 UDP DNS nwpolice.org "pushdo (malware)" (static)\n' +
    '"2015-03-10 07:24:31.462811" r2d2 68.12.104.178 42846 68.12.99.2 53 UDP DNS (tracker.coppersurfer).tk "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:24:31.462809" r2d2 68.12.104.178 42846 68.12.99.2 53 UDP DNS (tracker.coppersurfer).tk "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:24:36.828844" r2d2 68.12.104.178 57321 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 07:24:36.828848" r2d2 68.12.104.178 57321 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 07:24:39.493512" r2d2 68.12.104.178 39986 68.12.99.2 53 UDP DNS peer.pickeklosarske.ru "palevo (malware)" (static)\n' +
    '"2015-03-10 07:24:39.493496" r2d2 68.12.104.178 39986 68.12.99.2 53 UDP DNS peer.pickeklosarske.ru "palevo (malware)" (static)\n' +
    '"2015-03-10 07:24:41.579246" r2d2 68.12.104.178 49926 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 07:24:41.579245" r2d2 68.12.104.178 49926 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 07:24:42.440443" r2d2 68.12.104.178 47618 68.12.99.2 53 UDP DNS (ns2.rhf).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:24:42.440156" r2d2 68.12.104.178 46816 68.12.99.2 53 UDP DNS (ns1.rhf).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:24:42.440445" r2d2 68.12.104.178 47618 68.12.99.2 53 UDP DNS (ns2.rhf).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:24:42.440160" r2d2 68.12.104.178 46816 68.12.99.2 53 UDP DNS (ns1.rhf).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:24:45.889865" r2d2 68.12.104.178 52918 68.12.99.2 53 UDP DNS (browse.dict).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:24:45.889867" r2d2 68.12.104.178 52918 68.12.99.2 53 UDP DNS (browse.dict).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:24:46.157233" r2d2 68.12.104.178 41260 68.12.99.2 53 UDP DNS (www9.dict).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:24:46.157200" r2d2 68.12.104.178 41260 68.12.99.2 53 UDP DNS (www9.dict).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:24:49.994326" r2d2 68.12.104.178 38817 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 07:24:49.994322" r2d2 68.12.104.178 38817 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 07:25:09.607135" r2d2 68.12.104.178 46970 68.12.99.2 53 UDP DNS teske.pornicarke.com "palevo (malware)" (static)\n' +
    '"2015-03-10 07:25:09.607148" r2d2 68.12.104.178 46970 68.12.99.2 53 UDP DNS teske.pornicarke.com "palevo (malware)" (static)\n' +
    '"2015-03-10 07:25:19.898179" r2d2 68.12.104.178 38195 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 07:25:19.898145" r2d2 68.12.104.178 38195 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 07:25:26.540257" r2d2 68.12.104.178 44552 68.12.99.2 53 UDP DNS (extratorrent).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:25:26.540259" r2d2 68.12.104.178 44552 68.12.99.2 53 UDP DNS (extratorrent).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:25:26.545192" r2d2 68.12.104.178 40234 68.12.99.2 53 UDP DNS (extratorrent).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:25:26.545194" r2d2 68.12.104.178 40234 68.12.99.2 53 UDP DNS (extratorrent).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:25:30.834536" r2d2 68.12.104.178 47029 68.12.99.2 53 UDP DNS (dict).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:25:30.834535" r2d2 68.12.104.178 47029 68.12.99.2 53 UDP DNS (dict).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:25:39.485978" r2d2 68.12.104.178 56578 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 07:25:39.485976" r2d2 68.12.104.178 56578 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 07:25:42.633333" r2d2 68.12.104.178 48913 68.12.99.2 53 UDP DNS (warez).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:25:42.633350" r2d2 68.12.104.178 48913 68.12.99.2 53 UDP DNS (warez).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:25:42.913948" r2d2 68.12.104.178 39511 68.12.99.2 53 UDP DNS (warez).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:25:42.913944" r2d2 68.12.104.178 39511 68.12.99.2 53 UDP DNS (warez).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:25:42.973467" r2d2 68.12.104.178 57355 8.8.8.8 53 UDP DNS (warez).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:25:42.973469" r2d2 68.12.104.178 57355 8.8.8.8 53 UDP DNS (warez).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:25:43.156014" r2d2 68.12.104.178 43005 8.8.4.4 53 UDP DNS (warez).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:25:43.156005" r2d2 68.12.104.178 43005 8.8.4.4 53 UDP DNS (warez).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:25:43.188430" r2d2 68.12.104.178 49658 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 07:25:43.188429" r2d2 68.12.104.178 49658 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 07:25:43.302238" r2d2 68.12.104.178 39765 81.2.199.97 53 UDP IP 81.2.199.97 "asprox (malware)" atrack.h3x.eu\n' +
    '"2015-03-10 07:25:43.302240" r2d2 68.12.104.178 39765 81.2.199.97 53 UDP IP 81.2.199.97 "asprox (malware)" atrack.h3x.eu\n' +
    '"2015-03-10 07:25:46.762123" r2d2 68.12.104.178 39430 68.12.99.2 53 UDP DNS (ing).wanadoo.es attackpage safebrowsing.clients.google.com\n' +
    '"2015-03-10 07:25:46.762120" r2d2 68.12.104.178 39430 68.12.99.2 53 UDP DNS (ing).wanadoo.es attackpage safebrowsing.clients.google.com\n' +
    '"2015-03-10 07:26:14.181849" r2d2 68.12.104.178 50474 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 07:26:14.181656" r2d2 68.12.104.178 50474 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 07:26:19.404745" r2d2 68.12.104.178 43416 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 07:26:19.404748" r2d2 68.12.104.178 43416 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 07:26:20.178545" r2d2 68.12.104.178 35856 68.12.99.2 53 UDP DNS (rolxjwzc).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:26:20.178543" r2d2 68.12.104.178 35856 68.12.99.2 53 UDP DNS (rolxjwzc).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:26:20.210688" r2d2 68.12.104.178 47031 68.12.99.2 53 UDP DNS (wafohvuqtka).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:26:20.210686" r2d2 68.12.104.178 47031 68.12.99.2 53 UDP DNS (wafohvuqtka).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:26:20.254868" r2d2 68.12.104.178 37262 38.102.150.29 53 UDP IP 38.102.150.29 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:26:20.254877" r2d2 68.12.104.178 37262 38.102.150.29 53 UDP IP 38.102.150.29 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:26:20.257724" r2d2 68.12.104.178 39608 38.102.150.29 53 UDP IP 38.102.150.29 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:26:20.258158" r2d2 68.12.104.178 54398 38.102.150.29 53 UDP IP 38.102.150.29 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:26:20.257726" r2d2 68.12.104.178 39608 38.102.150.29 53 UDP IP 38.102.150.29 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:26:20.258135" r2d2 68.12.104.178 54398 38.102.150.29 53 UDP IP 38.102.150.29 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:26:20.289242" r2d2 68.12.104.178 37011 38.102.150.29 53 UDP IP 38.102.150.29 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:26:20.289245" r2d2 68.12.104.178 37011 38.102.150.29 53 UDP IP 38.102.150.29 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:26:20.335110" r2d2 68.12.104.178 40564 38.102.150.29 53 UDP IP 38.102.150.29 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:26:20.335108" r2d2 68.12.104.178 40564 38.102.150.29 53 UDP IP 38.102.150.29 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:26:20.429837" r2d2 68.12.104.178 54701 38.229.70.125 53 UDP IP 38.229.70.125 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:26:20.429839" r2d2 68.12.104.178 54701 38.229.70.125 53 UDP IP 38.229.70.125 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:26:27.542102" r2d2 68.12.104.178 37583 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:26:27.542101" r2d2 68.12.104.178 37583 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:26:27.572531" r2d2 68.12.104.178 37798 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:26:27.572542" r2d2 68.12.104.178 37798 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:26:27.838650" r2d2 68.12.104.178 43850 68.12.99.2 53 UDP DNS digitalmind.cn "palevo (malware)" palevotracker.abuse.ch\n' +
    '"2015-03-10 07:26:27.838653" r2d2 68.12.104.178 43850 68.12.99.2 53 UDP DNS digitalmind.cn "palevo (malware)" palevotracker.abuse.ch\n' +
    '"2015-03-10 07:26:34.133871" r2d2 68.12.104.178 39675 117.120.5.218 53 UDP IP 117.120.5.218 abuser openbl.org\n' +
    '"2015-03-10 07:26:34.133869" r2d2 68.12.104.178 39675 117.120.5.218 53 UDP IP 117.120.5.218 abuser openbl.org\n' +
    '"2015-03-10 07:26:34.851539" r2d2 68.12.104.178 56650 38.229.70.125 53 UDP IP 38.229.70.125 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:26:34.851540" r2d2 68.12.104.178 56650 38.229.70.125 53 UDP IP 38.229.70.125 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:26:34.901149" r2d2 68.12.104.178 55223 38.229.70.125 53 UDP IP 38.229.70.125 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:26:34.901182" r2d2 68.12.104.178 55223 38.229.70.125 53 UDP IP 38.229.70.125 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:26:34.914007" r2d2 68.12.104.178 40479 68.12.99.2 53 UDP DNS (cxpveohxx).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:26:34.914010" r2d2 68.12.104.178 40479 68.12.99.2 53 UDP DNS (cxpveohxx).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:26:34.919695" r2d2 68.12.104.178 54959 38.229.70.125 53 UDP IP 38.229.70.125 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:26:34.919698" r2d2 68.12.104.178 54959 38.229.70.125 53 UDP IP 38.229.70.125 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:26:34.941723" r2d2 68.12.104.178 43907 38.229.70.125 53 UDP IP 38.229.70.125 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:26:34.941714" r2d2 68.12.104.178 43907 38.229.70.125 53 UDP IP 38.229.70.125 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:26:42.164519" r2d2 68.12.104.178 48190 68.12.99.2 53 UDP DNS (crbygtjt).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:26:42.164520" r2d2 68.12.104.178 48190 68.12.99.2 53 UDP DNS (crbygtjt).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:26:42.174551" r2d2 68.12.104.178 53333 68.12.99.2 53 UDP DNS (tbivyqyy).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:26:42.174548" r2d2 68.12.104.178 53333 68.12.99.2 53 UDP DNS (tbivyqyy).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:26:42.189801" r2d2 68.12.104.178 41589 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:26:42.189802" r2d2 68.12.104.178 41589 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:26:42.219957" r2d2 68.12.104.178 35737 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:26:42.219959" r2d2 68.12.104.178 35737 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:26:42.238095" r2d2 68.12.104.178 42868 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:26:42.238099" r2d2 68.12.104.178 42868 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:26:42.246016" r2d2 68.12.104.178 46819 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:26:42.246015" r2d2 68.12.104.178 46819 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:26:42.413992" r2d2 68.12.104.178 53446 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:26:42.414007" r2d2 68.12.104.178 53446 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:26:43.811152" r2d2 68.12.104.178 51529 68.12.99.2 53 UDP DNS promisex.ru "zeus (malware)" (custom)\n' +
    '"2015-03-10 07:26:43.811280" r2d2 68.12.104.178 51529 68.12.99.2 53 UDP DNS promisex.ru "zeus (malware)" (custom)\n' +
    '"2015-03-10 07:26:47.167919" r2d2 68.12.104.178 48544 68.12.99.2 53 UDP DNS (palermo).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:26:47.167918" r2d2 68.12.104.178 48544 68.12.99.2 53 UDP DNS (palermo).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:26:49.497147" r2d2 68.12.104.178 55880 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:26:49.497148" r2d2 68.12.104.178 55880 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:26:49.538753" r2d2 68.12.104.178 42682 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:26:49.538767" r2d2 68.12.104.178 42682 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:26:49.550694" r2d2 68.12.104.178 46214 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:26:49.550682" r2d2 68.12.104.178 46214 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:26:49.590233" r2d2 68.12.104.178 38354 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:26:49.590217" r2d2 68.12.104.178 38354 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:26:49.611108" r2d2 68.12.104.178 46559 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 07:26:49.611111" r2d2 68.12.104.178 46559 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 07:26:49.627225" r2d2 68.12.104.178 57447 38.229.70.125 53 UDP IP 38.229.70.125 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:26:49.627237" r2d2 68.12.104.178 57447 38.229.70.125 53 UDP IP 38.229.70.125 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:26:56.676970" r2d2 68.12.104.178 38006 68.12.99.2 53 UDP DNS (upfbd).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:26:56.676966" r2d2 68.12.104.178 38006 68.12.99.2 53 UDP DNS (upfbd).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:26:56.691895" r2d2 68.12.104.178 46380 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:26:56.691894" r2d2 68.12.104.178 46380 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:26:56.695778" r2d2 68.12.104.178 53891 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:26:56.695780" r2d2 68.12.104.178 53891 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:26:56.708079" r2d2 68.12.104.178 47477 68.12.99.2 53 UDP DNS (pungqgy).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:26:56.708078" r2d2 68.12.104.178 47477 68.12.99.2 53 UDP DNS (pungqgy).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:27:03.286383" r2d2 68.12.104.178 38835 68.12.99.2 53 UDP DNS counter.yadro.ru "zeroaccess (malware)" (static)\n' +
    '"2015-03-10 07:27:03.286384" r2d2 68.12.104.178 38835 68.12.99.2 53 UDP DNS counter.yadro.ru "zeroaccess (malware)" (static)\n' +
    '"2015-03-10 07:27:03.405185" r2d2 68.12.104.178 52317 68.12.99.2 53 UDP DNS (cglhnli).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:27:03.405182" r2d2 68.12.104.178 52317 68.12.99.2 53 UDP DNS (cglhnli).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:27:03.481224" r2d2 68.12.104.178 42294 38.229.70.125 53 UDP IP 38.229.70.125 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:27:03.481221" r2d2 68.12.104.178 42294 38.229.70.125 53 UDP IP 38.229.70.125 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:27:03.485326" r2d2 68.12.104.178 46680 38.229.70.125 53 UDP IP 38.229.70.125 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:27:03.485329" r2d2 68.12.104.178 46680 38.229.70.125 53 UDP IP 38.229.70.125 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:27:03.490359" r2d2 68.12.104.178 52851 38.229.70.125 53 UDP IP 38.229.70.125 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:27:03.490348" r2d2 68.12.104.178 52851 38.229.70.125 53 UDP IP 38.229.70.125 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:27:03.509498" r2d2 68.12.104.178 41659 38.229.70.125 53 UDP IP 38.229.70.125 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:27:03.509507" r2d2 68.12.104.178 41659 38.229.70.125 53 UDP IP 38.229.70.125 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:27:03.513989" r2d2 68.12.104.178 48746 38.229.70.125 53 UDP IP 38.229.70.125 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:27:03.514004" r2d2 68.12.104.178 48746 38.229.70.125 53 UDP IP 38.229.70.125 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:27:03.964787" r2d2 68.12.104.178 38591 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:27:03.964790" r2d2 68.12.104.178 38591 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:27:03.980881" r2d2 68.12.104.178 41777 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:27:03.980869" r2d2 68.12.104.178 41777 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:27:03.985277" r2d2 68.12.104.178 42752 68.12.99.2 53 UDP DNS (xvova).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:27:03.985280" r2d2 68.12.104.178 42752 68.12.99.2 53 UDP DNS (xvova).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:27:04.026313" r2d2 68.12.104.178 47744 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:27:04.026302" r2d2 68.12.104.178 47744 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:27:06.903667" r2d2 68.12.104.178 52406 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 07:27:06.903668" r2d2 68.12.104.178 52406 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 07:27:09.185268" r2d2 68.12.104.178 46710 68.12.99.2 53 UDP DNS peer.pickeklosarske.ru "palevo (malware)" (static)\n' +
    '"2015-03-10 07:27:09.185267" r2d2 68.12.104.178 46710 68.12.99.2 53 UDP DNS peer.pickeklosarske.ru "palevo (malware)" (static)\n' +
    '"2015-03-10 07:27:10.807635" r2d2 68.12.104.178 51562 68.12.99.2 53 UDP DNS (srxfevhi).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:27:10.807630" r2d2 68.12.104.178 51562 68.12.99.2 53 UDP DNS (srxfevhi).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:27:10.829308" r2d2 68.12.104.178 44150 38.102.150.29 53 UDP IP 38.102.150.29 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:27:10.829294" r2d2 68.12.104.178 44150 38.102.150.29 53 UDP IP 38.102.150.29 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:27:10.833739" r2d2 68.12.104.178 53413 38.102.150.29 53 UDP IP 38.102.150.29 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:27:10.833737" r2d2 68.12.104.178 53413 38.102.150.29 53 UDP IP 38.102.150.29 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:27:11.338458" r2d2 68.12.104.178 58399 68.12.99.2 53 UDP DNS (roays).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:27:11.338480" r2d2 68.12.104.178 58399 68.12.99.2 53 UDP DNS (roays).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:27:11.380360" r2d2 68.12.104.178 43066 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:27:11.380363" r2d2 68.12.104.178 43066 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:27:11.395483" r2d2 68.12.104.178 41019 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:27:11.396554" r2d2 68.12.104.178 41380 68.12.99.2 53 UDP DNS (extzkxbobnj).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:27:11.395486" r2d2 68.12.104.178 41019 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:27:11.396562" r2d2 68.12.104.178 41380 68.12.99.2 53 UDP DNS (extzkxbobnj).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:27:15.797465" r2d2 68.12.104.178 41755 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 07:27:15.797474" r2d2 68.12.104.178 41755 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 07:27:18.237602" r2d2 68.12.104.178 44503 68.12.99.2 53 UDP DNS (iifmsnhj).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:27:18.237599" r2d2 68.12.104.178 44503 68.12.99.2 53 UDP DNS (iifmsnhj).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:27:18.271444" r2d2 68.12.104.178 39389 68.12.99.2 53 UDP DNS (bqltd).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:27:18.271445" r2d2 68.12.104.178 39389 68.12.99.2 53 UDP DNS (bqltd).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:27:18.282550" r2d2 68.12.104.178 42191 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:27:18.282546" r2d2 68.12.104.178 42191 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:27:18.290083" r2d2 68.12.104.178 49064 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:27:18.290086" r2d2 68.12.104.178 49064 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:27:18.702513" r2d2 68.12.104.178 54677 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:27:18.702509" r2d2 68.12.104.178 54677 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:27:18.705592" r2d2 68.12.104.178 43781 68.12.99.2 53 UDP DNS (xnzxvcrq).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:27:18.705580" r2d2 68.12.104.178 43781 68.12.99.2 53 UDP DNS (xnzxvcrq).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:27:18.711515" r2d2 68.12.104.178 39711 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:27:18.711512" r2d2 68.12.104.178 39711 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:27:18.713992" r2d2 68.12.104.178 40515 68.12.99.2 53 UDP DNS (iqysaowq).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:27:18.713998" r2d2 68.12.104.178 40515 68.12.99.2 53 UDP DNS (iqysaowq).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:27:18.790770" r2d2 68.12.104.178 46052 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:27:18.790772" r2d2 68.12.104.178 46052 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:27:18.803538" r2d2 68.12.104.178 56808 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:27:18.803533" r2d2 68.12.104.178 56808 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:27:25.753532" r2d2 68.12.104.178 35462 38.229.70.125 53 UDP IP 38.229.70.125 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:27:25.753533" r2d2 68.12.104.178 35462 38.229.70.125 53 UDP IP 38.229.70.125 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:27:25.796083" r2d2 68.12.104.178 50498 38.229.70.125 53 UDP IP 38.229.70.125 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:27:25.796080" r2d2 68.12.104.178 50498 38.229.70.125 53 UDP IP 38.229.70.125 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:27:25.800646" r2d2 68.12.104.178 41746 38.229.70.125 53 UDP IP 38.229.70.125 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:27:25.800645" r2d2 68.12.104.178 41746 38.229.70.125 53 UDP IP 38.229.70.125 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:27:25.989427" r2d2 68.12.104.178 36648 68.12.99.2 53 UDP DNS (nqnnn).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:27:25.989425" r2d2 68.12.104.178 36648 68.12.99.2 53 UDP DNS (nqnnn).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:27:26.036093" r2d2 68.12.104.178 45755 68.12.99.2 53 UDP DNS (nfhxrpdr).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:27:26.036097" r2d2 68.12.104.178 45755 68.12.99.2 53 UDP DNS (nfhxrpdr).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:27:30.477196" r2d2 68.12.104.178 51692 113.108.80.138 53 UDP IP 113.108.80.138 dnspod (custom)\n' +
    '"2015-03-10 07:27:30.477185" r2d2 68.12.104.178 51692 113.108.80.138 53 UDP IP 113.108.80.138 dnspod (custom)\n' +
    '"2015-03-10 07:27:33.305893" r2d2 68.12.104.178 37439 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:27:33.305903" r2d2 68.12.104.178 37439 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:27:33.309484" r2d2 68.12.104.178 49680 68.12.99.2 53 UDP DNS (bjtwpgax).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:27:33.309492" r2d2 68.12.104.178 49680 68.12.99.2 53 UDP DNS (bjtwpgax).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:27:33.408160" r2d2 68.12.104.178 51411 68.12.99.2 53 UDP DNS (qveawzyob).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:27:33.408151" r2d2 68.12.104.178 51411 68.12.99.2 53 UDP DNS (qveawzyob).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:27:33.440869" r2d2 68.12.104.178 50773 68.12.99.2 53 UDP DNS (fnkeriocfbn).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:27:33.440865" r2d2 68.12.104.178 50773 68.12.99.2 53 UDP DNS (fnkeriocfbn).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:27:33.494990" r2d2 68.12.104.178 49044 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:27:33.494991" r2d2 68.12.104.178 49044 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:27:40.649595" r2d2 68.12.104.178 44870 68.12.99.2 53 UDP DNS (nzfuob).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:27:40.649640" r2d2 68.12.104.178 44870 68.12.99.2 53 UDP DNS (nzfuob).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:27:40.655154" r2d2 68.12.104.178 48726 68.12.99.2 53 UDP DNS (rzvbcocgymm).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:27:40.655185" r2d2 68.12.104.178 48726 68.12.99.2 53 UDP DNS (rzvbcocgymm).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:27:40.670915" r2d2 68.12.104.178 35760 68.12.99.2 53 UDP DNS (gwknw).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:27:40.670913" r2d2 68.12.104.178 35760 68.12.99.2 53 UDP DNS (gwknw).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:27:40.695295" r2d2 68.12.104.178 46215 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:27:40.695299" r2d2 68.12.104.178 46215 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:27:40.866359" r2d2 68.12.104.178 39921 68.12.99.2 53 UDP DNS (dzigse).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:27:40.866358" r2d2 68.12.104.178 39921 68.12.99.2 53 UDP DNS (dzigse).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:27:40.936048" r2d2 68.12.104.178 39358 38.102.150.29 53 UDP IP 38.102.150.29 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:27:40.936046" r2d2 68.12.104.178 39358 38.102.150.29 53 UDP IP 38.102.150.29 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:27:46.625384" r2d2 68.12.104.178 52099 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 07:27:46.625391" r2d2 68.12.104.178 52099 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 07:27:47.070669" r2d2 68.12.104.178 51149 198.58.92.228 53 UDP IP 198.58.92.228 malware cybercrime-tracker.net\n' +
    '"2015-03-10 07:27:47.070837" r2d2 68.12.104.178 51149 198.58.92.228 53 UDP IP 198.58.92.228 malware cybercrime-tracker.net\n' +
    '"2015-03-10 07:27:47.994138" r2d2 68.12.104.178 39100 68.12.99.2 53 UDP DNS (yerhlttz).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:27:47.994149" r2d2 68.12.104.178 39100 68.12.99.2 53 UDP DNS (yerhlttz).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:27:48.045893" r2d2 68.12.104.178 48177 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:27:48.045889" r2d2 68.12.104.178 48177 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:27:48.047555" r2d2 68.12.104.178 38508 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:27:48.047557" r2d2 68.12.104.178 38508 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:27:48.071704" r2d2 68.12.104.178 49385 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:27:48.071706" r2d2 68.12.104.178 49385 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:27:48.144649" r2d2 68.12.104.178 47507 68.12.99.2 53 UDP DNS (seaohagd).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:27:48.144644" r2d2 68.12.104.178 47507 68.12.99.2 53 UDP DNS (seaohagd).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:27:48.160238" r2d2 68.12.104.178 41867 68.12.99.2 53 UDP DNS (hjwtyunmfq).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:27:48.160241" r2d2 68.12.104.178 41867 68.12.99.2 53 UDP DNS (hjwtyunmfq).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:27:51.615264" r2d2 68.12.104.178 40347 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 07:27:51.615260" r2d2 68.12.104.178 40347 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 07:27:55.111833" r2d2 68.12.104.178 40510 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:27:55.111835" r2d2 68.12.104.178 40510 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:27:55.146162" r2d2 68.12.104.178 53216 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:27:55.146158" r2d2 68.12.104.178 53216 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:27:55.175193" r2d2 68.12.104.178 55306 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:27:55.175364" r2d2 68.12.104.178 55306 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:27:55.659339" r2d2 68.12.104.178 46336 68.12.99.2 53 UDP DNS (hwptmgit).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:27:55.659341" r2d2 68.12.104.178 46336 68.12.99.2 53 UDP DNS (hwptmgit).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:27:55.842048" r2d2 68.12.104.178 39394 38.229.70.125 53 UDP IP 38.229.70.125 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:27:55.842051" r2d2 68.12.104.178 39394 38.229.70.125 53 UDP IP 38.229.70.125 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:28:02.158795" r2d2 68.12.104.178 36019 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:28:02.158970" r2d2 68.12.104.178 36019 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:28:02.167555" r2d2 68.12.104.178 43777 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:28:02.167541" r2d2 68.12.104.178 43777 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:28:02.267246" r2d2 68.12.104.178 59549 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:28:02.267262" r2d2 68.12.104.178 59549 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:28:02.276217" r2d2 68.12.104.178 58446 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:28:02.276222" r2d2 68.12.104.178 58446 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:28:02.303112" r2d2 68.12.104.178 49974 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:28:02.303108" r2d2 68.12.104.178 49974 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:28:03.014714" r2d2 68.12.104.178 42225 38.229.70.125 53 UDP IP 38.229.70.125 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:28:03.014617" r2d2 68.12.104.178 42225 38.229.70.125 53 UDP IP 38.229.70.125 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:28:03.021685" r2d2 68.12.104.178 44393 38.229.70.125 53 UDP IP 38.229.70.125 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:28:03.021661" r2d2 68.12.104.178 44393 38.229.70.125 53 UDP IP 38.229.70.125 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:28:09.341586" r2d2 68.12.104.178 47957 38.102.150.29 53 UDP IP 38.102.150.29 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:28:09.341588" r2d2 68.12.104.178 47957 38.102.150.29 53 UDP IP 38.102.150.29 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:28:09.347380" r2d2 68.12.104.178 41167 68.12.99.2 53 UDP DNS (oncal).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:28:09.347368" r2d2 68.12.104.178 41167 68.12.99.2 53 UDP DNS (oncal).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:28:09.349905" r2d2 68.12.104.178 38458 38.102.150.29 53 UDP IP 38.102.150.29 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:28:09.349920" r2d2 68.12.104.178 38458 38.102.150.29 53 UDP IP 38.102.150.29 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:28:09.372392" r2d2 68.12.104.178 40660 68.12.99.2 53 UDP DNS (kqpmceqcv).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:28:09.372395" r2d2 68.12.104.178 40660 68.12.99.2 53 UDP DNS (kqpmceqcv).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:28:10.166199" r2d2 68.12.104.178 49477 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 07:28:10.166200" r2d2 68.12.104.178 49477 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 07:28:10.350925" r2d2 68.12.104.178 52142 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:28:10.350937" r2d2 68.12.104.178 52142 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:28:10.368234" r2d2 68.12.104.178 53663 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:28:10.368232" r2d2 68.12.104.178 53663 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:28:11.781961" r2d2 68.12.104.178 40445 68.12.99.2 53 UDP DNS (media2000-networks).ddns.net "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 07:28:11.781973" r2d2 68.12.104.178 40445 68.12.99.2 53 UDP DNS (media2000-networks).ddns.net "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 07:28:16.589491" r2d2 68.12.104.178 53788 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:28:16.589503" r2d2 68.12.104.178 53788 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:28:16.593972" r2d2 68.12.104.178 42576 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:28:16.593957" r2d2 68.12.104.178 42576 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:28:16.623913" r2d2 68.12.104.178 52422 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:28:16.623911" r2d2 68.12.104.178 52422 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:28:17.785843" r2d2 68.12.104.178 53747 38.229.70.125 53 UDP IP 38.229.70.125 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:28:17.785847" r2d2 68.12.104.178 53747 38.229.70.125 53 UDP IP 38.229.70.125 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:28:17.805494" r2d2 68.12.104.178 39782 38.229.70.125 53 UDP IP 38.229.70.125 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:28:17.805493" r2d2 68.12.104.178 39782 38.229.70.125 53 UDP IP 38.229.70.125 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:28:20.752884" r2d2 68.12.104.178 47152 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 07:28:20.752887" r2d2 68.12.104.178 47152 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 07:28:23.616857" r2d2 68.12.104.178 36285 68.12.99.2 53 UDP DNS (ajvznltod).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:28:23.616855" r2d2 68.12.104.178 36285 68.12.99.2 53 UDP DNS (ajvznltod).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:28:31.171999" r2d2 68.12.104.178 49560 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:28:31.172001" r2d2 68.12.104.178 49560 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:28:31.187753" r2d2 68.12.104.178 56781 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:28:31.189021" r2d2 68.12.104.178 45315 68.12.99.2 53 UDP DNS (wqzmlwur).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:28:31.187750" r2d2 68.12.104.178 56781 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:28:31.189019" r2d2 68.12.104.178 45315 68.12.99.2 53 UDP DNS (wqzmlwur).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:28:37.343111" r2d2 68.12.104.178 49855 68.12.99.2 53 UDP DNS (ebrev).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:28:37.343114" r2d2 68.12.104.178 49855 68.12.99.2 53 UDP DNS (ebrev).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:28:39.746604" r2d2 68.12.104.178 36768 68.12.99.2 53 UDP DNS (ktare).tk "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:28:39.746606" r2d2 68.12.104.178 36768 68.12.99.2 53 UDP DNS (ktare).tk "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:28:39.826464" r2d2 68.12.104.178 40318 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:28:39.826452" r2d2 68.12.104.178 40318 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:28:39.864903" r2d2 68.12.104.178 58210 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:28:39.864899" r2d2 68.12.104.178 58210 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:28:47.185043" r2d2 68.12.104.178 47666 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:28:47.185069" r2d2 68.12.104.178 47666 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:28:48.262072" r2d2 68.12.104.178 42333 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 07:28:48.262093" r2d2 68.12.104.178 42333 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 07:28:52.878511" r2d2 68.12.104.178 44480 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:28:52.878509" r2d2 68.12.104.178 44480 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:28:52.964807" r2d2 68.12.104.178 38586 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:28:52.964818" r2d2 68.12.104.178 38586 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:28:54.560996" r2d2 68.12.104.178 49224 68.12.99.2 53 UDP DNS (hhedqcvd).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:28:54.560994" r2d2 68.12.104.178 49224 68.12.99.2 53 UDP DNS (hhedqcvd).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:28:55.602719" r2d2 68.12.104.178 35319 68.12.99.2 53 UDP DNS xlhost.com angler blogs.cisco.com\n' +
    '"2015-03-10 07:28:55.602716" r2d2 68.12.104.178 35319 68.12.99.2 53 UDP DNS xlhost.com angler blogs.cisco.com\n' +
    '"2015-03-10 07:28:57.191445" r2d2 68.12.104.178 42207 198.58.92.228 53 UDP IP 198.58.92.228 malware cybercrime-tracker.net\n' +
    '"2015-03-10 07:28:57.191448" r2d2 68.12.104.178 42207 198.58.92.228 53 UDP IP 198.58.92.228 malware cybercrime-tracker.net\n' +
    '"2015-03-10 07:28:57.545411" r2d2 68.12.104.178 47490 198.58.92.228 53 UDP IP 198.58.92.228 malware cybercrime-tracker.net\n' +
    '"2015-03-10 07:28:57.545396" r2d2 68.12.104.178 47490 198.58.92.228 53 UDP IP 198.58.92.228 malware cybercrime-tracker.net\n' +
    '"2015-03-10 07:29:00.019478" r2d2 68.12.104.178 50917 68.12.99.2 53 UDP DNS (wdpthpmqz).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:29:00.019460" r2d2 68.12.104.178 50917 68.12.99.2 53 UDP DNS (wdpthpmqz).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:29:00.050888" r2d2 68.12.104.178 36881 38.229.70.125 53 UDP IP 38.229.70.125 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:29:00.050890" r2d2 68.12.104.178 36881 38.229.70.125 53 UDP IP 38.229.70.125 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:29:00.082921" r2d2 68.12.104.178 38392 68.12.99.2 53 UDP DNS (soulttajykw).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:29:00.082925" r2d2 68.12.104.178 38392 68.12.99.2 53 UDP DNS (soulttajykw).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:29:02.814071" r2d2 68.12.104.178 59310 68.12.99.2 53 UDP DNS cychefs.com malware cybercrime-tracker.net\n' +
    '"2015-03-10 07:29:02.814067" r2d2 68.12.104.178 59310 68.12.99.2 53 UDP DNS cychefs.com malware cybercrime-tracker.net\n' +
    '"2015-03-10 07:29:14.502046" r2d2 68.12.104.178 37073 68.12.99.2 53 UDP DNS (mkwysvgo).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:29:14.502040" r2d2 68.12.104.178 37073 68.12.99.2 53 UDP DNS (mkwysvgo).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:29:14.590680" r2d2 68.12.104.178 46055 38.102.150.29 53 UDP IP 38.102.150.29 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:29:14.590682" r2d2 68.12.104.178 46055 38.102.150.29 53 UDP IP 38.102.150.29 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:29:19.093460" r2d2 68.12.104.178 53394 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 07:29:19.093464" r2d2 68.12.104.178 53394 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 07:29:20.672855" r2d2 68.12.104.178 54071 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 07:29:20.672854" r2d2 68.12.104.178 54071 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 07:29:36.977739" r2d2 68.12.104.178 46526 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 07:29:36.977744" r2d2 68.12.104.178 46526 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 07:29:39.086919" r2d2 68.12.104.178 55311 68.12.99.2 53 UDP DNS peer.pickeklosarske.ru "palevo (malware)" (static)\n' +
    '"2015-03-10 07:29:39.086921" r2d2 68.12.104.178 55311 68.12.99.2 53 UDP DNS peer.pickeklosarske.ru "palevo (malware)" (static)\n' +
    '"2015-03-10 07:29:49.903094" r2d2 68.12.104.178 55682 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 07:29:49.903090" r2d2 68.12.104.178 55682 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 07:30:04.250913" r2d2 68.12.104.178 42913 68.12.99.2 53 UDP DNS (media2000-networks).ddns.net "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 07:30:04.250917" r2d2 68.12.104.178 42913 68.12.99.2 53 UDP DNS (media2000-networks).ddns.net "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 07:30:11.235995" r2d2 68.12.104.178 47997 68.12.99.2 53 UDP DNS (ctrl-c).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:30:11.235991" r2d2 68.12.104.178 47997 68.12.99.2 53 UDP DNS (ctrl-c).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:30:20.703141" r2d2 68.12.104.178 37928 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 07:30:20.703144" r2d2 68.12.104.178 37928 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 07:30:26.395530" r2d2 68.12.104.178 56148 113.108.80.138 53 UDP IP 113.108.80.138 dnspod (custom)\n' +
    '"2015-03-10 07:30:26.395526" r2d2 68.12.104.178 56148 113.108.80.138 53 UDP IP 113.108.80.138 dnspod (custom)\n' +
    '"2015-03-10 07:30:30.284929" r2d2 68.12.104.178 52397 68.12.99.2 53 UDP DNS dentesmitec.ru "zeus (malware)" zeustracker.abuse.ch\n' +
    '"2015-03-10 07:30:30.284930" r2d2 68.12.104.178 52397 68.12.99.2 53 UDP DNS dentesmitec.ru "zeus (malware)" zeustracker.abuse.ch\n' +
    '"2015-03-10 07:30:38.946000" r2d2 68.12.104.178 53073 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 07:30:38.945997" r2d2 68.12.104.178 53073 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 07:30:44.781147" r2d2 68.12.104.178 54624 87.118.100.86 53 UDP IP 87.118.100.86 abuser openbl.org\n' +
    '"2015-03-10 07:30:44.781137" r2d2 68.12.104.178 54624 87.118.100.86 53 UDP IP 87.118.100.86 abuser openbl.org\n' +
    '"2015-03-10 07:30:44.781443" r2d2 68.12.104.178 51073 87.118.100.86 53 UDP IP 87.118.100.86 abuser openbl.org\n' +
    '"2015-03-10 07:30:44.781447" r2d2 68.12.104.178 51073 87.118.100.86 53 UDP IP 87.118.100.86 abuser openbl.org\n' +
    '"2015-03-10 07:30:47.823123" r2d2 68.12.104.178 44028 68.12.99.2 53 UDP DNS (academy).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:30:47.823137" r2d2 68.12.104.178 44028 68.12.99.2 53 UDP DNS (academy).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:30:49.029229" r2d2 68.12.104.178 59457 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 07:30:49.029227" r2d2 68.12.104.178 59457 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 07:30:51.532149" r2d2 68.12.104.178 49766 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 07:30:51.532152" r2d2 68.12.104.178 49766 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 07:30:57.876745" r2d2 68.12.104.178 43325 68.12.99.2 53 UDP DNS (brainshome).no-ip.biz "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 07:30:57.876741" r2d2 68.12.104.178 43325 68.12.99.2 53 UDP DNS (brainshome).no-ip.biz "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 07:31:12.497106" r2d2 68.12.104.178 51953 68.12.99.2 53 UDP DNS tetoimoveis.net malware cybercrime-tracker.net\n' +
    '"2015-03-10 07:31:12.497112" r2d2 68.12.104.178 51953 68.12.99.2 53 UDP DNS tetoimoveis.net malware cybercrime-tracker.net\n' +
    '"2015-03-10 07:31:13.968997" r2d2 68.12.104.178 41398 68.12.99.2 53 UDP DNS (mail4.myhsphere).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:31:13.969241" r2d2 68.12.104.178 40255 68.12.99.2 53 UDP DNS (ns1.myhsphere).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:31:13.969238" r2d2 68.12.104.178 40255 68.12.99.2 53 UDP DNS (ns1.myhsphere).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:31:13.968996" r2d2 68.12.104.178 41398 68.12.99.2 53 UDP DNS (mail4.myhsphere).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:31:13.969391" r2d2 68.12.104.178 48066 68.12.99.2 53 UDP DNS (ns2.myhsphere).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:31:13.969444" r2d2 68.12.104.178 48066 68.12.99.2 53 UDP DNS (ns2.myhsphere).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:31:19.434859" r2d2 68.12.104.178 42074 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 07:31:19.434935" r2d2 68.12.104.178 42074 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 07:31:27.961049" r2d2 68.12.104.178 48205 68.12.99.2 53 UDP DNS promisex.ru "zeus (malware)" (custom)\n' +
    '"2015-03-10 07:31:27.961053" r2d2 68.12.104.178 48205 68.12.99.2 53 UDP DNS promisex.ru "zeus (malware)" (custom)\n' +
    '"2015-03-10 07:31:34.540191" r2d2 68.12.104.178 58614 68.12.99.2 53 UDP DNS (geneng).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:31:34.540194" r2d2 68.12.104.178 58614 68.12.99.2 53 UDP DNS (geneng).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:31:37.476118" r2d2 68.12.104.178 51678 68.12.99.2 53 UDP DNS esvwp.com "pushdo (malware)" (static)\n' +
    '"2015-03-10 07:31:37.476117" r2d2 68.12.104.178 51678 68.12.99.2 53 UDP DNS esvwp.com "pushdo (malware)" (static)\n' +
    '"2015-03-10 07:31:43.049472" r2d2 68.12.104.178 45445 68.12.99.2 53 UDP DNS (theoffer).club "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:31:43.049468" r2d2 68.12.104.178 45445 68.12.99.2 53 UDP DNS (theoffer).club "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:31:53.140396" r2d2 68.12.104.178 55189 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 07:31:53.140394" r2d2 68.12.104.178 55189 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 07:31:54.621640" r2d2 68.12.104.178 56364 68.12.99.2 53 UDP DNS (rorupp).tk "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:31:54.621642" r2d2 68.12.104.178 56364 68.12.99.2 53 UDP DNS (rorupp).tk "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:32:01.571530" r2d2 68.12.104.178 42082 68.12.99.2 53 UDP DNS (kunal).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:32:01.571532" r2d2 68.12.104.178 42082 68.12.99.2 53 UDP DNS (kunal).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:32:07.051686" r2d2 68.12.104.178 57031 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 07:32:07.051688" r2d2 68.12.104.178 57031 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 07:32:09.189778" r2d2 68.12.104.178 58460 68.12.99.2 53 UDP DNS peer.pickeklosarske.ru "palevo (malware)" (static)\n' +
    '"2015-03-10 07:32:09.189775" r2d2 68.12.104.178 58460 68.12.99.2 53 UDP DNS peer.pickeklosarske.ru "palevo (malware)" (static)\n' +
    '"2015-03-10 07:32:15.048531" r2d2 68.12.104.178 49904 198.58.92.228 53 UDP IP 198.58.92.228 malware cybercrime-tracker.net\n' +
    '"2015-03-10 07:32:15.048530" r2d2 68.12.104.178 49904 198.58.92.228 53 UDP IP 198.58.92.228 malware cybercrime-tracker.net\n' +
    '"2015-03-10 07:32:21.353402" r2d2 68.12.104.178 41681 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 07:32:21.353404" r2d2 68.12.104.178 41681 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 07:32:23.970192" r2d2 68.12.104.178 52450 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 07:32:23.970189" r2d2 68.12.104.178 52450 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 07:32:41.838920" r2d2 68.12.104.178 44264 68.12.99.2 53 UDP DNS digitalmind.cn "palevo (malware)" palevotracker.abuse.ch\n' +
    '"2015-03-10 07:32:41.838922" r2d2 68.12.104.178 44264 68.12.99.2 53 UDP DNS digitalmind.cn "palevo (malware)" palevotracker.abuse.ch\n' +
    '"2015-03-10 07:32:51.737236" r2d2 68.12.104.178 46733 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 07:32:51.737238" r2d2 68.12.104.178 46733 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 07:32:57.617054" r2d2 68.12.104.178 42658 68.12.99.2 53 UDP DNS (business).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:32:57.617056" r2d2 68.12.104.178 42658 68.12.99.2 53 UDP DNS (business).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:33:04.960429" r2d2 68.12.104.178 57263 68.12.99.2 53 UDP DNS (citylifechurch).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:33:04.960431" r2d2 68.12.104.178 57263 68.12.99.2 53 UDP DNS (citylifechurch).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:33:05.269755" r2d2 68.12.104.178 46550 68.12.99.2 53 UDP DNS (mail.citylifechurch).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:33:05.269756" r2d2 68.12.104.178 46550 68.12.99.2 53 UDP DNS (mail.citylifechurch).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:33:06.354461" r2d2 68.12.104.178 59145 68.12.99.2 53 UDP DNS (cisco).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:33:06.354463" r2d2 68.12.104.178 59145 68.12.99.2 53 UDP DNS (cisco).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:33:09.031180" r2d2 68.12.104.178 55759 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 07:33:09.031175" r2d2 68.12.104.178 55759 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 07:33:11.482648" r2d2 68.12.104.178 36876 68.12.99.2 53 UDP DNS (beta.ads).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:33:11.482647" r2d2 68.12.104.178 36876 68.12.99.2 53 UDP DNS (beta.ads).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:33:11.925016" r2d2 68.12.104.178 57412 68.12.99.2 53 UDP DNS (aemc).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:33:11.925014" r2d2 68.12.104.178 57412 68.12.99.2 53 UDP DNS (aemc).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:33:25.577412" r2d2 68.12.104.178 41281 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 07:33:25.577415" r2d2 68.12.104.178 41281 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 07:33:43.988647" r2d2 68.12.104.178 44296 68.12.99.2 53 UDP DNS (panocam.skiline).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:33:43.988650" r2d2 68.12.104.178 44296 68.12.99.2 53 UDP DNS (panocam.skiline).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:33:44.910481" r2d2 68.12.104.178 37440 68.12.99.2 53 UDP DNS clicksor.com geinimi securehomenetworks.blogspot.com\n' +
    '"2015-03-10 07:33:44.910472" r2d2 68.12.104.178 37440 68.12.99.2 53 UDP DNS clicksor.com geinimi securehomenetworks.blogspot.com\n' +
    '"2015-03-10 07:33:47.327487" r2d2 62.210.248.159 5114 68.12.104.178 5060 UDP IP 62.210.248.159 "sipvicious scan" autoshun.org\n' +
    '"2015-03-10 07:33:47.327489" r2d2 62.210.248.159 5114 68.12.104.178 5060 UDP IP 62.210.248.159 "sipvicious scan" autoshun.org\n' +
    '"2015-03-10 07:33:51.756286" r2d2 68.12.104.178 43176 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 07:33:51.756282" r2d2 68.12.104.178 43176 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 07:33:56.405643" r2d2 68.12.104.178 47774 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 07:33:56.405655" r2d2 68.12.104.178 47774 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 07:34:03.748941" r2d2 68.12.104.178 57557 68.12.99.2 53 UDP DNS (euroshina).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:34:03.748945" r2d2 68.12.104.178 57557 68.12.99.2 53 UDP DNS (euroshina).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:34:04.395242" r2d2 68.12.104.178 35776 68.12.99.2 53 UDP DNS moscom.ru attackpage safebrowsing.clients.google.com\n' +
    '"2015-03-10 07:34:04.395238" r2d2 68.12.104.178 35776 68.12.99.2 53 UDP DNS moscom.ru attackpage safebrowsing.clients.google.com\n' +
    '"2015-03-10 07:34:11.297663" r2d2 68.12.104.178 43979 68.12.99.2 53 UDP DNS (icr).ddns.net "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 07:34:11.297664" r2d2 68.12.104.178 43979 68.12.99.2 53 UDP DNS (icr).ddns.net "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 07:34:18.360779" r2d2 68.12.104.178 44053 68.12.99.2 53 UDP DNS (ns.newsx).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:34:18.361664" r2d2 68.12.104.178 40891 68.12.99.2 53 UDP DNS (ns2.newsx).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:34:18.360777" r2d2 68.12.104.178 44053 68.12.99.2 53 UDP DNS (ns.newsx).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:34:18.361656" r2d2 68.12.104.178 40891 68.12.99.2 53 UDP DNS (ns2.newsx).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:34:21.301470" r2d2 68.12.104.178 48548 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 07:34:21.301468" r2d2 68.12.104.178 48548 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 07:34:24.251383" r2d2 68.12.104.178 35370 68.12.99.2 53 UDP DNS (efilter.sysone).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:34:24.251381" r2d2 68.12.104.178 35370 68.12.99.2 53 UDP DNS (efilter.sysone).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:34:26.576456" r2d2 68.12.104.178 50254 216.245.222.194 53 UDP IP 216.245.222.194 malware cybercrime-tracker.net\n' +
    '"2015-03-10 07:34:26.576469" r2d2 68.12.104.178 50254 216.245.222.194 53 UDP IP 216.245.222.194 malware cybercrime-tracker.net\n' +
    '"2015-03-10 07:34:27.294756" r2d2 68.12.104.178 49484 68.12.99.2 53 UDP DNS wanadoo.es attackpage safebrowsing.clients.google.com\n' +
    '"2015-03-10 07:34:27.294769" r2d2 68.12.104.178 49484 68.12.99.2 53 UDP DNS wanadoo.es attackpage safebrowsing.clients.google.com\n' +
    '"2015-03-10 07:34:34.122661" r2d2 68.12.104.178 40242 68.12.99.2 53 UDP DNS (tracker.coppersurfer).tk "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:34:34.122663" r2d2 68.12.104.178 40242 68.12.99.2 53 UDP DNS (tracker.coppersurfer).tk "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:34:37.126090" r2d2 68.12.104.178 45681 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 07:34:37.126093" r2d2 68.12.104.178 45681 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 07:34:40.229559" r2d2 68.12.104.178 56584 68.153.37.23 53 UDP IP 68.153.37.23 abuser openbl.org\n' +
    '"2015-03-10 07:34:40.229545" r2d2 68.12.104.178 56584 68.153.37.23 53 UDP IP 68.153.37.23 abuser openbl.org\n' +
    '"2015-03-10 07:34:40.344271" r2d2 68.12.104.178 47068 68.12.99.2 53 UDP DNS peer.pickeklosarske.ru "palevo (malware)" (static)\n' +
    '"2015-03-10 07:34:40.344268" r2d2 68.12.104.178 47068 68.12.99.2 53 UDP DNS peer.pickeklosarske.ru "palevo (malware)" (static)\n' +
    '"2015-03-10 07:34:53.769279" r2d2 68.12.104.178 48584 68.12.99.2 53 UDP DNS (brightlounge).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:34:53.769278" r2d2 68.12.104.178 48584 68.12.99.2 53 UDP DNS (brightlounge).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:34:58.017476" r2d2 68.12.104.178 46051 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 07:34:58.017462" r2d2 68.12.104.178 46051 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 07:34:58.187068" r2d2 68.12.104.178 49338 113.108.80.138 53 UDP IP 113.108.80.138 dnspod (custom)\n' +
    '"2015-03-10 07:34:58.187070" r2d2 68.12.104.178 49338 113.108.80.138 53 UDP IP 113.108.80.138 dnspod (custom)\n' +
    '"2015-03-10 07:35:22.909255" r2d2 68.12.104.178 47472 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 07:35:22.909257" r2d2 68.12.104.178 47472 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 07:35:28.844144" r2d2 68.12.104.178 39587 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 07:35:28.844147" r2d2 68.12.104.178 39587 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 07:35:31.223630" r2d2 68.12.104.178 54084 68.12.99.2 53 UDP DNS (orders).fiftyone.com "pushdo (malware)" (static)\n' +
    '"2015-03-10 07:35:31.223634" r2d2 68.12.104.178 54084 68.12.99.2 53 UDP DNS (orders).fiftyone.com "pushdo (malware)" (static)\n' +
    '"2015-03-10 07:35:39.131577" r2d2 68.12.104.178 46510 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 07:35:39.131567" r2d2 68.12.104.178 46510 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 07:35:50.751991" r2d2 68.12.104.178 43759 68.12.99.2 53 UDP DNS (mail01.mcgown).enterprises "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:35:50.751992" r2d2 68.12.104.178 43759 68.12.99.2 53 UDP DNS (mail01.mcgown).enterprises "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:35:54.110529" r2d2 68.12.104.178 40783 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 07:35:54.110530" r2d2 68.12.104.178 40783 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 07:36:14.124351" r2d2 68.12.104.178 39555 68.12.99.2 53 UDP DNS (ontika).ignorelist.com "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:36:14.124349" r2d2 68.12.104.178 39555 68.12.99.2 53 UDP DNS (ontika).ignorelist.com "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:36:30.452776" r2d2 68.12.104.178 50759 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 07:36:30.452774" r2d2 68.12.104.178 50759 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 07:36:37.185793" r2d2 68.12.104.178 58128 68.12.99.2 53 UDP DNS teske.pornicarke.com "palevo (malware)" (static)\n' +
    '"2015-03-10 07:36:37.185803" r2d2 68.12.104.178 58128 68.12.99.2 53 UDP DNS teske.pornicarke.com "palevo (malware)" (static)\n' +
    '"2015-03-10 07:36:40.281877" r2d2 68.12.104.178 47892 198.58.92.228 53 UDP IP 198.58.92.228 malware cybercrime-tracker.net\n' +
    '"2015-03-10 07:36:40.281880" r2d2 68.12.104.178 47892 198.58.92.228 53 UDP IP 198.58.92.228 malware cybercrime-tracker.net\n' +
    '"2015-03-10 07:36:40.595496" r2d2 68.12.104.178 41112 198.58.92.228 53 UDP IP 198.58.92.228 malware cybercrime-tracker.net\n' +
    '"2015-03-10 07:36:40.595532" r2d2 68.12.104.178 41112 198.58.92.228 53 UDP IP 198.58.92.228 malware cybercrime-tracker.net\n' +
    '"2015-03-10 07:36:55.701621" r2d2 68.12.104.178 45809 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 07:36:55.701624" r2d2 68.12.104.178 45809 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 07:37:01.285551" r2d2 68.12.104.178 38628 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 07:37:01.285550" r2d2 68.12.104.178 38628 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 07:37:07.200788" r2d2 68.12.104.178 40939 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 07:37:07.200773" r2d2 68.12.104.178 40939 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 07:37:09.212634" r2d2 68.12.104.178 46555 68.12.99.2 53 UDP DNS peer.pickeklosarske.ru "palevo (malware)" (static)\n' +
    '"2015-03-10 07:37:09.212636" r2d2 68.12.104.178 46555 68.12.99.2 53 UDP DNS peer.pickeklosarske.ru "palevo (malware)" (static)\n' +
    '"2015-03-10 07:37:17.349996" r2d2 68.12.104.178 54316 205.178.189.131 53 UDP IP 205.178.189.131 "malware distribution site" autoshun.org\n' +
    '"2015-03-10 07:37:17.350059" r2d2 68.12.104.178 54316 205.178.189.131 53 UDP IP 205.178.189.131 "malware distribution site" autoshun.org\n' +
    '"2015-03-10 07:37:17.350263" r2d2 68.12.104.178 41400 205.178.189.131 53 UDP IP 205.178.189.131 "malware distribution site" autoshun.org\n' +
    '"2015-03-10 07:37:17.350250" r2d2 68.12.104.178 41400 205.178.189.131 53 UDP IP 205.178.189.131 "malware distribution site" autoshun.org\n' +
    '"2015-03-10 07:37:17.396745" r2d2 68.12.104.178 51624 205.178.189.131 53 UDP IP 205.178.189.131 "malware distribution site" autoshun.org\n' +
    '"2015-03-10 07:37:17.396329" r2d2 68.12.104.178 57413 205.178.189.131 53 UDP IP 205.178.189.131 "malware distribution site" autoshun.org\n' +
    '"2015-03-10 07:37:17.396344" r2d2 68.12.104.178 57413 205.178.189.131 53 UDP IP 205.178.189.131 "malware distribution site" autoshun.org\n' +
    '"2015-03-10 07:37:17.396729" r2d2 68.12.104.178 51624 205.178.189.131 53 UDP IP 205.178.189.131 "malware distribution site" autoshun.org\n' +
    '"2015-03-10 07:37:19.397856" r2d2 68.12.104.178 50645 205.178.189.131 53 UDP IP 205.178.189.131 "malware distribution site" autoshun.org\n' +
    '"2015-03-10 07:37:19.397854" r2d2 68.12.104.178 44785 205.178.189.131 53 UDP IP 205.178.189.131 "malware distribution site" autoshun.org\n' +
    '"2015-03-10 07:37:19.397852" r2d2 68.12.104.178 44785 205.178.189.131 53 UDP IP 205.178.189.131 "malware distribution site" autoshun.org\n' +
    '"2015-03-10 07:37:19.397857" r2d2 68.12.104.178 50645 205.178.189.131 53 UDP IP 205.178.189.131 "malware distribution site" autoshun.org\n' +
    '"2015-03-10 07:37:26.529056" r2d2 68.12.104.178 49348 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 07:37:26.529054" r2d2 68.12.104.178 49348 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 07:37:55.629392" r2d2 68.12.104.178 57344 68.12.99.2 53 UDP DNS (ns1.megaline).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:37:55.629732" r2d2 68.12.104.178 44103 68.12.99.2 53 UDP DNS (ns2.megaline).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:37:55.629734" r2d2 68.12.104.178 44103 68.12.99.2 53 UDP DNS (ns2.megaline).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:37:55.629382" r2d2 68.12.104.178 57344 68.12.99.2 53 UDP DNS (ns1.megaline).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:38:02.888580" r2d2 68.12.104.178 56903 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 07:38:02.888581" r2d2 68.12.104.178 56903 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 07:38:09.247184" r2d2 68.12.104.178 37356 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 07:38:09.247182" r2d2 68.12.104.178 37356 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 07:38:13.959156" r2d2 68.12.104.178 47490 68.12.99.2 53 UDP DNS (www).superfish.com superfish (static)\n' +
    '"2015-03-10 07:38:13.959147" r2d2 68.12.104.178 47490 68.12.99.2 53 UDP DNS (www).superfish.com superfish (static)\n' +
    '"2015-03-10 07:38:13.979444" r2d2 68.12.104.178 35492 68.12.99.2 53 UDP DNS superfish.com superfish (static)\n' +
    '"2015-03-10 07:38:13.979443" r2d2 68.12.104.178 35492 68.12.99.2 53 UDP DNS superfish.com superfish (static)\n' +
    '"2015-03-10 07:38:28.090060" r2d2 68.12.104.178 44785 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 07:38:28.090061" r2d2 68.12.104.178 44785 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 07:38:33.748388" r2d2 68.12.104.178 48481 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 07:38:33.748383" r2d2 68.12.104.178 48481 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 07:38:38.213138" r2d2 68.12.104.178 46190 68.153.37.23 53 UDP IP 68.153.37.23 abuser openbl.org\n' +
    '"2015-03-10 07:38:38.213136" r2d2 68.12.104.178 46190 68.153.37.23 53 UDP IP 68.153.37.23 abuser openbl.org\n' +
    '"2015-03-10 07:38:47.619201" r2d2 199.217.116.159 5149 68.12.104.178 5060 UDP IP 199.217.116.159 "sipvicious scan" autoshun.org\n' +
    '"2015-03-10 07:38:47.619197" r2d2 199.217.116.159 5149 68.12.104.178 5060 UDP IP 199.217.116.159 "sipvicious scan" autoshun.org\n' +
    '"2015-03-10 07:38:47.738607" r2d2 68.12.104.178 46205 68.12.99.2 53 UDP DNS upperlowstream.ru "zeus (malware)" zeustracker.abuse.ch\n' +
    '"2015-03-10 07:38:47.738608" r2d2 68.12.104.178 46205 68.12.99.2 53 UDP DNS upperlowstream.ru "zeus (malware)" zeustracker.abuse.ch\n' +
    '"2015-03-10 07:38:55.980748" r2d2 68.12.104.178 50455 68.12.99.2 53 UDP DNS digitalmind.cn "palevo (malware)" palevotracker.abuse.ch\n' +
    '"2015-03-10 07:38:55.980746" r2d2 68.12.104.178 50455 68.12.99.2 53 UDP DNS digitalmind.cn "palevo (malware)" palevotracker.abuse.ch\n' +
    '"2015-03-10 07:38:58.900248" r2d2 68.12.104.178 57883 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 07:38:58.900245" r2d2 68.12.104.178 57883 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 07:39:35.356904" r2d2 68.12.104.178 52976 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 07:39:35.356922" r2d2 68.12.104.178 52976 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 07:39:37.274978" r2d2 68.12.104.178 42793 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 07:39:37.274976" r2d2 68.12.104.178 42793 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 07:39:39.295086" r2d2 68.12.104.178 47467 68.12.99.2 53 UDP DNS peer.pickeklosarske.ru "palevo (malware)" (static)\n' +
    '"2015-03-10 07:39:39.295088" r2d2 68.12.104.178 47467 68.12.99.2 53 UDP DNS peer.pickeklosarske.ru "palevo (malware)" (static)\n' +
    '"2015-03-10 07:39:49.916993" r2d2 68.12.104.178 56170 68.12.99.2 53 UDP DNS (davidharrison).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:39:49.916989" r2d2 68.12.104.178 56170 68.12.99.2 53 UDP DNS (davidharrison).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:40:00.412730" r2d2 68.12.104.178 51616 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 07:40:00.412726" r2d2 68.12.104.178 51616 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 07:40:06.669590" r2d2 68.12.104.178 44558 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 07:40:06.669588" r2d2 68.12.104.178 44558 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 07:40:16.024034" r2d2 68.12.104.178 45223 113.108.80.138 53 UDP IP 113.108.80.138 dnspod (custom)\n' +
    '"2015-03-10 07:40:16.024039" r2d2 68.12.104.178 45223 113.108.80.138 53 UDP IP 113.108.80.138 dnspod (custom)\n' +
    '"2015-03-10 07:40:21.357334" r2d2 68.12.104.178 35058 68.12.99.2 53 UDP DNS (beech.jcd).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:40:21.357331" r2d2 68.12.104.178 35058 68.12.99.2 53 UDP DNS (beech.jcd).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:40:24.780429" r2d2 68.12.104.178 41774 68.12.99.2 53 UDP DNS promisex.ru "zeus (malware)" (custom)\n' +
    '"2015-03-10 07:40:24.780430" r2d2 68.12.104.178 41774 68.12.99.2 53 UDP DNS promisex.ru "zeus (malware)" (custom)\n' +
    '"2015-03-10 07:40:31.224058" r2d2 68.12.104.178 55947 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 07:40:31.224063" r2d2 68.12.104.178 55947 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 07:40:39.339448" r2d2 68.12.104.178 38251 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 07:40:39.339447" r2d2 68.12.104.178 38251 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 07:40:45.717549" r2d2 68.12.104.178 44279 68.12.99.2 53 UDP DNS (mailcluster01.cbs).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:40:45.717551" r2d2 68.12.104.178 44279 68.12.99.2 53 UDP DNS (mailcluster01.cbs).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:41:06.587769" r2d2 68.12.104.178 39312 95.154.24.73 53 UDP IP 95.154.24.73 "tor exit node" torproject.org\n' +
    '"2015-03-10 07:41:06.587771" r2d2 68.12.104.178 39312 95.154.24.73 53 UDP IP 95.154.24.73 "tor exit node" torproject.org\n' +
    '"2015-03-10 07:41:08.279017" r2d2 68.12.104.178 51265 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 07:41:08.279022" r2d2 68.12.104.178 51265 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 07:41:08.387030" r2d2 68.12.104.178 37934 68.12.99.2 53 UDP DNS counter.yadro.ru "zeroaccess (malware)" (static)\n' +
    '"2015-03-10 07:41:08.387034" r2d2 68.12.104.178 37934 68.12.99.2 53 UDP DNS counter.yadro.ru "zeroaccess (malware)" (static)\n' +
    '"2015-03-10 07:41:16.545624" r2d2 68.12.104.178 49693 68.12.99.2 53 UDP DNS (server.unimatrix).xyz "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:41:16.545627" r2d2 68.12.104.178 49693 68.12.99.2 53 UDP DNS (server.unimatrix).xyz "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:41:32.799460" r2d2 68.12.104.178 46865 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 07:41:32.799458" r2d2 68.12.104.178 46865 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 07:41:39.106690" r2d2 68.12.104.178 58873 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 07:41:39.106708" r2d2 68.12.104.178 58873 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 07:41:45.860951" r2d2 68.12.104.178 35019 68.12.99.2 53 UDP DNS (pantherwholesale).no-ip.biz "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 07:41:45.860952" r2d2 68.12.104.178 35019 68.12.99.2 53 UDP DNS (pantherwholesale).no-ip.biz "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 07:41:47.283114" r2d2 68.12.104.178 38260 167.114.91.160 53 UDP IP 167.114.91.160 malware cybercrime-tracker.net\n' +
    '"2015-03-10 07:41:47.283117" r2d2 68.12.104.178 38260 167.114.91.160 53 UDP IP 167.114.91.160 malware cybercrime-tracker.net\n' +
    '"2015-03-10 07:42:01.423683" r2d2 68.12.104.178 39941 198.58.92.228 53 UDP IP 198.58.92.228 malware cybercrime-tracker.net\n' +
    '"2015-03-10 07:42:01.423681" r2d2 68.12.104.178 39941 198.58.92.228 53 UDP IP 198.58.92.228 malware cybercrime-tracker.net\n' +
    '"2015-03-10 07:42:03.610436" r2d2 68.12.104.178 43153 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 07:42:03.610432" r2d2 68.12.104.178 43153 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 07:42:06.637163" r2d2 68.12.104.178 54174 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 07:42:06.637164" r2d2 68.12.104.178 54174 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 07:42:07.346158" r2d2 68.12.104.178 42669 68.12.99.2 53 UDP DNS www.ip-adress.com "suspicious ipinfo" (static)\n' +
    '"2015-03-10 07:42:07.346154" r2d2 68.12.104.178 42669 68.12.99.2 53 UDP DNS www.ip-adress.com "suspicious ipinfo" (static)\n' +
    '"2015-03-10 07:42:09.411435" r2d2 68.12.104.178 47699 68.12.99.2 53 UDP DNS peer.pickeklosarske.ru "palevo (malware)" (static)\n' +
    '"2015-03-10 07:42:09.411444" r2d2 68.12.104.178 47699 68.12.99.2 53 UDP DNS peer.pickeklosarske.ru "palevo (malware)" (static)\n' +
    '"2015-03-10 07:42:16.241591" r2d2 68.12.104.178 41486 68.12.99.2 53 UDP DNS (dir-ns-2.a1).4dq.com "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 07:42:16.241581" r2d2 68.12.104.178 41285 68.12.99.2 53 UDP DNS (dir-ns-1.a1).4dq.com "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 07:42:16.241590" r2d2 68.12.104.178 41486 68.12.99.2 53 UDP DNS (dir-ns-2.a1).4dq.com "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 07:42:16.241960" r2d2 68.12.104.178 42388 68.12.99.2 53 UDP DNS (ns1).changeip.org "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 07:42:16.241959" r2d2 68.12.104.178 42388 68.12.99.2 53 UDP DNS (ns1).changeip.org "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 07:42:16.242588" r2d2 68.12.104.178 51566 68.12.99.2 53 UDP DNS (ns2).changeip.org "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 07:42:16.241577" r2d2 68.12.104.178 41285 68.12.99.2 53 UDP DNS (dir-ns-1.a1).4dq.com "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 07:42:16.242835" r2d2 68.12.104.178 52911 68.12.99.2 53 UDP DNS (ns3).changeip.org "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 07:42:16.242594" r2d2 68.12.104.178 51566 68.12.99.2 53 UDP DNS (ns2).changeip.org "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 07:42:16.242831" r2d2 68.12.104.178 52911 68.12.99.2 53 UDP DNS (ns3).changeip.org "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 07:42:22.781665" r2d2 68.12.104.178 53490 68.12.99.2 53 UDP DNS (mx.cloudafrica).email "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:42:22.781668" r2d2 68.12.104.178 53490 68.12.99.2 53 UDP DNS (mx.cloudafrica).email "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:42:22.809147" r2d2 68.12.104.178 47402 68.12.99.2 53 UDP DNS (mx01.cloudafrica).email "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:42:22.809148" r2d2 68.12.104.178 47402 68.12.99.2 53 UDP DNS (mx01.cloudafrica).email "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:42:24.717854" r2d2 68.12.104.178 42414 80.247.72.132 53 UDP IP 80.247.72.132 "asprox (malware)" atrack.h3x.eu\n' +
    '"2015-03-10 07:42:24.718096" r2d2 68.12.104.178 42414 80.247.72.132 53 UDP IP 80.247.72.132 "asprox (malware)" atrack.h3x.eu\n' +
    '"2015-03-10 07:42:24.722774" r2d2 68.12.104.178 41034 80.247.72.132 53 UDP IP 80.247.72.132 "asprox (malware)" atrack.h3x.eu\n' +
    '"2015-03-10 07:42:24.722787" r2d2 68.12.104.178 41034 80.247.72.132 53 UDP IP 80.247.72.132 "asprox (malware)" atrack.h3x.eu\n' +
    '"2015-03-10 07:42:26.549289" r2d2 68.12.104.178 39761 80.247.72.132 53 UDP IP 80.247.72.132 "asprox (malware)" atrack.h3x.eu\n' +
    '"2015-03-10 07:42:26.549300" r2d2 68.12.104.178 39761 80.247.72.132 53 UDP IP 80.247.72.132 "asprox (malware)" atrack.h3x.eu\n' +
    '"2015-03-10 07:42:40.716561" r2d2 68.12.104.178 49354 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 07:42:40.716559" r2d2 68.12.104.178 49354 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 07:42:48.668322" r2d2 68.12.104.178 49079 68.12.99.2 53 UDP DNS (tracker.coppersurfer).tk "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:42:48.668324" r2d2 68.12.104.178 49079 68.12.99.2 53 UDP DNS (tracker.coppersurfer).tk "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:42:51.394694" r2d2 68.12.104.178 41021 68.12.99.2 53 UDP DNS (ns6.techsolutions).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:42:51.394936" r2d2 68.12.104.178 58621 68.12.99.2 53 UDP DNS (ns8.techsolutions).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:42:51.394938" r2d2 68.12.104.178 58621 68.12.99.2 53 UDP DNS (ns8.techsolutions).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:42:51.395325" r2d2 68.12.104.178 59919 68.12.99.2 53 UDP DNS (ns20.techsolutions).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:42:51.394692" r2d2 68.12.104.178 41021 68.12.99.2 53 UDP DNS (ns6.techsolutions).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:42:51.395326" r2d2 68.12.104.178 59919 68.12.99.2 53 UDP DNS (ns20.techsolutions).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:42:58.666978" r2d2 68.12.104.178 36847 68.12.99.2 53 UDP DNS (zmzm).tk "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:42:58.666962" r2d2 68.12.104.178 36847 68.12.99.2 53 UDP DNS (zmzm).tk "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:42:59.717057" r2d2 68.12.104.178 37106 68.12.99.2 53 UDP DNS (riverwood).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:42:59.717061" r2d2 68.12.104.178 37106 68.12.99.2 53 UDP DNS (riverwood).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:43:00.514309" r2d2 68.12.104.178 56255 68.12.99.2 53 UDP DNS (ns2.ord).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:43:00.513943" r2d2 68.12.104.178 39758 68.12.99.2 53 UDP DNS (ns.ord).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:43:00.513959" r2d2 68.12.104.178 39758 68.12.99.2 53 UDP DNS (ns.ord).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:43:00.514306" r2d2 68.12.104.178 56255 68.12.99.2 53 UDP DNS (ns2.ord).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:43:00.736644" r2d2 68.12.104.178 35820 68.12.99.2 53 UDP DNS (mx-host.dot).tk "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:43:00.736642" r2d2 68.12.104.178 35820 68.12.99.2 53 UDP DNS (mx-host.dot).tk "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:43:03.032091" r2d2 68.12.104.178 37056 113.108.80.138 53 UDP IP 113.108.80.138 dnspod (custom)\n' +
    '"2015-03-10 07:43:03.032093" r2d2 68.12.104.178 37056 113.108.80.138 53 UDP IP 113.108.80.138 dnspod (custom)\n' +
    '"2015-03-10 07:43:05.219545" r2d2 68.12.104.178 39555 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 07:43:05.219547" r2d2 68.12.104.178 39555 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 07:43:05.494495" r2d2 68.12.104.178 42652 68.12.99.2 53 UDP DNS (ns01.oto).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:43:05.494496" r2d2 68.12.104.178 42652 68.12.99.2 53 UDP DNS (ns01.oto).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:43:06.981405" r2d2 68.12.104.178 57355 8.8.8.8 53 UDP DNS (mx-host.dot).tk "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:43:06.981403" r2d2 68.12.104.178 57355 8.8.8.8 53 UDP DNS (mx-host.dot).tk "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:43:09.822308" r2d2 68.12.104.178 47861 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 07:43:09.822311" r2d2 68.12.104.178 47861 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 07:43:11.545421" r2d2 68.12.104.178 44681 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 07:43:11.545422" r2d2 68.12.104.178 44681 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 07:43:12.582003" r2d2 68.12.104.178 45612 68.12.99.2 53 UDP DNS (mail2.konzept).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:43:12.581981" r2d2 68.12.104.178 45612 68.12.99.2 53 UDP DNS (mail2.konzept).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:43:17.223488" r2d2 68.12.104.178 47723 68.12.99.2 53 UDP DNS (alidaf).duckdns.org "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 07:43:17.223487" r2d2 68.12.104.178 47723 68.12.99.2 53 UDP DNS (alidaf).duckdns.org "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 07:43:27.530798" r2d2 68.12.104.178 40551 5.199.172.41 53 UDP IP 5.199.172.41 malware cybercrime-tracker.net\n' +
    '"2015-03-10 07:43:27.530800" r2d2 68.12.104.178 40551 5.199.172.41 53 UDP IP 5.199.172.41 malware cybercrime-tracker.net\n' +
    '"2015-03-10 07:43:27.531813" r2d2 68.12.104.178 43213 5.199.172.41 53 UDP IP 5.199.172.41 malware cybercrime-tracker.net\n' +
    '"2015-03-10 07:43:27.531811" r2d2 68.12.104.178 43213 5.199.172.41 53 UDP IP 5.199.172.41 malware cybercrime-tracker.net\n' +
    '"2015-03-10 07:43:36.028763" r2d2 68.12.104.178 49657 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 07:43:36.028764" r2d2 68.12.104.178 49657 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 07:44:13.227435" r2d2 68.12.104.178 44249 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 07:44:13.227437" r2d2 68.12.104.178 44249 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 07:44:17.916789" r2d2 68.12.104.178 41072 68.12.99.2 53 UDP DNS promisex.ru "zeus (malware)" (custom)\n' +
    '"2015-03-10 07:44:17.916786" r2d2 68.12.104.178 41072 68.12.99.2 53 UDP DNS promisex.ru "zeus (malware)" (custom)\n' +
    '"2015-03-10 07:44:22.474916" r2d2 68.12.104.178 47112 68.12.99.2 53 UDP DNS (ns2.workgroup).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:44:22.474913" r2d2 68.12.104.178 35332 68.12.99.2 53 UDP DNS (ns1.workgroup).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:44:22.474922" r2d2 68.12.104.178 47112 68.12.99.2 53 UDP DNS (ns2.workgroup).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:44:22.474914" r2d2 68.12.104.178 35332 68.12.99.2 53 UDP DNS (ns1.workgroup).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:44:35.862052" r2d2 68.12.104.178 40848 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 07:44:35.862025" r2d2 68.12.104.178 40848 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 07:44:37.168448" r2d2 68.12.104.178 40394 68.12.99.2 53 UDP DNS (tolkien).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:44:37.168450" r2d2 68.12.104.178 40394 68.12.99.2 53 UDP DNS (tolkien).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:44:37.620785" r2d2 68.12.104.178 48487 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 07:44:37.620783" r2d2 68.12.104.178 48487 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 07:44:41.762232" r2d2 68.12.104.178 36656 68.12.99.2 53 UDP DNS peer.pickeklosarske.ru "palevo (malware)" (static)\n' +
    '"2015-03-10 07:44:41.762219" r2d2 68.12.104.178 36656 68.12.99.2 53 UDP DNS peer.pickeklosarske.ru "palevo (malware)" (static)\n' +
    '"2015-03-10 07:44:44.512950" r2d2 68.12.104.178 44260 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 07:44:44.512946" r2d2 68.12.104.178 44260 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 07:45:08.478725" r2d2 68.12.104.178 56280 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 07:45:08.478724" r2d2 68.12.104.178 56280 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 07:45:10.152668" r2d2 68.12.104.178 45825 68.12.99.2 53 UDP DNS digitalmind.cn "palevo (malware)" palevotracker.abuse.ch\n' +
    '"2015-03-10 07:45:10.152667" r2d2 68.12.104.178 45825 68.12.99.2 53 UDP DNS digitalmind.cn "palevo (malware)" palevotracker.abuse.ch\n' +
    '"2015-03-10 07:45:16.031194" r2d2 68.12.104.178 43317 113.108.80.138 53 UDP IP 113.108.80.138 dnspod (custom)\n' +
    '"2015-03-10 07:45:16.031192" r2d2 68.12.104.178 43317 113.108.80.138 53 UDP IP 113.108.80.138 dnspod (custom)\n' +
    '"2015-03-10 07:45:22.244011" r2d2 68.12.104.178 46804 68.12.99.2 53 UDP DNS (ine).wanadoo.es attackpage safebrowsing.clients.google.com\n' +
    '"2015-03-10 07:45:22.244013" r2d2 68.12.104.178 46804 68.12.99.2 53 UDP DNS (ine).wanadoo.es attackpage safebrowsing.clients.google.com\n' +
    '"2015-03-10 07:45:28.827227" r2d2 68.12.104.178 36617 68.12.99.2 53 UDP DNS (mwsd).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:45:28.827228" r2d2 68.12.104.178 36617 68.12.99.2 53 UDP DNS (mwsd).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:45:38.161714" r2d2 68.12.104.178 35458 68.12.99.2 53 UDP DNS (mx.mytemp).email "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:45:38.161727" r2d2 68.12.104.178 35458 68.12.99.2 53 UDP DNS (mx.mytemp).email "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:45:38.726477" r2d2 68.12.104.178 59262 68.12.99.2 53 UDP DNS fitt.prince.kz "palevo (malware)" palevotracker.abuse.ch\n' +
    '"2015-03-10 07:45:38.726479" r2d2 68.12.104.178 59262 68.12.99.2 53 UDP DNS fitt.prince.kz "palevo (malware)" palevotracker.abuse.ch\n' +
    '"2015-03-10 07:45:38.746810" r2d2 68.12.104.178 44514 87.236.178.49 53 UDP IP 87.236.178.49 malware malwarepatrol.net\n' +
    '"2015-03-10 07:45:38.746806" r2d2 68.12.104.178 44514 87.236.178.49 53 UDP IP 87.236.178.49 malware malwarepatrol.net\n' +
    '"2015-03-10 07:45:39.493876" r2d2 68.12.104.178 43220 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 07:45:39.493974" r2d2 68.12.104.178 43220 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 07:45:46.150095" r2d2 68.12.104.178 45694 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 07:45:46.150090" r2d2 68.12.104.178 45694 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 07:45:50.835083" r2d2 68.12.104.178 36908 68.12.99.2 53 UDP DNS (ns1.coldzaens).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:45:50.835057" r2d2 68.12.104.178 36908 68.12.99.2 53 UDP DNS (ns1.coldzaens).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:45:50.835568" r2d2 68.12.104.178 53971 68.12.99.2 53 UDP DNS (ns2.coldzaens).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:45:50.835565" r2d2 68.12.104.178 53971 68.12.99.2 53 UDP DNS (ns2.coldzaens).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:45:50.836129" r2d2 68.12.104.178 36672 68.12.99.2 53 UDP DNS (ns3.coldzaens).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:45:50.836132" r2d2 68.12.104.178 48153 68.12.99.2 53 UDP DNS (ns4.coldzaens).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:45:50.836133" r2d2 68.12.104.178 48153 68.12.99.2 53 UDP DNS (ns4.coldzaens).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:45:50.836131" r2d2 68.12.104.178 36672 68.12.99.2 53 UDP DNS (ns3.coldzaens).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:46:08.741448" r2d2 68.12.104.178 49546 68.12.99.2 53 UDP DNS (eit.folks).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:46:08.741453" r2d2 68.12.104.178 49546 68.12.99.2 53 UDP DNS (eit.folks).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:46:10.046927" r2d2 68.12.104.178 45363 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 07:46:10.046925" r2d2 68.12.104.178 45363 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 07:46:16.996165" r2d2 68.12.104.178 52011 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 07:46:16.996162" r2d2 68.12.104.178 52011 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 07:46:21.975623" r2d2 68.12.104.178 36050 68.12.99.2 53 UDP DNS jorpe.co.za attackpage safebrowsing.clients.google.com\n' +
    '"2015-03-10 07:46:21.975625" r2d2 68.12.104.178 36050 68.12.99.2 53 UDP DNS jorpe.co.za attackpage safebrowsing.clients.google.com\n' +
    '"2015-03-10 07:46:25.225975" r2d2 68.12.104.178 40568 68.12.99.2 53 UDP DNS (mail.pcc).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:46:25.225983" r2d2 68.12.104.178 40568 68.12.99.2 53 UDP DNS (mail.pcc).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:46:26.147465" r2d2 68.12.104.178 55760 68.12.99.2 53 UDP DNS (mx1.spamfilter).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:46:26.147473" r2d2 68.12.104.178 55760 68.12.99.2 53 UDP DNS (mx1.spamfilter).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:46:27.590693" r2d2 68.12.104.178 47298 68.12.99.2 53 UDP DNS (caza).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:46:27.590692" r2d2 68.12.104.178 47298 68.12.99.2 53 UDP DNS (caza).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:46:40.866288" r2d2 68.12.104.178 51615 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 07:46:40.866327" r2d2 68.12.104.178 51615 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 07:46:41.870774" r2d2 68.12.104.178 49082 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 07:46:41.870760" r2d2 68.12.104.178 49082 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 07:46:49.524789" r2d2 212.83.132.65 5119 68.12.104.178 5060 UDP IP 212.83.132.65 "sipvicious scan" autoshun.org\n' +
    '"2015-03-10 07:46:49.524787" r2d2 212.83.132.65 5119 68.12.104.178 5060 UDP IP 212.83.132.65 "sipvicious scan" autoshun.org\n' +
    '"2015-03-10 07:46:50.127732" r2d2 68.12.104.178 40711 68.12.99.2 53 UDP DNS promisex.ru "zeus (malware)" (custom)\n' +
    '"2015-03-10 07:46:50.127735" r2d2 68.12.104.178 40711 68.12.99.2 53 UDP DNS promisex.ru "zeus (malware)" (custom)\n' +
    '"2015-03-10 07:47:05.811940" r2d2 68.12.104.178 54366 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 07:47:05.811939" r2d2 68.12.104.178 54366 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 07:47:09.813735" r2d2 68.12.104.178 46387 68.12.99.2 53 UDP DNS peer.pickeklosarske.ru "palevo (malware)" (static)\n' +
    '"2015-03-10 07:47:09.813746" r2d2 68.12.104.178 46387 68.12.99.2 53 UDP DNS peer.pickeklosarske.ru "palevo (malware)" (static)\n' +
    '"2015-03-10 07:47:18.615510" r2d2 68.12.104.178 53931 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 07:47:18.615509" r2d2 68.12.104.178 53931 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 07:47:19.694954" r2d2 68.12.104.178 35405 68.12.99.2 53 UDP DNS (brightlounge).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:47:19.695003" r2d2 68.12.104.178 35405 68.12.99.2 53 UDP DNS (brightlounge).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:47:24.998698" r2d2 68.12.104.178 57355 8.8.8.8 53 UDP DNS (brightlounge).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:47:24.998682" r2d2 68.12.104.178 57355 8.8.8.8 53 UDP DNS (brightlounge).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:47:38.274751" r2d2 68.12.104.178 59501 68.12.99.2 53 UDP DNS (fomichov).no-ip.biz "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 07:47:38.274730" r2d2 68.12.104.178 59501 68.12.99.2 53 UDP DNS (fomichov).no-ip.biz "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 07:47:40.019349" r2d2 68.12.104.178 44121 68.12.99.2 53 UDP DNS teske.pornicarke.com "palevo (malware)" (static)\n' +
    '"2015-03-10 07:47:40.019347" r2d2 68.12.104.178 44121 68.12.99.2 53 UDP DNS teske.pornicarke.com "palevo (malware)" (static)\n' +
    '"2015-03-10 07:47:43.514410" r2d2 68.12.104.178 50387 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 07:47:43.514409" r2d2 68.12.104.178 50387 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 07:47:49.530439" r2d2 68.12.104.178 59690 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 07:47:49.530441" r2d2 68.12.104.178 59690 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 07:47:59.831069" r2d2 68.12.104.178 40246 122.155.16.127 53 UDP IP 122.155.16.127 "brute forcer" danger.rulez.sk\n' +
    '"2015-03-10 07:47:59.831073" r2d2 68.12.104.178 40246 122.155.16.127 53 UDP IP 122.155.16.127 "brute forcer" danger.rulez.sk\n' +
    '"2015-03-10 07:48:02.787105" r2d2 68.12.104.178 36753 68.12.99.2 53 UDP DNS counter.yadro.ru "zeroaccess (malware)" (static)\n' +
    '"2015-03-10 07:48:02.787107" r2d2 68.12.104.178 36753 68.12.99.2 53 UDP DNS counter.yadro.ru "zeroaccess (malware)" (static)\n' +
    '"2015-03-10 07:48:09.584051" r2d2 68.12.104.178 53916 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 07:48:09.584048" r2d2 68.12.104.178 53916 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 07:48:14.408540" r2d2 68.12.104.178 35782 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 07:48:14.408543" r2d2 68.12.104.178 35782 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 07:48:16.356066" r2d2 68.12.104.178 40017 68.12.99.2 53 UDP DNS (mx3.spamfilter).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:48:16.356064" r2d2 68.12.104.178 40017 68.12.99.2 53 UDP DNS (mx3.spamfilter).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:48:18.310598" r2d2 68.12.104.178 56905 68.12.99.2 53 UDP DNS (neversay).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:48:18.310588" r2d2 68.12.104.178 56905 68.12.99.2 53 UDP DNS (neversay).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:48:29.316870" r2d2 68.12.104.178 56919 212.24.144.188 53 UDP IP 212.24.144.188 "tor exit node" torproject.org\n' +
    '"2015-03-10 07:48:29.316873" r2d2 68.12.104.178 56919 212.24.144.188 53 UDP IP 212.24.144.188 "tor exit node" torproject.org\n' +
    '"2015-03-10 07:48:31.390998" r2d2 68.12.104.178 40737 212.24.144.188 53 UDP IP 212.24.144.188 "tor exit node" torproject.org\n' +
    '"2015-03-10 07:48:31.391117" r2d2 68.12.104.178 40737 212.24.144.188 53 UDP IP 212.24.144.188 "tor exit node" torproject.org\n' +
    '"2015-03-10 07:48:51.172069" r2d2 68.12.104.178 37724 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 07:48:51.172070" r2d2 68.12.104.178 37724 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 07:48:53.830190" r2d2 68.12.104.178 37295 68.12.99.2 53 UDP DNS (ns5.devel).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:48:53.829783" r2d2 68.12.104.178 52627 68.12.99.2 53 UDP DNS (ns4.devel).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:48:53.829781" r2d2 68.12.104.178 52627 68.12.99.2 53 UDP DNS (ns4.devel).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:48:53.830189" r2d2 68.12.104.178 37295 68.12.99.2 53 UDP DNS (ns5.devel).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:48:57.765751" r2d2 68.12.104.178 44230 68.12.99.2 53 UDP DNS (wearethechurch).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:48:57.765748" r2d2 68.12.104.178 44230 68.12.99.2 53 UDP DNS (wearethechurch).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:49:10.595043" r2d2 68.12.104.178 41611 81.2.199.97 53 UDP IP 81.2.199.97 "asprox (malware)" atrack.h3x.eu\n' +
    '"2015-03-10 07:49:10.595041" r2d2 68.12.104.178 41611 81.2.199.97 53 UDP IP 81.2.199.97 "asprox (malware)" atrack.h3x.eu\n' +
    '"2015-03-10 07:49:16.359694" r2d2 68.12.104.178 57373 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 07:49:16.359695" r2d2 68.12.104.178 57373 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 07:49:22.011575" r2d2 68.12.104.178 43788 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 07:49:22.011578" r2d2 68.12.104.178 43788 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 07:49:28.797209" r2d2 68.12.104.178 45698 68.12.99.2 53 UDP DNS (ns0.starbwqinfo).xyz "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:49:28.797213" r2d2 68.12.104.178 45698 68.12.99.2 53 UDP DNS (ns0.starbwqinfo).xyz "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:49:35.727981" r2d2 68.12.104.178 57720 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 07:49:35.727978" r2d2 68.12.104.178 57720 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 07:49:35.828687" r2d2 68.12.104.178 49378 68.12.99.2 53 UDP DNS sureioratte.ru "zeus (malware)" zeustracker.abuse.ch\n' +
    '"2015-03-10 07:49:35.828685" r2d2 68.12.104.178 49378 68.12.99.2 53 UDP DNS sureioratte.ru "zeus (malware)" zeustracker.abuse.ch\n' +
    '"2015-03-10 07:49:39.678512" r2d2 68.12.104.178 54711 68.12.99.2 53 UDP DNS peer.pickeklosarske.ru "palevo (malware)" (static)\n' +
    '"2015-03-10 07:49:39.678514" r2d2 68.12.104.178 54711 68.12.99.2 53 UDP DNS peer.pickeklosarske.ru "palevo (malware)" (static)\n' +
    '"2015-03-10 07:49:47.169980" r2d2 68.12.104.178 51374 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 07:49:47.169976" r2d2 68.12.104.178 51374 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 07:49:48.882304" r2d2 68.12.104.178 39982 68.12.99.2 53 UDP DNS (mx02.ha.epcom).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:49:48.882300" r2d2 68.12.104.178 39982 68.12.99.2 53 UDP DNS (mx02.ha.epcom).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:49:54.325991" r2d2 68.12.104.178 54257 68.12.99.2 53 UDP DNS gmai.com "fake flash" www.malwaredomains.com\n' +
    '"2015-03-10 07:49:54.325986" r2d2 68.12.104.178 54257 68.12.99.2 53 UDP DNS gmai.com "fake flash" www.malwaredomains.com\n' +
    '"2015-03-10 07:49:56.717333" r2d2 68.12.104.178 41417 109.74.194.110 53 UDP IP 109.74.194.110 c&c emergingthreats.net\n' +
    '"2015-03-10 07:49:56.717322" r2d2 68.12.104.178 41417 109.74.194.110 53 UDP IP 109.74.194.110 c&c emergingthreats.net\n' +
    '"2015-03-10 07:50:00.293423" r2d2 68.12.104.178 53909 68.12.99.2 53 UDP DNS (rzone).onthenetas.com malspam blog.dynamoo.com\n' +
    '"2015-03-10 07:50:00.293424" r2d2 68.12.104.178 53909 68.12.99.2 53 UDP DNS (rzone).onthenetas.com malspam blog.dynamoo.com\n' +
    '"2015-03-10 07:50:06.432199" r2d2 68.12.104.178 36109 68.12.99.2 53 UDP DNS (zdzupanija).dynu.com "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 07:50:06.432196" r2d2 68.12.104.178 36109 68.12.99.2 53 UDP DNS (zdzupanija).dynu.com "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 07:50:08.345956" r2d2 68.12.104.178 40417 68.12.99.2 53 UDP DNS promisex.ru "zeus (malware)" (custom)\n' +
    '"2015-03-10 07:50:08.345952" r2d2 68.12.104.178 40417 68.12.99.2 53 UDP DNS promisex.ru "zeus (malware)" (custom)\n' +
    '"2015-03-10 07:50:12.969652" r2d2 68.12.104.178 46133 68.12.99.2 53 UDP DNS (artbox).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:50:12.969648" r2d2 68.12.104.178 46133 68.12.99.2 53 UDP DNS (artbox).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:50:21.196835" r2d2 68.12.104.178 51989 68.12.99.2 53 UDP DNS (monitmass).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:50:21.196833" r2d2 68.12.104.178 51989 68.12.99.2 53 UDP DNS (monitmass).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:50:23.620300" r2d2 68.12.104.178 36987 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 07:50:23.620301" r2d2 68.12.104.178 36987 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 07:50:24.367987" r2d2 68.12.104.178 46178 68.12.99.2 53 UDP DNS (012).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:50:24.367988" r2d2 68.12.104.178 46178 68.12.99.2 53 UDP DNS (012).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:50:27.557840" r2d2 68.12.104.178 46493 68.12.99.2 53 UDP DNS (onlineplay).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:50:27.557843" r2d2 68.12.104.178 46493 68.12.99.2 53 UDP DNS (onlineplay).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:50:41.036588" r2d2 68.12.104.178 49407 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 07:50:41.036589" r2d2 68.12.104.178 49407 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 07:50:48.776985" r2d2 68.12.104.178 37360 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 07:50:48.776975" r2d2 68.12.104.178 37360 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 07:50:54.448751" r2d2 68.12.104.178 46987 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 07:50:54.448749" r2d2 68.12.104.178 46987 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 07:50:58.304839" r2d2 68.12.104.178 59387 68.12.99.2 53 UDP DNS (errors).ourdatagenserv.com malware malwareurls.joxeankoret.com\n' +
    '"2015-03-10 07:50:58.304831" r2d2 68.12.104.178 59387 68.12.99.2 53 UDP DNS (errors).ourdatagenserv.com malware malwareurls.joxeankoret.com\n' +
    '"2015-03-10 07:51:19.588900" r2d2 68.12.104.178 57574 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 07:51:19.588897" r2d2 68.12.104.178 57574 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 07:51:20.387426" r2d2 68.12.104.178 46539 68.12.99.2 53 UDP DNS digitalmind.cn "palevo (malware)" palevotracker.abuse.ch\n' +
    '"2015-03-10 07:51:20.387423" r2d2 68.12.104.178 46539 68.12.99.2 53 UDP DNS digitalmind.cn "palevo (malware)" palevotracker.abuse.ch\n' +
    '"2015-03-10 07:51:21.586494" r2d2 68.12.104.178 37761 68.12.99.2 53 UDP DNS (ns1).torpig-sinkhole.org "torpig (malware)" (static)\n' +
    '"2015-03-10 07:51:21.586789" r2d2 68.12.104.178 58482 68.12.99.2 53 UDP DNS (ns1).torpig-sinkhole.org "torpig (malware)" (static)\n' +
    '"2015-03-10 07:51:21.586492" r2d2 68.12.104.178 37761 68.12.99.2 53 UDP DNS (ns1).torpig-sinkhole.org "torpig (malware)" (static)\n' +
    '"2015-03-10 07:51:21.587349" r2d2 68.12.104.178 50849 68.12.99.2 53 UDP DNS (ns2).torpig-sinkhole.org "torpig (malware)" (static)\n' +
    '"2015-03-10 07:51:21.586598" r2d2 68.12.104.178 58482 68.12.99.2 53 UDP DNS (ns1).torpig-sinkhole.org "torpig (malware)" (static)\n' +
    '"2015-03-10 07:51:21.586837" r2d2 68.12.104.178 46926 68.12.99.2 53 UDP DNS (ns2).torpig-sinkhole.org "torpig (malware)" (static)\n' +
    '"2015-03-10 07:51:21.586841" r2d2 68.12.104.178 46926 68.12.99.2 53 UDP DNS (ns2).torpig-sinkhole.org "torpig (malware)" (static)\n' +
    '"2015-03-10 07:51:21.587352" r2d2 68.12.104.178 50849 68.12.99.2 53 UDP DNS (ns2).torpig-sinkhole.org "torpig (malware)" (static)\n' +
    '"2015-03-10 07:51:21.783231" r2d2 68.12.104.178 59020 87.106.240.162 53 UDP IP 87.106.240.162 "torpig (malware)" (static)\n' +
    '"2015-03-10 07:51:21.783221" r2d2 68.12.104.178 59020 87.106.240.162 53 UDP IP 87.106.240.162 "torpig (malware)" (static)\n' +
    '"2015-03-10 07:51:21.785256" r2d2 68.12.104.178 40897 87.106.240.162 53 UDP IP 87.106.240.162 "torpig (malware)" (static)\n' +
    '"2015-03-10 07:51:21.785253" r2d2 68.12.104.178 40897 87.106.240.162 53 UDP IP 87.106.240.162 "torpig (malware)" (static)\n' +
    '"2015-03-10 07:51:21.810452" r2d2 68.12.104.178 40499 212.227.55.84 53 UDP IP 212.227.55.84 "torpig (malware)" (static)\n' +
    '"2015-03-10 07:51:21.810737" r2d2 68.12.104.178 52108 212.227.55.84 53 UDP IP 212.227.55.84 "torpig (malware)" (static)\n' +
    '"2015-03-10 07:51:21.810432" r2d2 68.12.104.178 40499 212.227.55.84 53 UDP IP 212.227.55.84 "torpig (malware)" (static)\n' +
    '"2015-03-10 07:51:21.810728" r2d2 68.12.104.178 52108 212.227.55.84 53 UDP IP 212.227.55.84 "torpig (malware)" (static)\n' +
    '"2015-03-10 07:51:21.840066" r2d2 68.12.104.178 40852 212.227.55.84 53 UDP IP 212.227.55.84 "torpig (malware)" (static)\n' +
    '"2015-03-10 07:51:23.136801" r2d2 68.12.104.178 39321 68.12.99.2 53 UDP DNS (ns1.webtek).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:51:23.136803" r2d2 68.12.104.178 39321 68.12.99.2 53 UDP DNS (ns1.webtek).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:51:23.137141" r2d2 68.12.104.178 58267 68.12.99.2 53 UDP DNS (ns1.webtek).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:51:23.137125" r2d2 68.12.104.178 58267 68.12.99.2 53 UDP DNS (ns1.webtek).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:51:23.137306" r2d2 68.12.104.178 47530 68.12.99.2 53 UDP DNS (ns2.webtek).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:51:23.137889" r2d2 68.12.104.178 48360 68.12.99.2 53 UDP DNS (ns2.webtek).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:51:23.137289" r2d2 68.12.104.178 47530 68.12.99.2 53 UDP DNS (ns2.webtek).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:51:23.137878" r2d2 68.12.104.178 48360 68.12.99.2 53 UDP DNS (ns2.webtek).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:51:56.058027" r2d2 68.12.104.178 44023 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 07:51:56.058020" r2d2 68.12.104.178 44023 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 07:52:04.062109" r2d2 68.12.104.178 38847 68.12.99.2 53 UDP DNS (ns2.hosting2).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:52:04.061976" r2d2 68.12.104.178 40916 68.12.99.2 53 UDP DNS (ns1.hosting2).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:52:04.061978" r2d2 68.12.104.178 40916 68.12.99.2 53 UDP DNS (ns1.hosting2).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:52:04.062108" r2d2 68.12.104.178 38847 68.12.99.2 53 UDP DNS (ns2.hosting2).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:52:04.631165" r2d2 68.12.104.178 57562 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 07:52:04.631162" r2d2 68.12.104.178 57562 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 07:52:07.713559" r2d2 68.12.104.178 56050 68.12.99.2 53 UDP DNS www.vipcpms.com malware malwaredomainlist.com\n' +
    '"2015-03-10 07:52:07.713562" r2d2 68.12.104.178 56050 68.12.99.2 53 UDP DNS www.vipcpms.com malware malwaredomainlist.com\n' +
    '"2015-03-10 07:52:10.251994" r2d2 68.12.104.178 38410 68.12.99.2 53 UDP DNS peer.pickeklosarske.ru "palevo (malware)" (static)\n' +
    '"2015-03-10 07:52:10.251989" r2d2 68.12.104.178 38410 68.12.99.2 53 UDP DNS peer.pickeklosarske.ru "palevo (malware)" (static)\n' +
    '"2015-03-10 07:52:13.695066" r2d2 68.12.104.178 38425 68.12.99.2 53 UDP DNS (reitter).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:52:13.695072" r2d2 68.12.104.178 38425 68.12.99.2 53 UDP DNS (reitter).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:52:19.738722" r2d2 68.12.104.178 48793 113.108.80.138 53 UDP IP 113.108.80.138 dnspod (custom)\n' +
    '"2015-03-10 07:52:19.738724" r2d2 68.12.104.178 48793 113.108.80.138 53 UDP IP 113.108.80.138 dnspod (custom)\n' +
    '"2015-03-10 07:52:21.148572" r2d2 68.12.104.178 40947 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 07:52:21.148576" r2d2 68.12.104.178 40947 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 07:52:23.840708" r2d2 68.12.104.178 58875 68.12.99.2 53 UDP DNS (download).media-get.com suspicious dshield.org\n' +
    '"2015-03-10 07:52:23.840706" r2d2 68.12.104.178 58875 68.12.99.2 53 UDP DNS (download).media-get.com suspicious dshield.org\n' +
    '"2015-03-10 07:52:24.985225" r2d2 68.12.104.178 41504 68.12.99.2 53 UDP DNS (mail.occupythecomms).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:52:24.985244" r2d2 68.12.104.178 41504 68.12.99.2 53 UDP DNS (mail.occupythecomms).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:52:26.885637" r2d2 68.12.104.178 38104 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 07:52:26.885640" r2d2 68.12.104.178 38104 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 07:52:52.069054" r2d2 68.12.104.178 45764 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 07:52:52.069051" r2d2 68.12.104.178 45764 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 07:53:10.893240" r2d2 68.12.104.178 55904 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 07:53:10.893241" r2d2 68.12.104.178 55904 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 07:53:28.494980" r2d2 68.12.104.178 43615 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 07:53:28.494997" r2d2 68.12.104.178 43615 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 07:53:34.617950" r2d2 68.12.104.178 47811 198.58.93.56 53 UDP IP 198.58.93.56 malware cybercrime-tracker.net\n' +
    '"2015-03-10 07:53:34.617970" r2d2 68.12.104.178 47811 198.58.93.56 53 UDP IP 198.58.93.56 malware cybercrime-tracker.net\n' +
    '"2015-03-10 07:53:45.802447" r2d2 68.12.104.178 38893 68.12.99.2 53 UDP DNS (tracker.coppersurfer).tk "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:53:45.802449" r2d2 68.12.104.178 38893 68.12.99.2 53 UDP DNS (tracker.coppersurfer).tk "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:53:53.709465" r2d2 68.12.104.178 45073 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 07:53:53.709466" r2d2 68.12.104.178 45073 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 07:53:58.820936" r2d2 68.12.104.178 35981 113.108.80.138 53 UDP IP 113.108.80.138 dnspod (custom)\n' +
    '"2015-03-10 07:53:58.820938" r2d2 68.12.104.178 35981 113.108.80.138 53 UDP IP 113.108.80.138 dnspod (custom)\n' +
    '"2015-03-10 07:53:59.323033" r2d2 68.12.104.178 46974 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 07:53:59.323035" r2d2 68.12.104.178 46974 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 07:53:59.804567" r2d2 68.12.104.178 50238 113.108.80.138 53 UDP IP 113.108.80.138 dnspod (custom)\n' +
    '"2015-03-10 07:53:59.804565" r2d2 68.12.104.178 50238 113.108.80.138 53 UDP IP 113.108.80.138 dnspod (custom)\n' +
    '"2015-03-10 07:54:07.704266" r2d2 68.12.104.178 37903 68.12.99.2 53 UDP DNS (static7).superfish.com superfish (static)\n' +
    '"2015-03-10 07:54:07.704267" r2d2 68.12.104.178 37903 68.12.99.2 53 UDP DNS (static7).superfish.com superfish (static)\n' +
    '"2015-03-10 07:54:07.710373" r2d2 68.12.104.178 55899 68.12.99.2 53 UDP DNS (static8).superfish.com superfish (static)\n' +
    '"2015-03-10 07:54:07.710376" r2d2 68.12.104.178 55899 68.12.99.2 53 UDP DNS (static8).superfish.com superfish (static)\n' +
    '"2015-03-10 07:54:07.715425" r2d2 68.12.104.178 54797 68.12.99.2 53 UDP DNS (static9).superfish.com superfish (static)\n' +
    '"2015-03-10 07:54:07.715428" r2d2 68.12.104.178 54797 68.12.99.2 53 UDP DNS (static9).superfish.com superfish (static)\n' +
    '"2015-03-10 07:54:07.821562" r2d2 68.12.104.178 54130 68.12.99.2 53 UDP DNS (static).superfish.com superfish (static)\n' +
    '"2015-03-10 07:54:07.821564" r2d2 68.12.104.178 54130 68.12.99.2 53 UDP DNS (static).superfish.com superfish (static)\n' +
    '"2015-03-10 07:54:21.099366" r2d2 68.12.104.178 37959 113.108.80.138 53 UDP IP 113.108.80.138 dnspod (custom)\n' +
    '"2015-03-10 07:54:21.099364" r2d2 68.12.104.178 37959 113.108.80.138 53 UDP IP 113.108.80.138 dnspod (custom)\n' +
    '"2015-03-10 07:54:24.127195" r2d2 68.12.104.178 40826 68.12.99.2 53 UDP DNS (jabberstorm).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:54:24.127199" r2d2 68.12.104.178 40826 68.12.99.2 53 UDP DNS (jabberstorm).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:54:24.581768" r2d2 68.12.104.178 38467 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 07:54:24.581770" r2d2 68.12.104.178 38467 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 07:54:31.006466" r2d2 68.12.104.178 57355 8.8.8.8 53 UDP DNS (jabberstorm).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:54:31.006468" r2d2 68.12.104.178 57355 8.8.8.8 53 UDP DNS (jabberstorm).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:54:31.321612" r2d2 68.12.104.178 56372 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 07:54:31.321613" r2d2 68.12.104.178 56372 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 07:54:40.036228" r2d2 68.12.104.178 47498 68.12.99.2 53 UDP DNS peer.pickeklosarske.ru "palevo (malware)" (static)\n' +
    '"2015-03-10 07:54:40.036229" r2d2 68.12.104.178 47498 68.12.99.2 53 UDP DNS peer.pickeklosarske.ru "palevo (malware)" (static)\n' +
    '"2015-03-10 07:54:44.574225" r2d2 68.12.104.178 40543 68.12.99.2 53 UDP DNS (igate).myftp.org "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 07:54:44.574221" r2d2 68.12.104.178 40543 68.12.99.2 53 UDP DNS (igate).myftp.org "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 07:54:52.167273" r2d2 68.12.104.178 38878 68.12.99.2 53 UDP DNS counter.yadro.ru "zeroaccess (malware)" (static)\n' +
    '"2015-03-10 07:54:52.167276" r2d2 68.12.104.178 38878 68.12.99.2 53 UDP DNS counter.yadro.ru "zeroaccess (malware)" (static)\n' +
    '"2015-03-10 07:55:00.932364" r2d2 68.12.104.178 57710 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 07:55:00.932363" r2d2 68.12.104.178 57710 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 07:55:26.173426" r2d2 68.12.104.178 45382 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 07:55:26.173407" r2d2 68.12.104.178 45382 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 07:55:31.763825" r2d2 68.12.104.178 36059 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 07:55:31.763818" r2d2 68.12.104.178 36059 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 07:55:40.029448" r2d2 68.12.104.178 37125 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 07:55:40.029453" r2d2 68.12.104.178 37125 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 07:55:53.020937" r2d2 68.12.104.178 54824 68.12.99.2 53 UDP DNS (ns1.securehost).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:55:53.020523" r2d2 68.12.104.178 49959 68.12.99.2 53 UDP DNS (ns0.securehost).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:55:53.021555" r2d2 68.12.104.178 42322 68.12.99.2 53 UDP DNS (ns1.securehost).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:55:53.020929" r2d2 68.12.104.178 47618 68.12.99.2 53 UDP DNS (ns0.securehost).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:55:53.021560" r2d2 68.12.104.178 42473 68.12.99.2 53 UDP DNS (ns2.securehost).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:55:53.020936" r2d2 68.12.104.178 54824 68.12.99.2 53 UDP DNS (ns1.securehost).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:55:53.022125" r2d2 68.12.104.178 38725 68.12.99.2 53 UDP DNS (ns2.securehost).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:55:53.020520" r2d2 68.12.104.178 49959 68.12.99.2 53 UDP DNS (ns0.securehost).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:55:53.021554" r2d2 68.12.104.178 42322 68.12.99.2 53 UDP DNS (ns1.securehost).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:55:53.022607" r2d2 68.12.104.178 46155 68.12.99.2 53 UDP DNS (ns3.securehost).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:55:53.020916" r2d2 68.12.104.178 47618 68.12.99.2 53 UDP DNS (ns0.securehost).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:55:53.022133" r2d2 68.12.104.178 38725 68.12.99.2 53 UDP DNS (ns2.securehost).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:55:53.022605" r2d2 68.12.104.178 46155 68.12.99.2 53 UDP DNS (ns3.securehost).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:55:53.022744" r2d2 68.12.104.178 53085 68.12.99.2 53 UDP DNS (ns3.securehost).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:55:53.021562" r2d2 68.12.104.178 42473 68.12.99.2 53 UDP DNS (ns2.securehost).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:55:53.023180" r2d2 68.12.104.178 49007 68.12.99.2 53 UDP DNS (ns4.securehost).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:55:53.022740" r2d2 68.12.104.178 53085 68.12.99.2 53 UDP DNS (ns3.securehost).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:55:53.023174" r2d2 68.12.104.178 49007 68.12.99.2 53 UDP DNS (ns4.securehost).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:55:53.024308" r2d2 68.12.104.178 51157 68.12.99.2 53 UDP DNS (ns4.securehost).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:55:53.024313" r2d2 68.12.104.178 51157 68.12.99.2 53 UDP DNS (ns4.securehost).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:55:56.983327" r2d2 68.12.104.178 55777 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 07:55:56.983328" r2d2 68.12.104.178 55777 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 07:55:58.689283" r2d2 68.12.104.178 44972 68.12.99.2 53 UDP DNS (zsbrectanova).myvnc.com "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 07:55:58.689287" r2d2 68.12.104.178 44972 68.12.99.2 53 UDP DNS (zsbrectanova).myvnc.com "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 07:56:05.265421" r2d2 68.12.104.178 35813 68.12.99.2 53 UDP DNS (ns1.quant).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:56:05.265699" r2d2 68.12.104.178 44998 68.12.99.2 53 UDP DNS (ns2.quant).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:56:05.265420" r2d2 68.12.104.178 35813 68.12.99.2 53 UDP DNS (ns1.quant).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:56:05.265879" r2d2 68.12.104.178 39950 68.12.99.2 53 UDP DNS (ns3.quant).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:56:05.265696" r2d2 68.12.104.178 44998 68.12.99.2 53 UDP DNS (ns2.quant).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:56:05.265883" r2d2 68.12.104.178 39950 68.12.99.2 53 UDP DNS (ns3.quant).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:56:05.873123" r2d2 68.12.104.178 53743 38.102.150.29 53 UDP IP 38.102.150.29 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:56:05.873125" r2d2 68.12.104.178 53743 38.102.150.29 53 UDP IP 38.102.150.29 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:56:05.982389" r2d2 68.12.104.178 36145 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:56:05.982754" r2d2 68.12.104.178 47496 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:56:05.982756" r2d2 68.12.104.178 47496 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:56:05.982380" r2d2 68.12.104.178 36145 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:56:06.051587" r2d2 68.12.104.178 58369 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:56:06.051590" r2d2 68.12.104.178 58369 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:56:06.733730" r2d2 68.12.104.178 35256 38.229.70.125 53 UDP IP 38.229.70.125 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:56:06.733741" r2d2 68.12.104.178 35256 38.229.70.125 53 UDP IP 38.229.70.125 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:56:14.096137" r2d2 68.12.104.178 35068 38.229.70.125 53 UDP IP 38.229.70.125 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:56:14.096139" r2d2 68.12.104.178 35068 38.229.70.125 53 UDP IP 38.229.70.125 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:56:14.102597" r2d2 68.12.104.178 58035 38.229.70.125 53 UDP IP 38.229.70.125 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:56:14.102595" r2d2 68.12.104.178 58035 38.229.70.125 53 UDP IP 38.229.70.125 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:56:16.147015" r2d2 68.12.104.178 50018 68.12.99.2 53 UDP DNS (tvi).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:56:16.147018" r2d2 68.12.104.178 50018 68.12.99.2 53 UDP DNS (tvi).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:56:21.588110" r2d2 68.12.104.178 42093 38.102.150.29 53 UDP IP 38.102.150.29 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:56:21.588108" r2d2 68.12.104.178 42093 38.102.150.29 53 UDP IP 38.102.150.29 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:56:21.611322" r2d2 68.12.104.178 46439 38.102.150.29 53 UDP IP 38.102.150.29 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:56:21.611332" r2d2 68.12.104.178 46439 38.102.150.29 53 UDP IP 38.102.150.29 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:56:21.611872" r2d2 68.12.104.178 47337 38.102.150.29 53 UDP IP 38.102.150.29 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:56:21.611871" r2d2 68.12.104.178 47337 38.102.150.29 53 UDP IP 38.102.150.29 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:56:21.762697" r2d2 68.12.104.178 46282 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:56:21.762983" r2d2 68.12.104.178 45724 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:56:21.762972" r2d2 68.12.104.178 45724 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:56:21.762688" r2d2 68.12.104.178 46282 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:56:21.763488" r2d2 68.12.104.178 59372 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:56:21.763501" r2d2 68.12.104.178 59372 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:56:28.934732" r2d2 68.12.104.178 40002 38.229.70.125 53 UDP IP 38.229.70.125 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:56:28.934745" r2d2 68.12.104.178 40002 38.229.70.125 53 UDP IP 38.229.70.125 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:56:31.245080" r2d2 68.12.104.178 56302 68.12.99.2 53 UDP DNS (ns1.konov).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:56:31.245084" r2d2 68.12.104.178 56302 68.12.99.2 53 UDP DNS (ns1.konov).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:56:31.770850" r2d2 68.12.104.178 35582 174.136.57.250 53 UDP IP 174.136.57.250 malware cybercrime-tracker.net\n' +
    '"2015-03-10 07:56:31.770496" r2d2 68.12.104.178 39311 174.136.57.250 53 UDP IP 174.136.57.250 malware cybercrime-tracker.net\n' +
    '"2015-03-10 07:56:31.770485" r2d2 68.12.104.178 39311 174.136.57.250 53 UDP IP 174.136.57.250 malware cybercrime-tracker.net\n' +
    '"2015-03-10 07:56:31.770854" r2d2 68.12.104.178 35582 174.136.57.250 53 UDP IP 174.136.57.250 malware cybercrime-tracker.net\n' +
    '"2015-03-10 07:56:31.899735" r2d2 68.12.104.178 57239 174.136.57.250 53 UDP IP 174.136.57.250 malware cybercrime-tracker.net\n' +
    '"2015-03-10 07:56:31.899736" r2d2 68.12.104.178 57239 174.136.57.250 53 UDP IP 174.136.57.250 malware cybercrime-tracker.net\n' +
    '"2015-03-10 07:56:33.381614" r2d2 68.12.104.178 53509 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 07:56:33.381616" r2d2 68.12.104.178 53509 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 07:56:34.382611" r2d2 68.12.104.178 35057 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 07:56:34.382613" r2d2 68.12.104.178 35057 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 07:56:43.713043" r2d2 68.12.104.178 41613 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:56:43.713044" r2d2 68.12.104.178 41613 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:56:43.764845" r2d2 68.12.104.178 40997 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:56:43.764846" r2d2 68.12.104.178 40997 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:56:45.389112" r2d2 68.12.104.178 52979 68.12.99.2 53 UDP DNS promisex.ru "zeus (malware)" (custom)\n' +
    '"2015-03-10 07:56:45.389114" r2d2 68.12.104.178 52979 68.12.99.2 53 UDP DNS promisex.ru "zeus (malware)" (custom)\n' +
    '"2015-03-10 07:56:51.049905" r2d2 68.12.104.178 44351 38.229.70.125 53 UDP IP 38.229.70.125 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:56:51.049908" r2d2 68.12.104.178 44351 38.229.70.125 53 UDP IP 38.229.70.125 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:56:58.502745" r2d2 68.12.104.178 59050 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:56:58.502743" r2d2 68.12.104.178 59050 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:56:58.504866" r2d2 68.12.104.178 35390 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 07:56:58.504867" r2d2 68.12.104.178 35390 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 07:56:58.540377" r2d2 68.12.104.178 45718 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:56:58.539827" r2d2 68.12.104.178 45718 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:56:58.605573" r2d2 68.12.104.178 55405 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 07:56:58.605551" r2d2 68.12.104.178 55405 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 07:57:05.213490" r2d2 68.12.104.178 57324 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 07:57:05.213499" r2d2 68.12.104.178 57324 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 07:57:09.307836" r2d2 68.12.104.178 39587 212.24.144.188 53 UDP IP 212.24.144.188 "tor exit node" torproject.org\n' +
    '"2015-03-10 07:57:09.307837" r2d2 68.12.104.178 39587 212.24.144.188 53 UDP IP 212.24.144.188 "tor exit node" torproject.org\n' +
    '"2015-03-10 07:57:10.218650" r2d2 68.12.104.178 38781 68.12.99.2 53 UDP DNS peer.pickeklosarske.ru "palevo (malware)" (static)\n' +
    '"2015-03-10 07:57:10.218661" r2d2 68.12.104.178 38781 68.12.99.2 53 UDP DNS peer.pickeklosarske.ru "palevo (malware)" (static)\n' +
    '"2015-03-10 07:57:13.420916" r2d2 68.12.104.178 50468 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:57:13.420914" r2d2 68.12.104.178 50468 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:57:21.020699" r2d2 68.12.104.178 46079 38.229.70.125 53 UDP IP 38.229.70.125 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:57:21.020963" r2d2 68.12.104.178 46079 38.229.70.125 53 UDP IP 38.229.70.125 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:57:21.035438" r2d2 68.12.104.178 49420 38.229.70.125 53 UDP IP 38.229.70.125 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:57:21.035295" r2d2 68.12.104.178 49420 38.229.70.125 53 UDP IP 38.229.70.125 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:57:28.347542" r2d2 68.12.104.178 39641 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:57:28.347539" r2d2 68.12.104.178 39641 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:57:29.433268" r2d2 68.12.104.178 51421 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 07:57:29.433265" r2d2 68.12.104.178 51421 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 07:57:32.924322" r2d2 68.12.104.178 47810 95.154.24.73 53 UDP IP 95.154.24.73 "tor exit node" torproject.org\n' +
    '"2015-03-10 07:57:32.924320" r2d2 68.12.104.178 47810 95.154.24.73 53 UDP IP 95.154.24.73 "tor exit node" torproject.org\n' +
    '"2015-03-10 07:57:34.669531" r2d2 68.12.104.178 59039 68.12.99.2 53 UDP DNS digitalmind.cn "palevo (malware)" palevotracker.abuse.ch\n' +
    '"2015-03-10 07:57:34.669520" r2d2 68.12.104.178 59039 68.12.99.2 53 UDP DNS digitalmind.cn "palevo (malware)" palevotracker.abuse.ch\n' +
    '"2015-03-10 07:57:35.701922" r2d2 68.12.104.178 38700 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:57:35.701929" r2d2 68.12.104.178 38700 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:57:35.732477" r2d2 68.12.104.178 41131 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:57:35.732499" r2d2 68.12.104.178 41131 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:57:36.040900" r2d2 68.12.104.178 50687 68.12.99.2 53 UDP DNS pica.banjalucke-ljepotice.ru "palevo (malware)" (static)\n' +
    '"2015-03-10 07:57:36.040901" r2d2 68.12.104.178 50687 68.12.99.2 53 UDP DNS pica.banjalucke-ljepotice.ru "palevo (malware)" (static)\n' +
    '"2015-03-10 07:57:40.049428" r2d2 68.12.104.178 53908 68.12.99.2 53 UDP DNS teske.pornicarke.com "palevo (malware)" (static)\n' +
    '"2015-03-10 07:57:40.049427" r2d2 68.12.104.178 53908 68.12.99.2 53 UDP DNS teske.pornicarke.com "palevo (malware)" (static)\n' +
    '"2015-03-10 07:57:43.206486" r2d2 68.12.104.178 57327 38.102.150.29 53 UDP IP 38.102.150.29 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:57:43.206585" r2d2 68.12.104.178 57327 38.102.150.29 53 UDP IP 38.102.150.29 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:57:50.254094" r2d2 68.12.104.178 37544 68.12.99.2 53 UDP DNS (6y).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:57:50.254110" r2d2 68.12.104.178 37544 68.12.99.2 53 UDP DNS (6y).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:57:50.503435" r2d2 68.12.104.178 37986 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:57:50.503452" r2d2 68.12.104.178 37986 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:57:57.853886" r2d2 68.12.104.178 46864 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:57:57.853888" r2d2 68.12.104.178 46864 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:58:02.793209" r2d2 68.12.104.178 58579 68.12.99.2 53 UDP DNS (brightlounge).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:58:02.793199" r2d2 68.12.104.178 58579 68.12.99.2 53 UDP DNS (brightlounge).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:58:05.294222" r2d2 68.12.104.178 53459 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:58:05.294223" r2d2 68.12.104.178 53459 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:58:05.317384" r2d2 68.12.104.178 49983 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:58:05.317402" r2d2 68.12.104.178 49983 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:58:05.334830" r2d2 68.12.104.178 44446 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:58:05.334844" r2d2 68.12.104.178 44446 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:58:05.336019" r2d2 68.12.104.178 35678 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:58:05.336018" r2d2 68.12.104.178 35678 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:58:07.162404" r2d2 68.12.104.178 37699 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 07:58:07.162407" r2d2 68.12.104.178 37699 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 07:58:10.053763" r2d2 68.12.104.178 39786 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 07:58:10.053762" r2d2 68.12.104.178 39786 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 07:58:16.243964" r2d2 68.12.104.178 50356 113.108.80.138 53 UDP IP 113.108.80.138 dnspod (custom)\n' +
    '"2015-03-10 07:58:16.243971" r2d2 68.12.104.178 50356 113.108.80.138 53 UDP IP 113.108.80.138 dnspod (custom)\n' +
    '"2015-03-10 07:58:20.156084" r2d2 68.12.104.178 54651 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:58:20.156083" r2d2 68.12.104.178 54651 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:58:20.172288" r2d2 68.12.104.178 47330 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:58:20.172286" r2d2 68.12.104.178 47330 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:58:23.167625" r2d2 68.12.104.178 48151 68.12.99.2 53 UDP DNS (mx.mytemp).email "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:58:23.167627" r2d2 68.12.104.178 48151 68.12.99.2 53 UDP DNS (mx.mytemp).email "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:58:29.729147" r2d2 68.12.104.178 35385 68.12.99.2 53 UDP DNS (dasleihcenter).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:58:29.729144" r2d2 68.12.104.178 35385 68.12.99.2 53 UDP DNS (dasleihcenter).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:58:31.024232" r2d2 68.12.104.178 45675 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 07:58:31.024235" r2d2 68.12.104.178 45675 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 07:58:32.366426" r2d2 68.12.104.178 37598 113.108.80.138 53 UDP IP 113.108.80.138 dnspod (custom)\n' +
    '"2015-03-10 07:58:32.366437" r2d2 68.12.104.178 37598 113.108.80.138 53 UDP IP 113.108.80.138 dnspod (custom)\n' +
    '"2015-03-10 07:58:34.994996" r2d2 68.12.104.178 49655 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:58:34.994997" r2d2 68.12.104.178 49655 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:58:35.009388" r2d2 68.12.104.178 53588 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:58:35.009389" r2d2 68.12.104.178 53588 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:58:38.029720" r2d2 68.12.104.178 42938 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 07:58:38.029723" r2d2 68.12.104.178 42938 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 07:58:42.476374" r2d2 68.12.104.178 48578 38.102.150.29 53 UDP IP 38.102.150.29 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:58:42.476377" r2d2 68.12.104.178 48578 38.102.150.29 53 UDP IP 38.102.150.29 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:58:42.506321" r2d2 68.12.104.178 51740 38.102.150.29 53 UDP IP 38.102.150.29 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:58:42.506355" r2d2 68.12.104.178 51740 38.102.150.29 53 UDP IP 38.102.150.29 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:58:57.244855" r2d2 68.12.104.178 45955 198.58.92.228 53 UDP IP 198.58.92.228 malware cybercrime-tracker.net\n' +
    '"2015-03-10 07:58:57.244852" r2d2 68.12.104.178 45955 198.58.92.228 53 UDP IP 198.58.92.228 malware cybercrime-tracker.net\n' +
    '"2015-03-10 07:58:57.261063" r2d2 68.12.104.178 45510 113.108.80.138 53 UDP IP 113.108.80.138 dnspod (custom)\n' +
    '"2015-03-10 07:58:57.261054" r2d2 68.12.104.178 45510 113.108.80.138 53 UDP IP 113.108.80.138 dnspod (custom)\n' +
    '"2015-03-10 07:58:57.269734" r2d2 68.12.104.178 51011 113.108.80.138 53 UDP IP 113.108.80.138 dnspod (custom)\n' +
    '"2015-03-10 07:58:57.269738" r2d2 68.12.104.178 51011 113.108.80.138 53 UDP IP 113.108.80.138 dnspod (custom)\n' +
    '"2015-03-10 07:58:57.429698" r2d2 68.12.104.178 39900 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:58:57.430439" r2d2 68.12.104.178 36954 198.58.92.228 53 UDP IP 198.58.92.228 malware cybercrime-tracker.net\n' +
    '"2015-03-10 07:58:57.430427" r2d2 68.12.104.178 36954 198.58.92.228 53 UDP IP 198.58.92.228 malware cybercrime-tracker.net\n' +
    '"2015-03-10 07:58:57.429700" r2d2 68.12.104.178 39900 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:58:57.750855" r2d2 68.12.104.178 53879 68.12.99.2 53 UDP DNS (pegasus).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:58:57.750851" r2d2 68.12.104.178 53879 68.12.99.2 53 UDP DNS (pegasus).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:58:58.467019" r2d2 68.12.104.178 36880 198.58.92.228 53 UDP IP 198.58.92.228 malware cybercrime-tracker.net\n' +
    '"2015-03-10 07:58:58.467017" r2d2 68.12.104.178 36880 198.58.92.228 53 UDP IP 198.58.92.228 malware cybercrime-tracker.net\n' +
    '"2015-03-10 07:58:58.777859" r2d2 68.12.104.178 38367 198.58.92.228 53 UDP IP 198.58.92.228 malware cybercrime-tracker.net\n' +
    '"2015-03-10 07:58:58.777848" r2d2 68.12.104.178 38367 198.58.92.228 53 UDP IP 198.58.92.228 malware cybercrime-tracker.net\n' +
    '"2015-03-10 07:58:59.345075" r2d2 68.12.104.178 38367 198.58.92.228 53 UDP IP 198.58.92.228 malware cybercrime-tracker.net\n' +
    '"2015-03-10 07:58:59.345079" r2d2 68.12.104.178 38367 198.58.92.228 53 UDP IP 198.58.92.228 malware cybercrime-tracker.net\n' +
    '"2015-03-10 07:59:01.913230" r2d2 68.12.104.178 57265 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 07:59:01.913218" r2d2 68.12.104.178 57265 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 07:59:05.776570" r2d2 68.12.104.178 36814 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:59:05.776551" r2d2 68.12.104.178 36814 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 07:59:12.967322" r2d2 68.12.104.178 46083 68.12.99.2 53 UDP DNS (hafi).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:59:12.967333" r2d2 68.12.104.178 46083 68.12.99.2 53 UDP DNS (hafi).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:59:25.051960" r2d2 68.12.104.178 51348 68.12.99.2 53 UDP DNS (47rgl).no-ip.org "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 07:59:25.051962" r2d2 68.12.104.178 51348 68.12.99.2 53 UDP DNS (47rgl).no-ip.org "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 07:59:25.210820" r2d2 68.12.104.178 55442 68.12.99.2 53 UDP DNS (tracker.coppersurfer).tk "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:59:25.210822" r2d2 68.12.104.178 55442 68.12.99.2 53 UDP DNS (tracker.coppersurfer).tk "domain (suspicious)" (static)\n' +
    '"2015-03-10 07:59:26.829563" r2d2 68.12.104.178 41698 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 07:59:26.829550" r2d2 68.12.104.178 41698 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 07:59:33.642739" r2d2 68.12.104.178 36424 68.12.99.2 53 UDP DNS promisex.ru "zeus (malware)" (custom)\n' +
    '"2015-03-10 07:59:33.642749" r2d2 68.12.104.178 36424 68.12.99.2 53 UDP DNS promisex.ru "zeus (malware)" (custom)\n' +
    '"2015-03-10 07:59:39.649559" r2d2 68.12.104.178 39204 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 07:59:39.649572" r2d2 68.12.104.178 39204 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 07:59:40.115794" r2d2 68.12.104.178 49410 68.12.99.2 53 UDP DNS peer.pickeklosarske.ru "palevo (malware)" (static)\n' +
    '"2015-03-10 07:59:40.115797" r2d2 68.12.104.178 49410 68.12.99.2 53 UDP DNS peer.pickeklosarske.ru "palevo (malware)" (static)\n' +
    '"2015-03-10 07:59:55.185376" r2d2 68.12.104.178 44966 5.199.172.41 53 UDP IP 5.199.172.41 malware cybercrime-tracker.net\n' +
    '"2015-03-10 07:59:55.185360" r2d2 68.12.104.178 44966 5.199.172.41 53 UDP IP 5.199.172.41 malware cybercrime-tracker.net\n' +
    '"2015-03-10 08:00:00.965942" r2d2 68.12.104.178 38294 68.12.99.2 53 UDP DNS (mx.cloudafrica).email "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:00:00.965921" r2d2 68.12.104.178 38294 68.12.99.2 53 UDP DNS (mx.cloudafrica).email "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:00:01.104541" r2d2 68.12.104.178 36573 68.12.99.2 53 UDP DNS (mx01.cloudafrica).email "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:00:01.104538" r2d2 68.12.104.178 36573 68.12.99.2 53 UDP DNS (mx01.cloudafrica).email "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:00:03.512952" r2d2 68.12.104.178 44592 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 08:00:03.512951" r2d2 68.12.104.178 44592 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 08:00:10.480063" r2d2 68.12.104.178 56167 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 08:00:10.480066" r2d2 68.12.104.178 56167 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 08:00:24.627025" r2d2 68.12.104.178 58231 68.12.99.2 53 UDP DNS (ns1.infopop).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:00:24.627026" r2d2 68.12.104.178 58231 68.12.99.2 53 UDP DNS (ns1.infopop).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:00:24.627518" r2d2 68.12.104.178 55638 68.12.99.2 53 UDP DNS (ns1.infopop).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:00:24.627523" r2d2 68.12.104.178 55638 68.12.99.2 53 UDP DNS (ns1.infopop).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:00:24.627734" r2d2 68.12.104.178 47225 68.12.99.2 53 UDP DNS (ns2.infopop).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:00:24.627733" r2d2 68.12.104.178 47225 68.12.99.2 53 UDP DNS (ns2.infopop).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:00:24.628037" r2d2 68.12.104.178 56086 68.12.99.2 53 UDP DNS (ns2.infopop).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:00:24.628034" r2d2 68.12.104.178 56086 68.12.99.2 53 UDP DNS (ns2.infopop).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:00:32.486906" r2d2 68.12.104.178 59398 68.12.99.2 53 UDP DNS (vdns1.yelle).solutions "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:00:32.486904" r2d2 68.12.104.178 59398 68.12.99.2 53 UDP DNS (vdns1.yelle).solutions "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:00:32.486908" r2d2 68.12.104.178 43871 68.12.99.2 53 UDP DNS (vdns2.yelle).solutions "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:00:32.486907" r2d2 68.12.104.178 43871 68.12.99.2 53 UDP DNS (vdns2.yelle).solutions "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:00:34.125006" r2d2 121.8.241.180 6000 68.12.104.178 1433 TCP IP 121.8.241.180 abuser openbl.org\n' +
    '"2015-03-10 08:00:34.125018" r2d2 121.8.241.180 6000 68.12.104.178 1433 TCP IP 121.8.241.180 abuser openbl.org\n' +
    '"2015-03-10 08:00:34.380408" r2d2 68.12.104.178 49741 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 08:00:34.380406" r2d2 68.12.104.178 49741 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 08:00:39.796007" r2d2 68.12.104.178 38878 68.12.99.2 53 UDP DNS (webdragon).ddns.net "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 08:00:39.796008" r2d2 68.12.104.178 38878 68.12.99.2 53 UDP DNS (webdragon).ddns.net "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 08:00:40.237116" r2d2 68.12.104.178 42828 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 08:00:40.237117" r2d2 68.12.104.178 42828 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 08:00:57.658829" r2d2 68.12.104.178 49648 68.12.99.2 53 UDP DNS (settings.smartbar).conduit-services.com phishing www.phishtank.com\n' +
    '"2015-03-10 08:00:57.658827" r2d2 68.12.104.178 49648 68.12.99.2 53 UDP DNS (settings.smartbar).conduit-services.com phishing www.phishtank.com\n' +
    '"2015-03-10 08:01:12.087104" r2d2 68.12.104.178 38347 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 08:01:12.087105" r2d2 68.12.104.178 38347 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 08:01:36.080756" r2d2 68.12.104.178 55533 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 08:01:36.080757" r2d2 68.12.104.178 55533 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 08:01:36.150447" r2d2 68.12.104.178 45647 68.12.99.2 53 UDP DNS (smtp.duco).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:01:36.150443" r2d2 68.12.104.178 45647 68.12.99.2 53 UDP DNS (smtp.duco).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:01:40.625570" r2d2 68.12.104.178 42581 68.12.99.2 53 UDP DNS counter.yadro.ru "zeroaccess (malware)" (static)\n' +
    '"2015-03-10 08:01:40.625568" r2d2 68.12.104.178 42581 68.12.99.2 53 UDP DNS counter.yadro.ru "zeroaccess (malware)" (static)\n' +
    '"2015-03-10 08:01:43.884778" r2d2 68.12.104.178 41068 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 08:01:43.884788" r2d2 68.12.104.178 41068 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 08:01:55.099509" r2d2 68.12.104.178 39762 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 08:01:55.099507" r2d2 68.12.104.178 39762 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 08:02:06.844341" r2d2 68.12.104.178 36678 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 08:02:06.844343" r2d2 68.12.104.178 36678 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 08:02:10.223190" r2d2 68.12.104.178 49094 68.12.99.2 53 UDP DNS peer.pickeklosarske.ru "palevo (malware)" (static)\n' +
    '"2015-03-10 08:02:10.223192" r2d2 68.12.104.178 49094 68.12.99.2 53 UDP DNS peer.pickeklosarske.ru "palevo (malware)" (static)\n' +
    '"2015-03-10 08:02:10.530210" r2d2 68.12.104.178 37421 68.12.99.2 53 UDP DNS (weinberger).servehttp.com "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 08:02:10.530213" r2d2 68.12.104.178 37421 68.12.99.2 53 UDP DNS (weinberger).servehttp.com "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 08:02:33.080010" r2d2 68.12.104.178 48793 68.12.99.2 53 UDP DNS (onlineplay).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:02:33.080012" r2d2 68.12.104.178 48793 68.12.99.2 53 UDP DNS (onlineplay).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:02:45.493722" r2d2 68.12.104.178 43613 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 08:02:45.493719" r2d2 68.12.104.178 43613 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 08:02:46.803709" r2d2 68.12.104.178 41950 198.58.92.228 53 UDP IP 198.58.92.228 malware cybercrime-tracker.net\n' +
    '"2015-03-10 08:02:46.803712" r2d2 68.12.104.178 41950 198.58.92.228 53 UDP IP 198.58.92.228 malware cybercrime-tracker.net\n' +
    '"2015-03-10 08:03:00.439227" r2d2 68.12.104.178 45414 68.12.99.2 53 UDP DNS (atc).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:03:00.439230" r2d2 68.12.104.178 45414 68.12.99.2 53 UDP DNS (atc).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:03:08.552854" r2d2 68.12.104.178 52158 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 08:03:08.552855" r2d2 68.12.104.178 52158 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 08:03:10.220233" r2d2 68.12.104.178 52510 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 08:03:10.220235" r2d2 68.12.104.178 52510 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 08:03:16.339088" r2d2 68.12.104.178 38504 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 08:03:16.339090" r2d2 68.12.104.178 38504 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 08:03:23.322993" r2d2 68.12.104.178 56761 113.108.80.138 53 UDP IP 113.108.80.138 dnspod (custom)\n' +
    '"2015-03-10 08:03:23.323006" r2d2 68.12.104.178 56761 113.108.80.138 53 UDP IP 113.108.80.138 dnspod (custom)\n' +
    '"2015-03-10 08:03:25.373024" r2d2 68.12.104.178 48558 68.12.99.2 53 UDP DNS (ns2.tut).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:03:25.372583" r2d2 68.12.104.178 43278 68.12.99.2 53 UDP DNS (ns1.tut).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:03:25.372580" r2d2 68.12.104.178 43278 68.12.99.2 53 UDP DNS (ns1.tut).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:03:25.373021" r2d2 68.12.104.178 48558 68.12.99.2 53 UDP DNS (ns2.tut).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:03:25.373364" r2d2 68.12.104.178 49207 68.12.99.2 53 UDP DNS (ns3.tut).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:03:25.373366" r2d2 68.12.104.178 49207 68.12.99.2 53 UDP DNS (ns3.tut).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:03:25.476785" r2d2 68.12.104.178 48355 113.108.80.138 53 UDP IP 113.108.80.138 dnspod (custom)\n' +
    '"2015-03-10 08:03:25.477993" r2d2 68.12.104.178 48355 113.108.80.138 53 UDP IP 113.108.80.138 dnspod (custom)\n' +
    '"2015-03-10 08:03:29.118602" r2d2 68.12.104.178 58292 68.12.99.2 53 UDP DNS (mail0.myhsphere).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:03:29.118599" r2d2 68.12.104.178 58292 68.12.99.2 53 UDP DNS (mail0.myhsphere).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:03:29.119032" r2d2 68.12.104.178 54232 68.12.99.2 53 UDP DNS (ns1.myhsphere).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:03:29.119033" r2d2 68.12.104.178 54232 68.12.99.2 53 UDP DNS (ns1.myhsphere).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:03:29.119396" r2d2 68.12.104.178 47301 68.12.99.2 53 UDP DNS (ns2.myhsphere).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:03:29.119394" r2d2 68.12.104.178 47301 68.12.99.2 53 UDP DNS (ns2.myhsphere).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:03:39.371891" r2d2 68.12.104.178 37807 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 08:03:39.371890" r2d2 68.12.104.178 37807 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 08:03:48.685397" r2d2 68.12.104.178 40991 68.12.99.2 53 UDP DNS digitalmind.cn "palevo (malware)" palevotracker.abuse.ch\n' +
    '"2015-03-10 08:03:48.685394" r2d2 68.12.104.178 40991 68.12.99.2 53 UDP DNS digitalmind.cn "palevo (malware)" palevotracker.abuse.ch\n' +
    '"2015-03-10 08:04:09.899364" r2d2 68.12.104.178 49019 68.12.99.2 53 UDP DNS promisex.ru "zeus (malware)" (custom)\n' +
    '"2015-03-10 08:04:09.899344" r2d2 68.12.104.178 49019 68.12.99.2 53 UDP DNS promisex.ru "zeus (malware)" (custom)\n' +
    '"2015-03-10 08:04:10.252577" r2d2 68.12.104.178 51336 68.12.99.2 53 UDP DNS jebena.ananikolic.su "palevo (malware)" (static)\n' +
    '"2015-03-10 08:04:10.252603" r2d2 68.12.104.178 51336 68.12.99.2 53 UDP DNS jebena.ananikolic.su "palevo (malware)" (static)\n' +
    '"2015-03-10 08:04:17.946821" r2d2 68.12.104.178 46433 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 08:04:17.946818" r2d2 68.12.104.178 46433 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 08:04:25.074694" r2d2 68.12.104.178 36539 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 08:04:25.074692" r2d2 68.12.104.178 36539 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 08:04:32.350305" r2d2 68.12.104.178 57847 68.12.99.2 53 UDP DNS cychefs.com malware cybercrime-tracker.net\n' +
    '"2015-03-10 08:04:32.350293" r2d2 68.12.104.178 57847 68.12.99.2 53 UDP DNS cychefs.com malware cybercrime-tracker.net\n' +
    '"2015-03-10 08:04:40.381875" r2d2 68.12.104.178 57062 68.12.99.2 53 UDP DNS peer.pickeklosarske.ru "palevo (malware)" (static)\n' +
    '"2015-03-10 08:04:40.381874" r2d2 68.12.104.178 57062 68.12.99.2 53 UDP DNS peer.pickeklosarske.ru "palevo (malware)" (static)\n' +
    '"2015-03-10 08:04:40.951441" r2d2 68.12.104.178 38797 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 08:04:40.951445" r2d2 68.12.104.178 38797 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 08:04:47.714804" r2d2 68.12.104.178 39475 68.12.99.2 53 UDP DNS (susiebanks).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:04:47.714805" r2d2 68.12.104.178 39475 68.12.99.2 53 UDP DNS (susiebanks).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:04:48.774860" r2d2 68.12.104.178 35610 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 08:04:48.774857" r2d2 68.12.104.178 35610 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 08:04:49.854965" r2d2 68.12.104.178 36969 113.108.80.138 53 UDP IP 113.108.80.138 dnspod (custom)\n' +
    '"2015-03-10 08:04:49.854967" r2d2 68.12.104.178 36969 113.108.80.138 53 UDP IP 113.108.80.138 dnspod (custom)\n' +
    '"2015-03-10 08:04:52.945884" r2d2 68.12.104.178 36940 68.12.99.2 53 UDP DNS (tracker.coppersurfer).tk "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:04:52.945885" r2d2 68.12.104.178 36940 68.12.99.2 53 UDP DNS (tracker.coppersurfer).tk "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:04:54.711201" r2d2 68.12.104.178 54425 68.12.99.2 53 UDP DNS (extratorrent).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:04:54.711205" r2d2 68.12.104.178 54425 68.12.99.2 53 UDP DNS (extratorrent).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:04:54.717598" r2d2 68.12.104.178 49402 68.12.99.2 53 UDP DNS (extratorrent).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:04:54.717596" r2d2 68.12.104.178 49402 68.12.99.2 53 UDP DNS (extratorrent).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:05:11.915076" r2d2 68.12.104.178 52693 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 08:05:11.915077" r2d2 68.12.104.178 52693 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 08:05:12.010408" r2d2 68.12.104.178 56938 113.108.80.138 53 UDP IP 113.108.80.138 dnspod (custom)\n' +
    '"2015-03-10 08:05:12.010412" r2d2 68.12.104.178 56938 113.108.80.138 53 UDP IP 113.108.80.138 dnspod (custom)\n' +
    '"2015-03-10 08:05:36.840260" r2d2 68.12.104.178 41264 68.12.99.2 53 UDP DNS (nmm).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:05:36.840258" r2d2 68.12.104.178 41264 68.12.99.2 53 UDP DNS (nmm).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:05:39.771971" r2d2 68.12.104.178 40905 68.12.99.2 53 UDP DNS (ns.eurocom).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:05:39.772183" r2d2 68.12.104.178 53979 68.12.99.2 53 UDP DNS (ns1.eurocom).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:05:39.771973" r2d2 68.12.104.178 40905 68.12.99.2 53 UDP DNS (ns.eurocom).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:05:39.772181" r2d2 68.12.104.178 53979 68.12.99.2 53 UDP DNS (ns1.eurocom).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:05:39.772893" r2d2 68.12.104.178 43800 68.12.99.2 53 UDP DNS (ns2.eurocom).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:05:39.772895" r2d2 68.12.104.178 43800 68.12.99.2 53 UDP DNS (ns2.eurocom).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:05:40.297921" r2d2 68.12.104.178 37738 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 08:05:40.297919" r2d2 68.12.104.178 37738 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 08:05:50.398206" r2d2 68.12.104.178 55794 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 08:05:50.398400" r2d2 68.12.104.178 55794 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 08:05:58.727717" r2d2 68.12.104.178 38161 68.12.99.2 53 UDP DNS (sfa).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:05:58.727719" r2d2 68.12.104.178 38161 68.12.99.2 53 UDP DNS (sfa).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:06:07.404120" r2d2 68.12.104.178 37009 113.108.80.138 53 UDP IP 113.108.80.138 dnspod (custom)\n' +
    '"2015-03-10 08:06:07.404119" r2d2 68.12.104.178 37009 113.108.80.138 53 UDP IP 113.108.80.138 dnspod (custom)\n' +
    '"2015-03-10 08:06:09.487666" r2d2 68.12.104.178 41952 68.12.99.2 53 UDP DNS (ns1).securitytactics.com "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 08:06:09.488018" r2d2 68.12.104.178 39179 68.12.99.2 53 UDP DNS (ns2).securitytactics.com "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 08:06:09.487667" r2d2 68.12.104.178 41952 68.12.99.2 53 UDP DNS (ns1).securitytactics.com "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 08:06:09.488020" r2d2 68.12.104.178 39179 68.12.99.2 53 UDP DNS (ns2).securitytactics.com "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 08:06:13.521832" r2d2 68.12.104.178 53528 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 08:06:13.521834" r2d2 68.12.104.178 53528 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 08:06:21.368012" r2d2 68.12.104.178 42246 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 08:06:21.368015" r2d2 68.12.104.178 42246 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 08:06:38.676865" r2d2 68.12.104.178 39332 68.12.99.2 53 UDP DNS (ns1.via).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:06:38.676863" r2d2 68.12.104.178 39332 68.12.99.2 53 UDP DNS (ns1.via).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:06:38.763164" r2d2 68.12.104.178 42762 68.12.99.2 53 UDP DNS (ns2.via).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:06:38.763165" r2d2 68.12.104.178 42762 68.12.99.2 53 UDP DNS (ns2.via).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:06:41.969629" r2d2 68.12.104.178 41076 68.12.99.2 53 UDP DNS (ns1.konov).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:06:41.969635" r2d2 68.12.104.178 41076 68.12.99.2 53 UDP DNS (ns1.konov).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:06:44.349078" r2d2 68.12.104.178 49163 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 08:06:44.349081" r2d2 68.12.104.178 49163 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 08:06:52.416851" r2d2 68.12.104.178 46523 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 08:06:52.416874" r2d2 68.12.104.178 46523 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 08:06:56.464234" r2d2 68.12.104.178 36681 68.12.99.2 53 UDP DNS (megascor).no-ip.biz "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 08:06:56.464230" r2d2 68.12.104.178 36681 68.12.99.2 53 UDP DNS (megascor).no-ip.biz "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 08:06:58.617756" r2d2 68.12.104.178 43501 68.12.99.2 53 UDP DNS (ffupdate.engine).conduit-services.com phishing www.phishtank.com\n' +
    '"2015-03-10 08:06:58.617753" r2d2 68.12.104.178 43501 68.12.99.2 53 UDP DNS (ffupdate.engine).conduit-services.com phishing www.phishtank.com\n' +
    '"2015-03-10 08:06:58.628750" r2d2 68.12.104.178 51365 68.12.99.2 53 UDP DNS (ffupdate).conduit-services.com phishing www.phishtank.com\n' +
    '"2015-03-10 08:06:58.628748" r2d2 68.12.104.178 51365 68.12.99.2 53 UDP DNS (ffupdate).conduit-services.com phishing www.phishtank.com\n' +
    '"2015-03-10 08:06:58.694369" r2d2 68.12.104.178 40575 68.12.99.2 53 UDP DNS (eu-dc-ffupdate).conduit-services.com phishing www.phishtank.com\n' +
    '"2015-03-10 08:06:58.694360" r2d2 68.12.104.178 40575 68.12.99.2 53 UDP DNS (eu-dc-ffupdate).conduit-services.com phishing www.phishtank.com\n' +
    '"2015-03-10 08:06:58.726384" r2d2 68.12.104.178 41488 68.12.99.2 53 UDP DNS (ffupdate.ams).conduit-services.com phishing www.phishtank.com\n' +
    '"2015-03-10 08:06:58.726381" r2d2 68.12.104.178 41488 68.12.99.2 53 UDP DNS (ffupdate.ams).conduit-services.com phishing www.phishtank.com\n' +
    '"2015-03-10 08:06:58.780940" r2d2 68.12.104.178 49054 68.12.99.2 53 UDP DNS (gothope).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:06:58.780941" r2d2 68.12.104.178 49054 68.12.99.2 53 UDP DNS (gothope).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:07:07.658210" r2d2 68.12.104.178 48923 68.12.99.2 53 UDP DNS (tracker.coppersurfer).tk "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:07:07.658206" r2d2 68.12.104.178 48923 68.12.99.2 53 UDP DNS (tracker.coppersurfer).tk "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:07:10.477963" r2d2 68.12.104.178 39925 68.12.99.2 53 UDP DNS peer.pickeklosarske.ru "palevo (malware)" (static)\n' +
    '"2015-03-10 08:07:10.477972" r2d2 68.12.104.178 39925 68.12.99.2 53 UDP DNS peer.pickeklosarske.ru "palevo (malware)" (static)\n' +
    '"2015-03-10 08:07:19.777675" r2d2 68.12.104.178 44836 198.58.92.228 53 UDP IP 198.58.92.228 malware cybercrime-tracker.net\n' +
    '"2015-03-10 08:07:19.777679" r2d2 68.12.104.178 44836 198.58.92.228 53 UDP IP 198.58.92.228 malware cybercrime-tracker.net\n' +
    '"2015-03-10 08:07:20.074956" r2d2 68.12.104.178 38850 198.58.92.228 53 UDP IP 198.58.92.228 malware cybercrime-tracker.net\n' +
    '"2015-03-10 08:07:20.074930" r2d2 68.12.104.178 38850 198.58.92.228 53 UDP IP 198.58.92.228 malware cybercrime-tracker.net\n' +
    '"2015-03-10 08:07:22.976922" r2d2 68.12.104.178 51185 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 08:07:22.976927" r2d2 68.12.104.178 51185 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 08:07:31.726663" r2d2 68.12.104.178 55417 68.12.99.2 53 UDP DNS jandasurveying.co.uk malware cybercrime-tracker.net\n' +
    '"2015-03-10 08:07:31.726674" r2d2 68.12.104.178 55417 68.12.99.2 53 UDP DNS jandasurveying.co.uk malware cybercrime-tracker.net\n' +
    '"2015-03-10 08:07:36.915244" r2d2 68.12.104.178 53338 108.175.157.56 53 UDP IP 108.175.157.56 c&c emergingthreats.net\n' +
    '"2015-03-10 08:07:36.915253" r2d2 68.12.104.178 53338 108.175.157.56 53 UDP IP 108.175.157.56 c&c emergingthreats.net\n' +
    '"2015-03-10 08:07:38.189316" r2d2 68.12.104.178 58280 68.12.99.2 53 UDP DNS (orange-getesa).gq "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:07:38.189313" r2d2 68.12.104.178 58280 68.12.99.2 53 UDP DNS (orange-getesa).gq "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:07:40.506008" r2d2 68.12.104.178 57605 68.12.99.2 53 UDP DNS teske.pornicarke.com "palevo (malware)" (static)\n' +
    '"2015-03-10 08:07:40.506009" r2d2 68.12.104.178 57605 68.12.99.2 53 UDP DNS teske.pornicarke.com "palevo (malware)" (static)\n' +
    '"2015-03-10 08:07:45.941882" r2d2 68.12.104.178 44242 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 08:07:45.941867" r2d2 68.12.104.178 44242 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 08:07:49.547626" r2d2 68.12.104.178 56748 68.12.99.2 53 UDP DNS (stroganova).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:07:49.547624" r2d2 68.12.104.178 56748 68.12.99.2 53 UDP DNS (stroganova).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:07:53.805895" r2d2 68.12.104.178 50969 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 08:07:53.805896" r2d2 68.12.104.178 50969 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 08:08:09.557025" r2d2 68.12.104.178 48811 68.12.99.2 53 UDP DNS (brightlounge).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:08:09.557028" r2d2 68.12.104.178 48811 68.12.99.2 53 UDP DNS (brightlounge).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:08:10.467784" r2d2 68.12.104.178 35541 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 08:08:10.467782" r2d2 68.12.104.178 35541 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 08:08:14.244925" r2d2 68.12.104.178 59434 113.108.80.138 53 UDP IP 113.108.80.138 dnspod (custom)\n' +
    '"2015-03-10 08:08:14.244927" r2d2 68.12.104.178 59434 113.108.80.138 53 UDP IP 113.108.80.138 dnspod (custom)\n' +
    '"2015-03-10 08:08:16.014979" r2d2 68.12.104.178 57355 8.8.8.8 53 UDP DNS (brightlounge).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:08:16.014980" r2d2 68.12.104.178 57355 8.8.8.8 53 UDP DNS (brightlounge).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:08:16.735321" r2d2 68.12.104.178 40581 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 08:08:16.735322" r2d2 68.12.104.178 40581 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 08:08:17.715906" r2d2 68.12.104.178 46962 68.12.99.2 53 UDP DNS (btmqprx-friends).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:08:17.715908" r2d2 68.12.104.178 46962 68.12.99.2 53 UDP DNS (btmqprx-friends).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:08:18.349673" r2d2 68.12.104.178 47070 68.12.99.2 53 UDP DNS (megascor).no-ip.biz "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 08:08:18.349675" r2d2 68.12.104.178 47070 68.12.99.2 53 UDP DNS (megascor).no-ip.biz "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 08:08:27.830053" r2d2 68.12.104.178 51988 68.12.99.2 53 UDP DNS (servicemap).conduit-services.com phishing www.phishtank.com\n' +
    '"2015-03-10 08:08:27.830055" r2d2 68.12.104.178 51988 68.12.99.2 53 UDP DNS (servicemap).conduit-services.com phishing www.phishtank.com\n' +
    '"2015-03-10 08:08:28.048174" r2d2 68.12.104.178 37114 68.12.99.2 53 UDP DNS (translation.toolbar).conduit-services.com phishing www.phishtank.com\n' +
    '"2015-03-10 08:08:28.048173" r2d2 68.12.104.178 37114 68.12.99.2 53 UDP DNS (translation.toolbar).conduit-services.com phishing www.phishtank.com\n' +
    '"2015-03-10 08:08:28.093962" r2d2 68.12.104.178 38583 68.12.99.2 53 UDP DNS (ip2location).conduit-services.com phishing www.phishtank.com\n' +
    '"2015-03-10 08:08:28.093952" r2d2 68.12.104.178 38583 68.12.99.2 53 UDP DNS (ip2location).conduit-services.com phishing www.phishtank.com\n' +
    '"2015-03-10 08:08:28.172826" r2d2 68.12.104.178 45691 68.12.99.2 53 UDP DNS (eu-dc-ip2location).conduit-services.com phishing www.phishtank.com\n' +
    '"2015-03-10 08:08:28.172823" r2d2 68.12.104.178 45691 68.12.99.2 53 UDP DNS (eu-dc-ip2location).conduit-services.com phishing www.phishtank.com\n' +
    '"2015-03-10 08:08:28.204055" r2d2 68.12.104.178 40515 68.12.99.2 53 UDP DNS (ip2location.ams).conduit-services.com phishing www.phishtank.com\n' +
    '"2015-03-10 08:08:28.204057" r2d2 68.12.104.178 40515 68.12.99.2 53 UDP DNS (ip2location.ams).conduit-services.com phishing www.phishtank.com\n' +
    '"2015-03-10 08:08:55.429765" r2d2 68.12.104.178 59986 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 08:08:55.429758" r2d2 68.12.104.178 59986 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 08:09:14.790202" r2d2 68.12.104.178 44503 68.12.99.2 53 UDP DNS (tracker.coppersurfer).tk "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:09:14.790221" r2d2 68.12.104.178 44503 68.12.99.2 53 UDP DNS (tracker.coppersurfer).tk "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:09:18.345738" r2d2 68.12.104.178 47970 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 08:09:18.345746" r2d2 68.12.104.178 47970 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 08:09:19.453780" r2d2 68.12.104.178 46773 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 08:09:19.453783" r2d2 68.12.104.178 46773 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 08:09:25.056413" r2d2 68.12.104.178 35108 68.12.99.2 53 UDP DNS (www).superfish.com superfish (static)\n' +
    '"2015-03-10 08:09:25.056410" r2d2 68.12.104.178 35108 68.12.99.2 53 UDP DNS (www).superfish.com superfish (static)\n' +
    '"2015-03-10 08:09:25.077746" r2d2 68.12.104.178 46982 68.12.99.2 53 UDP DNS superfish.com superfish (static)\n' +
    '"2015-03-10 08:09:25.077744" r2d2 68.12.104.178 46982 68.12.99.2 53 UDP DNS superfish.com superfish (static)\n' +
    '"2015-03-10 08:09:26.523860" r2d2 68.12.104.178 40938 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 08:09:26.523858" r2d2 68.12.104.178 40938 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 08:09:39.331504" r2d2 68.12.104.178 39822 68.12.99.2 53 UDP DNS (nes).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:09:39.331502" r2d2 68.12.104.178 39822 68.12.99.2 53 UDP DNS (nes).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:09:40.420562" r2d2 68.12.104.178 43050 68.12.99.2 53 UDP DNS peer.pickeklosarske.ru "palevo (malware)" (static)\n' +
    '"2015-03-10 08:09:40.420560" r2d2 68.12.104.178 43050 68.12.99.2 53 UDP DNS peer.pickeklosarske.ru "palevo (malware)" (static)\n' +
    '"2015-03-10 08:09:45.612204" r2d2 68.12.104.178 39906 68.12.99.2 53 UDP DNS (megascor).no-ip.biz "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 08:09:45.612197" r2d2 68.12.104.178 39906 68.12.99.2 53 UDP DNS (megascor).no-ip.biz "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 08:09:49.095235" r2d2 68.12.104.178 41601 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 08:09:49.095250" r2d2 68.12.104.178 41601 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 08:09:49.103729" r2d2 68.12.104.178 37023 68.12.99.2 53 UDP DNS (fantasti).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:09:49.103752" r2d2 68.12.104.178 37023 68.12.99.2 53 UDP DNS (fantasti).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:09:58.982301" r2d2 68.12.104.178 37576 68.12.99.2 53 UDP DNS digitalmind.cn "palevo (malware)" palevotracker.abuse.ch\n' +
    '"2015-03-10 08:09:58.982303" r2d2 68.12.104.178 37576 68.12.99.2 53 UDP DNS digitalmind.cn "palevo (malware)" palevotracker.abuse.ch\n' +
    '"2015-03-10 08:10:02.427465" r2d2 68.12.104.178 38939 68.12.99.2 53 UDP DNS cdnvideo.ru "pushdo (malware)" (static)\n' +
    '"2015-03-10 08:10:02.427474" r2d2 68.12.104.178 38939 68.12.99.2 53 UDP DNS cdnvideo.ru "pushdo (malware)" (static)\n' +
    '"2015-03-10 08:10:02.936561" r2d2 68.12.104.178 55870 68.12.99.2 53 UDP DNS www.findamo.com malware malwarepatrol.net\n' +
    '"2015-03-10 08:10:02.936564" r2d2 68.12.104.178 55870 68.12.99.2 53 UDP DNS www.findamo.com malware malwarepatrol.net\n' +
    '"2015-03-10 08:10:05.854314" r2d2 68.12.104.178 40441 68.12.99.2 53 UDP DNS (tracker.coppersurfer).tk "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:10:05.854315" r2d2 68.12.104.178 40441 68.12.99.2 53 UDP DNS (tracker.coppersurfer).tk "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:10:06.093699" r2d2 68.12.104.178 47854 68.12.99.2 53 UDP DNS (mail.tusmobil).club "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:10:06.093941" r2d2 68.12.104.178 39005 68.12.99.2 53 UDP DNS (ns1.tusmobil).club "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:10:06.094421" r2d2 68.12.104.178 43673 68.12.99.2 53 UDP DNS (ns2.tusmobil).club "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:10:06.093697" r2d2 68.12.104.178 47854 68.12.99.2 53 UDP DNS (mail.tusmobil).club "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:10:06.094419" r2d2 68.12.104.178 43673 68.12.99.2 53 UDP DNS (ns2.tusmobil).club "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:10:06.093943" r2d2 68.12.104.178 39005 68.12.99.2 53 UDP DNS (ns1.tusmobil).club "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:10:19.338373" r2d2 68.12.104.178 52655 68.12.99.2 53 UDP DNS (x64).no-ip.org "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 08:10:19.338365" r2d2 68.12.104.178 52655 68.12.99.2 53 UDP DNS (x64).no-ip.org "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 08:10:25.464338" r2d2 68.12.104.178 50695 68.12.99.2 53 UDP DNS (andyworth).no-ip.org "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 08:10:25.464337" r2d2 68.12.104.178 50695 68.12.99.2 53 UDP DNS (andyworth).no-ip.org "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 08:10:28.132836" r2d2 68.12.104.178 45059 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 08:10:28.132837" r2d2 68.12.104.178 45059 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 08:10:36.348961" r2d2 68.12.104.178 44136 198.58.92.228 53 UDP IP 198.58.92.228 malware cybercrime-tracker.net\n' +
    '"2015-03-10 08:10:36.348960" r2d2 68.12.104.178 44136 198.58.92.228 53 UDP IP 198.58.92.228 malware cybercrime-tracker.net\n' +
    '"2015-03-10 08:10:36.666640" r2d2 68.12.104.178 59287 198.58.92.228 53 UDP IP 198.58.92.228 malware cybercrime-tracker.net\n' +
    '"2015-03-10 08:10:36.666642" r2d2 68.12.104.178 59287 198.58.92.228 53 UDP IP 198.58.92.228 malware cybercrime-tracker.net\n' +
    '"2015-03-10 08:10:36.796627" r2d2 68.12.104.178 42357 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 08:10:36.796628" r2d2 68.12.104.178 42357 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 08:10:37.603956" r2d2 68.12.104.178 49953 198.58.92.228 53 UDP IP 198.58.92.228 malware cybercrime-tracker.net\n' +
    '"2015-03-10 08:10:37.603955" r2d2 68.12.104.178 49953 198.58.92.228 53 UDP IP 198.58.92.228 malware cybercrime-tracker.net\n' +
    '"2015-03-10 08:10:48.997725" r2d2 68.12.104.178 46626 68.12.99.2 53 UDP DNS (mybr).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:10:48.997723" r2d2 68.12.104.178 46626 68.12.99.2 53 UDP DNS (mybr).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:10:50.669909" r2d2 68.12.104.178 43641 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 08:10:50.669910" r2d2 68.12.104.178 43641 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 08:10:51.896924" r2d2 68.12.104.178 46917 68.12.99.2 53 UDP DNS (megascor).no-ip.biz "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 08:10:51.896923" r2d2 68.12.104.178 46917 68.12.99.2 53 UDP DNS (megascor).no-ip.biz "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 08:10:58.960974" r2d2 68.12.104.178 44619 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 08:10:58.960976" r2d2 68.12.104.178 44619 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 08:11:00.451519" r2d2 68.12.104.178 48188 113.108.80.138 53 UDP IP 113.108.80.138 dnspod (custom)\n' +
    '"2015-03-10 08:11:00.451515" r2d2 68.12.104.178 48188 113.108.80.138 53 UDP IP 113.108.80.138 dnspod (custom)\n' +
    '"2015-03-10 08:11:02.364801" r2d2 68.12.104.178 52147 68.12.99.2 53 UDP DNS (rosinkas.lipetsk).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:11:02.364800" r2d2 68.12.104.178 52147 68.12.99.2 53 UDP DNS (rosinkas.lipetsk).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:11:05.829949" r2d2 68.12.104.178 58205 68.12.99.2 53 UDP DNS promisex.ru "zeus (malware)" (custom)\n' +
    '"2015-03-10 08:11:05.829950" r2d2 68.12.104.178 58205 68.12.99.2 53 UDP DNS promisex.ru "zeus (malware)" (custom)\n' +
    '"2015-03-10 08:11:06.745368" r2d2 68.12.104.178 50203 68.12.99.2 53 UDP DNS (mx.cloudafrica).email "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:11:06.745365" r2d2 68.12.104.178 50203 68.12.99.2 53 UDP DNS (mx.cloudafrica).email "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:11:06.774340" r2d2 68.12.104.178 39969 68.12.99.2 53 UDP DNS (mx01.cloudafrica).email "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:11:06.774312" r2d2 68.12.104.178 39969 68.12.99.2 53 UDP DNS (mx01.cloudafrica).email "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:11:12.017510" r2d2 68.12.104.178 57355 8.8.8.8 53 UDP DNS promisex.ru "zeus (malware)" (custom)\n' +
    '"2015-03-10 08:11:12.017509" r2d2 68.12.104.178 57355 8.8.8.8 53 UDP DNS promisex.ru "zeus (malware)" (custom)\n' +
    '"2015-03-10 08:11:16.460403" r2d2 68.12.104.178 41860 113.108.80.138 53 UDP IP 113.108.80.138 dnspod (custom)\n' +
    '"2015-03-10 08:11:16.460404" r2d2 68.12.104.178 41860 113.108.80.138 53 UDP IP 113.108.80.138 dnspod (custom)\n' +
    '"2015-03-10 08:11:21.479067" r2d2 68.12.104.178 56380 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 08:11:21.479059" r2d2 68.12.104.178 56380 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 08:11:42.558343" r2d2 68.12.104.178 44928 198.58.92.228 53 UDP IP 198.58.92.228 malware cybercrime-tracker.net\n' +
    '"2015-03-10 08:11:42.558355" r2d2 68.12.104.178 44928 198.58.92.228 53 UDP IP 198.58.92.228 malware cybercrime-tracker.net\n' +
    '"2015-03-10 08:11:48.264860" r2d2 68.12.104.178 57153 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 08:11:48.264859" r2d2 68.12.104.178 57153 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 08:12:00.710714" r2d2 68.12.104.178 43247 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 08:12:00.710716" r2d2 68.12.104.178 43247 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 08:12:01.050559" r2d2 68.12.104.178 40578 68.12.99.2 53 UDP DNS (errors).ourdatagenserv.com malware malwareurls.joxeankoret.com\n' +
    '"2015-03-10 08:12:01.050556" r2d2 68.12.104.178 40578 68.12.99.2 53 UDP DNS (errors).ourdatagenserv.com malware malwareurls.joxeankoret.com\n' +
    '"2015-03-10 08:12:05.170640" r2d2 68.12.104.178 47863 68.12.99.2 53 UDP DNS peer.pickeklosarske.ru "palevo (malware)" (static)\n' +
    '"2015-03-10 08:12:05.170641" r2d2 68.12.104.178 47863 68.12.99.2 53 UDP DNS peer.pickeklosarske.ru "palevo (malware)" (static)\n' +
    '"2015-03-10 08:12:08.862102" r2d2 68.12.104.178 48969 68.12.99.2 53 UDP DNS (megascor).no-ip.biz "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 08:12:08.862119" r2d2 68.12.104.178 48969 68.12.99.2 53 UDP DNS (megascor).no-ip.biz "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 08:12:23.070716" r2d2 68.12.104.178 55180 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 08:12:23.070706" r2d2 68.12.104.178 55180 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 08:12:31.038538" r2d2 68.12.104.178 49689 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 08:12:31.038540" r2d2 68.12.104.178 49689 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 08:12:31.104272" r2d2 68.12.104.178 42377 122.155.16.127 53 UDP IP 122.155.16.127 "brute forcer" danger.rulez.sk\n' +
    '"2015-03-10 08:12:31.104264" r2d2 68.12.104.178 42377 122.155.16.127 53 UDP IP 122.155.16.127 "brute forcer" danger.rulez.sk\n' +
    '"2015-03-10 08:12:33.714801" r2d2 68.12.104.178 37524 68.12.99.2 53 UDP DNS (dwn).pushtraffic.net malicious www.virustotal.com\n' +
    '"2015-03-10 08:12:33.714817" r2d2 68.12.104.178 37524 68.12.99.2 53 UDP DNS (dwn).pushtraffic.net malicious www.virustotal.com\n' +
    '"2015-03-10 08:12:39.385399" r2d2 68.12.104.178 38358 68.12.99.2 53 UDP DNS (n01).us.to "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:12:39.385400" r2d2 68.12.104.178 38358 68.12.99.2 53 UDP DNS (n01).us.to "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:12:45.582334" r2d2 68.12.104.178 53825 68.12.99.2 53 UDP DNS (ns3.olven).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:12:45.582968" r2d2 68.12.104.178 48862 68.12.99.2 53 UDP DNS (ns5.olven).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:12:45.583487" r2d2 68.12.104.178 49611 68.12.99.2 53 UDP DNS (ns5.olven).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:12:45.582313" r2d2 68.12.104.178 53825 68.12.99.2 53 UDP DNS (ns3.olven).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:12:45.582966" r2d2 68.12.104.178 48862 68.12.99.2 53 UDP DNS (ns5.olven).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:12:45.583483" r2d2 68.12.104.178 49611 68.12.99.2 53 UDP DNS (ns5.olven).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:12:53.882342" r2d2 68.12.104.178 56622 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 08:12:53.882339" r2d2 68.12.104.178 56622 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 08:13:05.093505" r2d2 68.12.104.178 56837 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 08:13:05.093503" r2d2 68.12.104.178 56837 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 08:13:17.692224" r2d2 68.12.104.178 43832 95.211.17.71 53 UDP IP 95.211.17.71 attacker blocklist.de\n' +
    '"2015-03-10 08:13:17.692227" r2d2 68.12.104.178 43832 95.211.17.71 53 UDP IP 95.211.17.71 attacker blocklist.de\n' +
    '"2015-03-10 08:13:30.926846" r2d2 68.12.104.178 58060 68.12.99.2 53 UDP DNS (megascor).no-ip.biz "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 08:13:30.926848" r2d2 68.12.104.178 58060 68.12.99.2 53 UDP DNS (megascor).no-ip.biz "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 08:13:31.664346" r2d2 68.12.104.178 35270 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 08:13:31.664348" r2d2 68.12.104.178 35270 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 08:13:49.729800" r2d2 68.12.104.178 37822 68.12.99.2 53 UDP DNS crazyerror.su malicious www.virustotal.com\n' +
    '"2015-03-10 08:13:49.729798" r2d2 68.12.104.178 37822 68.12.99.2 53 UDP DNS crazyerror.su malicious www.virustotal.com\n' +
    '"2015-03-10 08:13:55.445250" r2d2 68.12.104.178 53195 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 08:13:55.445252" r2d2 68.12.104.178 53195 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 08:14:02.491955" r2d2 68.12.104.178 48372 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 08:14:02.491957" r2d2 68.12.104.178 48372 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 08:14:06.370018" r2d2 68.12.104.178 36321 68.12.99.2 53 UDP DNS (www).best-deals-products.com superfish (static)\n' +
    '"2015-03-10 08:14:06.370005" r2d2 68.12.104.178 36321 68.12.99.2 53 UDP DNS (www).best-deals-products.com superfish (static)\n' +
    '"2015-03-10 08:14:06.548779" r2d2 68.12.104.178 37457 68.12.99.2 53 UDP DNS best-deals-products.com superfish (static)\n' +
    '"2015-03-10 08:14:06.548777" r2d2 68.12.104.178 37457 68.12.99.2 53 UDP DNS best-deals-products.com superfish (static)\n' +
    '"2015-03-10 08:14:16.146325" r2d2 68.12.104.178 41322 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 08:14:16.146327" r2d2 68.12.104.178 41322 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 08:14:16.525155" r2d2 68.12.104.178 55172 68.12.99.2 53 UDP DNS (static.extratorrent).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:14:16.525142" r2d2 68.12.104.178 55172 68.12.99.2 53 UDP DNS (static.extratorrent).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:14:16.534303" r2d2 68.12.104.178 35036 68.12.99.2 53 UDP DNS (extratorrent).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:14:16.534302" r2d2 68.12.104.178 35036 68.12.99.2 53 UDP DNS (extratorrent).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:14:26.254512" r2d2 68.12.104.178 48301 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 08:14:26.254510" r2d2 68.12.104.178 48301 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 08:14:31.672739" r2d2 68.12.104.178 38038 68.12.99.2 53 UDP DNS (hsmuepiemno).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:14:31.672740" r2d2 68.12.104.178 38038 68.12.99.2 53 UDP DNS (hsmuepiemno).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:14:31.698689" r2d2 68.12.104.178 36780 68.12.99.2 53 UDP DNS (cfelgmuuv).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:14:31.698677" r2d2 68.12.104.178 36780 68.12.99.2 53 UDP DNS (cfelgmuuv).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:14:31.901664" r2d2 68.12.104.178 35724 68.12.99.2 53 UDP DNS (yoihkvyneah).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:14:31.901668" r2d2 68.12.104.178 35724 68.12.99.2 53 UDP DNS (yoihkvyneah).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:14:32.110342" r2d2 68.12.104.178 42267 68.12.99.2 53 UDP DNS (vrmqckwm).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:14:32.110340" r2d2 68.12.104.178 42267 68.12.99.2 53 UDP DNS (vrmqckwm).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:14:32.225744" r2d2 68.12.104.178 45971 68.12.99.2 53 UDP DNS (lhopkqwyauphpj).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:14:32.225741" r2d2 68.12.104.178 45971 68.12.99.2 53 UDP DNS (lhopkqwyauphpj).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:14:32.306179" r2d2 68.12.104.178 48346 68.12.99.2 53 UDP DNS (paytxjgplh).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:14:32.306175" r2d2 68.12.104.178 48346 68.12.99.2 53 UDP DNS (paytxjgplh).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:14:32.415760" r2d2 68.12.104.178 41328 68.12.99.2 53 UDP DNS (plgiamfqvigdwj).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:14:32.415758" r2d2 68.12.104.178 41328 68.12.99.2 53 UDP DNS (plgiamfqvigdwj).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:14:32.669954" r2d2 68.12.104.178 50122 68.12.99.2 53 UDP DNS (ppchsdmer).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:14:32.669957" r2d2 68.12.104.178 50122 68.12.99.2 53 UDP DNS (ppchsdmer).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:14:32.845222" r2d2 68.12.104.178 53500 68.12.99.2 53 UDP DNS (qsqjrfdirvfxbwamnk).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:14:32.845220" r2d2 68.12.104.178 53500 68.12.99.2 53 UDP DNS (qsqjrfdirvfxbwamnk).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:14:32.955597" r2d2 68.12.104.178 55119 68.12.99.2 53 UDP DNS (yteypts).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:14:32.955596" r2d2 68.12.104.178 55119 68.12.99.2 53 UDP DNS (yteypts).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:14:33.330902" r2d2 68.12.104.178 38680 68.12.99.2 53 UDP DNS (enksgvkdtclfs).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:14:33.330892" r2d2 68.12.104.178 38680 68.12.99.2 53 UDP DNS (enksgvkdtclfs).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:14:33.432008" r2d2 68.12.104.178 43324 68.12.99.2 53 UDP DNS (onlineplay).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:14:33.432004" r2d2 68.12.104.178 43324 68.12.99.2 53 UDP DNS (onlineplay).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:14:33.433969" r2d2 68.12.104.178 43153 68.12.99.2 53 UDP DNS (hsjvcymfvteka).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:14:33.433970" r2d2 68.12.104.178 43153 68.12.99.2 53 UDP DNS (hsjvcymfvteka).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:14:33.435442" r2d2 68.12.104.178 52117 68.12.99.2 53 UDP DNS promisex.ru "zeus (malware)" (custom)\n' +
    '"2015-03-10 08:14:33.435441" r2d2 68.12.104.178 52117 68.12.99.2 53 UDP DNS promisex.ru "zeus (malware)" (custom)\n' +
    '"2015-03-10 08:14:33.583958" r2d2 68.12.104.178 52602 68.12.99.2 53 UDP DNS (puehkctpajn).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:14:33.583959" r2d2 68.12.104.178 52602 68.12.99.2 53 UDP DNS (puehkctpajn).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:14:33.635623" r2d2 68.12.104.178 48875 68.12.99.2 53 UDP DNS (gdssshqutbjg).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:14:33.635622" r2d2 68.12.104.178 48875 68.12.99.2 53 UDP DNS (gdssshqutbjg).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:14:33.759834" r2d2 68.12.104.178 54229 68.12.99.2 53 UDP DNS (tyfjxeckqbo).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:14:33.759835" r2d2 68.12.104.178 54229 68.12.99.2 53 UDP DNS (tyfjxeckqbo).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:14:33.782974" r2d2 68.12.104.178 57814 68.12.99.2 53 UDP DNS (rxwsgwqhldnrrk).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:14:33.782977" r2d2 68.12.104.178 57814 68.12.99.2 53 UDP DNS (rxwsgwqhldnrrk).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:14:33.834318" r2d2 68.12.104.178 48412 68.12.99.2 53 UDP DNS (qlvplkwffgy).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:14:33.834325" r2d2 68.12.104.178 48412 68.12.99.2 53 UDP DNS (qlvplkwffgy).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:14:33.936686" r2d2 68.12.104.178 40013 68.12.99.2 53 UDP DNS (suflkdxomwrvgy).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:14:33.936684" r2d2 68.12.104.178 40013 68.12.99.2 53 UDP DNS (suflkdxomwrvgy).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:14:33.990098" r2d2 68.12.104.178 50673 68.12.99.2 53 UDP DNS (nwdfugphavjylddcf).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:14:33.990097" r2d2 68.12.104.178 50673 68.12.99.2 53 UDP DNS (nwdfugphavjylddcf).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:14:34.133881" r2d2 68.12.104.178 59418 68.12.99.2 53 UDP DNS (qakjsundwigw).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:14:34.133877" r2d2 68.12.104.178 59418 68.12.99.2 53 UDP DNS (qakjsundwigw).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:14:34.252137" r2d2 68.12.104.178 44655 68.12.99.2 53 UDP DNS (cvdfuekvigfrnxfnpk).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:14:34.252138" r2d2 68.12.104.178 44655 68.12.99.2 53 UDP DNS (cvdfuekvigfrnxfnpk).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:14:34.290083" r2d2 68.12.104.178 56477 68.12.99.2 53 UDP DNS (ovubsmdcbmffulxrhsd).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:14:34.290079" r2d2 68.12.104.178 56477 68.12.99.2 53 UDP DNS (ovubsmdcbmffulxrhsd).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:14:34.863971" r2d2 68.12.104.178 40521 68.12.99.2 53 UDP DNS (jaeceglpxrycfkf).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:14:34.863970" r2d2 68.12.104.178 40521 68.12.99.2 53 UDP DNS (jaeceglpxrycfkf).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:14:35.042851" r2d2 68.12.104.178 49094 68.12.99.2 53 UDP DNS (iuauujmukj).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:14:35.042857" r2d2 68.12.104.178 49094 68.12.99.2 53 UDP DNS (iuauujmukj).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:14:35.108945" r2d2 68.12.104.178 47851 68.12.99.2 53 UDP DNS peer.pickeklosarske.ru "palevo (malware)" (static)\n' +
    '"2015-03-10 08:14:35.108932" r2d2 68.12.104.178 47851 68.12.99.2 53 UDP DNS peer.pickeklosarske.ru "palevo (malware)" (static)\n' +
    '"2015-03-10 08:14:35.262956" r2d2 68.12.104.178 47753 68.12.99.2 53 UDP DNS (jtwbkkntkcucauixkhake).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:14:35.262969" r2d2 68.12.104.178 47753 68.12.99.2 53 UDP DNS (jtwbkkntkcucauixkhake).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:14:35.545676" r2d2 68.12.104.178 37728 68.12.99.2 53 UDP DNS (lyteepkgbhrw).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:14:35.545852" r2d2 68.12.104.178 37728 68.12.99.2 53 UDP DNS (lyteepkgbhrw).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:14:35.845490" r2d2 68.12.104.178 44203 68.12.99.2 53 UDP DNS (oixxmxgikh).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:14:35.845495" r2d2 68.12.104.178 44203 68.12.99.2 53 UDP DNS (oixxmxgikh).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:14:35.887096" r2d2 68.12.104.178 36093 68.12.99.2 53 UDP DNS (qxbekna).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:14:35.887099" r2d2 68.12.104.178 36093 68.12.99.2 53 UDP DNS (qxbekna).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:14:35.970656" r2d2 68.12.104.178 35548 68.12.99.2 53 UDP DNS (fnrrumhkhxpsvobyopvau).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:14:35.970668" r2d2 68.12.104.178 35548 68.12.99.2 53 UDP DNS (fnrrumhkhxpsvobyopvau).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:14:35.988564" r2d2 68.12.104.178 36368 68.12.99.2 53 UDP DNS (eetdebduftrfaurucngs).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:14:35.988563" r2d2 68.12.104.178 36368 68.12.99.2 53 UDP DNS (eetdebduftrfaurucngs).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:14:36.599127" r2d2 68.12.104.178 40036 68.12.99.2 53 UDP DNS (dbmsimpbtpewyacsolpqg).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:14:36.599115" r2d2 68.12.104.178 40036 68.12.99.2 53 UDP DNS (dbmsimpbtpewyacsolpqg).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:14:36.609050" r2d2 68.12.104.178 35922 68.12.99.2 53 UDP DNS (nmmjymkprlsxyruiksvq).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:14:36.609049" r2d2 68.12.104.178 35922 68.12.99.2 53 UDP DNS (nmmjymkprlsxyruiksvq).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:14:36.653186" r2d2 68.12.104.178 38740 68.12.99.2 53 UDP DNS (vqgehvbhimpcjhqdtp).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:14:36.653188" r2d2 68.12.104.178 38740 68.12.99.2 53 UDP DNS (vqgehvbhimpcjhqdtp).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:14:37.029197" r2d2 68.12.104.178 49188 68.12.99.2 53 UDP DNS (vurfkwodmraiiqtmqopi).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:14:37.029198" r2d2 68.12.104.178 49188 68.12.99.2 53 UDP DNS (vurfkwodmraiiqtmqopi).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:14:37.269534" r2d2 68.12.104.178 47332 68.12.99.2 53 UDP DNS (wevnxcxduixldv).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:14:37.269548" r2d2 68.12.104.178 47332 68.12.99.2 53 UDP DNS (wevnxcxduixldv).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:14:37.276331" r2d2 68.12.104.178 54232 68.12.99.2 53 UDP DNS (mrgcnciukgi).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:14:37.276330" r2d2 68.12.104.178 54232 68.12.99.2 53 UDP DNS (mrgcnciukgi).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:14:37.980363" r2d2 68.12.104.178 45118 68.12.99.2 53 UDP DNS (knqmvfcdvcqfqyimy).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:14:37.980365" r2d2 68.12.104.178 45118 68.12.99.2 53 UDP DNS (knqmvfcdvcqfqyimy).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:14:38.362118" r2d2 68.12.104.178 55835 68.12.99.2 53 UDP DNS (bvlkxnt).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:14:38.362119" r2d2 68.12.104.178 55835 68.12.99.2 53 UDP DNS (bvlkxnt).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:14:38.831073" r2d2 68.12.104.178 39889 68.12.99.2 53 UDP DNS (hfdxsmmkilvf).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:14:38.831077" r2d2 68.12.104.178 39889 68.12.99.2 53 UDP DNS (hfdxsmmkilvf).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:14:38.935483" r2d2 68.12.104.178 39357 68.12.99.2 53 UDP DNS (giwbrwlgllswtch).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:14:38.935481" r2d2 68.12.104.178 39357 68.12.99.2 53 UDP DNS (giwbrwlgllswtch).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:14:39.169827" r2d2 68.12.104.178 50988 68.12.99.2 53 UDP DNS (eyphigsiqgkmrumur).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:14:39.169806" r2d2 68.12.104.178 50988 68.12.99.2 53 UDP DNS (eyphigsiqgkmrumur).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:14:39.453005" r2d2 68.12.104.178 44269 68.12.99.2 53 UDP DNS counter.yadro.ru "zeroaccess (malware)" (static)\n' +
    '"2015-03-10 08:14:39.453008" r2d2 68.12.104.178 44269 68.12.99.2 53 UDP DNS counter.yadro.ru "zeroaccess (malware)" (static)\n' +
    '"2015-03-10 08:14:39.513559" r2d2 68.12.104.178 41236 68.12.99.2 53 UDP DNS (mbmpmbhpl).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:14:39.513547" r2d2 68.12.104.178 41236 68.12.99.2 53 UDP DNS (mbmpmbhpl).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:14:40.019884" r2d2 68.12.104.178 57355 8.8.8.8 53 UDP DNS promisex.ru "zeus (malware)" (custom)\n' +
    '"2015-03-10 08:14:40.019886" r2d2 68.12.104.178 57355 8.8.8.8 53 UDP DNS promisex.ru "zeus (malware)" (custom)\n' +
    '"2015-03-10 08:14:40.188852" r2d2 68.12.104.178 44837 68.12.99.2 53 UDP DNS (psnoeykodpeymvy).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:14:40.188855" r2d2 68.12.104.178 44837 68.12.99.2 53 UDP DNS (psnoeykodpeymvy).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:14:40.204802" r2d2 68.12.104.178 54709 68.12.99.2 53 UDP DNS (nbniwyiamfsbugkenyjpd).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:14:40.204797" r2d2 68.12.104.178 54709 68.12.99.2 53 UDP DNS (nbniwyiamfsbugkenyjpd).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:14:40.634234" r2d2 68.12.104.178 48396 68.12.99.2 53 UDP DNS (wtwslkytehswwvukfhgic).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:14:40.634235" r2d2 68.12.104.178 48396 68.12.99.2 53 UDP DNS (wtwslkytehswwvukfhgic).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:14:41.766011" r2d2 68.12.104.178 56695 68.12.99.2 53 UDP DNS (lspkhgcyvwbxxapcdd).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:14:41.766008" r2d2 68.12.104.178 56695 68.12.99.2 53 UDP DNS (lspkhgcyvwbxxapcdd).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:14:41.887575" r2d2 68.12.104.178 47958 68.12.99.2 53 UDP DNS (pthdngfsyixqtswlvli).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:14:41.887577" r2d2 68.12.104.178 47958 68.12.99.2 53 UDP DNS (pthdngfsyixqtswlvli).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:14:43.583322" r2d2 68.12.104.178 56085 68.12.99.2 53 UDP DNS (ytmcackikio).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:14:43.583319" r2d2 68.12.104.178 56085 68.12.99.2 53 UDP DNS (ytmcackikio).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:14:44.350465" r2d2 68.12.104.178 40353 68.12.99.2 53 UDP DNS (nbcdtimwr).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:14:44.350476" r2d2 68.12.104.178 40353 68.12.99.2 53 UDP DNS (nbcdtimwr).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:14:44.408179" r2d2 68.12.104.178 47458 68.12.99.2 53 UDP DNS (uyqeudxqybqcqseou).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:14:44.408177" r2d2 68.12.104.178 47458 68.12.99.2 53 UDP DNS (uyqeudxqybqcqseou).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:14:44.555948" r2d2 68.12.104.178 49827 68.12.99.2 53 UDP DNS (srbqfeabymofcuglqlx).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:14:44.555947" r2d2 68.12.104.178 49827 68.12.99.2 53 UDP DNS (srbqfeabymofcuglqlx).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:14:44.633084" r2d2 68.12.104.178 43650 68.12.99.2 53 UDP DNS (feooutflcxoc).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:14:44.633085" r2d2 68.12.104.178 43650 68.12.99.2 53 UDP DNS (feooutflcxoc).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:14:44.810429" r2d2 68.12.104.178 38238 68.12.99.2 53 UDP DNS (asbmwwwrl).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:14:44.810430" r2d2 68.12.104.178 38238 68.12.99.2 53 UDP DNS (asbmwwwrl).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:14:44.988195" r2d2 68.12.104.178 52325 68.12.99.2 53 UDP DNS (fkywshdffenjkcommdpcp).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:14:44.988193" r2d2 68.12.104.178 52325 68.12.99.2 53 UDP DNS (fkywshdffenjkcommdpcp).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:14:45.143698" r2d2 68.12.104.178 45399 68.12.99.2 53 UDP DNS (bpulloppkoswireo).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:14:45.143699" r2d2 68.12.104.178 45399 68.12.99.2 53 UDP DNS (bpulloppkoswireo).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:14:45.463618" r2d2 68.12.104.178 44244 68.12.99.2 53 UDP DNS (iveuoqxdohyrmhcof).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:14:45.463617" r2d2 68.12.104.178 44244 68.12.99.2 53 UDP DNS (iveuoqxdohyrmhcof).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:14:46.517993" r2d2 68.12.104.178 38977 68.12.99.2 53 UDP DNS (googlerunapi).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:14:46.517989" r2d2 68.12.104.178 38977 68.12.99.2 53 UDP DNS (googlerunapi).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:14:46.606900" r2d2 68.12.104.178 48011 68.12.99.2 53 UDP DNS (ahnmtljhlayway).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:14:46.606911" r2d2 68.12.104.178 48011 68.12.99.2 53 UDP DNS (ahnmtljhlayway).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:14:46.814874" r2d2 68.12.104.178 47821 68.12.99.2 53 UDP DNS (lqlstts).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:14:46.814854" r2d2 68.12.104.178 47821 68.12.99.2 53 UDP DNS (lqlstts).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:14:46.868871" r2d2 68.12.104.178 43413 68.12.99.2 53 UDP DNS (uxuivdbl).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:14:46.868872" r2d2 68.12.104.178 43413 68.12.99.2 53 UDP DNS (uxuivdbl).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:14:46.898501" r2d2 68.12.104.178 38419 68.12.99.2 53 UDP DNS (ncxyoysqcurkwdxcobv).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:14:46.898503" r2d2 68.12.104.178 38419 68.12.99.2 53 UDP DNS (ncxyoysqcurkwdxcobv).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:14:47.013549" r2d2 68.12.104.178 59073 68.12.99.2 53 UDP DNS (nhfcubvcst).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:14:47.013556" r2d2 68.12.104.178 59073 68.12.99.2 53 UDP DNS (nhfcubvcst).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:14:47.549648" r2d2 68.12.104.178 40410 68.12.99.2 53 UDP DNS (olqhgjlirwh).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:14:47.549646" r2d2 68.12.104.178 40410 68.12.99.2 53 UDP DNS (olqhgjlirwh).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:14:47.900382" r2d2 68.12.104.178 45378 68.12.99.2 53 UDP DNS (gaiyrmgfqehdrv).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:14:47.900381" r2d2 68.12.104.178 45378 68.12.99.2 53 UDP DNS (gaiyrmgfqehdrv).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:14:47.973283" r2d2 68.12.104.178 50519 68.12.99.2 53 UDP DNS (hxhrpxeuctl).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:14:47.973270" r2d2 68.12.104.178 50519 68.12.99.2 53 UDP DNS (hxhrpxeuctl).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:14:48.184931" r2d2 68.12.104.178 41633 68.12.99.2 53 UDP DNS (rbjrbdscwfpkmbewimnw).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:14:48.184932" r2d2 68.12.104.178 41633 68.12.99.2 53 UDP DNS (rbjrbdscwfpkmbewimnw).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:14:48.482478" r2d2 68.12.104.178 51057 68.12.99.2 53 UDP DNS (bvtnvasdlmcduftmigc).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:14:48.482475" r2d2 68.12.104.178 51057 68.12.99.2 53 UDP DNS (bvtnvasdlmcduftmigc).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:14:48.579503" r2d2 68.12.104.178 45194 68.12.99.2 53 UDP DNS (yqmddygacl).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:14:48.579505" r2d2 68.12.104.178 45194 68.12.99.2 53 UDP DNS (yqmddygacl).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:14:48.694221" r2d2 68.12.104.178 58370 68.12.99.2 53 UDP DNS (qdvjvqrelna).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:14:48.694222" r2d2 68.12.104.178 58370 68.12.99.2 53 UDP DNS (qdvjvqrelna).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:14:48.704954" r2d2 68.12.104.178 53884 68.12.99.2 53 UDP DNS (vborlqmshhmxmv).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:14:48.704956" r2d2 68.12.104.178 53884 68.12.99.2 53 UDP DNS (vborlqmshhmxmv).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:14:48.924309" r2d2 68.12.104.178 44512 68.12.99.2 53 UDP DNS (megascor).no-ip.biz "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 08:14:48.924311" r2d2 68.12.104.178 44512 68.12.99.2 53 UDP DNS (megascor).no-ip.biz "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 08:14:49.210508" r2d2 68.12.104.178 35142 68.12.99.2 53 UDP DNS (yugpclyqofql).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:14:49.210512" r2d2 68.12.104.178 35142 68.12.99.2 53 UDP DNS (yugpclyqofql).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:14:49.262301" r2d2 68.12.104.178 41738 68.12.99.2 53 UDP DNS (rujjhgphwoxhdv).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:14:49.262299" r2d2 68.12.104.178 41738 68.12.99.2 53 UDP DNS (rujjhgphwoxhdv).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:14:49.378797" r2d2 68.12.104.178 47329 68.12.99.2 53 UDP DNS (gjiosnl).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:14:49.378789" r2d2 68.12.104.178 47329 68.12.99.2 53 UDP DNS (gjiosnl).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:14:50.393003" r2d2 68.12.104.178 52150 68.12.99.2 53 UDP DNS (mnwituubbok).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:14:50.393005" r2d2 68.12.104.178 52150 68.12.99.2 53 UDP DNS (mnwituubbok).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:14:50.473694" r2d2 68.12.104.178 37200 68.12.99.2 53 UDP DNS (qqkmrhouyxgl).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:14:50.473672" r2d2 68.12.104.178 37200 68.12.99.2 53 UDP DNS (qqkmrhouyxgl).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:14:50.525169" r2d2 68.12.104.178 57264 68.12.99.2 53 UDP DNS (ctjyhxtj).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:14:50.525172" r2d2 68.12.104.178 57264 68.12.99.2 53 UDP DNS (ctjyhxtj).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:14:50.743731" r2d2 68.12.104.178 45690 68.12.99.2 53 UDP DNS (xvuqseqsmagysdtxk).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:14:50.743734" r2d2 68.12.104.178 45690 68.12.99.2 53 UDP DNS (xvuqseqsmagysdtxk).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:14:51.228808" r2d2 68.12.104.178 59103 68.12.99.2 53 UDP DNS (pdjlrrjodrik).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:14:51.228839" r2d2 68.12.104.178 59103 68.12.99.2 53 UDP DNS (pdjlrrjodrik).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:14:51.393956" r2d2 68.12.104.178 45605 68.12.99.2 53 UDP DNS (frnmlmwvdyrgqucesits).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:14:51.393953" r2d2 68.12.104.178 45605 68.12.99.2 53 UDP DNS (frnmlmwvdyrgqucesits).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:14:51.541837" r2d2 68.12.104.178 39779 68.12.99.2 53 UDP DNS (fcgpokxypfurin).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:14:51.542018" r2d2 68.12.104.178 39779 68.12.99.2 53 UDP DNS (fcgpokxypfurin).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:14:51.701073" r2d2 68.12.104.178 46997 68.12.99.2 53 UDP DNS (gdlxxrdufrlnmo).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:14:51.701074" r2d2 68.12.104.178 46997 68.12.99.2 53 UDP DNS (gdlxxrdufrlnmo).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:14:51.726309" r2d2 68.12.104.178 44346 68.12.99.2 53 UDP DNS (gsomievmdpibw).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:14:51.726313" r2d2 68.12.104.178 44346 68.12.99.2 53 UDP DNS (gsomievmdpibw).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:14:51.809242" r2d2 68.12.104.178 56242 68.12.99.2 53 UDP DNS (rrrvmpujs).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:14:51.809240" r2d2 68.12.104.178 56242 68.12.99.2 53 UDP DNS (rrrvmpujs).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:14:51.854235" r2d2 68.12.104.178 42793 68.12.99.2 53 UDP DNS (hnjjxsm).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:14:51.854233" r2d2 68.12.104.178 42793 68.12.99.2 53 UDP DNS (hnjjxsm).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:14:52.693420" r2d2 68.12.104.178 39293 68.12.99.2 53 UDP DNS (btiyjeaqrq).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:14:52.693418" r2d2 68.12.104.178 39293 68.12.99.2 53 UDP DNS (btiyjeaqrq).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:14:53.010017" r2d2 68.12.104.178 49681 68.12.99.2 53 UDP DNS (ceiymicjifpncdebnu).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:14:53.010013" r2d2 68.12.104.178 49681 68.12.99.2 53 UDP DNS (ceiymicjifpncdebnu).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:14:53.143995" r2d2 68.12.104.178 37241 68.12.99.2 53 UDP DNS (nwmwwrigxjofmkpol).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:14:53.143996" r2d2 68.12.104.178 37241 68.12.99.2 53 UDP DNS (nwmwwrigxjofmkpol).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:14:54.616619" r2d2 68.12.104.178 35848 68.12.99.2 53 UDP DNS (ikkfkimgkbewpwfmpor).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:14:54.616617" r2d2 68.12.104.178 35848 68.12.99.2 53 UDP DNS (ikkfkimgkbewpwfmpor).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:14:54.969684" r2d2 68.12.104.178 40984 68.12.99.2 53 UDP DNS (eihxabppxdqqnfahftwfd).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:14:54.969683" r2d2 68.12.104.178 40984 68.12.99.2 53 UDP DNS (eihxabppxdqqnfahftwfd).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:14:55.872655" r2d2 68.12.104.178 46503 68.12.99.2 53 UDP DNS (lmxpvikwprmj).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:14:55.872654" r2d2 68.12.104.178 46503 68.12.99.2 53 UDP DNS (lmxpvikwprmj).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:14:56.186109" r2d2 68.12.104.178 52015 68.12.99.2 53 UDP DNS barclays.com expiro (static)\n' +
    '"2015-03-10 08:14:56.186100" r2d2 68.12.104.178 52015 68.12.99.2 53 UDP DNS barclays.com expiro (static)\n' +
    '"2015-03-10 08:14:57.422040" r2d2 68.12.104.178 53812 68.12.99.2 53 UDP DNS (kjbehpxwlufkcx).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:14:57.422042" r2d2 68.12.104.178 53812 68.12.99.2 53 UDP DNS (kjbehpxwlufkcx).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:14:58.395410" r2d2 68.12.104.178 51347 68.12.99.2 53 UDP DNS (xkjajenjswqncsi).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:14:58.395405" r2d2 68.12.104.178 51347 68.12.99.2 53 UDP DNS (xkjajenjswqncsi).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:14:58.446848" r2d2 68.12.104.178 50262 68.12.99.2 53 UDP DNS (kuluexytosjnlckrve).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:14:58.446850" r2d2 68.12.104.178 50262 68.12.99.2 53 UDP DNS (kuluexytosjnlckrve).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:14:58.600906" r2d2 68.12.104.178 49968 68.12.99.2 53 UDP DNS (wgwpujnlixggmjpcfowyd).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:14:58.600905" r2d2 68.12.104.178 49968 68.12.99.2 53 UDP DNS (wgwpujnlixggmjpcfowyd).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:15:01.361146" r2d2 222.186.34.202 6000 68.12.104.178 22 TCP IP 222.186.34.202 abuser openbl.org\n' +
    '"2015-03-10 08:15:01.361143" r2d2 222.186.34.202 6000 68.12.104.178 22 TCP IP 222.186.34.202 abuser openbl.org\n' +
    '"2015-03-10 08:15:01.476442" r2d2 68.12.104.178 41625 68.12.99.2 53 UDP DNS (vsqxboyqde).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:15:01.476441" r2d2 68.12.104.178 41625 68.12.99.2 53 UDP DNS (vsqxboyqde).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:15:01.660049" r2d2 68.12.104.178 52974 68.12.99.2 53 UDP DNS (ddmjfrqkhbfdrrblq).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:15:01.660050" r2d2 68.12.104.178 52974 68.12.99.2 53 UDP DNS (ddmjfrqkhbfdrrblq).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:15:01.960738" r2d2 68.12.104.178 36878 68.12.99.2 53 UDP DNS (wymbfqgy).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:15:01.960735" r2d2 68.12.104.178 36878 68.12.99.2 53 UDP DNS (wymbfqgy).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:15:02.372302" r2d2 68.12.104.178 36061 68.12.99.2 53 UDP DNS (jvgyobuvkjgrbj).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:15:02.372300" r2d2 68.12.104.178 36061 68.12.99.2 53 UDP DNS (jvgyobuvkjgrbj).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:15:02.670469" r2d2 68.12.104.178 45819 68.12.99.2 53 UDP DNS (dsweqocogohp).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:15:02.670479" r2d2 68.12.104.178 45819 68.12.99.2 53 UDP DNS (dsweqocogohp).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:15:02.868778" r2d2 68.12.104.178 52531 68.12.99.2 53 UDP DNS (ussyuxendpq).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:15:02.868776" r2d2 68.12.104.178 52531 68.12.99.2 53 UDP DNS (ussyuxendpq).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:15:03.156106" r2d2 68.12.104.178 50510 68.12.99.2 53 UDP DNS (hilyichhoiyth).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:15:03.156107" r2d2 68.12.104.178 50510 68.12.99.2 53 UDP DNS (hilyichhoiyth).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:15:03.163867" r2d2 68.12.104.178 41505 68.12.99.2 53 UDP DNS (kgxbnqxmenrl).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:15:03.163869" r2d2 68.12.104.178 41505 68.12.99.2 53 UDP DNS (kgxbnqxmenrl).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:15:03.235209" r2d2 68.12.104.178 41303 68.12.99.2 53 UDP DNS (sntyacoaditegysqhg).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:15:03.235205" r2d2 68.12.104.178 41303 68.12.99.2 53 UDP DNS (sntyacoaditegysqhg).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:15:03.272992" r2d2 68.12.104.178 59831 68.12.99.2 53 UDP DNS (wwsixxnnqnpgospvfnxg).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:15:03.272993" r2d2 68.12.104.178 59831 68.12.99.2 53 UDP DNS (wwsixxnnqnpgospvfnxg).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:15:03.465896" r2d2 68.12.104.178 52747 68.12.99.2 53 UDP DNS (wehuckdtdm).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:15:03.465897" r2d2 68.12.104.178 52747 68.12.99.2 53 UDP DNS (wehuckdtdm).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:15:03.586857" r2d2 68.12.104.178 45127 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 08:15:03.586852" r2d2 68.12.104.178 45127 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 08:15:03.712016" r2d2 68.12.104.178 40389 68.12.99.2 53 UDP DNS (hpvycxcfksyvwecnlfl).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:15:03.712014" r2d2 68.12.104.178 40389 68.12.99.2 53 UDP DNS (hpvycxcfksyvwecnlfl).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:15:04.074309" r2d2 68.12.104.178 40837 68.12.99.2 53 UDP DNS (tburiinomv).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:15:04.074310" r2d2 68.12.104.178 40837 68.12.99.2 53 UDP DNS (tburiinomv).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:15:04.127765" r2d2 68.12.104.178 47180 68.12.99.2 53 UDP DNS (ckbxwirugwck).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:15:04.127763" r2d2 68.12.104.178 47180 68.12.99.2 53 UDP DNS (ckbxwirugwck).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:15:04.207218" r2d2 68.12.104.178 59630 68.12.99.2 53 UDP DNS (eljlieajrrodexjbil).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:15:04.207216" r2d2 68.12.104.178 59630 68.12.99.2 53 UDP DNS (eljlieajrrodexjbil).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:15:04.383452" r2d2 68.12.104.178 58104 68.12.99.2 53 UDP DNS (yfrayyrchvgclcci).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:15:04.383453" r2d2 68.12.104.178 58104 68.12.99.2 53 UDP DNS (yfrayyrchvgclcci).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:15:04.434292" r2d2 68.12.104.178 47638 68.12.99.2 53 UDP DNS (erbjnidvgh).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:15:04.434291" r2d2 68.12.104.178 47638 68.12.99.2 53 UDP DNS (erbjnidvgh).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:15:05.145410" r2d2 68.12.104.178 58581 68.12.99.2 53 UDP DNS (nhxgaolisigaxcaaq).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:15:05.145408" r2d2 68.12.104.178 58581 68.12.99.2 53 UDP DNS (nhxgaolisigaxcaaq).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:15:05.675081" r2d2 68.12.104.178 52206 68.12.99.2 53 UDP DNS (ajgnurwovhapxmjf).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:15:05.675239" r2d2 68.12.104.178 52206 68.12.99.2 53 UDP DNS (ajgnurwovhapxmjf).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:15:05.874534" r2d2 68.12.104.178 57255 68.12.99.2 53 UDP DNS (tracker.coppersurfer).tk "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:15:05.874550" r2d2 68.12.104.178 57255 68.12.99.2 53 UDP DNS (tracker.coppersurfer).tk "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:15:06.352501" r2d2 68.12.104.178 44571 68.12.99.2 53 UDP DNS (kypbrupnjm).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:15:06.352499" r2d2 68.12.104.178 44571 68.12.99.2 53 UDP DNS (kypbrupnjm).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:15:06.757861" r2d2 68.12.104.178 47505 68.12.99.2 53 UDP DNS (mqeeqbrwupm).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:15:06.757874" r2d2 68.12.104.178 47505 68.12.99.2 53 UDP DNS (mqeeqbrwupm).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:15:06.876761" r2d2 68.12.104.178 46603 68.12.99.2 53 UDP DNS (kshotkykawjnvw).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:15:06.876763" r2d2 68.12.104.178 46603 68.12.99.2 53 UDP DNS (kshotkykawjnvw).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:15:06.942999" r2d2 68.12.104.178 48293 68.12.99.2 53 UDP DNS (jcydchkgarscg).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:15:06.943012" r2d2 68.12.104.178 48293 68.12.99.2 53 UDP DNS (jcydchkgarscg).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:15:09.030539" r2d2 68.12.104.178 39433 68.12.99.2 53 UDP DNS (gypnuwvydjdpfq).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:15:09.030540" r2d2 68.12.104.178 39433 68.12.99.2 53 UDP DNS (gypnuwvydjdpfq).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:15:09.678460" r2d2 68.12.104.178 58285 113.108.80.138 53 UDP IP 113.108.80.138 dnspod (custom)\n' +
    '"2015-03-10 08:15:09.678449" r2d2 68.12.104.178 58285 113.108.80.138 53 UDP IP 113.108.80.138 dnspod (custom)\n' +
    '"2015-03-10 08:15:10.097511" r2d2 68.12.104.178 43373 68.12.99.2 53 UDP DNS (aapfoxoie).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:15:10.097510" r2d2 68.12.104.178 43373 68.12.99.2 53 UDP DNS (aapfoxoie).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:15:10.517775" r2d2 68.12.104.178 36394 68.12.99.2 53 UDP DNS (mhtpalmgbpklryhvljs).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:15:10.517790" r2d2 68.12.104.178 36394 68.12.99.2 53 UDP DNS (mhtpalmgbpklryhvljs).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:15:11.285630" r2d2 68.12.104.178 43481 68.12.99.2 53 UDP DNS (hltkhcrjucqcmqrc).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:15:11.285628" r2d2 68.12.104.178 43481 68.12.99.2 53 UDP DNS (hltkhcrjucqcmqrc).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:15:11.465020" r2d2 68.12.104.178 53779 68.12.99.2 53 UDP DNS (htjvvkgrd).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:15:11.465018" r2d2 68.12.104.178 53779 68.12.99.2 53 UDP DNS (htjvvkgrd).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:15:14.071930" r2d2 68.12.104.178 55920 68.12.99.2 53 UDP DNS (tomfaakklyukbsrg).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:15:14.071929" r2d2 68.12.104.178 55920 68.12.99.2 53 UDP DNS (tomfaakklyukbsrg).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:15:15.389410" r2d2 68.12.104.178 46160 68.12.99.2 53 UDP DNS (www.conseo).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:15:15.389412" r2d2 68.12.104.178 46160 68.12.99.2 53 UDP DNS (www.conseo).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:15:15.673937" r2d2 68.12.104.178 49584 68.12.99.2 53 UDP DNS (dhntjoyse).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:15:15.673935" r2d2 68.12.104.178 49584 68.12.99.2 53 UDP DNS (dhntjoyse).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:15:16.402644" r2d2 68.12.104.178 42823 68.12.99.2 53 UDP DNS (nutwqorkjbgxo).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:15:16.402648" r2d2 68.12.104.178 42823 68.12.99.2 53 UDP DNS (nutwqorkjbgxo).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:15:16.485189" r2d2 68.12.104.178 42258 68.12.99.2 53 UDP DNS (hcarsjmhvpnen).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:15:16.485180" r2d2 68.12.104.178 42258 68.12.99.2 53 UDP DNS (hcarsjmhvpnen).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:15:16.770015" r2d2 68.12.104.178 52304 68.12.99.2 53 UDP DNS (eraxwqfikmc).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:15:16.770028" r2d2 68.12.104.178 52304 68.12.99.2 53 UDP DNS (eraxwqfikmc).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:15:17.321049" r2d2 68.12.104.178 57910 68.12.99.2 53 UDP DNS (diiojdftje).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:15:17.321051" r2d2 68.12.104.178 57910 68.12.99.2 53 UDP DNS (diiojdftje).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:15:17.404593" r2d2 68.12.104.178 42153 68.12.99.2 53 UDP DNS (yoxwscyfftr).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:15:17.404595" r2d2 68.12.104.178 42153 68.12.99.2 53 UDP DNS (yoxwscyfftr).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:15:18.360363" r2d2 68.12.104.178 38895 68.12.99.2 53 UDP DNS (tlmetrogsj).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:15:18.360362" r2d2 68.12.104.178 38895 68.12.99.2 53 UDP DNS (tlmetrogsj).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:15:18.400315" r2d2 68.12.104.178 37058 68.12.99.2 53 UDP DNS (vhtblupjffijnc).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:15:18.400314" r2d2 68.12.104.178 37058 68.12.99.2 53 UDP DNS (vhtblupjffijnc).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:15:18.562257" r2d2 68.12.104.178 54069 68.12.99.2 53 UDP DNS (rdhsqqeatpape).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:15:18.562259" r2d2 68.12.104.178 54069 68.12.99.2 53 UDP DNS (rdhsqqeatpape).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:15:18.605472" r2d2 68.12.104.178 35409 68.12.99.2 53 UDP DNS (egwdhbgweqcmpsk).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:15:18.605473" r2d2 68.12.104.178 35409 68.12.99.2 53 UDP DNS (egwdhbgweqcmpsk).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:15:19.414341" r2d2 68.12.104.178 38610 68.12.99.2 53 UDP DNS (mikupusjuwvofcylhl).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:15:19.414339" r2d2 68.12.104.178 38610 68.12.99.2 53 UDP DNS (mikupusjuwvofcylhl).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:15:19.740470" r2d2 192.198.115.139 5081 68.12.104.178 5060 UDP IP 192.198.115.139 "sipvicious scan" autoshun.org\n' +
    '"2015-03-10 08:15:19.740472" r2d2 192.198.115.139 5081 68.12.104.178 5060 UDP IP 192.198.115.139 "sipvicious scan" autoshun.org\n' +
    '"2015-03-10 08:15:20.846688" r2d2 68.12.104.178 42129 68.12.99.2 53 UDP DNS (xcorqmyioedncw).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:15:20.846689" r2d2 68.12.104.178 42129 68.12.99.2 53 UDP DNS (xcorqmyioedncw).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:15:24.206513" r2d2 68.12.104.178 44308 68.12.99.2 53 UDP DNS (www.raymond).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:15:24.206528" r2d2 68.12.104.178 44308 68.12.99.2 53 UDP DNS (www.raymond).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:15:24.849922" r2d2 68.12.104.178 35852 68.12.99.2 53 UDP DNS (brrwlvfxtaia).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:15:24.849920" r2d2 68.12.104.178 35852 68.12.99.2 53 UDP DNS (brrwlvfxtaia).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:15:26.526904" r2d2 68.12.104.178 40269 68.12.99.2 53 UDP DNS (esxqrqnaeevrgd).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:15:26.526900" r2d2 68.12.104.178 40269 68.12.99.2 53 UDP DNS (esxqrqnaeevrgd).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:15:26.679284" r2d2 68.12.104.178 42002 68.12.99.2 53 UDP DNS (wgvqbaebckqcmiv).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:15:26.679283" r2d2 68.12.104.178 42002 68.12.99.2 53 UDP DNS (wgvqbaebckqcmiv).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:15:26.728815" r2d2 68.12.104.178 46040 68.12.99.2 53 UDP DNS (vguorkteosy).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:15:26.728817" r2d2 68.12.104.178 46040 68.12.99.2 53 UDP DNS (vguorkteosy).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:15:27.302847" r2d2 68.12.104.178 51919 68.12.99.2 53 UDP DNS (gredfweokxek).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:15:27.302834" r2d2 68.12.104.178 51919 68.12.99.2 53 UDP DNS (gredfweokxek).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:15:27.829262" r2d2 68.12.104.178 50331 68.12.99.2 53 UDP DNS (alhlxqaxof).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:15:27.829784" r2d2 68.12.104.178 45685 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 08:15:27.829253" r2d2 68.12.104.178 50331 68.12.99.2 53 UDP DNS (alhlxqaxof).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:15:27.829783" r2d2 68.12.104.178 45685 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 08:15:28.736733" r2d2 68.12.104.178 57070 68.12.99.2 53 UDP DNS (mail3.myhsphere).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:15:28.736731" r2d2 68.12.104.178 57070 68.12.99.2 53 UDP DNS (mail3.myhsphere).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:15:28.872446" r2d2 68.12.104.178 38843 68.12.99.2 53 UDP DNS (mail0.myhsphere).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:15:28.872443" r2d2 68.12.104.178 38843 68.12.99.2 53 UDP DNS (mail0.myhsphere).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:15:33.944569" r2d2 68.12.104.178 39937 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 08:15:33.944567" r2d2 68.12.104.178 39937 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 08:15:35.027681" r2d2 68.12.104.178 47060 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 08:15:35.027682" r2d2 68.12.104.178 47060 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 08:15:58.656181" r2d2 68.12.104.178 41030 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 08:15:58.656180" r2d2 68.12.104.178 41030 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 08:16:00.823616" r2d2 68.12.104.178 50340 68.12.99.2 53 UDP DNS (megascor).no-ip.biz "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 08:16:00.823615" r2d2 68.12.104.178 50340 68.12.99.2 53 UDP DNS (megascor).no-ip.biz "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 08:16:07.941551" r2d2 68.12.104.178 52009 68.12.99.2 53 UDP DNS (lajf09).zapto.org "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 08:16:07.941550" r2d2 68.12.104.178 52009 68.12.99.2 53 UDP DNS (lajf09).zapto.org "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 08:16:13.240931" r2d2 68.12.104.178 39425 68.12.99.2 53 UDP DNS digitalmind.cn "palevo (malware)" palevotracker.abuse.ch\n' +
    '"2015-03-10 08:16:13.240941" r2d2 68.12.104.178 39425 68.12.99.2 53 UDP DNS digitalmind.cn "palevo (malware)" palevotracker.abuse.ch\n' +
    '"2015-03-10 08:16:33.629406" r2d2 68.12.104.178 37130 68.12.99.2 53 UDP DNS (forsyth).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:16:33.629804" r2d2 68.12.104.178 47088 68.12.99.2 53 UDP DNS (ns1.nic).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:16:33.630109" r2d2 68.12.104.178 48625 68.12.99.2 53 UDP DNS (ns2.nic).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:16:33.629408" r2d2 68.12.104.178 37130 68.12.99.2 53 UDP DNS (forsyth).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:16:33.629806" r2d2 68.12.104.178 47088 68.12.99.2 53 UDP DNS (ns1.nic).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:16:33.630111" r2d2 68.12.104.178 48625 68.12.99.2 53 UDP DNS (ns2.nic).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:16:34.743324" r2d2 68.12.104.178 35591 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 08:16:34.743326" r2d2 68.12.104.178 35591 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 08:16:45.686897" r2d2 68.12.104.178 58326 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 08:16:45.686894" r2d2 68.12.104.178 58326 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 08:17:00.249722" r2d2 68.12.104.178 43100 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 08:17:00.249724" r2d2 68.12.104.178 43100 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 08:17:05.089317" r2d2 68.12.104.178 46073 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 08:17:05.089319" r2d2 68.12.104.178 46073 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 08:17:17.763517" r2d2 68.12.104.178 57979 68.12.99.2 53 UDP DNS (megascor).no-ip.biz "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 08:17:17.763626" r2d2 68.12.104.178 57979 68.12.99.2 53 UDP DNS (megascor).no-ip.biz "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 08:17:31.057942" r2d2 68.12.104.178 52478 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 08:17:31.057943" r2d2 68.12.104.178 52478 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 08:17:35.449018" r2d2 68.12.104.178 46479 68.12.99.2 53 UDP DNS promisex.ru "zeus (malware)" (custom)\n' +
    '"2015-03-10 08:17:35.449021" r2d2 68.12.104.178 46479 68.12.99.2 53 UDP DNS promisex.ru "zeus (malware)" (custom)\n' +
    '"2015-03-10 08:17:42.297594" r2d2 68.12.104.178 47112 68.12.99.2 53 UDP DNS (icr).ddns.net "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 08:17:42.297592" r2d2 68.12.104.178 47112 68.12.99.2 53 UDP DNS (icr).ddns.net "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 08:17:53.228583" r2d2 68.12.104.178 56607 68.12.99.2 53 UDP DNS (powerdrive).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:17:53.228585" r2d2 68.12.104.178 56607 68.12.99.2 53 UDP DNS (powerdrive).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:18:04.823615" r2d2 68.12.104.178 39121 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 08:18:04.823618" r2d2 68.12.104.178 39121 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 08:18:05.717200" r2d2 68.12.104.178 56352 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 08:18:05.717202" r2d2 68.12.104.178 56352 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 08:18:17.725260" r2d2 68.12.104.178 43549 68.12.99.2 53 UDP DNS (brightlounge).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:18:17.725270" r2d2 68.12.104.178 43549 68.12.99.2 53 UDP DNS (brightlounge).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:18:19.661995" r2d2 68.12.104.178 38044 68.12.99.2 53 UDP DNS (megascor).no-ip.biz "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 08:18:19.661998" r2d2 68.12.104.178 38044 68.12.99.2 53 UDP DNS (megascor).no-ip.biz "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 08:18:23.023014" r2d2 68.12.104.178 57355 8.8.8.8 53 UDP DNS (brightlounge).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:18:23.023025" r2d2 68.12.104.178 57355 8.8.8.8 53 UDP DNS (brightlounge).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:18:23.451890" r2d2 68.12.104.178 44316 113.108.80.138 53 UDP IP 113.108.80.138 dnspod (custom)\n' +
    '"2015-03-10 08:18:23.451888" r2d2 68.12.104.178 44316 113.108.80.138 53 UDP IP 113.108.80.138 dnspod (custom)\n' +
    '"2015-03-10 08:18:23.981584" r2d2 68.12.104.178 43345 113.108.80.138 53 UDP IP 113.108.80.138 dnspod (custom)\n' +
    '"2015-03-10 08:18:23.981590" r2d2 68.12.104.178 43345 113.108.80.138 53 UDP IP 113.108.80.138 dnspod (custom)\n' +
    '"2015-03-10 08:18:32.760424" r2d2 68.12.104.178 43115 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 08:18:32.760794" r2d2 68.12.104.178 43115 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 08:18:36.060009" r2d2 68.12.104.178 59556 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 08:18:36.060011" r2d2 68.12.104.178 59556 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 08:18:45.621518" r2d2 68.12.104.178 48653 68.12.99.2 53 UDP DNS teske.pornicarke.com "palevo (malware)" (static)\n' +
    '"2015-03-10 08:18:45.621514" r2d2 68.12.104.178 48653 68.12.99.2 53 UDP DNS teske.pornicarke.com "palevo (malware)" (static)\n' +
    '"2015-03-10 08:18:49.676460" r2d2 68.12.104.178 52511 68.12.99.2 53 UDP DNS (nycaasa).no-ip.org "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 08:18:49.676457" r2d2 68.12.104.178 52511 68.12.99.2 53 UDP DNS (nycaasa).no-ip.org "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 08:19:03.586138" r2d2 68.12.104.178 51339 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 08:19:03.586137" r2d2 68.12.104.178 51339 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 08:19:06.759968" r2d2 68.12.104.178 43862 202.129.216.60 53 UDP IP 202.129.216.60 abuser openbl.org\n' +
    '"2015-03-10 08:19:06.759966" r2d2 68.12.104.178 43862 202.129.216.60 53 UDP IP 202.129.216.60 abuser openbl.org\n' +
    '"2015-03-10 08:19:06.761728" r2d2 68.12.104.178 43347 202.129.216.60 53 UDP IP 202.129.216.60 abuser openbl.org\n' +
    '"2015-03-10 08:19:06.761729" r2d2 68.12.104.178 43347 202.129.216.60 53 UDP IP 202.129.216.60 abuser openbl.org\n' +
    '"2015-03-10 08:19:08.591803" r2d2 68.12.104.178 39334 202.129.216.60 53 UDP IP 202.129.216.60 abuser openbl.org\n' +
    '"2015-03-10 08:19:08.591804" r2d2 68.12.104.178 39334 202.129.216.60 53 UDP IP 202.129.216.60 abuser openbl.org\n' +
    '"2015-03-10 08:19:15.524698" r2d2 68.12.104.178 46775 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 08:19:15.524699" r2d2 68.12.104.178 46775 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 08:19:22.426362" r2d2 68.12.104.178 52802 68.12.99.2 53 UDP DNS (megascor).no-ip.biz "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 08:19:22.426360" r2d2 68.12.104.178 52802 68.12.99.2 53 UDP DNS (megascor).no-ip.biz "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 08:19:35.536596" r2d2 68.12.104.178 47992 68.12.99.2 53 UDP DNS peer.pickeklosarske.ru "palevo (malware)" (static)\n' +
    '"2015-03-10 08:19:36.746016" r2d2 68.12.104.178 45282 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 08:19:36.746020" r2d2 68.12.104.178 45282 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 08:20:05.162937" r2d2 68.12.104.178 48172 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 08:20:05.162922" r2d2 68.12.104.178 48172 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 08:20:05.878855" r2d2 68.12.104.178 58883 68.12.99.2 53 UDP DNS (tracker.coppersurfer).tk "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:20:05.878858" r2d2 68.12.104.178 58883 68.12.99.2 53 UDP DNS (tracker.coppersurfer).tk "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:20:07.584335" r2d2 68.12.104.178 48734 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 08:20:07.584334" r2d2 68.12.104.178 48734 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 08:20:34.619219" r2d2 68.12.104.178 55477 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 08:20:34.619220" r2d2 68.12.104.178 55477 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 08:20:35.997158" r2d2 68.12.104.178 49625 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 08:20:35.997156" r2d2 68.12.104.178 49625 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 08:20:40.415470" r2d2 68.12.104.178 59942 68.12.99.2 53 UDP DNS (megascor).no-ip.biz "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 08:20:40.415460" r2d2 68.12.104.178 59942 68.12.99.2 53 UDP DNS (megascor).no-ip.biz "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 08:21:01.514928" r2d2 68.12.104.178 42478 81.2.199.97 53 UDP IP 81.2.199.97 "asprox (malware)" atrack.h3x.eu\n' +
    '"2015-03-10 08:21:01.514926" r2d2 68.12.104.178 42478 81.2.199.97 53 UDP IP 81.2.199.97 "asprox (malware)" atrack.h3x.eu\n' +
    '"2015-03-10 08:21:09.194130" r2d2 68.12.104.178 37053 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 08:21:09.194147" r2d2 68.12.104.178 37053 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 08:21:11.619200" r2d2 68.12.104.178 56132 68.12.99.2 53 UDP DNS (ns1.via).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:21:11.619377" r2d2 68.12.104.178 49536 68.12.99.2 53 UDP DNS (ns2.via).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:21:11.619189" r2d2 68.12.104.178 56132 68.12.99.2 53 UDP DNS (ns1.via).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:21:11.619380" r2d2 68.12.104.178 49536 68.12.99.2 53 UDP DNS (ns2.via).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:21:37.588806" r2d2 68.12.104.178 48201 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 08:21:37.588805" r2d2 68.12.104.178 48201 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 08:21:39.101018" r2d2 61.240.144.66 60000 68.12.104.178 514 UDP IP 61.240.144.66 "incoming masscan detected" autoshun.org\n' +
    '"2015-03-10 08:21:39.101020" r2d2 61.240.144.66 60000 68.12.104.178 514 UDP IP 61.240.144.66 "incoming masscan detected" autoshun.org\n' +
    '"2015-03-10 08:21:40.065117" r2d2 68.12.104.178 47816 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 08:21:40.065124" r2d2 68.12.104.178 47816 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 08:21:45.090727" r2d2 68.12.104.178 59619 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 08:21:45.090726" r2d2 68.12.104.178 59619 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 08:21:59.095713" r2d2 68.12.104.178 35191 68.12.99.2 53 UDP DNS peer.pickeklosarske.ru "palevo (malware)" (static)\n' +
    '"2015-03-10 08:21:59.095714" r2d2 68.12.104.178 35191 68.12.99.2 53 UDP DNS peer.pickeklosarske.ru "palevo (malware)" (static)\n' +
    '"2015-03-10 08:22:02.533116" r2d2 68.12.104.178 40769 68.12.99.2 53 UDP DNS (megascor).no-ip.biz "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 08:22:02.533118" r2d2 68.12.104.178 40769 68.12.99.2 53 UDP DNS (megascor).no-ip.biz "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 08:22:02.890397" r2d2 68.12.104.178 48207 113.108.80.138 53 UDP IP 113.108.80.138 dnspod (custom)\n' +
    '"2015-03-10 08:22:02.890417" r2d2 68.12.104.178 48207 113.108.80.138 53 UDP IP 113.108.80.138 dnspod (custom)\n' +
    '"2015-03-10 08:22:08.647265" r2d2 68.12.104.178 51132 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 08:22:08.647268" r2d2 68.12.104.178 51132 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 08:22:12.141734" r2d2 68.12.104.178 55867 68.12.99.2 53 UDP DNS promisex.ru "zeus (malware)" (custom)\n' +
    '"2015-03-10 08:22:12.141732" r2d2 68.12.104.178 55867 68.12.99.2 53 UDP DNS promisex.ru "zeus (malware)" (custom)\n' +
    '"2015-03-10 08:22:20.588534" r2d2 68.12.104.178 50132 68.12.99.2 53 UDP DNS anvimob.ro attackpage safebrowsing.clients.google.com\n' +
    '"2015-03-10 08:22:20.588535" r2d2 68.12.104.178 50132 68.12.99.2 53 UDP DNS anvimob.ro attackpage safebrowsing.clients.google.com\n' +
    '"2015-03-10 08:22:23.138905" r2d2 68.12.104.178 54098 68.12.99.2 53 UDP DNS digitalmind.cn "palevo (malware)" palevotracker.abuse.ch\n' +
    '"2015-03-10 08:22:23.138906" r2d2 68.12.104.178 54098 68.12.99.2 53 UDP DNS digitalmind.cn "palevo (malware)" palevotracker.abuse.ch\n' +
    '"2015-03-10 08:22:41.703502" r2d2 68.12.104.178 51084 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 08:22:41.703504" r2d2 68.12.104.178 51084 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 08:22:53.159081" r2d2 68.12.104.178 42795 68.12.99.2 53 UDP DNS (tracker.coppersurfer).tk "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:22:53.159078" r2d2 68.12.104.178 42795 68.12.99.2 53 UDP DNS (tracker.coppersurfer).tk "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:22:53.358187" r2d2 68.12.104.178 40310 68.12.99.2 53 UDP DNS (api).browsestudio.com malware malwareurls.joxeankoret.com\n' +
    '"2015-03-10 08:22:53.358186" r2d2 68.12.104.178 40310 68.12.99.2 53 UDP DNS (api).browsestudio.com malware malwareurls.joxeankoret.com\n' +
    '"2015-03-10 08:22:55.399961" r2d2 68.12.104.178 48714 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 08:22:55.399958" r2d2 68.12.104.178 48714 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 08:23:10.209936" r2d2 68.12.104.178 39769 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 08:23:10.209940" r2d2 68.12.104.178 39769 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 08:23:12.558700" r2d2 68.12.104.178 45519 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 08:23:12.558703" r2d2 68.12.104.178 45519 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 08:23:13.536581" r2d2 68.12.104.178 50343 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 08:23:13.536582" r2d2 68.12.104.178 50343 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 08:23:20.359900" r2d2 68.12.104.178 55626 113.108.80.138 53 UDP IP 113.108.80.138 dnspod (custom)\n' +
    '"2015-03-10 08:23:20.359898" r2d2 68.12.104.178 55626 113.108.80.138 53 UDP IP 113.108.80.138 dnspod (custom)\n' +
    '"2015-03-10 08:23:25.882111" r2d2 68.12.104.178 36917 68.12.99.2 53 UDP DNS (megascor).no-ip.biz "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 08:23:25.882112" r2d2 68.12.104.178 36917 68.12.99.2 53 UDP DNS (megascor).no-ip.biz "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 08:23:26.325635" r2d2 68.12.104.178 57583 113.108.80.138 53 UDP IP 113.108.80.138 dnspod (custom)\n' +
    '"2015-03-10 08:23:26.325631" r2d2 68.12.104.178 57583 113.108.80.138 53 UDP IP 113.108.80.138 dnspod (custom)\n' +
    '"2015-03-10 08:23:34.836343" r2d2 68.12.104.178 47879 80.248.208.131 53 UDP IP 80.248.208.131 "tor exit node" torproject.org\n' +
    '"2015-03-10 08:23:34.836341" r2d2 68.12.104.178 47879 80.248.208.131 53 UDP IP 80.248.208.131 "tor exit node" torproject.org\n' +
    '"2015-03-10 08:23:41.029002" r2d2 68.12.104.178 43302 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 08:23:41.029003" r2d2 68.12.104.178 43302 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 08:23:43.064506" r2d2 68.12.104.178 39106 68.12.99.2 53 UDP DNS (mf).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:23:43.064507" r2d2 68.12.104.178 39106 68.12.99.2 53 UDP DNS (mf).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:23:46.751520" r2d2 68.12.104.178 37979 113.108.80.138 53 UDP IP 113.108.80.138 dnspod (custom)\n' +
    '"2015-03-10 08:23:46.751519" r2d2 68.12.104.178 37979 113.108.80.138 53 UDP IP 113.108.80.138 dnspod (custom)\n' +
    '"2015-03-10 08:23:50.486158" r2d2 68.12.104.178 57252 68.12.99.2 53 UDP DNS counter.yadro.ru "zeroaccess (malware)" (static)\n' +
    '"2015-03-10 08:23:50.486151" r2d2 68.12.104.178 57252 68.12.99.2 53 UDP DNS counter.yadro.ru "zeroaccess (malware)" (static)\n' +
    '"2015-03-10 08:24:14.459934" r2d2 68.12.104.178 37608 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 08:24:14.459932" r2d2 68.12.104.178 37608 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 08:24:14.902351" r2d2 68.12.104.178 36957 68.12.99.2 53 UDP DNS (thepowerhouse).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:24:14.902346" r2d2 68.12.104.178 36957 68.12.99.2 53 UDP DNS (thepowerhouse).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:24:15.162596" r2d2 68.12.104.178 36842 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 08:24:15.162592" r2d2 68.12.104.178 36842 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 08:24:19.884654" r2d2 68.12.104.178 38084 68.12.99.2 53 UDP DNS peer.pickeklosarske.ru "palevo (malware)" (static)\n' +
    '"2015-03-10 08:24:19.884652" r2d2 68.12.104.178 38084 68.12.99.2 53 UDP DNS peer.pickeklosarske.ru "palevo (malware)" (static)\n' +
    '"2015-03-10 08:24:25.691086" r2d2 68.12.104.178 39716 68.12.99.2 53 UDP DNS (ns35.vpsturk).tk "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:24:25.691085" r2d2 68.12.104.178 39716 68.12.99.2 53 UDP DNS (ns35.vpsturk).tk "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:24:25.691121" r2d2 68.12.104.178 55579 68.12.99.2 53 UDP DNS (ns38.vpsturk).tk "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:24:25.691119" r2d2 68.12.104.178 55579 68.12.99.2 53 UDP DNS (ns38.vpsturk).tk "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:24:31.848588" r2d2 68.12.104.178 36067 68.12.99.2 53 UDP DNS (megascor).no-ip.biz "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 08:24:31.848600" r2d2 68.12.104.178 36067 68.12.99.2 53 UDP DNS (megascor).no-ip.biz "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 08:24:42.591395" r2d2 68.12.104.178 39056 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 08:24:42.591397" r2d2 68.12.104.178 39056 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 08:24:42.866812" r2d2 68.12.104.178 46958 68.12.99.2 53 UDP DNS promisex.ru "zeus (malware)" (custom)\n' +
    '"2015-03-10 08:24:42.867079" r2d2 68.12.104.178 46958 68.12.99.2 53 UDP DNS promisex.ru "zeus (malware)" (custom)\n' +
    '"2015-03-10 08:24:44.775298" r2d2 68.12.104.178 44239 68.12.99.2 53 UDP DNS cnr.edu "pushdo (malware)" (static)\n' +
    '"2015-03-10 08:24:44.775296" r2d2 68.12.104.178 44239 68.12.99.2 53 UDP DNS cnr.edu "pushdo (malware)" (static)\n' +
    '"2015-03-10 08:24:46.084869" r2d2 68.12.104.178 44289 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 08:24:46.084871" r2d2 68.12.104.178 44289 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 08:25:03.950605" r2d2 68.12.104.178 42882 113.108.80.138 53 UDP IP 113.108.80.138 dnspod (custom)\n' +
    '"2015-03-10 08:25:03.950608" r2d2 68.12.104.178 42882 113.108.80.138 53 UDP IP 113.108.80.138 dnspod (custom)\n' +
    '"2015-03-10 08:25:05.902030" r2d2 68.12.104.178 53650 68.12.99.2 53 UDP DNS (tracker.coppersurfer).tk "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:25:05.902040" r2d2 68.12.104.178 53650 68.12.99.2 53 UDP DNS (tracker.coppersurfer).tk "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:25:06.494055" r2d2 68.12.104.178 42175 68.12.99.2 53 UDP DNS (olle67).ddns.net "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 08:25:06.494053" r2d2 68.12.104.178 42175 68.12.99.2 53 UDP DNS (olle67).ddns.net "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 08:25:13.425806" r2d2 68.12.104.178 44156 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 08:25:13.425795" r2d2 68.12.104.178 44156 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 08:25:16.119263" r2d2 68.12.104.178 49979 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 08:25:16.119252" r2d2 68.12.104.178 49979 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 08:25:34.953140" r2d2 68.12.104.178 44610 68.12.99.2 53 UDP DNS (rl).ammyy.com malware malwarepatrol.net\n' +
    '"2015-03-10 08:25:34.953145" r2d2 68.12.104.178 44610 68.12.99.2 53 UDP DNS (rl).ammyy.com malware malwarepatrol.net\n' +
    '"2015-03-10 08:25:44.514351" r2d2 68.12.104.178 45942 68.12.99.2 53 UDP DNS (ns2.pa.gbnet).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:25:44.514751" r2d2 68.12.104.178 43739 68.12.99.2 53 UDP DNS (ns2.pa.gbnet).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:25:44.514727" r2d2 68.12.104.178 45942 68.12.99.2 53 UDP DNS (ns2.pa.gbnet).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:25:44.514755" r2d2 68.12.104.178 43739 68.12.99.2 53 UDP DNS (ns2.pa.gbnet).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:25:44.518712" r2d2 68.12.104.178 41704 68.12.99.2 53 UDP DNS (ns.pa.gbnet).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:25:44.518710" r2d2 68.12.104.178 41704 68.12.99.2 53 UDP DNS (ns.pa.gbnet).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:25:47.211555" r2d2 68.12.104.178 44725 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 08:25:47.211556" r2d2 68.12.104.178 44725 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 08:25:49.852494" r2d2 68.12.104.178 51603 68.12.99.2 53 UDP DNS (megascor).no-ip.biz "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 08:25:49.852496" r2d2 68.12.104.178 51603 68.12.99.2 53 UDP DNS (megascor).no-ip.biz "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 08:25:50.386833" r2d2 68.12.104.178 43854 68.12.99.2 53 UDP DNS (schengenvisa).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:25:50.386841" r2d2 68.12.104.178 43854 68.12.99.2 53 UDP DNS (schengenvisa).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:26:02.628625" r2d2 68.12.104.178 36447 113.108.80.138 53 UDP IP 113.108.80.138 dnspod (custom)\n' +
    '"2015-03-10 08:26:02.628623" r2d2 68.12.104.178 36447 113.108.80.138 53 UDP IP 113.108.80.138 dnspod (custom)\n' +
    '"2015-03-10 08:26:15.020626" r2d2 68.12.104.178 47742 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 08:26:15.020623" r2d2 68.12.104.178 47742 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 08:26:17.830689" r2d2 68.12.104.178 40716 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 08:26:17.830692" r2d2 68.12.104.178 40716 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 08:26:25.838130" r2d2 68.12.104.178 46023 113.108.80.138 53 UDP IP 113.108.80.138 dnspod (custom)\n' +
    '"2015-03-10 08:26:25.838133" r2d2 68.12.104.178 46023 113.108.80.138 53 UDP IP 113.108.80.138 dnspod (custom)\n' +
    '"2015-03-10 08:26:40.945487" r2d2 68.12.104.178 37634 68.12.99.2 53 UDP DNS peer.pickeklosarske.ru "palevo (malware)" (static)\n' +
    '"2015-03-10 08:26:40.945481" r2d2 68.12.104.178 37634 68.12.99.2 53 UDP DNS peer.pickeklosarske.ru "palevo (malware)" (static)\n' +
    '"2015-03-10 08:26:44.076478" r2d2 68.12.104.178 43161 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 08:26:44.076479" r2d2 68.12.104.178 43161 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 08:26:45.850358" r2d2 68.12.104.178 46291 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 08:26:45.850369" r2d2 68.12.104.178 46291 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 08:26:46.829468" r2d2 68.12.104.178 46678 68.12.99.2 53 UDP DNS (forsyth).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:26:46.829479" r2d2 68.12.104.178 46678 68.12.99.2 53 UDP DNS (forsyth).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:26:55.029413" r2d2 68.12.104.178 57403 113.108.80.138 53 UDP IP 113.108.80.138 dnspod (custom)\n' +
    '"2015-03-10 08:26:55.029416" r2d2 68.12.104.178 57403 113.108.80.138 53 UDP IP 113.108.80.138 dnspod (custom)\n' +
    '"2015-03-10 08:27:01.773730" r2d2 68.12.104.178 58355 68.12.99.2 53 UDP DNS (megascor).no-ip.biz "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 08:27:01.773728" r2d2 68.12.104.178 58355 68.12.99.2 53 UDP DNS (megascor).no-ip.biz "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 08:27:13.495405" r2d2 68.12.104.178 35630 68.12.99.2 53 UDP DNS (changeinc).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:27:13.495417" r2d2 68.12.104.178 35630 68.12.99.2 53 UDP DNS (changeinc).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:27:18.943215" r2d2 68.12.104.178 46436 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 08:27:18.943212" r2d2 68.12.104.178 46436 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 08:27:37.225517" r2d2 68.12.104.178 38553 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 08:27:37.225518" r2d2 68.12.104.178 38553 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 08:27:47.237855" r2d2 68.12.104.178 42593 198.58.92.228 53 UDP IP 198.58.92.228 malware cybercrime-tracker.net\n' +
    '"2015-03-10 08:27:47.237858" r2d2 68.12.104.178 42593 198.58.92.228 53 UDP IP 198.58.92.228 malware cybercrime-tracker.net\n' +
    '"2015-03-10 08:27:47.443995" r2d2 68.12.104.178 46441 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 08:27:47.443993" r2d2 68.12.104.178 46441 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 08:27:47.550839" r2d2 68.12.104.178 36377 198.58.92.228 53 UDP IP 198.58.92.228 malware cybercrime-tracker.net\n' +
    '"2015-03-10 08:27:47.550875" r2d2 68.12.104.178 36377 198.58.92.228 53 UDP IP 198.58.92.228 malware cybercrime-tracker.net\n' +
    '"2015-03-10 08:27:49.771034" r2d2 68.12.104.178 59975 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 08:27:49.771042" r2d2 68.12.104.178 59975 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 08:28:18.268923" r2d2 68.12.104.178 42312 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 08:28:18.268953" r2d2 68.12.104.178 42312 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 08:28:18.778857" r2d2 68.12.104.178 39403 68.12.99.2 53 UDP DNS (megascor).no-ip.biz "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 08:28:18.778856" r2d2 68.12.104.178 39403 68.12.99.2 53 UDP DNS (megascor).no-ip.biz "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 08:28:37.140685" r2d2 68.12.104.178 53780 68.12.99.2 53 UDP DNS digitalmind.cn "palevo (malware)" palevotracker.abuse.ch\n' +
    '"2015-03-10 08:28:37.140686" r2d2 68.12.104.178 53780 68.12.99.2 53 UDP DNS digitalmind.cn "palevo (malware)" palevotracker.abuse.ch\n' +
    '"2015-03-10 08:28:38.201747" r2d2 68.12.104.178 45572 68.12.99.2 53 UDP DNS www.findamo.com malware malwarepatrol.net\n' +
    '"2015-03-10 08:28:38.201746" r2d2 68.12.104.178 45572 68.12.99.2 53 UDP DNS www.findamo.com malware malwarepatrol.net\n' +
    '"2015-03-10 08:28:40.453018" r2d2 68.12.104.178 50512 217.168.153.11 53 UDP IP 217.168.153.11 abuser openbl.org\n' +
    '"2015-03-10 08:28:40.453017" r2d2 68.12.104.178 50512 217.168.153.11 53 UDP IP 217.168.153.11 abuser openbl.org\n' +
    '"2015-03-10 08:28:43.243105" r2d2 68.12.104.178 37853 113.108.80.138 53 UDP IP 113.108.80.138 dnspod (custom)\n' +
    '"2015-03-10 08:28:43.243083" r2d2 68.12.104.178 37853 113.108.80.138 53 UDP IP 113.108.80.138 dnspod (custom)\n' +
    '"2015-03-10 08:28:44.098881" r2d2 68.12.104.178 35878 113.108.80.138 53 UDP IP 113.108.80.138 dnspod (custom)\n' +
    '"2015-03-10 08:28:44.098883" r2d2 68.12.104.178 35878 113.108.80.138 53 UDP IP 113.108.80.138 dnspod (custom)\n' +
    '"2015-03-10 08:28:46.162035" r2d2 68.12.104.178 52970 68.12.99.2 53 UDP DNS (static7).superfish.com superfish (static)\n' +
    '"2015-03-10 08:28:46.162032" r2d2 68.12.104.178 52970 68.12.99.2 53 UDP DNS (static7).superfish.com superfish (static)\n' +
    '"2015-03-10 08:28:46.167297" r2d2 68.12.104.178 56386 68.12.99.2 53 UDP DNS (static8).superfish.com superfish (static)\n' +
    '"2015-03-10 08:28:46.167339" r2d2 68.12.104.178 56386 68.12.99.2 53 UDP DNS (static8).superfish.com superfish (static)\n' +
    '"2015-03-10 08:28:46.173204" r2d2 68.12.104.178 53844 68.12.99.2 53 UDP DNS (static9).superfish.com superfish (static)\n' +
    '"2015-03-10 08:28:46.173206" r2d2 68.12.104.178 53844 68.12.99.2 53 UDP DNS (static9).superfish.com superfish (static)\n' +
    '"2015-03-10 08:28:46.265000" r2d2 68.12.104.178 49252 68.12.99.2 53 UDP DNS (static).superfish.com superfish (static)\n' +
    '"2015-03-10 08:28:46.265005" r2d2 68.12.104.178 49252 68.12.99.2 53 UDP DNS (static).superfish.com superfish (static)\n' +
    '"2015-03-10 08:28:48.412926" r2d2 68.12.104.178 40419 68.12.99.2 53 UDP DNS (ontika).ignorelist.com "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:28:48.412960" r2d2 68.12.104.178 40419 68.12.99.2 53 UDP DNS (ontika).ignorelist.com "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:28:51.385870" r2d2 68.12.104.178 48279 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 08:28:51.386113" r2d2 68.12.104.178 48279 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 08:28:55.030647" r2d2 68.12.104.178 57355 8.8.8.8 53 UDP DNS (ontika).ignorelist.com "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:28:55.030654" r2d2 68.12.104.178 57355 8.8.8.8 53 UDP DNS (ontika).ignorelist.com "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:29:01.725665" r2d2 68.12.104.178 44190 68.12.99.2 53 UDP DNS peer.pickeklosarske.ru "palevo (malware)" (static)\n' +
    '"2015-03-10 08:29:01.725666" r2d2 68.12.104.178 44190 68.12.99.2 53 UDP DNS peer.pickeklosarske.ru "palevo (malware)" (static)\n' +
    '"2015-03-10 08:29:04.092945" r2d2 68.12.104.178 46627 113.108.80.138 53 UDP IP 113.108.80.138 dnspod (custom)\n' +
    '"2015-03-10 08:29:04.092941" r2d2 68.12.104.178 46627 113.108.80.138 53 UDP IP 113.108.80.138 dnspod (custom)\n' +
    '"2015-03-10 08:29:05.528010" r2d2 68.12.104.178 59995 68.12.99.2 53 UDP DNS (stjpaetzold).no-ip.org "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 08:29:05.528009" r2d2 68.12.104.178 59995 68.12.99.2 53 UDP DNS (stjpaetzold).no-ip.org "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 08:29:12.554733" r2d2 68.12.104.178 43559 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 08:29:12.554759" r2d2 68.12.104.178 43559 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 08:29:18.921280" r2d2 68.12.104.178 39269 68.12.99.2 53 UDP DNS (brightlounge).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:29:18.921277" r2d2 68.12.104.178 39269 68.12.99.2 53 UDP DNS (brightlounge).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:29:19.885519" r2d2 68.12.104.178 43085 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 08:29:19.885516" r2d2 68.12.104.178 43085 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 08:29:23.212688" r2d2 68.12.104.178 56187 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 08:29:23.212704" r2d2 68.12.104.178 56187 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 08:29:25.031149" r2d2 68.12.104.178 57355 8.8.8.8 53 UDP DNS (brightlounge).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:29:25.031152" r2d2 68.12.104.178 57355 8.8.8.8 53 UDP DNS (brightlounge).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:29:29.859559" r2d2 68.12.104.178 47937 68.12.99.2 53 UDP DNS teske.pornicarke.com "palevo (malware)" (static)\n' +
    '"2015-03-10 08:29:29.859557" r2d2 68.12.104.178 47937 68.12.99.2 53 UDP DNS teske.pornicarke.com "palevo (malware)" (static)\n' +
    '"2015-03-10 08:29:30.910845" r2d2 68.12.104.178 44113 68.12.99.2 53 UDP DNS (mx.cloudafrica).email "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:29:30.910848" r2d2 68.12.104.178 44113 68.12.99.2 53 UDP DNS (mx.cloudafrica).email "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:29:30.943390" r2d2 68.12.104.178 56303 68.12.99.2 53 UDP DNS (mx01.cloudafrica).email "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:29:30.943391" r2d2 68.12.104.178 56303 68.12.99.2 53 UDP DNS (mx01.cloudafrica).email "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:29:35.883885" r2d2 68.12.104.178 54263 68.12.99.2 53 UDP DNS (mxdk01.spamfilter).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:29:35.883883" r2d2 68.12.104.178 54263 68.12.99.2 53 UDP DNS (mxdk01.spamfilter).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:29:41.819219" r2d2 68.12.104.178 50329 68.12.99.2 53 UDP DNS (megascor).no-ip.biz "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 08:29:41.819221" r2d2 68.12.104.178 50329 68.12.99.2 53 UDP DNS (megascor).no-ip.biz "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 08:29:47.344652" r2d2 68.12.104.178 48575 173.255.206.17 53 UDP IP 173.255.206.17 c&c emergingthreats.net\n' +
    '"2015-03-10 08:29:47.344651" r2d2 68.12.104.178 48575 173.255.206.17 53 UDP IP 173.255.206.17 c&c emergingthreats.net\n' +
    '"2015-03-10 08:29:48.342584" r2d2 68.12.104.178 35145 113.108.80.138 53 UDP IP 113.108.80.138 dnspod (custom)\n' +
    '"2015-03-10 08:29:48.342589" r2d2 68.12.104.178 35145 113.108.80.138 53 UDP IP 113.108.80.138 dnspod (custom)\n' +
    '"2015-03-10 08:29:48.705511" r2d2 68.12.104.178 43172 68.12.99.2 53 UDP DNS (6y).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:29:48.705509" r2d2 68.12.104.178 43172 68.12.99.2 53 UDP DNS (6y).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:29:50.734978" r2d2 68.12.104.178 58441 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 08:29:50.734983" r2d2 68.12.104.178 58441 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 08:29:58.131503" r2d2 68.12.104.178 40004 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 08:29:58.131501" r2d2 68.12.104.178 40004 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 08:30:02.170561" r2d2 68.12.104.178 45582 68.12.99.2 53 UDP DNS promisex.ru "zeus (malware)" (custom)\n' +
    '"2015-03-10 08:30:02.170590" r2d2 68.12.104.178 45582 68.12.99.2 53 UDP DNS promisex.ru "zeus (malware)" (custom)\n' +
    '"2015-03-10 08:30:04.372589" r2d2 68.12.104.178 45974 68.12.99.2 53 UDP DNS (ns2.dorn).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:30:04.372105" r2d2 68.12.104.178 54865 68.12.99.2 53 UDP DNS (ns1.dorn).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:30:04.372104" r2d2 68.12.104.178 54865 68.12.99.2 53 UDP DNS (ns1.dorn).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:30:04.372592" r2d2 68.12.104.178 45974 68.12.99.2 53 UDP DNS (ns2.dorn).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:30:07.386922" r2d2 68.12.104.178 41197 113.108.80.138 53 UDP IP 113.108.80.138 dnspod (custom)\n' +
    '"2015-03-10 08:30:07.386920" r2d2 68.12.104.178 41197 113.108.80.138 53 UDP IP 113.108.80.138 dnspod (custom)\n' +
    '"2015-03-10 08:30:15.458909" r2d2 68.12.104.178 43527 113.108.80.138 53 UDP IP 113.108.80.138 dnspod (custom)\n' +
    '"2015-03-10 08:30:15.458910" r2d2 68.12.104.178 43527 113.108.80.138 53 UDP IP 113.108.80.138 dnspod (custom)\n' +
    '"2015-03-10 08:30:24.819183" r2d2 68.12.104.178 59485 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 08:30:38.425713" r2d2 68.12.104.178 40043 113.108.80.138 53 UDP IP 113.108.80.138 dnspod (custom)\n' +
    '"2015-03-10 08:30:38.426720" r2d2 68.12.104.178 38349 113.108.80.138 53 UDP IP 113.108.80.138 dnspod (custom)\n' +
    '"2015-03-10 08:30:38.425712" r2d2 68.12.104.178 40043 113.108.80.138 53 UDP IP 113.108.80.138 dnspod (custom)\n' +
    '"2015-03-10 08:30:38.426724" r2d2 68.12.104.178 38349 113.108.80.138 53 UDP IP 113.108.80.138 dnspod (custom)\n' +
    '"2015-03-10 08:30:54.702649" r2d2 68.12.104.178 43600 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 08:30:54.702645" r2d2 68.12.104.178 43600 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 08:30:55.646021" r2d2 68.12.104.178 43290 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 08:30:55.646019" r2d2 68.12.104.178 43290 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 08:31:04.885963" r2d2 68.12.104.178 56160 68.12.99.2 53 UDP DNS (megascor).no-ip.biz "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 08:31:04.885967" r2d2 68.12.104.178 56160 68.12.99.2 53 UDP DNS (megascor).no-ip.biz "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 08:31:05.902298" r2d2 68.12.104.178 47800 68.12.99.2 53 UDP DNS (tracker.coppersurfer).tk "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:31:07.690340" r2d2 68.12.104.178 35489 68.12.99.2 53 UDP DNS hsbc.ca expiro (static)\n' +
    '"2015-03-10 08:31:07.690342" r2d2 68.12.104.178 35489 68.12.99.2 53 UDP DNS hsbc.ca expiro (static)\n' +
    '"2015-03-10 08:31:22.740275" r2d2 68.12.104.178 47440 68.12.99.2 53 UDP DNS peer.pickeklosarske.ru "palevo (malware)" (static)\n' +
    '"2015-03-10 08:31:22.740273" r2d2 68.12.104.178 47440 68.12.99.2 53 UDP DNS peer.pickeklosarske.ru "palevo (malware)" (static)\n' +
    '"2015-03-10 08:31:25.535018" r2d2 68.12.104.178 41995 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 08:31:25.535019" r2d2 68.12.104.178 41995 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 08:31:36.170238" r2d2 68.12.104.178 46981 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 08:31:36.170235" r2d2 68.12.104.178 46981 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 08:31:44.881608" r2d2 68.12.104.178 50256 74.81.79.3 53 UDP IP 74.81.79.3 attacker blocklist.de\n' +
    '"2015-03-10 08:31:44.881609" r2d2 68.12.104.178 50256 74.81.79.3 53 UDP IP 74.81.79.3 attacker blocklist.de\n' +
    '"2015-03-10 08:31:44.884161" r2d2 68.12.104.178 43746 74.81.79.3 53 UDP IP 74.81.79.3 attacker blocklist.de\n' +
    '"2015-03-10 08:31:44.884163" r2d2 68.12.104.178 37953 74.81.79.3 53 UDP IP 74.81.79.3 attacker blocklist.de\n' +
    '"2015-03-10 08:31:44.884162" r2d2 68.12.104.178 37953 74.81.79.3 53 UDP IP 74.81.79.3 attacker blocklist.de\n' +
    '"2015-03-10 08:31:46.647432" r2d2 68.12.104.178 46596 68.12.99.2 53 UDP DNS (rac).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:31:46.647433" r2d2 68.12.104.178 46596 68.12.99.2 53 UDP DNS (rac).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:31:47.094861" r2d2 68.12.104.178 47349 68.12.99.2 53 UDP DNS (happypeople).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:31:47.094864" r2d2 68.12.104.178 47349 68.12.99.2 53 UDP DNS (happypeople).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:31:48.766993" r2d2 68.12.104.178 53847 68.12.99.2 53 UDP DNS (emka3.vv).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:31:48.766996" r2d2 68.12.104.178 53847 68.12.99.2 53 UDP DNS (emka3.vv).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:31:55.034286" r2d2 68.12.104.178 57355 8.8.8.8 53 UDP DNS (emka3.vv).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:31:55.034284" r2d2 68.12.104.178 57355 8.8.8.8 53 UDP DNS (emka3.vv).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:31:57.154624" r2d2 68.12.104.178 42561 122.155.18.80 53 UDP IP 122.155.18.80 "ssh brute force" autoshun.org\n' +
    '"2015-03-10 08:31:57.154623" r2d2 68.12.104.178 42561 122.155.18.80 53 UDP IP 122.155.18.80 "ssh brute force" autoshun.org\n' +
    '"2015-03-10 08:31:57.256774" r2d2 68.12.104.178 38127 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 08:31:57.256776" r2d2 68.12.104.178 38127 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 08:31:57.382438" r2d2 68.12.104.178 43005 8.8.4.4 53 UDP DNS (emka3.vv).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:31:57.382429" r2d2 68.12.104.178 43005 8.8.4.4 53 UDP DNS (emka3.vv).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:31:59.693687" r2d2 68.12.104.178 46601 68.12.99.2 53 UDP DNS crazyerror.su malicious www.virustotal.com\n' +
    '"2015-03-10 08:31:59.693686" r2d2 68.12.104.178 46601 68.12.99.2 53 UDP DNS crazyerror.su malicious www.virustotal.com\n' +
    '"2015-03-10 08:32:00.829778" r2d2 68.12.104.178 42290 68.12.99.2 53 UDP DNS (lux.steurer).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:32:00.829143" r2d2 68.12.104.178 41706 68.12.99.2 53 UDP DNS (fux.steurer).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:32:00.829141" r2d2 68.12.104.178 41706 68.12.99.2 53 UDP DNS (fux.steurer).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:32:00.829788" r2d2 68.12.104.178 42290 68.12.99.2 53 UDP DNS (lux.steurer).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:32:02.033876" r2d2 68.12.104.178 57355 8.8.8.8 53 UDP DNS (emka3.vv).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:32:02.033878" r2d2 68.12.104.178 57355 8.8.8.8 53 UDP DNS (emka3.vv).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:32:05.065982" r2d2 68.12.104.178 43005 8.8.4.4 53 UDP DNS (emka3.vv).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:32:05.065986" r2d2 68.12.104.178 43005 8.8.4.4 53 UDP DNS (emka3.vv).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:32:18.124197" r2d2 68.12.104.178 41848 68.12.99.2 53 UDP DNS (a5).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:32:18.124198" r2d2 68.12.104.178 41848 68.12.99.2 53 UDP DNS (a5).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:32:19.052855" r2d2 68.12.104.178 37680 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 08:32:19.052852" r2d2 68.12.104.178 37680 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 08:32:27.155074" r2d2 68.12.104.178 45796 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 08:32:27.155075" r2d2 68.12.104.178 45796 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 08:32:28.083788" r2d2 68.12.104.178 41869 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 08:32:28.083785" r2d2 68.12.104.178 41869 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 08:32:40.204030" r2d2 68.12.104.178 35772 68.12.99.2 53 UDP DNS (clerkofcourts).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:32:40.204033" r2d2 68.12.104.178 35772 68.12.99.2 53 UDP DNS (clerkofcourts).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:32:44.543695" r2d2 68.12.104.178 58316 68.12.99.2 53 UDP DNS (wavefront).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:32:44.543697" r2d2 68.12.104.178 58316 68.12.99.2 53 UDP DNS (wavefront).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:32:47.261333" r2d2 68.12.104.178 41581 68.12.99.2 53 UDP DNS (dns4).wanadoo.es attackpage safebrowsing.clients.google.com\n' +
    '"2015-03-10 08:32:47.261331" r2d2 68.12.104.178 38168 68.12.99.2 53 UDP DNS (dns3).wanadoo.es attackpage safebrowsing.clients.google.com\n' +
    '"2015-03-10 08:32:47.261330" r2d2 68.12.104.178 38168 68.12.99.2 53 UDP DNS (dns3).wanadoo.es attackpage safebrowsing.clients.google.com\n' +
    '"2015-03-10 08:32:47.567891" r2d2 68.12.104.178 56528 68.12.99.2 53 UDP DNS (inc).wanadoo.es attackpage safebrowsing.clients.google.com\n' +
    '"2015-03-10 08:32:47.567889" r2d2 68.12.104.178 56528 68.12.99.2 53 UDP DNS (inc).wanadoo.es attackpage safebrowsing.clients.google.com\n' +
    '"2015-03-10 08:32:52.070508" r2d2 68.12.104.178 57857 68.12.99.2 53 UDP DNS (stockbridge).ddns.net "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 08:32:52.070506" r2d2 68.12.104.178 57857 68.12.99.2 53 UDP DNS (stockbridge).ddns.net "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 08:32:54.910728" r2d2 68.12.104.178 55888 194.71.224.39 53 UDP IP 194.71.224.39 attacker blocklist.de\n' +
    '"2015-03-10 08:32:54.910725" r2d2 68.12.104.178 55888 194.71.224.39 53 UDP IP 194.71.224.39 attacker blocklist.de\n' +
    '"2015-03-10 08:32:57.963214" r2d2 68.12.104.178 46676 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 08:32:57.963221" r2d2 68.12.104.178 46676 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 08:33:09.179556" r2d2 68.12.104.178 48921 68.12.99.2 53 UDP DNS 4java.ca malware cybercrime-tracker.net\n' +
    '"2015-03-10 08:33:09.179559" r2d2 68.12.104.178 48921 68.12.99.2 53 UDP DNS 4java.ca malware cybercrime-tracker.net\n' +
    '"2015-03-10 08:33:09.269542" r2d2 68.12.104.178 59646 68.12.99.2 53 UDP DNS (acegroup).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:33:09.269538" r2d2 68.12.104.178 59646 68.12.99.2 53 UDP DNS (acegroup).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:33:09.786634" r2d2 68.12.104.178 42840 68.12.99.2 53 UDP DNS (megascor).no-ip.biz "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 08:33:09.786654" r2d2 68.12.104.178 42840 68.12.99.2 53 UDP DNS (megascor).no-ip.biz "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 08:33:21.477604" r2d2 68.12.104.178 43598 68.12.99.2 53 UDP DNS (ns1).torpig-sinkhole.org "torpig (malware)" (static)\n' +
    '"2015-03-10 08:33:21.477931" r2d2 68.12.104.178 56299 68.12.99.2 53 UDP DNS (ns1).torpig-sinkhole.org "torpig (malware)" (static)\n' +
    '"2015-03-10 08:33:21.477926" r2d2 68.12.104.178 56299 68.12.99.2 53 UDP DNS (ns1).torpig-sinkhole.org "torpig (malware)" (static)\n' +
    '"2015-03-10 08:33:21.477938" r2d2 68.12.104.178 47337 68.12.99.2 53 UDP DNS (ns2).torpig-sinkhole.org "torpig (malware)" (static)\n' +
    '"2015-03-10 08:33:21.477603" r2d2 68.12.104.178 43598 68.12.99.2 53 UDP DNS (ns1).torpig-sinkhole.org "torpig (malware)" (static)\n' +
    '"2015-03-10 08:33:21.478366" r2d2 68.12.104.178 59666 68.12.99.2 53 UDP DNS (ns2).torpig-sinkhole.org "torpig (malware)" (static)\n' +
    '"2015-03-10 08:33:21.478363" r2d2 68.12.104.178 59666 68.12.99.2 53 UDP DNS (ns2).torpig-sinkhole.org "torpig (malware)" (static)\n' +
    '"2015-03-10 08:33:21.477940" r2d2 68.12.104.178 47337 68.12.99.2 53 UDP DNS (ns2).torpig-sinkhole.org "torpig (malware)" (static)\n' +
    '"2015-03-10 08:33:21.526052" r2d2 68.12.104.178 56278 87.106.240.162 53 UDP IP 87.106.240.162 "torpig (malware)" (static)\n' +
    '"2015-03-10 08:33:21.526042" r2d2 68.12.104.178 56278 87.106.240.162 53 UDP IP 87.106.240.162 "torpig (malware)" (static)\n' +
    '"2015-03-10 08:33:21.552011" r2d2 68.12.104.178 51094 212.227.55.84 53 UDP IP 212.227.55.84 "torpig (malware)" (static)\n' +
    '"2015-03-10 08:33:21.552135" r2d2 68.12.104.178 36772 212.227.55.84 53 UDP IP 212.227.55.84 "torpig (malware)" (static)\n' +
    '"2015-03-10 08:33:21.552013" r2d2 68.12.104.178 51094 212.227.55.84 53 UDP IP 212.227.55.84 "torpig (malware)" (static)\n' +
    '"2015-03-10 08:33:21.552137" r2d2 68.12.104.178 36772 212.227.55.84 53 UDP IP 212.227.55.84 "torpig (malware)" (static)\n' +
    '"2015-03-10 08:33:21.580816" r2d2 68.12.104.178 52140 87.106.240.162 53 UDP IP 87.106.240.162 "torpig (malware)" (static)\n' +
    '"2015-03-10 08:33:21.580824" r2d2 68.12.104.178 52140 87.106.240.162 53 UDP IP 87.106.240.162 "torpig (malware)" (static)\n' +
    '"2015-03-10 08:33:21.893432" r2d2 68.12.104.178 38248 68.12.99.2 53 UDP DNS (percussion).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:33:21.893422" r2d2 68.12.104.178 38248 68.12.99.2 53 UDP DNS (percussion).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:33:23.520039" r2d2 68.12.104.178 41884 87.106.240.162 53 UDP IP 87.106.240.162 "torpig (malware)" (static)\n' +
    '"2015-03-10 08:33:23.520037" r2d2 68.12.104.178 41884 87.106.240.162 53 UDP IP 87.106.240.162 "torpig (malware)" (static)\n' +
    '"2015-03-10 08:33:23.924234" r2d2 68.12.104.178 38515 68.12.99.2 53 UDP DNS (tsn).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:33:23.924236" r2d2 68.12.104.178 38515 68.12.99.2 53 UDP DNS (tsn).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:33:28.686080" r2d2 68.12.104.178 36849 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 08:33:28.686078" r2d2 68.12.104.178 36849 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 08:33:43.443341" r2d2 68.12.104.178 57950 68.12.99.2 53 UDP DNS peer.pickeklosarske.ru "palevo (malware)" (static)\n' +
    '"2015-03-10 08:33:43.443343" r2d2 68.12.104.178 57950 68.12.99.2 53 UDP DNS peer.pickeklosarske.ru "palevo (malware)" (static)\n' +
    '"2015-03-10 08:33:59.029139" r2d2 68.12.104.178 35044 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 08:33:59.029141" r2d2 68.12.104.178 35044 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 08:33:59.755700" r2d2 68.12.104.178 44373 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 08:33:59.755698" r2d2 68.12.104.178 44373 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 08:34:05.753283" r2d2 68.12.104.178 35578 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 08:34:05.753284" r2d2 68.12.104.178 35578 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 08:34:14.161129" r2d2 68.12.104.178 56158 68.12.99.2 53 UDP DNS (www).browsestudio.com malware malwareurls.joxeankoret.com\n' +
    '"2015-03-10 08:34:14.161126" r2d2 68.12.104.178 56158 68.12.99.2 53 UDP DNS (www).browsestudio.com malware malwareurls.joxeankoret.com\n' +
    '"2015-03-10 08:34:14.190920" r2d2 68.12.104.178 40748 68.12.99.2 53 UDP DNS browsestudio.com malware malwareurls.joxeankoret.com\n' +
    '"2015-03-10 08:34:14.190921" r2d2 68.12.104.178 40748 68.12.99.2 53 UDP DNS browsestudio.com malware malwareurls.joxeankoret.com\n' +
    '"2015-03-10 08:34:26.101797" r2d2 68.12.104.178 38420 68.12.99.2 53 UDP DNS (fondis).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:34:26.101799" r2d2 68.12.104.178 38420 68.12.99.2 53 UDP DNS (fondis).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:34:31.975181" r2d2 68.12.104.178 42426 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 08:34:31.975182" r2d2 68.12.104.178 42426 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 08:34:32.027731" r2d2 68.12.104.178 45416 68.12.99.2 53 UDP DNS (de).publicvm.com "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 08:34:32.027721" r2d2 68.12.104.178 45416 68.12.99.2 53 UDP DNS (de).publicvm.com "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 08:34:41.805389" r2d2 68.12.104.178 47289 68.12.99.2 53 UDP DNS (lessing.clusters).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:34:41.806032" r2d2 68.12.104.178 55099 68.12.99.2 53 UDP DNS (aristoteles.clusters).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:34:41.805387" r2d2 68.12.104.178 47289 68.12.99.2 53 UDP DNS (lessing.clusters).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:34:41.806030" r2d2 68.12.104.178 55099 68.12.99.2 53 UDP DNS (aristoteles.clusters).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:34:41.836808" r2d2 68.12.104.178 53894 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 08:34:41.836805" r2d2 68.12.104.178 53894 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 08:34:46.329169" r2d2 68.12.104.178 38504 68.12.99.2 53 UDP DNS digitalmind.cn "palevo (malware)" palevotracker.abuse.ch\n' +
    '"2015-03-10 08:34:46.329172" r2d2 68.12.104.178 38504 68.12.99.2 53 UDP DNS digitalmind.cn "palevo (malware)" palevotracker.abuse.ch\n' +
    '"2015-03-10 08:34:58.749765" r2d2 68.12.104.178 50444 68.12.99.2 53 UDP DNS (efilter.sysone).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:34:58.749764" r2d2 68.12.104.178 50444 68.12.99.2 53 UDP DNS (efilter.sysone).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:35:01.811980" r2d2 68.12.104.178 46585 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 08:35:01.811981" r2d2 68.12.104.178 46585 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 08:35:06.260144" r2d2 68.12.104.178 55423 68.12.99.2 53 UDP DNS (ontika).ignorelist.com "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:35:06.260145" r2d2 68.12.104.178 55423 68.12.99.2 53 UDP DNS (ontika).ignorelist.com "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:35:07.387317" r2d2 68.12.104.178 54964 68.12.99.2 53 UDP DNS (megascor).no-ip.biz "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 08:35:07.387312" r2d2 68.12.104.178 54964 68.12.99.2 53 UDP DNS (megascor).no-ip.biz "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 08:35:25.341438" r2d2 68.12.104.178 49126 113.108.80.138 53 UDP IP 113.108.80.138 dnspod (custom)\n' +
    '"2015-03-10 08:35:25.341435" r2d2 68.12.104.178 49126 113.108.80.138 53 UDP IP 113.108.80.138 dnspod (custom)\n' +
    '"2015-03-10 08:35:25.955185" r2d2 68.12.104.178 52388 68.12.99.2 53 UDP DNS promisex.ru "zeus (malware)" (custom)\n' +
    '"2015-03-10 08:35:25.955178" r2d2 68.12.104.178 52388 68.12.99.2 53 UDP DNS promisex.ru "zeus (malware)" (custom)\n' +
    '"2015-03-10 08:35:32.216451" r2d2 68.12.104.178 48565 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 08:35:32.216448" r2d2 68.12.104.178 48565 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 08:35:33.600193" r2d2 68.12.104.178 47829 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 08:35:33.600192" r2d2 68.12.104.178 47829 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 08:35:48.891246" r2d2 80.82.64.116 52480 68.12.104.178 8080 TCP IP 80.82.64.116 attacker blocklist.de\n' +
    '"2015-03-10 08:35:48.891589" r2d2 80.82.64.116 52480 68.12.104.178 8080 TCP IP 80.82.64.116 attacker blocklist.de\n' +
    '"2015-03-10 08:36:01.212815" r2d2 68.12.104.178 35330 68.12.99.2 53 UDP DNS (st.stattds).club "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:36:01.212816" r2d2 68.12.104.178 35330 68.12.99.2 53 UDP DNS (st.stattds).club "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:36:02.058628" r2d2 68.12.104.178 54720 68.12.99.2 53 UDP DNS (stattds).club "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:36:02.058642" r2d2 68.12.104.178 54720 68.12.99.2 53 UDP DNS (stattds).club "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:36:04.031878" r2d2 68.12.104.178 40705 68.12.99.2 53 UDP DNS (tracker.coppersurfer).tk "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:36:04.031876" r2d2 68.12.104.178 40705 68.12.99.2 53 UDP DNS (tracker.coppersurfer).tk "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:36:04.408778" r2d2 68.12.104.178 56313 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 08:36:04.408780" r2d2 68.12.104.178 56313 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 08:36:05.921268" r2d2 68.12.104.178 35394 68.12.99.2 53 UDP DNS (tracker.coppersurfer).tk "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:36:05.921272" r2d2 68.12.104.178 35394 68.12.99.2 53 UDP DNS (tracker.coppersurfer).tk "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:36:11.867521" r2d2 68.12.104.178 47349 68.12.99.2 53 UDP DNS peer.pickeklosarske.ru "palevo (malware)" (static)\n' +
    '"2015-03-10 08:36:11.867522" r2d2 68.12.104.178 47349 68.12.99.2 53 UDP DNS peer.pickeklosarske.ru "palevo (malware)" (static)\n' +
    '"2015-03-10 08:36:23.614579" r2d2 68.12.104.178 46363 113.108.80.138 53 UDP IP 113.108.80.138 dnspod (custom)\n' +
    '"2015-03-10 08:36:23.614578" r2d2 68.12.104.178 46363 113.108.80.138 53 UDP IP 113.108.80.138 dnspod (custom)\n' +
    '"2015-03-10 08:36:24.032102" r2d2 106.240.231.227 6000 68.12.104.178 1433 TCP IP 106.240.231.227 attacker cinsscore.com\n' +
    '"2015-03-10 08:36:24.032100" r2d2 106.240.231.227 6000 68.12.104.178 1433 TCP IP 106.240.231.227 attacker cinsscore.com\n' +
    '"2015-03-10 08:36:30.433133" r2d2 68.12.104.178 40833 68.12.99.2 53 UDP DNS (megascor).no-ip.biz "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 08:36:30.433143" r2d2 68.12.104.178 40833 68.12.99.2 53 UDP DNS (megascor).no-ip.biz "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 08:36:32.993659" r2d2 68.12.104.178 35829 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 08:36:32.993660" r2d2 68.12.104.178 35829 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 08:36:35.152763" r2d2 68.12.104.178 39378 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 08:36:35.152760" r2d2 68.12.104.178 39378 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 08:36:45.699555" r2d2 68.12.104.178 56316 113.108.80.138 53 UDP IP 113.108.80.138 dnspod (custom)\n' +
    '"2015-03-10 08:36:45.699553" r2d2 68.12.104.178 56316 113.108.80.138 53 UDP IP 113.108.80.138 dnspod (custom)\n' +
    '"2015-03-10 08:36:50.182481" r2d2 68.12.104.178 47357 109.201.130.1 53 UDP IP 109.201.130.1 malware cybercrime-tracker.net\n' +
    '"2015-03-10 08:36:50.182483" r2d2 68.12.104.178 47357 109.201.130.1 53 UDP IP 109.201.130.1 malware cybercrime-tracker.net\n' +
    '"2015-03-10 08:36:56.643034" r2d2 68.12.104.178 39659 68.12.99.2 53 UDP DNS (ing).wanadoo.es attackpage safebrowsing.clients.google.com\n' +
    '"2015-03-10 08:36:56.643030" r2d2 68.12.104.178 39659 68.12.99.2 53 UDP DNS (ing).wanadoo.es attackpage safebrowsing.clients.google.com\n' +
    '"2015-03-10 08:37:03.338117" r2d2 68.12.104.178 45886 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 08:37:03.338114" r2d2 68.12.104.178 45886 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 08:37:04.473970" r2d2 68.12.104.178 41912 37.59.0.34 53 UDP IP 37.59.0.34 attacker blocklist.de\n' +
    '"2015-03-10 08:37:04.473960" r2d2 68.12.104.178 41912 37.59.0.34 53 UDP IP 37.59.0.34 attacker blocklist.de\n' +
    '"2015-03-10 08:37:05.987731" r2d2 68.12.104.178 36712 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 08:37:11.140407" r2d2 68.12.104.178 35491 198.58.92.228 53 UDP IP 198.58.92.228 malware cybercrime-tracker.net\n' +
    '"2015-03-10 08:37:11.140405" r2d2 68.12.104.178 35491 198.58.92.228 53 UDP IP 198.58.92.228 malware cybercrime-tracker.net\n' +
    '"2015-03-10 08:37:11.569437" r2d2 68.12.104.178 47653 198.58.92.228 53 UDP IP 198.58.92.228 malware cybercrime-tracker.net\n' +
    '"2015-03-10 08:37:11.569440" r2d2 68.12.104.178 47653 198.58.92.228 53 UDP IP 198.58.92.228 malware cybercrime-tracker.net\n' +
    '"2015-03-10 08:37:11.901042" r2d2 68.12.104.178 42898 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 08:37:11.901056" r2d2 68.12.104.178 42898 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 08:37:12.761429" r2d2 68.12.104.178 37166 198.58.92.228 53 UDP IP 198.58.92.228 malware cybercrime-tracker.net\n' +
    '"2015-03-10 08:37:12.761450" r2d2 68.12.104.178 37166 198.58.92.228 53 UDP IP 198.58.92.228 malware cybercrime-tracker.net\n' +
    '"2015-03-10 08:37:36.766000" r2d2 68.12.104.178 49685 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 08:37:36.766014" r2d2 68.12.104.178 49685 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 08:37:45.385840" r2d2 68.12.104.178 39976 68.12.99.2 53 UDP DNS (the.arrowroot).club "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:37:45.385839" r2d2 68.12.104.178 39976 68.12.99.2 53 UDP DNS (the.arrowroot).club "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:37:48.103201" r2d2 68.12.104.178 40786 68.12.99.2 53 UDP DNS (ns1.xactmail).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:37:48.103191" r2d2 68.12.104.178 40786 68.12.99.2 53 UDP DNS (ns1.xactmail).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:37:48.103316" r2d2 68.12.104.178 39927 68.12.99.2 53 UDP DNS (ns1.xactmail).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:37:48.103310" r2d2 68.12.104.178 39927 68.12.99.2 53 UDP DNS (ns1.xactmail).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:37:48.104155" r2d2 68.12.104.178 44729 68.12.99.2 53 UDP DNS (ns2.xactmail).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:37:48.104160" r2d2 68.12.104.178 37164 68.12.99.2 53 UDP DNS (ns2.xactmail).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:37:48.104153" r2d2 68.12.104.178 44729 68.12.99.2 53 UDP DNS (ns2.xactmail).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:37:48.104161" r2d2 68.12.104.178 37164 68.12.99.2 53 UDP DNS (ns2.xactmail).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:37:48.750931" r2d2 68.12.104.178 58249 68.12.99.2 53 UDP DNS (mail.xactmail).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:37:48.750928" r2d2 68.12.104.178 58249 68.12.99.2 53 UDP DNS (mail.xactmail).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:37:54.442985" r2d2 68.12.104.178 44990 198.58.93.56 53 UDP IP 198.58.93.56 malware cybercrime-tracker.net\n' +
    '"2015-03-10 08:37:54.442989" r2d2 68.12.104.178 44990 198.58.93.56 53 UDP IP 198.58.93.56 malware cybercrime-tracker.net\n' +
    '"2015-03-10 08:37:57.254254" r2d2 68.12.104.178 45213 50.87.144.81 53 UDP IP 50.87.144.81 attacker blocklist.de\n' +
    '"2015-03-10 08:37:57.254272" r2d2 68.12.104.178 45213 50.87.144.81 53 UDP IP 50.87.144.81 attacker blocklist.de\n' +
    '"2015-03-10 08:37:59.951748" r2d2 68.12.104.178 50693 68.12.99.2 53 UDP DNS (techmeology.co).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:37:59.951750" r2d2 68.12.104.178 50693 68.12.99.2 53 UDP DNS (techmeology.co).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:38:03.966322" r2d2 68.12.104.178 43666 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 08:38:03.966293" r2d2 68.12.104.178 43666 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 08:38:11.450436" r2d2 68.12.104.178 39520 68.12.99.2 53 UDP DNS gmai.com "fake flash" www.malwaredomains.com\n' +
    '"2015-03-10 08:38:11.450439" r2d2 68.12.104.178 39520 68.12.99.2 53 UDP DNS gmai.com "fake flash" www.malwaredomains.com\n' +
    '"2015-03-10 08:38:16.429295" r2d2 68.12.104.178 49347 68.12.99.2 53 UDP DNS (ns1.via).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:38:16.429294" r2d2 68.12.104.178 49347 68.12.99.2 53 UDP DNS (ns1.via).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:38:16.429758" r2d2 68.12.104.178 36664 68.12.99.2 53 UDP DNS (ns2.via).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:38:16.429749" r2d2 68.12.104.178 36664 68.12.99.2 53 UDP DNS (ns2.via).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:38:22.088016" r2d2 68.12.104.178 44514 68.12.99.2 53 UDP DNS (neversay).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:38:22.088014" r2d2 68.12.104.178 44514 68.12.99.2 53 UDP DNS (neversay).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:38:34.417075" r2d2 68.12.104.178 59237 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 08:38:34.417077" r2d2 68.12.104.178 59237 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 08:38:36.776917" r2d2 68.12.104.178 40981 68.12.99.2 53 UDP DNS (add).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:38:36.776915" r2d2 68.12.104.178 40981 68.12.99.2 53 UDP DNS (add).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:38:38.278428" r2d2 68.12.104.178 48668 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 08:38:38.278431" r2d2 68.12.104.178 48668 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 08:38:38.701215" r2d2 68.12.104.178 54218 68.12.99.2 53 UDP DNS members.tripod.com malware malwareurls.joxeankoret.com\n' +
    '"2015-03-10 08:38:38.701216" r2d2 68.12.104.178 54218 68.12.99.2 53 UDP DNS members.tripod.com malware malwareurls.joxeankoret.com\n' +
    '"2015-03-10 08:38:41.961229" r2d2 68.12.104.178 40527 68.12.99.2 53 UDP DNS peer.pickeklosarske.ru "palevo (malware)" (static)\n' +
    '"2015-03-10 08:38:41.961218" r2d2 68.12.104.178 40527 68.12.99.2 53 UDP DNS peer.pickeklosarske.ru "palevo (malware)" (static)\n' +
    '"2015-03-10 08:38:42.030405" r2d2 68.12.104.178 59398 68.12.99.2 53 UDP DNS promisex.ru "zeus (malware)" (custom)\n' +
    '"2015-03-10 08:38:42.030403" r2d2 68.12.104.178 59398 68.12.99.2 53 UDP DNS promisex.ru "zeus (malware)" (custom)\n' +
    '"2015-03-10 08:38:48.038793" r2d2 68.12.104.178 57355 8.8.8.8 53 UDP DNS promisex.ru "zeus (malware)" (custom)\n' +
    '"2015-03-10 08:38:48.038792" r2d2 68.12.104.178 57355 8.8.8.8 53 UDP DNS promisex.ru "zeus (malware)" (custom)\n' +
    '"2015-03-10 08:39:01.598629" r2d2 68.12.104.178 40314 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 08:39:01.598627" r2d2 68.12.104.178 40314 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 08:39:09.073827" r2d2 68.12.104.178 39547 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 08:39:09.073829" r2d2 68.12.104.178 39547 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 08:39:09.518638" r2d2 68.12.104.178 37184 68.12.99.2 53 UDP DNS (ns1.spbhost).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:39:09.519305" r2d2 68.12.104.178 49689 68.12.99.2 53 UDP DNS (ns2.spbhost).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:39:09.518640" r2d2 68.12.104.178 37184 68.12.99.2 53 UDP DNS (ns1.spbhost).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:39:09.519318" r2d2 68.12.104.178 49689 68.12.99.2 53 UDP DNS (ns2.spbhost).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:39:10.880451" r2d2 68.12.104.178 45928 113.108.80.138 53 UDP IP 113.108.80.138 dnspod (custom)\n' +
    '"2015-03-10 08:39:10.880449" r2d2 68.12.104.178 45928 113.108.80.138 53 UDP IP 113.108.80.138 dnspod (custom)\n' +
    '"2015-03-10 08:39:13.620029" r2d2 68.12.104.178 56322 68.12.99.2 53 UDP DNS (mail.spbhost).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:39:13.620028" r2d2 68.12.104.178 56322 68.12.99.2 53 UDP DNS (mail.spbhost).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:39:24.116940" r2d2 68.12.104.178 51597 68.12.99.2 53 UDP DNS (dwc).no-ip.biz "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 08:39:24.116942" r2d2 68.12.104.178 51597 68.12.99.2 53 UDP DNS (dwc).no-ip.biz "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 08:39:31.649225" r2d2 68.12.104.178 42167 68.12.99.2 53 UDP DNS (ontika).ignorelist.com "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:39:31.649226" r2d2 68.12.104.178 42167 68.12.99.2 53 UDP DNS (ontika).ignorelist.com "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:39:33.774461" r2d2 68.12.104.178 45240 68.12.99.2 53 UDP DNS (brightlounge).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:39:33.774459" r2d2 68.12.104.178 45240 68.12.99.2 53 UDP DNS (brightlounge).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:39:35.466290" r2d2 68.12.104.178 50993 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 08:39:35.466288" r2d2 68.12.104.178 50993 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 08:39:40.039081" r2d2 68.12.104.178 57355 8.8.8.8 53 UDP DNS (brightlounge).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:39:40.039071" r2d2 68.12.104.178 57355 8.8.8.8 53 UDP DNS (brightlounge).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:39:41.994502" r2d2 68.12.104.178 39273 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 08:39:41.994518" r2d2 68.12.104.178 39273 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 08:39:50.399949" r2d2 68.12.104.178 35618 68.12.99.2 53 UDP DNS (carter).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:39:50.399948" r2d2 68.12.104.178 35618 68.12.99.2 53 UDP DNS (carter).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:39:52.447643" r2d2 68.12.104.178 38286 68.12.99.2 53 UDP DNS (www).superfish.com superfish (static)\n' +
    '"2015-03-10 08:39:52.447640" r2d2 68.12.104.178 38286 68.12.99.2 53 UDP DNS (www).superfish.com superfish (static)\n' +
    '"2015-03-10 08:39:52.566824" r2d2 68.12.104.178 38007 68.12.99.2 53 UDP DNS superfish.com superfish (static)\n' +
    '"2015-03-10 08:39:52.566828" r2d2 68.12.104.178 38007 68.12.99.2 53 UDP DNS superfish.com superfish (static)\n' +
    '"2015-03-10 08:39:53.787550" r2d2 68.12.104.178 43241 68.12.99.2 53 UDP DNS (ns3.quagmire).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:39:53.787548" r2d2 68.12.104.178 43241 68.12.99.2 53 UDP DNS (ns3.quagmire).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:40:00.231210" r2d2 61.240.144.64 60000 68.12.104.178 32764 TCP IP 61.240.144.64 "incoming masscan detected" autoshun.org\n' +
    '"2015-03-10 08:40:00.231212" r2d2 61.240.144.64 60000 68.12.104.178 32764 TCP IP 61.240.144.64 "incoming masscan detected" autoshun.org\n' +
    '"2015-03-10 08:40:05.807448" r2d2 68.12.104.178 37355 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 08:40:05.807447" r2d2 68.12.104.178 37355 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 08:40:08.674367" r2d2 68.12.104.178 44588 68.12.99.2 53 UDP DNS (eza).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:40:08.674365" r2d2 68.12.104.178 44588 68.12.99.2 53 UDP DNS (eza).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:40:10.688012" r2d2 68.12.104.178 50289 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 08:40:10.688014" r2d2 68.12.104.178 50289 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 08:40:18.586291" r2d2 68.12.104.178 42863 68.12.99.2 53 UDP DNS (ns2.croonen).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:40:18.586050" r2d2 68.12.104.178 47552 68.12.99.2 53 UDP DNS (ns1.croonen).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:40:18.586288" r2d2 68.12.104.178 42863 68.12.99.2 53 UDP DNS (ns2.croonen).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:40:18.586048" r2d2 68.12.104.178 47552 68.12.99.2 53 UDP DNS (ns1.croonen).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:40:24.111680" r2d2 68.12.104.178 42739 68.12.99.2 53 UDP DNS (inbox).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:40:24.111682" r2d2 68.12.104.178 42739 68.12.99.2 53 UDP DNS (inbox).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:40:32.542936" r2d2 68.12.104.178 37393 68.12.99.2 53 UDP DNS cychefs.com malware cybercrime-tracker.net\n' +
    '"2015-03-10 08:40:32.542947" r2d2 68.12.104.178 37393 68.12.99.2 53 UDP DNS cychefs.com malware cybercrime-tracker.net\n' +
    '"2015-03-10 08:40:34.798907" r2d2 68.12.104.178 59502 68.12.99.2 53 UDP DNS (sms.systemhaus).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:40:34.798915" r2d2 68.12.104.178 59502 68.12.99.2 53 UDP DNS (sms.systemhaus).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:40:34.799629" r2d2 68.12.104.178 36745 68.12.99.2 53 UDP DNS (dns1.systemhaus).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:40:34.799627" r2d2 68.12.104.178 36745 68.12.99.2 53 UDP DNS (dns1.systemhaus).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:40:34.799635" r2d2 68.12.104.178 57603 68.12.99.2 53 UDP DNS (dns2.systemhaus).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:40:34.799636" r2d2 68.12.104.178 57603 68.12.99.2 53 UDP DNS (dns2.systemhaus).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:40:41.514026" r2d2 68.12.104.178 41552 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 08:40:41.514027" r2d2 68.12.104.178 41552 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 08:40:50.112020" r2d2 68.12.104.178 42120 198.58.92.228 53 UDP IP 198.58.92.228 malware cybercrime-tracker.net\n' +
    '"2015-03-10 08:40:50.112019" r2d2 68.12.104.178 42120 198.58.92.228 53 UDP IP 198.58.92.228 malware cybercrime-tracker.net\n' +
    '"2015-03-10 08:40:50.308089" r2d2 68.12.104.178 55535 198.58.92.228 53 UDP IP 198.58.92.228 malware cybercrime-tracker.net\n' +
    '"2015-03-10 08:40:50.308091" r2d2 68.12.104.178 55535 198.58.92.228 53 UDP IP 198.58.92.228 malware cybercrime-tracker.net\n' +
    '"2015-03-10 08:40:51.447001" r2d2 68.12.104.178 41339 198.58.92.228 53 UDP IP 198.58.92.228 malware cybercrime-tracker.net\n' +
    '"2015-03-10 08:40:51.446999" r2d2 68.12.104.178 41339 198.58.92.228 53 UDP IP 198.58.92.228 malware cybercrime-tracker.net\n' +
    '"2015-03-10 08:40:53.750901" r2d2 68.12.104.178 46853 68.12.99.2 53 UDP DNS digitalmind.cn "palevo (malware)" palevotracker.abuse.ch\n' +
    '"2015-03-10 08:40:53.750893" r2d2 68.12.104.178 46853 68.12.99.2 53 UDP DNS digitalmind.cn "palevo (malware)" palevotracker.abuse.ch\n' +
    '"2015-03-10 08:40:54.032280" r2d2 68.12.104.178 56283 68.12.99.2 53 UDP DNS gmai.com "fake flash" www.malwaredomains.com\n' +
    '"2015-03-10 08:40:54.032281" r2d2 68.12.104.178 56283 68.12.99.2 53 UDP DNS gmai.com "fake flash" www.malwaredomains.com\n' +
    '"2015-03-10 08:40:54.562144" r2d2 68.12.104.178 48301 68.12.99.2 53 UDP DNS (ns1.sky-walker).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:40:54.562156" r2d2 68.12.104.178 50786 68.12.99.2 53 UDP DNS (ns2.sky-walker).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:40:54.562145" r2d2 68.12.104.178 48301 68.12.99.2 53 UDP DNS (ns1.sky-walker).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:40:54.562158" r2d2 68.12.104.178 50786 68.12.99.2 53 UDP DNS (ns2.sky-walker).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:41:00.849278" r2d2 68.12.104.178 52498 68.12.99.2 53 UDP DNS teske.pornicarke.com "palevo (malware)" (static)\n' +
    '"2015-03-10 08:41:00.849280" r2d2 68.12.104.178 52498 68.12.99.2 53 UDP DNS teske.pornicarke.com "palevo (malware)" (static)\n' +
    '"2015-03-10 08:41:05.938651" r2d2 68.12.104.178 47284 68.12.99.2 53 UDP DNS (tracker.coppersurfer).tk "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:41:05.938648" r2d2 68.12.104.178 47284 68.12.99.2 53 UDP DNS (tracker.coppersurfer).tk "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:41:06.432381" r2d2 68.12.104.178 46818 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 08:41:06.432383" r2d2 68.12.104.178 46818 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 08:41:12.055022" r2d2 68.12.104.178 44954 68.12.99.2 53 UDP DNS peer.pickeklosarske.ru "palevo (malware)" (static)\n' +
    '"2015-03-10 08:41:12.055020" r2d2 68.12.104.178 44954 68.12.99.2 53 UDP DNS peer.pickeklosarske.ru "palevo (malware)" (static)\n' +
    '"2015-03-10 08:41:12.569788" r2d2 68.12.104.178 36007 68.12.99.2 53 UDP DNS whgrp.com "pushdo (malware)" (static)\n' +
    '"2015-03-10 08:41:12.569784" r2d2 68.12.104.178 36007 68.12.99.2 53 UDP DNS whgrp.com "pushdo (malware)" (static)\n' +
    '"2015-03-10 08:41:25.212937" r2d2 68.12.104.178 38925 68.12.99.2 53 UDP DNS (isp2.carringtongroup).email "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:41:25.212935" r2d2 68.12.104.178 38925 68.12.99.2 53 UDP DNS (isp2.carringtongroup).email "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:41:30.502765" r2d2 68.12.104.178 58031 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 08:41:30.502767" r2d2 68.12.104.178 58031 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 08:41:36.791164" r2d2 68.12.104.178 49265 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 08:41:36.791166" r2d2 68.12.104.178 49265 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 08:41:43.258539" r2d2 68.12.104.178 55055 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 08:41:43.258534" r2d2 68.12.104.178 55055 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 08:41:57.305646" r2d2 68.12.104.178 43982 113.108.80.138 53 UDP IP 113.108.80.138 dnspod (custom)\n' +
    '"2015-03-10 08:41:57.305914" r2d2 68.12.104.178 43982 113.108.80.138 53 UDP IP 113.108.80.138 dnspod (custom)\n' +
    '"2015-03-10 08:42:12.213843" r2d2 68.12.104.178 39578 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 08:42:12.213832" r2d2 68.12.104.178 39578 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 08:42:14.075024" r2d2 68.12.104.178 37999 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 08:42:14.075019" r2d2 68.12.104.178 37999 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 08:42:17.430226" r2d2 68.12.104.178 53952 68.12.99.2 53 UDP DNS barbaros.com malicious app.webinspector.com\n' +
    '"2015-03-10 08:42:17.430224" r2d2 68.12.104.178 53952 68.12.99.2 53 UDP DNS barbaros.com malicious app.webinspector.com\n' +
    '"2015-03-10 08:42:37.429614" r2d2 68.12.104.178 52207 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 08:42:37.429636" r2d2 68.12.104.178 52207 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 08:42:51.909419" r2d2 68.12.104.178 36717 68.12.99.2 53 UDP DNS animeonline.net attackpage safebrowsing.clients.google.com\n' +
    '"2015-03-10 08:42:51.909420" r2d2 68.12.104.178 36717 68.12.99.2 53 UDP DNS animeonline.net attackpage safebrowsing.clients.google.com\n' +
    '"2015-03-10 08:43:08.286834" r2d2 68.12.104.178 52045 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 08:43:08.286841" r2d2 68.12.104.178 52045 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 08:43:08.472131" r2d2 68.12.104.178 40258 68.12.99.2 53 UDP DNS (ns.denali).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:43:08.472304" r2d2 68.12.104.178 47603 68.12.99.2 53 UDP DNS (ns.denali).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:43:08.472133" r2d2 68.12.104.178 40258 68.12.99.2 53 UDP DNS (ns.denali).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:43:08.472307" r2d2 68.12.104.178 47603 68.12.99.2 53 UDP DNS (ns.denali).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:43:14.787254" r2d2 68.12.104.178 42852 61.19.249.88 53 UDP IP 61.19.249.88 "brute forcer" danger.rulez.sk\n' +
    '"2015-03-10 08:43:14.787264" r2d2 68.12.104.178 42852 61.19.249.88 53 UDP IP 61.19.249.88 "brute forcer" danger.rulez.sk\n' +
    '"2015-03-10 08:43:15.637067" r2d2 68.12.104.178 58068 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 08:43:15.637063" r2d2 68.12.104.178 58068 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 08:43:34.316210" r2d2 68.12.104.178 44928 68.12.99.2 53 UDP DNS (megascor).no-ip.biz "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 08:43:34.316208" r2d2 68.12.104.178 44928 68.12.99.2 53 UDP DNS (megascor).no-ip.biz "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 08:43:42.115990" r2d2 68.12.104.178 57382 68.12.99.2 53 UDP DNS peer.pickeklosarske.ru "palevo (malware)" (static)\n' +
    '"2015-03-10 08:43:42.115989" r2d2 68.12.104.178 57382 68.12.99.2 53 UDP DNS peer.pickeklosarske.ru "palevo (malware)" (static)\n' +
    '"2015-03-10 08:43:46.455961" r2d2 68.12.104.178 48158 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 08:43:46.455959" r2d2 68.12.104.178 48158 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 08:43:48.312903" r2d2 68.12.104.178 35730 68.12.99.2 53 UDP DNS (www).lsrj.in malspam malware-traffic-analysis.net\n' +
    '"2015-03-10 08:43:48.312881" r2d2 68.12.104.178 35730 68.12.99.2 53 UDP DNS (www).lsrj.in malspam malware-traffic-analysis.net\n' +
    '"2015-03-10 08:43:48.467659" r2d2 68.12.104.178 45011 68.12.99.2 53 UDP DNS lsrj.in malspam malware-traffic-analysis.net\n' +
    '"2015-03-10 08:43:59.740373" r2d2 68.12.104.178 45475 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 08:43:59.740374" r2d2 68.12.104.178 45475 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 08:44:00.955150" r2d2 212.83.171.94 5109 68.12.104.178 5060 UDP IP 212.83.171.94 "sipvicious scan" autoshun.org\n' +
    '"2015-03-10 08:44:00.955148" r2d2 212.83.171.94 5109 68.12.104.178 5060 UDP IP 212.83.171.94 "sipvicious scan" autoshun.org\n' +
    '"2015-03-10 08:44:09.934373" r2d2 68.12.104.178 45757 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 08:44:09.934370" r2d2 68.12.104.178 45757 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 08:44:19.173484" r2d2 68.12.104.178 54519 68.12.99.2 53 UDP DNS (stroigrad).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:44:19.173480" r2d2 68.12.104.178 54519 68.12.99.2 53 UDP DNS (stroigrad).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:44:26.485840" r2d2 68.12.104.178 41165 68.12.99.2 53 UDP DNS (clmediterraneo).ddns.net "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 08:44:38.719054" r2d2 68.12.104.178 57885 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 08:44:38.719051" r2d2 68.12.104.178 57885 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 08:44:40.800408" r2d2 68.12.104.178 54104 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 08:44:40.800407" r2d2 68.12.104.178 54104 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 08:44:47.285594" r2d2 68.12.104.178 37715 68.12.99.2 53 UDP DNS (ccc.bluegrals).xyz "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:44:47.285611" r2d2 68.12.104.178 37715 68.12.99.2 53 UDP DNS (ccc.bluegrals).xyz "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:44:48.051197" r2d2 68.12.104.178 38142 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 08:44:48.051180" r2d2 68.12.104.178 38142 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 08:44:57.417716" r2d2 68.12.104.178 56861 68.12.99.2 53 UDP DNS a.datacardbar.info malware malwareurls.joxeankoret.com\n' +
    '"2015-03-10 08:44:57.417715" r2d2 68.12.104.178 56861 68.12.99.2 53 UDP DNS a.datacardbar.info malware malwareurls.joxeankoret.com\n' +
    '"2015-03-10 08:44:59.136408" r2d2 68.12.104.178 40298 5.199.172.41 53 UDP IP 5.199.172.41 malware cybercrime-tracker.net\n' +
    '"2015-03-10 08:44:59.136407" r2d2 68.12.104.178 40298 5.199.172.41 53 UDP IP 5.199.172.41 malware cybercrime-tracker.net\n' +
    '"2015-03-10 08:45:01.330360" r2d2 68.12.104.178 44118 68.12.99.2 53 UDP DNS (megascor).no-ip.biz "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 08:45:01.330344" r2d2 68.12.104.178 44118 68.12.99.2 53 UDP DNS (megascor).no-ip.biz "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 08:45:16.998181" r2d2 68.12.104.178 35999 68.12.99.2 53 UDP DNS (tiny).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:45:16.998183" r2d2 68.12.104.178 35999 68.12.99.2 53 UDP DNS (tiny).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:45:18.906273" r2d2 68.12.104.178 50802 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 08:45:18.906275" r2d2 68.12.104.178 50802 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 08:45:31.662462" r2d2 68.12.104.178 51180 184.173.68.2 53 UDP IP 184.173.68.2 malware cybercrime-tracker.net\n' +
    '"2015-03-10 08:45:31.662470" r2d2 68.12.104.178 51180 184.173.68.2 53 UDP IP 184.173.68.2 malware cybercrime-tracker.net\n' +
    '"2015-03-10 08:45:36.186646" r2d2 68.12.104.178 56887 81.2.199.97 53 UDP IP 81.2.199.97 "asprox (malware)" atrack.h3x.eu\n' +
    '"2015-03-10 08:45:36.186647" r2d2 68.12.104.178 56887 81.2.199.97 53 UDP IP 81.2.199.97 "asprox (malware)" atrack.h3x.eu\n' +
    '"2015-03-10 08:45:36.603118" r2d2 68.12.104.178 49548 68.12.99.2 53 UDP DNS browsestudio.com malware malwareurls.joxeankoret.com\n' +
    '"2015-03-10 08:45:36.603114" r2d2 68.12.104.178 49548 68.12.99.2 53 UDP DNS browsestudio.com malware malwareurls.joxeankoret.com\n' +
    '"2015-03-10 08:45:37.018438" r2d2 68.12.104.178 51157 68.12.99.2 53 UDP DNS (ns1.plato).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:45:37.018439" r2d2 68.12.104.178 51157 68.12.99.2 53 UDP DNS (ns1.plato).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:45:37.018871" r2d2 68.12.104.178 43793 68.12.99.2 53 UDP DNS (ns2.plato).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:45:37.018874" r2d2 68.12.104.178 43793 68.12.99.2 53 UDP DNS (ns2.plato).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:45:38.777208" r2d2 68.12.104.178 47839 68.12.99.2 53 UDP DNS promisex.ru "zeus (malware)" (custom)\n' +
    '"2015-03-10 08:45:38.777206" r2d2 68.12.104.178 47839 68.12.99.2 53 UDP DNS promisex.ru "zeus (malware)" (custom)\n' +
    '"2015-03-10 08:45:42.420680" r2d2 68.12.104.178 48151 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 08:45:42.420679" r2d2 68.12.104.178 48151 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 08:45:53.325077" r2d2 68.12.104.178 51958 68.12.99.2 53 UDP DNS (primm).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:45:53.325075" r2d2 68.12.104.178 51958 68.12.99.2 53 UDP DNS (primm).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:45:54.126880" r2d2 68.12.104.178 47276 68.12.99.2 53 UDP DNS (fairmandavis).no-ip.co.uk "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 08:45:54.126882" r2d2 68.12.104.178 47276 68.12.99.2 53 UDP DNS (fairmandavis).no-ip.co.uk "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 08:46:03.188882" r2d2 68.12.104.178 37844 68.12.99.2 53 UDP DNS peer.pickeklosarske.ru "palevo (malware)" (static)\n' +
    '"2015-03-10 08:46:03.188881" r2d2 68.12.104.178 37844 68.12.99.2 53 UDP DNS peer.pickeklosarske.ru "palevo (malware)" (static)\n' +
    '"2015-03-10 08:46:10.638675" r2d2 68.12.104.178 44359 68.12.99.2 53 UDP DNS (eit.folks).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:46:10.638677" r2d2 68.12.104.178 44359 68.12.99.2 53 UDP DNS (eit.folks).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:46:13.232215" r2d2 68.12.104.178 57373 68.12.99.2 53 UDP DNS (megascor).no-ip.biz "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 08:46:13.232214" r2d2 68.12.104.178 57373 68.12.99.2 53 UDP DNS (megascor).no-ip.biz "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 08:46:13.270020" r2d2 68.12.104.178 47689 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 08:46:13.270021" r2d2 68.12.104.178 47689 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 08:46:20.574911" r2d2 68.12.104.178 45885 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 08:46:20.574909" r2d2 68.12.104.178 45885 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 08:46:21.241358" r2d2 68.12.104.178 53036 68.12.99.2 53 UDP DNS bitc1.biz fraud www.spamhaus.org\n' +
    '"2015-03-10 08:46:21.242287" r2d2 68.12.104.178 38056 68.12.99.2 53 UDP DNS (ns1).bitc1.biz fraud www.spamhaus.org\n' +
    '"2015-03-10 08:46:21.242461" r2d2 68.12.104.178 53456 68.12.99.2 53 UDP DNS (ns2).bitc1.biz fraud www.spamhaus.org\n' +
    '"2015-03-10 08:46:21.241356" r2d2 68.12.104.178 53036 68.12.99.2 53 UDP DNS bitc1.biz fraud www.spamhaus.org\n' +
    '"2015-03-10 08:46:21.242276" r2d2 68.12.104.178 38056 68.12.99.2 53 UDP DNS (ns1).bitc1.biz fraud www.spamhaus.org\n' +
    '"2015-03-10 08:46:21.242463" r2d2 68.12.104.178 53456 68.12.99.2 53 UDP DNS (ns2).bitc1.biz fraud www.spamhaus.org\n' +
    '"2015-03-10 08:46:24.665989" r2d2 68.12.104.178 41090 68.12.99.2 53 UDP DNS (ns3.olven).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:46:24.665991" r2d2 68.12.104.178 41090 68.12.99.2 53 UDP DNS (ns3.olven).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:46:24.666830" r2d2 68.12.104.178 53419 68.12.99.2 53 UDP DNS (ns5.olven).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:46:24.666828" r2d2 68.12.104.178 53419 68.12.99.2 53 UDP DNS (ns5.olven).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:46:24.666952" r2d2 68.12.104.178 39453 68.12.99.2 53 UDP DNS (ns5.olven).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:46:24.666946" r2d2 68.12.104.178 39453 68.12.99.2 53 UDP DNS (ns5.olven).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:46:24.972776" r2d2 68.12.104.178 45426 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 08:46:24.972780" r2d2 68.12.104.178 45426 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 08:46:26.096734" r2d2 68.12.104.178 39715 68.12.99.2 53 UDP DNS (gma).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:46:26.096733" r2d2 68.12.104.178 39715 68.12.99.2 53 UDP DNS (gma).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:46:36.336552" r2d2 68.12.104.178 43711 68.12.99.2 53 UDP DNS upperlowstream.ru "zeus (malware)" zeustracker.abuse.ch\n' +
    '"2015-03-10 08:46:36.336551" r2d2 68.12.104.178 43711 68.12.99.2 53 UDP DNS upperlowstream.ru "zeus (malware)" zeustracker.abuse.ch\n' +
    '"2015-03-10 08:46:40.798047" r2d2 68.12.104.178 40215 68.12.99.2 53 UDP DNS (tracker.coppersurfer).tk "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:46:40.798050" r2d2 68.12.104.178 40215 68.12.99.2 53 UDP DNS (tracker.coppersurfer).tk "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:46:51.410566" r2d2 68.12.104.178 53742 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 08:46:51.410568" r2d2 68.12.104.178 53742 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 08:46:59.500015" r2d2 68.12.104.178 44443 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 08:46:59.500014" r2d2 68.12.104.178 44443 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 08:47:01.689393" r2d2 68.12.104.178 46266 113.108.80.138 53 UDP IP 113.108.80.138 dnspod (custom)\n' +
    '"2015-03-10 08:47:01.689401" r2d2 68.12.104.178 46266 113.108.80.138 53 UDP IP 113.108.80.138 dnspod (custom)\n' +
    '"2015-03-10 08:47:03.729880" r2d2 68.12.104.178 52389 68.12.99.2 53 UDP DNS (moneyworldwide).club "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:47:03.729886" r2d2 68.12.104.178 52389 68.12.99.2 53 UDP DNS (moneyworldwide).club "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:47:07.314038" r2d2 68.12.104.178 41644 68.12.99.2 53 UDP DNS digitalmind.cn "palevo (malware)" palevotracker.abuse.ch\n' +
    '"2015-03-10 08:47:07.314041" r2d2 68.12.104.178 41644 68.12.99.2 53 UDP DNS digitalmind.cn "palevo (malware)" palevotracker.abuse.ch\n' +
    '"2015-03-10 08:47:12.754040" r2d2 68.12.104.178 41826 5.199.172.41 53 UDP IP 5.199.172.41 malware cybercrime-tracker.net\n' +
    '"2015-03-10 08:47:12.754030" r2d2 68.12.104.178 41826 5.199.172.41 53 UDP IP 5.199.172.41 malware cybercrime-tracker.net\n' +
    '"2015-03-10 08:47:15.207261" r2d2 68.12.104.178 36158 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 08:47:15.207259" r2d2 68.12.104.178 36158 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 08:47:26.168960" r2d2 68.12.104.178 48982 68.12.99.2 53 UDP DNS (ns1.workgroup).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:47:26.168965" r2d2 68.12.104.178 48982 68.12.99.2 53 UDP DNS (ns1.workgroup).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:47:26.170487" r2d2 68.12.104.178 39659 68.12.99.2 53 UDP DNS (ns2.workgroup).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:47:26.170483" r2d2 68.12.104.178 39659 68.12.99.2 53 UDP DNS (ns2.workgroup).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:47:44.981616" r2d2 68.12.104.178 35041 68.12.99.2 53 UDP DNS gmai.com "fake flash" www.malwaredomains.com\n' +
    '"2015-03-10 08:47:44.981618" r2d2 68.12.104.178 35041 68.12.99.2 53 UDP DNS gmai.com "fake flash" www.malwaredomains.com\n' +
    '"2015-03-10 08:47:46.050988" r2d2 68.12.104.178 46178 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 08:47:46.050990" r2d2 68.12.104.178 46178 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 08:47:52.992739" r2d2 68.12.104.178 50500 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 08:47:52.992741" r2d2 68.12.104.178 50500 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 08:47:53.838262" r2d2 68.12.104.178 44677 68.12.99.2 53 UDP DNS crazyerror.su malicious www.virustotal.com\n' +
    '"2015-03-10 08:47:53.838265" r2d2 68.12.104.178 44677 68.12.99.2 53 UDP DNS crazyerror.su malicious www.virustotal.com\n' +
    '"2015-03-10 08:48:02.641639" r2d2 68.12.104.178 36056 68.12.99.2 53 UDP DNS (lns1.muru).guru "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:48:02.641796" r2d2 68.12.104.178 42860 68.12.99.2 53 UDP DNS (lns2.muru).guru "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:48:02.641641" r2d2 68.12.104.178 36056 68.12.99.2 53 UDP DNS (lns1.muru).guru "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:48:02.641797" r2d2 68.12.104.178 42860 68.12.99.2 53 UDP DNS (lns2.muru).guru "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:48:05.364551" r2d2 68.12.104.178 57319 84.205.160.1 53 UDP IP 84.205.160.1 "brute forcer" danger.rulez.sk\n' +
    '"2015-03-10 08:48:05.364552" r2d2 68.12.104.178 57319 84.205.160.1 53 UDP IP 84.205.160.1 "brute forcer" danger.rulez.sk\n' +
    '"2015-03-10 08:48:16.770624" r2d2 68.12.104.178 52648 68.12.99.2 53 UDP DNS (megascor).no-ip.biz "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 08:48:16.770621" r2d2 68.12.104.178 52648 68.12.99.2 53 UDP DNS (megascor).no-ip.biz "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 08:48:23.808376" r2d2 68.12.104.178 41612 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 08:48:23.808373" r2d2 68.12.104.178 41612 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 08:48:24.124521" r2d2 68.12.104.178 48625 68.12.99.2 53 UDP DNS peer.pickeklosarske.ru "palevo (malware)" (static)\n' +
    '"2015-03-10 08:48:24.124522" r2d2 68.12.104.178 48625 68.12.99.2 53 UDP DNS peer.pickeklosarske.ru "palevo (malware)" (static)\n' +
    '"2015-03-10 08:48:25.326739" r2d2 68.12.104.178 35120 68.12.99.2 53 UDP DNS (mail2.konzept).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:48:25.326736" r2d2 68.12.104.178 35120 68.12.99.2 53 UDP DNS (mail2.konzept).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:48:47.738508" r2d2 68.12.104.178 52911 68.12.99.2 53 UDP DNS (scdev2).zapto.org "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 08:48:47.738530" r2d2 68.12.104.178 52911 68.12.99.2 53 UDP DNS (scdev2).zapto.org "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 08:48:47.811139" r2d2 68.12.104.178 58096 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 08:48:47.811144" r2d2 68.12.104.178 58096 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 08:48:53.233397" r2d2 68.12.104.178 42914 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 08:48:53.233393" r2d2 68.12.104.178 42914 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 08:49:07.282695" r2d2 68.12.104.178 59401 113.108.80.138 53 UDP IP 113.108.80.138 dnspod (custom)\n' +
    '"2015-03-10 08:49:07.282775" r2d2 68.12.104.178 59401 113.108.80.138 53 UDP IP 113.108.80.138 dnspod (custom)\n' +
    '"2015-03-10 08:49:18.644846" r2d2 68.12.104.178 47142 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 08:49:18.644883" r2d2 68.12.104.178 47142 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 08:49:20.250711" r2d2 68.12.104.178 56275 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 08:49:23.299431" r2d2 68.12.104.178 53102 113.108.80.138 53 UDP IP 113.108.80.138 dnspod (custom)\n' +
    '"2015-03-10 08:49:23.299432" r2d2 68.12.104.178 53102 113.108.80.138 53 UDP IP 113.108.80.138 dnspod (custom)\n' +
    '"2015-03-10 08:49:25.414199" r2d2 68.12.104.178 59707 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 08:49:25.414202" r2d2 68.12.104.178 59707 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 08:49:26.554863" r2d2 68.12.104.178 52540 68.12.99.2 53 UDP DNS superfish.com superfish (static)\n' +
    '"2015-03-10 08:49:26.554862" r2d2 68.12.104.178 52540 68.12.99.2 53 UDP DNS superfish.com superfish (static)\n' +
    '"2015-03-10 08:49:28.951768" r2d2 68.12.104.178 43303 68.12.99.2 53 UDP DNS (imap).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:49:28.951767" r2d2 68.12.104.178 43303 68.12.99.2 53 UDP DNS (imap).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:49:36.157472" r2d2 68.12.104.178 42075 68.12.99.2 53 UDP DNS (gis).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:49:36.157461" r2d2 68.12.104.178 42075 68.12.99.2 53 UDP DNS (gis).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:49:56.164204" r2d2 68.12.104.178 37921 68.12.99.2 53 UDP DNS (jetfire).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:49:56.164203" r2d2 68.12.104.178 37921 68.12.99.2 53 UDP DNS (jetfire).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:49:56.222695" r2d2 68.12.104.178 46313 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 08:49:56.222687" r2d2 68.12.104.178 46313 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 08:49:57.491315" r2d2 68.12.104.178 39307 68.12.99.2 53 UDP DNS (brightlounge).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:49:57.491317" r2d2 68.12.104.178 39307 68.12.99.2 53 UDP DNS (brightlounge).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:50:02.736956" r2d2 68.12.104.178 37227 68.12.99.2 53 UDP DNS (klmn).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:50:02.736958" r2d2 68.12.104.178 37227 68.12.99.2 53 UDP DNS (klmn).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:50:14.300323" r2d2 68.12.104.178 47761 68.12.99.2 53 UDP DNS (megascor).no-ip.biz "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 08:50:14.300325" r2d2 68.12.104.178 47761 68.12.99.2 53 UDP DNS (megascor).no-ip.biz "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 08:50:17.144597" r2d2 68.12.104.178 49975 68.12.99.2 53 UDP DNS (ns2.novastar).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:50:17.144164" r2d2 68.12.104.178 36346 68.12.99.2 53 UDP DNS (ns1.novastar).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:50:17.144599" r2d2 68.12.104.178 49975 68.12.99.2 53 UDP DNS (ns2.novastar).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:50:17.144165" r2d2 68.12.104.178 36346 68.12.99.2 53 UDP DNS (ns1.novastar).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:50:20.255303" r2d2 68.12.104.178 48242 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 08:50:20.255307" r2d2 68.12.104.178 48242 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 08:50:33.779983" r2d2 68.12.104.178 56579 68.12.99.2 53 UDP DNS promisex.ru "zeus (malware)" (custom)\n' +
    '"2015-03-10 08:50:33.779985" r2d2 68.12.104.178 56579 68.12.99.2 53 UDP DNS promisex.ru "zeus (malware)" (custom)\n' +
    '"2015-03-10 08:50:36.361035" r2d2 68.12.104.178 59854 113.108.80.138 53 UDP IP 113.108.80.138 dnspod (custom)\n' +
    '"2015-03-10 08:50:36.361025" r2d2 68.12.104.178 59854 113.108.80.138 53 UDP IP 113.108.80.138 dnspod (custom)\n' +
    '"2015-03-10 08:50:46.615447" r2d2 68.12.104.178 42846 68.12.99.2 53 UDP DNS peer.pickeklosarske.ru "palevo (malware)" (static)\n' +
    '"2015-03-10 08:50:46.615450" r2d2 68.12.104.178 42846 68.12.99.2 53 UDP DNS peer.pickeklosarske.ru "palevo (malware)" (static)\n' +
    '"2015-03-10 08:50:51.555934" r2d2 68.12.104.178 38165 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 08:50:51.555933" r2d2 68.12.104.178 38165 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 08:50:57.836261" r2d2 68.12.104.178 53274 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 08:50:57.836252" r2d2 68.12.104.178 53274 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 08:51:08.048089" r2d2 68.12.104.178 51738 207.188.93.162 53 UDP IP 207.188.93.162 abuser openbl.org\n' +
    '"2015-03-10 08:51:08.048090" r2d2 68.12.104.178 51738 207.188.93.162 53 UDP IP 207.188.93.162 abuser openbl.org\n' +
    '"2015-03-10 08:51:16.630972" r2d2 68.12.104.178 57452 68.12.99.2 53 UDP DNS teske.pornicarke.com "palevo (malware)" (static)\n' +
    '"2015-03-10 08:51:16.630971" r2d2 68.12.104.178 57452 68.12.99.2 53 UDP DNS teske.pornicarke.com "palevo (malware)" (static)\n' +
    '"2015-03-10 08:51:17.604062" r2d2 68.12.104.178 35294 68.12.99.2 53 UDP DNS (dobrowski).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:51:17.604061" r2d2 68.12.104.178 35294 68.12.99.2 53 UDP DNS (dobrowski).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:51:21.774843" r2d2 68.12.104.178 39271 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 08:51:21.774833" r2d2 68.12.104.178 39271 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 08:51:23.616919" r2d2 68.12.104.178 46170 68.12.99.2 53 UDP DNS (ns.pdm).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:51:23.617230" r2d2 68.12.104.178 59842 68.12.99.2 53 UDP DNS (ns2.pdm).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:51:23.616917" r2d2 68.12.104.178 46170 68.12.99.2 53 UDP DNS (ns.pdm).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:51:23.617223" r2d2 68.12.104.178 59842 68.12.99.2 53 UDP DNS (ns2.pdm).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:51:28.797788" r2d2 68.12.104.178 44773 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 08:51:28.797790" r2d2 68.12.104.178 44773 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 08:51:36.890144" r2d2 68.12.104.178 49246 68.12.99.2 53 UDP DNS (ns1.coldzaens).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:51:36.890512" r2d2 68.12.104.178 44404 68.12.99.2 53 UDP DNS (ns2.coldzaens).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:51:36.890146" r2d2 68.12.104.178 49246 68.12.99.2 53 UDP DNS (ns1.coldzaens).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:51:36.891022" r2d2 68.12.104.178 44114 68.12.99.2 53 UDP DNS (ns3.coldzaens).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:51:36.891201" r2d2 68.12.104.178 38370 68.12.99.2 53 UDP DNS (ns4.coldzaens).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:51:36.891205" r2d2 68.12.104.178 38370 68.12.99.2 53 UDP DNS (ns4.coldzaens).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:51:36.890523" r2d2 68.12.104.178 44404 68.12.99.2 53 UDP DNS (ns2.coldzaens).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:51:36.891033" r2d2 68.12.104.178 44114 68.12.99.2 53 UDP DNS (ns3.coldzaens).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:51:37.076821" r2d2 68.12.104.178 45354 68.12.99.2 53 UDP DNS (dir-ns-1.a1).4dq.com "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 08:51:37.077081" r2d2 68.12.104.178 42890 68.12.99.2 53 UDP DNS (dir-ns-2.a1).4dq.com "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 08:51:37.077122" r2d2 68.12.104.178 44363 68.12.99.2 53 UDP DNS (ns1).changeip.org "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 08:51:37.077112" r2d2 68.12.104.178 44363 68.12.99.2 53 UDP DNS (ns1).changeip.org "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 08:51:37.077828" r2d2 68.12.104.178 47620 68.12.99.2 53 UDP DNS (ns1).changeip.org "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 08:51:37.077861" r2d2 68.12.104.178 48384 68.12.99.2 53 UDP DNS (ns2).changeip.org "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 08:51:37.076819" r2d2 68.12.104.178 45354 68.12.99.2 53 UDP DNS (dir-ns-1.a1).4dq.com "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 08:51:37.078366" r2d2 68.12.104.178 45805 68.12.99.2 53 UDP DNS (ns2).changeip.org "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 08:51:37.078903" r2d2 68.12.104.178 43972 68.12.99.2 53 UDP DNS (ns3).changeip.org "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 08:51:37.078924" r2d2 68.12.104.178 43972 68.12.99.2 53 UDP DNS (ns3).changeip.org "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 08:51:37.077084" r2d2 68.12.104.178 42890 68.12.99.2 53 UDP DNS (dir-ns-2.a1).4dq.com "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 08:51:37.079173" r2d2 68.12.104.178 35916 68.12.99.2 53 UDP DNS (ns3).changeip.org "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 08:51:37.079172" r2d2 68.12.104.178 35916 68.12.99.2 53 UDP DNS (ns3).changeip.org "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 08:51:37.077830" r2d2 68.12.104.178 47620 68.12.99.2 53 UDP DNS (ns1).changeip.org "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 08:51:37.077859" r2d2 68.12.104.178 48384 68.12.99.2 53 UDP DNS (ns2).changeip.org "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 08:51:37.078362" r2d2 68.12.104.178 45805 68.12.99.2 53 UDP DNS (ns2).changeip.org "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 08:51:37.374766" r2d2 68.12.104.178 48508 68.12.99.2 53 UDP DNS (megascor).no-ip.biz "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 08:51:37.374769" r2d2 68.12.104.178 48508 68.12.99.2 53 UDP DNS (megascor).no-ip.biz "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 08:51:46.647956" r2d2 68.12.104.178 38636 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 08:51:46.647964" r2d2 68.12.104.178 38636 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 08:51:53.317440" r2d2 68.12.104.178 36919 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 08:51:53.317458" r2d2 68.12.104.178 36919 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 08:52:04.818484" r2d2 68.12.104.178 40898 68.12.99.2 53 UDP DNS (ns3.vsphere).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:52:04.818858" r2d2 68.12.104.178 57765 68.12.99.2 53 UDP DNS (ns4.vsphere).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:52:04.818488" r2d2 68.12.104.178 40898 68.12.99.2 53 UDP DNS (ns3.vsphere).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:52:04.818860" r2d2 68.12.104.178 57765 68.12.99.2 53 UDP DNS (ns4.vsphere).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:52:24.155601" r2d2 68.12.104.178 56965 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 08:52:24.155623" r2d2 68.12.104.178 56965 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 08:52:30.389384" r2d2 68.12.104.178 50279 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 08:52:30.389385" r2d2 68.12.104.178 50279 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 08:52:49.468467" r2d2 68.12.104.178 35931 68.12.99.2 53 UDP DNS (notredameschool).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:52:49.468470" r2d2 68.12.104.178 35931 68.12.99.2 53 UDP DNS (notredameschool).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:52:49.998998" r2d2 68.12.104.178 40091 68.12.99.2 53 UDP DNS peer.pickeklosarske.ru "palevo (malware)" (static)\n' +
    '"2015-03-10 08:52:49.999001" r2d2 68.12.104.178 40091 68.12.99.2 53 UDP DNS peer.pickeklosarske.ru "palevo (malware)" (static)\n' +
    '"2015-03-10 08:53:00.560256" r2d2 68.12.104.178 56183 68.12.99.2 53 UDP DNS (megascor).no-ip.biz "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 08:53:00.560257" r2d2 68.12.104.178 56183 68.12.99.2 53 UDP DNS (megascor).no-ip.biz "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 08:53:01.209775" r2d2 68.12.104.178 37697 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 08:53:01.209774" r2d2 68.12.104.178 37697 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 08:53:10.844513" r2d2 68.12.104.178 57867 68.12.99.2 53 UDP DNS (ns1.krump).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:53:10.844515" r2d2 68.12.104.178 57867 68.12.99.2 53 UDP DNS (ns1.krump).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:53:10.845056" r2d2 68.12.104.178 45757 68.12.99.2 53 UDP DNS (ns2.krump).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:53:10.845066" r2d2 68.12.104.178 45757 68.12.99.2 53 UDP DNS (ns2.krump).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:53:17.408150" r2d2 68.12.104.178 52227 68.12.99.2 53 UDP DNS digitalmind.cn "palevo (malware)" palevotracker.abuse.ch\n' +
    '"2015-03-10 08:53:17.408152" r2d2 68.12.104.178 52227 68.12.99.2 53 UDP DNS digitalmind.cn "palevo (malware)" palevotracker.abuse.ch\n' +
    '"2015-03-10 08:53:17.910046" r2d2 68.12.104.178 40102 68.12.99.2 53 UDP DNS (mcnamee).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:53:17.910049" r2d2 68.12.104.178 40102 68.12.99.2 53 UDP DNS (mcnamee).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:53:24.602013" r2d2 68.12.104.178 55272 68.12.99.2 53 UDP DNS (ns4.ipserver).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:53:24.601797" r2d2 68.12.104.178 52634 68.12.99.2 53 UDP DNS (ns3.ipserver).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:53:24.601790" r2d2 68.12.104.178 52634 68.12.99.2 53 UDP DNS (ns3.ipserver).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:53:24.602015" r2d2 68.12.104.178 55272 68.12.99.2 53 UDP DNS (ns4.ipserver).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:53:25.771991" r2d2 68.12.104.178 52306 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 08:53:25.771992" r2d2 68.12.104.178 52306 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 08:53:47.591982" r2d2 68.12.104.178 38766 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 08:53:47.591980" r2d2 68.12.104.178 38766 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 08:53:55.372856" r2d2 68.12.104.178 41669 68.12.99.2 53 UDP DNS (monitmass).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:53:55.372853" r2d2 68.12.104.178 41669 68.12.99.2 53 UDP DNS (monitmass).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:53:56.289460" r2d2 68.12.104.178 49168 113.108.80.138 53 UDP IP 113.108.80.138 dnspod (custom)\n' +
    '"2015-03-10 08:53:56.289458" r2d2 68.12.104.178 49168 113.108.80.138 53 UDP IP 113.108.80.138 dnspod (custom)\n' +
    '"2015-03-10 08:53:56.597053" r2d2 68.12.104.178 41464 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 08:53:56.597055" r2d2 68.12.104.178 41464 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 08:54:02.809244" r2d2 68.12.104.178 57170 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 08:54:02.809258" r2d2 68.12.104.178 57170 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 08:54:16.745791" r2d2 68.12.104.178 54388 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 08:54:16.745794" r2d2 68.12.104.178 54388 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 08:54:18.262176" r2d2 68.12.104.178 36201 68.12.99.2 53 UDP DNS (ns1).0fees.net malicious securehomenetworks.blogspot.com\n' +
    '"2015-03-10 08:54:18.262381" r2d2 68.12.104.178 55721 68.12.99.2 53 UDP DNS (ns2).0fees.net malicious securehomenetworks.blogspot.com\n' +
    '"2015-03-10 08:54:18.262180" r2d2 68.12.104.178 36201 68.12.99.2 53 UDP DNS (ns1).0fees.net malicious securehomenetworks.blogspot.com\n' +
    '"2015-03-10 08:54:18.262378" r2d2 68.12.104.178 55721 68.12.99.2 53 UDP DNS (ns2).0fees.net malicious securehomenetworks.blogspot.com\n' +
    '"2015-03-10 08:54:33.620118" r2d2 68.12.104.178 39454 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 08:54:33.620117" r2d2 68.12.104.178 39454 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 08:54:53.941164" r2d2 68.12.104.178 49136 68.12.99.2 53 UDP DNS (megascor).no-ip.biz "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 08:54:53.941162" r2d2 68.12.104.178 49136 68.12.99.2 53 UDP DNS (megascor).no-ip.biz "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 08:54:57.991157" r2d2 68.12.104.178 38487 68.12.99.2 53 UDP DNS (infactory).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:54:57.991154" r2d2 68.12.104.178 38487 68.12.99.2 53 UDP DNS (infactory).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:54:58.219319" r2d2 68.12.104.178 45700 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 08:54:58.219321" r2d2 68.12.104.178 45700 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 08:55:02.788068" r2d2 68.12.104.178 49762 68.12.99.2 53 UDP DNS ejsus.com "pushdo (malware)" (static)\n' +
    '"2015-03-10 08:55:02.788067" r2d2 68.12.104.178 49762 68.12.99.2 53 UDP DNS ejsus.com "pushdo (malware)" (static)\n' +
    '"2015-03-10 08:55:14.106578" r2d2 68.12.104.178 54168 68.12.99.2 53 UDP DNS peer.pickeklosarske.ru "palevo (malware)" (static)\n' +
    '"2015-03-10 08:55:14.106567" r2d2 68.12.104.178 54168 68.12.99.2 53 UDP DNS peer.pickeklosarske.ru "palevo (malware)" (static)\n' +
    '"2015-03-10 08:55:21.742100" r2d2 68.12.104.178 43411 68.12.99.2 53 UDP DNS (webdragon).no-ip.org "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 08:55:21.742097" r2d2 68.12.104.178 43411 68.12.99.2 53 UDP DNS (webdragon).no-ip.org "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 08:55:33.211544" r2d2 68.12.104.178 58301 68.12.99.2 53 UDP DNS (nycaasa).no-ip.org "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 08:55:33.211542" r2d2 68.12.104.178 58301 68.12.99.2 53 UDP DNS (nycaasa).no-ip.org "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 08:55:34.644347" r2d2 68.12.104.178 45315 68.12.99.2 53 UDP DNS (ine).wanadoo.es attackpage safebrowsing.clients.google.com\n' +
    '"2015-03-10 08:55:34.644349" r2d2 68.12.104.178 45315 68.12.99.2 53 UDP DNS (ine).wanadoo.es attackpage safebrowsing.clients.google.com\n' +
    '"2015-03-10 08:55:35.430011" r2d2 68.12.104.178 57215 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 08:55:35.430001" r2d2 68.12.104.178 57215 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 08:55:55.924119" r2d2 68.12.104.178 36636 68.12.99.2 53 UDP DNS dentesmitec.ru "zeus (malware)" zeustracker.abuse.ch\n' +
    '"2015-03-10 08:55:55.924121" r2d2 68.12.104.178 36636 68.12.99.2 53 UDP DNS dentesmitec.ru "zeus (malware)" zeustracker.abuse.ch\n' +
    '"2015-03-10 08:55:56.110586" r2d2 68.12.104.178 52103 68.12.99.2 53 UDP DNS promisex.ru "zeus (malware)" (custom)\n' +
    '"2015-03-10 08:55:56.110584" r2d2 68.12.104.178 52103 68.12.99.2 53 UDP DNS promisex.ru "zeus (malware)" (custom)\n' +
    '"2015-03-10 08:56:06.264398" r2d2 68.12.104.178 54159 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 08:56:06.264396" r2d2 68.12.104.178 54159 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 08:56:11.917690" r2d2 68.12.104.178 45886 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 08:56:11.917706" r2d2 68.12.104.178 45886 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 08:56:17.079596" r2d2 68.12.104.178 45589 68.12.99.2 53 UDP DNS (megascor).no-ip.biz "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 08:56:17.079600" r2d2 68.12.104.178 45589 68.12.99.2 53 UDP DNS (megascor).no-ip.biz "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 08:56:22.390201" r2d2 68.12.104.178 51447 68.12.99.2 53 UDP DNS (workcompsolutions).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:56:22.390194" r2d2 68.12.104.178 51447 68.12.99.2 53 UDP DNS (workcompsolutions).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:56:30.188027" r2d2 68.12.104.178 54913 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 08:56:30.188028" r2d2 68.12.104.178 54913 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 08:56:38.737897" r2d2 68.12.104.178 47777 113.108.80.138 53 UDP IP 113.108.80.138 dnspod (custom)\n' +
    '"2015-03-10 08:56:38.737899" r2d2 68.12.104.178 47777 113.108.80.138 53 UDP IP 113.108.80.138 dnspod (custom)\n' +
    '"2015-03-10 08:56:39.514216" r2d2 68.12.104.178 43283 108.175.157.56 53 UDP IP 108.175.157.56 c&c emergingthreats.net\n' +
    '"2015-03-10 08:56:39.514211" r2d2 68.12.104.178 43283 108.175.157.56 53 UDP IP 108.175.157.56 c&c emergingthreats.net\n' +
    '"2015-03-10 08:56:46.848752" r2d2 68.12.104.178 41599 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 08:56:46.848754" r2d2 68.12.104.178 41599 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 08:56:51.332036" r2d2 68.12.104.178 46006 68.12.99.2 53 UDP DNS (mailcluster01.cbs).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:56:51.332035" r2d2 68.12.104.178 46006 68.12.99.2 53 UDP DNS (mailcluster01.cbs).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:57:00.521960" r2d2 68.12.104.178 43513 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 08:57:00.521958" r2d2 68.12.104.178 43513 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 08:57:08.019718" r2d2 68.12.104.178 42807 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 08:57:08.019719" r2d2 68.12.104.178 42807 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 08:57:09.093089" r2d2 68.12.104.178 49665 68.12.99.2 53 UDP DNS (exebug).linkpc.net "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 08:57:09.093091" r2d2 68.12.104.178 49665 68.12.99.2 53 UDP DNS (exebug).linkpc.net "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 08:57:20.384324" r2d2 68.12.104.178 41846 198.58.92.228 53 UDP IP 198.58.92.228 malware cybercrime-tracker.net\n' +
    '"2015-03-10 08:57:20.384327" r2d2 68.12.104.178 41846 198.58.92.228 53 UDP IP 198.58.92.228 malware cybercrime-tracker.net\n' +
    '"2015-03-10 08:57:38.202113" r2d2 68.12.104.178 40927 68.12.99.2 53 UDP DNS peer.pickeklosarske.ru "palevo (malware)" (static)\n' +
    '"2015-03-10 08:57:38.817171" r2d2 68.12.104.178 47331 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 08:57:38.817174" r2d2 68.12.104.178 47331 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 08:57:39.142946" r2d2 68.12.104.178 51088 68.12.99.2 53 UDP DNS (megascor).no-ip.biz "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 08:57:39.142945" r2d2 68.12.104.178 51088 68.12.99.2 53 UDP DNS (megascor).no-ip.biz "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 08:57:39.283532" r2d2 68.12.104.178 58835 68.12.99.2 53 UDP DNS (lms).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:57:39.283530" r2d2 68.12.104.178 58835 68.12.99.2 53 UDP DNS (lms).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:57:42.517097" r2d2 68.12.104.178 48130 95.154.24.73 53 UDP IP 95.154.24.73 "tor exit node" torproject.org\n' +
    '"2015-03-10 08:57:54.074296" r2d2 68.12.104.178 35380 68.12.99.2 53 UDP DNS (icr).ddns.net "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 08:57:54.074297" r2d2 68.12.104.178 35380 68.12.99.2 53 UDP DNS (icr).ddns.net "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 08:58:01.670976" r2d2 68.12.104.178 57338 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 08:58:01.670978" r2d2 68.12.104.178 57338 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 08:58:02.014526" r2d2 68.12.104.178 59755 68.12.99.2 53 UDP DNS (awax).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:58:02.014522" r2d2 68.12.104.178 59755 68.12.99.2 53 UDP DNS (awax).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:58:09.646684" r2d2 68.12.104.178 50489 68.12.99.2 53 UDP DNS pica.banjalucke-ljepotice.ru "palevo (malware)" (static)\n' +
    '"2015-03-10 08:58:09.646683" r2d2 68.12.104.178 50489 68.12.99.2 53 UDP DNS pica.banjalucke-ljepotice.ru "palevo (malware)" (static)\n' +
    '"2015-03-10 08:58:32.503657" r2d2 68.12.104.178 48273 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 08:58:32.503656" r2d2 68.12.104.178 48273 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 08:58:35.902216" r2d2 68.12.104.178 46290 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 08:58:35.902205" r2d2 68.12.104.178 46290 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 08:58:40.842479" r2d2 68.12.104.178 51531 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 08:58:40.842490" r2d2 68.12.104.178 51531 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 08:58:44.740590" r2d2 68.12.104.178 55063 50.97.99.2 53 UDP IP 50.97.99.2 geodo (static)\n' +
    '"2015-03-10 08:58:44.740575" r2d2 68.12.104.178 40752 50.97.99.2 53 UDP IP 50.97.99.2 geodo (static)\n' +
    '"2015-03-10 08:58:44.740588" r2d2 68.12.104.178 55063 50.97.99.2 53 UDP IP 50.97.99.2 geodo (static)\n' +
    '"2015-03-10 08:58:44.740570" r2d2 68.12.104.178 40752 50.97.99.2 53 UDP IP 50.97.99.2 geodo (static)\n' +
    '"2015-03-10 08:58:44.878918" r2d2 68.12.104.178 55082 50.97.99.2 53 UDP IP 50.97.99.2 geodo (static)\n' +
    '"2015-03-10 08:58:44.878920" r2d2 68.12.104.178 55082 50.97.99.2 53 UDP IP 50.97.99.2 geodo (static)\n' +
    '"2015-03-10 08:58:45.338388" r2d2 68.12.104.178 38372 50.97.99.2 53 UDP IP 50.97.99.2 geodo (static)\n' +
    '"2015-03-10 08:58:45.338401" r2d2 68.12.104.178 38372 50.97.99.2 53 UDP IP 50.97.99.2 geodo (static)\n' +
    '"2015-03-10 08:58:47.042230" r2d2 68.12.104.178 48731 50.97.99.2 53 UDP IP 50.97.99.2 geodo (static)\n' +
    '"2015-03-10 08:58:47.042228" r2d2 68.12.104.178 48731 50.97.99.2 53 UDP IP 50.97.99.2 geodo (static)\n' +
    '"2015-03-10 08:58:58.479332" r2d2 68.12.104.178 39896 68.12.99.2 53 UDP DNS (www.galileomauritius).dnsdynamic.com "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 08:58:58.479338" r2d2 68.12.104.178 39896 68.12.99.2 53 UDP DNS (www.galileomauritius).dnsdynamic.com "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 08:59:02.198883" r2d2 68.12.104.178 56009 68.12.99.2 53 UDP DNS (megascor).no-ip.biz "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 08:59:02.198884" r2d2 68.12.104.178 56009 68.12.99.2 53 UDP DNS (megascor).no-ip.biz "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 08:59:11.657015" r2d2 68.12.104.178 35639 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 08:59:11.657016" r2d2 68.12.104.178 35639 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 08:59:16.895419" r2d2 68.12.104.178 44626 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 08:59:16.895418" r2d2 68.12.104.178 44626 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 08:59:31.456056" r2d2 68.12.104.178 53377 68.12.99.2 53 UDP DNS digitalmind.cn "palevo (malware)" palevotracker.abuse.ch\n' +
    '"2015-03-10 08:59:31.456060" r2d2 68.12.104.178 53377 68.12.99.2 53 UDP DNS digitalmind.cn "palevo (malware)" palevotracker.abuse.ch\n' +
    '"2015-03-10 08:59:34.166117" r2d2 68.12.104.178 55400 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 08:59:34.166118" r2d2 68.12.104.178 55400 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 08:59:42.397999" r2d2 68.12.104.178 55111 68.12.99.2 53 UDP DNS wanadoo.es attackpage safebrowsing.clients.google.com\n' +
    '"2015-03-10 08:59:42.398000" r2d2 68.12.104.178 55111 68.12.99.2 53 UDP DNS wanadoo.es attackpage safebrowsing.clients.google.com\n' +
    '"2015-03-10 08:59:47.106610" r2d2 68.12.104.178 50000 68.12.99.2 53 UDP DNS counter.yadro.ru "zeroaccess (malware)" (static)\n' +
    '"2015-03-10 08:59:47.106612" r2d2 68.12.104.178 50000 68.12.99.2 53 UDP DNS counter.yadro.ru "zeroaccess (malware)" (static)\n' +
    '"2015-03-10 08:59:47.578053" r2d2 68.12.104.178 59864 68.12.99.2 53 UDP DNS (pcc).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:59:47.578089" r2d2 68.12.104.178 59864 68.12.99.2 53 UDP DNS (pcc).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:59:47.695382" r2d2 68.12.104.178 44948 68.12.99.2 53 UDP DNS (mail.pcc).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:59:47.695402" r2d2 68.12.104.178 44948 68.12.99.2 53 UDP DNS (mail.pcc).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 08:59:49.844327" r2d2 68.12.104.178 42462 68.12.99.2 53 UDP DNS zalil.ru dorifel (static)\n' +
    '"2015-03-10 08:59:49.844328" r2d2 68.12.104.178 42462 68.12.99.2 53 UDP DNS zalil.ru dorifel (static)\n' +
    '"2015-03-10 08:59:50.199112" r2d2 68.12.104.178 39237 68.12.99.2 53 UDP DNS zalil.ru dorifel (static)\n' +
    '"2015-03-10 08:59:50.199115" r2d2 68.12.104.178 39237 68.12.99.2 53 UDP DNS zalil.ru dorifel (static)\n' +
    '"2015-03-10 08:59:50.484424" r2d2 68.12.104.178 57355 8.8.8.8 53 UDP DNS zalil.ru dorifel (static)\n' +
    '"2015-03-10 08:59:50.484427" r2d2 68.12.104.178 57355 8.8.8.8 53 UDP DNS zalil.ru dorifel (static)\n' +
    '"2015-03-10 08:59:50.945342" r2d2 68.12.104.178 43005 8.8.4.4 53 UDP DNS zalil.ru dorifel (static)\n' +
    '"2015-03-10 08:59:50.945330" r2d2 68.12.104.178 43005 8.8.4.4 53 UDP DNS zalil.ru dorifel (static)\n' +
    '"2015-03-10 09:00:05.012117" r2d2 68.12.104.178 45478 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 09:00:05.012119" r2d2 68.12.104.178 45478 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 09:00:05.614344" r2d2 68.12.104.178 56647 68.12.99.2 53 UDP DNS peer.pickeklosarske.ru "palevo (malware)" (static)\n' +
    '"2015-03-10 09:00:05.614348" r2d2 68.12.104.178 56647 68.12.99.2 53 UDP DNS peer.pickeklosarske.ru "palevo (malware)" (static)\n' +
    '"2015-03-10 09:00:07.984660" r2d2 68.12.104.178 38841 68.12.99.2 53 UDP DNS jimster480.com malware malwarepatrol.net\n' +
    '"2015-03-10 09:00:07.984648" r2d2 68.12.104.178 38841 68.12.99.2 53 UDP DNS jimster480.com malware malwarepatrol.net\n' +
    '"2015-03-10 09:00:13.277547" r2d2 68.12.104.178 59833 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 09:00:13.277558" r2d2 68.12.104.178 59833 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 09:00:24.268362" r2d2 68.12.104.178 46859 68.12.99.2 53 UDP DNS (megascor).no-ip.biz "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 09:00:24.268363" r2d2 68.12.104.178 46859 68.12.99.2 53 UDP DNS (megascor).no-ip.biz "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 09:00:38.923782" r2d2 68.12.104.178 52632 209.62.65.146 53 UDP IP 209.62.65.146 attacker blocklist.de\n' +
    '"2015-03-10 09:00:38.923783" r2d2 68.12.104.178 52632 209.62.65.146 53 UDP IP 209.62.65.146 attacker blocklist.de\n' +
    '"2015-03-10 09:00:38.980953" r2d2 68.12.104.178 54133 209.62.65.146 53 UDP IP 209.62.65.146 attacker blocklist.de\n' +
    '"2015-03-10 09:00:38.981542" r2d2 68.12.104.178 35917 209.62.65.146 53 UDP IP 209.62.65.146 attacker blocklist.de\n' +
    '"2015-03-10 09:00:38.981531" r2d2 68.12.104.178 35917 209.62.65.146 53 UDP IP 209.62.65.146 attacker blocklist.de\n' +
    '"2015-03-10 09:00:38.980954" r2d2 68.12.104.178 54133 209.62.65.146 53 UDP IP 209.62.65.146 attacker blocklist.de\n' +
    '"2015-03-10 09:00:39.082231" r2d2 68.12.104.178 50785 68.12.99.2 53 UDP DNS (westerra).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:00:39.082229" r2d2 68.12.104.178 50785 68.12.99.2 53 UDP DNS (westerra).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:00:44.091506" r2d2 68.12.104.178 35371 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 09:00:44.091508" r2d2 68.12.104.178 35371 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 09:00:47.670907" r2d2 68.12.104.178 46359 68.12.99.2 53 UDP DNS (ns11).cdnvideo.ru "pushdo (malware)" (static)\n' +
    '"2015-03-10 09:00:47.670909" r2d2 68.12.104.178 46359 68.12.99.2 53 UDP DNS (ns11).cdnvideo.ru "pushdo (malware)" (static)\n' +
    '"2015-03-10 09:00:47.671633" r2d2 68.12.104.178 54068 68.12.99.2 53 UDP DNS (ns13).cdnvideo.ru "pushdo (malware)" (static)\n' +
    '"2015-03-10 09:00:47.671634" r2d2 68.12.104.178 54068 68.12.99.2 53 UDP DNS (ns13).cdnvideo.ru "pushdo (malware)" (static)\n' +
    '"2015-03-10 09:00:48.990100" r2d2 68.12.104.178 52253 68.12.99.2 53 UDP DNS (brightlounge).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:00:48.990102" r2d2 68.12.104.178 52253 68.12.99.2 53 UDP DNS (brightlounge).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:00:49.342975" r2d2 68.12.104.178 47417 68.12.99.2 53 UDP DNS browsestudio.com malware malwareurls.joxeankoret.com\n' +
    '"2015-03-10 09:00:49.342974" r2d2 68.12.104.178 47417 68.12.99.2 53 UDP DNS browsestudio.com malware malwareurls.joxeankoret.com\n' +
    '"2015-03-10 09:00:58.230446" r2d2 68.12.104.178 47363 113.108.80.138 53 UDP IP 113.108.80.138 dnspod (custom)\n' +
    '"2015-03-10 09:00:58.230447" r2d2 68.12.104.178 47363 113.108.80.138 53 UDP IP 113.108.80.138 dnspod (custom)\n' +
    '"2015-03-10 09:01:02.929334" r2d2 68.12.104.178 46089 209.62.65.146 53 UDP IP 209.62.65.146 attacker blocklist.de\n' +
    '"2015-03-10 09:01:02.929338" r2d2 68.12.104.178 46089 209.62.65.146 53 UDP IP 209.62.65.146 attacker blocklist.de\n' +
    '"2015-03-10 09:01:05.553717" r2d2 68.12.104.178 52968 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 09:01:05.553715" r2d2 68.12.104.178 52968 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 09:01:06.629078" r2d2 68.12.104.178 50381 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 09:01:06.629076" r2d2 68.12.104.178 50381 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 09:01:14.257601" r2d2 68.12.104.178 37141 113.108.80.138 53 UDP IP 113.108.80.138 dnspod (custom)\n' +
    '"2015-03-10 09:01:14.257618" r2d2 68.12.104.178 37141 113.108.80.138 53 UDP IP 113.108.80.138 dnspod (custom)\n' +
    '"2015-03-10 09:01:16.940396" r2d2 68.12.104.178 49763 68.12.99.2 53 UDP DNS teske.pornicarke.com "palevo (malware)" (static)\n' +
    '"2015-03-10 09:01:16.940395" r2d2 68.12.104.178 49763 68.12.99.2 53 UDP DNS teske.pornicarke.com "palevo (malware)" (static)\n' +
    '"2015-03-10 09:01:24.049160" r2d2 71.6.167.142 12842 68.12.104.178 8443 TCP IP 71.6.167.142 "supermicro bmc password disclosure attempt" autoshun.org\n' +
    '"2015-03-10 09:01:24.049164" r2d2 71.6.167.142 12842 68.12.104.178 8443 TCP IP 71.6.167.142 "supermicro bmc password disclosure attempt" autoshun.org\n' +
    '"2015-03-10 09:01:37.456578" r2d2 68.12.104.178 56874 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 09:01:37.456577" r2d2 68.12.104.178 56874 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 09:01:45.674143" r2d2 68.12.104.178 59250 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 09:01:45.674157" r2d2 68.12.104.178 59250 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 09:01:46.310589" r2d2 68.12.104.178 40971 68.12.99.2 53 UDP DNS (megascor).no-ip.biz "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 09:01:46.310590" r2d2 68.12.104.178 40971 68.12.99.2 53 UDP DNS (megascor).no-ip.biz "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 09:01:46.955829" r2d2 68.12.104.178 40945 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 09:01:46.955828" r2d2 68.12.104.178 40945 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 09:01:52.245826" r2d2 68.12.104.178 44012 68.12.99.2 53 UDP DNS (cybergun).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:01:52.245840" r2d2 68.12.104.178 44012 68.12.99.2 53 UDP DNS (cybergun).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:01:57.010833" r2d2 68.12.104.178 45955 68.12.99.2 53 UDP DNS (mikecomputer).no-ip.biz "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 09:01:57.010834" r2d2 68.12.104.178 45955 68.12.99.2 53 UDP DNS (mikecomputer).no-ip.biz "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 09:02:16.510584" r2d2 68.12.104.178 52244 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 09:02:16.510588" r2d2 68.12.104.178 52244 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 09:02:20.147018" r2d2 68.12.104.178 39677 68.12.99.2 53 UDP DNS promisex.ru "zeus (malware)" (custom)\n' +
    '"2015-03-10 09:02:20.147017" r2d2 68.12.104.178 39677 68.12.99.2 53 UDP DNS promisex.ru "zeus (malware)" (custom)\n' +
    '"2015-03-10 09:02:24.022934" r2d2 68.12.104.178 58106 198.58.92.228 53 UDP IP 198.58.92.228 malware cybercrime-tracker.net\n' +
    '"2015-03-10 09:02:24.022926" r2d2 68.12.104.178 58106 198.58.92.228 53 UDP IP 198.58.92.228 malware cybercrime-tracker.net\n' +
    '"2015-03-10 09:02:24.320860" r2d2 68.12.104.178 45300 198.58.92.228 53 UDP IP 198.58.92.228 malware cybercrime-tracker.net\n' +
    '"2015-03-10 09:02:24.320863" r2d2 68.12.104.178 45300 198.58.92.228 53 UDP IP 198.58.92.228 malware cybercrime-tracker.net\n' +
    '"2015-03-10 09:02:25.271022" r2d2 68.12.104.178 49994 68.12.99.2 53 UDP DNS (extratorrent).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:02:25.271010" r2d2 68.12.104.178 49994 68.12.99.2 53 UDP DNS (extratorrent).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:02:25.363113" r2d2 68.12.104.178 38987 198.58.92.228 53 UDP IP 198.58.92.228 malware cybercrime-tracker.net\n' +
    '"2015-03-10 09:02:25.363071" r2d2 68.12.104.178 38987 198.58.92.228 53 UDP IP 198.58.92.228 malware cybercrime-tracker.net\n' +
    '"2015-03-10 09:02:27.009835" r2d2 68.12.104.178 55037 68.12.99.2 53 UDP DNS (ns3.oped).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:02:27.009833" r2d2 68.12.104.178 55037 68.12.99.2 53 UDP DNS (ns3.oped).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:02:27.010334" r2d2 68.12.104.178 37045 68.12.99.2 53 UDP DNS (ns4.oped).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:02:27.010332" r2d2 68.12.104.178 37045 68.12.99.2 53 UDP DNS (ns4.oped).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:02:35.455200" r2d2 68.12.104.178 36363 68.12.99.2 53 UDP DNS peer.pickeklosarske.ru "palevo (malware)" (static)\n' +
    '"2015-03-10 09:02:35.455199" r2d2 68.12.104.178 36363 68.12.99.2 53 UDP DNS peer.pickeklosarske.ru "palevo (malware)" (static)\n' +
    '"2015-03-10 09:02:39.102502" r2d2 68.12.104.178 45222 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 09:02:39.102501" r2d2 68.12.104.178 45222 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 09:03:08.507572" r2d2 68.12.104.178 41374 68.12.99.2 53 UDP DNS (pipo).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:03:10.189563" r2d2 68.12.104.178 45988 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 09:03:10.189564" r2d2 68.12.104.178 45988 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 09:03:13.834803" r2d2 68.12.104.178 38623 91.223.182.171 53 UDP IP 91.223.182.171 attacker blocklist.de\n' +
    '"2015-03-10 09:03:13.834791" r2d2 68.12.104.178 38623 91.223.182.171 53 UDP IP 91.223.182.171 attacker blocklist.de\n' +
    '"2015-03-10 09:03:14.069862" r2d2 68.12.104.178 35639 68.12.99.2 53 UDP DNS (ns2.via).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:03:14.069173" r2d2 68.12.104.178 46989 68.12.99.2 53 UDP DNS (ns1.via).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:03:14.069174" r2d2 68.12.104.178 46989 68.12.99.2 53 UDP DNS (ns1.via).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:03:14.069872" r2d2 68.12.104.178 35639 68.12.99.2 53 UDP DNS (ns2.via).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:03:18.073113" r2d2 68.12.104.178 38984 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 09:03:18.073111" r2d2 68.12.104.178 38984 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 09:03:35.376200" r2d2 68.12.104.178 42863 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 09:03:35.376203" r2d2 68.12.104.178 42863 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 09:03:35.400961" r2d2 68.12.104.178 53316 68.12.99.2 53 UDP DNS (www.socskrb.hr).ipaddress.com "suspicious ipinfo" (static)\n' +
    '"2015-03-10 09:03:35.400960" r2d2 68.12.104.178 53316 68.12.99.2 53 UDP DNS (www.socskrb.hr).ipaddress.com "suspicious ipinfo" (static)\n' +
    '"2015-03-10 09:03:35.795223" r2d2 68.12.104.178 49090 68.12.99.2 53 UDP DNS (ricefamily).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:03:35.795226" r2d2 68.12.104.178 49090 68.12.99.2 53 UDP DNS (ricefamily).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:03:35.818139" r2d2 68.12.104.178 56013 68.12.99.2 53 UDP DNS ipaddress.com "suspicious ipinfo" (static)\n' +
    '"2015-03-10 09:03:35.818137" r2d2 68.12.104.178 56013 68.12.99.2 53 UDP DNS ipaddress.com "suspicious ipinfo" (static)\n' +
    '"2015-03-10 09:03:35.884026" r2d2 68.12.104.178 59501 68.12.99.2 53 UDP DNS (c).ipaddress.com "suspicious ipinfo" (static)\n' +
    '"2015-03-10 09:03:35.884028" r2d2 68.12.104.178 59501 68.12.99.2 53 UDP DNS (c).ipaddress.com "suspicious ipinfo" (static)\n' +
    '"2015-03-10 09:03:48.902612" r2d2 68.12.104.178 35941 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 09:03:48.902615" r2d2 68.12.104.178 35941 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 09:04:10.241736" r2d2 68.12.104.178 52199 68.12.99.2 53 UDP DNS (megascor).no-ip.biz "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 09:04:10.241747" r2d2 68.12.104.178 52199 68.12.99.2 53 UDP DNS (megascor).no-ip.biz "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 09:04:10.289326" r2d2 68.12.104.178 54564 68.12.99.2 53 UDP DNS (mx2.spamfilter).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:04:10.289325" r2d2 68.12.104.178 54564 68.12.99.2 53 UDP DNS (mx2.spamfilter).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:04:11.827019" r2d2 68.12.104.178 41799 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 09:04:11.827000" r2d2 68.12.104.178 41799 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 09:04:17.034646" r2d2 68.12.104.178 54227 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 09:04:17.034645" r2d2 68.12.104.178 54227 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 09:04:42.659488" r2d2 68.12.104.178 55001 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 09:04:42.659491" r2d2 68.12.104.178 55001 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 09:04:50.490135" r2d2 68.12.104.178 48590 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 09:04:50.490138" r2d2 68.12.104.178 48590 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 09:04:50.910424" r2d2 68.12.104.178 47955 68.12.99.2 53 UDP DNS (dns1.systemhaus).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:04:50.910653" r2d2 68.12.104.178 50046 68.12.99.2 53 UDP DNS (dns2.systemhaus).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:04:50.910655" r2d2 68.12.104.178 50046 68.12.99.2 53 UDP DNS (dns2.systemhaus).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:04:50.909946" r2d2 68.12.104.178 55849 68.12.99.2 53 UDP DNS (sms.systemhaus).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:04:50.909951" r2d2 68.12.104.178 55849 68.12.99.2 53 UDP DNS (sms.systemhaus).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:04:50.910423" r2d2 68.12.104.178 47955 68.12.99.2 53 UDP DNS (dns1.systemhaus).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:05:05.265870" r2d2 68.12.104.178 35746 68.12.99.2 53 UDP DNS peer.pickeklosarske.ru "palevo (malware)" (static)\n' +
    '"2015-03-10 09:05:05.265872" r2d2 68.12.104.178 35746 68.12.99.2 53 UDP DNS peer.pickeklosarske.ru "palevo (malware)" (static)\n' +
    '"2015-03-10 09:05:21.299835" r2d2 68.12.104.178 51054 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 09:05:21.299833" r2d2 68.12.104.178 51054 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 09:05:33.390812" r2d2 68.12.104.178 47528 68.12.99.2 53 UDP DNS (megascor).no-ip.biz "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 09:05:33.390813" r2d2 68.12.104.178 47528 68.12.99.2 53 UDP DNS (megascor).no-ip.biz "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 09:05:40.065133" r2d2 68.12.104.178 52857 68.12.99.2 53 UDP DNS digitalmind.cn "palevo (malware)" palevotracker.abuse.ch\n' +
    '"2015-03-10 09:05:40.065132" r2d2 68.12.104.178 52857 68.12.99.2 53 UDP DNS digitalmind.cn "palevo (malware)" palevotracker.abuse.ch\n' +
    '"2015-03-10 09:05:40.509312" r2d2 68.12.104.178 47435 113.108.80.138 53 UDP IP 113.108.80.138 dnspod (custom)\n' +
    '"2015-03-10 09:05:40.509310" r2d2 68.12.104.178 47435 113.108.80.138 53 UDP IP 113.108.80.138 dnspod (custom)\n' +
    '"2015-03-10 09:05:43.989601" r2d2 68.12.104.178 39831 207.188.93.162 53 UDP IP 207.188.93.162 abuser openbl.org\n' +
    '"2015-03-10 09:05:43.989602" r2d2 68.12.104.178 39831 207.188.93.162 53 UDP IP 207.188.93.162 abuser openbl.org\n' +
    '"2015-03-10 09:05:44.268542" r2d2 68.12.104.178 53954 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 09:05:44.268543" r2d2 68.12.104.178 53954 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 09:05:49.620261" r2d2 68.12.104.178 43976 68.12.99.2 53 UDP DNS (intermarket).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:05:49.620260" r2d2 68.12.104.178 43976 68.12.99.2 53 UDP DNS (intermarket).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:05:54.530447" r2d2 68.12.104.178 51719 113.108.80.138 53 UDP IP 113.108.80.138 dnspod (custom)\n' +
    '"2015-03-10 09:05:54.530437" r2d2 68.12.104.178 51719 113.108.80.138 53 UDP IP 113.108.80.138 dnspod (custom)\n' +
    '"2015-03-10 09:06:05.217197" r2d2 68.12.104.178 45380 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 09:06:05.217194" r2d2 68.12.104.178 45380 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 09:06:10.260295" r2d2 68.12.104.178 47338 113.108.80.138 53 UDP IP 113.108.80.138 dnspod (custom)\n' +
    '"2015-03-10 09:06:10.260293" r2d2 68.12.104.178 47338 113.108.80.138 53 UDP IP 113.108.80.138 dnspod (custom)\n' +
    '"2015-03-10 09:06:10.738230" r2d2 68.12.104.178 46558 68.12.99.2 53 UDP DNS superfish.com superfish (static)\n' +
    '"2015-03-10 09:06:10.738233" r2d2 68.12.104.178 46558 68.12.99.2 53 UDP DNS superfish.com superfish (static)\n' +
    '"2015-03-10 09:06:15.096657" r2d2 68.12.104.178 35210 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 09:06:15.096655" r2d2 68.12.104.178 35210 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 09:06:15.834835" r2d2 68.12.104.178 46081 84.124.94.52 53 UDP IP 84.124.94.52 "asprox (malware)" atrack.h3x.eu\n' +
    '"2015-03-10 09:06:15.834836" r2d2 68.12.104.178 46081 84.124.94.52 53 UDP IP 84.124.94.52 "asprox (malware)" atrack.h3x.eu\n' +
    '"2015-03-10 09:06:16.030644" r2d2 68.12.104.178 48192 84.124.94.52 53 UDP IP 84.124.94.52 "asprox (malware)" atrack.h3x.eu\n' +
    '"2015-03-10 09:06:16.030629" r2d2 68.12.104.178 48192 84.124.94.52 53 UDP IP 84.124.94.52 "asprox (malware)" atrack.h3x.eu\n' +
    '"2015-03-10 09:06:16.449967" r2d2 68.12.104.178 59492 84.124.94.52 53 UDP IP 84.124.94.52 "asprox (malware)" atrack.h3x.eu\n' +
    '"2015-03-10 09:06:16.449969" r2d2 68.12.104.178 59492 84.124.94.52 53 UDP IP 84.124.94.52 "asprox (malware)" atrack.h3x.eu\n' +
    '"2015-03-10 09:06:21.407795" r2d2 68.12.104.178 46694 89.31.76.20 53 UDP IP 89.31.76.20 attacker blocklist.de\n' +
    '"2015-03-10 09:06:21.407796" r2d2 68.12.104.178 46694 89.31.76.20 53 UDP IP 89.31.76.20 attacker blocklist.de\n' +
    '"2015-03-10 09:06:21.407974" r2d2 68.12.104.178 56904 89.31.76.20 53 UDP IP 89.31.76.20 attacker blocklist.de\n' +
    '"2015-03-10 09:06:21.407971" r2d2 68.12.104.178 56904 89.31.76.20 53 UDP IP 89.31.76.20 attacker blocklist.de\n' +
    '"2015-03-10 09:06:22.893048" r2d2 68.12.104.178 47252 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 09:06:22.893049" r2d2 68.12.104.178 47252 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 09:06:34.736217" r2d2 68.12.104.178 40953 68.12.99.2 53 UDP DNS (cyberstudy).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:06:34.736216" r2d2 68.12.104.178 40953 68.12.99.2 53 UDP DNS (cyberstudy).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:06:40.622836" r2d2 68.12.104.178 59846 68.12.99.2 53 UDP DNS (mailcluster04.cbs).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:06:40.622829" r2d2 68.12.104.178 59846 68.12.99.2 53 UDP DNS (mailcluster04.cbs).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:06:46.552227" r2d2 68.12.104.178 57056 68.12.99.2 53 UDP DNS (ns1.bitonline).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:06:46.552226" r2d2 68.12.104.178 57056 68.12.99.2 53 UDP DNS (ns1.bitonline).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:06:46.552240" r2d2 68.12.104.178 45019 68.12.99.2 53 UDP DNS (ns2.bitonline).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:06:46.552239" r2d2 68.12.104.178 45019 68.12.99.2 53 UDP DNS (ns2.bitonline).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:06:47.112124" r2d2 68.12.104.178 51067 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 09:06:47.112126" r2d2 68.12.104.178 51067 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 09:06:53.720573" r2d2 68.12.104.178 55235 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 09:06:53.720572" r2d2 68.12.104.178 55235 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 09:07:16.705670" r2d2 68.12.104.178 45852 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 09:07:16.705669" r2d2 68.12.104.178 45852 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 09:07:35.106937" r2d2 68.12.104.178 35896 68.12.99.2 53 UDP DNS peer.pickeklosarske.ru "palevo (malware)" (static)\n' +
    '"2015-03-10 09:07:35.106939" r2d2 68.12.104.178 35896 68.12.99.2 53 UDP DNS peer.pickeklosarske.ru "palevo (malware)" (static)\n' +
    '"2015-03-10 09:07:35.798617" r2d2 68.12.104.178 35923 117.120.5.218 53 UDP IP 117.120.5.218 abuser openbl.org\n' +
    '"2015-03-10 09:07:35.798619" r2d2 68.12.104.178 35923 117.120.5.218 53 UDP IP 117.120.5.218 abuser openbl.org\n' +
    '"2015-03-10 09:07:47.533567" r2d2 68.12.104.178 38530 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 09:07:47.533558" r2d2 68.12.104.178 38530 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 09:07:55.264222" r2d2 68.12.104.178 47453 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 09:07:55.264219" r2d2 68.12.104.178 47453 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 09:08:00.224753" r2d2 68.12.104.178 57328 68.12.99.2 53 UDP DNS (nmm).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:08:00.224758" r2d2 68.12.104.178 57328 68.12.99.2 53 UDP DNS (nmm).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:08:01.698759" r2d2 68.12.104.178 56701 118.127.52.221 53 UDP IP 118.127.52.221 "asprox (malware)" atrack.h3x.eu\n' +
    '"2015-03-10 09:08:01.698745" r2d2 68.12.104.178 56701 118.127.52.221 53 UDP IP 118.127.52.221 "asprox (malware)" atrack.h3x.eu\n' +
    '"2015-03-10 09:08:14.524016" r2d2 68.12.104.178 37123 68.12.99.2 53 UDP DNS (synology).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:08:14.524018" r2d2 68.12.104.178 37123 68.12.99.2 53 UDP DNS (synology).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:08:15.430533" r2d2 68.12.104.178 45772 68.12.99.2 53 UDP DNS (ecu).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:08:15.430550" r2d2 68.12.104.178 45772 68.12.99.2 53 UDP DNS (ecu).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:08:26.091878" r2d2 68.12.104.178 55065 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 09:08:26.091877" r2d2 68.12.104.178 55065 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 09:08:35.052812" r2d2 68.12.104.178 42371 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 09:08:35.052817" r2d2 68.12.104.178 42371 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 09:08:42.303420" r2d2 68.12.104.178 41519 113.108.80.138 53 UDP IP 113.108.80.138 dnspod (custom)\n' +
    '"2015-03-10 09:08:42.303418" r2d2 68.12.104.178 41519 113.108.80.138 53 UDP IP 113.108.80.138 dnspod (custom)\n' +
    '"2015-03-10 09:08:43.683085" r2d2 68.12.104.178 50803 68.12.99.2 53 UDP DNS (megascor).no-ip.biz "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 09:08:43.683086" r2d2 68.12.104.178 50803 68.12.99.2 53 UDP DNS (megascor).no-ip.biz "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 09:08:44.302018" r2d2 68.12.104.178 39943 68.12.99.2 53 UDP DNS (ns3.olven).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:08:44.302020" r2d2 68.12.104.178 39943 68.12.99.2 53 UDP DNS (ns3.olven).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:08:44.302547" r2d2 68.12.104.178 45734 68.12.99.2 53 UDP DNS (ns5.olven).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:08:44.302658" r2d2 68.12.104.178 41678 68.12.99.2 53 UDP DNS (ns5.olven).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:08:44.302549" r2d2 68.12.104.178 45734 68.12.99.2 53 UDP DNS (ns5.olven).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:08:44.302670" r2d2 68.12.104.178 41678 68.12.99.2 53 UDP DNS (ns5.olven).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:08:49.143447" r2d2 68.12.104.178 49593 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 09:08:49.143446" r2d2 68.12.104.178 49593 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 09:08:55.117396" r2d2 68.12.104.178 49101 68.12.99.2 53 UDP DNS (ns3.bitonline).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:08:55.117402" r2d2 68.12.104.178 49101 68.12.99.2 53 UDP DNS (ns3.bitonline).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:08:55.167250" r2d2 68.12.104.178 45286 68.12.99.2 53 UDP DNS (mx1.bitonline).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:08:55.167257" r2d2 68.12.104.178 45286 68.12.99.2 53 UDP DNS (mx1.bitonline).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:08:58.310281" r2d2 68.12.104.178 51290 113.108.80.138 53 UDP IP 113.108.80.138 dnspod (custom)\n' +
    '"2015-03-10 09:08:58.310280" r2d2 68.12.104.178 51290 113.108.80.138 53 UDP IP 113.108.80.138 dnspod (custom)\n' +
    '"2015-03-10 09:09:17.230936" r2d2 68.12.104.178 35952 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 09:09:17.230935" r2d2 68.12.104.178 35952 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 09:09:19.970291" r2d2 68.12.104.178 47796 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 09:09:19.970293" r2d2 68.12.104.178 47796 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 09:09:21.165471" r2d2 68.12.104.178 59995 68.153.37.23 53 UDP IP 68.153.37.23 abuser openbl.org\n' +
    '"2015-03-10 09:09:27.159033" r2d2 68.12.104.178 49532 68.12.99.2 53 UDP DNS (niklasson).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:09:27.159009" r2d2 68.12.104.178 49532 68.12.99.2 53 UDP DNS (niklasson).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:09:27.688371" r2d2 68.12.104.178 39218 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 09:09:27.688375" r2d2 68.12.104.178 39218 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 09:09:49.236226" r2d2 68.12.104.178 36037 68.12.99.2 53 UDP DNS (qualityplumbing).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:09:49.236224" r2d2 68.12.104.178 36037 68.12.99.2 53 UDP DNS (qualityplumbing).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:09:58.493618" r2d2 68.12.104.178 43098 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 09:09:58.493615" r2d2 68.12.104.178 43098 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 09:10:04.950634" r2d2 68.12.104.178 54285 68.12.99.2 53 UDP DNS peer.pickeklosarske.ru "palevo (malware)" (static)\n' +
    '"2015-03-10 09:10:04.950631" r2d2 68.12.104.178 54285 68.12.99.2 53 UDP DNS peer.pickeklosarske.ru "palevo (malware)" (static)\n' +
    '"2015-03-10 09:10:21.588153" r2d2 68.12.104.178 51234 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 09:10:21.588152" r2d2 68.12.104.178 51234 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 09:10:24.309827" r2d2 68.12.104.178 56067 198.58.92.228 53 UDP IP 198.58.92.228 malware cybercrime-tracker.net\n' +
    '"2015-03-10 09:10:24.309825" r2d2 68.12.104.178 56067 198.58.92.228 53 UDP IP 198.58.92.228 malware cybercrime-tracker.net\n' +
    '"2015-03-10 09:10:24.449831" r2d2 68.12.104.178 59192 198.58.92.228 53 UDP IP 198.58.92.228 malware cybercrime-tracker.net\n' +
    '"2015-03-10 09:10:24.449829" r2d2 68.12.104.178 59192 198.58.92.228 53 UDP IP 198.58.92.228 malware cybercrime-tracker.net\n' +
    '"2015-03-10 09:10:26.185468" r2d2 68.12.104.178 45855 68.12.99.2 53 UDP DNS (ns.infopro.spb).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:10:26.185467" r2d2 68.12.104.178 45855 68.12.99.2 53 UDP DNS (ns.infopro.spb).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:10:26.186011" r2d2 68.12.104.178 38837 68.12.99.2 53 UDP DNS (ns2.infopro.spb).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:10:26.186008" r2d2 68.12.104.178 38837 68.12.99.2 53 UDP DNS (ns2.infopro.spb).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:10:33.848015" r2d2 68.12.104.178 47062 113.108.80.138 53 UDP IP 113.108.80.138 dnspod (custom)\n' +
    '"2015-03-10 09:10:33.848012" r2d2 68.12.104.178 47062 113.108.80.138 53 UDP IP 113.108.80.138 dnspod (custom)\n' +
    '"2015-03-10 09:10:45.642216" r2d2 68.12.104.178 40278 68.12.99.2 53 UDP DNS (tracker.coppersurfer).tk "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:10:45.642215" r2d2 68.12.104.178 40278 68.12.99.2 53 UDP DNS (tracker.coppersurfer).tk "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:10:45.732952" r2d2 68.12.104.178 45281 68.12.99.2 53 UDP DNS (tracker.coppersurfer).tk "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:10:45.732953" r2d2 68.12.104.178 45281 68.12.99.2 53 UDP DNS (tracker.coppersurfer).tk "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:10:49.857968" r2d2 68.12.104.178 58571 113.108.80.138 53 UDP IP 113.108.80.138 dnspod (custom)\n' +
    '"2015-03-10 09:10:49.857967" r2d2 68.12.104.178 58571 113.108.80.138 53 UDP IP 113.108.80.138 dnspod (custom)\n' +
    '"2015-03-10 09:10:52.407869" r2d2 68.12.104.178 53220 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 09:10:52.407868" r2d2 68.12.104.178 53220 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 09:10:55.316397" r2d2 68.12.104.178 49960 68.12.99.2 53 UDP DNS (mx.cloudafrica).email "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:10:55.316396" r2d2 68.12.104.178 49960 68.12.99.2 53 UDP DNS (mx.cloudafrica).email "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:10:55.467320" r2d2 68.12.104.178 44133 68.12.99.2 53 UDP DNS (mx01.cloudafrica).email "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:10:55.467316" r2d2 68.12.104.178 44133 68.12.99.2 53 UDP DNS (mx01.cloudafrica).email "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:10:56.048239" r2d2 68.12.104.178 57355 8.8.8.8 53 UDP DNS (brightlounge).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:10:56.048241" r2d2 68.12.104.178 57355 8.8.8.8 53 UDP DNS (brightlounge).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:11:00.085081" r2d2 68.12.104.178 49808 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 09:11:00.085082" r2d2 68.12.104.178 49808 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 09:11:04.516175" r2d2 68.12.104.178 51009 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 09:11:04.516177" r2d2 68.12.104.178 51009 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 09:11:09.507631" r2d2 68.12.104.178 49771 68.12.99.2 53 UDP DNS (tracker.coppersurfer).tk "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:11:09.507632" r2d2 68.12.104.178 49771 68.12.99.2 53 UDP DNS (tracker.coppersurfer).tk "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:11:17.250554" r2d2 68.12.104.178 59006 68.12.99.2 53 UDP DNS teske.pornicarke.com "palevo (malware)" (static)\n' +
    '"2015-03-10 09:11:21.545827" r2d2 68.12.104.178 50048 198.58.93.56 53 UDP IP 198.58.93.56 malware cybercrime-tracker.net\n' +
    '"2015-03-10 09:11:21.545828" r2d2 68.12.104.178 50048 198.58.93.56 53 UDP IP 198.58.93.56 malware cybercrime-tracker.net\n' +
    '"2015-03-10 09:11:24.896663" r2d2 68.12.104.178 43058 68.12.99.2 53 UDP DNS browsestudio.com malware malwareurls.joxeankoret.com\n' +
    '"2015-03-10 09:11:24.896664" r2d2 68.12.104.178 43058 68.12.99.2 53 UDP DNS browsestudio.com malware malwareurls.joxeankoret.com\n' +
    '"2015-03-10 09:11:30.905204" r2d2 68.12.104.178 47645 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 09:11:30.905203" r2d2 68.12.104.178 47645 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 09:11:42.406337" r2d2 68.12.104.178 39425 68.12.99.2 53 UDP DNS (hames).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:11:42.406336" r2d2 68.12.104.178 39425 68.12.99.2 53 UDP DNS (hames).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:11:44.123651" r2d2 68.12.104.178 56230 68.12.99.2 53 UDP DNS (megascor).no-ip.biz "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 09:11:44.123652" r2d2 68.12.104.178 56230 68.12.99.2 53 UDP DNS (megascor).no-ip.biz "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 09:11:44.339118" r2d2 68.12.104.178 40737 68.12.99.2 53 UDP DNS (mcse).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:11:44.339116" r2d2 68.12.104.178 40737 68.12.99.2 53 UDP DNS (mcse).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:11:47.263801" r2d2 68.12.104.178 51297 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 09:11:47.263800" r2d2 68.12.104.178 51297 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 09:11:47.405691" r2d2 68.12.104.178 35613 68.12.99.2 53 UDP DNS (aine).no-ip.biz "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 09:11:47.405694" r2d2 68.12.104.178 35613 68.12.99.2 53 UDP DNS (aine).no-ip.biz "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 09:11:49.894277" r2d2 68.12.104.178 56008 68.12.99.2 53 UDP DNS digitalmind.cn "palevo (malware)" palevotracker.abuse.ch\n' +
    '"2015-03-10 09:11:49.894272" r2d2 68.12.104.178 56008 68.12.99.2 53 UDP DNS digitalmind.cn "palevo (malware)" palevotracker.abuse.ch\n' +
    '"2015-03-10 09:11:54.267002" r2d2 68.12.104.178 36132 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 09:11:54.267007" r2d2 68.12.104.178 36132 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 09:12:02.067532" r2d2 68.12.104.178 46919 68.12.99.2 53 UDP DNS (errors).ourdatagenserv.com malware malwareurls.joxeankoret.com\n' +
    '"2015-03-10 09:12:02.067534" r2d2 68.12.104.178 46919 68.12.99.2 53 UDP DNS (errors).ourdatagenserv.com malware malwareurls.joxeankoret.com\n' +
    '"2015-03-10 09:12:34.239792" r2d2 68.12.104.178 45804 68.12.99.2 53 UDP DNS peer.pickeklosarske.ru "palevo (malware)" (static)\n' +
    '"2015-03-10 09:12:34.239793" r2d2 68.12.104.178 45804 68.12.99.2 53 UDP DNS peer.pickeklosarske.ru "palevo (malware)" (static)\n' +
    '"2015-03-10 09:12:40.409609" r2d2 68.12.104.178 45254 68.12.99.2 53 UDP DNS promisex.ru "zeus (malware)" (custom)\n' +
    '"2015-03-10 09:12:40.409608" r2d2 68.12.104.178 45254 68.12.99.2 53 UDP DNS promisex.ru "zeus (malware)" (custom)\n' +
    '"2015-03-10 09:13:14.032547" r2d2 68.12.104.178 59634 76.74.184.23 53 UDP IP 76.74.184.23 "feodo c&c" feodotracker.abuse.ch\n' +
    '"2015-03-10 09:13:14.032553" r2d2 68.12.104.178 59634 76.74.184.23 53 UDP IP 76.74.184.23 "feodo c&c" feodotracker.abuse.ch\n' +
    '"2015-03-10 09:13:18.246902" r2d2 68.12.104.178 36074 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 09:13:18.246939" r2d2 68.12.104.178 36074 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 09:13:23.386889" r2d2 68.12.104.178 41141 68.12.99.2 53 UDP DNS (blackroses).tk "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:13:23.386906" r2d2 68.12.104.178 41141 68.12.99.2 53 UDP DNS (blackroses).tk "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:13:23.433455" r2d2 68.12.104.178 41189 68.12.99.2 53 UDP DNS (mx-host.dot).tk "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:13:23.433460" r2d2 68.12.104.178 41189 68.12.99.2 53 UDP DNS (mx-host.dot).tk "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:13:33.187564" r2d2 68.12.104.178 47206 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 09:13:33.187562" r2d2 68.12.104.178 47206 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 09:13:41.659208" r2d2 68.12.104.178 50171 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 09:13:41.659207" r2d2 68.12.104.178 50171 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 09:13:48.279213" r2d2 68.12.104.178 44487 68.12.99.2 53 UDP DNS (megascor).no-ip.biz "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 09:13:48.279225" r2d2 68.12.104.178 44487 68.12.99.2 53 UDP DNS (megascor).no-ip.biz "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 09:13:54.091000" r2d2 68.12.104.178 56231 68.12.99.2 53 UDP DNS (moy).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:13:54.090999" r2d2 68.12.104.178 56231 68.12.99.2 53 UDP DNS (moy).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:14:09.889221" r2d2 68.12.104.178 49282 68.12.99.2 53 UDP DNS (ns1.jtr).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:14:09.889526" r2d2 68.12.104.178 53685 68.12.99.2 53 UDP DNS (ns2.jtr).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:14:09.889218" r2d2 68.12.104.178 49282 68.12.99.2 53 UDP DNS (ns1.jtr).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:14:09.889985" r2d2 68.12.104.178 43742 68.12.99.2 53 UDP DNS (ns4.jtr).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:14:09.889528" r2d2 68.12.104.178 53685 68.12.99.2 53 UDP DNS (ns2.jtr).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:14:09.889971" r2d2 68.12.104.178 57611 68.12.99.2 53 UDP DNS (ns3.jtr).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:14:09.889974" r2d2 68.12.104.178 57611 68.12.99.2 53 UDP DNS (ns3.jtr).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:14:09.889982" r2d2 68.12.104.178 43742 68.12.99.2 53 UDP DNS (ns4.jtr).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:14:12.516467" r2d2 68.12.104.178 50484 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 09:14:12.516468" r2d2 68.12.104.178 50484 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 09:14:17.437237" r2d2 68.12.104.178 57046 68.12.99.2 53 UDP DNS (olle67).ddns.net "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 09:14:17.437232" r2d2 68.12.104.178 57046 68.12.99.2 53 UDP DNS (olle67).ddns.net "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 09:14:17.711813" r2d2 68.12.104.178 51171 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 09:14:17.711814" r2d2 68.12.104.178 51171 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 09:14:19.797920" r2d2 68.12.104.178 42023 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 09:14:19.797916" r2d2 68.12.104.178 42023 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 09:14:27.994660" r2d2 68.12.104.178 41988 68.12.99.2 53 UDP DNS (orcas).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:14:27.994669" r2d2 68.12.104.178 41988 68.12.99.2 53 UDP DNS (orcas).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:14:28.582214" r2d2 68.12.104.178 53274 50.63.202.70 53 UDP IP 50.63.202.70 c&c emergingthreats.net\n' +
    '"2015-03-10 09:14:28.582217" r2d2 68.12.104.178 53274 50.63.202.70 53 UDP IP 50.63.202.70 c&c emergingthreats.net\n' +
    '"2015-03-10 09:14:31.107559" r2d2 68.12.104.178 36054 68.12.99.2 53 UDP DNS jebena.ananikolic.su "palevo (malware)" (static)\n' +
    '"2015-03-10 09:14:31.107535" r2d2 68.12.104.178 36054 68.12.99.2 53 UDP DNS jebena.ananikolic.su "palevo (malware)" (static)\n' +
    '"2015-03-10 09:14:36.836674" r2d2 68.12.104.178 46395 68.12.99.2 53 UDP DNS (reichl).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:14:36.836661" r2d2 68.12.104.178 46395 68.12.99.2 53 UDP DNS (reichl).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:14:38.624586" r2d2 68.12.104.178 38193 68.12.99.2 53 UDP DNS (ns5.praxisnet).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:14:38.625142" r2d2 68.12.104.178 39620 68.12.99.2 53 UDP DNS (ns6.praxisnet).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:14:38.624587" r2d2 68.12.104.178 38193 68.12.99.2 53 UDP DNS (ns5.praxisnet).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:14:38.625146" r2d2 68.12.104.178 39620 68.12.99.2 53 UDP DNS (ns6.praxisnet).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:14:44.585495" r2d2 68.12.104.178 57910 50.63.202.70 53 UDP IP 50.63.202.70 c&c emergingthreats.net\n' +
    '"2015-03-10 09:14:44.585496" r2d2 68.12.104.178 57910 50.63.202.70 53 UDP IP 50.63.202.70 c&c emergingthreats.net\n' +
    '"2015-03-10 09:14:45.234839" r2d2 68.12.104.178 47612 68.12.99.2 53 UDP DNS (wap).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:14:45.234828" r2d2 68.12.104.178 47612 68.12.99.2 53 UDP DNS (wap).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:14:50.637048" r2d2 68.12.104.178 57319 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 09:14:50.637047" r2d2 68.12.104.178 57319 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 09:14:55.059751" r2d2 68.12.104.178 59982 68.12.99.2 53 UDP DNS (tysseng).ddns.net "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 09:14:55.059754" r2d2 68.12.104.178 59982 68.12.99.2 53 UDP DNS (tysseng).ddns.net "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 09:14:59.113851" r2d2 68.12.104.178 50068 68.12.99.2 53 UDP DNS sureioratte.ru "zeus (malware)" zeustracker.abuse.ch\n' +
    '"2015-03-10 09:14:59.113852" r2d2 68.12.104.178 50068 68.12.99.2 53 UDP DNS sureioratte.ru "zeus (malware)" zeustracker.abuse.ch\n' +
    '"2015-03-10 09:15:00.146074" r2d2 68.12.104.178 35394 68.12.99.2 53 UDP DNS peer.pickeklosarske.ru "palevo (malware)" (static)\n' +
    '"2015-03-10 09:15:00.146071" r2d2 68.12.104.178 35394 68.12.99.2 53 UDP DNS peer.pickeklosarske.ru "palevo (malware)" (static)\n' +
    '"2015-03-10 09:15:08.176279" r2d2 222.186.21.202 6000 68.12.104.178 5901 TCP IP 222.186.21.202 attacker blocklist.de\n' +
    '"2015-03-10 09:15:08.176281" r2d2 222.186.21.202 6000 68.12.104.178 5901 TCP IP 222.186.21.202 attacker blocklist.de\n' +
    '"2015-03-10 09:15:11.063175" r2d2 68.12.104.178 46689 68.12.99.2 53 UDP DNS (ns1).torpig-sinkhole.org "torpig (malware)" (static)\n' +
    '"2015-03-10 09:15:11.063135" r2d2 68.12.104.178 45970 68.12.99.2 53 UDP DNS (ns1).torpig-sinkhole.org "torpig (malware)" (static)\n' +
    '"2015-03-10 09:15:11.063137" r2d2 68.12.104.178 45970 68.12.99.2 53 UDP DNS (ns1).torpig-sinkhole.org "torpig (malware)" (static)\n' +
    '"2015-03-10 09:15:11.063184" r2d2 68.12.104.178 46689 68.12.99.2 53 UDP DNS (ns1).torpig-sinkhole.org "torpig (malware)" (static)\n' +
    '"2015-03-10 09:15:11.064150" r2d2 68.12.104.178 45966 68.12.99.2 53 UDP DNS (ns2).torpig-sinkhole.org "torpig (malware)" (static)\n' +
    '"2015-03-10 09:15:11.063612" r2d2 68.12.104.178 42546 68.12.99.2 53 UDP DNS (ns2).torpig-sinkhole.org "torpig (malware)" (static)\n' +
    '"2015-03-10 09:15:11.063613" r2d2 68.12.104.178 42546 68.12.99.2 53 UDP DNS (ns2).torpig-sinkhole.org "torpig (malware)" (static)\n' +
    '"2015-03-10 09:15:11.064149" r2d2 68.12.104.178 45966 68.12.99.2 53 UDP DNS (ns2).torpig-sinkhole.org "torpig (malware)" (static)\n' +
    '"2015-03-10 09:15:11.093415" r2d2 68.12.104.178 47710 87.106.240.162 53 UDP IP 87.106.240.162 "torpig (malware)" (static)\n' +
    '"2015-03-10 09:15:11.094176" r2d2 68.12.104.178 36922 87.106.240.162 53 UDP IP 87.106.240.162 "torpig (malware)" (static)\n' +
    '"2015-03-10 09:15:11.093388" r2d2 68.12.104.178 47710 87.106.240.162 53 UDP IP 87.106.240.162 "torpig (malware)" (static)\n' +
    '"2015-03-10 09:15:11.094177" r2d2 68.12.104.178 36922 87.106.240.162 53 UDP IP 87.106.240.162 "torpig (malware)" (static)\n' +
    '"2015-03-10 09:15:11.121117" r2d2 68.12.104.178 43798 212.227.55.84 53 UDP IP 212.227.55.84 "torpig (malware)" (static)\n' +
    '"2015-03-10 09:15:11.121645" r2d2 68.12.104.178 42648 212.227.55.84 53 UDP IP 212.227.55.84 "torpig (malware)" (static)\n' +
    '"2015-03-10 09:15:11.121130" r2d2 68.12.104.178 43798 212.227.55.84 53 UDP IP 212.227.55.84 "torpig (malware)" (static)\n' +
    '"2015-03-10 09:15:11.121634" r2d2 68.12.104.178 42648 212.227.55.84 53 UDP IP 212.227.55.84 "torpig (malware)" (static)\n' +
    '"2015-03-10 09:15:11.150708" r2d2 68.12.104.178 50243 212.227.55.84 53 UDP IP 212.227.55.84 "torpig (malware)" (static)\n' +
    '"2015-03-10 09:15:11.150709" r2d2 68.12.104.178 50243 212.227.55.84 53 UDP IP 212.227.55.84 "torpig (malware)" (static)\n' +
    '"2015-03-10 09:15:14.141585" r2d2 68.12.104.178 57153 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 09:15:14.141587" r2d2 68.12.104.178 57153 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 09:15:37.550730" r2d2 68.12.104.178 38077 68.12.99.2 53 UDP DNS (megascor).no-ip.biz "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 09:15:37.550729" r2d2 68.12.104.178 38077 68.12.99.2 53 UDP DNS (megascor).no-ip.biz "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 09:15:43.345138" r2d2 68.12.104.178 47896 68.12.99.2 53 UDP DNS (ns2.thepromise).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:15:43.344830" r2d2 68.12.104.178 57947 68.12.99.2 53 UDP DNS (ns1.thepromise).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:15:43.344831" r2d2 68.12.104.178 57947 68.12.99.2 53 UDP DNS (ns1.thepromise).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:15:43.345183" r2d2 68.12.104.178 47896 68.12.99.2 53 UDP DNS (ns2.thepromise).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:15:45.079572" r2d2 68.12.104.178 47608 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 09:15:45.079571" r2d2 68.12.104.178 47608 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 09:15:52.272068" r2d2 68.12.104.178 53808 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 09:15:52.272069" r2d2 68.12.104.178 53808 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 09:15:53.853428" r2d2 68.12.104.178 46249 68.12.99.2 53 UDP DNS (saintjoseph).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:15:53.853430" r2d2 68.12.104.178 46249 68.12.99.2 53 UDP DNS (saintjoseph).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:15:57.881202" r2d2 68.12.104.178 47135 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 09:15:57.881205" r2d2 68.12.104.178 47135 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 09:16:01.693582" r2d2 68.12.104.178 49386 50.97.99.2 53 UDP IP 50.97.99.2 geodo (static)\n' +
    '"2015-03-10 09:16:01.693584" r2d2 68.12.104.178 49386 50.97.99.2 53 UDP IP 50.97.99.2 geodo (static)\n' +
    '"2015-03-10 09:16:02.009981" r2d2 68.12.104.178 47985 50.97.99.2 53 UDP IP 50.97.99.2 geodo (static)\n' +
    '"2015-03-10 09:16:02.009976" r2d2 68.12.104.178 47985 50.97.99.2 53 UDP IP 50.97.99.2 geodo (static)\n' +
    '"2015-03-10 09:16:03.965101" r2d2 68.12.104.178 56080 50.97.99.2 53 UDP IP 50.97.99.2 geodo (static)\n' +
    '"2015-03-10 09:16:03.965102" r2d2 68.12.104.178 56080 50.97.99.2 53 UDP IP 50.97.99.2 geodo (static)\n' +
    '"2015-03-10 09:16:09.515937" r2d2 68.12.104.178 41124 50.87.144.81 53 UDP IP 50.87.144.81 attacker blocklist.de\n' +
    '"2015-03-10 09:16:09.515938" r2d2 68.12.104.178 41124 50.87.144.81 53 UDP IP 50.87.144.81 attacker blocklist.de\n' +
    '"2015-03-10 09:16:10.504071" r2d2 68.12.104.178 36902 68.12.99.2 53 UDP DNS cychefs.com malware cybercrime-tracker.net\n' +
    '"2015-03-10 09:16:10.504075" r2d2 68.12.104.178 36902 68.12.99.2 53 UDP DNS cychefs.com malware cybercrime-tracker.net\n' +
    '"2015-03-10 09:16:20.747246" r2d2 68.12.104.178 43233 162.254.166.28 53 UDP IP 162.254.166.28 c&c emergingthreats.net\n' +
    '"2015-03-10 09:16:20.747241" r2d2 68.12.104.178 43233 162.254.166.28 53 UDP IP 162.254.166.28 c&c emergingthreats.net\n' +
    '"2015-03-10 09:16:21.476255" r2d2 68.12.104.178 44310 68.12.99.2 53 UDP DNS (sudano).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:16:21.476257" r2d2 68.12.104.178 44310 68.12.99.2 53 UDP DNS (sudano).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:16:23.104464" r2d2 68.12.104.178 54433 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 09:16:23.104462" r2d2 68.12.104.178 54433 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 09:16:36.198626" r2d2 68.12.104.178 51311 68.12.99.2 53 UDP DNS (www).superfish.com superfish (static)\n' +
    '"2015-03-10 09:16:36.198628" r2d2 68.12.104.178 51311 68.12.99.2 53 UDP DNS (www).superfish.com superfish (static)\n' +
    '"2015-03-10 09:16:36.393084" r2d2 68.12.104.178 48017 68.12.99.2 53 UDP DNS superfish.com superfish (static)\n' +
    '"2015-03-10 09:16:36.393082" r2d2 68.12.104.178 48017 68.12.99.2 53 UDP DNS superfish.com superfish (static)\n' +
    '"2015-03-10 09:16:37.213184" r2d2 68.12.104.178 48724 68.12.99.2 53 UDP DNS (ns4).tophostbg.net malware malwaredomainlist.com\n' +
    '"2015-03-10 09:16:37.213511" r2d2 68.12.104.178 45071 68.12.99.2 53 UDP DNS (ns5).tophostbg.net malware malwaredomainlist.com\n' +
    '"2015-03-10 09:16:37.213209" r2d2 68.12.104.178 48724 68.12.99.2 53 UDP DNS (ns4).tophostbg.net malware malwaredomainlist.com\n' +
    '"2015-03-10 09:16:37.213507" r2d2 68.12.104.178 45071 68.12.99.2 53 UDP DNS (ns5).tophostbg.net malware malwaredomainlist.com\n' +
    '"2015-03-10 09:16:39.517325" r2d2 68.12.104.178 47620 68.12.99.2 53 UDP DNS counter.yadro.ru "zeroaccess (malware)" (static)\n' +
    '"2015-03-10 09:16:39.517327" r2d2 68.12.104.178 47620 68.12.99.2 53 UDP DNS counter.yadro.ru "zeroaccess (malware)" (static)\n' +
    '"2015-03-10 09:16:46.533742" r2d2 68.12.104.178 57541 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 09:16:46.533739" r2d2 68.12.104.178 57541 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 09:16:47.625342" r2d2 68.12.104.178 46283 68.12.99.2 53 UDP DNS (megascor).no-ip.biz "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 09:16:47.625357" r2d2 68.12.104.178 46283 68.12.99.2 53 UDP DNS (megascor).no-ip.biz "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 09:16:49.970410" r2d2 68.12.104.178 43289 113.108.80.138 53 UDP IP 113.108.80.138 dnspod (custom)\n' +
    '"2015-03-10 09:16:49.970409" r2d2 68.12.104.178 43289 113.108.80.138 53 UDP IP 113.108.80.138 dnspod (custom)\n' +
    '"2015-03-10 09:16:52.993565" r2d2 68.12.104.178 49655 68.12.99.2 53 UDP DNS (lajf09).zapto.org "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 09:16:52.993594" r2d2 68.12.104.178 49655 68.12.99.2 53 UDP DNS (lajf09).zapto.org "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 09:17:05.985363" r2d2 68.12.104.178 55266 113.108.80.138 53 UDP IP 113.108.80.138 dnspod (custom)\n' +
    '"2015-03-10 09:17:05.985360" r2d2 68.12.104.178 55266 113.108.80.138 53 UDP IP 113.108.80.138 dnspod (custom)\n' +
    '"2015-03-10 09:17:16.216950" r2d2 68.12.104.178 57489 81.2.199.97 53 UDP IP 81.2.199.97 "asprox (malware)" atrack.h3x.eu\n' +
    '"2015-03-10 09:17:16.216952" r2d2 68.12.104.178 57489 81.2.199.97 53 UDP IP 81.2.199.97 "asprox (malware)" atrack.h3x.eu\n' +
    '"2015-03-10 09:17:17.532883" r2d2 68.12.104.178 46045 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 09:17:17.532879" r2d2 68.12.104.178 46045 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 09:17:24.723336" r2d2 68.12.104.178 51536 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 09:17:24.723334" r2d2 68.12.104.178 51536 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 09:17:27.128775" r2d2 68.12.104.178 42286 68.12.99.2 53 UDP DNS peer.pickeklosarske.ru "palevo (malware)" (static)\n' +
    '"2015-03-10 09:17:27.128773" r2d2 68.12.104.178 42286 68.12.99.2 53 UDP DNS peer.pickeklosarske.ru "palevo (malware)" (static)\n' +
    '"2015-03-10 09:17:55.549279" r2d2 68.12.104.178 39539 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 09:17:55.549294" r2d2 68.12.104.178 39539 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 09:17:58.612986" r2d2 68.12.104.178 37736 113.108.80.138 53 UDP IP 113.108.80.138 dnspod (custom)\n' +
    '"2015-03-10 09:17:58.612984" r2d2 68.12.104.178 37736 113.108.80.138 53 UDP IP 113.108.80.138 dnspod (custom)\n' +
    '"2015-03-10 09:17:59.738012" r2d2 68.12.104.178 40708 68.12.99.2 53 UDP DNS digitalmind.cn "palevo (malware)" palevotracker.abuse.ch\n' +
    '"2015-03-10 09:17:59.738010" r2d2 68.12.104.178 40708 68.12.99.2 53 UDP DNS digitalmind.cn "palevo (malware)" palevotracker.abuse.ch\n' +
    '"2015-03-10 09:18:14.633715" r2d2 68.12.104.178 43285 113.108.80.138 53 UDP IP 113.108.80.138 dnspod (custom)\n' +
    '"2015-03-10 09:18:26.613721" r2d2 68.12.104.178 41889 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 09:18:27.629437" r2d2 68.12.104.178 44348 68.12.99.2 53 UDP DNS (ns.chaban).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:18:27.629440" r2d2 68.12.104.178 44348 68.12.99.2 53 UDP DNS (ns.chaban).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:18:48.876960" r2d2 68.12.104.178 49620 68.12.99.2 53 UDP DNS movieroomreviews.com nuclear_ek malware-traffic-analysis.net\n' +
    '"2015-03-10 09:18:48.876958" r2d2 68.12.104.178 49620 68.12.99.2 53 UDP DNS movieroomreviews.com nuclear_ek malware-traffic-analysis.net\n' +
    '"2015-03-10 09:18:50.001821" r2d2 68.12.104.178 51793 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 09:18:50.001822" r2d2 68.12.104.178 51793 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 09:18:57.148041" r2d2 68.12.104.178 43613 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 09:18:57.148051" r2d2 68.12.104.178 43613 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 09:19:00.277605" r2d2 68.12.104.178 48363 68.12.99.2 53 UDP DNS (ofir).strangled.net "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:19:00.277597" r2d2 68.12.104.178 48363 68.12.99.2 53 UDP DNS (ofir).strangled.net "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:19:16.439207" r2d2 68.12.104.178 56242 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 09:19:16.439210" r2d2 68.12.104.178 56242 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 09:19:27.981426" r2d2 68.12.104.178 53621 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 09:19:27.981424" r2d2 68.12.104.178 53621 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 09:19:41.512399" r2d2 68.12.104.178 55130 68.12.99.2 53 UDP DNS (st.stattds).club "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:19:41.512398" r2d2 68.12.104.178 55130 68.12.99.2 53 UDP DNS (st.stattds).club "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:19:41.951384" r2d2 68.12.104.178 42025 68.12.99.2 53 UDP DNS (stattds).club "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:19:41.951380" r2d2 68.12.104.178 42025 68.12.99.2 53 UDP DNS (stattds).club "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:19:49.219068" r2d2 68.12.104.178 55134 68.12.99.2 53 UDP DNS (digicom).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:19:49.219067" r2d2 68.12.104.178 55134 68.12.99.2 53 UDP DNS (digicom).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:19:51.769051" r2d2 68.12.104.178 36796 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 09:19:56.062279" r2d2 68.12.104.178 52753 68.12.99.2 53 UDP DNS peer.pickeklosarske.ru "palevo (malware)" (static)\n' +
    '"2015-03-10 09:19:56.062263" r2d2 68.12.104.178 52753 68.12.99.2 53 UDP DNS peer.pickeklosarske.ru "palevo (malware)" (static)\n' +
    '"2015-03-10 09:20:10.520091" r2d2 68.12.104.178 37772 68.12.99.2 53 UDP DNS (ns01.oto).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:20:10.520090" r2d2 68.12.104.178 37772 68.12.99.2 53 UDP DNS (ns01.oto).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:20:21.112180" r2d2 68.12.104.178 50996 68.12.99.2 53 UDP DNS (megascor).no-ip.biz "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 09:20:21.112181" r2d2 68.12.104.178 50996 68.12.99.2 53 UDP DNS (megascor).no-ip.biz "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 09:20:22.593676" r2d2 68.12.104.178 59497 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 09:20:22.593677" r2d2 68.12.104.178 59497 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 09:20:29.598553" r2d2 68.12.104.178 38483 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 09:20:29.598551" r2d2 68.12.104.178 38483 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 09:20:55.316221" r2d2 68.12.104.178 36470 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 09:20:55.316220" r2d2 68.12.104.178 36470 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 09:21:00.433736" r2d2 68.12.104.178 51470 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 09:21:00.433738" r2d2 68.12.104.178 51470 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 09:21:24.204600" r2d2 68.12.104.178 56861 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 09:21:24.204601" r2d2 68.12.104.178 56861 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 09:21:35.536765" r2d2 68.12.104.178 37484 68.12.99.2 53 UDP DNS (brightlounge).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:21:35.536768" r2d2 68.12.104.178 37484 68.12.99.2 53 UDP DNS (brightlounge).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:21:42.072151" r2d2 68.12.104.178 49235 8.8.8.8 53 UDP DNS (brightlounge).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:21:42.072148" r2d2 68.12.104.178 49235 8.8.8.8 53 UDP DNS (brightlounge).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:21:46.360252" r2d2 68.12.104.178 35356 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 09:21:46.360254" r2d2 68.12.104.178 35356 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 09:21:55.032371" r2d2 68.12.104.178 53428 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 09:21:55.032370" r2d2 68.12.104.178 53428 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 09:22:02.031041" r2d2 68.12.104.178 35598 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 09:22:02.031039" r2d2 68.12.104.178 35598 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 09:22:24.169937" r2d2 68.12.104.178 35354 68.12.99.2 53 UDP DNS peer.pickeklosarske.ru "palevo (malware)" (static)\n' +
    '"2015-03-10 09:22:24.169935" r2d2 68.12.104.178 35354 68.12.99.2 53 UDP DNS peer.pickeklosarske.ru "palevo (malware)" (static)\n' +
    '"2015-03-10 09:22:32.858002" r2d2 68.12.104.178 38049 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 09:22:32.858000" r2d2 68.12.104.178 38049 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 09:22:42.996313" r2d2 68.12.104.178 42772 68.12.99.2 53 UDP DNS (k2s).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:22:42.996315" r2d2 68.12.104.178 42772 68.12.99.2 53 UDP DNS (k2s).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:22:43.390288" r2d2 68.12.104.178 36477 68.12.99.2 53 UDP DNS (static2.k2s).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:22:43.390286" r2d2 68.12.104.178 36477 68.12.99.2 53 UDP DNS (static2.k2s).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:22:53.747053" r2d2 68.12.104.178 41018 68.12.99.2 53 UDP DNS teske.pornicarke.com "palevo (malware)" (static)\n' +
    '"2015-03-10 09:22:53.747054" r2d2 68.12.104.178 41018 68.12.99.2 53 UDP DNS teske.pornicarke.com "palevo (malware)" (static)\n' +
    '"2015-03-10 09:22:55.640613" r2d2 68.12.104.178 39559 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 09:22:55.640615" r2d2 68.12.104.178 39559 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 09:23:01.749782" r2d2 68.12.104.178 41069 68.12.99.2 53 UDP DNS domefocrisis.ru "zeus (malware)" zeustracker.abuse.ch\n' +
    '"2015-03-10 09:23:01.749783" r2d2 68.12.104.178 41069 68.12.99.2 53 UDP DNS domefocrisis.ru "zeus (malware)" zeustracker.abuse.ch\n' +
    '"2015-03-10 09:23:10.089935" r2d2 68.12.104.178 42158 68.12.99.2 53 UDP DNS (static1.k2s).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:23:10.089939" r2d2 68.12.104.178 42158 68.12.99.2 53 UDP DNS (static1.k2s).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:23:19.524462" r2d2 68.12.104.178 58196 68.12.99.2 53 UDP DNS (api).browsestudio.com malware malwareurls.joxeankoret.com\n' +
    '"2015-03-10 09:23:19.524460" r2d2 68.12.104.178 58196 68.12.99.2 53 UDP DNS (api).browsestudio.com malware malwareurls.joxeankoret.com\n' +
    '"2015-03-10 09:23:19.683376" r2d2 68.12.104.178 38902 68.12.99.2 53 UDP DNS browsestudio.com malware malwareurls.joxeankoret.com\n' +
    '"2015-03-10 09:23:19.683363" r2d2 68.12.104.178 38902 68.12.99.2 53 UDP DNS browsestudio.com malware malwareurls.joxeankoret.com\n' +
    '"2015-03-10 09:23:23.304823" r2d2 68.12.104.178 54820 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 09:23:23.304826" r2d2 68.12.104.178 54820 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 09:23:25.984281" r2d2 68.12.104.178 43399 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 09:23:25.984283" r2d2 68.12.104.178 43399 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 09:23:27.463059" r2d2 68.12.104.178 41962 68.12.99.2 53 UDP DNS (megascor).no-ip.biz "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 09:23:27.463050" r2d2 68.12.104.178 41962 68.12.99.2 53 UDP DNS (megascor).no-ip.biz "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 09:23:34.467106" r2d2 68.12.104.178 37931 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 09:23:34.467109" r2d2 68.12.104.178 37931 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 09:24:05.292424" r2d2 68.12.104.178 50298 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 09:24:05.292426" r2d2 68.12.104.178 50298 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 09:24:09.457819" r2d2 68.12.104.178 50963 68.12.99.2 53 UDP DNS digitalmind.cn "palevo (malware)" palevotracker.abuse.ch\n' +
    '"2015-03-10 09:24:09.457830" r2d2 68.12.104.178 50963 68.12.99.2 53 UDP DNS digitalmind.cn "palevo (malware)" palevotracker.abuse.ch\n' +
    '"2015-03-10 09:24:16.421183" r2d2 68.12.104.178 37002 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 09:24:16.421171" r2d2 68.12.104.178 37002 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 09:24:27.609058" r2d2 68.12.104.178 55264 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 09:24:27.609091" r2d2 68.12.104.178 55264 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 09:24:32.016592" r2d2 68.12.104.178 35850 68.12.99.2 53 UDP DNS (slow-126.keep2share).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:24:32.016595" r2d2 68.12.104.178 35850 68.12.99.2 53 UDP DNS (slow-126.keep2share).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:24:32.602208" r2d2 68.12.104.178 50783 68.12.99.2 53 UDP DNS (slow-126.keep2share).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:24:32.602207" r2d2 68.12.104.178 50783 68.12.99.2 53 UDP DNS (slow-126.keep2share).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:24:36.461756" r2d2 68.12.104.178 40790 68.12.99.2 53 UDP DNS (nwmwwrigxjofmkpol).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:24:36.461738" r2d2 68.12.104.178 40790 68.12.99.2 53 UDP DNS (nwmwwrigxjofmkpol).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:24:36.635499" r2d2 68.12.104.178 57387 68.12.99.2 53 UDP DNS (fcgpokxypfurin).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:24:36.635500" r2d2 68.12.104.178 57387 68.12.99.2 53 UDP DNS (fcgpokxypfurin).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:24:36.696068" r2d2 68.12.104.178 47893 68.12.99.2 53 UDP DNS (tlmetrogsj).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:24:36.696070" r2d2 68.12.104.178 47893 68.12.99.2 53 UDP DNS (tlmetrogsj).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:24:36.734090" r2d2 68.12.104.178 46295 68.12.99.2 53 UDP DNS (tburiinomv).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:24:36.734088" r2d2 68.12.104.178 46295 68.12.99.2 53 UDP DNS (tburiinomv).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:24:37.013764" r2d2 68.12.104.178 46662 68.12.99.2 53 UDP DNS (ussyuxendpq).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:24:37.013759" r2d2 68.12.104.178 46662 68.12.99.2 53 UDP DNS (ussyuxendpq).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:24:37.073806" r2d2 68.12.104.178 43424 68.12.99.2 53 UDP DNS (tyfjxeckqbo).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:24:37.073803" r2d2 68.12.104.178 43424 68.12.99.2 53 UDP DNS (tyfjxeckqbo).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:24:37.233536" r2d2 68.12.104.178 53626 68.12.99.2 53 UDP DNS (enksgvkdtclfs).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:24:37.233539" r2d2 68.12.104.178 53626 68.12.99.2 53 UDP DNS (enksgvkdtclfs).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:24:37.332135" r2d2 68.12.104.178 38767 68.12.99.2 53 UDP DNS (vsqxboyqde).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:24:37.332133" r2d2 68.12.104.178 38767 68.12.99.2 53 UDP DNS (vsqxboyqde).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:24:37.477337" r2d2 68.12.104.178 55061 68.12.99.2 53 UDP DNS (gypnuwvydjdpfq).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:24:37.477342" r2d2 68.12.104.178 55061 68.12.99.2 53 UDP DNS (gypnuwvydjdpfq).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:24:37.513673" r2d2 68.12.104.178 36628 68.12.99.2 53 UDP DNS (erbjnidvgh).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:24:37.513674" r2d2 68.12.104.178 36628 68.12.99.2 53 UDP DNS (erbjnidvgh).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:24:37.701912" r2d2 68.12.104.178 36065 68.12.99.2 53 UDP DNS (xkjajenjswqncsi).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:24:37.701914" r2d2 68.12.104.178 36065 68.12.99.2 53 UDP DNS (xkjajenjswqncsi).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:24:38.143942" r2d2 68.12.104.178 54882 68.12.99.2 53 UDP DNS (iveuoqxdohyrmhcof).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:24:38.143940" r2d2 68.12.104.178 54882 68.12.99.2 53 UDP DNS (iveuoqxdohyrmhcof).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:24:38.281281" r2d2 68.12.104.178 38547 68.12.99.2 53 UDP DNS (asbmwwwrl).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:24:38.281282" r2d2 68.12.104.178 38547 68.12.99.2 53 UDP DNS (asbmwwwrl).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:24:38.633848" r2d2 68.12.104.178 47549 68.12.99.2 53 UDP DNS (nbniwyiamfsbugkenyjpd).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:24:38.633846" r2d2 68.12.104.178 47549 68.12.99.2 53 UDP DNS (nbniwyiamfsbugkenyjpd).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:24:38.801112" r2d2 68.12.104.178 59200 68.12.99.2 53 UDP DNS (yteypts).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:24:38.801114" r2d2 68.12.104.178 59200 68.12.99.2 53 UDP DNS (yteypts).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:24:38.890269" r2d2 68.12.104.178 42949 68.12.99.2 53 UDP DNS (vrmqckwm).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:24:38.890266" r2d2 68.12.104.178 42949 68.12.99.2 53 UDP DNS (vrmqckwm).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:24:39.109398" r2d2 68.12.104.178 43533 68.12.99.2 53 UDP DNS (brrwlvfxtaia).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:24:39.109399" r2d2 68.12.104.178 43533 68.12.99.2 53 UDP DNS (brrwlvfxtaia).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:24:39.115279" r2d2 68.12.104.178 43676 68.12.99.2 53 UDP DNS (paytxjgplh).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:24:39.115277" r2d2 68.12.104.178 43676 68.12.99.2 53 UDP DNS (paytxjgplh).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:24:39.478916" r2d2 68.12.104.178 37657 68.12.99.2 53 UDP DNS (jaeceglpxrycfkf).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:24:39.478914" r2d2 68.12.104.178 37657 68.12.99.2 53 UDP DNS (jaeceglpxrycfkf).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:24:39.519650" r2d2 68.12.104.178 37649 68.12.99.2 53 UDP DNS (eyphigsiqgkmrumur).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:24:39.519649" r2d2 68.12.104.178 37649 68.12.99.2 53 UDP DNS (eyphigsiqgkmrumur).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:24:40.604573" r2d2 68.12.104.178 49150 68.12.99.2 53 UDP DNS (kshotkykawjnvw).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:24:40.604575" r2d2 68.12.104.178 49150 68.12.99.2 53 UDP DNS (kshotkykawjnvw).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:24:40.792915" r2d2 68.12.104.178 35403 68.12.99.2 53 UDP DNS (qakjsundwigw).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:24:40.792916" r2d2 68.12.104.178 35403 68.12.99.2 53 UDP DNS (qakjsundwigw).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:24:40.827181" r2d2 68.12.104.178 42312 68.12.99.2 53 UDP DNS (ckbxwirugwck).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:24:40.827176" r2d2 68.12.104.178 42312 68.12.99.2 53 UDP DNS (ckbxwirugwck).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:24:40.902260" r2d2 68.12.104.178 49879 68.12.99.2 53 UDP DNS (kjbehpxwlufkcx).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:24:40.902264" r2d2 68.12.104.178 49879 68.12.99.2 53 UDP DNS (kjbehpxwlufkcx).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:24:40.907409" r2d2 68.12.104.178 50507 68.12.99.2 53 UDP DNS (jcydchkgarscg).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:24:40.907412" r2d2 68.12.104.178 50507 68.12.99.2 53 UDP DNS (jcydchkgarscg).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:24:41.032747" r2d2 68.12.104.178 36117 68.12.99.2 53 UDP DNS (eraxwqfikmc).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:24:41.032752" r2d2 68.12.104.178 36117 68.12.99.2 53 UDP DNS (eraxwqfikmc).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:24:41.369234" r2d2 68.12.104.178 39805 68.12.99.2 53 UDP DNS (mqeeqbrwupm).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:24:41.369232" r2d2 68.12.104.178 39805 68.12.99.2 53 UDP DNS (mqeeqbrwupm).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:24:41.440052" r2d2 68.12.104.178 48127 68.12.99.2 53 UDP DNS (lmxpvikwprmj).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:24:41.440053" r2d2 68.12.104.178 48127 68.12.99.2 53 UDP DNS (lmxpvikwprmj).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:24:41.714980" r2d2 68.12.104.178 52410 68.12.99.2 53 UDP DNS (ylhcikqsv).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:24:41.714982" r2d2 68.12.104.178 52410 68.12.99.2 53 UDP DNS (ylhcikqsv).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:24:41.970470" r2d2 68.12.104.178 45999 68.12.99.2 53 UDP DNS (vurfkwodmraiiqtmqopi).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:24:41.970466" r2d2 68.12.104.178 45999 68.12.99.2 53 UDP DNS (vurfkwodmraiiqtmqopi).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:24:42.296633" r2d2 68.12.104.178 37435 68.12.99.2 53 UDP DNS (puehkctpajn).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:24:42.296636" r2d2 68.12.104.178 37435 68.12.99.2 53 UDP DNS (puehkctpajn).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:24:42.379896" r2d2 68.12.104.178 49501 68.12.99.2 53 UDP DNS (mbmpmbhpl).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:24:42.379897" r2d2 68.12.104.178 49501 68.12.99.2 53 UDP DNS (mbmpmbhpl).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:24:42.932277" r2d2 68.12.104.178 48885 68.12.99.2 53 UDP DNS (dhntjoyse).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:24:42.932278" r2d2 68.12.104.178 48885 68.12.99.2 53 UDP DNS (dhntjoyse).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:24:43.347816" r2d2 68.12.104.178 56055 68.12.99.2 53 UDP DNS (qdvjvqrelna).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:24:43.347818" r2d2 68.12.104.178 56055 68.12.99.2 53 UDP DNS (qdvjvqrelna).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:24:43.970563" r2d2 68.12.104.178 40455 68.12.99.2 53 UDP DNS (wehuckdtdm).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:24:43.970565" r2d2 68.12.104.178 40455 68.12.99.2 53 UDP DNS (wehuckdtdm).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:24:44.872223" r2d2 68.12.104.178 40561 68.12.99.2 53 UDP DNS (hltkhcrjucqcmqrc).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:24:44.872222" r2d2 68.12.104.178 40561 68.12.99.2 53 UDP DNS (hltkhcrjucqcmqrc).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:24:45.950783" r2d2 68.12.104.178 41172 68.12.99.2 53 UDP DNS (aapfoxoie).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:24:45.950772" r2d2 68.12.104.178 41172 68.12.99.2 53 UDP DNS (aapfoxoie).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:24:46.046093" r2d2 68.12.104.178 58914 68.12.99.2 53 UDP DNS (gjiosnl).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:24:46.046095" r2d2 68.12.104.178 58914 68.12.99.2 53 UDP DNS (gjiosnl).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:24:46.301346" r2d2 68.12.104.178 35374 68.12.99.2 53 UDP DNS (egwdhbgweqcmpsk).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:24:46.301345" r2d2 68.12.104.178 35374 68.12.99.2 53 UDP DNS (egwdhbgweqcmpsk).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:24:46.473571" r2d2 68.12.104.178 41125 68.12.99.2 53 UDP DNS (plgiamfqvigdwj).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:24:46.473602" r2d2 68.12.104.178 41125 68.12.99.2 53 UDP DNS (plgiamfqvigdwj).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:24:46.511112" r2d2 68.12.104.178 37539 68.12.99.2 53 UDP DNS (psnoeykodpeymvy).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:24:46.511098" r2d2 68.12.104.178 37539 68.12.99.2 53 UDP DNS (psnoeykodpeymvy).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:24:47.892071" r2d2 68.12.104.178 35166 68.12.99.2 53 UDP DNS (sntyacoaditegysqhg).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:24:47.892075" r2d2 68.12.104.178 35166 68.12.99.2 53 UDP DNS (sntyacoaditegysqhg).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:24:47.910185" r2d2 68.12.104.178 56060 68.12.99.2 53 UDP DNS (feooutflcxoc).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:24:47.910168" r2d2 68.12.104.178 56060 68.12.99.2 53 UDP DNS (feooutflcxoc).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:24:48.083420" r2d2 68.12.104.178 35217 68.12.99.2 53 UDP DNS (hsmuepiemno).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:24:48.083422" r2d2 68.12.104.178 35217 68.12.99.2 53 UDP DNS (hsmuepiemno).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:24:48.522176" r2d2 68.12.104.178 39265 68.12.99.2 53 UDP DNS (mnwituubbok).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:24:48.522175" r2d2 68.12.104.178 39265 68.12.99.2 53 UDP DNS (mnwituubbok).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:24:48.624448" r2d2 68.12.104.178 50428 68.12.99.2 53 UDP DNS (yfrayyrchvgclcci).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:24:48.624449" r2d2 68.12.104.178 50428 68.12.99.2 53 UDP DNS (yfrayyrchvgclcci).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:24:48.691433" r2d2 68.12.104.178 40392 68.12.99.2 53 UDP DNS (xcorqmyioedncw).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:24:48.691428" r2d2 68.12.104.178 40392 68.12.99.2 53 UDP DNS (xcorqmyioedncw).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:24:50.340473" r2d2 68.12.104.178 46028 68.12.99.2 53 UDP DNS (nhfcubvcst).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:24:50.340475" r2d2 68.12.104.178 46028 68.12.99.2 53 UDP DNS (nhfcubvcst).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:24:50.510441" r2d2 68.12.104.178 35072 68.12.99.2 53 UDP DNS (ceiymicjifpncdebnu).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:24:50.510438" r2d2 68.12.104.178 35072 68.12.99.2 53 UDP DNS (ceiymicjifpncdebnu).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:24:50.815390" r2d2 68.12.104.178 49613 68.12.99.2 53 UDP DNS (srbqfeabymofcuglqlx).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:24:50.815388" r2d2 68.12.104.178 49613 68.12.99.2 53 UDP DNS (srbqfeabymofcuglqlx).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:24:50.908946" r2d2 68.12.104.178 38995 68.12.99.2 53 UDP DNS (frnmlmwvdyrgqucesits).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:24:50.908949" r2d2 68.12.104.178 38995 68.12.99.2 53 UDP DNS (frnmlmwvdyrgqucesits).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:24:51.999415" r2d2 68.12.104.178 45433 68.12.99.2 53 UDP DNS (gdssshqutbjg).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:24:51.999419" r2d2 68.12.104.178 45433 68.12.99.2 53 UDP DNS (gdssshqutbjg).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:24:52.072586" r2d2 68.12.104.178 37781 68.12.99.2 53 UDP DNS (ahnmtljhlayway).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:24:52.072589" r2d2 68.12.104.178 37781 68.12.99.2 53 UDP DNS (ahnmtljhlayway).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:24:53.166166" r2d2 68.12.104.178 38205 68.12.99.2 53 UDP DNS peer.pickeklosarske.ru "palevo (malware)" (static)\n' +
    '"2015-03-10 09:24:53.166163" r2d2 68.12.104.178 38205 68.12.99.2 53 UDP DNS peer.pickeklosarske.ru "palevo (malware)" (static)\n' +
    '"2015-03-10 09:24:54.366353" r2d2 68.12.104.178 54994 68.12.99.2 53 UDP DNS (bvtnvasdlmcduftmigc).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:24:54.366341" r2d2 68.12.104.178 54994 68.12.99.2 53 UDP DNS (bvtnvasdlmcduftmigc).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:24:54.481012" r2d2 68.12.104.178 45012 68.12.99.2 53 UDP DNS (uxuivdbl).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:24:54.481013" r2d2 68.12.104.178 45012 68.12.99.2 53 UDP DNS (uxuivdbl).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:24:55.053358" r2d2 68.12.104.178 44386 68.12.99.2 53 UDP DNS (lhopkqwyauphpj).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:24:55.053234" r2d2 68.12.104.178 44386 68.12.99.2 53 UDP DNS (lhopkqwyauphpj).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:24:55.297038" r2d2 68.12.104.178 35624 68.12.99.2 53 UDP DNS (ncxyoysqcurkwdxcobv).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:24:55.297028" r2d2 68.12.104.178 35624 68.12.99.2 53 UDP DNS (ncxyoysqcurkwdxcobv).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:24:55.397476" r2d2 68.12.104.178 41290 68.12.99.2 53 UDP DNS (dbmsimpbtpewyacsolpqg).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:24:55.397467" r2d2 68.12.104.178 41290 68.12.99.2 53 UDP DNS (dbmsimpbtpewyacsolpqg).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:24:55.567698" r2d2 68.12.104.178 43052 68.12.99.2 53 UDP DNS (yoxwscyfftr).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:24:55.567697" r2d2 68.12.104.178 43052 68.12.99.2 53 UDP DNS (yoxwscyfftr).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:24:56.234892" r2d2 68.12.104.178 48059 68.12.99.2 53 UDP DNS (gaiyrmgfqehdrv).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:24:56.234880" r2d2 68.12.104.178 48059 68.12.99.2 53 UDP DNS (gaiyrmgfqehdrv).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:24:56.678544" r2d2 68.12.104.178 48141 68.12.99.2 53 UDP DNS (ovubsmdcbmffulxrhsd).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:24:56.678546" r2d2 68.12.104.178 48141 68.12.99.2 53 UDP DNS (ovubsmdcbmffulxrhsd).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:24:56.698758" r2d2 68.12.104.178 53839 68.12.99.2 53 UDP DNS (cvdfuekvigfrnxfnpk).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:24:56.698760" r2d2 68.12.104.178 53839 68.12.99.2 53 UDP DNS (cvdfuekvigfrnxfnpk).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:24:57.065482" r2d2 68.12.104.178 54615 68.12.99.2 53 UDP DNS (vguorkteosy).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:24:57.065485" r2d2 68.12.104.178 54615 68.12.99.2 53 UDP DNS (vguorkteosy).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:24:57.619999" r2d2 68.12.104.178 53579 68.12.99.2 53 UDP DNS (gsomievmdpibw).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:24:57.620001" r2d2 68.12.104.178 53579 68.12.99.2 53 UDP DNS (gsomievmdpibw).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:24:58.207055" r2d2 68.12.104.178 39419 68.12.99.2 53 UDP DNS (nwdfugphavjylddcf).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:24:58.207053" r2d2 68.12.104.178 39419 68.12.99.2 53 UDP DNS (nwdfugphavjylddcf).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:24:58.437725" r2d2 68.12.104.178 37956 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 09:24:58.437721" r2d2 68.12.104.178 37956 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 09:24:58.758908" r2d2 68.12.104.178 56083 68.12.99.2 53 UDP DNS (qqkmrhouyxgl).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:24:58.758911" r2d2 68.12.104.178 56083 68.12.99.2 53 UDP DNS (qqkmrhouyxgl).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:24:59.316394" r2d2 68.12.104.178 35475 68.12.99.2 53 UDP DNS (rdhsqqeatpape).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:24:59.316398" r2d2 68.12.104.178 35475 68.12.99.2 53 UDP DNS (rdhsqqeatpape).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:25:00.020164" r2d2 68.12.104.178 36382 68.12.99.2 53 UDP DNS (nhxgaolisigaxcaaq).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:25:00.020163" r2d2 68.12.104.178 36382 68.12.99.2 53 UDP DNS (nhxgaolisigaxcaaq).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:25:00.154262" r2d2 68.12.104.178 53438 68.12.99.2 53 UDP DNS (yoihkvyneah).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:25:00.154263" r2d2 68.12.104.178 53438 68.12.99.2 53 UDP DNS (yoihkvyneah).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:25:00.532734" r2d2 68.12.104.178 36285 68.12.99.2 53 UDP DNS (tomfaakklyukbsrg).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:25:00.532736" r2d2 68.12.104.178 36285 68.12.99.2 53 UDP DNS (tomfaakklyukbsrg).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:25:00.682039" r2d2 68.12.104.178 39505 68.12.99.2 53 UDP DNS (kypbrupnjm).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:25:00.682040" r2d2 68.12.104.178 39505 68.12.99.2 53 UDP DNS (kypbrupnjm).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:25:02.525349" r2d2 68.12.104.178 52618 68.12.99.2 53 UDP DNS (yugpclyqofql).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:25:02.525348" r2d2 68.12.104.178 52618 68.12.99.2 53 UDP DNS (yugpclyqofql).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:25:04.681529" r2d2 68.12.104.178 43302 68.12.99.2 53 UDP DNS (bvlkxnt).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:25:04.681527" r2d2 68.12.104.178 43302 68.12.99.2 53 UDP DNS (bvlkxnt).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:25:06.107879" r2d2 68.12.104.178 59841 68.12.99.2 53 UDP DNS (bpulloppkoswireo).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:25:06.107878" r2d2 68.12.104.178 59841 68.12.99.2 53 UDP DNS (bpulloppkoswireo).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:25:06.901136" r2d2 68.12.104.178 56481 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 09:25:06.901125" r2d2 68.12.104.178 56481 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 09:25:07.339991" r2d2 68.12.104.178 45292 68.12.99.2 53 UDP DNS (rbjrbdscwfpkmbewimnw).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:25:07.339994" r2d2 68.12.104.178 45292 68.12.99.2 53 UDP DNS (rbjrbdscwfpkmbewimnw).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:25:07.793275" r2d2 68.12.104.178 43286 68.12.99.2 53 UDP DNS (fkywshdffenjkcommdpcp).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:25:07.793276" r2d2 68.12.104.178 43286 68.12.99.2 53 UDP DNS (fkywshdffenjkcommdpcp).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:25:08.019156" r2d2 68.12.104.178 47520 68.12.99.2 53 UDP DNS (mhtpalmgbpklryhvljs).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:25:08.019152" r2d2 68.12.104.178 47520 68.12.99.2 53 UDP DNS (mhtpalmgbpklryhvljs).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:25:08.791187" r2d2 68.12.104.178 56379 68.12.99.2 53 UDP DNS (gdlxxrdufrlnmo).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:25:08.791185" r2d2 68.12.104.178 56379 68.12.99.2 53 UDP DNS (gdlxxrdufrlnmo).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:25:09.397515" r2d2 68.12.104.178 38241 68.12.99.2 53 UDP DNS (hcarsjmhvpnen).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:25:09.397513" r2d2 68.12.104.178 38241 68.12.99.2 53 UDP DNS (hcarsjmhvpnen).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:25:09.675299" r2d2 68.12.104.178 58574 68.12.99.2 53 UDP DNS (alhlxqaxof).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:25:09.675297" r2d2 68.12.104.178 58574 68.12.99.2 53 UDP DNS (alhlxqaxof).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:25:09.715644" r2d2 68.12.104.178 37857 68.12.99.2 53 UDP DNS (esxqrqnaeevrgd).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:25:09.715643" r2d2 68.12.104.178 37857 68.12.99.2 53 UDP DNS (esxqrqnaeevrgd).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:25:10.177468" r2d2 68.12.104.178 56404 68.12.99.2 53 UDP DNS (diiojdftje).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:25:10.177467" r2d2 68.12.104.178 56404 68.12.99.2 53 UDP DNS (diiojdftje).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:25:10.428851" r2d2 68.12.104.178 36902 68.12.99.2 53 UDP DNS (uyqeudxqybqcqseou).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:25:10.428852" r2d2 68.12.104.178 36902 68.12.99.2 53 UDP DNS (uyqeudxqybqcqseou).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:25:11.073259" r2d2 68.12.104.178 37822 68.12.99.2 53 UDP DNS (hfdxsmmkilvf).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:25:13.507279" r2d2 68.12.104.178 46870 68.12.99.2 53 UDP DNS (nbcdtimwr).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:25:13.507283" r2d2 68.12.104.178 46870 68.12.99.2 53 UDP DNS (nbcdtimwr).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:25:15.428146" r2d2 68.12.104.178 55595 68.12.99.2 53 UDP DNS (nutwqorkjbgxo).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:25:15.428148" r2d2 68.12.104.178 55595 68.12.99.2 53 UDP DNS (nutwqorkjbgxo).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:25:27.567830" r2d2 68.12.104.178 38140 68.12.99.2 53 UDP DNS (htjvvkgrd).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:25:27.567832" r2d2 68.12.104.178 38140 68.12.99.2 53 UDP DNS (htjvvkgrd).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:25:28.332431" r2d2 68.12.104.178 55509 68.12.99.2 53 UDP DNS (ohihswxtf).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:25:28.332430" r2d2 68.12.104.178 55509 68.12.99.2 53 UDP DNS (ohihswxtf).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:25:29.642030" r2d2 68.12.104.178 58199 68.12.99.2 53 UDP DNS (wymbfqgy).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:25:29.642028" r2d2 68.12.104.178 58199 68.12.99.2 53 UDP DNS (wymbfqgy).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:25:29.920816" r2d2 68.12.104.178 55643 68.12.99.2 53 UDP DNS (nmmjymkprlsxyruiksvq).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:25:29.920819" r2d2 68.12.104.178 55643 68.12.99.2 53 UDP DNS (nmmjymkprlsxyruiksvq).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:25:30.382641" r2d2 68.12.104.178 47885 68.12.99.2 53 UDP DNS (yqmddygacl).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:25:30.382651" r2d2 68.12.104.178 47885 68.12.99.2 53 UDP DNS (yqmddygacl).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:25:32.536932" r2d2 68.12.104.178 37665 96.47.225.142 53 UDP IP 96.47.225.142 attacker blocklist.de\n' +
    '"2015-03-10 09:25:32.536948" r2d2 68.12.104.178 37665 96.47.225.142 53 UDP IP 96.47.225.142 attacker blocklist.de\n' +
    '"2015-03-10 09:25:34.785202" r2d2 68.12.104.178 48951 68.12.99.2 53 UDP DNS (giwbrwlgllswtch).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:25:34.785206" r2d2 68.12.104.178 48951 68.12.99.2 53 UDP DNS (giwbrwlgllswtch).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:25:37.727012" r2d2 68.12.104.178 36138 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 09:25:37.727010" r2d2 68.12.104.178 36138 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 09:25:43.180448" r2d2 68.12.104.178 57332 68.12.99.2 53 UDP DNS (pthdngfsyixqtswlvli).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:25:43.180447" r2d2 68.12.104.178 57332 68.12.99.2 53 UDP DNS (pthdngfsyixqtswlvli).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:25:53.205927" r2d2 68.12.104.178 37706 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 09:25:53.205929" r2d2 68.12.104.178 37706 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 09:25:55.324563" r2d2 68.12.104.178 37940 68.12.99.2 53 UDP DNS (megascor).no-ip.biz "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 09:25:55.324561" r2d2 68.12.104.178 37940 68.12.99.2 53 UDP DNS (megascor).no-ip.biz "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 09:26:00.046768" r2d2 68.12.104.178 48303 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 09:26:00.046774" r2d2 68.12.104.178 48303 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 09:26:31.014892" r2d2 68.12.104.178 56409 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 09:26:31.014890" r2d2 68.12.104.178 56409 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 09:26:39.336260" r2d2 68.12.104.178 51849 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 09:26:39.336258" r2d2 68.12.104.178 51849 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 09:26:46.466929" r2d2 68.12.104.178 35113 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 09:26:46.466924" r2d2 68.12.104.178 35113 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 09:27:10.161896" r2d2 68.12.104.178 36572 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 09:27:10.161883" r2d2 68.12.104.178 36572 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 09:27:22.100782" r2d2 68.12.104.178 40252 68.12.99.2 53 UDP DNS peer.pickeklosarske.ru "palevo (malware)" (static)\n' +
    '"2015-03-10 09:27:22.100779" r2d2 68.12.104.178 40252 68.12.99.2 53 UDP DNS peer.pickeklosarske.ru "palevo (malware)" (static)\n' +
    '"2015-03-10 09:27:32.625298" r2d2 68.12.104.178 59067 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 09:27:32.625300" r2d2 68.12.104.178 59067 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 09:27:35.269758" r2d2 68.12.104.178 45024 113.108.80.138 53 UDP IP 113.108.80.138 dnspod (custom)\n' +
    '"2015-03-10 09:27:35.269756" r2d2 68.12.104.178 45024 113.108.80.138 53 UDP IP 113.108.80.138 dnspod (custom)\n' +
    '"2015-03-10 09:27:58.021613" r2d2 68.12.104.178 41854 68.12.99.2 53 UDP DNS counter.yadro.ru "zeroaccess (malware)" (static)\n' +
    '"2015-03-10 09:27:58.021614" r2d2 68.12.104.178 41854 68.12.99.2 53 UDP DNS counter.yadro.ru "zeroaccess (malware)" (static)\n' +
    '"2015-03-10 09:28:03.546099" r2d2 68.12.104.178 38487 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 09:28:03.546128" r2d2 68.12.104.178 38487 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 09:28:04.052029" r2d2 68.12.104.178 35512 68.12.99.2 53 UDP DNS (megascor).no-ip.biz "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 09:28:04.052028" r2d2 68.12.104.178 35512 68.12.99.2 53 UDP DNS (megascor).no-ip.biz "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 09:28:11.770417" r2d2 68.12.104.178 55967 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 09:28:11.770419" r2d2 68.12.104.178 55967 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 09:28:22.020199" r2d2 68.12.104.178 57272 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 09:28:22.020198" r2d2 68.12.104.178 57272 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 09:28:31.651401" r2d2 68.12.104.178 45847 68.12.99.2 53 UDP DNS superfish.com superfish (static)\n' +
    '"2015-03-10 09:28:31.651404" r2d2 68.12.104.178 45847 68.12.99.2 53 UDP DNS superfish.com superfish (static)\n' +
    '"2015-03-10 09:28:33.708956" r2d2 178.162.211.207 5277 68.12.104.178 5060 UDP IP 178.162.211.207 "sipvicious scan" autoshun.org\n' +
    '"2015-03-10 09:28:33.708954" r2d2 178.162.211.207 5277 68.12.104.178 5060 UDP IP 178.162.211.207 "sipvicious scan" autoshun.org\n' +
    '"2015-03-10 09:28:35.268394" r2d2 68.12.104.178 44202 68.12.99.2 53 UDP DNS barclays.com expiro (static)\n' +
    '"2015-03-10 09:28:35.268393" r2d2 68.12.104.178 44202 68.12.99.2 53 UDP DNS barclays.com expiro (static)\n' +
    '"2015-03-10 09:28:42.596649" r2d2 68.12.104.178 57908 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 09:28:42.596650" r2d2 68.12.104.178 57908 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 09:29:05.155231" r2d2 68.12.104.178 52473 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 09:29:05.155235" r2d2 68.12.104.178 52473 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 09:29:16.496577" r2d2 68.12.104.178 48379 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 09:29:16.496575" r2d2 68.12.104.178 48379 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 09:29:35.983409" r2d2 68.12.104.178 50889 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 09:29:35.983406" r2d2 68.12.104.178 50889 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 09:29:40.306981" r2d2 68.12.104.178 47389 92.240.232.232 53 UDP IP 92.240.232.232 "asprox (malware)" atrack.h3x.eu\n' +
    '"2015-03-10 09:29:40.306984" r2d2 68.12.104.178 47389 92.240.232.232 53 UDP IP 92.240.232.232 "asprox (malware)" atrack.h3x.eu\n' +
    '"2015-03-10 09:29:44.206033" r2d2 68.12.104.178 41021 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 09:29:44.206035" r2d2 68.12.104.178 41021 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 09:29:51.424679" r2d2 68.12.104.178 45774 68.12.99.2 53 UDP DNS peer.pickeklosarske.ru "palevo (malware)" (static)\n' +
    '"2015-03-10 09:29:51.424682" r2d2 68.12.104.178 45774 68.12.99.2 53 UDP DNS peer.pickeklosarske.ru "palevo (malware)" (static)\n' +
    '"2015-03-10 09:30:15.044975" r2d2 68.12.104.178 38200 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 09:30:15.044973" r2d2 68.12.104.178 38200 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 09:30:23.458433" r2d2 68.12.104.178 59124 68.12.99.2 53 UDP DNS digitalmind.cn "palevo (malware)" palevotracker.abuse.ch\n' +
    '"2015-03-10 09:30:23.458435" r2d2 68.12.104.178 59124 68.12.99.2 53 UDP DNS digitalmind.cn "palevo (malware)" palevotracker.abuse.ch\n' +
    '"2015-03-10 09:30:37.595102" r2d2 68.12.104.178 50068 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 09:30:37.595114" r2d2 68.12.104.178 50068 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 09:30:51.408240" r2d2 68.12.104.178 53788 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 09:30:51.408243" r2d2 68.12.104.178 53788 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 09:31:08.421071" r2d2 68.12.104.178 35517 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 09:31:08.421065" r2d2 68.12.104.178 35517 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 09:31:16.654013" r2d2 68.12.104.178 45840 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 09:31:16.654015" r2d2 68.12.104.178 45840 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 09:31:34.742581" r2d2 68.12.104.178 35468 68.12.99.2 53 UDP DNS (megascor).no-ip.biz "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 09:31:34.742583" r2d2 68.12.104.178 35468 68.12.99.2 53 UDP DNS (megascor).no-ip.biz "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 09:31:46.573921" r2d2 68.12.104.178 45877 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 09:31:46.573923" r2d2 68.12.104.178 45877 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 09:31:47.622301" r2d2 68.12.104.178 47321 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 09:31:47.622288" r2d2 68.12.104.178 47321 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 09:32:10.030545" r2d2 68.12.104.178 55165 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 09:32:10.030547" r2d2 68.12.104.178 55165 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 09:32:10.165966" r2d2 68.12.104.178 50846 68.12.99.2 53 UDP DNS (brightlounge).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:32:10.165975" r2d2 68.12.104.178 50846 68.12.99.2 53 UDP DNS (brightlounge).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:32:21.328384" r2d2 68.12.104.178 43053 68.12.99.2 53 UDP DNS peer.pickeklosarske.ru "palevo (malware)" (static)\n' +
    '"2015-03-10 09:32:21.328382" r2d2 68.12.104.178 43053 68.12.99.2 53 UDP DNS peer.pickeklosarske.ru "palevo (malware)" (static)\n' +
    '"2015-03-10 09:32:40.858241" r2d2 68.12.104.178 46370 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 09:32:40.858240" r2d2 68.12.104.178 46370 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 09:32:47.958474" r2d2 68.12.104.178 41140 68.12.99.2 53 UDP DNS (megascor).no-ip.biz "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 09:32:47.958476" r2d2 68.12.104.178 41140 68.12.99.2 53 UDP DNS (megascor).no-ip.biz "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 09:32:49.230886" r2d2 68.12.104.178 46912 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 09:32:49.230884" r2d2 68.12.104.178 46912 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 09:33:09.828811" r2d2 68.12.104.178 35157 68.12.99.2 53 UDP DNS counter.yadro.ru "zeroaccess (malware)" (static)\n' +
    '"2015-03-10 09:33:09.828812" r2d2 68.12.104.178 35157 68.12.99.2 53 UDP DNS counter.yadro.ru "zeroaccess (malware)" (static)\n' +
    '"2015-03-10 09:33:20.196357" r2d2 68.12.104.178 51507 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 09:33:20.196355" r2d2 68.12.104.178 51507 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 09:33:21.326400" r2d2 68.12.104.178 36491 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 09:33:21.326401" r2d2 68.12.104.178 36491 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 09:33:42.469800" r2d2 68.12.104.178 47737 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 09:33:42.469810" r2d2 68.12.104.178 47737 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 09:33:46.621228" r2d2 68.12.104.178 56238 68.12.99.2 53 UDP DNS teske.pornicarke.com "palevo (malware)" (static)\n' +
    '"2015-03-10 09:33:46.621230" r2d2 68.12.104.178 56238 68.12.99.2 53 UDP DNS teske.pornicarke.com "palevo (malware)" (static)\n' +
    '"2015-03-10 09:34:04.958206" r2d2 68.12.104.178 45675 68.12.99.2 53 UDP DNS (megascor).no-ip.biz "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 09:34:04.958204" r2d2 68.12.104.178 45675 68.12.99.2 53 UDP DNS (megascor).no-ip.biz "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 09:34:13.294938" r2d2 68.12.104.178 39614 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 09:34:13.294936" r2d2 68.12.104.178 39614 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 09:34:16.634908" r2d2 68.12.104.178 46378 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 09:34:16.634906" r2d2 68.12.104.178 46378 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 09:34:21.802602" r2d2 68.12.104.178 45144 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 09:34:21.802604" r2d2 68.12.104.178 45144 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 09:34:50.291167" r2d2 68.12.104.178 54578 68.12.99.2 53 UDP DNS peer.pickeklosarske.ru "palevo (malware)" (static)\n' +
    '"2015-03-10 09:34:50.291166" r2d2 68.12.104.178 54578 68.12.99.2 53 UDP DNS peer.pickeklosarske.ru "palevo (malware)" (static)\n' +
    '"2015-03-10 09:34:52.629686" r2d2 68.12.104.178 46844 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 09:34:52.629593" r2d2 68.12.104.178 46844 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 09:35:14.904488" r2d2 68.12.104.178 42135 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 09:35:14.904487" r2d2 68.12.104.178 42135 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 09:35:17.879590" r2d2 68.12.104.178 48068 68.12.99.2 53 UDP DNS (megascor).no-ip.biz "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 09:35:17.879579" r2d2 68.12.104.178 48068 68.12.99.2 53 UDP DNS (megascor).no-ip.biz "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 09:35:43.730759" r2d2 68.12.104.178 38825 68.12.99.2 53 UDP DNS (gitgroup).no-ip.co.uk "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 09:35:43.730756" r2d2 68.12.104.178 38825 68.12.99.2 53 UDP DNS (gitgroup).no-ip.co.uk "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 09:35:45.732567" r2d2 68.12.104.178 40224 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 09:35:45.732568" r2d2 68.12.104.178 40224 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 09:35:49.948351" r2d2 68.12.104.178 35251 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 09:35:49.948350" r2d2 68.12.104.178 35251 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 09:35:54.239150" r2d2 68.12.104.178 40956 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 09:35:54.239152" r2d2 68.12.104.178 40956 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 09:35:56.878624" r2d2 68.12.104.178 48953 68.12.99.2 53 UDP DNS (sissel).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:35:56.878753" r2d2 68.12.104.178 48953 68.12.99.2 53 UDP DNS (sissel).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:35:57.080985" r2d2 68.12.104.178 50306 68.12.99.2 53 UDP DNS (epstein).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:35:57.080984" r2d2 68.12.104.178 50306 68.12.99.2 53 UDP DNS (epstein).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:36:15.958025" r2d2 68.12.104.178 52590 113.108.80.138 53 UDP IP 113.108.80.138 dnspod (custom)\n' +
    '"2015-03-10 09:36:15.958046" r2d2 68.12.104.178 52590 113.108.80.138 53 UDP IP 113.108.80.138 dnspod (custom)\n' +
    '"2015-03-10 09:36:22.649767" r2d2 68.12.104.178 37708 68.12.99.2 53 UDP DNS promisex.ru "zeus (malware)" (custom)\n' +
    '"2015-03-10 09:36:22.649765" r2d2 68.12.104.178 37708 68.12.99.2 53 UDP DNS promisex.ru "zeus (malware)" (custom)\n' +
    '"2015-03-10 09:36:25.065956" r2d2 68.12.104.178 41874 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 09:36:25.065957" r2d2 68.12.104.178 41874 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 09:36:37.474608" r2d2 68.12.104.178 58030 68.12.99.2 53 UDP DNS digitalmind.cn "palevo (malware)" palevotracker.abuse.ch\n' +
    '"2015-03-10 09:36:37.474606" r2d2 68.12.104.178 58030 68.12.99.2 53 UDP DNS digitalmind.cn "palevo (malware)" palevotracker.abuse.ch\n' +
    '"2015-03-10 09:36:46.213172" r2d2 68.12.104.178 55637 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 09:36:46.213162" r2d2 68.12.104.178 55637 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 09:36:47.342718" r2d2 68.12.104.178 46902 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 09:36:47.342737" r2d2 68.12.104.178 46902 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 09:37:18.170037" r2d2 68.12.104.178 52221 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 09:37:18.169865" r2d2 68.12.104.178 52221 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 09:37:18.997354" r2d2 68.12.104.178 41356 68.12.99.2 53 UDP DNS peer.pickeklosarske.ru "palevo (malware)" (static)\n' +
    '"2015-03-10 09:37:18.997342" r2d2 68.12.104.178 41356 68.12.99.2 53 UDP DNS peer.pickeklosarske.ru "palevo (malware)" (static)\n' +
    '"2015-03-10 09:37:26.875156" r2d2 68.12.104.178 48463 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 09:37:26.875160" r2d2 68.12.104.178 48463 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 09:37:57.701937" r2d2 68.12.104.178 46011 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 09:37:57.701934" r2d2 68.12.104.178 46011 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 09:38:12.079856" r2d2 68.12.104.178 35242 68.12.99.2 53 UDP DNS (megascor).no-ip.biz "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 09:38:12.079857" r2d2 68.12.104.178 35242 68.12.99.2 53 UDP DNS (megascor).no-ip.biz "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 09:38:18.617634" r2d2 68.12.104.178 43871 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 09:38:18.617635" r2d2 68.12.104.178 43871 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 09:38:19.778829" r2d2 68.12.104.178 59952 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 09:38:19.778825" r2d2 68.12.104.178 59952 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 09:38:32.609519" r2d2 68.12.104.178 48407 68.12.99.2 53 UDP DNS (additio.tut).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:38:32.609521" r2d2 68.12.104.178 48407 68.12.99.2 53 UDP DNS (additio.tut).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:38:50.607146" r2d2 68.12.104.178 39641 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 09:38:50.607065" r2d2 68.12.104.178 39641 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 09:38:59.310611" r2d2 68.12.104.178 39764 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 09:38:59.310618" r2d2 68.12.104.178 39764 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 09:39:02.504657" r2d2 68.12.104.178 40775 68.12.99.2 53 UDP DNS counter.yadro.ru "zeroaccess (malware)" (static)\n' +
    '"2015-03-10 09:39:02.504659" r2d2 68.12.104.178 40775 68.12.99.2 53 UDP DNS counter.yadro.ru "zeroaccess (malware)" (static)\n' +
    '"2015-03-10 09:39:16.303897" r2d2 68.12.104.178 39129 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 09:39:16.303896" r2d2 68.12.104.178 39129 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 09:39:30.136770" r2d2 68.12.104.178 55789 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 09:39:30.136771" r2d2 68.12.104.178 55789 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 09:39:48.531180" r2d2 68.12.104.178 49072 68.12.99.2 53 UDP DNS peer.pickeklosarske.ru "palevo (malware)" (static)\n' +
    '"2015-03-10 09:39:48.531191" r2d2 68.12.104.178 49072 68.12.99.2 53 UDP DNS peer.pickeklosarske.ru "palevo (malware)" (static)\n' +
    '"2015-03-10 09:39:52.216858" r2d2 68.12.104.178 38288 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 09:39:52.216857" r2d2 68.12.104.178 38288 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 09:40:23.045302" r2d2 68.12.104.178 38693 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 09:40:23.045304" r2d2 68.12.104.178 38693 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 09:40:31.745384" r2d2 68.12.104.178 35751 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 09:40:31.745385" r2d2 68.12.104.178 35751 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 09:40:38.169510" r2d2 222.66.55.242 6000 68.12.104.178 1433 TCP IP 222.66.55.242 attacker blocklist.de\n' +
    '"2015-03-10 09:40:38.169513" r2d2 222.66.55.242 6000 68.12.104.178 1433 TCP IP 222.66.55.242 attacker blocklist.de\n' +
    '"2015-03-10 09:40:47.988602" r2d2 68.12.104.178 47510 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 09:40:47.988604" r2d2 68.12.104.178 47510 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 09:41:02.695423" r2d2 68.12.104.178 51696 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 09:41:02.695422" r2d2 68.12.104.178 51696 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 09:41:24.654319" r2d2 68.12.104.178 41576 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 09:41:24.654318" r2d2 68.12.104.178 41576 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 09:41:46.349262" r2d2 68.12.104.178 58497 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 09:41:46.349259" r2d2 68.12.104.178 58497 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 09:41:55.483944" r2d2 68.12.104.178 42359 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 09:41:55.483942" r2d2 68.12.104.178 42359 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 09:42:04.304295" r2d2 68.12.104.178 48240 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 09:42:04.304293" r2d2 68.12.104.178 48240 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 09:42:09.037507" r2d2 68.12.104.178 52356 68.12.99.2 53 UDP DNS (megascor).no-ip.biz "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 09:42:09.037518" r2d2 68.12.104.178 52356 68.12.99.2 53 UDP DNS (megascor).no-ip.biz "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 09:42:17.165988" r2d2 68.12.104.178 51216 68.12.99.2 53 UDP DNS peer.pickeklosarske.ru "palevo (malware)" (static)\n' +
    '"2015-03-10 09:42:17.165720" r2d2 68.12.104.178 51216 68.12.99.2 53 UDP DNS peer.pickeklosarske.ru "palevo (malware)" (static)\n' +
    '"2015-03-10 09:42:30.112203" r2d2 68.12.104.178 38108 68.12.99.2 53 UDP DNS (brightlounge).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:42:30.112205" r2d2 68.12.104.178 38108 68.12.99.2 53 UDP DNS (brightlounge).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:42:35.129698" r2d2 68.12.104.178 43156 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 09:42:35.129697" r2d2 68.12.104.178 43156 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 09:42:37.072875" r2d2 68.12.104.178 35444 8.8.8.8 53 UDP DNS (brightlounge).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:42:37.072871" r2d2 68.12.104.178 35444 8.8.8.8 53 UDP DNS (brightlounge).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:42:51.631789" r2d2 68.12.104.178 39451 68.12.99.2 53 UDP DNS digitalmind.cn "palevo (malware)" palevotracker.abuse.ch\n' +
    '"2015-03-10 09:42:51.631786" r2d2 68.12.104.178 39451 68.12.99.2 53 UDP DNS digitalmind.cn "palevo (malware)" palevotracker.abuse.ch\n' +
    '"2015-03-10 09:42:57.090742" r2d2 68.12.104.178 57488 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 09:42:57.090779" r2d2 68.12.104.178 57488 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 09:43:10.731681" r2d2 68.12.104.178 40649 68.12.99.2 53 UDP DNS (update.drp).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:43:10.731671" r2d2 68.12.104.178 40649 68.12.99.2 53 UDP DNS (update.drp).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:43:16.459245" r2d2 68.12.104.178 45097 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 09:43:16.459264" r2d2 68.12.104.178 45097 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 09:43:27.919256" r2d2 68.12.104.178 56446 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 09:43:27.919247" r2d2 68.12.104.178 56446 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 09:43:36.739563" r2d2 68.12.104.178 48633 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 09:43:36.739548" r2d2 68.12.104.178 48633 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 09:43:45.301206" r2d2 68.12.104.178 46083 68.12.99.2 53 UDP DNS (tracker.coppersurfer).tk "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:43:45.301207" r2d2 68.12.104.178 46083 68.12.99.2 53 UDP DNS (tracker.coppersurfer).tk "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:43:46.395166" r2d2 68.12.104.178 59770 68.12.99.2 53 UDP DNS teske.pornicarke.com "palevo (malware)" (static)\n' +
    '"2015-03-10 09:43:46.395163" r2d2 68.12.104.178 59770 68.12.99.2 53 UDP DNS teske.pornicarke.com "palevo (malware)" (static)\n' +
    '"2015-03-10 09:44:07.564571" r2d2 68.12.104.178 48759 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 09:44:07.564570" r2d2 68.12.104.178 48759 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 09:44:16.411341" r2d2 68.12.104.178 59691 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 09:44:16.411326" r2d2 68.12.104.178 59691 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 09:44:29.528888" r2d2 68.12.104.178 47593 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 09:44:29.528887" r2d2 68.12.104.178 47593 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 09:44:34.112827" r2d2 68.12.104.178 45292 68.12.99.2 53 UDP DNS (megascor).no-ip.biz "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 09:44:34.112828" r2d2 68.12.104.178 45292 68.12.99.2 53 UDP DNS (megascor).no-ip.biz "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 09:44:45.861470" r2d2 68.12.104.178 56140 68.12.99.2 53 UDP DNS peer.pickeklosarske.ru "palevo (malware)" (static)\n' +
    '"2015-03-10 09:44:45.861444" r2d2 68.12.104.178 56140 68.12.99.2 53 UDP DNS peer.pickeklosarske.ru "palevo (malware)" (static)\n' +
    '"2015-03-10 09:45:00.357052" r2d2 68.12.104.178 35722 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 09:45:00.357055" r2d2 68.12.104.178 35722 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 09:45:09.173131" r2d2 68.12.104.178 46052 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 09:45:09.173129" r2d2 68.12.104.178 46052 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 09:45:28.396900" r2d2 68.12.104.178 47946 68.12.99.2 53 UDP DNS counter.yadro.ru "zeroaccess (malware)" (static)\n' +
    '"2015-03-10 09:45:28.396898" r2d2 68.12.104.178 47946 68.12.99.2 53 UDP DNS counter.yadro.ru "zeroaccess (malware)" (static)\n' +
    '"2015-03-10 09:45:38.863316" r2d2 68.12.104.178 52665 68.12.99.2 53 UDP DNS promisex.ru "zeus (malware)" (custom)\n' +
    '"2015-03-10 09:45:38.863313" r2d2 68.12.104.178 52665 68.12.99.2 53 UDP DNS promisex.ru "zeus (malware)" (custom)\n' +
    '"2015-03-10 09:45:39.999004" r2d2 68.12.104.178 59376 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 09:45:39.999006" r2d2 68.12.104.178 59376 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 09:45:42.519369" r2d2 68.12.104.178 52623 68.12.99.2 53 UDP DNS fitt.prince.kz "palevo (malware)" palevotracker.abuse.ch\n' +
    '"2015-03-10 09:45:42.519368" r2d2 68.12.104.178 52623 68.12.99.2 53 UDP DNS fitt.prince.kz "palevo (malware)" palevotracker.abuse.ch\n' +
    '"2015-03-10 09:45:42.539284" r2d2 68.12.104.178 49446 87.236.178.49 53 UDP IP 87.236.178.49 malware malwarepatrol.net\n' +
    '"2015-03-10 09:45:42.539281" r2d2 68.12.104.178 49446 87.236.178.49 53 UDP IP 87.236.178.49 malware malwarepatrol.net\n' +
    '"2015-03-10 09:45:43.800099" r2d2 68.12.104.178 37582 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 09:45:44.742184" r2d2 68.12.104.178 54662 68.12.99.2 53 UDP DNS (icemovie).cf "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:45:44.742182" r2d2 68.12.104.178 54662 68.12.99.2 53 UDP DNS (icemovie).cf "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:46:02.059462" r2d2 68.12.104.178 59160 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 09:46:02.059423" r2d2 68.12.104.178 59160 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 09:46:12.535036" r2d2 68.12.104.178 54546 68.12.99.2 53 UDP DNS (eit.folks).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:46:12.535034" r2d2 68.12.104.178 54546 68.12.99.2 53 UDP DNS (eit.folks).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:46:32.888183" r2d2 68.12.104.178 38490 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 09:46:32.888182" r2d2 68.12.104.178 38490 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 09:46:41.609683" r2d2 68.12.104.178 35615 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 09:46:41.609661" r2d2 68.12.104.178 35615 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 09:46:46.190172" r2d2 68.12.104.178 49831 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 09:46:46.190175" r2d2 68.12.104.178 49831 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 09:46:47.923973" r2d2 68.12.104.178 44626 68.12.99.2 53 UDP DNS (megascor).no-ip.biz "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 09:46:47.923976" r2d2 68.12.104.178 44626 68.12.99.2 53 UDP DNS (megascor).no-ip.biz "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 09:47:12.233544" r2d2 68.12.104.178 39587 68.12.99.2 53 UDP DNS peer.pickeklosarske.ru "palevo (malware)" (static)\n' +
    '"2015-03-10 09:47:12.233541" r2d2 68.12.104.178 39587 68.12.99.2 53 UDP DNS peer.pickeklosarske.ru "palevo (malware)" (static)\n' +
    '"2015-03-10 09:47:12.433915" r2d2 68.12.104.178 57329 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 09:47:12.433913" r2d2 68.12.104.178 57329 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 09:47:34.499331" r2d2 68.12.104.178 44201 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 09:47:34.499327" r2d2 68.12.104.178 44201 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 09:48:05.325920" r2d2 68.12.104.178 54787 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 09:48:05.325919" r2d2 68.12.104.178 54787 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 09:48:11.191061" r2d2 68.12.104.178 35848 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 09:48:11.191064" r2d2 68.12.104.178 35848 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 09:48:14.041035" r2d2 68.12.104.178 37907 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 09:48:14.041033" r2d2 68.12.104.178 37907 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 09:48:43.100483" r2d2 68.12.104.178 48017 68.12.99.2 53 UDP DNS (tracker.coppersurfer).tk "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:48:43.100481" r2d2 68.12.104.178 48017 68.12.99.2 53 UDP DNS (tracker.coppersurfer).tk "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:48:44.868086" r2d2 68.12.104.178 44574 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 09:48:44.868085" r2d2 68.12.104.178 44574 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 09:49:01.929519" r2d2 68.12.104.178 35110 68.12.99.2 53 UDP DNS digitalmind.cn "palevo (malware)" palevotracker.abuse.ch\n' +
    '"2015-03-10 09:49:01.929521" r2d2 68.12.104.178 35110 68.12.99.2 53 UDP DNS digitalmind.cn "palevo (malware)" palevotracker.abuse.ch\n' +
    '"2015-03-10 09:49:07.076475" r2d2 68.12.104.178 48108 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 09:49:07.076473" r2d2 68.12.104.178 48108 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 09:49:16.251498" r2d2 68.12.104.178 36432 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 09:49:16.251497" r2d2 68.12.104.178 36432 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 09:49:21.169745" r2d2 61.240.144.65 60000 68.12.104.178 5631 TCP IP 61.240.144.65 "incoming masscan detected" autoshun.org\n' +
    '"2015-03-10 09:49:21.169729" r2d2 61.240.144.65 60000 68.12.104.178 5631 TCP IP 61.240.144.65 "incoming masscan detected" autoshun.org\n' +
    '"2015-03-10 09:49:38.230784" r2d2 68.12.104.178 53853 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 09:49:38.230786" r2d2 68.12.104.178 53853 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 09:49:40.403092" r2d2 68.12.104.178 36424 68.12.99.2 53 UDP DNS peer.pickeklosarske.ru "palevo (malware)" (static)\n' +
    '"2015-03-10 09:49:40.403107" r2d2 68.12.104.178 36424 68.12.99.2 53 UDP DNS peer.pickeklosarske.ru "palevo (malware)" (static)\n' +
    '"2015-03-10 09:49:46.474957" r2d2 68.12.104.178 47877 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 09:49:46.474972" r2d2 68.12.104.178 47877 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 09:49:48.314446" r2d2 68.12.104.178 59382 68.12.99.2 53 UDP DNS (megascor).no-ip.biz "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 09:49:48.314449" r2d2 68.12.104.178 59382 68.12.99.2 53 UDP DNS (megascor).no-ip.biz "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 09:50:17.306021" r2d2 68.12.104.178 55511 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 09:50:17.306026" r2d2 68.12.104.178 55511 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 09:50:30.344296" r2d2 68.12.104.178 57115 68.12.99.2 53 UDP DNS (www).superfish.com superfish (static)\n' +
    '"2015-03-10 09:50:30.344294" r2d2 68.12.104.178 57115 68.12.99.2 53 UDP DNS (www).superfish.com superfish (static)\n' +
    '"2015-03-10 09:50:30.365920" r2d2 68.12.104.178 43515 68.12.99.2 53 UDP DNS superfish.com superfish (static)\n' +
    '"2015-03-10 09:50:30.365917" r2d2 68.12.104.178 43515 68.12.99.2 53 UDP DNS superfish.com superfish (static)\n' +
    '"2015-03-10 09:50:35.802645" r2d2 202.105.183.147 6000 68.12.104.178 1433 TCP IP 202.105.183.147 attacker cinsscore.com\n' +
    '"2015-03-10 09:50:35.802704" r2d2 202.105.183.147 6000 68.12.104.178 1433 TCP IP 202.105.183.147 attacker cinsscore.com\n' +
    '"2015-03-10 09:50:39.841260" r2d2 68.12.104.178 46809 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 09:50:39.841256" r2d2 68.12.104.178 46809 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 09:50:39.948408" r2d2 68.12.104.178 50353 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 09:50:39.948410" r2d2 68.12.104.178 50353 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 09:51:08.149973" r2d2 211.235.228.43 55487 68.12.104.178 25 TCP IP 211.235.228.43 abuser openbl.org\n' +
    '"2015-03-10 09:51:08.149976" r2d2 211.235.228.43 55487 68.12.104.178 25 TCP IP 211.235.228.43 abuser openbl.org\n' +
    '"2015-03-10 09:51:10.808199" r2d2 68.12.104.178 45684 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 09:51:10.808197" r2d2 68.12.104.178 45684 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 09:51:11.149817" r2d2 211.235.228.43 55487 68.12.104.178 25 TCP IP 211.235.228.43 abuser openbl.org\n' +
    '"2015-03-10 09:51:11.149822" r2d2 211.235.228.43 55487 68.12.104.178 25 TCP IP 211.235.228.43 abuser openbl.org\n' +
    '"2015-03-10 09:51:18.911516" r2d2 68.12.104.178 45261 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 09:51:18.911515" r2d2 68.12.104.178 45261 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 09:51:23.884331" r2d2 68.12.104.178 42218 68.12.99.2 53 UDP DNS (www.forum54).tk "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:51:23.884334" r2d2 68.12.104.178 42218 68.12.99.2 53 UDP DNS (www.forum54).tk "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:51:26.020989" r2d2 68.12.104.178 37441 68.12.99.2 53 UDP DNS (forum54).tk "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:51:26.020986" r2d2 68.12.104.178 37441 68.12.99.2 53 UDP DNS (forum54).tk "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:51:42.502944" r2d2 68.12.104.178 38176 68.12.99.2 53 UDP DNS cychefs.com malware cybercrime-tracker.net\n' +
    '"2015-03-10 09:51:42.502965" r2d2 68.12.104.178 38176 68.12.99.2 53 UDP DNS cychefs.com malware cybercrime-tracker.net\n' +
    '"2015-03-10 09:51:46.218744" r2d2 68.12.104.178 43367 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 09:51:46.218729" r2d2 68.12.104.178 43367 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 09:51:49.736571" r2d2 68.12.104.178 40424 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 09:51:49.736702" r2d2 68.12.104.178 40424 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 09:52:08.805382" r2d2 68.12.104.178 47498 68.12.99.2 53 UDP DNS peer.pickeklosarske.ru "palevo (malware)" (static)\n' +
    '"2015-03-10 09:52:08.805386" r2d2 68.12.104.178 47498 68.12.99.2 53 UDP DNS peer.pickeklosarske.ru "palevo (malware)" (static)\n' +
    '"2015-03-10 09:52:12.417885" r2d2 68.12.104.178 50784 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 09:52:12.417884" r2d2 68.12.104.178 50784 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 09:52:43.245400" r2d2 68.12.104.178 59768 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 09:52:43.245402" r2d2 68.12.104.178 59768 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 09:52:51.343635" r2d2 68.12.104.178 40421 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 09:52:51.343633" r2d2 68.12.104.178 40421 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 09:53:08.396449" r2d2 68.12.104.178 52173 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 09:53:08.396447" r2d2 68.12.104.178 52173 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 09:53:11.284292" r2d2 68.12.104.178 46234 68.12.99.2 53 UDP DNS (update.drp).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:53:11.284277" r2d2 68.12.104.178 46234 68.12.99.2 53 UDP DNS (update.drp).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:53:16.799592" r2d2 68.12.104.178 46189 68.12.99.2 53 UDP DNS (brightlounge).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:53:16.799594" r2d2 68.12.104.178 46189 68.12.99.2 53 UDP DNS (brightlounge).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:53:19.962159" r2d2 68.12.104.178 48954 68.12.99.2 53 UDP DNS (coppersurfer).tk "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:53:19.962158" r2d2 68.12.104.178 48954 68.12.99.2 53 UDP DNS (coppersurfer).tk "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:53:22.172421" r2d2 68.12.104.178 59225 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 09:53:22.172418" r2d2 68.12.104.178 59225 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 09:53:25.277155" r2d2 68.12.104.178 53393 68.12.99.2 53 UDP DNS (coppersurfer).tk "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:53:25.277156" r2d2 68.12.104.178 53393 68.12.99.2 53 UDP DNS (coppersurfer).tk "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:53:30.032124" r2d2 68.12.104.178 45772 68.12.99.2 53 UDP DNS (megascor).no-ip.biz "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 09:53:30.032125" r2d2 68.12.104.178 45772 68.12.99.2 53 UDP DNS (megascor).no-ip.biz "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 09:53:57.401734" r2d2 68.12.104.178 47845 68.12.99.2 53 UDP DNS (tracker.coppersurfer).tk "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:53:57.401731" r2d2 68.12.104.178 47845 68.12.99.2 53 UDP DNS (tracker.coppersurfer).tk "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:54:00.006020" r2d2 68.12.104.178 41168 68.12.99.2 53 UDP DNS upperlowstream.ru "zeus (malware)" zeustracker.abuse.ch\n' +
    '"2015-03-10 09:54:00.006022" r2d2 68.12.104.178 41168 68.12.99.2 53 UDP DNS upperlowstream.ru "zeus (malware)" zeustracker.abuse.ch\n' +
    '"2015-03-10 09:54:14.827461" r2d2 68.12.104.178 51146 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 09:54:14.827463" r2d2 68.12.104.178 51146 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 09:54:15.682977" r2d2 68.12.104.178 44042 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 09:54:15.682979" r2d2 68.12.104.178 44042 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 09:54:17.945539" r2d2 68.12.104.178 43183 68.12.99.2 53 UDP DNS counter.yadro.ru "zeroaccess (malware)" (static)\n' +
    '"2015-03-10 09:54:17.945535" r2d2 68.12.104.178 43183 68.12.99.2 53 UDP DNS counter.yadro.ru "zeroaccess (malware)" (static)\n' +
    '"2015-03-10 09:54:23.779391" r2d2 68.12.104.178 53190 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 09:54:23.779399" r2d2 68.12.104.178 53190 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 09:54:38.005671" r2d2 68.12.104.178 38546 68.12.99.2 53 UDP DNS peer.pickeklosarske.ru "palevo (malware)" (static)\n' +
    '"2015-03-10 09:54:38.005669" r2d2 68.12.104.178 38546 68.12.99.2 53 UDP DNS peer.pickeklosarske.ru "palevo (malware)" (static)\n' +
    '"2015-03-10 09:54:54.610593" r2d2 68.12.104.178 48737 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 09:54:54.610594" r2d2 68.12.104.178 48737 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 09:55:03.512353" r2d2 68.12.104.178 48215 68.12.99.2 53 UDP DNS (monitmass).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:55:03.512354" r2d2 68.12.104.178 48215 68.12.99.2 53 UDP DNS (monitmass).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:55:07.639087" r2d2 68.12.104.178 53613 68.12.99.2 53 UDP DNS teske.pornicarke.com "palevo (malware)" (static)\n' +
    '"2015-03-10 09:55:07.639085" r2d2 68.12.104.178 53613 68.12.99.2 53 UDP DNS teske.pornicarke.com "palevo (malware)" (static)\n' +
    '"2015-03-10 09:55:12.320217" r2d2 68.12.104.178 46453 68.12.99.2 53 UDP DNS digitalmind.cn "palevo (malware)" palevotracker.abuse.ch\n' +
    '"2015-03-10 09:55:12.320218" r2d2 68.12.104.178 46453 68.12.99.2 53 UDP DNS digitalmind.cn "palevo (malware)" palevotracker.abuse.ch\n' +
    '"2015-03-10 09:55:17.292574" r2d2 68.12.104.178 44616 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 09:55:17.292570" r2d2 68.12.104.178 44616 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 09:55:29.144236" r2d2 68.12.104.178 48842 68.12.99.2 53 UDP DNS (static7).superfish.com superfish (static)\n' +
    '"2015-03-10 09:55:29.144237" r2d2 68.12.104.178 48842 68.12.99.2 53 UDP DNS (static7).superfish.com superfish (static)\n' +
    '"2015-03-10 09:55:29.242114" r2d2 68.12.104.178 36959 68.12.99.2 53 UDP DNS (static).superfish.com superfish (static)\n' +
    '"2015-03-10 09:55:29.242110" r2d2 68.12.104.178 36959 68.12.99.2 53 UDP DNS (static).superfish.com superfish (static)\n' +
    '"2015-03-10 09:55:29.413209" r2d2 68.12.104.178 38440 68.12.99.2 53 UDP DNS (static8).superfish.com superfish (static)\n' +
    '"2015-03-10 09:55:29.413205" r2d2 68.12.104.178 38440 68.12.99.2 53 UDP DNS (static8).superfish.com superfish (static)\n' +
    '"2015-03-10 09:55:29.449901" r2d2 68.12.104.178 54215 68.12.99.2 53 UDP DNS (static9).superfish.com superfish (static)\n' +
    '"2015-03-10 09:55:29.449915" r2d2 68.12.104.178 54215 68.12.99.2 53 UDP DNS (static9).superfish.com superfish (static)\n' +
    '"2015-03-10 09:55:36.582148" r2d2 68.12.104.178 37866 68.12.99.2 53 UDP DNS (megascor).no-ip.biz "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 09:55:36.582145" r2d2 68.12.104.178 37866 68.12.99.2 53 UDP DNS (megascor).no-ip.biz "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 09:55:37.541269" r2d2 68.12.104.178 56731 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 09:55:37.541266" r2d2 68.12.104.178 56731 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 09:55:41.327649" r2d2 68.12.104.178 44839 68.12.99.2 53 UDP DNS www.jollywallet.com malware www.virustotal.com\n' +
    '"2015-03-10 09:55:41.327652" r2d2 68.12.104.178 44839 68.12.99.2 53 UDP DNS www.jollywallet.com malware www.virustotal.com\n' +
    '"2015-03-10 09:55:48.120625" r2d2 68.12.104.178 35393 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 09:55:48.120623" r2d2 68.12.104.178 35393 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 09:55:56.228146" r2d2 68.12.104.178 36041 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 09:55:56.228149" r2d2 68.12.104.178 36041 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 09:56:27.055256" r2d2 68.12.104.178 35643 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 09:56:27.055259" r2d2 68.12.104.178 35643 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 09:56:43.669466" r2d2 68.12.104.178 39545 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 09:56:43.669464" r2d2 68.12.104.178 39545 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 09:56:49.729739" r2d2 68.12.104.178 45579 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 09:56:49.729736" r2d2 68.12.104.178 45579 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 09:56:58.949538" r2d2 68.12.104.178 37778 68.12.99.2 53 UDP DNS (megascor).no-ip.biz "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 09:56:58.949542" r2d2 68.12.104.178 37778 68.12.99.2 53 UDP DNS (megascor).no-ip.biz "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 09:57:05.997262" r2d2 68.12.104.178 36250 68.12.99.2 53 UDP DNS (ns1).torpig-sinkhole.org "torpig (malware)" (static)\n' +
    '"2015-03-10 09:57:05.997261" r2d2 68.12.104.178 36250 68.12.99.2 53 UDP DNS (ns1).torpig-sinkhole.org "torpig (malware)" (static)\n' +
    '"2015-03-10 09:57:05.997532" r2d2 68.12.104.178 43704 68.12.99.2 53 UDP DNS (ns1).torpig-sinkhole.org "torpig (malware)" (static)\n' +
    '"2015-03-10 09:57:05.997534" r2d2 68.12.104.178 43704 68.12.99.2 53 UDP DNS (ns1).torpig-sinkhole.org "torpig (malware)" (static)\n' +
    '"2015-03-10 09:57:05.997717" r2d2 68.12.104.178 37483 68.12.99.2 53 UDP DNS (ns2).torpig-sinkhole.org "torpig (malware)" (static)\n' +
    '"2015-03-10 09:57:05.997732" r2d2 68.12.104.178 37483 68.12.99.2 53 UDP DNS (ns2).torpig-sinkhole.org "torpig (malware)" (static)\n' +
    '"2015-03-10 09:57:05.997946" r2d2 68.12.104.178 50306 68.12.99.2 53 UDP DNS (ns2).torpig-sinkhole.org "torpig (malware)" (static)\n' +
    '"2015-03-10 09:57:05.997947" r2d2 68.12.104.178 50306 68.12.99.2 53 UDP DNS (ns2).torpig-sinkhole.org "torpig (malware)" (static)\n' +
    '"2015-03-10 09:57:06.039966" r2d2 68.12.104.178 44632 212.227.55.84 53 UDP IP 212.227.55.84 "torpig (malware)" (static)\n' +
    '"2015-03-10 09:57:06.041287" r2d2 68.12.104.178 35389 212.227.55.84 53 UDP IP 212.227.55.84 "torpig (malware)" (static)\n' +
    '"2015-03-10 09:57:06.041288" r2d2 68.12.104.178 35389 212.227.55.84 53 UDP IP 212.227.55.84 "torpig (malware)" (static)\n' +
    '"2015-03-10 09:57:06.068068" r2d2 68.12.104.178 58116 87.106.240.162 53 UDP IP 87.106.240.162 "torpig (malware)" (static)\n' +
    '"2015-03-10 09:57:06.068075" r2d2 68.12.104.178 59070 87.106.240.162 53 UDP IP 87.106.240.162 "torpig (malware)" (static)\n' +
    '"2015-03-10 09:57:06.068065" r2d2 68.12.104.178 58116 87.106.240.162 53 UDP IP 87.106.240.162 "torpig (malware)" (static)\n' +
    '"2015-03-10 09:57:06.068091" r2d2 68.12.104.178 59070 87.106.240.162 53 UDP IP 87.106.240.162 "torpig (malware)" (static)\n' +
    '"2015-03-10 09:57:06.097921" r2d2 68.12.104.178 56804 212.227.55.84 53 UDP IP 212.227.55.84 "torpig (malware)" (static)\n' +
    '"2015-03-10 09:57:06.097924" r2d2 68.12.104.178 56804 212.227.55.84 53 UDP IP 212.227.55.84 "torpig (malware)" (static)\n' +
    '"2015-03-10 09:57:06.971515" r2d2 68.12.104.178 36009 68.12.99.2 53 UDP DNS peer.pickeklosarske.ru "palevo (malware)" (static)\n' +
    '"2015-03-10 09:57:06.971513" r2d2 68.12.104.178 36009 68.12.99.2 53 UDP DNS peer.pickeklosarske.ru "palevo (malware)" (static)\n' +
    '"2015-03-10 09:57:20.557398" r2d2 68.12.104.178 54999 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 09:57:20.557397" r2d2 68.12.104.178 54999 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 09:57:23.164132" r2d2 68.12.104.178 48885 68.12.99.2 53 UDP DNS (ns2.coldzaens).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:57:23.163686" r2d2 68.12.104.178 59616 68.12.99.2 53 UDP DNS (ns1.coldzaens).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:57:23.164573" r2d2 68.12.104.178 55179 68.12.99.2 53 UDP DNS (ns3.coldzaens).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:57:23.163687" r2d2 68.12.104.178 59616 68.12.99.2 53 UDP DNS (ns1.coldzaens).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:57:23.164586" r2d2 68.12.104.178 37551 68.12.99.2 53 UDP DNS (ns4.coldzaens).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:57:23.164578" r2d2 68.12.104.178 55179 68.12.99.2 53 UDP DNS (ns3.coldzaens).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:57:23.164131" r2d2 68.12.104.178 48885 68.12.99.2 53 UDP DNS (ns2.coldzaens).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:57:23.164584" r2d2 68.12.104.178 37551 68.12.99.2 53 UDP DNS (ns4.coldzaens).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 09:57:28.662673" r2d2 68.12.104.178 59096 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 09:57:28.662670" r2d2 68.12.104.178 59096 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 09:57:45.910526" r2d2 68.12.104.178 58428 68.12.99.2 53 UDP DNS members.tripod.com malware malwareurls.joxeankoret.com\n' +
    '"2015-03-10 09:57:45.910529" r2d2 68.12.104.178 58428 68.12.99.2 53 UDP DNS members.tripod.com malware malwareurls.joxeankoret.com\n' +
    '"2015-03-10 09:57:59.491301" r2d2 68.12.104.178 36479 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 09:57:59.491303" r2d2 68.12.104.178 36479 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 09:58:06.798401" r2d2 68.12.104.178 40186 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 09:58:06.798404" r2d2 68.12.104.178 40186 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 09:58:22.293230" r2d2 68.12.104.178 51894 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 09:58:30.332801" r2d2 68.12.104.178 36092 68.12.99.2 53 UDP DNS pica.banjalucke-ljepotice.ru "palevo (malware)" (static)\n' +
    '"2015-03-10 09:58:30.332800" r2d2 68.12.104.178 36092 68.12.99.2 53 UDP DNS pica.banjalucke-ljepotice.ru "palevo (malware)" (static)\n' +
    '"2015-03-10 09:58:37.285354" r2d2 68.12.104.178 45064 68.12.99.2 53 UDP DNS (megascor).no-ip.biz "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 09:58:37.285356" r2d2 68.12.104.178 45064 68.12.99.2 53 UDP DNS (megascor).no-ip.biz "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 09:58:53.126913" r2d2 68.12.104.178 48424 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 09:58:53.126911" r2d2 68.12.104.178 48424 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 09:59:01.363490" r2d2 68.12.104.178 51632 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 09:59:01.363487" r2d2 68.12.104.178 51632 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 09:59:13.652207" r2d2 68.12.104.178 42071 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 09:59:13.652212" r2d2 68.12.104.178 42071 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 09:59:32.192664" r2d2 68.12.104.178 58631 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 09:59:32.192665" r2d2 68.12.104.178 58631 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 09:59:36.467691" r2d2 68.12.104.178 58108 68.12.99.2 53 UDP DNS peer.pickeklosarske.ru "palevo (malware)" (static)\n' +
    '"2015-03-10 09:59:36.467692" r2d2 68.12.104.178 58108 68.12.99.2 53 UDP DNS peer.pickeklosarske.ru "palevo (malware)" (static)\n' +
    '"2015-03-10 09:59:50.329084" r2d2 68.12.104.178 39147 68.12.99.2 53 UDP DNS (megascor).no-ip.biz "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 09:59:50.329083" r2d2 68.12.104.178 39147 68.12.99.2 53 UDP DNS (megascor).no-ip.biz "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 09:59:54.744925" r2d2 68.12.104.178 57226 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 09:59:54.744927" r2d2 68.12.104.178 57226 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 10:00:06.894414" r2d2 68.12.104.178 56645 113.108.80.138 53 UDP IP 113.108.80.138 dnspod (custom)\n' +
    '"2015-03-10 10:00:06.894417" r2d2 68.12.104.178 56645 113.108.80.138 53 UDP IP 113.108.80.138 dnspod (custom)\n' +
    '"2015-03-10 10:00:25.573326" r2d2 68.12.104.178 52797 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 10:00:25.573325" r2d2 68.12.104.178 52797 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 10:00:33.941722" r2d2 68.12.104.178 37644 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 10:00:33.941724" r2d2 68.12.104.178 37644 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 10:00:36.267023" r2d2 68.12.104.178 37768 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 10:00:36.267031" r2d2 68.12.104.178 37768 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 10:01:04.765341" r2d2 68.12.104.178 43340 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 10:01:04.765338" r2d2 68.12.104.178 43340 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 10:01:07.299648" r2d2 68.12.104.178 56950 68.12.99.2 53 UDP DNS (megascor).no-ip.biz "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 10:01:07.299650" r2d2 68.12.104.178 56950 68.12.99.2 53 UDP DNS (megascor).no-ip.biz "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 10:01:26.337777" r2d2 68.12.104.178 54704 68.12.99.2 53 UDP DNS digitalmind.cn "palevo (malware)" palevotracker.abuse.ch\n' +
    '"2015-03-10 10:01:26.337780" r2d2 68.12.104.178 54704 68.12.99.2 53 UDP DNS digitalmind.cn "palevo (malware)" palevotracker.abuse.ch\n' +
    '"2015-03-10 10:01:27.181856" r2d2 68.12.104.178 37229 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 10:01:27.181857" r2d2 68.12.104.178 37229 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 10:01:39.361815" r2d2 68.12.104.178 44177 68.12.99.2 53 UDP DNS counter.yadro.ru "zeroaccess (malware)" (static)\n' +
    '"2015-03-10 10:01:39.361817" r2d2 68.12.104.178 44177 68.12.99.2 53 UDP DNS counter.yadro.ru "zeroaccess (malware)" (static)\n' +
    '"2015-03-10 10:01:43.783867" r2d2 68.12.104.178 56942 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 10:01:43.783865" r2d2 68.12.104.178 56942 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 10:01:58.134850" r2d2 68.12.104.178 57662 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 10:01:58.134848" r2d2 68.12.104.178 57662 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 10:02:06.107246" r2d2 68.12.104.178 48227 68.12.99.2 53 UDP DNS peer.pickeklosarske.ru "palevo (malware)" (static)\n' +
    '"2015-03-10 10:02:06.107243" r2d2 68.12.104.178 48227 68.12.99.2 53 UDP DNS peer.pickeklosarske.ru "palevo (malware)" (static)\n' +
    '"2015-03-10 10:02:06.372406" r2d2 68.12.104.178 43806 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 10:02:06.372403" r2d2 68.12.104.178 43806 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 10:02:30.356394" r2d2 68.12.104.178 57332 68.12.99.2 53 UDP DNS (megascor).no-ip.biz "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 10:02:30.356404" r2d2 68.12.104.178 57332 68.12.99.2 53 UDP DNS (megascor).no-ip.biz "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 10:02:37.199992" r2d2 68.12.104.178 44715 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 10:02:37.199993" r2d2 68.12.104.178 44715 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 10:02:43.724236" r2d2 68.12.104.178 37972 68.12.99.2 53 UDP DNS (super-hairstyles).tk "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:02:43.724234" r2d2 68.12.104.178 37972 68.12.99.2 53 UDP DNS (super-hairstyles).tk "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:02:59.745132" r2d2 68.12.104.178 46923 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 10:02:59.745134" r2d2 68.12.104.178 46923 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 10:03:05.942916" r2d2 68.12.104.178 41488 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 10:03:05.942915" r2d2 68.12.104.178 41488 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 10:03:30.576483" r2d2 68.12.104.178 44818 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 10:03:30.576484" r2d2 68.12.104.178 44818 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 10:03:38.819849" r2d2 68.12.104.178 43103 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 10:03:38.819851" r2d2 68.12.104.178 43103 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 10:03:53.857049" r2d2 68.12.104.178 41714 68.12.99.2 53 UDP DNS (brightlounge).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:03:53.856979" r2d2 68.12.104.178 41714 68.12.99.2 53 UDP DNS (brightlounge).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:04:00.136627" r2d2 68.12.104.178 59293 8.8.8.8 53 UDP DNS (brightlounge).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:04:00.136630" r2d2 68.12.104.178 59293 8.8.8.8 53 UDP DNS (brightlounge).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:04:07.626518" r2d2 68.12.104.178 46103 68.12.99.2 53 UDP DNS (megascor).no-ip.biz "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 10:04:07.626503" r2d2 68.12.104.178 46103 68.12.99.2 53 UDP DNS (megascor).no-ip.biz "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 10:04:09.649621" r2d2 68.12.104.178 35188 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 10:04:09.649622" r2d2 68.12.104.178 35188 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 10:04:13.632186" r2d2 68.12.104.178 51648 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 10:04:13.632188" r2d2 68.12.104.178 51648 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 10:04:32.181922" r2d2 68.12.104.178 35804 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 10:04:32.181909" r2d2 68.12.104.178 35804 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 10:04:34.885677" r2d2 68.12.104.178 52255 68.12.99.2 53 UDP DNS peer.pickeklosarske.ru "palevo (malware)" (static)\n' +
    '"2015-03-10 10:04:34.885681" r2d2 68.12.104.178 52255 68.12.99.2 53 UDP DNS peer.pickeklosarske.ru "palevo (malware)" (static)\n' +
    '"2015-03-10 10:05:03.009161" r2d2 68.12.104.178 47279 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 10:05:03.009158" r2d2 68.12.104.178 47279 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 10:05:29.698041" r2d2 68.12.104.178 43932 68.12.99.2 53 UDP DNS (megascor).no-ip.biz "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 10:05:29.698056" r2d2 68.12.104.178 43932 68.12.99.2 53 UDP DNS (megascor).no-ip.biz "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 10:05:34.375199" r2d2 68.12.104.178 42480 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 10:05:34.375195" r2d2 68.12.104.178 42480 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 10:05:36.972484" r2d2 68.12.104.178 57203 113.108.80.138 53 UDP IP 113.108.80.138 dnspod (custom)\n' +
    '"2015-03-10 10:05:36.972475" r2d2 68.12.104.178 57203 113.108.80.138 53 UDP IP 113.108.80.138 dnspod (custom)\n' +
    '"2015-03-10 10:05:42.131363" r2d2 68.12.104.178 55492 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 10:05:42.131361" r2d2 68.12.104.178 55492 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 10:06:04.619028" r2d2 68.12.104.178 55016 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 10:06:04.618839" r2d2 68.12.104.178 55016 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 10:06:13.208765" r2d2 68.12.104.178 38466 68.12.99.2 53 UDP DNS teske.pornicarke.com "palevo (malware)" (static)\n' +
    '"2015-03-10 10:06:13.208759" r2d2 68.12.104.178 38466 68.12.99.2 53 UDP DNS teske.pornicarke.com "palevo (malware)" (static)\n' +
    '"2015-03-10 10:06:35.447364" r2d2 68.12.104.178 42687 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 10:06:35.447366" r2d2 68.12.104.178 42687 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 10:06:42.597757" r2d2 68.12.104.178 37331 68.12.99.2 53 UDP DNS (megascor).no-ip.biz "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 10:06:42.597759" r2d2 68.12.104.178 37331 68.12.99.2 53 UDP DNS (megascor).no-ip.biz "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 10:06:42.935557" r2d2 68.12.104.178 35855 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 10:06:42.935561" r2d2 68.12.104.178 35855 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 10:06:43.738419" r2d2 68.12.104.178 40467 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 10:06:43.738418" r2d2 68.12.104.178 40467 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 10:07:05.460420" r2d2 68.12.104.178 44854 68.12.99.2 53 UDP DNS peer.pickeklosarske.ru "palevo (malware)" (static)\n' +
    '"2015-03-10 10:07:05.460417" r2d2 68.12.104.178 44854 68.12.99.2 53 UDP DNS peer.pickeklosarske.ru "palevo (malware)" (static)\n' +
    '"2015-03-10 10:07:14.565828" r2d2 68.12.104.178 56915 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 10:07:14.565813" r2d2 68.12.104.178 56915 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 10:07:37.056515" r2d2 68.12.104.178 35944 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 10:07:37.056516" r2d2 68.12.104.178 35944 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 10:07:40.337483" r2d2 68.12.104.178 41100 68.12.99.2 53 UDP DNS digitalmind.cn "palevo (malware)" palevotracker.abuse.ch\n' +
    '"2015-03-10 10:07:40.337485" r2d2 68.12.104.178 41100 68.12.99.2 53 UDP DNS digitalmind.cn "palevo (malware)" palevotracker.abuse.ch\n' +
    '"2015-03-10 10:07:48.888072" r2d2 68.12.104.178 58256 68.12.99.2 53 UDP DNS (megascor).no-ip.biz "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 10:07:48.888074" r2d2 68.12.104.178 58256 68.12.99.2 53 UDP DNS (megascor).no-ip.biz "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 10:08:05.872697" r2d2 68.12.104.178 36631 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 10:08:05.872712" r2d2 68.12.104.178 36631 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 10:08:07.883640" r2d2 68.12.104.178 37906 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 10:08:07.883823" r2d2 68.12.104.178 37906 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 10:08:16.172611" r2d2 68.12.104.178 41648 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 10:08:16.172609" r2d2 68.12.104.178 41648 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 10:08:46.733146" r2d2 68.12.104.178 53821 68.12.99.2 53 UDP DNS (extratorrent).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:08:46.733147" r2d2 68.12.104.178 53821 68.12.99.2 53 UDP DNS (extratorrent).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:08:46.739373" r2d2 68.12.104.178 59030 68.12.99.2 53 UDP DNS (extratorrent).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:08:46.739372" r2d2 68.12.104.178 59030 68.12.99.2 53 UDP DNS (extratorrent).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:08:47.000408" r2d2 68.12.104.178 57543 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 10:08:47.000407" r2d2 68.12.104.178 57543 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 10:09:06.983257" r2d2 68.12.104.178 41955 68.12.99.2 53 UDP DNS (megascor).no-ip.biz "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 10:09:06.983255" r2d2 68.12.104.178 41955 68.12.99.2 53 UDP DNS (megascor).no-ip.biz "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 10:09:09.493789" r2d2 68.12.104.178 43407 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 10:09:09.493817" r2d2 68.12.104.178 43407 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 10:09:11.677915" r2d2 68.12.104.178 47995 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 10:09:11.677916" r2d2 68.12.104.178 47995 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 10:09:12.734737" r2d2 68.12.104.178 56989 113.108.80.138 53 UDP IP 113.108.80.138 dnspod (custom)\n' +
    '"2015-03-10 10:09:12.734739" r2d2 68.12.104.178 56989 113.108.80.138 53 UDP IP 113.108.80.138 dnspod (custom)\n' +
    '"2015-03-10 10:09:28.145273" r2d2 68.12.104.178 48056 68.12.99.2 53 UDP DNS (www).browsestudio.com malware malwareurls.joxeankoret.com\n' +
    '"2015-03-10 10:09:28.145283" r2d2 68.12.104.178 48056 68.12.99.2 53 UDP DNS (www).browsestudio.com malware malwareurls.joxeankoret.com\n' +
    '"2015-03-10 10:09:28.174440" r2d2 68.12.104.178 48811 68.12.99.2 53 UDP DNS browsestudio.com malware malwareurls.joxeankoret.com\n' +
    '"2015-03-10 10:09:28.174444" r2d2 68.12.104.178 48811 68.12.99.2 53 UDP DNS browsestudio.com malware malwareurls.joxeankoret.com\n' +
    '"2015-03-10 10:09:28.880986" r2d2 68.12.104.178 46789 68.12.99.2 53 UDP DNS (www).best-deals-products.com superfish (static)\n' +
    '"2015-03-10 10:09:28.880987" r2d2 68.12.104.178 46789 68.12.99.2 53 UDP DNS (www).best-deals-products.com superfish (static)\n' +
    '"2015-03-10 10:09:29.058548" r2d2 68.12.104.178 51472 68.12.99.2 53 UDP DNS best-deals-products.com superfish (static)\n' +
    '"2015-03-10 10:09:29.058538" r2d2 68.12.104.178 51472 68.12.99.2 53 UDP DNS best-deals-products.com superfish (static)\n' +
    '"2015-03-10 10:09:36.357710" r2d2 68.12.104.178 59445 68.12.99.2 53 UDP DNS peer.pickeklosarske.ru "palevo (malware)" (static)\n' +
    '"2015-03-10 10:09:36.357711" r2d2 68.12.104.178 59445 68.12.99.2 53 UDP DNS peer.pickeklosarske.ru "palevo (malware)" (static)\n' +
    '"2015-03-10 10:09:40.321124" r2d2 68.12.104.178 37709 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 10:09:40.321125" r2d2 68.12.104.178 37709 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 10:09:48.610320" r2d2 68.12.104.178 43272 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 10:09:48.610345" r2d2 68.12.104.178 43272 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 10:10:19.434226" r2d2 68.12.104.178 37683 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 10:10:19.434230" r2d2 68.12.104.178 37683 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 10:10:29.143852" r2d2 68.12.104.178 57950 68.12.99.2 53 UDP DNS (megascor).no-ip.biz "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 10:10:29.143853" r2d2 68.12.104.178 57950 68.12.99.2 53 UDP DNS (megascor).no-ip.biz "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 10:10:33.854908" r2d2 68.12.104.178 57110 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 10:10:33.854906" r2d2 68.12.104.178 57110 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 10:10:42.181256" r2d2 68.12.104.178 42461 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 10:10:42.181259" r2d2 68.12.104.178 42461 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 10:11:13.007924" r2d2 68.12.104.178 40258 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 10:11:13.007923" r2d2 68.12.104.178 40258 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 10:11:21.139317" r2d2 68.12.104.178 47854 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 10:11:21.139329" r2d2 68.12.104.178 47854 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 10:11:41.738543" r2d2 68.12.104.178 35585 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 10:11:41.738541" r2d2 68.12.104.178 35585 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 10:11:50.245514" r2d2 68.12.104.178 42003 68.12.99.2 53 UDP DNS (static7).best-deals-products.com superfish (static)\n' +
    '"2015-03-10 10:11:50.245521" r2d2 68.12.104.178 42003 68.12.99.2 53 UDP DNS (static7).best-deals-products.com superfish (static)\n' +
    '"2015-03-10 10:11:50.255038" r2d2 68.12.104.178 54217 68.12.99.2 53 UDP DNS (static8).best-deals-products.com superfish (static)\n' +
    '"2015-03-10 10:11:50.255055" r2d2 68.12.104.178 58620 68.12.99.2 53 UDP DNS (static9).best-deals-products.com superfish (static)\n' +
    '"2015-03-10 10:11:50.255041" r2d2 68.12.104.178 54217 68.12.99.2 53 UDP DNS (static8).best-deals-products.com superfish (static)\n' +
    '"2015-03-10 10:11:50.255054" r2d2 68.12.104.178 58620 68.12.99.2 53 UDP DNS (static9).best-deals-products.com superfish (static)\n' +
    '"2015-03-10 10:11:50.352779" r2d2 68.12.104.178 38425 68.12.99.2 53 UDP DNS (static).best-deals-products.com superfish (static)\n' +
    '"2015-03-10 10:11:50.352776" r2d2 68.12.104.178 38425 68.12.99.2 53 UDP DNS (static).best-deals-products.com superfish (static)\n' +
    '"2015-03-10 10:11:51.963135" r2d2 68.12.104.178 40657 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 10:11:51.963133" r2d2 68.12.104.178 40657 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 10:11:58.266010" r2d2 68.12.104.178 50294 68.12.99.2 53 UDP DNS (megascor).no-ip.biz "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 10:11:58.265996" r2d2 68.12.104.178 50294 68.12.99.2 53 UDP DNS (megascor).no-ip.biz "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 10:12:00.601605" r2d2 68.12.104.178 57714 68.12.99.2 53 UDP DNS (errors).ourdatagenserv.com malware malwareurls.joxeankoret.com\n' +
    '"2015-03-10 10:12:00.601064" r2d2 68.12.104.178 57714 68.12.99.2 53 UDP DNS (errors).ourdatagenserv.com malware malwareurls.joxeankoret.com\n' +
    '"2015-03-10 10:12:03.803530" r2d2 68.12.104.178 46543 68.12.99.2 53 UDP DNS peer.pickeklosarske.ru "palevo (malware)" (static)\n' +
    '"2015-03-10 10:12:03.803529" r2d2 68.12.104.178 46543 68.12.99.2 53 UDP DNS peer.pickeklosarske.ru "palevo (malware)" (static)\n' +
    '"2015-03-10 10:12:14.617326" r2d2 68.12.104.178 41872 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 10:12:14.617310" r2d2 68.12.104.178 41872 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 10:12:42.209528" r2d2 68.12.104.178 41149 68.12.99.2 53 UDP DNS (static.extratorrent).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:12:42.209526" r2d2 68.12.104.178 41149 68.12.99.2 53 UDP DNS (static.extratorrent).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:12:42.227421" r2d2 68.12.104.178 40204 68.12.99.2 53 UDP DNS www.vipcpms.com malware malwaredomainlist.com\n' +
    '"2015-03-10 10:12:42.227423" r2d2 68.12.104.178 40204 68.12.99.2 53 UDP DNS www.vipcpms.com malware malwaredomainlist.com\n' +
    '"2015-03-10 10:12:45.446182" r2d2 68.12.104.178 40008 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 10:12:45.446185" r2d2 68.12.104.178 40008 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 10:12:53.571539" r2d2 68.12.104.178 48966 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 10:12:53.571541" r2d2 68.12.104.178 48966 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 10:12:58.445274" r2d2 68.12.104.178 37877 68.12.99.2 53 UDP DNS (k7x).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:12:58.445273" r2d2 68.12.104.178 37877 68.12.99.2 53 UDP DNS (k7x).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:12:59.464495" r2d2 68.12.104.178 43921 68.12.99.2 53 UDP DNS counter.yadro.ru "zeroaccess (malware)" (static)\n' +
    '"2015-03-10 10:12:59.464493" r2d2 68.12.104.178 43921 68.12.99.2 53 UDP DNS counter.yadro.ru "zeroaccess (malware)" (static)\n' +
    '"2015-03-10 10:13:03.829947" r2d2 68.12.104.178 37445 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 10:13:03.829952" r2d2 68.12.104.178 37445 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 10:13:17.240586" r2d2 68.12.104.178 51243 68.12.99.2 53 UDP DNS (megascor).no-ip.biz "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 10:13:17.240584" r2d2 68.12.104.178 51243 68.12.99.2 53 UDP DNS (megascor).no-ip.biz "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 10:13:24.396818" r2d2 68.12.104.178 40398 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 10:13:24.396813" r2d2 68.12.104.178 40398 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 10:13:47.054933" r2d2 68.12.104.178 52419 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 10:13:47.054936" r2d2 68.12.104.178 52419 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 10:13:54.510197" r2d2 68.12.104.178 47990 68.12.99.2 53 UDP DNS digitalmind.cn "palevo (malware)" palevotracker.abuse.ch\n' +
    '"2015-03-10 10:13:54.510195" r2d2 68.12.104.178 47990 68.12.99.2 53 UDP DNS digitalmind.cn "palevo (malware)" palevotracker.abuse.ch\n' +
    '"2015-03-10 10:14:11.800211" r2d2 68.12.104.178 46382 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 10:14:11.800213" r2d2 68.12.104.178 46382 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 10:14:18.148569" r2d2 68.12.104.178 59272 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 10:14:18.148568" r2d2 68.12.104.178 59272 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 10:14:26.004527" r2d2 68.12.104.178 42994 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 10:14:26.004529" r2d2 68.12.104.178 42994 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 10:14:29.069821" r2d2 68.12.104.178 40077 68.12.99.2 53 UDP DNS (tracker.coppersurfer).tk "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:14:29.070069" r2d2 68.12.104.178 40077 68.12.99.2 53 UDP DNS (tracker.coppersurfer).tk "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:14:29.167420" r2d2 68.12.104.178 40802 68.12.99.2 53 UDP DNS (tracker.coppersurfer).tk "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:14:29.167419" r2d2 68.12.104.178 40802 68.12.99.2 53 UDP DNS (tracker.coppersurfer).tk "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:14:33.869267" r2d2 68.12.104.178 50255 68.12.99.2 53 UDP DNS peer.pickeklosarske.ru "palevo (malware)" (static)\n' +
    '"2015-03-10 10:14:33.869268" r2d2 68.12.104.178 50255 68.12.99.2 53 UDP DNS peer.pickeklosarske.ru "palevo (malware)" (static)\n' +
    '"2015-03-10 10:14:34.250314" r2d2 68.12.104.178 47415 68.12.99.2 53 UDP DNS (megascor).no-ip.biz "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 10:14:34.250311" r2d2 68.12.104.178 47415 68.12.99.2 53 UDP DNS (megascor).no-ip.biz "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 10:14:56.832647" r2d2 68.12.104.178 43909 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 10:14:56.832653" r2d2 68.12.104.178 43909 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 10:15:19.758209" r2d2 68.12.104.178 51380 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 10:15:19.758213" r2d2 68.12.104.178 51380 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 10:15:33.842954" r2d2 68.12.104.178 41195 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 10:15:33.842956" r2d2 68.12.104.178 41195 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 10:15:41.082871" r2d2 68.12.104.178 35611 68.12.99.2 53 UDP DNS (megascor).no-ip.biz "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 10:15:50.585944" r2d2 68.12.104.178 50324 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 10:15:50.585942" r2d2 68.12.104.178 50324 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 10:15:58.440889" r2d2 68.12.104.178 42675 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 10:15:58.440892" r2d2 68.12.104.178 42675 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 10:16:29.265913" r2d2 68.12.104.178 37002 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 10:16:29.265915" r2d2 68.12.104.178 37002 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 10:16:41.861190" r2d2 68.12.104.178 53654 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 10:16:41.861189" r2d2 68.12.104.178 53654 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 10:16:48.293182" r2d2 68.12.104.178 41512 68.12.99.2 53 UDP DNS (megascor).no-ip.biz "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 10:16:52.200552" r2d2 68.12.104.178 58605 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 10:16:52.200550" r2d2 68.12.104.178 58605 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 10:17:02.095304" r2d2 68.12.104.178 41817 68.12.99.2 53 UDP DNS (lajf09).zapto.org "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 10:17:02.095305" r2d2 68.12.104.178 41817 68.12.99.2 53 UDP DNS (lajf09).zapto.org "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 10:17:03.212258" r2d2 68.12.104.178 35054 68.12.99.2 53 UDP DNS (ns1.demiart).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:17:03.212255" r2d2 68.12.104.178 35054 68.12.99.2 53 UDP DNS (ns1.demiart).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:17:03.212688" r2d2 68.12.104.178 53899 68.12.99.2 53 UDP DNS (ns2.demiart).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:17:03.212686" r2d2 68.12.104.178 53899 68.12.99.2 53 UDP DNS (ns2.demiart).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:17:03.855522" r2d2 68.12.104.178 41307 68.12.99.2 53 UDP DNS peer.pickeklosarske.ru "palevo (malware)" (static)\n' +
    '"2015-03-10 10:17:03.855524" r2d2 68.12.104.178 41307 68.12.99.2 53 UDP DNS peer.pickeklosarske.ru "palevo (malware)" (static)\n' +
    '"2015-03-10 10:17:23.022537" r2d2 68.12.104.178 39467 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 10:17:23.022535" r2d2 68.12.104.178 39467 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 10:17:30.873311" r2d2 68.12.104.178 37335 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 10:17:30.873310" r2d2 68.12.104.178 37335 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 10:17:33.854002" r2d2 68.12.104.178 36262 68.12.99.2 53 UDP DNS teske.pornicarke.com "palevo (malware)" (static)\n' +
    '"2015-03-10 10:17:33.854000" r2d2 68.12.104.178 36262 68.12.99.2 53 UDP DNS teske.pornicarke.com "palevo (malware)" (static)\n' +
    '"2015-03-10 10:17:41.877695" r2d2 68.12.104.178 38448 68.12.99.2 53 UDP DNS jebena.ananikolic.su "palevo (malware)" (static)\n' +
    '"2015-03-10 10:17:41.877696" r2d2 68.12.104.178 38448 68.12.99.2 53 UDP DNS jebena.ananikolic.su "palevo (malware)" (static)\n' +
    '"2015-03-10 10:17:49.333115" r2d2 68.12.104.178 50951 68.12.99.2 53 UDP DNS (kaknado).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:17:49.333111" r2d2 68.12.104.178 50951 68.12.99.2 53 UDP DNS (kaknado).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:17:53.149212" r2d2 68.12.104.178 46031 68.12.99.2 53 UDP DNS (brightlounge).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:17:53.149224" r2d2 68.12.104.178 46031 68.12.99.2 53 UDP DNS (brightlounge).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:17:53.577645" r2d2 68.12.104.178 40386 113.108.80.138 53 UDP IP 113.108.80.138 dnspod (custom)\n' +
    '"2015-03-10 10:17:53.577632" r2d2 68.12.104.178 40386 113.108.80.138 53 UDP IP 113.108.80.138 dnspod (custom)\n' +
    '"2015-03-10 10:17:53.585372" r2d2 68.12.104.178 50470 113.108.80.138 53 UDP IP 113.108.80.138 dnspod (custom)\n' +
    '"2015-03-10 10:17:53.585374" r2d2 68.12.104.178 50470 113.108.80.138 53 UDP IP 113.108.80.138 dnspod (custom)\n' +
    '"2015-03-10 10:17:53.745515" r2d2 68.12.104.178 49230 113.108.80.138 53 UDP IP 113.108.80.138 dnspod (custom)\n' +
    '"2015-03-10 10:17:53.745504" r2d2 68.12.104.178 49230 113.108.80.138 53 UDP IP 113.108.80.138 dnspod (custom)\n' +
    '"2015-03-10 10:17:59.179212" r2d2 68.12.104.178 44900 8.8.8.8 53 UDP DNS (brightlounge).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:17:59.179204" r2d2 68.12.104.178 44900 8.8.8.8 53 UDP DNS (brightlounge).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:18:01.700265" r2d2 68.12.104.178 35553 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 10:18:01.700267" r2d2 68.12.104.178 35553 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 10:18:03.838311" r2d2 68.12.104.178 42438 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 10:18:03.838315" r2d2 68.12.104.178 42438 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 10:18:24.631744" r2d2 68.12.104.178 43686 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 10:18:24.631745" r2d2 68.12.104.178 43686 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 10:18:53.936076" r2d2 68.12.104.178 36858 68.12.99.2 53 UDP DNS (jabberstorm).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:18:53.936343" r2d2 68.12.104.178 36858 68.12.99.2 53 UDP DNS (jabberstorm).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:18:55.460851" r2d2 68.12.104.178 37552 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 10:18:55.460856" r2d2 68.12.104.178 37552 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 10:18:59.179600" r2d2 68.12.104.178 44900 8.8.8.8 53 UDP DNS (jabberstorm).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:18:59.179601" r2d2 68.12.104.178 44900 8.8.8.8 53 UDP DNS (jabberstorm).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:19:03.403282" r2d2 68.12.104.178 40867 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 10:19:03.403280" r2d2 68.12.104.178 40867 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 10:19:11.576795" r2d2 61.240.144.66 60000 68.12.104.178 161 TCP IP 61.240.144.66 "incoming masscan detected" autoshun.org\n' +
    '"2015-03-10 10:19:11.576799" r2d2 61.240.144.66 60000 68.12.104.178 161 TCP IP 61.240.144.66 "incoming masscan detected" autoshun.org\n' +
    '"2015-03-10 10:19:11.793922" r2d2 68.12.104.178 53275 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 10:19:11.793932" r2d2 68.12.104.178 53275 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 10:19:33.835994" r2d2 68.12.104.178 36689 68.12.99.2 53 UDP DNS peer.pickeklosarske.ru "palevo (malware)" (static)\n' +
    '"2015-03-10 10:19:33.835987" r2d2 68.12.104.178 36689 68.12.99.2 53 UDP DNS peer.pickeklosarske.ru "palevo (malware)" (static)\n' +
    '"2015-03-10 10:19:34.228585" r2d2 68.12.104.178 39970 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 10:19:34.228587" r2d2 68.12.104.178 39970 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 10:19:41.692455" r2d2 68.12.104.178 57061 68.12.99.2 53 UDP DNS (tracker.coppersurfer).tk "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:19:41.692410" r2d2 68.12.104.178 57061 68.12.99.2 53 UDP DNS (tracker.coppersurfer).tk "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:19:57.068720" r2d2 68.12.104.178 38212 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 10:19:57.068725" r2d2 68.12.104.178 38212 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 10:20:04.793283" r2d2 68.12.104.178 53243 68.12.99.2 53 UDP DNS digitalmind.cn "palevo (malware)" palevotracker.abuse.ch\n' +
    '"2015-03-10 10:20:04.793281" r2d2 68.12.104.178 53243 68.12.99.2 53 UDP DNS digitalmind.cn "palevo (malware)" palevotracker.abuse.ch\n' +
    '"2015-03-10 10:20:27.897142" r2d2 68.12.104.178 43396 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 10:20:27.897141" r2d2 68.12.104.178 43396 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 10:20:29.615239" r2d2 68.12.104.178 58704 113.108.80.138 53 UDP IP 113.108.80.138 dnspod (custom)\n' +
    '"2015-03-10 10:20:29.615235" r2d2 68.12.104.178 58704 113.108.80.138 53 UDP IP 113.108.80.138 dnspod (custom)\n' +
    '"2015-03-10 10:20:33.834710" r2d2 68.12.104.178 39815 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 10:20:33.834708" r2d2 68.12.104.178 39815 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 10:20:35.835972" r2d2 68.12.104.178 36403 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 10:20:35.835973" r2d2 68.12.104.178 36403 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 10:21:06.662595" r2d2 68.12.104.178 49017 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 10:21:06.662598" r2d2 68.12.104.178 49017 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 10:21:16.273612" r2d2 68.12.104.178 40545 68.12.99.2 53 UDP DNS (megascor).no-ip.biz "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 10:21:16.273615" r2d2 68.12.104.178 40545 68.12.99.2 53 UDP DNS (megascor).no-ip.biz "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 10:21:29.506979" r2d2 68.12.104.178 47983 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 10:21:29.506981" r2d2 68.12.104.178 47983 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 10:21:31.422670" r2d2 68.12.104.178 52379 68.12.99.2 53 UDP DNS dentesmitec.ru "zeus (malware)" zeustracker.abuse.ch\n' +
    '"2015-03-10 10:21:31.422667" r2d2 68.12.104.178 52379 68.12.99.2 53 UDP DNS dentesmitec.ru "zeus (malware)" zeustracker.abuse.ch\n' +
    '"2015-03-10 10:21:41.733391" r2d2 68.12.104.178 58794 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 10:21:41.733390" r2d2 68.12.104.178 58794 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 10:21:52.151929" r2d2 68.12.104.178 42672 68.12.99.2 53 UDP DNS (diamandwell).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:21:52.151930" r2d2 68.12.104.178 42672 68.12.99.2 53 UDP DNS (diamandwell).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:22:00.333928" r2d2 68.12.104.178 39963 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 10:22:00.333931" r2d2 68.12.104.178 39963 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 10:22:03.819128" r2d2 68.12.104.178 50590 68.12.99.2 53 UDP DNS peer.pickeklosarske.ru "palevo (malware)" (static)\n' +
    '"2015-03-10 10:22:08.274142" r2d2 68.12.104.178 49295 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 10:22:08.274143" r2d2 68.12.104.178 49295 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 10:22:39.208037" r2d2 68.12.104.178 53110 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 10:22:39.208039" r2d2 68.12.104.178 53110 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 10:22:40.960463" r2d2 68.12.104.178 54770 68.12.99.2 53 UDP DNS (www).superfish.com superfish (static)\n' +
    '"2015-03-10 10:22:40.960462" r2d2 68.12.104.178 54770 68.12.99.2 53 UDP DNS (www).superfish.com superfish (static)\n' +
    '"2015-03-10 10:22:41.138246" r2d2 68.12.104.178 47787 68.12.99.2 53 UDP DNS superfish.com superfish (static)\n' +
    '"2015-03-10 10:22:41.138248" r2d2 68.12.104.178 47787 68.12.99.2 53 UDP DNS superfish.com superfish (static)\n' +
    '"2015-03-10 10:23:01.945381" r2d2 68.12.104.178 37919 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 10:23:01.945383" r2d2 68.12.104.178 37919 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 10:23:03.816122" r2d2 68.12.104.178 39722 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 10:23:03.816125" r2d2 68.12.104.178 39722 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 10:23:15.679885" r2d2 68.12.104.178 37646 68.12.99.2 53 UDP DNS (megascor).no-ip.biz "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 10:23:15.679882" r2d2 68.12.104.178 37646 68.12.99.2 53 UDP DNS (megascor).no-ip.biz "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 10:23:32.770884" r2d2 68.12.104.178 41268 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 10:23:32.770898" r2d2 68.12.104.178 41268 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 10:23:40.815462" r2d2 68.12.104.178 38376 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 10:23:40.815459" r2d2 68.12.104.178 38376 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 10:23:42.441460" r2d2 68.12.104.178 44030 68.12.99.2 53 UDP DNS (api).browsestudio.com malware malwareurls.joxeankoret.com\n' +
    '"2015-03-10 10:23:42.441476" r2d2 68.12.104.178 44030 68.12.99.2 53 UDP DNS (api).browsestudio.com malware malwareurls.joxeankoret.com\n' +
    '"2015-03-10 10:23:42.795005" r2d2 68.12.104.178 44227 68.12.99.2 53 UDP DNS browsestudio.com malware malwareurls.joxeankoret.com\n' +
    '"2015-03-10 10:23:42.795007" r2d2 68.12.104.178 44227 68.12.99.2 53 UDP DNS browsestudio.com malware malwareurls.joxeankoret.com\n' +
    '"2015-03-10 10:24:11.640800" r2d2 68.12.104.178 43491 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 10:24:11.640802" r2d2 68.12.104.178 43491 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 10:24:11.778987" r2d2 68.12.104.178 45580 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 10:24:11.778986" r2d2 68.12.104.178 45580 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 10:24:22.404145" r2d2 68.12.104.178 48321 68.12.99.2 53 UDP DNS (mailcluster01.cbs).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:24:22.404150" r2d2 68.12.104.178 48321 68.12.99.2 53 UDP DNS (mailcluster01.cbs).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:24:33.814568" r2d2 68.12.104.178 42461 68.12.99.2 53 UDP DNS peer.pickeklosarske.ru "palevo (malware)" (static)\n' +
    '"2015-03-10 10:24:33.814567" r2d2 68.12.104.178 42461 68.12.99.2 53 UDP DNS peer.pickeklosarske.ru "palevo (malware)" (static)\n' +
    '"2015-03-10 10:24:34.380446" r2d2 68.12.104.178 51529 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 10:24:34.380444" r2d2 68.12.104.178 51529 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 10:25:05.208574" r2d2 68.12.104.178 45230 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 10:25:05.208576" r2d2 68.12.104.178 45230 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 10:25:13.249306" r2d2 68.12.104.178 35463 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 10:25:13.249303" r2d2 68.12.104.178 35463 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 10:25:33.814213" r2d2 68.12.104.178 46312 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 10:25:33.814215" r2d2 68.12.104.178 46312 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 10:25:44.077018" r2d2 68.12.104.178 41927 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 10:25:44.077024" r2d2 68.12.104.178 41927 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 10:25:52.608870" r2d2 68.12.104.178 45600 68.12.99.2 53 UDP DNS promisex.ru "zeus (malware)" (custom)\n' +
    '"2015-03-10 10:25:52.608868" r2d2 68.12.104.178 45600 68.12.99.2 53 UDP DNS promisex.ru "zeus (malware)" (custom)\n' +
    '"2015-03-10 10:26:06.818452" r2d2 68.12.104.178 52316 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 10:26:06.818454" r2d2 68.12.104.178 52316 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 10:26:15.058003" r2d2 68.12.104.178 41071 68.12.99.2 53 UDP DNS digitalmind.cn "palevo (malware)" palevotracker.abuse.ch\n' +
    '"2015-03-10 10:26:15.058005" r2d2 68.12.104.178 41071 68.12.99.2 53 UDP DNS digitalmind.cn "palevo (malware)" palevotracker.abuse.ch\n' +
    '"2015-03-10 10:26:21.186451" r2d2 68.12.104.178 53368 8.8.8.8 53 UDP DNS digitalmind.cn "palevo (malware)" palevotracker.abuse.ch\n' +
    '"2015-03-10 10:26:21.186448" r2d2 68.12.104.178 53368 8.8.8.8 53 UDP DNS digitalmind.cn "palevo (malware)" palevotracker.abuse.ch\n' +
    '"2015-03-10 10:26:37.786072" r2d2 68.12.104.178 42826 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 10:26:37.786061" r2d2 68.12.104.178 42826 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 10:26:41.840107" r2d2 68.12.104.178 39085 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 10:26:41.840010" r2d2 68.12.104.178 39085 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 10:26:45.739513" r2d2 68.12.104.178 37694 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 10:26:45.739511" r2d2 68.12.104.178 37694 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 10:27:03.910655" r2d2 68.12.104.178 46926 68.12.99.2 53 UDP DNS peer.pickeklosarske.ru "palevo (malware)" (static)\n' +
    '"2015-03-10 10:27:03.910635" r2d2 68.12.104.178 46926 68.12.99.2 53 UDP DNS peer.pickeklosarske.ru "palevo (malware)" (static)\n' +
    '"2015-03-10 10:27:06.436272" r2d2 68.12.104.178 39643 68.12.99.2 53 UDP DNS (yoxwscyfftr).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:27:06.436275" r2d2 68.12.104.178 39643 68.12.99.2 53 UDP DNS (yoxwscyfftr).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:27:06.566908" r2d2 68.12.104.178 53087 68.12.99.2 53 UDP DNS (mbmpmbhpl).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:27:06.566901" r2d2 68.12.104.178 53087 68.12.99.2 53 UDP DNS (mbmpmbhpl).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:27:06.757557" r2d2 68.12.104.178 46342 68.12.99.2 53 UDP DNS (megascor).no-ip.biz "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 10:27:06.757556" r2d2 68.12.104.178 46342 68.12.99.2 53 UDP DNS (megascor).no-ip.biz "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 10:27:06.782496" r2d2 68.12.104.178 59243 68.12.99.2 53 UDP DNS (nmmjymkprlsxyruiksvq).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:27:06.782509" r2d2 68.12.104.178 59243 68.12.99.2 53 UDP DNS (nmmjymkprlsxyruiksvq).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:27:06.853194" r2d2 68.12.104.178 44838 68.12.99.2 53 UDP DNS (gdssshqutbjg).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:27:06.853196" r2d2 68.12.104.178 44838 68.12.99.2 53 UDP DNS (gdssshqutbjg).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:27:06.887679" r2d2 68.12.104.178 47791 68.12.99.2 53 UDP DNS (bpulloppkoswireo).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:27:06.887676" r2d2 68.12.104.178 47791 68.12.99.2 53 UDP DNS (bpulloppkoswireo).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:27:06.915396" r2d2 68.12.104.178 58710 68.12.99.2 53 UDP DNS (yqmddygacl).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:27:06.915399" r2d2 68.12.104.178 58710 68.12.99.2 53 UDP DNS (yqmddygacl).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:27:07.327730" r2d2 68.12.104.178 52970 68.12.99.2 53 UDP DNS (wehuckdtdm).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:27:07.766155" r2d2 68.12.104.178 38993 68.12.99.2 53 UDP DNS (ohihswxtf).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:27:07.766169" r2d2 68.12.104.178 38993 68.12.99.2 53 UDP DNS (ohihswxtf).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:27:08.368134" r2d2 68.12.104.178 39067 68.12.99.2 53 UDP DNS (dhntjoyse).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:27:08.368135" r2d2 68.12.104.178 39067 68.12.99.2 53 UDP DNS (dhntjoyse).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:27:08.877914" r2d2 68.12.104.178 41729 68.12.99.2 53 UDP DNS (tlmetrogsj).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:27:08.877912" r2d2 68.12.104.178 41729 68.12.99.2 53 UDP DNS (tlmetrogsj).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:27:09.060136" r2d2 68.12.104.178 37161 68.12.99.2 53 UDP DNS (kypbrupnjm).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:27:09.060138" r2d2 68.12.104.178 37161 68.12.99.2 53 UDP DNS (kypbrupnjm).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:27:09.431145" r2d2 68.12.104.178 46794 68.12.99.2 53 UDP DNS (jaeceglpxrycfkf).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:27:09.431142" r2d2 68.12.104.178 46794 68.12.99.2 53 UDP DNS (jaeceglpxrycfkf).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:27:09.823749" r2d2 68.12.104.178 38515 68.12.99.2 53 UDP DNS (xcorqmyioedncw).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:27:09.823750" r2d2 68.12.104.178 38515 68.12.99.2 53 UDP DNS (xcorqmyioedncw).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:27:10.147431" r2d2 68.12.104.178 46352 68.12.99.2 53 UDP DNS (qdvjvqrelna).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:27:10.147428" r2d2 68.12.104.178 46352 68.12.99.2 53 UDP DNS (qdvjvqrelna).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:27:10.615687" r2d2 68.12.104.178 54978 68.12.99.2 53 UDP DNS (gsomievmdpibw).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:27:10.615689" r2d2 68.12.104.178 54978 68.12.99.2 53 UDP DNS (gsomievmdpibw).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:27:10.649993" r2d2 68.12.104.178 50408 68.12.99.2 53 UDP DNS (hfdxsmmkilvf).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:27:10.649991" r2d2 68.12.104.178 50408 68.12.99.2 53 UDP DNS (hfdxsmmkilvf).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:27:10.975524" r2d2 68.12.104.178 40824 68.12.99.2 53 UDP DNS (nbniwyiamfsbugkenyjpd).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:27:10.975525" r2d2 68.12.104.178 40824 68.12.99.2 53 UDP DNS (nbniwyiamfsbugkenyjpd).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:27:11.038002" r2d2 68.12.104.178 37036 68.12.99.2 53 UDP DNS (qakjsundwigw).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:27:11.038007" r2d2 68.12.104.178 37036 68.12.99.2 53 UDP DNS (qakjsundwigw).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:27:11.053982" r2d2 68.12.104.178 40421 68.12.99.2 53 UDP DNS (kjbehpxwlufkcx).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:27:11.053999" r2d2 68.12.104.178 40421 68.12.99.2 53 UDP DNS (kjbehpxwlufkcx).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:27:11.098489" r2d2 68.12.104.178 52710 68.12.99.2 53 UDP DNS (nutwqorkjbgxo).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:27:11.098492" r2d2 68.12.104.178 52710 68.12.99.2 53 UDP DNS (nutwqorkjbgxo).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:27:12.361198" r2d2 68.12.104.178 38768 68.12.99.2 53 UDP DNS (wymbfqgy).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:27:12.361203" r2d2 68.12.104.178 38768 68.12.99.2 53 UDP DNS (wymbfqgy).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:27:12.686158" r2d2 68.12.104.178 42442 68.12.99.2 53 UDP DNS (vurfkwodmraiiqtmqopi).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:27:12.686197" r2d2 68.12.104.178 42442 68.12.99.2 53 UDP DNS (vurfkwodmraiiqtmqopi).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:27:13.530144" r2d2 68.12.104.178 39984 68.12.99.2 53 UDP DNS (nhfcubvcst).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:27:13.530156" r2d2 68.12.104.178 39984 68.12.99.2 53 UDP DNS (nhfcubvcst).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:27:13.535612" r2d2 68.12.104.178 48234 68.12.99.2 53 UDP DNS (qqkmrhouyxgl).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:27:13.535613" r2d2 68.12.104.178 48234 68.12.99.2 53 UDP DNS (qqkmrhouyxgl).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:27:13.799443" r2d2 68.12.104.178 49430 68.12.99.2 53 UDP DNS (gypnuwvydjdpfq).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:27:13.799442" r2d2 68.12.104.178 49430 68.12.99.2 53 UDP DNS (gypnuwvydjdpfq).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:27:13.913589" r2d2 68.12.104.178 42724 68.12.99.2 53 UDP DNS (tyfjxeckqbo).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:27:13.913590" r2d2 68.12.104.178 42724 68.12.99.2 53 UDP DNS (tyfjxeckqbo).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:27:14.119643" r2d2 68.12.104.178 56641 68.12.99.2 53 UDP DNS (hcarsjmhvpnen).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:27:14.119641" r2d2 68.12.104.178 56641 68.12.99.2 53 UDP DNS (hcarsjmhvpnen).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:27:14.131643" r2d2 68.12.104.178 58812 68.12.99.2 53 UDP DNS (uxuivdbl).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:27:14.131645" r2d2 68.12.104.178 58812 68.12.99.2 53 UDP DNS (uxuivdbl).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:27:14.546507" r2d2 68.12.104.178 40284 68.12.99.2 53 UDP DNS (ceiymicjifpncdebnu).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:27:14.546511" r2d2 68.12.104.178 40284 68.12.99.2 53 UDP DNS (ceiymicjifpncdebnu).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:27:14.692103" r2d2 68.12.104.178 47533 68.12.99.2 53 UDP DNS (erbjnidvgh).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:27:14.692106" r2d2 68.12.104.178 47533 68.12.99.2 53 UDP DNS (erbjnidvgh).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:27:14.897479" r2d2 68.12.104.178 47208 68.12.99.2 53 UDP DNS cychefs.com malware cybercrime-tracker.net\n' +
    '"2015-03-10 10:27:14.897466" r2d2 68.12.104.178 47208 68.12.99.2 53 UDP DNS cychefs.com malware cybercrime-tracker.net\n' +
    '"2015-03-10 10:27:15.476415" r2d2 68.12.104.178 58065 68.12.99.2 53 UDP DNS (sntyacoaditegysqhg).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:27:15.476411" r2d2 68.12.104.178 58065 68.12.99.2 53 UDP DNS (sntyacoaditegysqhg).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:27:15.567887" r2d2 68.12.104.178 39440 68.12.99.2 53 UDP DNS (egwdhbgweqcmpsk).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:27:15.567889" r2d2 68.12.104.178 39440 68.12.99.2 53 UDP DNS (egwdhbgweqcmpsk).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:27:15.667502" r2d2 68.12.104.178 36261 68.12.99.2 53 UDP DNS (dbmsimpbtpewyacsolpqg).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:27:15.667498" r2d2 68.12.104.178 36261 68.12.99.2 53 UDP DNS (dbmsimpbtpewyacsolpqg).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:27:16.571901" r2d2 68.12.104.178 36822 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 10:27:16.571899" r2d2 68.12.104.178 36822 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 10:27:16.630846" r2d2 68.12.104.178 36831 68.12.99.2 53 UDP DNS (yteypts).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:27:16.630868" r2d2 68.12.104.178 36831 68.12.99.2 53 UDP DNS (yteypts).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:27:16.957120" r2d2 68.12.104.178 59929 68.12.99.2 53 UDP DNS (gaiyrmgfqehdrv).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:27:16.957118" r2d2 68.12.104.178 59929 68.12.99.2 53 UDP DNS (gaiyrmgfqehdrv).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:27:17.107840" r2d2 68.12.104.178 40100 68.12.99.2 53 UDP DNS (ylhcikqsv).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:27:17.107841" r2d2 68.12.104.178 40100 68.12.99.2 53 UDP DNS (ylhcikqsv).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:27:17.583308" r2d2 68.12.104.178 35215 68.12.99.2 53 UDP DNS (alhlxqaxof).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:27:17.583304" r2d2 68.12.104.178 35215 68.12.99.2 53 UDP DNS (alhlxqaxof).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:27:17.802542" r2d2 68.12.104.178 44000 68.12.99.2 53 UDP DNS (bvlkxnt).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:27:17.802541" r2d2 68.12.104.178 44000 68.12.99.2 53 UDP DNS (bvlkxnt).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:27:18.005908" r2d2 68.12.104.178 56915 68.12.99.2 53 UDP DNS (vrmqckwm).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:27:18.005906" r2d2 68.12.104.178 56915 68.12.99.2 53 UDP DNS (vrmqckwm).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:27:18.367007" r2d2 68.12.104.178 41644 68.12.99.2 53 UDP DNS (kshotkykawjnvw).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:27:18.366997" r2d2 68.12.104.178 41644 68.12.99.2 53 UDP DNS (kshotkykawjnvw).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:27:18.885072" r2d2 68.12.104.178 58551 68.12.99.2 53 UDP DNS (giwbrwlgllswtch).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:27:18.885071" r2d2 68.12.104.178 58551 68.12.99.2 53 UDP DNS (giwbrwlgllswtch).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:27:18.978347" r2d2 68.12.104.178 52392 68.12.99.2 53 UDP DNS (hsmuepiemno).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:27:18.978349" r2d2 68.12.104.178 52392 68.12.99.2 53 UDP DNS (hsmuepiemno).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:27:19.383361" r2d2 68.12.104.178 39645 68.12.99.2 53 UDP DNS (frnmlmwvdyrgqucesits).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:27:19.697863" r2d2 68.12.104.178 49247 68.12.99.2 53 UDP DNS (uyqeudxqybqcqseou).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:27:19.697860" r2d2 68.12.104.178 49247 68.12.99.2 53 UDP DNS (uyqeudxqybqcqseou).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:27:19.925183" r2d2 68.12.104.178 39715 68.12.99.2 53 UDP DNS (bvtnvasdlmcduftmigc).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:27:19.925185" r2d2 68.12.104.178 39715 68.12.99.2 53 UDP DNS (bvtnvasdlmcduftmigc).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:27:20.343252" r2d2 68.12.104.178 46778 68.12.99.2 53 UDP DNS (eyphigsiqgkmrumur).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:27:20.343251" r2d2 68.12.104.178 46778 68.12.99.2 53 UDP DNS (eyphigsiqgkmrumur).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:27:21.132816" r2d2 68.12.104.178 55111 68.12.99.2 53 UDP DNS (rdhsqqeatpape).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:27:21.132923" r2d2 68.12.104.178 55111 68.12.99.2 53 UDP DNS (rdhsqqeatpape).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:27:21.439796" r2d2 68.12.104.178 37572 68.12.99.2 53 UDP DNS (diiojdftje).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:27:21.439797" r2d2 68.12.104.178 37572 68.12.99.2 53 UDP DNS (diiojdftje).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:27:21.609371" r2d2 68.12.104.178 48440 68.12.99.2 53 UDP DNS (vsqxboyqde).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:27:21.609361" r2d2 68.12.104.178 48440 68.12.99.2 53 UDP DNS (vsqxboyqde).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:27:21.961834" r2d2 68.12.104.178 36049 68.12.99.2 53 UDP DNS (esxqrqnaeevrgd).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:27:21.961835" r2d2 68.12.104.178 36049 68.12.99.2 53 UDP DNS (esxqrqnaeevrgd).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:27:22.069272" r2d2 68.12.104.178 51402 68.12.99.2 53 UDP DNS (feooutflcxoc).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:27:22.069269" r2d2 68.12.104.178 51402 68.12.99.2 53 UDP DNS (feooutflcxoc).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:27:22.499106" r2d2 68.12.104.178 35088 68.12.99.2 53 UDP DNS (ussyuxendpq).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:27:22.499101" r2d2 68.12.104.178 35088 68.12.99.2 53 UDP DNS (ussyuxendpq).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:27:22.579711" r2d2 68.12.104.178 56398 68.12.99.2 53 UDP DNS (pthdngfsyixqtswlvli).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:27:22.579709" r2d2 68.12.104.178 56398 68.12.99.2 53 UDP DNS (pthdngfsyixqtswlvli).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:27:23.012552" r2d2 68.12.104.178 40250 68.12.99.2 53 UDP DNS (srbqfeabymofcuglqlx).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:27:23.012551" r2d2 68.12.104.178 40250 68.12.99.2 53 UDP DNS (srbqfeabymofcuglqlx).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:27:23.714311" r2d2 68.12.104.178 51690 68.12.99.2 53 UDP DNS (nbcdtimwr).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:27:23.714313" r2d2 68.12.104.178 51690 68.12.99.2 53 UDP DNS (nbcdtimwr).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:27:23.863097" r2d2 68.12.104.178 37385 68.12.99.2 53 UDP DNS (enksgvkdtclfs).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:27:23.863100" r2d2 68.12.104.178 37385 68.12.99.2 53 UDP DNS (enksgvkdtclfs).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:27:24.420028" r2d2 68.12.104.178 46469 68.12.99.2 53 UDP DNS (hltkhcrjucqcmqrc).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:27:24.420027" r2d2 68.12.104.178 46469 68.12.99.2 53 UDP DNS (hltkhcrjucqcmqrc).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:27:24.769946" r2d2 68.12.104.178 36981 68.12.99.2 53 UDP DNS (fkywshdffenjkcommdpcp).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:27:24.769948" r2d2 68.12.104.178 36981 68.12.99.2 53 UDP DNS (fkywshdffenjkcommdpcp).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:27:24.795087" r2d2 68.12.104.178 55866 68.12.99.2 53 UDP DNS (puehkctpajn).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:27:24.795086" r2d2 68.12.104.178 55866 68.12.99.2 53 UDP DNS (puehkctpajn).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:27:24.958527" r2d2 68.12.104.178 39805 68.12.99.2 53 UDP DNS (plgiamfqvigdwj).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:27:24.958529" r2d2 68.12.104.178 39805 68.12.99.2 53 UDP DNS (plgiamfqvigdwj).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:27:25.334267" r2d2 68.12.104.178 46150 68.12.99.2 53 UDP DNS (xkjajenjswqncsi).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:27:25.334266" r2d2 68.12.104.178 46150 68.12.99.2 53 UDP DNS (xkjajenjswqncsi).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:27:26.379656" r2d2 68.12.104.178 38747 68.12.99.2 53 UDP DNS (ovubsmdcbmffulxrhsd).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:27:26.379656" r2d2 68.12.104.178 38747 68.12.99.2 53 UDP DNS (ovubsmdcbmffulxrhsd).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:27:26.588193" r2d2 68.12.104.178 35458 68.12.99.2 53 UDP DNS (ncxyoysqcurkwdxcobv).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:27:26.588190" r2d2 68.12.104.178 35458 68.12.99.2 53 UDP DNS (ncxyoysqcurkwdxcobv).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:27:26.888234" r2d2 68.12.104.178 47841 68.12.99.2 53 UDP DNS (lmxpvikwprmj).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:27:26.888235" r2d2 68.12.104.178 47841 68.12.99.2 53 UDP DNS (lmxpvikwprmj).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:27:26.924491" r2d2 68.12.104.178 45532 68.12.99.2 53 UDP DNS (cvdfuekvigfrnxfnpk).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:27:26.924493" r2d2 68.12.104.178 45532 68.12.99.2 53 UDP DNS (cvdfuekvigfrnxfnpk).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:27:27.731241" r2d2 68.12.104.178 49496 68.12.99.2 53 UDP DNS (htjvvkgrd).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:27:27.731243" r2d2 68.12.104.178 49496 68.12.99.2 53 UDP DNS (htjvvkgrd).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:27:27.781129" r2d2 68.12.104.178 48692 68.12.99.2 53 UDP DNS (fcgpokxypfurin).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:27:27.781130" r2d2 68.12.104.178 48692 68.12.99.2 53 UDP DNS (fcgpokxypfurin).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:27:27.954985" r2d2 68.12.104.178 52609 68.12.99.2 53 UDP DNS (jcydchkgarscg).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:27:27.954986" r2d2 68.12.104.178 52609 68.12.99.2 53 UDP DNS (jcydchkgarscg).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:27:28.230088" r2d2 68.12.104.178 45211 68.12.99.2 53 UDP DNS (rbjrbdscwfpkmbewimnw).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:27:28.230090" r2d2 68.12.104.178 45211 68.12.99.2 53 UDP DNS (rbjrbdscwfpkmbewimnw).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:27:28.269343" r2d2 68.12.104.178 49530 68.12.99.2 53 UDP DNS (brrwlvfxtaia).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:27:28.269348" r2d2 68.12.104.178 49530 68.12.99.2 53 UDP DNS (brrwlvfxtaia).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:27:28.604274" r2d2 68.12.104.178 38564 68.12.99.2 53 UDP DNS (yfrayyrchvgclcci).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:27:28.604272" r2d2 68.12.104.178 38564 68.12.99.2 53 UDP DNS (yfrayyrchvgclcci).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:27:28.670999" r2d2 68.12.104.178 53748 68.12.99.2 53 UDP DNS (ahnmtljhlayway).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:27:28.671004" r2d2 68.12.104.178 53748 68.12.99.2 53 UDP DNS (ahnmtljhlayway).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:27:34.637900" r2d2 68.12.104.178 51489 68.12.99.2 53 UDP DNS (iveuoqxdohyrmhcof).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:27:34.637898" r2d2 68.12.104.178 51489 68.12.99.2 53 UDP DNS (iveuoqxdohyrmhcof).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:27:35.806951" r2d2 68.12.104.178 44181 68.12.99.2 53 UDP DNS (paytxjgplh).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:27:35.806954" r2d2 68.12.104.178 44181 68.12.99.2 53 UDP DNS (paytxjgplh).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:27:35.968935" r2d2 68.12.104.178 40635 68.12.99.2 53 UDP DNS (yoihkvyneah).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:27:35.968940" r2d2 68.12.104.178 40635 68.12.99.2 53 UDP DNS (yoihkvyneah).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:27:36.501880" r2d2 68.12.104.178 46061 68.12.99.2 53 UDP DNS (eraxwqfikmc).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:27:36.501849" r2d2 68.12.104.178 46061 68.12.99.2 53 UDP DNS (eraxwqfikmc).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:27:37.388562" r2d2 68.12.104.178 44998 68.12.99.2 53 UDP DNS (nhxgaolisigaxcaaq).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:27:37.388558" r2d2 68.12.104.178 44998 68.12.99.2 53 UDP DNS (nhxgaolisigaxcaaq).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:27:37.581163" r2d2 68.12.104.178 46351 68.12.99.2 53 UDP DNS (gdlxxrdufrlnmo).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:27:37.581165" r2d2 68.12.104.178 46351 68.12.99.2 53 UDP DNS (gdlxxrdufrlnmo).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:27:37.808652" r2d2 68.12.104.178 36289 68.12.99.2 53 UDP DNS (lhopkqwyauphpj).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:27:37.808651" r2d2 68.12.104.178 36289 68.12.99.2 53 UDP DNS (lhopkqwyauphpj).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:27:38.035908" r2d2 68.12.104.178 45914 68.12.99.2 53 UDP DNS (tomfaakklyukbsrg).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:27:38.035906" r2d2 68.12.104.178 45914 68.12.99.2 53 UDP DNS (tomfaakklyukbsrg).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:27:38.103357" r2d2 68.12.104.178 50250 68.12.99.2 53 UDP DNS (asbmwwwrl).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:27:38.103359" r2d2 68.12.104.178 50250 68.12.99.2 53 UDP DNS (asbmwwwrl).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:27:39.488624" r2d2 68.12.104.178 54747 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 10:27:39.488634" r2d2 68.12.104.178 54747 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 10:27:46.140280" r2d2 68.12.104.178 38755 68.12.99.2 53 UDP DNS (ckbxwirugwck).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:27:46.140281" r2d2 68.12.104.178 38755 68.12.99.2 53 UDP DNS (ckbxwirugwck).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:27:50.412229" r2d2 68.12.104.178 42178 68.12.99.2 53 UDP DNS (mnwituubbok).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:27:50.412228" r2d2 68.12.104.178 42178 68.12.99.2 53 UDP DNS (mnwituubbok).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:27:51.084652" r2d2 68.12.104.178 47173 68.12.99.2 53 UDP DNS (mhtpalmgbpklryhvljs).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:27:51.084650" r2d2 68.12.104.178 47173 68.12.99.2 53 UDP DNS (mhtpalmgbpklryhvljs).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:27:52.559109" r2d2 68.12.104.178 52395 68.12.99.2 53 UDP DNS (tburiinomv).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:27:52.559123" r2d2 68.12.104.178 52395 68.12.99.2 53 UDP DNS (tburiinomv).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:27:52.602359" r2d2 68.12.104.178 47818 68.12.99.2 53 UDP DNS (yugpclyqofql).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:27:52.602360" r2d2 68.12.104.178 47818 68.12.99.2 53 UDP DNS (yugpclyqofql).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:27:52.796877" r2d2 68.12.104.178 47267 68.12.99.2 53 UDP DNS (gjiosnl).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:27:52.796859" r2d2 68.12.104.178 47267 68.12.99.2 53 UDP DNS (gjiosnl).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:27:53.141798" r2d2 68.12.104.178 43186 68.12.99.2 53 UDP DNS (psnoeykodpeymvy).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:27:53.141807" r2d2 68.12.104.178 43186 68.12.99.2 53 UDP DNS (psnoeykodpeymvy).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:27:58.646091" r2d2 68.12.104.178 35358 68.12.99.2 53 UDP DNS (aapfoxoie).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:27:58.646099" r2d2 68.12.104.178 35358 68.12.99.2 53 UDP DNS (aapfoxoie).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:28:00.185250" r2d2 68.12.104.178 35463 68.12.99.2 53 UDP DNS (hnjjxsm).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:28:00.185249" r2d2 68.12.104.178 35463 68.12.99.2 53 UDP DNS (hnjjxsm).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:28:00.319888" r2d2 68.12.104.178 49101 68.12.99.2 53 UDP DNS (nwmwwrigxjofmkpol).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:28:00.319889" r2d2 68.12.104.178 49101 68.12.99.2 53 UDP DNS (nwmwwrigxjofmkpol).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:28:00.771115" r2d2 68.12.104.178 53405 68.12.99.2 53 UDP DNS (nwdfugphavjylddcf).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:28:00.771113" r2d2 68.12.104.178 53405 68.12.99.2 53 UDP DNS (nwdfugphavjylddcf).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:28:01.899759" r2d2 68.12.104.178 50548 68.12.99.2 53 UDP DNS (vguorkteosy).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:28:01.899756" r2d2 68.12.104.178 50548 68.12.99.2 53 UDP DNS (vguorkteosy).ga "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:28:03.795037" r2d2 68.12.104.178 52010 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 10:28:03.795041" r2d2 68.12.104.178 52010 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 10:28:10.317382" r2d2 68.12.104.178 47752 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 10:28:10.317380" r2d2 68.12.104.178 47752 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 10:28:14.100387" r2d2 68.12.104.178 43558 68.12.99.2 53 UDP DNS (ns8.starbwqinfo).xyz "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:28:14.100389" r2d2 68.12.104.178 43558 68.12.99.2 53 UDP DNS (ns8.starbwqinfo).xyz "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:28:18.179231" r2d2 68.12.104.178 55303 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 10:28:18.179219" r2d2 68.12.104.178 55303 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 10:28:40.966998" r2d2 68.12.104.178 47917 68.12.99.2 53 UDP DNS (megascor).no-ip.biz "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 10:28:40.966996" r2d2 68.12.104.178 47917 68.12.99.2 53 UDP DNS (megascor).no-ip.biz "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 10:28:41.869780" r2d2 68.12.104.178 44953 68.12.99.2 53 UDP DNS teske.pornicarke.com "palevo (malware)" (static)\n' +
    '"2015-03-10 10:28:41.869779" r2d2 68.12.104.178 44953 68.12.99.2 53 UDP DNS teske.pornicarke.com "palevo (malware)" (static)\n' +
    '"2015-03-10 10:28:44.224934" r2d2 68.12.104.178 55522 68.12.99.2 53 UDP DNS (ns9.starbwqinfo).xyz "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:28:44.224943" r2d2 68.12.104.178 55522 68.12.99.2 53 UDP DNS (ns9.starbwqinfo).xyz "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:28:49.007219" r2d2 68.12.104.178 42904 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 10:28:49.007207" r2d2 68.12.104.178 42904 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 10:29:10.723393" r2d2 68.12.104.178 37221 68.12.99.2 53 UDP DNS (xvova).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:29:10.723400" r2d2 68.12.104.178 37221 68.12.99.2 53 UDP DNS (xvova).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:29:10.918741" r2d2 68.12.104.178 45964 68.12.99.2 53 UDP DNS (ns).conficker-sinkhole.com "conficker (malware)" (static)\n' +
    '"2015-03-10 10:29:10.919266" r2d2 68.12.104.178 58065 68.12.99.2 53 UDP DNS (ns).conficker-sinkhole.net "conficker (malware)" (static)\n' +
    '"2015-03-10 10:29:10.918747" r2d2 68.12.104.178 45964 68.12.99.2 53 UDP DNS (ns).conficker-sinkhole.com "conficker (malware)" (static)\n' +
    '"2015-03-10 10:29:10.919264" r2d2 68.12.104.178 58065 68.12.99.2 53 UDP DNS (ns).conficker-sinkhole.net "conficker (malware)" (static)\n' +
    '"2015-03-10 10:29:10.919682" r2d2 68.12.104.178 51275 68.12.99.2 53 UDP DNS (ns).conficker-sinkhole.org "conficker (malware)" (static)\n' +
    '"2015-03-10 10:29:10.919679" r2d2 68.12.104.178 51275 68.12.99.2 53 UDP DNS (ns).conficker-sinkhole.org "conficker (malware)" (static)\n' +
    '"2015-03-10 10:29:10.934370" r2d2 68.12.104.178 55562 38.102.150.29 53 UDP IP 38.102.150.29 "conficker (malware)" (static)\n' +
    '"2015-03-10 10:29:10.934378" r2d2 68.12.104.178 55562 38.102.150.29 53 UDP IP 38.102.150.29 "conficker (malware)" (static)\n' +
    '"2015-03-10 10:29:10.946379" r2d2 68.12.104.178 36869 38.229.70.125 53 UDP IP 38.229.70.125 "conficker (malware)" (static)\n' +
    '"2015-03-10 10:29:10.946122" r2d2 68.12.104.178 47329 38.102.150.29 53 UDP IP 38.102.150.29 "conficker (malware)" (static)\n' +
    '"2015-03-10 10:29:10.946116" r2d2 68.12.104.178 47329 38.102.150.29 53 UDP IP 38.102.150.29 "conficker (malware)" (static)\n' +
    '"2015-03-10 10:29:10.946376" r2d2 68.12.104.178 36869 38.229.70.125 53 UDP IP 38.229.70.125 "conficker (malware)" (static)\n' +
    '"2015-03-10 10:29:11.075298" r2d2 68.12.104.178 58239 38.102.150.29 53 UDP IP 38.102.150.29 "conficker (malware)" (static)\n' +
    '"2015-03-10 10:29:11.075269" r2d2 68.12.104.178 58239 38.102.150.29 53 UDP IP 38.102.150.29 "conficker (malware)" (static)\n' +
    '"2015-03-10 10:29:11.885507" r2d2 68.12.104.178 44750 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 10:29:11.885506" r2d2 68.12.104.178 44750 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 10:29:11.926150" r2d2 68.12.104.178 38225 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 10:29:11.926148" r2d2 68.12.104.178 38225 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 10:29:16.482824" r2d2 68.12.104.178 45398 68.12.99.2 53 UDP DNS (brightlounge).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:29:16.482822" r2d2 68.12.104.178 45398 68.12.99.2 53 UDP DNS (brightlounge).su "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:29:18.167427" r2d2 68.12.104.178 41898 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 10:29:18.167428" r2d2 68.12.104.178 41898 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 10:29:18.167973" r2d2 68.12.104.178 45709 68.12.99.2 53 UDP DNS (oncal).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:29:18.167972" r2d2 68.12.104.178 45709 68.12.99.2 53 UDP DNS (oncal).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:29:18.247963" r2d2 68.12.104.178 38249 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 10:29:18.247964" r2d2 68.12.104.178 38249 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 10:29:18.282609" r2d2 68.12.104.178 56239 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 10:29:18.282623" r2d2 68.12.104.178 56239 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 10:29:21.554594" r2d2 68.12.104.178 40073 68.12.99.2 53 UDP DNS (ns7.starbwqinfo).xyz "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:29:21.554597" r2d2 68.12.104.178 40073 68.12.99.2 53 UDP DNS (ns7.starbwqinfo).xyz "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:29:25.663873" r2d2 68.12.104.178 48466 38.229.70.125 53 UDP IP 38.229.70.125 "conficker (malware)" (static)\n' +
    '"2015-03-10 10:29:25.663875" r2d2 68.12.104.178 48466 38.229.70.125 53 UDP IP 38.229.70.125 "conficker (malware)" (static)\n' +
    '"2015-03-10 10:29:25.664856" r2d2 68.12.104.178 39586 68.12.99.2 53 UDP DNS (hjwtyunmfq).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:29:25.664905" r2d2 68.12.104.178 39586 68.12.99.2 53 UDP DNS (hjwtyunmfq).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:29:33.077621" r2d2 68.12.104.178 38022 68.12.99.2 53 UDP DNS (fnkeriocfbn).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:29:33.076869" r2d2 68.12.104.178 56049 38.229.70.125 53 UDP IP 38.229.70.125 "conficker (malware)" (static)\n' +
    '"2015-03-10 10:29:33.076870" r2d2 68.12.104.178 56049 38.229.70.125 53 UDP IP 38.229.70.125 "conficker (malware)" (static)\n' +
    '"2015-03-10 10:29:33.077623" r2d2 68.12.104.178 38022 68.12.99.2 53 UDP DNS (fnkeriocfbn).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:29:33.130104" r2d2 68.12.104.178 49409 38.229.70.125 53 UDP IP 38.229.70.125 "conficker (malware)" (static)\n' +
    '"2015-03-10 10:29:33.130092" r2d2 68.12.104.178 49409 38.229.70.125 53 UDP IP 38.229.70.125 "conficker (malware)" (static)\n' +
    '"2015-03-10 10:29:33.231038" r2d2 68.12.104.178 37775 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 10:29:33.231027" r2d2 68.12.104.178 37775 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 10:29:33.263178" r2d2 68.12.104.178 55166 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 10:29:33.263175" r2d2 68.12.104.178 55166 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 10:29:33.794055" r2d2 68.12.104.178 47088 68.12.99.2 53 UDP DNS peer.pickeklosarske.ru "palevo (malware)" (static)\n' +
    '"2015-03-10 10:29:33.794054" r2d2 68.12.104.178 47088 68.12.99.2 53 UDP DNS peer.pickeklosarske.ru "palevo (malware)" (static)\n' +
    '"2015-03-10 10:29:40.482249" r2d2 68.12.104.178 45448 68.12.99.2 53 UDP DNS (upfbd).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:29:40.482239" r2d2 68.12.104.178 45448 68.12.99.2 53 UDP DNS (upfbd).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:29:40.501617" r2d2 68.12.104.178 40506 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 10:29:40.501618" r2d2 68.12.104.178 40506 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 10:29:40.526833" r2d2 68.12.104.178 36105 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 10:29:40.526989" r2d2 68.12.104.178 36105 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 10:29:40.556588" r2d2 68.12.104.178 42091 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 10:29:40.556589" r2d2 68.12.104.178 42091 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 10:29:40.607463" r2d2 68.12.104.178 52544 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 10:29:40.607464" r2d2 68.12.104.178 52544 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 10:29:42.755289" r2d2 68.12.104.178 54966 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 10:29:42.755290" r2d2 68.12.104.178 54966 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 10:29:47.894550" r2d2 68.12.104.178 35826 68.12.99.2 53 UDP DNS (dzigse).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:29:47.894558" r2d2 68.12.104.178 35826 68.12.99.2 53 UDP DNS (dzigse).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:29:47.927830" r2d2 68.12.104.178 41684 68.12.99.2 53 UDP DNS (nzfuob).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:29:47.927828" r2d2 68.12.104.178 41684 68.12.99.2 53 UDP DNS (nzfuob).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:29:47.936058" r2d2 68.12.104.178 55521 68.12.99.2 53 UDP DNS (cxpveohxx).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:29:47.936059" r2d2 68.12.104.178 55521 68.12.99.2 53 UDP DNS (cxpveohxx).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:29:49.955414" r2d2 68.12.104.178 42496 38.229.70.125 53 UDP IP 38.229.70.125 "conficker (malware)" (static)\n' +
    '"2015-03-10 10:29:49.955416" r2d2 68.12.104.178 42496 38.229.70.125 53 UDP IP 38.229.70.125 "conficker (malware)" (static)\n' +
    '"2015-03-10 10:29:49.978402" r2d2 68.12.104.178 54512 38.229.70.125 53 UDP IP 38.229.70.125 "conficker (malware)" (static)\n' +
    '"2015-03-10 10:29:49.978391" r2d2 68.12.104.178 54512 38.229.70.125 53 UDP IP 38.229.70.125 "conficker (malware)" (static)\n' +
    '"2015-03-10 10:29:50.613623" r2d2 68.12.104.178 46873 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 10:29:50.613624" r2d2 68.12.104.178 46873 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 10:29:52.303119" r2d2 68.12.104.178 41674 68.12.99.2 53 UDP DNS (megascor).no-ip.biz "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 10:29:52.303107" r2d2 68.12.104.178 41674 68.12.99.2 53 UDP DNS (megascor).no-ip.biz "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 10:29:55.404264" r2d2 68.12.104.178 59018 68.12.99.2 53 UDP DNS (crbygtjt).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:29:55.404265" r2d2 68.12.104.178 59018 68.12.99.2 53 UDP DNS (crbygtjt).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:29:55.454076" r2d2 68.12.104.178 41963 68.12.99.2 53 UDP DNS (roays).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:29:55.454066" r2d2 68.12.104.178 41963 68.12.99.2 53 UDP DNS (roays).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:29:55.470378" r2d2 68.12.104.178 52054 38.102.150.29 53 UDP IP 38.102.150.29 "conficker (malware)" (static)\n' +
    '"2015-03-10 10:29:55.470355" r2d2 68.12.104.178 52054 38.102.150.29 53 UDP IP 38.102.150.29 "conficker (malware)" (static)\n' +
    '"2015-03-10 10:29:58.671766" r2d2 68.12.104.178 59901 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 10:29:58.671767" r2d2 68.12.104.178 59901 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 10:29:58.673831" r2d2 68.12.104.178 42616 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 10:29:58.673822" r2d2 68.12.104.178 42616 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 10:29:58.698768" r2d2 68.12.104.178 42131 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 10:29:58.698816" r2d2 68.12.104.178 42131 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 10:30:02.894996" r2d2 68.12.104.178 47574 68.12.99.2 53 UDP DNS (nqnnn).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:30:02.894995" r2d2 68.12.104.178 47574 68.12.99.2 53 UDP DNS (nqnnn).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:30:02.903427" r2d2 68.12.104.178 43799 68.12.99.2 53 UDP DNS (wafohvuqtka).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:30:02.903416" r2d2 68.12.104.178 43799 68.12.99.2 53 UDP DNS (wafohvuqtka).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:30:02.911392" r2d2 68.12.104.178 40853 68.12.99.2 53 UDP DNS (cglhnli).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:30:02.911359" r2d2 68.12.104.178 40853 68.12.99.2 53 UDP DNS (cglhnli).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:30:02.917807" r2d2 68.12.104.178 40631 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 10:30:02.917805" r2d2 68.12.104.178 40631 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 10:30:02.920290" r2d2 68.12.104.178 47186 68.12.99.2 53 UDP DNS (ajvznltod).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:30:02.920289" r2d2 68.12.104.178 47186 68.12.99.2 53 UDP DNS (ajvznltod).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:30:02.923040" r2d2 68.12.104.178 47978 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 10:30:02.923027" r2d2 68.12.104.178 47978 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 10:30:05.929918" r2d2 68.12.104.178 56055 68.12.99.2 53 UDP DNS (iqysaowq).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:30:05.929917" r2d2 68.12.104.178 56055 68.12.99.2 53 UDP DNS (iqysaowq).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:30:05.960297" r2d2 68.12.104.178 51455 68.12.99.2 53 UDP DNS (xnzxvcrq).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:30:05.960298" r2d2 68.12.104.178 51455 68.12.99.2 53 UDP DNS (xnzxvcrq).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:30:06.000170" r2d2 68.12.104.178 36943 38.229.70.125 53 UDP IP 38.229.70.125 "conficker (malware)" (static)\n' +
    '"2015-03-10 10:30:06.000171" r2d2 68.12.104.178 36943 38.229.70.125 53 UDP IP 38.229.70.125 "conficker (malware)" (static)\n' +
    '"2015-03-10 10:30:10.271728" r2d2 68.12.104.178 48808 68.12.99.2 53 UDP DNS (rzvbcocgymm).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:30:10.271727" r2d2 68.12.104.178 48808 68.12.99.2 53 UDP DNS (rzvbcocgymm).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:30:10.296644" r2d2 68.12.104.178 54062 68.12.99.2 53 UDP DNS (kqpmceqcv).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:30:10.296640" r2d2 68.12.104.178 54062 68.12.99.2 53 UDP DNS (kqpmceqcv).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:30:10.321943" r2d2 68.12.104.178 36686 68.12.99.2 53 UDP DNS (yerhlttz).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:30:10.321959" r2d2 68.12.104.178 36686 68.12.99.2 53 UDP DNS (yerhlttz).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:30:10.348593" r2d2 68.12.104.178 48000 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 10:30:10.348592" r2d2 68.12.104.178 48000 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 10:30:13.620848" r2d2 68.12.104.178 47946 68.12.99.2 53 UDP DNS (rolxjwzc).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:30:13.644045" r2d2 68.12.104.178 56163 38.102.150.29 53 UDP IP 38.102.150.29 "conficker (malware)" (static)\n' +
    '"2015-03-10 10:30:13.644046" r2d2 68.12.104.178 56163 38.102.150.29 53 UDP IP 38.102.150.29 "conficker (malware)" (static)\n' +
    '"2015-03-10 10:30:17.735007" r2d2 68.12.104.178 37892 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 10:30:17.735020" r2d2 68.12.104.178 37892 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 10:30:17.739427" r2d2 68.12.104.178 48959 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 10:30:17.739415" r2d2 68.12.104.178 48959 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 10:30:17.748597" r2d2 68.12.104.178 58023 68.12.99.2 53 UDP DNS (hwptmgit).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:30:17.748600" r2d2 68.12.104.178 58023 68.12.99.2 53 UDP DNS (hwptmgit).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:30:17.772943" r2d2 68.12.104.178 55791 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 10:30:17.772945" r2d2 68.12.104.178 55791 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 10:30:17.784111" r2d2 68.12.104.178 41794 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 10:30:17.784112" r2d2 68.12.104.178 41794 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 10:30:21.043355" r2d2 68.12.104.178 42059 38.229.70.125 53 UDP IP 38.229.70.125 "conficker (malware)" (static)\n' +
    '"2015-03-10 10:30:21.043357" r2d2 68.12.104.178 42059 38.229.70.125 53 UDP IP 38.229.70.125 "conficker (malware)" (static)\n' +
    '"2015-03-10 10:30:25.200391" r2d2 68.12.104.178 52603 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 10:30:25.200395" r2d2 68.12.104.178 52603 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 10:30:25.218594" r2d2 68.12.104.178 50165 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 10:30:25.218593" r2d2 68.12.104.178 50165 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 10:30:25.330485" r2d2 68.12.104.178 38135 38.229.70.125 53 UDP IP 38.229.70.125 "conficker (malware)" (static)\n' +
    '"2015-03-10 10:30:25.330498" r2d2 68.12.104.178 38135 38.229.70.125 53 UDP IP 38.229.70.125 "conficker (malware)" (static)\n' +
    '"2015-03-10 10:30:25.341247" r2d2 68.12.104.178 38412 38.229.70.125 53 UDP IP 38.229.70.125 "conficker (malware)" (static)\n' +
    '"2015-03-10 10:30:25.341249" r2d2 68.12.104.178 38412 38.229.70.125 53 UDP IP 38.229.70.125 "conficker (malware)" (static)\n' +
    '"2015-03-10 10:30:25.355973" r2d2 68.12.104.178 37793 38.229.70.125 53 UDP IP 38.229.70.125 "conficker (malware)" (static)\n' +
    '"2015-03-10 10:30:25.355974" r2d2 68.12.104.178 37793 38.229.70.125 53 UDP IP 38.229.70.125 "conficker (malware)" (static)\n' +
    '"2015-03-10 10:30:28.354479" r2d2 68.12.104.178 55926 68.12.99.2 53 UDP DNS (bqltd).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:30:28.354480" r2d2 68.12.104.178 55926 68.12.99.2 53 UDP DNS (bqltd).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:30:28.365964" r2d2 68.12.104.178 53153 68.12.99.2 53 UDP DNS (srxfevhi).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:30:28.365962" r2d2 68.12.104.178 53153 68.12.99.2 53 UDP DNS (srxfevhi).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:30:28.374713" r2d2 68.12.104.178 41121 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 10:30:28.374711" r2d2 68.12.104.178 41121 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 10:30:32.620907" r2d2 68.12.104.178 58813 68.12.99.2 53 UDP DNS (gwknw).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:30:32.620906" r2d2 68.12.104.178 58813 68.12.99.2 53 UDP DNS (gwknw).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:30:32.661813" r2d2 68.12.104.178 48247 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 10:30:32.661795" r2d2 68.12.104.178 48247 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 10:30:33.793066" r2d2 68.12.104.178 41637 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 10:30:33.793069" r2d2 68.12.104.178 41637 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 10:30:35.707203" r2d2 68.12.104.178 55159 38.102.150.29 53 UDP IP 38.102.150.29 "conficker (malware)" (static)\n' +
    '"2015-03-10 10:30:35.707200" r2d2 68.12.104.178 55159 38.102.150.29 53 UDP IP 38.102.150.29 "conficker (malware)" (static)\n' +
    '"2015-03-10 10:30:39.956823" r2d2 68.12.104.178 37479 68.12.99.2 53 UDP DNS (wdpthpmqz).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:30:39.956825" r2d2 68.12.104.178 37479 68.12.99.2 53 UDP DNS (wdpthpmqz).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:30:40.000967" r2d2 68.12.104.178 45763 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 10:30:40.000968" r2d2 68.12.104.178 45763 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 10:30:40.025594" r2d2 68.12.104.178 37141 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 10:30:40.025640" r2d2 68.12.104.178 37141 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 10:30:43.022049" r2d2 68.12.104.178 50005 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 10:30:43.022047" r2d2 68.12.104.178 50005 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 10:30:43.031770" r2d2 68.12.104.178 37357 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 10:30:43.031772" r2d2 68.12.104.178 37357 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 10:30:43.047079" r2d2 68.12.104.178 58707 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 10:30:43.047069" r2d2 68.12.104.178 58707 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 10:30:44.362791" r2d2 68.12.104.178 50454 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 10:30:44.362789" r2d2 68.12.104.178 50454 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 10:30:45.019824" r2d2 68.12.104.178 40909 38.229.70.125 53 UDP IP 38.229.70.125 "conficker (malware)" (static)\n' +
    '"2015-03-10 10:30:45.019823" r2d2 68.12.104.178 40909 38.229.70.125 53 UDP IP 38.229.70.125 "conficker (malware)" (static)\n' +
    '"2015-03-10 10:30:47.325204" r2d2 68.12.104.178 48674 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 10:30:47.325203" r2d2 68.12.104.178 48674 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 10:30:47.339087" r2d2 68.12.104.178 35955 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 10:30:47.339108" r2d2 68.12.104.178 35955 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 10:30:47.348195" r2d2 68.12.104.178 58271 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 10:30:47.348197" r2d2 68.12.104.178 58271 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 10:30:47.392387" r2d2 68.12.104.178 42515 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 10:30:47.392389" r2d2 68.12.104.178 42515 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 10:30:50.356282" r2d2 68.12.104.178 50963 38.102.150.29 53 UDP IP 38.102.150.29 "conficker (malware)" (static)\n' +
    '"2015-03-10 10:30:50.356283" r2d2 68.12.104.178 50963 38.102.150.29 53 UDP IP 38.102.150.29 "conficker (malware)" (static)\n' +
    '"2015-03-10 10:30:50.379515" r2d2 68.12.104.178 42826 38.102.150.29 53 UDP IP 38.102.150.29 "conficker (malware)" (static)\n' +
    '"2015-03-10 10:30:50.379481" r2d2 68.12.104.178 42826 38.102.150.29 53 UDP IP 38.102.150.29 "conficker (malware)" (static)\n' +
    '"2015-03-10 10:30:50.475282" r2d2 68.12.104.178 46374 38.102.150.29 53 UDP IP 38.102.150.29 "conficker (malware)" (static)\n' +
    '"2015-03-10 10:30:50.475294" r2d2 68.12.104.178 46374 38.102.150.29 53 UDP IP 38.102.150.29 "conficker (malware)" (static)\n' +
    '"2015-03-10 10:30:50.489291" r2d2 68.12.104.178 47303 38.102.150.29 53 UDP IP 38.102.150.29 "conficker (malware)" (static)\n' +
    '"2015-03-10 10:30:50.489294" r2d2 68.12.104.178 47303 38.102.150.29 53 UDP IP 38.102.150.29 "conficker (malware)" (static)\n' +
    '"2015-03-10 10:30:54.676401" r2d2 68.12.104.178 42886 68.12.99.2 53 UDP DNS (soulttajykw).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:30:54.676402" r2d2 68.12.104.178 42886 68.12.99.2 53 UDP DNS (soulttajykw).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:30:57.725920" r2d2 68.12.104.178 35168 68.12.99.2 53 UDP DNS (iifmsnhj).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:30:57.725908" r2d2 68.12.104.178 35168 68.12.99.2 53 UDP DNS (iifmsnhj).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:30:57.766512" r2d2 68.12.104.178 49045 38.229.70.125 53 UDP IP 38.229.70.125 "conficker (malware)" (static)\n' +
    '"2015-03-10 10:30:57.766513" r2d2 68.12.104.178 49045 38.229.70.125 53 UDP IP 38.229.70.125 "conficker (malware)" (static)\n' +
    '"2015-03-10 10:30:57.894214" r2d2 68.12.104.178 53192 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 10:30:57.894215" r2d2 68.12.104.178 53192 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 10:30:57.928903" r2d2 68.12.104.178 39375 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 10:30:57.928921" r2d2 68.12.104.178 39375 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 10:30:59.198710" r2d2 68.12.104.178 38566 68.12.99.2 53 UDP DNS (megascor).no-ip.biz "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 10:30:59.198683" r2d2 68.12.104.178 38566 68.12.99.2 53 UDP DNS (megascor).no-ip.biz "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 10:31:02.112818" r2d2 68.12.104.178 42848 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 10:31:02.112817" r2d2 68.12.104.178 42848 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 10:31:02.172918" r2d2 68.12.104.178 35057 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 10:31:02.172917" r2d2 68.12.104.178 35057 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 10:31:02.179416" r2d2 68.12.104.178 37760 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 10:31:02.179425" r2d2 68.12.104.178 37760 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 10:31:09.524568" r2d2 68.12.104.178 49827 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 10:31:09.524578" r2d2 68.12.104.178 49827 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 10:31:09.567833" r2d2 68.12.104.178 41421 68.12.99.2 53 UDP DNS (hhedqcvd).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:31:09.567831" r2d2 68.12.104.178 41421 68.12.99.2 53 UDP DNS (hhedqcvd).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:31:09.576153" r2d2 68.12.104.178 47824 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 10:31:09.576150" r2d2 68.12.104.178 47824 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 10:31:09.597043" r2d2 68.12.104.178 45711 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 10:31:09.597040" r2d2 68.12.104.178 45711 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 10:31:15.441116" r2d2 68.12.104.178 41304 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 10:31:15.441115" r2d2 68.12.104.178 41304 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 10:31:16.885476" r2d2 68.12.104.178 59768 38.229.70.125 53 UDP IP 38.229.70.125 "conficker (malware)" (static)\n' +
    '"2015-03-10 10:31:16.887006" r2d2 68.12.104.178 44345 68.12.99.2 53 UDP DNS (nfhxrpdr).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:31:16.885474" r2d2 68.12.104.178 59768 38.229.70.125 53 UDP IP 38.229.70.125 "conficker (malware)" (static)\n' +
    '"2015-03-10 10:31:16.887023" r2d2 68.12.104.178 44345 68.12.99.2 53 UDP DNS (nfhxrpdr).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:31:16.950380" r2d2 68.12.104.178 42395 38.229.70.125 53 UDP IP 38.229.70.125 "conficker (malware)" (static)\n' +
    '"2015-03-10 10:31:16.950390" r2d2 68.12.104.178 42395 38.229.70.125 53 UDP IP 38.229.70.125 "conficker (malware)" (static)\n' +
    '"2015-03-10 10:31:16.960687" r2d2 68.12.104.178 36333 38.229.70.125 53 UDP IP 38.229.70.125 "conficker (malware)" (static)\n' +
    '"2015-03-10 10:31:16.960688" r2d2 68.12.104.178 36333 38.229.70.125 53 UDP IP 38.229.70.125 "conficker (malware)" (static)\n' +
    '"2015-03-10 10:31:19.902705" r2d2 68.12.104.178 51863 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 10:31:19.902703" r2d2 68.12.104.178 51863 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 10:31:19.920505" r2d2 68.12.104.178 58382 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 10:31:19.920509" r2d2 68.12.104.178 58382 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 10:31:23.047566" r2d2 68.12.104.178 42016 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 10:31:23.047569" r2d2 68.12.104.178 42016 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 10:31:24.422531" r2d2 68.12.104.178 58098 68.12.99.2 53 UDP DNS (extzkxbobnj).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:31:24.422535" r2d2 68.12.104.178 58098 68.12.99.2 53 UDP DNS (extzkxbobnj).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:31:24.473017" r2d2 68.12.104.178 57518 68.12.99.2 53 UDP DNS (mkwysvgo).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:31:24.473032" r2d2 68.12.104.178 57518 68.12.99.2 53 UDP DNS (mkwysvgo).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:31:24.484185" r2d2 68.12.104.178 58796 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 10:31:24.484186" r2d2 68.12.104.178 58796 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 10:31:27.225723" r2d2 68.12.104.178 35984 68.12.99.2 53 UDP DNS (bjtwpgax).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:31:27.225724" r2d2 68.12.104.178 35984 68.12.99.2 53 UDP DNS (bjtwpgax).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:31:31.782760" r2d2 68.12.104.178 40162 68.12.99.2 53 UDP DNS (qveawzyob).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:31:31.782755" r2d2 68.12.104.178 40162 68.12.99.2 53 UDP DNS (qveawzyob).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:31:31.815527" r2d2 68.12.104.178 41193 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 10:31:31.867361" r2d2 68.12.104.178 39812 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 10:31:31.867357" r2d2 68.12.104.178 39812 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 10:31:31.879237" r2d2 68.12.104.178 49837 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 10:31:31.879226" r2d2 68.12.104.178 49837 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 10:31:34.662048" r2d2 68.12.104.178 59027 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 10:31:34.662047" r2d2 68.12.104.178 59027 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 10:31:34.663168" r2d2 68.12.104.178 47808 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 10:31:34.663180" r2d2 68.12.104.178 47808 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 10:31:39.171144" r2d2 68.12.104.178 47654 38.229.70.125 53 UDP IP 38.229.70.125 "conficker (malware)" (static)\n' +
    '"2015-03-10 10:31:39.171130" r2d2 68.12.104.178 47654 38.229.70.125 53 UDP IP 38.229.70.125 "conficker (malware)" (static)\n' +
    '"2015-03-10 10:31:41.946416" r2d2 68.12.104.178 36975 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 10:31:41.946417" r2d2 68.12.104.178 36975 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 10:31:46.469423" r2d2 68.12.104.178 57474 68.12.99.2 53 UDP DNS (tbivyqyy).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:31:46.469409" r2d2 68.12.104.178 57474 68.12.99.2 53 UDP DNS (tbivyqyy).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:31:46.521747" r2d2 68.12.104.178 58948 38.102.150.29 53 UDP IP 38.102.150.29 "conficker (malware)" (static)\n' +
    '"2015-03-10 10:31:46.521742" r2d2 68.12.104.178 58948 38.102.150.29 53 UDP IP 38.102.150.29 "conficker (malware)" (static)\n' +
    '"2015-03-10 10:31:46.547770" r2d2 68.12.104.178 44497 38.102.150.29 53 UDP IP 38.102.150.29 "conficker (malware)" (static)\n' +
    '"2015-03-10 10:31:46.547772" r2d2 68.12.104.178 44497 38.102.150.29 53 UDP IP 38.102.150.29 "conficker (malware)" (static)\n' +
    '"2015-03-10 10:31:53.796045" r2d2 68.12.104.178 58796 68.12.99.2 53 UDP DNS (pungqgy).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:31:53.796047" r2d2 68.12.104.178 58796 68.12.99.2 53 UDP DNS (pungqgy).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:31:53.903448" r2d2 68.12.104.178 35356 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 10:31:53.903442" r2d2 68.12.104.178 35356 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 10:32:01.211686" r2d2 68.12.104.178 57510 68.12.99.2 53 UDP DNS (seaohagd).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:32:01.211687" r2d2 68.12.104.178 57510 68.12.99.2 53 UDP DNS (seaohagd).cc "domain (suspicious)" (static)\n' +
    '"2015-03-10 10:32:01.365824" r2d2 68.12.104.178 47799 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 10:32:01.365820" r2d2 68.12.104.178 47799 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 10:32:03.792128" r2d2 68.12.104.178 53781 68.12.99.2 53 UDP DNS peer.pickeklosarske.ru "palevo (malware)" (static)\n' +
    '"2015-03-10 10:32:03.792124" r2d2 68.12.104.178 53781 68.12.99.2 53 UDP DNS peer.pickeklosarske.ru "palevo (malware)" (static)\n' +
    '"2015-03-10 10:32:08.606930" r2d2 68.12.104.178 58934 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 10:32:08.606922" r2d2 68.12.104.178 58934 136.161.101.53 53 UDP IP 136.161.101.53 "conficker (malware)" (static)\n' +
    '"2015-03-10 10:32:17.050611" r2d2 68.12.104.178 44500 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 10:32:17.050585" r2d2 68.12.104.178 44500 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 10:32:22.254593" r2d2 68.12.104.178 45385 68.12.99.2 53 UDP DNS (megascor).no-ip.biz "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 10:32:22.254607" r2d2 68.12.104.178 45385 68.12.99.2 53 UDP DNS (megascor).no-ip.biz "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 10:32:30.933664" r2d2 68.12.104.178 53713 68.12.99.2 53 UDP DNS digitalmind.cn "palevo (malware)" palevotracker.abuse.ch\n' +
    '"2015-03-10 10:32:30.933666" r2d2 68.12.104.178 53713 68.12.99.2 53 UDP DNS digitalmind.cn "palevo (malware)" palevotracker.abuse.ch\n' +
    '"2015-03-10 10:32:47.877799" r2d2 68.12.104.178 50876 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 10:32:47.877796" r2d2 68.12.104.178 50876 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 10:32:55.499244" r2d2 68.12.104.178 54499 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 10:32:55.499241" r2d2 68.12.104.178 54499 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 10:33:03.790412" r2d2 68.12.104.178 37541 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 10:33:03.790410" r2d2 68.12.104.178 37541 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 10:33:26.465250" r2d2 68.12.104.178 37429 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 10:33:26.465253" r2d2 68.12.104.178 37429 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 10:33:49.487608" r2d2 68.12.104.178 35415 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 10:33:49.487610" r2d2 68.12.104.178 35415 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 10:34:10.042924" r2d2 68.12.104.178 35137 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 10:34:10.042937" r2d2 68.12.104.178 35137 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 10:34:20.315771" r2d2 68.12.104.178 52660 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 10:34:20.315774" r2d2 68.12.104.178 52660 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 10:34:22.865656" r2d2 68.12.104.178 35279 68.12.99.2 53 UDP DNS (megascor).no-ip.biz "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 10:34:22.865655" r2d2 68.12.104.178 35279 68.12.99.2 53 UDP DNS (megascor).no-ip.biz "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 10:34:28.073161" r2d2 68.12.104.178 46814 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 10:34:28.073159" r2d2 68.12.104.178 46814 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 10:34:33.789407" r2d2 68.12.104.178 57062 68.12.99.2 53 UDP DNS peer.pickeklosarske.ru "palevo (malware)" (static)\n' +
    '"2015-03-10 10:34:33.789408" r2d2 68.12.104.178 57062 68.12.99.2 53 UDP DNS peer.pickeklosarske.ru "palevo (malware)" (static)\n' +
    '"2015-03-10 10:34:58.899309" r2d2 68.12.104.178 38921 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 10:34:58.899308" r2d2 68.12.104.178 38921 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 10:35:21.989735" r2d2 68.12.104.178 37116 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 10:35:21.989737" r2d2 68.12.104.178 37116 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 10:35:33.788159" r2d2 68.12.104.178 51794 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 10:35:33.788160" r2d2 68.12.104.178 51794 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 10:35:52.814689" r2d2 68.12.104.178 55335 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 10:35:52.814691" r2d2 68.12.104.178 55335 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 10:36:00.601468" r2d2 68.12.104.178 40106 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 10:36:00.601465" r2d2 68.12.104.178 40106 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 10:36:31.426988" r2d2 68.12.104.178 58547 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 10:36:31.426870" r2d2 68.12.104.178 58547 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 10:36:39.678126" r2d2 68.12.104.178 54496 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 10:36:39.678123" r2d2 68.12.104.178 54496 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 10:36:54.564875" r2d2 68.12.104.178 58863 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 10:36:54.564876" r2d2 68.12.104.178 58863 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 10:37:03.787282" r2d2 68.12.104.178 52891 68.12.99.2 53 UDP DNS peer.pickeklosarske.ru "palevo (malware)" (static)\n' +
    '"2015-03-10 10:37:03.787276" r2d2 68.12.104.178 52891 68.12.99.2 53 UDP DNS peer.pickeklosarske.ru "palevo (malware)" (static)\n' +
    '"2015-03-10 10:37:25.392821" r2d2 68.12.104.178 59459 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 10:37:25.392822" r2d2 68.12.104.178 59459 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 10:37:33.034484" r2d2 68.12.104.178 54891 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 10:37:33.034483" r2d2 68.12.104.178 54891 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 10:37:37.117077" r2d2 68.12.104.178 38516 81.2.199.97 53 UDP IP 81.2.199.97 "asprox (malware)" atrack.h3x.eu\n' +
    '"2015-03-10 10:37:37.117066" r2d2 68.12.104.178 38516 81.2.199.97 53 UDP IP 81.2.199.97 "asprox (malware)" atrack.h3x.eu\n' +
    '"2015-03-10 10:38:03.770655" r2d2 68.12.104.178 52734 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 10:38:03.770658" r2d2 68.12.104.178 52734 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 10:38:03.863302" r2d2 68.12.104.178 41041 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 10:38:03.863304" r2d2 68.12.104.178 41041 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 10:38:10.752839" r2d2 68.12.104.178 49598 68.12.99.2 53 UDP DNS (megascor).no-ip.biz "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 10:38:10.752840" r2d2 68.12.104.178 49598 68.12.99.2 53 UDP DNS (megascor).no-ip.biz "dynamic domain (suspicious)" (static)\n' +
    '"2015-03-10 10:38:27.002032" r2d2 68.12.104.178 47111 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 10:38:27.002083" r2d2 68.12.104.178 47111 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 10:38:41.138161" r2d2 68.12.104.178 37638 68.12.99.2 53 UDP DNS digitalmind.cn "palevo (malware)" palevotracker.abuse.ch\n' +
    '"2015-03-10 10:38:41.138160" r2d2 68.12.104.178 37638 68.12.99.2 53 UDP DNS digitalmind.cn "palevo (malware)" palevotracker.abuse.ch\n' +
    '"2015-03-10 10:38:57.830859" r2d2 68.12.104.178 57891 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 10:38:57.830861" r2d2 68.12.104.178 57891 68.12.99.2 53 UDP DNS sandra.prichaonica.com "palevo (malware)" (static)\n' +
    '"2015-03-10 10:39:02.186244" r2d2 68.12.104.178 48371 68.12.99.2 53 UDP DNS (ns1).torpig-sinkhole.org "torpig (malware)" (static)\n' +
    '"2015-03-10 10:39:02.187021" r2d2 68.12.104.178 59190 68.12.99.2 53 UDP DNS (ns2).torpig-sinkhole.org "torpig (malware)" (static)\n' +
    '"2015-03-10 10:39:02.186248" r2d2 68.12.104.178 48371 68.12.99.2 53 UDP DNS (ns1).torpig-sinkhole.org "torpig (malware)" (static)\n' +
    '"2015-03-10 10:39:02.187019" r2d2 68.12.104.178 59190 68.12.99.2 53 UDP DNS (ns2).torpig-sinkhole.org "torpig (malware)" (static)\n' +
    '"2015-03-10 10:39:02.186676" r2d2 68.12.104.178 50766 68.12.99.2 53 UDP DNS (ns1).torpig-sinkhole.org "torpig (malware)" (static)\n' +
    '"2015-03-10 10:39:02.223255" r2d2 68.12.104.178 45940 87.106.240.162 53 UDP IP 87.106.240.162 "torpig (malware)" (static)\n' +
    '"2015-03-10 10:39:02.223235" r2d2 68.12.104.178 55197 87.106.240.162 53 UDP IP 87.106.240.162 "torpig (malware)" (static)\n' +
    '"2015-03-10 10:39:02.223265" r2d2 68.12.104.178 45940 87.106.240.162 53 UDP IP 87.106.240.162 "torpig (malware)" (static)\n' +
    '"2015-03-10 10:39:02.223248" r2d2 68.12.104.178 55197 87.106.240.162 53 UDP IP 87.106.240.162 "torpig (malware)" (static)\n' +
    '"2015-03-10 10:39:02.250733" r2d2 68.12.104.178 47526 212.227.55.84 53 UDP IP 212.227.55.84 "torpig (malware)" (static)\n' +
    '"2015-03-10 10:39:02.250440" r2d2 68.12.104.178 37480 212.227.55.84 53 UDP IP 212.227.55.84 "torpig (malware)" (static)\n' +
    '"2015-03-10 10:39:02.250430" r2d2 68.12.104.178 37480 212.227.55.84 53 UDP IP 212.227.55.84 "torpig (malware)" (static)\n' +
    '"2015-03-10 10:39:02.250730" r2d2 68.12.104.178 47526 212.227.55.84 53 UDP IP 212.227.55.84 "torpig (malware)" (static)\n' +
    '"2015-03-10 10:39:02.278733" r2d2 68.12.104.178 48350 212.227.55.84 53 UDP IP 212.227.55.84 "torpig (malware)" (static)\n' +
    '"2015-03-10 10:39:02.278735" r2d2 68.12.104.178 48350 212.227.55.84 53 UDP IP 212.227.55.84 "torpig (malware)" (static)\n' +
    '"2015-03-10 10:39:05.470846" r2d2 68.12.104.178 49639 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 10:39:05.470844" r2d2 68.12.104.178 49639 68.12.99.2 53 UDP DNS l33t.brand-clothes.net "palevo (malware)" (static)\n' +
    '"2015-03-10 10:39:07.880021" r2d2 68.12.104.178 56376 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n' +
    '"2015-03-10 10:39:07.880019" r2d2 68.12.104.178 56376 68.12.99.2 53 UDP DNS juice.losmibracala.org "palevo (malware)" (static)\n';
}
