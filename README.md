![Maltrail](https://i.imgur.com/3xjInOD.png)

[![License](https://img.shields.io/badge/license-MIT-red.svg)](#licence)
[![Sensor](https://img.shields.io/badge/sensor-Rust%201.74%2B-orange.svg)](sensor/)
[![Server](https://img.shields.io/badge/server-Python%203.7%2B-blue.svg)](server.py)
[![Trails](https://img.shields.io/badge/trails-%3E1.5M-brightgreen.svg)](#trails)
[![X](https://img.shields.io/badge/X-%40maltrail-black.svg)](https://x.com/maltrail)

**Malicious traffic detection system.** Maltrail watches your network for contact with things that
are known to be bad — and tells you, in one line, what was seen and why it is considered bad.

```
"2026-08-07 09:14:22.117034" gw 10.13.13.2 57809 1.1.1.1 53 UDP DNS malware.bakewithdavid.com "asyncrat (malware)" (static)
```

No rule language, no tuning ritual, no ML. A **trail** is a domain, URL, IP address, `IP:port` or
User-Agent known to belong to something malicious, and Maltrail tells you when one appears on the
wire.

---

## Content

- [Why Maltrail](#why-maltrail)
- [Architecture](#architecture)
- [Performance](#performance)
- [Quick start](#quick-start)
  - [As a service](#as-a-service)
  - [Docker](#docker)
- [Configuration](#configuration)
- [Trails](#trails)
- [Events](#events)
- [Operating it](#operating-it)
  - [Event retention](#event-retention)
- [Documentation](#documentation)
- [Contributing](#contributing)
- [Licence](#licence)
- [Sponsors](#sponsors)
- [Developers](#developers)
- [Presentations](#presentations)
- [Publications](#publications)
- [Blacklist](#blacklist)
- [Thank you](#thank-you)
- [Third-party integrations](#third-party-integrations)

---

## Why Maltrail

Most network detection tools ask you to describe *behaviour*. Maltrail asks a simpler question that
answers most real incidents: **is this host talking to something we already know is bad?**

* **More than 1.5 million trails**, from more than 3,000 curated static lists plus 46 public feeds,
  refreshed daily and growing. Heavily weighted toward **malware** — C2 domains, droppers,
  stealers, APT infrastructure — because that is what shows up in a real compromise.
* **Trails are plain text.** One indicator per line, in a file you can read, grep and send a pull
  request against. That is why coverage stays current, and why you can always answer "why did this
  fire?".
* **Fast enough to stop thinking about it.** A single core handles a 10 GbE link on a realistic
  traffic mix; see [Performance](#performance).
* **Heuristics on top**, not instead — each one named in the event, never a bare score: port, UDP
  and web scanning, DNS exhaustion, DGA-shaped lookups (entropy and consonant thresholds, excessive
  NXDOMAIN), sinkholed, seized and parked domains, long domains, direct-IP and IoT-malware
  downloads, suspicious user agents and proxy probes.

---

## Architecture

Two independent processes. Run them on one box or many.

```
   ┌──────────┐   events (UDP or file)   ┌──────────┐
   │  sensor  │ ───────────────────────► │  server  │ ◄── browser
   └──────────┘                          └──────────┘
    Rust                                  Python
    libpcap + PACKET_FANOUT               reporting UI + API
    trail matching, heuristics
```

A sensor can log locally (`LOG_DIR`), ship to a remote server (`LOG_SERVER`), or both. For an
existing SIEM it also emits CEF over syslog (`SYSLOG_SERVER`) and Logstash JSON
(`LOGSTASH_SERVER`).

---

## Performance

The sensor is Rust, one thread per capture worker, sharing a single immutable trail store. Cost per
packet, by traffic type:

| traffic | per packet |
| --- | ---: |
| ICMP echo (58 B) | 101 ns |
| TCP SYN (70 B) | 302 ns |
| bulk TLS (1,473 B) | 402 ns |
| DNS query, warm cache (93 B) | 452 ns |
| mixed traffic (866 B average) | 552 ns |
| HTTP request (169 B) | 602 ns |
| DNS query, every name unique (DGA flood) | 1,102 ns |

Workers share nothing mutable, so that cost is what each additional core buys you. Replaying the
866-byte mix:

| workers | packets/s | Gbit/s | vs 1 worker |
| ---: | ---: | ---: | ---: |
| 1 | 1,687,991 | 11.69 | 1.00× |
| 2 | 3,209,627 | 22.24 | 1.90× |
| 4 | 5,379,436 | 37.27 | 3.19× |
| 8 | 8,552,231 | 59.25 | 5.07× |
| 16 | 10,165,773 | 70.43 | 6.02× |

**One core saturates 10 GbE.** Scaling is near-linear to four workers and then tapers on an
eight-physical-core box, because the rest is SMT — hardware, not lock contention.

Against the old Python sensor, replaying the **same 300,000-packet capture** with the **same
1,505,265 trails** and the same configuration, one worker each — startup excluded, so this is
steady-state packet cost. Both figures here are whole-process (pcap read and dispatch included),
which is why the sensor's number is higher than the 552 ns packet path measured in isolation
above:

| | per packet | packets/s |
| --- | ---: | ---: |
| sensor (Rust) | 865 ns | 1,156,423 |
| old sensor (Python) | 23,448 ns | 42,648 |
| | **27× faster** | |

Reproduce it yourself — the harness is committed, and it prints both sensors' event counts so a
throughput number can never be quoted without its correctness context:

```bash
python3 sensor/tools/bench_compare.py --packets 300000 --trails ~/.maltrail/trails.csv --repeat 3
```

Memory does not grow with cores: the 1.5M-trail store is **68.5 MB**, built in 1.2 s and shared
immutably by every worker.

**One capture worker by default**, which is ~1.1M packets/s and enough for almost any sensor host.
Extra workers are an explicit opt-in (`CAPTURE_FANOUT`), because the kernel flow-hashes capture
while the scan heuristics count per source: of the heuristic alerts one worker raises, 91% survive
at 2 sockets, 86% at 4, 65% at 8. Exact trail detection is identical at every worker count. Scale
out when `maltrail_capture_dropped_total` says to, not before.

<sub>AMD Ryzen 7 PRO 4750U (8 physical cores), heuristics on, real trail set, fastest of three runs.
The ratio has ranged 14–27× across runs and hardware; the per-packet costs above are the ones that
bound how much traffic a worker can absorb. **These are software-path figures** — a live NIC adds
driver and ring costs, so measure your own hardware and watch `maltrail_capture_dropped_total`.
Method, per-protocol breakdown, instruction counts and the profiler output are in
[`sensor/docs/REPORT.md`](sensor/docs/REPORT.md).</sub>

---

## Quick start

Linux, `libpcap`, Rust 1.74+ for the sensor, Python 3.7+ for the server.

Prebuilt sensor binaries for `x86_64` and `aarch64` are attached to every
[release](https://github.com/stamparm/maltrail/releases) with a SHA-256 checksum, so a Rust
toolchain is only needed to build from source. To build it anyway:

```bash
git clone --depth 1 https://github.com/stamparm/maltrail.git
cd maltrail

# 1. build the sensor
cd sensor && cargo build --release && cd ..

# 2. let it capture without running as root
sudo setcap cap_net_raw,cap_net_admin=eip sensor/target/release/maltrail-sensor

# 3. give it somewhere to write events (LOG_DIR, /var/log/maltrail by default)
#    ('id -gn', not "$USER": not every distribution gives each user their own group)
sudo install -d -o "$USER" -g "$(id -gn)" -m 750 /var/log/maltrail

# 4. check the deployment before trusting it — exits non-zero if anything is wrong
sensor/target/release/maltrail-sensor -T

# 5. run it (first start builds the trail set; takes a minute)
sensor/target/release/maltrail-sensor
```

In another terminal, or on another machine:

```bash
python3 server.py
```

Then open <http://127.0.0.1:8338> and log in with the credentials in `maltrail.conf` (`USERS`).

`-T` is the shortcut for "will this work?" — it validates the configuration, trails, whitelist, log
directory, capture filter and privileges, and tells you exactly what is missing:

```
[o] log directory: '/var/log/maltrail' is writable
[o] capture privileges: CAP_NET_RAW present
[o] capture filter: udp or icmp or (tcp and (tcp[tcpflags] == tcp-syn or port 80 or port...
[o] interface: any
[o] workers: 16 (PACKET_FANOUT required; verify with tools/fanout_check.py as root)
[o] whitelist: 3440 entries, 18 CIDR range(s)
[o] trails: 1505265 loaded (0 malformed row(s)), ipv4=144758 ipv4:port=253517 ipv6=2014 wildcard=29
[o] heuristics: on (disabled: none)
[i] configuration test PASSED
```

Skipping step 2 or 3 is the single most common way to end up with a sensor that starts and detects
nothing; `-T` names both.

### As a service

```bash
sudo useradd --system --no-create-home --shell /usr/sbin/nologin maltrail
sudo rsync -a --exclude .git . /opt/maltrail/
sudo cp /opt/maltrail/maltrail-{server,sensor}.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now maltrail-server maltrail-sensor
```

That is the whole installation — no directories to create, no `setcap`. The units create and own
`/var/log/maltrail` (events) and `/var/lib/maltrail` (the trail set) via systemd's
`LogsDirectory=`/`StateDirectory=`, run both processes as the unprivileged `maltrail` user with a
read-only filesystem, and give the sensor exactly `CAP_NET_RAW` and `CAP_NET_ADMIN` — nothing else,
and no root anywhere. The sensor runs `-T` as `ExecStartPre`, so a broken deployment fails at
`systemctl start` instead of running blind.

Check it: `systemctl status maltrail-sensor` and `journalctl -u maltrail-sensor -f`.

### Docker

```bash
docker compose -f docker/docker-compose.yml up -d
```

See [`docker/README.md`](docker/README.md).

---

## Configuration

Everything lives in **`maltrail.conf`**, split into `[Sensor]` and `[Server]`. The options most
worth knowing:

| option | what it does |
| --- | --- |
| `MONITOR_INTERFACE` | interface(s) to capture on, or `any` |
| `CAPTURE_FILTER` | BPF filter; the default keeps bulk line-rate traffic out of userspace |
| `PROCESS_COUNT` | capture workers — one per core is a reasonable default |
| `LOG_DIR` | where events are written (`/var/log/maltrail`) |
| `TRAILS_FILE` | where the built trail set lives (`~/.maltrail/trails.csv`; `/var/lib/maltrail` under the units) |
| `LOG_SERVER` | ship events to a remote server instead of, or as well as, logging locally |
| `STATS_ADDRESS` | expose Prometheus metrics (sensor; off unless set) |
| `UPDATE_PERIOD` | how often trails are refreshed |
| `USER_WHITELIST` | your own never-alert list |
| `CUSTOM_TRAILS_DIR` | your own trails, alongside the shipped ones |

---

## Trails

```
trails/static/malware/asyncrat.txt      # one indicator per line
trails/static/malicious/…
trails/static/suspicious/…
trails/feeds/*.py                       # public feeds, pulled on update
```

Adding an indicator is adding a line to a text file. Adding a feed is a small Python module. Both
are ordinary pull requests, and that low friction is why the set stays useful.

Your own indicators go in `CUSTOM_TRAILS_DIR`; anything you never want to hear about goes in
`USER_WHITELIST`.

---

## Events

One line per detection, whitespace-separated, CSV-quoted where needed:

```
"<time>" <sensor> <src_ip> <src_port> <dst_ip> <dst_port> <proto> <type> <trail> "<info>" <reference>
```

`type` is what matched — `DNS`, `IP`, `IPORT`, `URL`, `PATH`, `HTTP`, `UA`, `PORT` — `info` is why
it is considered bad, and `reference` is where the trail came from: `(static)`, a feed name, or
`(heuristic)`.

---

## Operating it

* **`-T`** validates a configuration and exits. Usable as a deployment gate; the systemd unit runs
  it as `ExecStartPre`.
* **`STATS_ADDRESS`** exposes Prometheus metrics. The four worth alerting on, all of which mean
  *this sensor is not detecting what you think it is*:

  | metric | what it means |
  | --- | --- |
  | `maltrail_up == 0` | no capture worker is alive — this host is **not monitored** |
  | `rate(maltrail_capture_dropped_total)` | the ring is dropping packets — **missed detections** |
  | `rate(maltrail_local_log_errors_total)` | detections were produced and then **lost** |
  | `maltrail_trail_generation` not advancing | trails have stopped refreshing |

  Also useful: `maltrail_log_dir_free_bytes` (see below) and
  `maltrail_state_saturations_total`, which is non-zero when a state-exhaustion flood has
  narrowed the heuristics. Exact trail matching is unaffected by that, by design.
* **`systemctl reload`** (`SIGHUP`) reloads trails without a restart. Trails refreshed by anything
  else are picked up within a second, with an atomic swap — no restart, no dropped packets.
* **The condensed observable store** (`USE_CONDENSED_STORAGE`, `meta.sqlite`) that feeds the
  server's `/meta` novelty and retro-hunt views is written in the same format the old sensor
  produces, and the two are compared row for row by the parity harness. Every deliberate
  difference between the sensors is listed in
  [`sensor/docs/COMPATIBILITY.md`](sensor/docs/COMPATIBILITY.md).

### Event retention

**Maltrail never deletes event evidence.** There is no retention setting that expires your logs,
and that is deliberate: these are the records you go back to after an incident, and a tool that
quietly discards them is worse than useless during the one week you need them.

That makes free space something you operate rather than ignore:

* **Ship the durable copy off-box.** `LOG_SERVER` (or `SYSLOG_SERVER` / `LOGSTASH_SERVER`) makes
  the server or your SIEM the system of record, and the sensor's local file a buffer. This is the
  retention strategy; local disk is not one.
* **Alert on `maltrail_log_dir_free_bytes`** with real headroom. `-T` reports it too, and warns
  below 10 GB. When it reaches zero the sensor cannot append and detections are lost.
* **Archiving is yours to decide.** Compress or move old daily logs on your own schedule if you
  need the space. Note that the reporting UI serves historical logs as plain seekable files, so
  compressing them in place removes those days from the interface — archive them elsewhere.

If your policy *requires* deletion (event logs contain IP addresses and domains, which are
personal data in some jurisdictions), that is an explicit operator decision — make it with your
own tooling, deliberately, rather than having a sensor default do it quietly.

---

## Documentation

| | |
| --- | --- |
| [`sensor/docs/INSTALL.md`](sensor/docs/INSTALL.md) | installation, privileges, configuration, troubleshooting |
| [`sensor/docs/ARCHITECTURE.md`](sensor/docs/ARCHITECTURE.md) | how the sensor works internally |
| [`sensor/docs/COMPATIBILITY.md`](sensor/docs/COMPATIBILITY.md) | every deliberate difference from the old sensor |
| [`sensor/docs/REPORT.md`](sensor/docs/REPORT.md) | measurements, profiles and test results |
| [`sensor/docs/ROADMAP.md`](sensor/docs/ROADMAP.md) | what is still open |
| [`old/README.md`](old/README.md) | the previous Python sensor, kept as reference and test oracle |

---

## Contributing

Trails are the most valuable contribution: a line in the right file, with a source. Feeds, bug
reports and sensor work are equally welcome.

The sensor's full gate is one command:

```bash
bash sensor/tools/check.sh
```

It runs formatting, lints, the test suite in **both** debug and release profiles, and replays a
corpus through both the current sensor and the old Python one, requiring byte-identical events. The
Python side is `bash tests/run.sh`.

---

## Licence

MIT. See [`LICENSE`](LICENSE).

---

## Sponsors

* [Sansec](https://sansec.io/) (2024-2025)
* [Sansec](https://sansec.io/) (2020-2021)

## Developers

* Miroslav Stampar ([@stamparm](https://github.com/stamparm))
* Mikhail Kasimov ([@MikhailKasimov](https://github.com/MikhailKasimov))

## Presentations

* 47th TF-CSIRT Meeting, Prague (Czech Republic), 2016 ([slides](https://web.archive.org/web/20161109135211/https://www.terena.org/activities/tf-csirt/meeting47/M.Stampar-Maltrail.pdf))

## Publications

* Detect attacks on your network with Maltrail, Linux Magazine, 2022 ([Annotation](https://www.linux-magazine.com/Issues/2022/258/Maltrail))
* Best Cyber Threat Intelligence Feeds ([SilentPush Review, 2022](https://www.silentpush.com/blog/best-cyber-threat-intelligence-feeds))
* Research on Network Malicious Traffic Detection System Based on Maltrail ([Nanotechnology Perceptions, ISSN 1660-6795, 2024](https://nano-ntp.com/index.php/nano/article/view/1915/1497))

## Blacklist

* Maltrail's daily updated blacklist of malware-related domains can be found [here](https://raw.githubusercontent.com/stamparm/aux/master/maltrail-malware-domains.txt). It is based on trails found at [trails/static/malware](trails/static/malware) and can be safely used for DNS traffic blocking purposes.

## Thank you

* Thomas Kristner
* Eduardo Arcusa Les
* James Lay
* Ladislav Baco (@laciKE)
* John Kristoff (@jtkdpu)
* Michael M&uuml;nz (@mimugmail)
* David Brush
* @Godwottery
* Chris Wild (@briskets)
* Keith Irwin (@ki9us)
* Simon Szustkowski (@simonszu)

## Third-party integrations

* [FreeBSD Port](https://www.freshports.org/security/maltrail)
* [OPNSense Gateway Plugin](https://github.com/opnsense/plugins/pull/1257)
* [D4 Project](https://www.d4-project.org/2019/09/25/maltrail-integration.html)
* [BlackArch Linux](https://github.com/BlackArch/blackarch/blob/master/packages/maltrail/PKGBUILD)
* [Validin LLC](https://x.com/ValidinLLC/status/1719666086390517762)
* [Maltrail Add-on for Splunk](https://splunkbase.splunk.com/app/7211)
* [Maltrail decoder and rules for Wazuh](https://github.com/MikhailKasimov/maltrail-wazuh-decoder-and-rules)
* [GScan](https://github.com/grayddq/GScan) <sup>1</sup>
* [MalwareWorld](https://www.malwareworld.com/) <sup>1</sup>
* [oisd | domain blocklist](https://oisd.nl/?p=inc) <sup>1</sup>
* [NextDNS](https://github.com/nextdns/metadata/blob/e0c9c7e908f5d10823b517ad230df214a7251b13/security/threat-intelligence-feeds.json) <sup>1</sup>
* [NoTracking](https://github.com/notracking/hosts-blocklists/blob/master/SOURCES.md) <sup>1</sup>
* [OWASP Mobile Audit](https://github.com/mpast/mobileAudit#environment-variables) <sup>1</sup>
* [Mobile-Security-Framework-MobSF](https://github.com/MobSF/Mobile-Security-Framework-MobSF/commit/12b07370674238fa4281fc7989b34decc2e08876) <sup>1</sup>
* [pfBlockerNG-devel](https://github.com/pfsense/FreeBSD-ports/blob/devel/net/pfSense-pkg-pfBlockerNG-devel/files/usr/local/www/pfblockerng/pfblockerng_feeds.json) <sup>1</sup>
* [Sansec eComscan](https://sansec.io/kb/about-ecomscan/ecomscan-license)<sup>1</sup>
* [Palo Alto Networks Cortex XSOAR](https://xsoar.pan.dev/docs/reference/integrations/github-maltrail-feed)<sup>2</sup>

<sup>1</sup> Using (only) trails

<sup>2</sup> Connector to trails (only)
