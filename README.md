![Maltrail](https://i.imgur.com/3xjInOD.png)

[![License](https://img.shields.io/badge/license-MIT-red.svg)](#licence)
[![Rust](https://img.shields.io/badge/sensor-Rust-orange.svg)](sensor/)
[![X](https://img.shields.io/badge/X-%40maltrail-black.svg)](https://x.com/maltrail)

**Malicious traffic detection system.** Maltrail watches your network for contact with things that
are known to be bad — and tells you, in one line, what was seen and why it is considered bad.

```
"2026-08-07 09:14:22.117034" gw 10.13.13.2 57809 1.1.1.1 53 UDP DNS malware.bakewithdavid.com "asyncrat (malware)" (static)
```

That is the whole idea. No rule language, no tuning ritual, no ML. A **trail** is a domain, URL, IP
address, `IP:port` or User-Agent known to belong to something malicious, and Maltrail tells you when
one appears on the wire.

---

## Why Maltrail

Most network detection tools ask you to describe *behaviour*. Maltrail asks a simpler question that
answers most real incidents: **is this host talking to something we already know is bad?**

* **~2.1 million trails**, from ~3,100 curated static lists plus ~47 public feeds, refreshed daily.
  Heavily weighted toward **malware** — C2 domains, droppers, stealers, APT infrastructure — because
  that is what actually shows up in a compromise.
* **Trails are plain text.** One indicator per line, in a file you can read, grep and send a pull
  request against. That simplicity is the point: it is why coverage stays current, and why you can
  always answer "why did this fire?".
* **Heuristics on top**, not instead: port/UDP/infection/web scanning, DNS resource exhaustion,
  DGA-looking lookups, suspicious HTTP requests, sinkholed and parked domains, long domains,
  direct-IP downloads.

---

## Architecture

Two independent processes. Run them on one box or many.

```
   ┌──────────┐   events (UDP or file)   ┌──────────┐
   │  sensor  │ ───────────────────────► │  server  │ ◄── browser
   └──────────┘                          └──────────┘
    libpcap                               reporting UI + API
    trail matching
    heuristics
```

* **Sensor** — captures packets, matches them against the trails, applies the heuristics, emits
  events. Written in Rust; uses Linux `PACKET_FANOUT` to scale across cores.
* **Server** — collects events, stores them, serves the reporting interface.

A sensor can log locally, ship to a remote server, or both. Events also go out as CEF/syslog or
Logstash JSON for an existing SIEM.

---

## Quick start

Linux, `libpcap`, Rust (stable) for the sensor, Python 3 for the server.

```bash
git clone --depth 1 https://github.com/stamparm/maltrail.git
cd maltrail

# sensor
cd sensor && cargo build --release && cd ..
sudo setcap cap_net_raw,cap_net_admin=eip sensor/target/release/maltrail-sensor
sensor/target/release/maltrail-sensor -T      # validate the deployment
sensor/target/release/maltrail-sensor         # run it

# server (separate terminal, or a different machine)
python3 server.py
```

Then open `http://127.0.0.1:8338`. Credentials are set in `maltrail.conf` (`USERS`).

The sensor needs **no root** — `CAP_NET_RAW` plus `CAP_NET_ADMIN` is enough. On first start it
builds the trail set, then refreshes it once per `UPDATE_PERIOD`.

As services:

```bash
sudo cp maltrail-server.service maltrail-sensor.service /etc/systemd/system/
sudo systemctl enable --now maltrail-server maltrail-sensor
```

---

## Configuration

Everything lives in **`maltrail.conf`**, split into `[Sensor]` and `[Server]`. The options you are
most likely to touch:

| option | what it does |
| --- | --- |
| `MONITOR_INTERFACE` | interface(s) to capture on, or `any` |
| `CAPTURE_FILTER` | BPF filter; the default keeps bulk line-rate traffic out of userspace |
| `PROCESS_COUNT` | capture workers (one per core is a reasonable default) |
| `LOG_SERVER` | ship events to a remote server instead of, or as well as, logging locally |
| `USE_HEURISTICS` | heuristic detections on top of trail matching |
| `UPDATE_PERIOD` | how often trails are refreshed |
| `USER_WHITELIST` | your own never-alert list |
| `CUSTOM_TRAILS_DIR` | your own trails, alongside the shipped ones |

`maltrail-sensor -T` validates a configuration — trails, whitelist, log directory, capture filter,
privileges — and exits non-zero if the sensor would not work. Use it before you trust a deployment.

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

`type` is what matched (`DNS`, `IP`, `URL`, `HTTP`, `UA`, `PORT`, `PATH`, …), `info` is why it is
considered bad, and `reference` is where the trail came from — `(static)`, a feed name, or
`(heuristic)`.

---

## Operating it

* **`-T`** validates a configuration and exits. Usable as a deployment gate (the shipped systemd
  unit runs it as `ExecStartPre`).
* **`STATS_ADDRESS`** exposes Prometheus metrics. Alert on `maltrail_capture_dropped_total` — a
  non-zero rate means the sensor is **missing detections** — and on `maltrail_trail_generation`
  failing to advance, which means trails have stopped refreshing.
* **`SIGHUP`** reloads trails without a restart. Trails refreshed by anything else (the server, a
  cron job) are picked up within a second, with an atomic swap — no restart, no dropped packets.

---

## Documentation

| | |
| --- | --- |
| [`sensor/docs/INSTALL.md`](sensor/docs/INSTALL.md) | installation, privileges, configuration, troubleshooting |
| [`sensor/docs/ARCHITECTURE.md`](sensor/docs/ARCHITECTURE.md) | how the sensor works internally |
| [`sensor/docs/COMPATIBILITY.md`](sensor/docs/COMPATIBILITY.md) | every deliberate difference from the old sensor |
| [`sensor/docs/REPORT.md`](sensor/docs/REPORT.md) | measurements and test results |
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
corpus through both the current sensor and the old Python one, requiring byte-identical events.

---

## Licence

MIT. See [`LICENSE`](LICENSE).
