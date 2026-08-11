# Installing and migrating to the sensor

The sensor is additive: `sensor.py` is untouched and remains the reference implementation,
the differential-test oracle and the fallback. Both read the same `maltrail.conf`, the same
`trails.csv` and write the same event format, so you can switch back and forth freely — and you
can run them side by side against the same traffic while you build confidence.

## 1. Prerequisites

* Linux (x86-64 or aarch64). `PACKET_FANOUT` is Linux-only; everything else is POSIX.
* `libpcap` headers and library.
* A Rust toolchain, **1.74 or newer** — the MSRV is deliberately old so distribution packages
  qualify. openSUSE Leap 15 / SLE 15 ship exactly 1.74, which is enough; `rustup` is not needed
  and installing it there *conflicts* with the packaged `rust`/`cargo`.
* `setcap`, to let the sensor capture without running as root.
* **Python 3.6 or newer** on `PATH`. The sensor shells out to Maltrail's own updater to build
  `trails.csv`. 3.6 is the stock `python3` of RHEL 8, CentOS 7, openSUSE Leap 15 / SLE 15 and
  Amazon Linux 2, and it is tested in CI (whole suite plus a full offline trail build), so those
  hosts need nothing extra. Below 3.6 the trail set cannot be built and the sensor therefore
  detects nothing: `-T` reports the version it found, and the sensor prefers a newer `python3.N`
  on `PATH` automatically.

```bash
# Debian / Ubuntu
sudo apt-get install libpcap-dev build-essential libcap2-bin
# RHEL / Fedora
sudo dnf install libpcap-devel gcc libcap
# openSUSE / SLES  (rust 1.74 and python3 are usually already installed)
sudo zypper install libpcap-devel gcc libcap-progs rust cargo
# Rust, only if your distribution has none
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

If `python3 --version` is older than 3.6, install a newer one and point the sensor at it:

```bash
export MALTRAIL_PYTHON=/usr/bin/python3.11
```

## 2. Build

```bash
cd /opt/maltrail/sensor        # or wherever the repository lives
cargo build --release
```

The binary is `sensor/target/release/maltrail-sensor` (~4 MB, no runtime dependencies
beyond `libpcap` and libc). For a few percent more throughput:

```bash
cargo build --profile release-lto   # fat LTO, one codegen unit
# -> sensor/target/release-lto/maltrail-sensor
```

## 3. Run

The sensor finds `maltrail.conf` by walking up from the executable, so from the repository root:

```bash
sudo ./sensor/target/release/maltrail-sensor
```

Explicit forms, all mirroring `sensor.py`:

```bash
# specific configuration file
sudo ./sensor/target/release/maltrail-sensor -c /etc/maltrail/maltrail.conf

# offline replay of one or more pcaps
./sensor/target/release/maltrail-sensor -r capture.pcap --offline -c test.conf

# print events to the console as well
sudo ./sensor/target/release/maltrail-sensor --console

# quiet (no operational output)
sudo ./sensor/target/release/maltrail-sensor -q
```

`MALTRAIL_CONFIG` and `MALTRAIL_ROOT` override configuration-file and repository-root discovery.

### Running without root

Grant the binary just the capabilities it needs instead of running the whole sensor as root:

```bash
sudo setcap 'cap_net_raw,cap_net_admin+eip' sensor/target/release/maltrail-sensor
echo 'DISABLE_CHECK_SUDO true' >> maltrail.conf     # the sudo check is a Python-era guard
```

`LOG_DIR` must then be writable by the sensor's user.

## 4. Startup diagnostics

Every run prints what it actually decided, so a misconfiguration is visible immediately:

```
[i] capture backend: pcap (libpcap live)
[i] interface(s): eth0
[i] PACKET_FANOUT: enabled (group 41234, mode hash, defrag off) across 8 worker socket(s)
[i] capture: snaplen=2000 buffer=64 MB timeout=100ms immediate=false
[i] effective BPF filter: udp or icmp or (tcp and (tcp[tcpflags] == tcp-syn or port 80 ...))
[i] workers: 8 (datalink 1)
[i] trails: ipv4=144,758 ipv4:port=253,517 ipv6=2,014 wildcard-regex=27 whitelisted=2 malformed=0 memory=68.5 MB
[i] whitelist: 3,440 entries, 18 CIDR range(s)
[i] heuristics: on (disabled: none)
[i] features: scan_window=30s check_host_domains=false check_missing_host=false user_agent_patterns=loaded sni_extraction=off
[i] event sinks: file:/var/log/maltrail
```

Runtime metrics are printed every `METRICS_INTERVAL` seconds (default 3600) and once at exit.

## 5. Configuration

No configuration change is required. Existing options behave identically; the sensor-relevant
ones are `MONITOR_INTERFACE`, `CAPTURE_FILTER`, `LOG_DIR`, `TRAILS_FILE`, `SENSOR_NAME`,
`PROCESS_COUNT`, `UPDATE_PERIOD`, `USE_HEURISTICS`, `DISABLED_HEURISTICS`, `SCAN_WINDOW`,
`CHECK_HOST_DOMAINS`, `CHECK_MISSING_HOST`, `LOG_SERVER`, `SYSLOG_SERVER`, `LOGSTASH_SERVER`,
`REMOTE_SEVERITY_REGEX`, `DISABLE_LOCAL_LOG_STORAGE`, `USER_WHITELIST`, `USER_IGNORELIST`,
`IGNORE_EVENTS_REGEX`, `CAPTURE_FANOUT`, `USE_FAST_PREFILTER`, `FAST_FLOW_CUTOFF`.

### Multi-core capture

Reuse the existing option:

```conf
CAPTURE_FANOUT auto      # one capture socket+worker per CPU core
# CAPTURE_FANOUT 8       # or an explicit count
```

Or set the worker count directly:

```conf
CAPTURE_WORKERS 8
```

Both open N sockets in one kernel `PACKET_FANOUT` group. **If fanout cannot be configured the
sensor exits** rather than falling back to N independent sockets, which would deliver every
packet to every worker and report every detection N times.

Verify a deployment once:

```bash
sudo python3 sensor/tools/fanout_check.py --interface eth0 --workers 8
```

It runs a 1-worker baseline and an N-worker run and asserts that traffic is **distributed**
(every worker gets packets) and **not duplicated** (the N-worker total matches the baseline).
A good run looks like this:

```
[i] run with 1 worker(s) on 'lo'...
    sent=20000 received=20000 processed=20000 fanout=disabled (single capture socket)
    per worker: w0=20000
[i] run with 4 worker(s) on 'lo'...
    sent=20000 received=20000 processed=20000 fanout=enabled (group 61155, mode hash, defrag off) across 4 worker socket(s)
    per worker: w0=5018, w1=5025, w2=5047, w3=4910

[i] total processed: 1 worker=20000, 4 workers=20000 (ratio 1.00)
[i] distribution: 4/4 workers received traffic
[i] no duplication: N-worker total matches the 1-worker baseline
[i] fanout check: PASSED
```

A ratio near N instead of 1.00 means the workers are on independent sockets rather than in one
fanout group — every detection would be reported N times.

### New, optional capture options

All have conservative defaults; none are required.

| option | default | meaning |
| --- | --- | --- |
| `CAPTURE_WORKERS` | `PROCESS_COUNT` (or `CAPTURE_FANOUT`, whichever is larger) | capture sockets/threads per interface (`auto` = CPU count). One worker = one `sensor.py` worker process. **Set to 1 if scan detection matters more than throughput** — see below |
| `CAPTURE_BUFFER_SIZE` | `16MB` | libpcap ring size per socket (accepts `kB`/`MB`/`GB`/`%`) |
| `CAPTURE_SNAPLEN` | 2000 (`SNAP_LEN`) | bytes captured per packet |
| `CAPTURE_TIMEOUT` | 100 | capture/poll timeout in ms; also bounds shutdown latency |
| `CAPTURE_IMMEDIATE` | false | deliver packets as they arrive (lower latency, worse throughput) |
| `CAPTURE_FANOUT_MODE` | `hash` | `hash`, `lb`, `cpu`, `rollover`, `random`, `qm`. Keep `hash`: worker-local heuristic state depends on stable flow assignment |
| `CAPTURE_FANOUT_DEFRAG` | false | ask the kernel to reassemble IP fragments before hashing |
| `CAPTURE_FANOUT_GROUP` | `(pid + iface index) & 0xffff` | pin the group id (needed if two sensors must share one group) |
| `OFFLINE_TIMESTAMPS` | `pcap` | `pcap` or `wallclock`; `wallclock` reproduces `sensor.py`-on-Python-3 offline behaviour |
| `METRICS_INTERVAL` | 3600 | seconds between metrics lines; 0 disables |
| `STATS_ADDRESS` | *(empty)* | `host:port` for the Prometheus metrics endpoint, e.g. `127.0.0.1:9109`. Empty = disabled |
| `EVENT_THROTTLE_MODE` | `summarize` | `summarize` (burst, then one aggregated line), `legacy` (`core/log.py` byte for byte), `off` |
| `EVENT_THROTTLE_WINDOW` | 60 | suppression window in seconds, per `(ip, trail)` |
| `EVENT_THROTTLE_BURST` | 3 | events written verbatim per key per window before summarizing |
| `EVENT_THROTTLE_MAX_KEYS` | 50000 | bound on tracked keys; the least recently used is summarized and dropped |
| `DISABLE_TRAIL_UPDATES` | false | stop refreshing `TRAILS_FILE` (for hosts where it is pushed in from elsewhere) |
| `REPAIR_TRUNCATED_TRAILS` | true | salvage wildcard trails the feed truncated; `false` = drop them like `sensor.py` |

For maximum throughput: a large `CAPTURE_BUFFER_SIZE` (64–256 MB), `CAPTURE_IMMEDIATE false`,
a small non-zero `CAPTURE_TIMEOUT` (50–100 ms) so the kernel can batch, the existing
`CAPTURE_FILTER`, and a `CAPTURE_SNAPLEN` no larger than needed (2000 covers every extraction
the sensor performs).

## 6. Privileges: no root required

The sensor needs two Linux capabilities, not a root account:

| capability | what needs it |
| --- | --- |
| `CAP_NET_RAW` | opening the `AF_PACKET` capture socket |
| `CAP_NET_ADMIN` | promiscuous mode and `PACKET_FANOUT` |

Grant them once to the binary and never run it as root again:

```bash
sudo setcap cap_net_raw,cap_net_admin=eip sensor/target/release/maltrail-sensor
```

`sensor.py` tests `geteuid() == 0`, which asks the wrong question in both directions: it refuses to
replay a pcap file (which needs no privileges at all) and it refuses to run under capabilities,
which is how a packet-capture process should be deployed. The sensor checks for the capability
it actually uses, skips the check entirely for `-r` replay, and prints the exact `setcap` line if it
is missing. `DISABLE_CHECK_SUDO true` still skips the check.

`maltrail-sensor.service` runs as an unprivileged `maltrail` user with exactly those two
ambient capabilities, `NoNewPrivileges=yes`, and the usual systemd hardening — so a parser bug in a
packet-facing process cannot become root on the host.

## 7. Testing a configuration before you trust it

```bash
sensor/target/release/maltrail-sensor -T -c /etc/maltrail.conf
```

Like `suricata -T` or `nginx -t`: validates everything that can be validated without capturing a
packet, prints one line per check, and exits 0 (usable) or 1 (would not work). It never modifies
anything — it does not run a trail update and does not create the log directory.

```
[o] log directory: '/var/log/maltrail' is writable
[o] capture filter: udp or icmp or (tcp and (tcp[tcpflags] == tcp-syn or port 80 or port...
[o] capture privileges: CAP_NET_RAW present
[o] interface: eth0
[o] workers: 8 (PACKET_FANOUT required; verify with tools/fanout_check.py as root)
[o] whitelist: 3440 entries, 18 CIDR range(s)
[o] trails: 1505265 loaded (0 malformed row(s)), ipv4=144758 ipv4:port=253517 ipv6=2014 wildcard=29
[!] trails age: 195.0 day(s) old, older than UPDATE_PERIOD
[o] trail updates: updater and interpreter present
[o] user-agent patterns: loaded from data/ua.txt
[o] heuristics: on (disabled: none)
```

Checked: config parses and has its mandatory options; `LOG_DIR` exists and a file can actually be
created in it; `CAPTURE_FILTER` compiles (against a dead pcap handle, so no interface or privileges
are needed); the monitor interfaces exist; capture privileges are present; the whitelist loads; the
trails file loads, how many trails of each kind, how many malformed rows, how many unusable
wildcard patterns, and **how old the file is**; the trail updater and a Python interpreter are
present; the User-Agent patterns loaded; heuristics are on; remote sinks are `host:port`.

The systemd unit runs it as `ExecStartPre=`, so a broken deployment fails loudly at start instead
of running a sensor that cannot detect anything.

### Worker count and scan detection

`PACKET_FANOUT_HASH` splits traffic by **flow**, but the scan heuristics count per **source**, and a
scan is many flows. A scanner using incrementing ephemeral source ports lands on a different worker
per probe, so with N workers a threshold needs roughly N times more probes before any single worker
trips it. The same applies to infection scanning, UDP scanning, per-domain DNS-exhaustion counters
and NXDOMAIN hour counters.

This is the same behaviour as `sensor.py`'s default (its own source comments the effect), so
migrating does not make it worse — but it is a real limitation, not something fanout solved.

* Throughput matters most (a busy gateway, trail matching is the point): leave `CAPTURE_WORKERS` at
  `PROCESS_COUNT`.
* Scan/heuristic fidelity matters most: `CAPTURE_WORKERS 1`. Fanout is skipped entirely at one
  worker, so per-source state is undiluted — at the cost of single-core capture.

## 8. Metrics endpoint

```
STATS_ADDRESS 127.0.0.1:9109
```

Exposes the sensor's counters in Prometheus text format at `/metrics`, so drops and throughput can
be **alerted on** rather than discovered in a log line printed once an hour:

```
maltrail_up 1
maltrail_workers_alive 1
maltrail_workers_total 1
maltrail_build_info{version="3.0"} 1
maltrail_uptime_seconds 3600
maltrail_packets_received_total 184203941
maltrail_capture_dropped_total 0
maltrail_capture_ifdropped_total 0
maltrail_events_total 1284
maltrail_events_written_total 1103
maltrail_local_log_errors_total 0
maltrail_events_throttled_total 9915
maltrail_log_dir_free_bytes 157066420224
maltrail_state_saturations_total 0
maltrail_trails 1505265
maltrail_trail_generation 4
maltrail_trail_reloads_rejected_total 0
maltrail_packet_path_nanoseconds 552
maltrail_worker_packets_total{worker="0"} 23018112
maltrail_worker_alive{worker="0"} 1
maltrail_worker_last_heartbeat_seconds{worker="0"} 1786118842
```

Alert on these five. Every one of them means *this sensor is not detecting what you think it is*:

| condition | what has happened |
| --- | --- |
| `maltrail_up == 0` | no capture worker is alive — this host is **not being monitored** |
| `rate(maltrail_capture_dropped_total) > 0` | the capture ring is dropping packets: **missed detections**, and nothing else in the sensor's output makes that visible in time to act |
| `rate(maltrail_local_log_errors_total) > 0` | detections were produced and then **lost** on the way to disk |
| `maltrail_trail_generation` not advancing | trails have stopped being refreshed |
| `maltrail_log_dir_free_bytes` low | evidence storage is filling; Maltrail never deletes event logs to reclaim it (see §9) |

`maltrail_state_saturations_total` is worth watching too: non-zero means a state-exhaustion flood
has narrowed the heuristics. Exact trail matching is unaffected by design, so this is a
degradation, not an outage. `maltrail_worker_alive{worker="N"}` and
`maltrail_worker_last_heartbeat_seconds` separate one dead worker (a partial blind spot, since
each owns a slice of the fanout) from a wedged one that still claims to be alive. The per-worker
packet counter exposes an unbalanced fanout hash, which the total hides.

It costs nothing on the packet path — a scrape reads the same per-worker atomic slots the metrics
line reads. It is opt-in, binds where you tell it to (use a loopback address; metrics reveal traffic
volumes and detection counts), and a failure to bind is reported but never fatal to detection.

## 9. Event retention and disk space

**Maltrail never deletes event evidence.** There is no retention setting that expires event logs,
and that is deliberate: they are the records an investigation goes back to, and a sensor that
quietly discards them is worst exactly when it matters most.

That makes free space something to operate rather than ignore:

* **Ship the durable copy off-box.** `LOG_SERVER` (or `SYSLOG_SERVER` / `LOGSTASH_SERVER`) makes
  the server or the SIEM the system of record and the sensor's local file a buffer. That is the
  retention strategy; a local disk is not one.
* **Alert on `maltrail_log_dir_free_bytes`** with real headroom, and watch
  `maltrail_local_log_errors_total` — non-zero means detections were produced and then lost.
  `-T` reports free space too, warns below 10 GB and fails below 1 GB.
* **Archive on your own schedule.** Compressing or moving old daily logs is fine and is the
  operator's call. Note the reporting interface serves historical logs as plain seekable files
  (byte offsets, Range requests, sampled counting), so compressing them **in place** removes
  those days from the UI. Archive them elsewhere instead.

If policy *requires* deletion — event logs contain IP addresses and domains, which are personal
data in some jurisdictions — that is an explicit operator decision, made with your own tooling,
rather than a sensor default that destroys evidence quietly.

## 10. Signals

| signal | effect |
| --- | --- |
| `SIGTERM`, `SIGINT` | clean shutdown: workers stop within `CAPTURE_TIMEOUT`, condensed events are flushed, the final metrics line is printed |
| `SIGHUP` | reload the trails now, without waiting for the poll and without restarting |

`SIGHUP`'s default action is to **terminate**, so before it was handled the reflex `kill -HUP`
— "reload your config" on any daemon — took the sensor down mid-capture. It now requests a trail
reload instead; `tests/trail_update.rs` asserts the process survives it.

Externally refreshed trails are also picked up without any signal: the reload thread polls
`TRAILS_FILE`'s mtime once a second (it is a single `stat()`), builds a fresh immutable store and
swaps it in atomically. Counted in the metrics line as `reloads=ok/failed` and `generation=`.

## 11. Trail updates

The sensor refreshes `TRAILS_FILE` itself, exactly like `sensor.py` does: once before the
first load, then every `UPDATE_PERIOD`. It does this by running Maltrail's **own** updater —
`sensor/tools/update_trails.py` is a thin wrapper around `core.update.update_trails()` — so
feeds, `UPDATE_SERVER`, `USE_FEED_UPDATES`, `DISABLED_FEEDS`, `IP_MINIMUM_FEEDS` and
`CUSTOM_TRAILS_DIR` all behave as they always have, and there is no second implementation to drift
out of sync. `--offline` rebuilds from the bundled static/custom trails without touching the
network, again matching `sensor.py --offline`.

This requires `python3` on the host (any interpreter that can run Maltrail itself; override with
`MALTRAIL_PYTHON`). If it is missing, the sensor says so loudly and keeps running on whatever
trails it already has — it does not exit, but it will not detect anything added since that file
was written.

Set `DISABLE_TRAIL_UPDATES true` if something else owns the file (the Maltrail server with
`USE_SERVER_UPDATE_TRAILS true`, a cron job, a config-management push). The sensor then warns when
the file is older than `UPDATE_PERIOD`:

```
[!] '/root/.maltrail/trails.csv' is 28.4 day(s) old (older than UPDATE_PERIOD): every trail added
    since then is NOT being detected
```

That warning exists because this failure is silent by nature: a month-old trails file loads
without complaint and the sensor looks perfectly healthy while missing every new IOC.

However the file is refreshed — by this sensor, the server or cron — the change is picked up
without a restart (mtime poll bounded by `UPDATE_PERIOD`, at most once a minute): a fresh
immutable trail store is built and swapped in atomically, counted in the metrics line
(`reloads=ok/failed`, `generation=`).

## 12. Running as a service

`maltrail-sensor.service` is provided:

```ini
[Unit]
Description=Maltrail. Sensor of malicious traffic detection system (Rust)
Requires=network.target
Wants=maltrail-server.service
After=network-online.target maltrail-server.service

[Service]
User=root
WorkingDirectory=/opt/maltrail/
ExecStart=/opt/maltrail/sensor/target/release/maltrail-sensor
Restart=on-failure
KillMode=mixed
KillSignal=SIGTERM
TimeoutStopSec=30

[Install]
WantedBy=multi-user.target
```

```bash
sudo cp maltrail-sensor.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now maltrail-sensor
journalctl -u maltrail-sensor -f
```

SIGTERM is handled: workers stop within `CAPTURE_TIMEOUT`, condensed events are flushed, final
metrics are printed and capture handles are released.

## 13. Verifying a deployment

Nothing here is required to run the sensor; it is how to convince yourself before you rely on it.

1. **Replay a corpus.** Detection is checked against a generated fixture corpus and against one
   sampled from your own `trails.csv`:

   ```bash
   python3 sensor/tools/gen_corpus.py
   cargo build --release --manifest-path sensor/Cargo.toml
   sh sensor/tools/check.sh
   ```

2. **Shadow your own traffic.** Capture live traffic while an adversarial workload runs, then
   replay that one capture and diff the results:

   ```bash
   bash sensor/tools/shadow_run.sh --seconds 600
   ```

3. **Scale out only if you need to.** One worker handles 1.8M packets/s on an eight-core laptop
   CPU and 3.7M on a Ryzen 9 5900X (steady-state, `tools/bench_compare.py`). If
   `maltrail_capture_dropped_total` is climbing, set `CAPTURE_FANOUT` and re-run
   `fanout_check.py` — and read §3 of `docs/COMPATIBILITY.md` first, because extra capture
   sockets cost scan-heuristic sensitivity.

## 14. Troubleshooting

| symptom | cause / fix |
| --- | --- |
| `please run 'maltrail-sensor' with root privileges` | run under `sudo`, or `setcap` the binary and set `DISABLE_CHECK_SUDO true` |
| `unable to open capture on 'ethX': permission problem` | same as above; also check the interface exists (`ip link`) |
| `PACKET_FANOUT was requested (N workers). Refusing to fall back…` | the kernel refused the group. Check it is Linux ≥ 3.1, that no other process holds the same group id with a different mode (`CAPTURE_FANOUT_GROUP`), or set `CAPTURE_WORKERS 1` |
| `missing mandatory option 'X'` | the config file is not the Maltrail one; `MONITOR_INTERFACE`, `CAPTURE_BUFFER` and `LOG_DIR` are required, exactly as for `sensor.py` |
| No events at all | check `CAPTURE_FILTER`, that `trails.csv` is non-empty (the startup line prints the count), and that `LOG_DIR` is writable |
| `[i] repaired N wildcard trail pattern(s) truncated in the feed` | informational: those trails were cut off in transit and were salvaged (the intact alternatives are kept, the dangling fragment dropped). `sensor.py` drops such trails entirely, so this is a detection gain |
| `[!] N wildcard trail pattern(s) are unusable and NOT matched` | those patterns could not be salvaged at all; CPython rejects them too, so `sensor.py` ignores them as well |
| No colour in `--console` output | colour is emitted only when stdout is a TTY (as in `sensor.py`), and `NO_COLOR` disables it |
| `trail update failed ('str' object has no attribute 'isascii')` | A Maltrail older than 3.1.1 on Python 3.6 (RHEL 8, CentOS 7, openSUSE Leap 15 / SLE 15, Amazon Linux 2). Fixed - `core/update.py` no longer needs 3.7 - so update Maltrail, or set `MALTRAIL_PYTHON` to a 3.7+ interpreter if you cannot. Without either the trail set is empty and the sensor detects nothing; `-T` reports the interpreter version rather than just its presence |
| `setcap: command not found` | install `libcap2-bin` (Debian/Ubuntu), `libcap` (RHEL/Fedora) or `libcap-progs` (openSUSE/SLES) |
| `rustup ... conflicts with 'rust+rustc'` on openSUSE/SLES | do not install `rustup`; the packaged `rust` 1.74 already meets the MSRV. `rustup` is only needed for the developer gate (`check.sh`), which wants `rustfmt` and `clippy` |
| `check.sh: rustfmt: command not found` | that gate is for contributors, not for running the sensor. `rustup component add rustfmt clippy`, or skip it — `cargo build --release` is all a deployment needs |
| `log directory: '...' is NOT writable` / `does not exist` | run the `sudo install -d ...` line `-T` prints. Note it uses `$(id -gn)` for the group: not every distribution gives each user a group named after them (openSUSE puts everyone in `users`), so `-g "$USER"` fails there with `install: invalid group` |
| `install: invalid group 'maltrail'` when setting up the systemd units | `useradd` only creates a matching group on distributions that default to per-user groups. Run `groupadd --system maltrail` first, then `useradd --system --gid maltrail ...` — both lines are in the unit file's header comment |
| `condensed observable store: flush of N rows failed` | the sensor could not write `LOG_DIR/meta.sqlite`; check the directory's permissions and free space. Detection and event logging are unaffected — only the server's `/meta` view loses that window. `maltrail_meta_flush_errors_total` counts these |
| High `capture_drops` in the metrics line | raise `CAPTURE_BUFFER_SIZE`, add `CAPTURE_WORKERS`, or tighten `CAPTURE_FILTER` |
