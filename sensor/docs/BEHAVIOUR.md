# Sensor behaviour

What the sensor reads and writes, what it detects, the design decisions behind both, and the
limitations worth knowing. How it is built is in [`ARCHITECTURE.md`](ARCHITECTURE.md); how to run
it is in [`INSTALL.md`](INSTALL.md).

Every detection below is pinned by a test: `tests/detection.rs` asserts on real log lines, and
each case of the replay corpus (`tests/corpus/`, one pcap per case plus `manifest.json`) declares
the events it must produce, which `tests/replay.rs` checks on every run.

---

## 1. Inputs and outputs

The sensor shares its files with the Maltrail server, so the formats below are a contract with
`core/` and `server.py`, not an internal detail.

### Configuration

* `maltrail.conf` is the only configuration source, parsed by the same rules as the server's
  `core/settings.py:read_config()`: comments are stripped before quotes are handled, indented
  lines form array blocks, digit strings become integers, `$VAR` expands from the settings
  globals and then the environment, `_DIR` values resolve against the repository root, and
  `MALTRAIL_<NAME>` environment variables override the file.
* Names starting with `USE_`, `SET_`, `CHECK_`, `ENABLE_`, `SHOW_` or `DISABLE_` are parsed as
  booleans. Any other boolean option (`REPAIR_TRUNCATED_TRAILS`, `TRAIL_STORE_CACHE`,
  `ALLOW_EMPTY_TRAILS`, ...) is read from its text, `true`/`false`/`yes`/`no`/`on`/`off`/`1`/`0`.
* `CAPTURE_BUFFER_SIZE` accepts bytes, `kB`/`MB`/`GB`, or `%` of physical memory. When it is
  absent, the old `CAPTURE_BUFFER` seeds it; the ring defaults to 10% of RAM within 64-256 MB.
* `-T` validates all of this, plus the trails, whitelist, log directory, capture filter and
  privileges, and reports every out-of-range value it clamped.

### Trails

* `TRAILS_FILE` is the `trail,info,reference` CSV the server's updater writes, read with Python
  `csv` quoting rules. Whitelisted trails are dropped at load, `(info, reference)` pairs are
  interned, and rows without exactly three fields are skipped and counted as malformed.
* The sensor refreshes `TRAILS_FILE` itself, before the first load and every `UPDATE_PERIOD`, by
  running `core/update.py` through `tools/update_trails.py`: there is one trail-update mechanism
  in the repository. `DISABLE_TRAIL_UPDATES true` hands the file to the server or a cron job, and
  the sensor then warns when it is older than `UPDATE_PERIOD`.
* A file refreshed by anyone is picked up within a second (an mtime poll) and swapped in
  atomically. A reload that would lose more than half the trails (`TRAIL_RELOAD_MIN_RATIO`) is
  rejected and the current set is kept, because a truncated file is far likelier than a real
  collapse. An empty trail set refuses to start unless `ALLOW_EMPTY_TRAILS` says otherwise.
* The built tables are kept in `<TRAILS_FILE>.store` and mapped on the next start, `-T` or
  reload, but only when the CSV's size, mtime and content, the whitelist and the sensor version
  all match (`TRAIL_STORE_CACHE`; see [`ARCHITECTURE.md`](ARCHITECTURE.md#reload)).
* Wildcard trails: `(static)` trails matching `[\].][*+]|\[[a-z0-9_.\-]+\]` that contain regex
  metacharacters form one alternation, in CSV order, capped at 100 groups. A pattern that needs
  look-around or back-references puts the whole alternation on a backtracking engine with a
  backtrack limit, so a pathological pattern returns "no match" instead of hanging.

### Event log

* One line per event: `"<localtime>" <sensor> <src_ip> <src_port> <dst_ip> <dst_port> <proto>
  <type> <trail> <info> <reference>`. Values are quoted the server's way (CR/LF flattened, then
  space/quote quoting with doubled quotes), and an empty value or a zero port is written as `-`.
* Timestamps use `localtime_r`, so they follow the same `TZ` and tzdata as the server.
* Daily `LOG_DIR/YYYY-MM-DD.log` files, created 0644, one `write(2)` per event; `O_APPEND` writes
  of this size are atomic, so workers sharing a file never interleave inside a line.
* `LOG_SERVER` receives `"<sec> <event line>"` over UDP; `SYSLOG_SERVER` receives CEF, with the
  severity from `REMOTE_SEVERITY_REGEX`; `LOGSTASH_SERVER` receives JSON.
* Events whose info matches `CONDENSE_ON_INFO_KEYWORDS` are condensed per `(src_ip, trail)` and
  flushed every `CONDENSED_EVENTS_FLUSH_PERIOD`, with the varying fields joined into sorted,
  comma-separated lists.
* `IGNORE_EVENTS` rules and `IGNORE_EVENTS_REGEX` (matched against a Python-style `repr()` of the
  event) drop events before they are written. An invalid regex warns once and is disabled, rather
  than dropping every event.
* `LOG_DIR/error.log` records problems, each distinct message once.

### Condensed observable store

`USE_CONDENSED_STORAGE` (on by default) writes `LOG_DIR/meta.sqlite`, one cumulative row per
domain or address with `first_seen`, `last_seen` and `count`, which the server's `/meta` novelty
and retro-hunt views read through `core/meta.py`. The file is that module's format exactly: the
same schema (`WITHOUT ROWID`, `meta_info.schema_version = 1`), addresses as 4/16-byte BLOBs and
domains as TEXT, the same min/max/count merge, a rollback journal rather than WAL, and mode 0644
so a non-root server can read a store the sensor wrote as root. Junk addresses are filtered, each
window is capped at `CONDENSED_MAX_WINDOW_KEYS`, and the file is pruned to `META_MAX_ROWS` by
score on the trail-update cycle. Workers hand their window to one writer thread, so a slow disk
never stalls capture.

### Console and command line

* `--console` prints events in the server's colour scheme, only when stdout is a terminal;
  `NO_COLOR` disables colour.
* Options: `-c`, `-r` (comma-separated and repeatable), `-q`, `--console`, `--offline`,
  `--debug`, `-T`, `--verify-trail-store`, `--timestamps pcap|wallclock`, `--version`, `-h`.

---

## 2. Detections

| detection | what triggers it |
| --- | --- |
| IP and IP:port trails on TCP | the SYN of a connection to or from a listed address; `IPORT` when the `address:port` key matched. To a listed host, `attacker` listings are not reported (noise the host provoked); from one, `malware` listings are not (backscatter); `parking site` only on ports 80/443 |
| IP trails on UDP and other protocols | the same two-sided rule for non-DNS UDP; echo requests only for ICMP |
| Domain trails | DNS queries, HTTP `Host`, TLS and QUIC SNI: exact names, parent domains (`(sub).listed.example`), `.onion` gateways, wildcard trails; infrastructure names under a suspicious parent and the bare domain of a dynamic-DNS provider are skipped |
| DNS answers | listed IPs in A/AAAA answers, with the query in the trail; sinkhole and parking answers |
| URL, path and host trails | the full candidate list from the request line, including the POST body |
| HTTP heuristics | SQL/XML/PHP/LDAP/XSS/XXE/SSTI injection, data leakage, config-file access, remote code execution, directory traversal, web scanners, DNS changers, direct-download extensions, suspicious paths, missing `Host`, proxy probes, IoT-malware downloads from a bare IP |
| HTTP responses | sinkhole banners, seized-domain `<title>`s, suspicious content types |
| User agents | `data/ua.txt` patterns, minus `WHITELIST_UA_REGEX` |
| TLS fingerprints | SHA-1 of the server certificate, JA3 and JA4 of the ClientHello, against trail keys of those shapes (`CHECK_TLS_FINGERPRINTS`) |
| `port_scanning` | SYN and the NULL/FIN/XMAS stealth flags to many ports of one host within `SCAN_WINDOW` |
| `udp_scanning` | UDP to many ports of one host |
| `infection` | one local source reaching `POTENTIAL_INFECTION_PORTS` on many hosts |
| `web_scanning` | many distinct paths from one source, except internal-to-internal |
| `dns_exhaustion` | many subdomains of one domain in a minute |
| `dns_tunneling` | sustained high-entropy queries to one zone that is not a known reputation or DNSBL service |
| excessive NXDOMAIN | many NXDOMAIN answers for one domain within an hour |
| `long_domain` | an over-long first label, minus known reputation zones |
| `idn_homograph` | an `xn--` name whose Cyrillic, Greek or Armenian lookalike letters spell a whitelisted domain it is not |
| `beaconing` | TCP SYNs from one source to one destination port at timer-like intervals |
| `icmp_tunneling` | echo requests carrying ever-changing payloads unlike any ping tool's |

Heuristics are switched off as a group with `USE_HEURISTICS false`, or by name with
`DISABLED_HEURISTICS` (the names in the table). Every heuristic finding is rated `suspicious` with
a `(heuristic)` reference, never `malware`. The state behind them is bounded
(`HEURISTIC_MAX_KEYS`, 50,000 keys); a full map refuses new keys and counts them in
`maltrail_state_saturations_total`, and exact trail matching is unaffected.

---

## 3. Design decisions

1. **Offline replay uses the pcap timestamps.** Replaying a capture behaves as capturing it did:
   scan windows, burst suppression, throttling and hourly resets run on the recorded clock.
   `--timestamps wallclock` stamps each packet with the time it is processed instead.
2. **Threads, not processes.** One thread per capture handle does capture and detection with no
   shared mutable state, so there is no ring buffer, no packet copy and no IPC.
3. **One capture worker by default.** `CAPTURE_WORKERS` (formerly `CAPTURE_FANOUT`) scales out
   on request; `auto` uses the CPU count. It is not derived from `PROCESS_COUNT`.
4. **Multi-worker capture keeps a source on one worker.** The scan heuristics count per source,
   and a scan is many flows: flow-hashed fanout (`CAPTURE_FANOUT_MODE hash`) kept 91% of the
   single-worker heuristic alerts at 2 workers, 87% at 4 and 66% at 8. `source`, the default above
   one worker, hashes the source address with a classic-BPF fanout program (no `bpf()` syscall, no
   extra privileges) and keeps 100% at 2, 4 and 8 (`tests/multi_worker_parity.rs`). Exact trail
   matching is identical at every worker count. Needs Linux 4.5+.
5. **Fanout is all or nothing.** N independent sockets would deliver every packet N times, so
   the sensor never opens them. If the kernel refuses the fanout group for the device, it runs
   one worker and says so; if a socket fails after others have joined the group, it exits.
6. **A UDP datagram to a listed address is reported.** Suppression depends on which side matched,
   as on TCP: `attacker` listings are dropped on the destination side, `malware` on the source
   side. A datagram to a listed host is the detection worth having; one from it is usually
   backscatter.
7. **Burst suppression compares the payload too.** A byte-for-byte repeat of a datagram within a
   second is skipped, but two different DNS queries on one socket are both examined: a stub
   resolver walking its `search` list, a retry or a forwarder all reuse the socket, and the
   second name would otherwise never be looked at.
8. **An exact trail beats its whitelisted parent.** A trail that names a more specific host than
   the closest whitelisted ancestor fires (3,082 shipped trails sit under platform domains such as
   cloudfront.net and amazonaws.com and could never fire otherwise). On a tie, or an exact
   whitelist entry, the whitelist wins; wildcard trails and all heuristics stay suppressed under
   any whitelisted ancestor.
9. **Truncated wildcard trails are repaired.** Feeds ship patterns cut off mid-alternation. The
   repair keeps every complete alternative and drops the dangling fragment, since keeping it
   would leave a one-character alternative that matches far more than the feed meant. Reported at
   startup; `REPAIR_TRUNCATED_TRAILS false` drops such patterns instead.
10. **Event-log throttling summarizes instead of discarding** (`EVENT_THROTTLE_MODE`). The first
    `EVENT_THROTTLE_BURST` (3) events per `(ip, trail)` per `EVENT_THROTTLE_WINDOW` (60 s) are
    written at once; the rest are held and written as one line when the window closes, with the
    varying fields comma-joined in place. A flood beyond the held-buffer cap appends `(+N more)`.
    `legacy` reproduces the server's `core/log.py` suppression (two events per
    `sec // PROCESS_COUNT` bucket, the rest discarded); `off` writes everything.
11. **Deterministic output.** Bundled NXDOMAIN names are sorted, scan events report their first
    observed detail, and a condensed record with mixed field types is still written.
12. **No root.** The sensor checks for `CAP_NET_RAW` (granted by `setcap`, an ambient set or
    root), skips the check for `-r`, and prints the exact `setcap` command when it is missing.
    `DISABLE_CHECK_SUDO` skips it entirely.
13. **Stacked VLAN tags are followed** (`0x8100`, `0x88a8`, `0x9100`, up to 4), so QinQ links at a
    carrier or datacentre edge are not invisible.
14. **IPv6 extension headers are walked to the transport header** (Hop-by-Hop, Routing,
    Fragment, AH, Destination Options, Mobility, HIP, Shim6; up to 8; ESP ends the walk).
    Otherwise eight bytes would hide a packet's ports, DNS name, HTTP host and SNI.
15. **Tunnels are decapsulated** - VXLAN (4789 and 8472), GENEVE, GRE, ERSPAN II/III and
    IP-in-IP, up to 3 deep. The outer header is still matched, and the inner packet is processed
    in its own right: on an overlay SPAN feed every host worth watching is inside the tunnel.
    `maltrail_packets_decapsulated_total` counts what was unwrapped.
16. **Split handshakes are reassembled.** A post-quantum ClientHello is about 2 KB, so the SNI is
    often in the second TCP segment, and every QUIC ClientHello now spans two Initials. Up to 64
    handshakes of 4 KB per worker are reassembled (stale after 3 s), and JA3/JA4 are computed
    over the whole hello. TLS SNI is read over IPv6 too; the shipped `CAPTURE_FILTER` passes the
    continuation segment for both families (`tests/capture_filter.rs`).
17. **CPU affinity is left to the operator** (`taskset`, systemd `CPUAffinity=`); with kernel
    fanout the kernel already spreads the work.

---

## 4. Limitations and edge cases

1. **IPv6 is rendered Maltrail's way, not per RFC 5952**: the last longest zero run is collapsed
   (`1:0:0:2:0:0:0:3` → `1:0:0:2::3`) and `::` renders as `::0`. Events always carry that form;
   IPv6 trails match in any spelling.
2. **DNS question names do not follow compression pointers**: a `0xc0` length byte reads as a
   192-byte label, the name fails validation, and the query is dropped. Answers do follow them.
3. **`.example`, `.local`, `.test`, `.arpa` and the other `IGNORE_DNS_QUERY_SUFFIXES` are never
   checked**, which is easy to trip over when writing test traffic.
4. **HTTP header names are matched case-sensitively** (`\r\nHost:`), and a header cut off by the
   snap length is skipped.
5. **`SNAP_LEN` (2000 bytes) applies to offline records too**, so a `-s 0` capture is analysed on
   the bytes live capture would have seen.
6. **A wildcard trail that defines a group named `g<digits>` is refused**, because those names
   identify which trail matched inside the alternation.
7. **Burst suppression is one slot per protocol**, not per flow: a repeat of the same 5-tuple in
   the same second is skipped, two interleaved flows are not.
8. **Certificates are matched only from TLS 1.2 and below** (1.3 encrypts them) and only when the
   server's certificate flight fits one segment.
9. **Heuristic state is per worker.** With `CAPTURE_FANOUT_MODE hash`, a scan spread across many
   flows needs each worker to cross the threshold on its own (decision 4).
10. **Event order between workers is not deterministic**; lines never interleave (§1).
11. **`-r -` (a pcap on stdin) is not supported**; use a file or a FIFO.
12. **`PACKET_FANOUT` is Linux-only.** Elsewhere (macOS, the BSDs, Windows with Npcap) capture
    works, but `CAPTURE_WORKERS` above 1 cannot be honoured, and `MONITOR_INTERFACE any` is
    expanded to the interfaces the machine has.
