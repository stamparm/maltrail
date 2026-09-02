# Maltrail sensor — architecture

The sensor replaces `sensor.py`'s packet-processing hot path. It reads the same
`maltrail.conf`, loads the same `trails.csv`, and writes the same event lines to the same log
directory / `LOG_SERVER`, so the existing Python server and web UI need no change.

## Data flow

```
        NIC / pcap file
              |
      libpcap (BPF filter, TPACKET_V3 mmap ring on Linux)
              |
     PACKET_FANOUT_HASH  (one AF_PACKET socket per worker, one kernel group per interface)
              |
   +----------+----------+----------+
   | worker 0 | worker 1 |   ...    |     run-to-completion, no shared mutable state
   +----------+----------+----------+
              |
   per worker:  DLT/VLAN offset -> IP -> TCP/UDP/ICMP
                -> trail lookups (native IPv4/IPv6/port tables, string table)
                -> DNS / HTTP / TLS / QUIC extraction
                -> heuristics (scan, infection, web scan, DNS exhaustion, NXDOMAIN)
                -> Event -> ignore rules -> whitelist -> condense -> throttle
                -> daily log file / LOG_SERVER UDP / CEF syslog / Logstash JSON
```

A worker never hands a packet to another thread. The only cross-thread traffic is:

* an `Arc<TrailDb>` published by the reload thread (one relaxed atomic load per packet to
  notice it),
* a metrics snapshot published every 1024 packets,
* a shutdown flag.

## Threading model

`sensor.py` runs one capture thread per interface plus `PROCESS_COUNT` worker **processes**
fed through an `mmap` ring buffer (a packet is copied into the ring, then copied out again).
Rust has no GIL, so the ring, the copies and the IPC all disappear: one **thread** per capture
handle does capture *and* detection.

* **Live:** `CAPTURE_WORKERS` sockets per interface, all joined to one `PACKET_FANOUT` group.
  Each socket is read by its own thread. `CAPTURE_WORKERS` falls back to `CAPTURE_FANOUT`, which
  the shipped `maltrail.conf` leaves commented out — so a stock install runs **one** worker, and
  fanout is skipped entirely. It is deliberately *not* derived from `PROCESS_COUNT`: flow-hashed
  fanout dilutes the per-source scan heuristics, so scaling out is an explicit opt-in. If the
  kernel refuses the fanout group for the device, the sensor drops to a single worker with a
  warning; it never opens N independent sockets, which would deliver every packet N times.
* **Offline:** every `-r` file is replayed through **one** `WorkerState`, sequentially, so a
  replay is deterministic and evidence split across files accumulates.

`PROCESS_COUNT` does not affect the worker count. It is read for `EVENT_THROTTLE_MODE legacy`,
where it sets the throttle bucket width `sec // PROCESS_COUNT` that `core/log.py` uses. The default
throttle mode does not use it — see `src/throttle.rs` and `docs/COMPATIBILITY.md` §2, difference 14.

### Why fanout, and why it is a hard error

Opening N plain capture sockets on one interface delivers **every** packet to **every** socket,
so each detection would be reported N times. `PACKET_FANOUT_HASH` makes the kernel hash each
packet's flow to exactly one socket, which both removes the duplication and keeps a flow's
packets on one worker — which matters because all heuristic state (scan accumulators, DNS
exhaustion windows, burst suppression) is worker-local. If fanout is requested and cannot be
configured, the sensor **refuses to start** rather than silently duplicating.

Caveats, both surfaced in the startup diagnostics:

* IPv4 fragments hash on the outer header only, so later fragments of one datagram may land on
  a different worker. `CAPTURE_FANOUT_DEFRAG true` asks the kernel to reassemble before
  hashing. (The sensor drops non-first fragments anyway, matching `sensor.py`.)
* Tunnelled traffic (GRE/IPIP/VXLAN) hashes on the outer flow, so all inner flows of one tunnel
  land on one worker.

## Modules

| module | responsibility |
| --- | --- |
| `main.rs` | CLI, startup, diagnostics, worker spawn, reload/metrics threads, signals |
| `config.rs` | `maltrail.conf` parser (a port of `read_config()`) + the new capture options |
| `settings.rs` + `settings_gen.rs` | constants and compiled regexes; `settings_gen.rs` is **generated** from `core/settings.py` by `tools/gen_settings.py` |
| `pyre.rs` | Python-`re` compatibility: `re.escape`, `\Z`→`\z`, literal-brace rewriting, CPython's group-syntax rules |
| `addr.rs` | native `Ip`, Maltrail's non-RFC-5952 IPv6 rendering, `addr_port`, `parse_host_port` |
| `smallstr.rs` | fixed-capacity stack string so the hot path renders addresses without allocating |
| `trails/` | CSV loader (batched, parsed in parallel, inserted serially in file order), interned pair table, string table, native IP tables, wildcard-trail regex |
| `whitelist.rs` | `WHITELIST` / `WHITELIST_RANGES`, domain-member checks |
| `packet/` | DLT/VLAN offsets, the offset-learning heuristic, IP/TCP/UDP/ICMP headers |
| `protocols/` | DNS, HTTP, TLS SNI, QUIC Initial SNI |
| `heuristics/` | bounded scan accumulators, DNS exhaustion, NXDOMAIN counters, entropy/consonants |
| `process.rs` | the port of `_process_packet()` and `_check_domain()` |
| `state.rs` | per-worker state: caches, burst suppression, accumulators |
| `event.rs` | the event tuple, `safe_value()`, log-line rendering, Python-`repr` rendering |
| `output.rs` | daily log file, `LOG_SERVER`, CEF, Logstash, condensing, throttling, error log |
| `ignore.rs` | `IGNORE_EVENTS` rules and `IGNORE_EVENTS_REGEX` |
| `capture/` | libpcap live/offline handles, `PACKET_FANOUT` |
| `worker.rs` | the run-to-completion loop |
| `metrics.rs` | worker-local counters + lock-free aggregation |
| `testkit.rs` | in-process harness used by tests, benches and fuzz targets |

## Hot-path properties

The normal, non-alerting packet path performs:

* **no heap allocation** — addresses render into a `SmallStr` on the stack; trail lookups take
  `&str`/`u32`/`u128` keys; the packet is a borrowed `&[u8]` from libpcap's ring.
* **no address-to-text formatting** — IPv4 trails are looked up in a `u32`-keyed table, IPv4:port
  in a `u64`-keyed table, IPv6 in a `u128`-keyed table. Text is produced only when an event is
  emitted or when a rare path genuinely needs it (`_get_local_prefix`, the HTTP `Host` default).
* **no locking** — all state is worker-owned; trail reloads are noticed with one relaxed load.
* **no regex compilation** — every pattern is compiled once at startup.
* **no packet copying** — except when an offline pcap record exceeds `SNAP_LEN`, which is
  truncated exactly as live capture would.
* **bounded work per packet** — the HTTP/TLS/DNS parsers are all single-pass with explicit
  bounds; QUIC decryption is capped at `MAX_INITIAL_DECRYPT` bytes.

Trail lookups are the one structure worth describing: a `StrTable` is an open-addressing index
over a single byte arena (no per-key allocation, keys compared exactly so a hash collision can
never produce a wrong match), plus `IntTable`s for the native address forms. The tables cost
**~1.4x the size of the CSV they were built from** — a 1.60M-row / 81 MB `trails.csv` measures
109 MB of tables (`db.memory_bytes()`, printed as `memory=` in the startup summary) — and lookups
measure ~2 ns (IPv4) / ~19 ns (domain). Quote the ratio rather than a byte count: the trail set
grows continuously, so any single figure is stale within weeks.

The one probabilistic structure in the tree is `NegativeFilter` (below): a bitmap in front of each
table that can answer "definitely absent" but never "absent" for a key that is present. That
asymmetry is the whole licence for it — a probabilistic structure may sit in front of the
authoritative table as a *negative* prefilter, never be the table itself.

## Reload

`sensor.py` re-reads `trails.csv` on a timer and swaps the store atomically. The sensor
does the same: a reload thread polls the file's mtime (at most once a minute, bounded by
`UPDATE_PERIOD`), rebuilds a fresh immutable `TrailDb`, and publishes it through `TrailStore`.
Workers adopt it between packets, so one packet always sees one consistent snapshot.

Trail *updating* (downloading feeds) is **not reimplemented**, but the sensor does drive it: it runs
Maltrail's own `core/update.py` through `sensor/tools/update_trails.py`, before the first load and every
`UPDATE_PERIOD`, exactly as `sensor.py:init()` did. `DISABLE_TRAIL_UPDATES true` hands the file to
the server or a cron job instead, and the sensor then warns when it goes stale. See
`docs/INSTALL.md` §11.

## Failure handling

* Malformed / truncated / hostile packets: every parser is bounds-checked and returns `None`.
  Two deterministic fuzzers run on every `cargo test` (`tests/fuzz_parsers.rs`,
  `tests/fuzz_extended.rs`), so the property is checked on every build rather than when
  someone remembers. `MT_FUZZ_SEED` / `MT_FUZZ_ITERS` turn the second one into a long
  campaign without making CI nondeterministic.
* As a last resort, each packet is processed inside `catch_unwind`, mirroring `sensor.py`'s
  blanket `except Exception`. A recovered panic increments `panics_recovered` and writes one
  deduplicated line to `error.log` — it must never happen, and it is visible if it does.
* Configuration and capture failures are fatal and explicit (bad BPF filter, missing interface,
  unavailable fanout, unreadable config).
* Recoverable packet problems are counted (`malformed`, `truncated`, `fragments`, `ignored`) and
  never logged per packet.

## Metrics

Worker-local `u64` counters, published to a shared slot every 1024 packets and summed by the
reporter thread. Printed every `METRICS_INTERVAL` seconds (default 3600, matching
`sensor.py`'s hourly capture-stats print) and once at exit:

```
received, processed, ignored, malformed, truncated, fragments, events, written,
trail_lookups, capture_drops, if_drops, panics, ns/packet, trails, generation,
reloads=ok/failed, and per-worker processed/events
```


## Performance-critical structures

Three things carry most of the packet-path performance, and all three are correctness-sensitive
enough to be worth naming here.

**`src/fasthash.rs` — FxHash for integer keys.** Every accumulator keyed by `(Ip, Ip)` or
`(Ip, u16)` uses it. Maps keyed by attacker-chosen bytes (domains, URLs, paths, User-Agents)
deliberately keep `std`'s SipHash: a collision flood there is a real denial-of-service against the
sensor, and those maps are not hot enough to justify the risk.

**`NegativeFilter` (`src/trails/table.rs`) — a cache-resident miss filter.** The trail store is
~100 MB and growing, so a lookup miss is a DRAM round trip, and nearly every lookup misses. A
~16-bit-per-entry bitmap in front of each table answers "definitely absent" from L2/L3. The
asymmetry is what makes it sound: a *clear* bit is exact (an inserted key always sets its bits), a
*set* bit only means "check the real table". A false negative here would be a silently missed
detection, so the invariant is asserted directly, at two scales:

* `tests/trails.rs::the_negative_filter_never_hides_a_key_at_real_scale` builds a 1.5M-key store
  from a deterministic generator and walks every key back through `get()`. No trails file needed,
  so it runs on every test run everywhere, CI included.
* `tests/trails.rs::real_trails_every_single_row_is_findable_with_its_own_info` does the same walk
  over the *real* trails file (`$MALTRAIL_TRAILS`, default `~/.maltrail/trails.csv`). It self-skips
  when there is none; the `real trail set` CI job builds one with
  `sensor/tools/update_trails.py --offline` so it runs there rather than only on an operator's box.

**Incremental scan accumulators (`src/heuristics/scan.rs`).** Keys queue themselves when they
cross their detection threshold, and `_get_local_prefix()` counts are maintained as keys are
added. The sweep is therefore proportional to the number of alerts, not to the number of tracked
flows. The previous shape — filter and sort all four accumulators once per second — cost 1,150 ns
per SYN once the accumulators were full.

`Dots` (`src/process.rs`) is the same idea applied to names: a suffix of a dotted name is a slice
of it, so the parent walk borrows instead of rebuilding a `String` per level. It is pinned against
the `split`/`join` semantics it replaces, because index arithmetic is exactly where an
optimisation quietly changes behaviour.
