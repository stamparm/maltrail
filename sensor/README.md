# Maltrail sensor

Maltrail's sensor: packet capture and trail detection, in Rust. It reads `maltrail.conf` and
`trails.csv`, and writes the event log the Maltrail server and web interface read.

It needs no root: `CAP_NET_RAW` (plus `CAP_NET_ADMIN` for promiscuous mode and `PACKET_FANOUT`)
is enough, and `-T` validates a deployment before you trust it.

```bash
# build
cd sensor && cargo build --release

# validate the configuration, trails, log directory and capture filter
./target/release/maltrail-sensor -c ../maltrail.conf -T

# run (live capture; grant the capabilities once instead of running as root - docs/INSTALL.md §6)
./target/release/maltrail-sensor -c ../maltrail.conf

# run (offline replay)
./target/release/maltrail-sensor -c ../maltrail.conf --offline -r capture.pcap
```

## Documentation

| document | contents |
| --- | --- |
| [`docs/INSTALL.md`](docs/INSTALL.md) | prerequisites, build, run, configuration, privileges, metrics, trail updates, small hosts, systemd, troubleshooting |
| [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) | data flow, threading model, modules, hot-path guarantees, the trail store, reload, metrics |
| [`docs/BEHAVIOUR.md`](docs/BEHAVIOUR.md) | what it reads and writes, every detection, design decisions, limitations and edge cases |

## Layout

```
sensor/
  src/
    main.rs          CLI, startup, diagnostics, worker spawn, reload + metrics threads
    config.rs        maltrail.conf parser
    settings.rs      compiled regexes and matchers
    settings_gen.rs  GENERATED from core/settings.py by tools/gen_settings.py
    pyre.rs          Python `re` syntax compatibility for trail and config patterns
    addr.rs          native IP type and Maltrail's address rendering
    smallstr.rs      fixed-capacity stack string (allocation-free rendering)
    trails/          CSV loader, lookup tables, negative filter, wildcard regex, prebuilt store
    whitelist.rs     WHITELIST / WHITELIST_RANGES
    packet/          link-layer offsets, IP/TCP/UDP/ICMP, tunnel decapsulation
    protocols/       DNS, HTTP, TLS, QUIC, ClientHello reassembly
    heuristics/      scanning, DNS exhaustion and tunneling, NXDOMAIN, beaconing, ICMP tunneling,
                     IDN homographs
    process.rs       per-packet detection and the domain check
    state.rs         per-worker state (caches, burst suppression, accumulators)
    event.rs         event tuple, log-line rendering
    output.rs        log file, LOG_SERVER, CEF/syslog, Logstash, condensing
    throttle.rs      event-log throttling (summarize / legacy / off)
    ignore.rs        IGNORE_EVENTS and IGNORE_EVENTS_REGEX
    capture/         libpcap handles, PACKET_FANOUT, source-affine fanout program
    worker.rs        run-to-completion capture loop
    metrics.rs       worker-local counters and lock-free aggregation
    stats.rs         Prometheus endpoint (STATS_ADDRESS)
    meta.rs          condensed observable store (LOG_DIR/meta.sqlite)
    trailupdate.rs   runs core/update.py through tools/update_trails.py
    selftest.rs      -T
    colorized.rs     --console colouring
    fasthash.rs, lru.rs  hashing and bounded caches
    testkit.rs       in-process harness for tests, benches and fuzzing
  tests/             integration suites; tests/corpus/ is the replay corpus (pcaps + manifest),
                     tests/vectors/ holds vectors generated from core/*.py
  benches/hotpath.rs microbenchmarks, packet path, replay, worker scaling
  tools/             generators (settings, vectors, corpus), check.sh, trail updater, release tools
```

## Everything that must pass

```bash
sh sensor/tools/check.sh
```

It checks that `src/settings_gen.rs` matches `core/settings.py`, regenerates the vectors, runs
`cargo fmt --check`, `cargo clippy -D warnings` and the full test suite in both the debug and
release profiles, and builds the release binary.

Live capture and `PACKET_FANOUT` need privileges, so they are checked separately:

```bash
sudo python3 sensor/tools/fanout_check.py --interface eth0 --workers 4
```

## Benchmarks

```bash
cargo bench --bench hotpath                        # every row
BENCH_FILTER=dns cargo bench --bench hotpath       # only rows whose name contains "dns"
```

Rows are reported in separate categories - isolated microbenchmarks, the full packet path, and
pcap replay - plus worker scaling, so a microbenchmark cannot be mistaken for sensor throughput.
