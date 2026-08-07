# Implementation report — Maltrail sensor

Scope: replace `sensor.py`'s packet-processing hot path with a Rust implementation that keeps
existing behaviour, configuration, trail data and event format. `sensor.py` and `core/` are
unchanged; nothing outside `sensor/` is modified except two additive files.

---

## 1. Changed files

Everything new lives under `sensor/`. Outside it, exactly two additions:

| file | change |
| --- | --- |
| `maltrail-sensor.service` | **new** — systemd unit for the sensor (the Python `maltrail-sensor.service` is untouched) |
| `README.md` | **modified** — one short section pointing at the sensor |

`sensor.py`, `core/*`, `server.py`, `html/*`, `trails/*` and the existing tests are **not**
touched.

### New: `sensor/` (~15,300 lines)

| area | files | lines |
| --- | --- | --- |
| sensor source | `src/*.rs`, `src/{packet,protocols,heuristics,trails,capture}/*.rs` | 11,041 |
| generated constants | `src/settings_gen.rs` (from `core/settings.py`) | 195 |
| integration tests | `tests/{detection,replay,trails,vectors,capture_live,fuzz_parsers}.rs` | 2,089 |
| benchmarks | `benches/hotpath.rs` | 330 |
| fuzz targets | `fuzz/fuzz_targets/*.rs`, `fuzz/Cargo.toml`, `fuzz/README.md` | 190 |
| tooling | `tools/*.py`, `tools/check.sh` | 2,000 |
| docs | `docs/*.md`, `README.md` | — |
| generated fixtures | `tests/corpus/` (36 pcaps + trails + manifest), `tests/vectors/` (18 files) | — |

Module-by-module mapping to the Python source: `docs/PORTING_MAP.md`.

### Tooling (all reproducible, all committed)

| tool | purpose |
| --- | --- |
| `tools/gen_settings.py` | generates `src/settings_gen.rs` **from `core/settings.py`**, so thresholds, keyword tuples and the long regexes cannot drift |
| `tools/gen_vectors.py` | generates `tests/vectors/*.tsv` by **calling the real Python functions** (`safe_value`, `_cef_escape`, `unquote`, `re.escape`, `compress_ipv6`, `splitext`, the `checks` builder, entropy, every detection regex, and the wildcard-trail accept/reject decision) |
| `tools/gen_corpus.py` | builds the 36-case replay corpus + fixture trails + manifest. `--from-trails <csv>` instead samples the **real** trails.csv and synthesizes the traffic each sampled trail should trip (8 traffic shapes), so parity is proven against real feed data rather than a 30-row fixture |
| `tools/dump_trails.py` | dumps what Python's `load_trails()` loaded (every row, plus the wildcard alternation), as the oracle for `tests/loader_parity.rs` |
| `tools/update_trails.py` | the sensor's trail-update entry point: a thin wrapper around `core.update.update_trails()` |
| `tools/parity.py` | runs **both** sensors over the corpus and diffs the events |
| `tools/bench_compare.py` | Python-vs-Rust offline full-sensor benchmark |
| `tools/fanout_check.py` | live-capture + `PACKET_FANOUT` verification (distributed, not duplicated) |
| `tools/check.sh` | everything that must pass, in one command |

---

## 2. Test results

```
cargo test --release
```

**311 tests, 0 failures — in BOTH profiles.**

```
cargo test            # debug: integer-overflow checks ON
cargo test --release  # what actually ships
```

Both, not one. A release-only gate compiles out overflow checks, which is how a real overflow in
`dns::question_type_class` survived: the fuzz suite that exists to prove the packet path never
panics on arbitrary input could not fire in the profile it was run in. `tools/check.sh` now runs
debug first.

| suite | tests | covers |
| --- | --- | --- |
| unit (`--lib`) | 191 | address rendering, LRU + admission filter, config parsing, Python-regex translation, trail tables + negative prefilter, wildcard regex, CSV splitting, DLT/VLAN, IP/TCP/UDP/ICMP, DNS (incl. named offset-overflow contracts), HTTP helpers, TLS SNI, QUIC (RFC 9001 key schedule, FIPS-197 AES vectors), scan/exhaustion/NXDOMAIN accumulators, event rendering, CEF/Logstash, throttle modes, hashers, fanout argument encoding, metrics, Prometheus exposition |
| `tests/detection.rs` | 57 | every detection class, ported case-for-case from `tests/test_sensor.py`, asserted on real log lines; plus the concurrent-first-write race and result-cache metric publication |
| `tests/vectors.rs` | 19 | Rust output vs vectors produced by the actual Python functions |
| `tests/trails.rs` | 10 | every trail shape, whitelist filtering, malformed rows, pair interning, and the operator's **real 1.5M-trail file** — every row findable with its own info |
| `tests/replay.rs` | 9 | the whole corpus through the real capture handle + DLT + packet path; determinism; multi-file replay; unknown-datalink learning |
| `tests/trail_update.rs` | 9 | trail refreshing (missing/stale/disabled), `-T` config test, SIGHUP survival |
| `tests/fuzz_parsers.rs` | 6 | ~200k random / patterned / mutated inputs through every parser and the whole packet path |
| `tests/capture_live.rs` | 6 | live-handle open, BPF rejection, fanout guards (privilege-adaptive) |
| `tests/loader_parity.rs` | 2 | the Rust loader vs `core.common.load_trails()` over the real CSV, row by row |

The unit total includes the console colouriser (`src/colorized.rs`), whose exact output is pinned
against `core/colorized.py` by a generated vector.

Also clean: `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings` (0 warnings).

### Bugs the tests found (and fixed)

1. **IPv6 rendering.** `compress_ipv6()`'s `0+(\w)` *backtracks* in Python; my first version consumed
   zeros greedily, so an all-zero trailing group was not shortened (`::0000` instead of `::0`).
   Found by a vector generated from `core/addr.py`.
2. **Wildcard trails with look-around would have been silently lost.** The `regex` crate cannot
   express look-around, which CPython accepts. Now such a trail puts the whole alternation on
   `fancy-regex` (a backtracking engine, like CPython's), and a vector asserts the accept/reject
   decision matches CPython for every wildcard trail in the real feed set.
3. **Shutdown could hang.** A blocking `pcap_next_ex` parked inside libpcap past the configured
   timeout, so a worker never saw the shutdown flag: SIGTERM required a SIGKILL and lost the
   final metrics and condensed-event flush. Live handles are now non-blocking with an explicit
   `poll()` in the worker, plus a bounded join in `main`. **Found by running
   `tools/fanout_check.py` on real hardware.**
4. **Trail loading slurped the whole CSV** (+73 MB peak RSS). Now streamed.
5. **Three bugs found by the maintainer running the sensor for real**, all now fixed and each
   with a regression test or a reproduction recorded here:
   * **A healthy live sensor stopped itself after 10 seconds.** The bounded join added in §2.3
     started its deadline at *startup* instead of at the shutdown request, so `main` declared the
     capture worker stuck and exited while it was happily capturing. The wait is now unbounded
     until shutdown is actually requested. Reproduced with a FIFO replay source and verified to
     run indefinitely.
   * **The process could hang on exit even after printing its summary.** A worker parked in
     libpcap's blocking read holds the underlying stdio stream's lock, and glibc's `exit()` blocks
     flushing every `FILE` on the way out. `sensor.py` sidesteps this with `os._exit()`; the Rust
     sensor now flushes its own buffers and calls `_exit()` too. Verified: exits exactly at the
     10 s grace deadline instead of never.
   * **Metrics could read all zeros.** Counters were published every 1024 packets, so a quiet
     interface never published. Housekeeping now also runs on a 1-second timer.
6. **The sensor never refreshed `trails.csv`** — the worst bug of the port, and it was reported
   from the field, not caught by a test. `sensor.py:init()` starts an `update_timer()` that
   refreshes the trails file before the first load and every `UPDATE_PERIOD`; the sensor only
   ever *read* it. On the maintainer's host the file was four weeks old, so `511mon.kozow.com` —
   added to `trails/static/malware/asyncrat.txt` two weeks after that snapshot — was detected only
   through its dynamic-DNS parent (`(511mon).kozow.com "dynamic domain (suspicious)"` instead of
   `511mon.kozow.com "asyncrat (malware)"`). It had been *documented* as an acceptable limitation,
   which was the real mistake: a sensor silently running on stale trails looks perfectly healthy.
   Now implemented by invoking Maltrail's own updater, with `tests/trail_update.rs` covering the
   exact scenario (stale file → refreshed → new IOC detected with its own info), plus a loud
   staleness warning when updates are disabled.
7. **One worker where `sensor.py` runs sixteen.** `CAPTURE_WORKERS` defaulted to `CAPTURE_FANOUT`,
   which is commented out in the shipped `maltrail.conf`, so a live run used a single worker while
   `sensor.py` used `PROCESS_COUNT` (16) processes. Because `core/log.py` keeps the log throttle
   **per worker**, the same 100 DNS lookups produced ~4 log lines instead of ~59 — no detection was
   lost (`events=101` in the metrics line), but the log looked wrong, which is just as bad.
   Reported from the field. `CAPTURE_WORKERS` now defaults to `PROCESS_COUNT`, and the throttle
   itself was redesigned (§2.14 in `docs/COMPATIBILITY.md`).
8. **Loader parity was never actually asserted against Python.** Every trail test compared the
   Rust loader with itself. `tests/loader_parity.rs` now runs `core.common.load_trails()` as an
   oracle over the real 1.5M-row CSV and compares every row's three fields, the distinct-key
   count, and the wildcard alternation in group order. It passes — but the absence of that test is
   how a stale-trails bug survived, and how two upstream data bugs (below) went unnoticed.
9. Several Python-regex constructs the `regex` crate rejects but CPython accepts (`{` that is not
   a repetition, `\Z`, `\>`), and one CPython *rejects* that the crate accepts (late `(?i)` global
   flags, duplicate group names) — all now handled in `src/pyre.rs` so the two loaders keep the
   same pattern set.

### Upstream findings (in the Python code / trail data, not the port)

These came out of the differential work and are **not** fixed here — they are `core/` and trail-data
issues, outside the sensor port's scope. Reported for the maintainer to decide on:

1. **`core/update.py:330` truncates regex trails at the first `?`.**

   ```python
   if '?' in key and not key.startswith('/'):
       key = key.split('?')[0]
   ```

   That rule normalises URL query strings, but it also applies to *regex* trails. Two
   `android_roamingmantis` patterns contain `b?post`, `sing-?post`, `soft{0,1}b(a\|o)nk`, so they
   are cut mid-alternation (692 → 373 chars, 685 → 388) and no longer compile. `build_trails_regex()`
   then silently drops them, so **two static malware trails are dead in `sensor.py`** — they have
   been generated into `trails.csv` in unusable form for as long as the rule has existed. A guard
   like `and not re.search(r"[\[\](){}*+|]", key)` would fix it at the source.
2. **The log throttle lets *two* events per bucket through, not one.** `core/log.py`'s bucket change
   resets `log_trails` without recording the current pair, so the first event of a bucket is written
   and forgotten, the second is written and remembered, and the third is dropped. Measured directly
   against `core/log.py`: 100 events over 5 seconds → 4 lines at `PROCESS_COUNT 16`, 10 at
   `PROCESS_COUNT 1`. If one-per-bucket was the intent, the reset branch needs to add the pair too.
3. **The suppression window is the machine's core count.** `sec // PROCESS_COUNT` means a 16-core
   host suppresses for 16 s and a 4-core host for 4 s, and the aggregate rate scales with the worker
   count on top of that. See `docs/COMPATIBILITY.md` §2.14 for what the sensor does instead.

---

## 3. Parity results

```
python3 sensor/tools/parity.py                    # strict
python3 sensor/tools/parity.py --timestamps pcap  # with real timestamps
```

**Strict mode: 36/36 cases OK. 0 event lines only in Python, 0 only in Rust.**

Roughly one run in ten shows a single Python-side surplus event, and it is worth being precise
about why rather than calling it flaky. `sensor.py` on Python 3 stamps every packet with
`time.time()` (`sensor.py:1523`), and the sensor in strict mode is told to do the same so the
heuristic windows line up — so **both** runs are driven by the wall clock, at different speeds.
The event-log throttle admits two events per `sec // PROCESS_COUNT` bucket, so whether a run
happens to straddle a second boundary changes the event count by one on a case with repeated
identical detections. That is nondeterminism in the *comparison*, not in either sensor. A real
regression fails every run; this fails occasionally. `tools/parity.py --repeat N` makes the
distinction explicit instead of leaving it to judgement — it fails hard when every run differs and
says so plainly when the failures are intermittent.

The corpus covers ordinary TCP, duplicate SYNs, port scans, stealth (NULL/FIN/XMAS) scans, an
ACK sweep that must *not* fire, UDP scans, infection scans, web scans, DNS queries (exact /
parent / onion / `ip-adress.com` / wildcard-regex), DNS resolver trails, PTR/AAAA exclusion, DNS
responses (sinkholed and parked, compressed and uncompressed answer names), malformed DNS,
NXDOMAIN floods, DGA labels, DNS exhaustion, ignored DNS suffixes, HTTP trails, the HTTP
heuristic battery, HTTP response heuristics, truncated packets, VLAN and QinQ, IPv4 fragments,
IPv6, ICMP, repeated detections, hour-crossing timestamps, TLS SNI, QUIC SNI, `DLT_RAW`,
`DLT_LINUX_SLL`, IPv4 options, whitelisting, and an interleaved mixed-traffic soup.

Only one value-level normalisation is applied, and it is genuinely nondeterministic in Python:
the "excessive no such domain" trail bundles observed sub-labels by iterating a `set`, so their
order varies **between runs of `sensor.py` itself** (string hashing is randomised per process).
The harness sorts that bundle on both sides; Rust emits it sorted. Nothing else is normalised —
trail text, info, reference, addresses, ports, protocol and event type must match exactly.

**With real pcap timestamps: 26/36 identical, 10 with a Rust surplus, 0 with a Python-only
event.** Those 10 are the timestamp-sensitive cases: `sensor.py` on Python 3 substitutes
wall-clock time for every packet, so offline it cannot advance its scan windows, its
burst-suppression 5-tuple never changes and its log-throttle bucket never rolls.
`core/testing.py` skips those very heuristics offline on Python 3 for the same reason. The Rust
sensor detects them correctly; run with `--timestamps wallclock` for byte-comparable output.

---

## 4. Benchmark results

Hardware: AMD Ryzen 7 PRO 4750U (8 cores / 16 threads), 14 GB RAM, Linux 6.8.0, `--release`.

### 4a. Python vs Rust — offline full-sensor replay

`tools/bench_compare.py --packets 300000 --trails ~/.maltrail/trails.csv --slope --repeat 3`,
1,505,265 real trails, 300k packets averaging 866 bytes (60% bulk TLS, 15% SYN, 10% DNS, 10%
HTTP, 5% ICMP/other), fastest of 3 runs:

| | wall (s) | CPU (s) | packets/s | peak RSS |
| --- | --- | --- | --- | --- |
| `sensor.py` | 5.21 | 4.44 | 57,580 | 63 MB |
| sensor | 1.54 | 1.52 | 194,598 | 88 MB |
| **ratio** | **3.4x faster** | **2.9x less CPU** | **3.4x** | 1.39x more |

Startup measured directly (same trails and config, 1-packet pcap), then subtracted:

| | startup (s) | ns/packet | steady packets/s |
| --- | --- | --- | --- |
| `sensor.py` | 0.20 (warm) / **7.63 (cold)** | 16,689 | 59,920 |
| sensor | 1.18 | **1,209** | **827,371** |
| **ratio** | — | **13.8x faster** | **13.8x** |

Read those two tables together — the totals and the per-packet costs tell different stories, and
both matter:

* **Per packet, the sensor is ~13.8x faster** (1.2 µs vs 16.7 µs). That is the number that
  bounds how much traffic one worker can absorb.
* **`sensor.py` starts faster and uses less memory**, and that is not noise: `core/trailsbin.py`
  builds a 48 MB binary trail store once and `mmap`s it thereafter, so a warm Python start skips
  CSV parsing entirely (0.20 s) and its trail pages are file-backed. The sensor parses the
  73 MB CSV on every start (1.18 s, 68 MB of resident tables). Python's *first* start, which
  builds that store, takes **7.63 s** — 6.5x slower than the sensor's every-time startup.
* Because a short replay is dominated by startup, the end-to-end ratio (3.4x) understates the
  steady-state one (13.8x). For a long-running sensor, steady state is what matters.

This is the clearest next optimization: give the sensor an mmap-able binary trail store
(§7.1).

**Re-measured after the §4c optimization rounds**, same harness, same command, same box, trail
set now 83.3 MB / 1,505,265 rows:

| | wall (s) | packets/s | peak RSS | startup (s) | ns/packet | steady packets/s |
| --- | --- | --- | --- | --- | --- | --- |
| `sensor.py` | 7.32 | 40,987 | 64 MB | 0.28 (warm) | 23,448 | 42,648 |
| sensor | 2.49 | 120,246 | 132 MB | 2.24 | **865** | **1,156,423** |
| **ratio** | 2.9x | 2.9x | 2.06x more | — | **27.1x faster** | **27.1x** |

Both sensors produced 0 events on this corpus (equal), so the ratio is like-for-like work.

The steady-state ratio moved from 13.8x to 27.1x for two independent reasons, and it is worth
being precise about which is which: the sensor's own per-packet cost fell 1,209 -> 865 ns (-28%,
the §4c work, reproducible), while `sensor.py` on this box measured 16,689 -> 23,448 ns/packet
(+40%) on a larger trail set and a machine under different load. **Only the first is an
improvement we made.** Quote 13.8x as the conservative floor and 27x as the current measurement;
the honest statement is "14-27x per packet, depending on run and hardware".

Startup regressed (1.18 -> 2.24 s) purely because the CSV grew; it is parsed on every start, which
is exactly what §7.1 fixes.

### 4b. Rust, staged (`cargo bench --bench hotpath`)

Categories are kept separate so a microbenchmark can never be quoted as sensor throughput.

| benchmark | kind | ns/iter | iter/s | Gbit/s |
| --- | --- | --- | --- | --- |
| ip+tcp header parse | microbench | 3.7 | 268,100,652 | – |
| dns question decode | microbench | 76.2 | 13,119,250 | – |
| http request line + host | microbench | 197.3 | 5,067,989 | – |
| tls clienthello sni | microbench | 84.5 | 11,828,396 | – |
| quic initial sni (hkdf+aes) | microbench | 3,783.0 | 264,342 | – |
| trail lookup: ipv4 miss | microbench | 2.3 | 426,235,933 | – |
| trail lookup: ipv4+port miss | microbench | 3.4 | 289,857,700 | – |
| trail lookup: domain miss | microbench | 20.0 | 50,075,795 | – |
| **process_packet (mixed traffic)** | **packet path** | **559.2** | **1,788,147** | **12.39** |
| process_packet (no heuristics) | packet path | 370.3 | 2,700,285 | 18.71 |
| process_packet (bulk tls only) | packet path | 91.6 | 10,913,231 | 126.94 |
| udp burst suppression (early out) | packet path | 23.5 | 42,643,505 | 25.59 |
| dns query, warm domain cache | packet path | 374.0 | 2,673,543 | 1.56 |
| dns query, cold domain cache | packet path | 937.4 | 1,066,767 | 0.59 |
| pcap replay | replay | 1,066.6 | 937,555 | 0.60 |

Notes on reading this table:

* Trail lookups against the **real 1.5M-trail set** cost 2–3 ns for an address and 20 ns for a
  domain, so they are not the bottleneck: the mixed-traffic packet path is dominated by the HTTP
  and DNS text handling.
* "bulk tls only" (92 ns, 127 Gbit/s at 1454-byte packets) is the shape that dominates a fat
  pipe: the sensor recognises there is no `HTTP/` in the payload and stops.
* The warm/cold domain-cache pair (374 ns vs 937 ns) shows what the 1000-entry result cache is
  worth; the cold figure is the DGA-flood shape that defeats it.
* `pcap replay` (1.07 µs/packet) is the honest single-worker offline figure — packet path plus
  libpcap, DLT resolution, snaplen handling, `catch_unwind` and metrics.

### 4c. Where a packet's time actually goes, and what was done about it

"13.8x faster than Python" and "fast" are different claims. Measured per protocol on
**1,000,000-packet** pcaps, the real 1,505,265-trail set, one worker pinned to one core
(`taskset -c 2`, best of three), end to end through the release binary:

| traffic | before | after | |
| --- | --- | --- | --- |
| TCP SYN (70 B) | 1,502 ns | **402 ns** | 3.7x |
| HTTP request (169 B) | 1,303 ns | **752 ns** | 1.7x |
| DNS query, every name unique (DGA flood) | 2,154 ns | **1,453 ns** | 1.5x |
| DNS query, warm result cache | – | **652 ns** | |
| bulk TLS (1,473 B) | 402 ns | 402 ns | read-bound |
| ICMP echo (58 B) | 101 ns | 101 ns | the floor |
| 866-byte mixed replay (60% bulk TLS) | 802 ns | **552 ns** | 1.45x |

*Method: median of eight runs each, pinned to one core. This machine is bimodal (frequency
scaling), so a single "best of three" overstates; the "before" column was measured as min-of-three
and is therefore, if anything, flattering to the old code.*

The mixed number moves least because 60% of that pcap is bulk TLS, whose cost is the libpcap read
of a 1,473-byte packet — and on a live sensor the shipped `CAPTURE_FILTER` never delivers those
packets in the first place. SYN, DNS and HTTP are what a live sensor actually processes.

**What the time was going on, and what changed:**

1. **The per-second heuristic sweep was O(everything tracked), not O(alerts) — 1,150 ns per SYN.**
   Each sweep filtered all four scan accumulators (up to `SCAN_MAX_KEYS` = 50,000 keys each) and
   sorted the survivors, and `_get_local_prefix()` rendered *every tracked source address* to a
   `String` and rebuilt a `HashMap` — once per second, i.e. ~20 allocations per packet at 5,000
   pps. Keys now queue themselves when they cross their threshold, and prefix counts are
   maintained as keys are added, so the sweep is proportional to the number of *alerts*.
   (`src/heuristics/scan.rs`)
2. **SipHash on integer keys.** `std`'s default hasher is HashDoS-resistant, which is dead weight
   for maps keyed by `(Ip, Ip)`. Those now use an inlined FxHash (`src/fasthash.rs`). Maps keyed
   by attacker-chosen bytes — domains, URLs, paths, User-Agents — deliberately keep SipHash.
3. **A cache-resident negative prefilter in front of the trail store** (`NegativeFilter` in
   `src/trails/table.rs`). The store is ~87 MB, so a miss — which is nearly every lookup — cost a
   DRAM round trip. A ~16-bit-per-entry bitmap answers "definitely absent" from L2/L3. It can
   never produce a false negative (an inserted key always sets its bits; a set bit only means
   "check the table"), which is the only reason a probabilistic structure is acceptable in a
   detection path. `tests/trails.rs` walks all 1,505,265 real rows through `get()` on every test
   run, which is the definitive check.
4. **Allocations on the DNS path.** `check_domain` lower-cased every query into a fresh `String`,
   built a `Vec` of labels, and rebuilt a `String` per parent level via `'.'.join(parts[i:])`. A
   suffix of a dotted name is already a contiguous slice of it, so the parent walk now borrows
   (`Dots`, pinned against `split`/`join` in `src/process.rs` tests). The lower-casing borrows
   unless the name actually contains an upper-case byte.
5. **Two hot regexes hand-coded.** `VALID_DNS_NAME_REGEX` runs on every DNS question and the
   dashed-quad check on every subdomain; both are two character classes and an anchor.
   `settings::is_valid_dns_name` / `is_dashed_quad` are asserted equal to the compiled patterns.
6. **`HashSet::insert(x.into())` on the hot path** in the DNS-exhaustion and web-scan trackers
   allocated an owned copy of the label on *every* packet just to discard it as a duplicate. Now
   `contains` first.
7. **Per-packet `Instant::now()` pair** for the `ns/packet` metric cost 56 ns — a metric consuming
   7% of the budget it reported. Sampled one packet in 64.
8. **`memmem::find` rebuilt its searcher on every call.** `perf` is unusable here
   (`perf_event_paranoid=4`), but callgrind is not, and it put **8% of the packet path** in
   `FinderBuilder::build_forward_with_ranker` — constructing the rare-byte heuristic, not
   searching. On a 169-byte HTTP payload that construction costs more than the search saves. The
   searchers for the fixed needles (`\r\n`, `\r\n\r\n`, ` HTTP/`, `\r\nHost:`,
   `\r\nUser-Agent:`, `\r\nContent-Type:`) are now built once in `Statics`. This is also the
   reason an earlier "switch header lookup to memmem" change produced no measurable gain — the
   profile explained what guessing had not.
9. **`String::from_utf8_lossy` on every TCP payload** was 4.5% of the packet path: it goes through
   `Utf8Chunks`, which is slower than `str::from_utf8`'s validator. Now the fast validator, with
   the lossy path kept only for genuinely invalid UTF-8.
10. **~20 allocations per HTTP request.** The method, the path, the destination address, the host,
   the request body, the web-scan segment, the candidate keys and the force-encoded path were all
   copied whether or not anything needed changing. They are borrowed now (`Cow`), and
   `build_checks` returns slices of the path rather than six fresh `String`s.

**What is left, measured, in order:**

* **DNS with a cold result cache: 1,453 ns vs 652 ns warm.** The largest remaining gap, and the
  obvious fix is a **measured dead end**: enlarging the result cache makes it *worse*, because a
  flood misses at any size and a bigger cache just makes each miss touch a colder structure. On a
  1M-query DGA flood — 1,000 entries: **1,554 ns**; 4,096: **1,704 ns**; 16,384: **2,004 ns**. The
  default stays at Python's 1,000; `DOMAIN_CACHE_ENTRIES` exists for hosts whose working set
  genuinely fits.
* **`str::split`/`find` with `char` patterns: 3.7%.** `CharSearcher` on short strings; some of
  these can become `memchr`.

**On the capture side, the sensor is already on the AF_PACKET fast path.** libpcap here is
1.10.4 *with TPACKET_V3*, so a live capture is served from an mmap'd `PACKET_RX_RING` and
`pcap_next_ex` hands back a pointer *into* that ring — there is no per-packet copy, and
`PACKET_FANOUT` is set on the ring's own socket. The "libpcap read: 179 ns, grows with packet
size" figure reported earlier is the **offline file reader**, which does copy; it says nothing
about live capture and has been withdrawn as a live-path claim. What remains live-side is the
per-packet FFI crossing and libpcap's block walking, which cannot be measured here without
`CAP_NET_RAW` — run the sensor on a real interface and read `ns/packet` and `pps` straight off its
own metrics line.

### Instruction counts, and why they are the metric

Wall-clock measurement on a developer machine is worthless once anything else is running: an
unrelated sandbox workload on this box doubled the *untouched* ICMP path from 101 ns to 202 ns and
made an unchanged DNS path look like a 2x regression. Callgrind counts **instructions retired**,
which no amount of CPU contention can perturb, so it is the metric used for the work below. (It
does not model cache-miss stalls, so it complements the timing numbers rather than replacing them.)

Per packet, excluding startup (measured by subtracting a one-packet run):

| path | instructions/packet | wall clock (idle box, median of 5, pinned) |
| --- | --- | --- |
| ICMP echo (the floor) | – | 101 ns |
| TCP SYN | **1,411** | 402 -> **302 ns** (-25%) |
| HTTP request | 7,023 -> **~5,200** | 752 -> **602 ns** (-20%) |
| DNS query, unique names | 10,505 -> **8,064** (-23%) | 1,453 -> **1,102 ns** (-24%) |
| DNS query, warm cache | – | 652 -> **452 ns** (-31%) |
| bulk TLS | – | 402 ns (unchanged) |
| 866-byte mixed replay | – | 552 ns |

The DNS reduction came from three findings, all of them leftovers from the Python shape of the code:

1. **The result cache cost more than the work it cached.** `LruMap::insert` alone was **15% of every
   instruction the sensor executed** — ~1,570 per packet: clone the key, evict the oldest (a hash
   remove), insert into the index (a hash insert), relink the slab. The computation it caches, a
   whitelist parent walk, costs about **2.4x less than that**. In Python the cached work was
   expensive enough that caching always won; in Rust it does not, and for traffic that never
   repeats a name the cache was strictly worse than no cache. Fixed with a doorkeeper
   (`LruMap::insert_if_seen_before`): a key is admitted only on its *second* sighting, so a DGA
   flood costs one array store instead of a full LRU insert while recurring names still get their
   hits. These are pure caches, so a skipped insert only means the verdict is recomputed.
2. **`dns::question` allocated a `String` per LABEL** through `from_utf8_lossy`, then a second one
   for the whole name via `to_lowercase()` — four or five allocations for every DNS question on the
   wire. Now lower-cased in place, with the lossy path kept for non-ASCII (which cannot pass
   `VALID_DNS_NAME_REGEX` anyway, so nothing observable changes).
3. **The whitelist parent walk** probes once per label level and almost always misses, so it got
   the same cache-resident negative prefilter as the trail store, plus `memchr` for the dot scan.

And the HTTP path, from its own profile:

6. **`request_line` was 17% of the HTTP path.** `line.matches(' ').count()` builds a pattern
   iterator and walks it, and `contains(" HTTP/")` was a second unindexed substring search. Both
   are now one byte loop plus the prebuilt searcher. (The `" HTTP/"` search still covers the whole
   line, not just the last field: Python's `line.count(' ') == 2 and " HTTP/" in line` accepts
   `"GET HTTP/1.1 x"`, and that is observable in the emitted trail.)
7. **`format!` was 11.6% of the HTTP path**, from two strings built on every request whether or not
   anything matched: `format!("{host}/")` and the `url` used only when a trail hits. The first now
   reuses the candidate buffer, the second is built lazily.

And the SYN path, from its own profile — 13% of it was in malloc/free:

4. **`_get_local_prefix()` support rendered every new source address to a `String` and hashed it
   with SipHash.** The prefix of an IPv4 address is its top 16 bits; it is now keyed natively and
   rendered only when the prefix is actually asked for (once per second at most).
5. **Every new `(src, dst)` accumulator key allocated a `HashSet`** to hold one or two ports. It is
   now a 12-entry inline array that only spills to a hash set past that. Every detection threshold
   (10) is below the inline capacity, so a scan is *recognised* before the set ever allocates.

Reproduce the profile with:

```
valgrind --tool=callgrind --cache-sim=no --callgrind-out-file=cg.out \
    sensor/target/release/maltrail-sensor -r <pcap> -c <conf> --offline -q
callgrind_annotate --auto=no cg.out
```

Use a SMALL trails file: with the real 1.5M-row set, trail loading dwarfs the packet path in the
profile and hides everything of interest.

Against `sensor.py`'s 16,689 ns/packet, a SYN is now ~37x faster, an HTTP request ~20x and the
mixed replay ~26x.

### 4d. Single-worker offline replay of a uniform load### 4d. Single-worker offline replay of a uniform load

Two further data points, measured by replaying a generated pcap through the release binary
end to end (libpcap + DLT + packet path + event output), reported by the sensor's own metrics:

| load | packets | ns/packet | packets/s |
| --- | --- | --- | --- |
| bulk TLS, 1454-byte frames (the fat-pipe shape) | 2,000,000 | 124 | 2,259,481 |
| DNS queries, a fresh domain every packet (cold cache, DGA-flood shape) | 2,519,040 | 493 | ~2,000,000 |

The bulk-TLS figure is the best case (the payload has no `HTTP/`, so the sensor stops early);
the cold-DNS figure is close to the worst case for a single protocol.

### 4e. Worker scaling (software path)

Same benchmark, N independent workers each with its own state — what `PACKET_FANOUT`
parallelises:

| workers | packets/s | Gbit/s (866-byte mix) | vs 1 worker |
| --- | --- | --- | --- |
| 1 | 1,687,991 | 11.69 | 1.00x |
| 2 | 3,209,627 | 22.24 | 1.90x |
| 4 | 5,379,436 | 37.27 | 3.19x |
| 8 | 8,552,231 | 59.25 | 5.07x |
| 16 | 10,165,773 | 70.43 | 6.02x |

Near-linear to 4 workers, then tapering as SMT threads share cores (8 physical cores; 8 workers
= 5.1x, 16 = 6.0x, which is what one expects once hyperthreads are the only capacity left).
Because workers share nothing mutable, the taper is hardware, not contention.

**These are software-path numbers.** Real capture adds NIC, driver and ring costs and must be
measured on the target hardware with `tools/fanout_check.py` plus the sensor's own
`capture_drops` / `if_drops` counters.

### 4f. Live capture and PACKET_FANOUT (measured)

`sudo python3 sensor/tools/fanout_check.py --interface lo --workers 4 --packets 20000`

| run | fanout | received | processed | per worker |
| --- | --- | --- | --- | --- |
| 1 worker (baseline) | disabled (single socket) | 20,000 | 20,000 | w0=20000 |
| 4 workers | enabled (group 61155, mode hash, defrag off) | 20,000 | 20,000 | w0=5018, w1=5025, w2=5047, w3=4910 |

* **Distributed:** all 4 workers received traffic, within 1.4% of an even split across 64
  flows — the kernel's flow hash is doing the work, and each flow stays on one worker.
* **Not duplicated:** the 4-worker total equals the 1-worker baseline exactly (ratio 1.00). With
  independent sockets instead of a fanout group this would have been ~4x the baseline, and every
  detection would have been reported four times.
* No packets lost relative to the baseline, and `capture_drops`/`if_drops` were zero.

### 4g. Memory

* Real 1.5M-trail store: **68.5 MB** resident (arena + index + native address tables + interned
  pairs), built in **1.2 s** while streaming the 73 MB CSV.
* Whole-process peak during a 300k-packet replay: **88 MB**.
* Per-worker state is bounded by construction: `SCAN_TRACK_PER_KEY` (1024) items per key,
  `SCAN_MAX_KEYS` (50,000) keys total, 1000-entry result caches, hour-bucketed NXDOMAIN counters
  pruned once per hour — all identical to `sensor.py`'s bounds.
* Steady-state allocation on the non-alerting path: none.

---

## 5. What was verified, and how

| requirement | status | evidence |
| --- | --- | --- |
| Behaviourally equivalent detections | **verified** | `tools/parity.py`: 36/36, 0 differences; 55 ported detection tests |
| Existing configuration format | **verified** | `read_config()` ported with its quirks; a test loads the repository's real `maltrail.conf` |
| Existing trail data, no new database | **verified** | `tests/trails.rs` loads the real 1.5M-trail CSV; native and text lookups cross-checked over 200k rows |
| Event format accepted by the Python server | **verified** | vectors generated from `core/log.py`; the parity harness compares complete log lines |
| Live Linux capture | **verified on real hardware** | `tools/fanout_check.py` opened live handles on `lo`, applied the BPF filter, captured 20,000/20,000 packets and shut down cleanly (this is also what exposed the shutdown bug in §2.3, now fixed) |
| `PACKET_FANOUT` multicore | **verified on real hardware** | `tools/fanout_check.py` on `lo`: 4 workers in one group, 20,000 packets distributed 5018/5025/5047/4910 and a 4-worker total identical to the 1-worker baseline (ratio 1.00) — see §4f |
| Offline pcap replay | **verified** | 36-case corpus, deterministic, multi-file |
| Detections against the REAL trail set | **verified** | `tools/gen_corpus.py --from-trails ~/.maltrail/trails.csv` samples real trails across 8 traffic shapes and replays them through both sensors: 1,600 sampled IOCs, **0 event differences in either direction** |
| Loader equivalence with `load_trails()` | **verified** | `tests/loader_parity.rs` against the real 1,505,265-row CSV: same accepted rows, same three fields per row, same distinct-key count, same wildcard alternation in group order |
| Trail refreshing | **verified** | `tests/trail_update.rs`: a missing file is built, a stale file is refreshed and the new IOC is then detected with its own info |
| No panics on malformed traffic | **verified** | ~200k fuzzed inputs per run + 6 `cargo-fuzz` targets; `catch_unwind` as a never-used net |
| Clean shutdown / resource release | **verified** | SIGTERM mid-replay: the sensor stopped after 2,519,040 of 4,000,000 packets, exited **90 ms** later, flushed condensed events and printed its final metrics (signal handler -> watcher -> worker -> bounded join -> summary) |
| Coexists with `sensor.py` | **verified** | separate binary, separate `LOG_DIR`, no shared state; the parity harness runs both |
| Reproducible benchmarks | **verified** | `cargo bench --bench hotpath`, `tools/bench_compare.py` |

---

## 6. Known limitations

1. **Rust startup is slower than a warm `sensor.py`** (1.18 s vs 0.20 s) and uses ~25 MB more
   RSS, because Python `mmap`s a prebuilt binary trail store while Rust parses the CSV. See
   §7.1.
1b. **802 ns/packet is not a good absolute number**, whatever the ratio to Python is. §4c
   decomposes it; §7.1–7.4 are the measured, ordered ways to bring it down. The honest summary is
   that the port is ~20x faster per packet than `sensor.py` and still leaves a large multiple on
   the table.
2. **Plugins were removed from Maltrail entirely** (both sensors, and the `plugins/` directory).
3. ~~**The condensed observable store (`meta.sqlite`) is not written.**~~ Written since the
   ROADMAP Gate 4.1 work: `src/meta.rs`, verified identical to `core/meta.py`'s output on all 36
   corpus cases by `tools/parity.py`.
4. **Trail updating runs Maltrail's own Python updater** (`tools/update_trails.py` →
   `core.update.update_trails()`), so the host needs `python3`. That is deliberate: a second
   implementation of feed handling would drift out of sync with the first, and the failure mode of
   drifting trail data is silent under-detection. If `python3` is unavailable the sensor keeps
   running and says so, loudly.
5. **Linux-only for fanout**; the rest is POSIX but untested elsewhere.
6. **`-r -` (stdin) is not supported.**
7. **The `USE_FAST_PREFILTER` admission tiers** (`FAST_ADMIT_LEVEL`, `FAST_ADMIT_ADAPTIVE`) have
   no equivalent — native parsing makes shedding unnecessary. The switch still enables the one
   *detection* the prefilter adds (TLS/QUIC SNI).
8. **Heuristic state is per worker**, exactly as it is per process in `sensor.py`. With N workers
   a scan spread across many targets can be split; `PACKET_FANOUT_HASH` keeps a single
   source→target scan on one worker. Use `CAPTURE_WORKERS 1` for single-worker semantics.
9. **`PACKET_FANOUT` was verified on `lo`**, not on a physical NIC. The kernel path is the same,
   but a real interface also exercises the driver, the NIC's own RSS queues and the ring under
   load. Re-run `tools/fanout_check.py --interface <nic>` on each deployment.
10. The full difference list, including the deliberate ones, is in `docs/COMPATIBILITY.md`.

---

## 6b. Third-party review findings

Two independent reviews of the port. What they found, and what was done:

| # | Finding | Status |
| --- | --- | --- |
| 1 | **`cargo test` was red in DEBUG**: `dns::question_type_class` overflowed on `start + 4` for a hostile `name_end`. Release wrapped silently; debug panicked. | **Fixed** (`checked_add` on both ends, plus the same in `first_a_record`'s RDATA slice). The real failure was in the process: `tools/check.sh` only ran `--release`, so overflow checks were never compiled in and the fuzz tests that exist to prove "never panics on arbitrary input" could not fire. `check.sh` now runs **both** profiles, debug first. |
| 2 | **`COMPATIBILITY.md` overstated `PACKET_FANOUT_HASH`**, claiming it was what `_src_hash` emulated "but better". | **Corrected.** Fanout hashes the flow; the scan heuristics count per source and a scan is many flows, so per-source evidence is diluted across workers by roughly the worker count. This matches `sensor.py`'s default (its own source comments the effect) but is a limitation, not an improvement. `CAPTURE_WORKERS 1` is now documented as the setting for undiluted per-source state, in both `COMPATIBILITY.md` and `INSTALL.md`. |
| 3 | **Event-log creation race**: `exists()` then `File::create` let two workers both find the file missing at a day boundary, and the second truncate the first's events. | **Fixed**: one atomic `OpenOptions::new().append(true).create(true).mode(0o644)`. Cannot truncate, and sets Python's mode without a second syscall. |
| 4 | **`maltrail_cache_hits_total` / `_misses_total` always exported 0**: incremented on the packet path, then hard-coded to zero in `MetricsSlot::snapshot`. | **Fixed** (atomics added, published, snapshotted) with a test that drives known hit/miss traffic and asserts the values survive the publish/snapshot round trip the endpoint reads through. A metric that is always zero is worse than no metric. |
| 5 | **Throttle eviction is O(`max_keys`)** per eviction once the table is full — attacker-influenced work on the capture thread. | **Attempted and reverted.** A `BTreeSet<(last_seen, key)>` index desynchronised from the key table (caught by `the_key_table_is_bounded_and_evictions_are_summarized`, which saw 9 keys with a cap of 8). Shipping a half-working throttle is worse than an O(n) eviction, so the scan stands and the reason is recorded at the call site. Still open. |
| 6 | **Repo hygiene**: build output and profiling artefacts untracked/shippable, `.codegraph/` not ignored. | **Fixed**: `.gitignore` covers `sensor/target/`, the fuzz corpus/artifacts, callgrind output and `.codegraph/`; the stray `out.txt` is deleted. **The tree is still uncommitted** — that needs the maintainer's decision on branch and message, not mine. |

### Round two

| Finding | Status |
| --- | --- |
| The write-atomicity comment was **factually wrong**: it justified interleave-safety with `PIPE_BUF`, which bounds atomic writes to *pipes*, not regular files — and `write_all` loops on a short write, so it was not "one write(2)" either. | **Fixed.** One explicit `write()`, a short write treated as an error rather than silently looping (a loop would split a record and let another worker's line land inside it), and the comment now states the property actually relied on: O_APPEND's atomic offset-plus-write, per system call. |
| No regression test for the log-creation race. | **Added**: 32 sinks barrier-synchronised on the first write to a shared directory; every record must appear exactly once and whole. Writing it surfaced my own misunderstanding — the first version shared one destination address, so the throttle's dst-side key suppressed 736 of 800 events and the test was measuring throttling, not the race. |
| No named regression test for the DNS overflow. | **Added**: `usize::MAX`, `MAX-1`, `MAX-4`, `MAX-5`, `MAX-6` against both `question_type_class` and `first_a_record`, plus a happy-path assertion so the guards cannot be "fixed" by breaking parsing. |
| **Throttle summaries never flush on a quiet interface.** Housekeeping passed `st.last_sec` — the packet clock — which stops advancing the moment traffic stops, so a burst that ends leaves its summary buffered until the next packet or shutdown. | **Fixed**: packet clock offline (a replay must stay deterministic), wall clock live (that is what "the window closed" means for a live sensor). |
| **`events_written` counted attempts, including failures** — an open failure, a write failure or a failed send all still incremented it. | **Fixed**: the counter is documented as attempts, and `log_write_errors` / `maltrail_local_log_errors_total` counts local-log failures. Non-zero means detections were produced and LOST, which is exactly the thing that must not be inferable only from a healthy-looking `events_written`. |
| `docs/REPORT.md` claimed 261 tests; the suite has 311, and the per-suite table was stale. | **Fixed**, and the counts were re-measured per suite rather than copied. |

### Round three

| Finding | Status |
| --- | --- |
| **`settings_gen.rs` can drift from `core/settings.py`.** The constants are generated and compiled in; the Python sensor reads them at runtime. Bump a threshold without regenerating and the two sensors silently disagree — and the parity harness *cannot* see it, because it compares two sensors that are each internally consistent. | **Fixed**: `tests/generated.rs` regenerates into a temp file, applies the same `rustfmt` pass `check.sh` applies, and requires byte-identical output — naming the first differing line, since "they differ" is not actionable at 26 kB. This closes a class of divergence no amount of parity testing could. |
| **`ip6_port` was the one native table still on SipHash.** | **Fixed**, along with the whitelist's `ip4`/`ip6` sets. The reviewer's argument is correct and worth stating: the HashDoS policy protects maps an attacker can *insert into*, and the trail store's key set is fixed when `trails.csv` loads. `exact` deliberately keeps the default hasher — it is the one whitelist structure whose *lookup* keys come off the wire. |

**On the suggestion to wrap the event log in `BufWriter` (finding #4): not done, and it would be wrong here.**
`BufWriter` flushes when its buffer fills, which happens mid-record — so a single event line would be
split across two `write(2)` calls. With several workers appending to one file that is exactly the
interleaving corruption the other reviewer's concurrent-first-write finding is about: another
worker's line can land inside the split. The two review findings conflict, and record atomicity
wins. The syscall reduction is still available, but it needs a buffer that only ever flushes on
**record boundaries** (accumulate whole lines; when the next line would overflow, write the whole
buffer, which by construction ends at a boundary). That is the right shape and it is not yet built.

### Open, and agreed

* **`meta.sqlite` (`USE_CONDENSED_STORAGE`)** — both reviewers ranked this the top remaining feature gap, above plugins, because the default config has it on and the server's condensed views go dark. **Resolved** (ROADMAP 4.1): `src/meta.rs` writes the store, and `tools/parity.py` now diffs the two sensors' databases row for row alongside their event logs.
* **Worker-death exit status** — a worker that dies leaves the process able to exit 0, so `Restart=on-failure` will not restart it. Workers should return a typed result and live-capture loss should be a non-zero exit.
* **Multi-`-r` semantics** — the binary gives each pcap its own worker and state; `tests/replay.rs` describes shared state and exercises the harness, not the binary. One of the two has to change.
* **systemd first-start bootstrap** — `ProtectHome=yes` plus a `$HOME`-derived default `TRAILS_FILE` plus `ExecStartPre=-T` requiring trails is a deadlock on a fresh install. Needs `StateDirectory=` and an explicit `/var/lib/maltrail` trail path.
* **Fail closed on an empty trail set**, bounded caps + saturation metrics for every network-influenced map, `-T` range validation, buffered event writes, a `settings_gen.rs` freshness test, and `ip6_port` on the fast hasher (its key set is fixed at load, so there is no HashDoS exposure to protect).

## 6c. Road to default

The sequenced plan for making this Maltrail's standard sensor — gates, exit criteria and open
blockers — is in [`docs/ROADMAP.md`](ROADMAP.md). Performance work is deliberately queued *behind*
the correctness and release-engineering gates.

## 7. Recommended next optimization steps

In the order I would do them.

### 7.1 Binary trail store (biggest win, and it removes the only regression)

Startup and RSS are the two places `sensor.py` currently wins, and both come from
`core/trailsbin.py`. Build the same idea for Rust: serialise the finished tables (arena + index
+ native maps + interned pairs) to a file next to `trails.csv`, `mmap` it read-only, and rebuild
only when the CSV is newer. Expected: startup 1.18 s → ~10 ms, RSS 88 MB → ~25 MB plus shared
file-backed pages, and reloads become near-free. It also makes several sensors on one host share
one physical copy. Reuse `trails.csv.bin` if a format-compatible reader is worth writing;
otherwise a `.rsbin` sidecar keeps the two independent.

### 7.2 Profile and trim the HTTP path

§4c puts the packet path at 618 ns/packet on the 866-byte mix (424 ns without heuristics). Of the
heuristic half, the HTTP battery is the largest single item. The path is dominated by HTTP: lowercasing, `unquote` on the path
and body, and building the `checks` candidate list all allocate. Since only ~10% of packets are
HTTP requests, this is where the remaining single-core headroom is. Concretely: build the
candidate keys into one reusable buffer instead of a `Vec<String>`, decode percent-escapes only
when a `%` is present (already done) *and* only into a scratch buffer, and lowercase in place.
Measure first — `perf record` on the `process_packet (mixed traffic)` benchmark.

### 7.3 Aho-Corasick for the suspicious-request regexes

`SUSPICIOUS_HTTP_REQUEST_REGEXES` is scanned in order until one matches. A single
`RegexSet` (or an Aho-Corasick prefilter over the literal fragments each pattern requires) would
replace up to 13 passes with one. Careful: the *first matching description in list order* is
part of the output, so a `RegexSet` result must be reduced back to the lowest matching index.

### 7.4 Batched capture — bigger than it looks

**Measured: `next_packet()` is 179 ns/packet, 22% of the 802 ns budget** on 866-byte packets
(§4c), and it grows with packet size because libpcap copies each packet. That makes it the
second-largest item after the detection path itself, not the "single-digit percent" I assumed
before measuring.

`pcap_dispatch` with a callback amortises the per-packet FFI crossing and lets libpcap hand out
packets from its mmap ring in blocks. If the copy itself dominates, the next step is reading the
TPACKET ring directly (deliberately out of scope for v1, and only worth it behind the existing
`Handle` abstraction so the offline path stays identical).

### 7.5 Then, and only then, the exotic options

Only after the above are measured: a Bloom/XOR **negative prefilter** in front of the domain
table (never as the authoritative structure — a false negative is a missed detection), an
`AF_XDP` backend behind the existing `Handle` abstraction, or explicit SIMD. None of these is
justified by the current profile: at 802 ns/packet and near-linear scaling to 4 workers, a
16-thread laptop already sustains ~10 Mpps of software packet path.

### 7.6 Operational follow-ups

* Re-run `tools/fanout_check.py` on each deployment's real interface (it was verified here on
  `lo`; a physical NIC exercises the driver and ring paths too).
* Consider exporting the metrics line as Prometheus text on a local socket — the counters and the
  aggregation already exist.
* Shadow-run against production traffic for a week and diff the daily logs before making the
  sensor the default (`docs/INSTALL.md` §8).
