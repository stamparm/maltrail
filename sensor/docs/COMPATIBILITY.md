# Compatibility status

Reference implementation: `sensor.py` + `core/` in this repository. "Verified" below means
covered by an automated test — either a Rust test, a shared vector generated from the Python
code (`tools/gen_vectors.py`), or the differential replay harness (`tools/parity.py`).

Last recorded parity result, on the then-36-case corpus: **36/36 cases, 0 event differences**
(`tools/parity.py`). See `docs/REPORT.md` for that run. The corpus is now 42 cases; five of them
(`udp_malware_dst`, `dns_same_socket_burst`, `trail_under_whitelist_parent`,
`tcp_periodic_beacon`, `tcp_malware_ja3`) pin the deliberate divergences in §2, differences
20-24, and are checked in **both** directions — the expected Rust-only event must be present,
and its absence fails the case. Run `python3 sensor/tools/parity.py` for the current result.

---

## 1. Fully compatible

### Configuration
* `maltrail.conf` is the only configuration source. `read_config()` is ported including its
  quirks: comment stripping before quote handling, array blocks, `USE_/SET_/CHECK_/ENABLE_/
  SHOW_/DISABLE_` prefixes coerced to booleans (with the same warning for a non-boolean value),
  digit strings coerced to ints, `$VAR` expansion from `core/settings.py` globals then the
  environment, `_DIR` values resolved against the repo root, `MALTRAIL_<NAME>` environment
  overrides, and `CAPTURE_BUFFER` accepting bytes / `kB|MB|GB` / `%` of physical memory rounded
  down to a whole ring block.
* Mandatory-option, `LOG_SERVER`, `SYSLOG_SERVER`, `LOGSTASH_SERVER`, `REMOTE_SEVERITY_REGEX`,
  `UPDATE_PERIOD`, `USER_WHITELIST` and `USER_IGNORELIST` validation, with the same messages.
* `USE_CONDENSED_STORAGE` defaults to on when the switch is absent (as `read_config()` does).
* Verified: `src/config.rs` tests, including one that loads the repository's real
  `maltrail.conf`.

### Condensed observable store

`USE_CONDENSED_STORAGE` writes `LOG_DIR/meta.sqlite` — one cumulative row per observable
(domain or address) with `first_seen`/`last_seen`/`count`, which is what the server's `/meta`
novelty and retro-hunt views read. `src/meta.rs` is a port of `core/meta.py`, and the file it
produces is byte-compatible with the one `sensor.py` produces:

* the same schema (`WITHOUT ROWID`, `PRIMARY KEY(observable)`, `meta_info.schema_version = 1`);
* the same key encoding — addresses as 4/16-byte BLOBs, domains as TEXT — which is what makes
  `core/meta.py:lookup()` find a row at all;
* the same `INSERT OR IGNORE` + `MIN`/`MAX`/`count +` merge, so several workers can drain into
  one file and a window flushed out of order still widens the interval correctly;
* rollback journal rather than WAL, and mode `0644`, so a non-root server can read a store the
  sensor wrote as root;
* the same junk filter (`0.0.0.0`, `255.255.255.255`, `::`, multicast), scope tagging, per-window
  key cap (`CONDENSED_MAX_WINDOW_KEYS`) and score-based `prune()` to `META_MAX_ROWS`.

The one structural difference is where the work happens: Python drains its aggregate from a
background thread per worker *process*, while each Rust worker drains its own on the
housekeeping tick it already runs — no extra thread, and nothing shared between workers.

* Verified: `tests/meta.rs` (schema, storage class, merge, junk filter, prune, failure
  handling) and `tools/parity.py`, which now replays every corpus case through both sensors with
  the store enabled and diffs the two databases row for row. `first_seen`/`last_seen` are
  excluded from that diff for the same reason the event timestamp field is — `sensor.py` stamps
  packets with `time.time()` on Python 3, so the two sensors are reading two different clocks.

### Trails

Trail **updating** works exactly as in `sensor.py:init():update_timer()`: `TRAILS_FILE` is
refreshed before the first load and every `UPDATE_PERIOD` thereafter, honouring `UPDATE_SERVER`,
`USE_FEED_UPDATES`, `DISABLED_FEEDS`, `IP_MINIMUM_FEEDS`, `CUSTOM_TRAILS_DIR` and `--offline`.
The update itself is **not reimplemented** — `tools/update_trails.py` is a thin wrapper around
Maltrail's own `core.update.update_trails()`, so there is exactly one trail-update mechanism in
the repository and both sensors use it. `DISABLE_TRAIL_UPDATES true` opts out (for hosts where
`trails.csv` is pushed in from elsewhere); the sensor then warns loudly when the file is older
than `UPDATE_PERIOD`, because a stale trails file looks perfectly healthy while quietly missing
every IOC added since it was written. Regression-tested end to end in `tests/trail_update.rs`.
* The existing `trails.csv` is read unchanged (`trail,info,reference`), with Python `csv`
  semantics for quoting, whitelisted trails dropped at load, `(info, reference)` pairs interned,
  and rows that do not produce exactly three fields skipped and counted.
* `build_trails_regex()`: only `(static)` trails matching `[\].][*+]|\[[a-z0-9_.\-]+\]` whose
  `re.escape()` differs from themselves, in CSV order, capped at 100 groups, with the matched
  group mapped back to the originating trail key.
* Verified: `tests/trails.rs` (including the operator's real 1.5M-trail file when present, and a
  cross-check that every canonical IP trail answers identically through the native and string
  lookup paths).

### Packet handling
* `DLT_OFFSETS` for this platform, the `DLT_RAW` / `DLT_PPP` / `DLT_NULL` special cases, one
  802.1Q tag skipped (QinQ dropped, exactly as in Python), IPv4/IPv6 EtherType gate.
* The unknown-datalink offset heuristic and its two-packets-agree learner.
* IPv4 (including IHL > 5), non-first fragments skipped, IPv6 with the Next Header taken as the
  protocol (extension headers deliberately *not* traversed, matching Python), TCP, UDP, ICMP and
  ICMPv6 echo-request gating, and the generic `IPPROTO_LUT` branch.
* Verified: `src/packet/*` tests, `tests/detection.rs`, `tests/replay.rs`.

### Detection
Every detection `sensor.py` can produce is ported, with the same trail text:

| detection | notes |
| --- | --- |
| IP / IP:port trails on TCP SYN | `IPORT` iff the `addr_port` key matched; `attacker` and off-web `parking site` suppression; the src-side `malware` suppression |
| IP trails on non-DNS UDP | `malware` suppression, `_last_logged_udp` gate |
| IP trails on ICMP / other protocols | echo-request only, `-` ports |
| DNS domain trails | exact, parent-domain bracketing, `.ip-adress.com` relation, `.onion.` gateways, wildcard-regex trails, the `[rd]ns/nf/mx/nic` and dynamic-DNS/free-web exclusions |
| DNS IP/IP:port trails | with the `(query)` annotation, PTR/AAAA excluded, class IN only |
| DNS response sinkhole / parked | A-record walk over compressed and uncompressed answer names |
| URL / path / host trails | the full `checks` candidate list, `(bracketing)` of the surrounding URL, the POST-body form |
| `host/` trails | |
| HTTP heuristics | sql injection, xml/php/ldap/xss/xxe/ssti injection, data leakage (with the `is_local` guard), config-file access, remote code execution, directory traversal, web scan, dns changer, direct-download extensions, suspicious path regexes, missing Host, proxy probe, IoT-malware direct-IP download |
| HTTP response heuristics | sinkhole banner, seized-domain `<title>` (only with a closing tag), suspicious content types |
| User-agent heuristic | `data/ua.txt` alternation, `WHITELIST_UA_REGEX`, the exact bracketing/escaping of the emitted trail |
| Forwarded-for | `CF-Connecting-IP` / `True-Client-IP` / `X-Forwarded-For` appended to `src_ip` |
| Port scanning | SYN plus the NULL/FIN/XMAS stealth flags, sliding window, once per (scanner, target) per window, whitelist-gated, ACK deliberately not counted |
| UDP scanning | |
| Infection scanning | `POTENTIAL_INFECTION_PORTS`, local-source prefix guard, `PORT` trail type |
| Web scanning | whitelist and internal↔internal guards |
| DNS exhaustion | 60-second window per domain, one alert per domain per window, DNSBL and local-lookup guards |
| Excessive NXDOMAIN | hour-bucketed counters with the hourly prune, wildcard and exact keys, `LOCAL_SUBDOMAIN_LOOKUPS` guard |
| DGA labels | entropy and consonant thresholds |
| Long domain | with `WHITELIST_LONG_DOMAIN_NAME_KEYWORDS` |
| TLS / QUIC SNI | gated on `USE_FAST_PREFILTER` + `FAST_FLOW_CUTOFF`, same as Python |

* `DISABLED_HEURISTICS`, `SCAN_WINDOW`, `CHECK_HOST_DOMAINS`, `CHECK_MISSING_HOST`,
  `USE_HEURISTICS` all behave identically.
* Bounded state: `SCAN_TRACK_PER_KEY` (1024) per key and `SCAN_MAX_KEYS` (50000) keys in total,
  with the total shared across the port-scan and infection accumulators because Python keeps
  both in one dict.

### Output
* Event line: `"<localtime>" <sensor> <src_ip> <src_port> <dst_ip> <dst_port> <proto> <type>
  <trail> <info> <reference>`, with `safe_value()` quoting (CR/LF flattened first, then
  space/quote quoting with doubled quotes) and the `value or '-'` fallback that turns an empty
  string *and a zero port* into `-`.
* Timestamps use `localtime_r` so they follow the same `TZ` and tzdata as Python's
  `time.localtime()`.
* Daily `YYYY-MM-DD.log` files created 0644, appended with one `write(2)` per event.
* `LOG_SERVER` datagram is `"<sec> <event line>"`; the UDP socket is created once per family and
  recreated once on a send error.
* CEF/syslog: same `CEF_FORMAT`, same header/extension escaping, the trails-file ctime as
  `signature_id` (refreshed at most every 5 minutes), the same severity mapping from
  `REMOTE_SEVERITY_REGEX` (look-around supported).
* Logstash JSON: same key order, same int-vs-string typing, `ensure_ascii`-style escaping.
* Condensing on `CONDENSE_ON_INFO_KEYWORDS` keyed by `(src_ip, trail)`, capped at
  `MAX_CONDENSED_EVENTS`, merging `src_port`/`dst_ip`/`dst_port`/`proto` into sorted
  comma-joined values, flushed on the `CONDENSED_EVENTS_FLUSH_PERIOD` and at exit.
* Log throttling by the `sec // PROCESS_COUNT` bucket, including the quirk that the first event
  of a bucket does not register itself.
* `IGNORE_EVENTS` rules and `IGNORE_EVENTS_REGEX` (matched against a CPython-compatible
  `repr()` of the event tuple; an invalid pattern warns once and is disabled rather than
  dropping every event).
* `error.log` with `single=`-style deduplication.
* Verified: `tests/vectors.rs` compares against vectors generated by calling the actual Python
  functions; `tests/detection.rs` asserts on real log lines.

### Console output
* `core/colorized.py` is ported in full (`src/colorized.rs`): the `[i]`/`[!]`/`[x]`/`[?]`/`[^]`
  marker colours, the banner and its URL, `Usage:`, single-quoted values, and — for `--console`
  event lines — the per-trail-type background colour, the greyed timestamp and parentheses, and
  the `malware`/`suspicious`/`malicious` severity colours.
* Colour is emitted only when stdout is a TTY (Python's `IS_TTY` check), so redirected output and
  the systemd journal stay plain. `NO_COLOR` also disables it.
* Verified byte-for-byte against `ColorizedStream` output in `tests/vectors.rs`
  (`tests/vectors/colorized.tsv`), including Python's quirk of wrapping an already-coloured
  `(malware)` a second time with the generic parenthesis rule.

### CLI
`-c`, `-r` (comma-separated and repeatable, plus the trailing-file behaviour), `-q/--quiet`,
`--console`, `--offline`, `--debug`, `--version`, `-h`. `-i` prints the same rename notice.

---

## 2. Deliberate differences

| # | Difference | Why | Impact |
| --- | --- | --- | --- |
| 1 | **Offline timestamps default to the pcap record time.** `sensor.py` on Python 3 substitutes wall-clock time for every packet (a `pcapy-ng` workaround at `sensor.py:1524`). | Using the real timestamp is correct, and is what live capture and Python 2 do. `core/testing.py` itself skips the counting heuristics offline on Python 3 for this reason. | The sensor detects the timing heuristics (port/UDP/web/infection scan) during offline replay, which `sensor.py` cannot. Burst suppression, the log-throttle bucket and the hourly resets also behave correctly instead of collapsing. Pass `--timestamps wallclock` for byte-comparable parity runs; `tools/parity.py` does this by default. |
| 2 | **Threads instead of processes; no `mmap` ring.** | Rust has no GIL, so the ring buffer, its two packet copies and the IPC all become unnecessary. | `CAPTURE_BUFFER` is parsed and validated (it is a mandatory option) but no longer allocates a ring; `CAPTURE_BUFFER_SIZE` sizes the libpcap ring instead. `PROCESS_COUNT` still drives the log-throttle bucket. |
| 3 | **`USE_CAPTURE_AFFINITY` / `_src_hash` are not implemented.** `PACKET_FANOUT_HASH` gives kernel-side **per-flow** affinity. | Per-flow affinity is strictly better than Python's *default*, which is per-packet round-robin across the worker pool. It is **not** what `_src_hash` did: that hashed the SOURCE only, keeping all of one host's evidence in one worker, and the kernel has no source-only fanout mode. | **The scan heuristics are per source, and a scan is many flows.** A scanner with incrementing ephemeral source ports lands on a different worker per probe, so with N workers a threshold of `PORT_SCANNING_THRESHOLD` effectively needs ~N x more probes before any single worker trips. The same dilution applies to infection scanning, UDP scanning, per-domain DNS-exhaustion counters and NXDOMAIN hour counters. This matches `sensor.py`'s default (see its own comment at `sensor.py:1535`), but it is a real limitation, not an improvement. **This is why `CAPTURE_WORKERS` defaults to 1** (fanout is skipped entirely at one worker, giving undiluted per-source state); it is not derived from `PROCESS_COUNT`, and scaling out is an explicit opt-in via `CAPTURE_FANOUT`/`CAPTURE_WORKERS`. **Measured**, replaying the whole corpus with flow-hashed distribution (`tests/multi_worker_parity.rs`): of the heuristic alerts a single worker raises, **91% survive at 2 workers, 86% at 4, 65% at 8**. Exact trail detection is a stateless per-packet decision and is **identical at every worker count** — the same test asserts that no IOC detection is ever lost or invented by fanout. |
| 4 | **Fanout is mandatory when multiple workers are requested.** `sensor.py` logs a warning and falls back to one socket. | A silent fallback to N independent sockets would deliver every packet N times. | The sensor exits with an explanatory message instead of starting in a duplicating configuration. |
| 5 | **NXDOMAIN name bundles are sorted.** Python joins a `set`, so its order is arbitrary *and varies between runs* (string hashing is randomised per process). | Determinism. | The trail text `(a,b,c).example.com` lists the same names in a stable order. `tools/parity.py` sorts both sides before comparing — the only value-level normalisation it performs. |
| 6 | **Condensing never loses a flush on mixed field types.** Python's `sorted()` raises `TypeError` when a condensed field set mixes an int port with the `'-'` of an ICMP event, which kills the whole flush in the condensing thread. | Not crashing. | Such records are emitted (with `-` sorting before numbers) instead of being dropped. |
| 7 | **Scan-detail selection is deterministic.** Python takes an arbitrary element from a `set` (`next(iter(...))` / `.pop()`) for the reported ports and timestamps. | Determinism. | The first observed detail is reported. Same detection, stable fields. |
| 8 | **Sweep event ordering.** Python iterates one dict holding both port-scan and infection keys, so those events interleave in insertion order. | Two typed accumulators are clearer and cheaper. | Within one sweep, port-scan events precede infection events. Same events, different order. Parity comparison is order-insensitive. |
| 9 | **Wildcard trails needing look-around use a backtracking engine.** | The `regex` crate cannot express look-around/backreferences, which CPython accepts; dropping such a trail would silently lose a live indicator. | Identical trail set. `fancy-regex` has a backtrack limit and returns "no match" instead of hanging on a pathological pattern, so it is safer than CPython here. `tests/vectors.rs` asserts the accept/reject decision matches CPython for every wildcard trail in the real feed set. |
| 10 | **Result caches are separate per kind** instead of sharing one 1000-entry `LRUDict`. | Type-safe and faster. | Cached values are pure functions of their keys, so eviction differences cannot change a detection — only how often it is recomputed. |
| 11 | **`ord(b"")`-style Python errors do not reach `error.log`.** A zero-length ICMP body makes `sensor.py` raise `TypeError` into its blanket handler and log an "unhandled exception". | It is a malformed packet, not a bug. | Fewer spurious error-log lines. No detection change. |
| 12 | **Wildcard trails truncated in the feed are repaired instead of dropped.** Real trail feeds ship patterns cut off mid-alternation (`\b[a-z0-9]{1,3}\-(aegin\|...\|nzpost\|b`). CPython cannot compile those, so `build_trails_regex()` discards the whole indicator. | Losing a live IOC to a transport truncation is worse than salvaging it. The repair keeps every complete alternative and **drops the dangling fragment** — keeping `\|b` would leave a one-character alternative matching far more than the feed intended, i.e. a naive repair would manufacture false positives. | The sensor matches these trails where `sensor.py` ignores them (2 such patterns in the current feed). Reported at startup as `[i] repaired N wildcard trail pattern(s) truncated in the feed`; only genuinely unsalvageable patterns produce a `[!]`. Unit-tested in `src/trails/regexset.rs`. |
| 13 | **`-r` accepts any existing path, not just a regular file.** `sensor.py` uses `os.path.isfile()`. | A FIFO is a legitimate replay source (it lets traffic be streamed into the sensor). | `-r /path/to/fifo` works. A non-existent path still fails with the same message. |
| 14 | **Event-log throttling is a redesign, not a port** (`EVENT_THROTTLE_MODE`, default `summarize`). `core/log.py` suppresses with `sec // PROCESS_COUNT`: the window length is the machine's core count, exactly *two* events per bucket get through (a bucket change resets the seen-set without recording the current pair — an invisible off-by-one), and everything suppressed is discarded without trace. | Those three properties are hard to defend as intended: the same traffic logs differently on different hardware, and a burst is indistinguishable from a trickle. The replacement is standard alert suppression (Suricata `threshold type both`, Snort `event_filter`, Zeek `suppress_for`): write the first `EVENT_THROTTLE_BURST` (3) events per `(ip, trail)` per `EVENT_THROTTLE_WINDOW` (60 s) immediately, hold the rest, then emit **one aggregated line** when the window closes — using Maltrail's own idiom from `flush_condensed_events()`, so the varying fields become comma-joined lists *in place* and the line still has its eleven columns. | A hundred lookups of one malware domain produce 3 immediate lines plus one summary naming every source port, instead of "however many the core count allows". Nothing is silently dropped: `metrics` reports `throttled=` and `summarized=`. `EVENT_THROTTLE_MODE legacy` restores `core/log.py` byte for byte (quirks included) and is what `tools/parity.py` runs; `off` disables throttling. Verified against `core/log.py` itself in `src/throttle.rs` (10 lines for PROCESS_COUNT 1, 4 for PROCESS_COUNT 16, on the same 100-event input). A flood longer than the held-buffer cap (`MAX_CONDENSED_EVENTS`, 1000) appends `(+N more)` to the summary info, so 5000 hits no longer read as 1000 — Python's condenser silently discards past its own cap (`core/log.py:282`), which this does not reproduce. |
| 15 | **One capture worker by default, and the count is not derived from `PROCESS_COUNT`.** `CAPTURE_WORKERS` falls back to `CAPTURE_FANOUT`, which is commented out in the shipped `maltrail.conf` — so a stock install runs a single worker. | Deriving it from `PROCESS_COUNT` (16 in the shipped config) was tried and reverted. That reasoning was about log *volume* under `EVENT_THROTTLE_MODE legacy`, whose throttle keeps state per worker; the default `summarize` mode aggregates suppressed events instead of discarding them, so nothing goes missing at one worker. Against that, 16 workers cost measured scan-heuristic sensitivity (difference 3) for throughput a single worker already has. | Scaling out is an explicit opt-in via `CAPTURE_FANOUT` or `CAPTURE_WORKERS`; `auto` uses the CPU count. If the kernel refuses `PACKET_FANOUT` for the device, the sensor drops to a single worker with a loud warning rather than opening N duplicating sockets. Locked by `config::tests::worker_count_is_opt_in`. |
| 16 | **No root requirement.** `sensor.py` refuses to start unless `geteuid() == 0`, including for offline pcap replay. | That test asks the wrong question twice over: replaying a file needs no privileges at all, and a capture process should run under capabilities rather than as root. | The sensor checks for `CAP_NET_RAW` (granted by `setcap`, an ambient set, or being root), skips the check entirely for `-r`, and prints the exact `setcap` command when it is missing. `DISABLE_CHECK_SUDO` still works. The shipped systemd unit runs as an unprivileged user with two ambient capabilities. |
| 17 | **`-T` / `--test-config`** validates a deployment and exits, like `suricata -T`. | `sensor.py` has no equivalent: the only way to learn that `LOG_DIR` is unwritable, the trails file is months old or the BPF filter does not compile was to start capturing and watch. | New flag; no effect on detection. Used as `ExecStartPre=` in the systemd unit. |
| 18 | **TLS server certificates are matched against the trail set by SHA-1 fingerprint** (`CHECK_TLS_CERTIFICATES`, default on; new `CERT` trail type). `core/tls_intel.py` parses certificates for the reporting side, but `sensor.py` never matches them, so this detects strictly more. | A certificate outlives the address and the domain in front of it — re-keying costs a C2 operator more than re-registering — so a fingerprint keeps matching after the other indicators have rotated. abuse.ch SSLBL publishes ~10,000 and is still adding ~2,000 a year, which is only possible because these handshakes remain observable. | Findings are rated `suspicious` (medium), not malware, because a small share of listings are dual-use remote-administration tooling. Matches TLS 1.2 and below (1.3 encrypts the certificate) and only when the flight fits one segment, since the sensor does no stream reassembly — both of which hold for the self-signed single-certificate servers these fingerprints identify. `tools/parity.py` sets the option false, since the comparison is only meaningful for behaviour both sensors have. The shipped `CAPTURE_FILTER` admits TLS handshake records on 443 for this — handshakes only, never bulk TLS; drop that clause to opt out of the capture cost. |
| 19 | **CPU affinity (`schedtool`) is not set.** | `DISABLE_CPU_AFFINITY` exists because the Python heuristic caused load problems, and with kernel fanout the kernel already spreads work. | Pin with `taskset`/systemd `CPUAffinity=` if wanted. |
| 20 | **A UDP datagram *to* a listed address is reported.** `old/sensor.py:880` collapsed the dst-side and src-side matches into one `trail` and then applied the src-side `"malware"` suppression to whichever had matched, so every non-DNS UDP flow to a known malware/C2 address produced nothing at all. | The TCP path in the same file never did this: it suppresses `attacker` on the dst side and `malware` only on the src side. A datagram *to* a listed host is the detection worth having; a datagram *from* one is usually backscatter. The oracle is retired, not a specification. | The sensor emits where `sensor.py` was silent. The src-side rule is unchanged, so backscatter stays suppressed. Pinned by corpus case `udp_malware_dst` and by three named tests in `tests/detection.rs`. |
| 21 | **Two different DNS queries on one socket in one second are both examined.** `old/sensor.py:863` compared only the 5-tuple and the second, and the check ran *before* the DNS parser, so the second datagram was never parsed. | A stub resolver walking its `search` list, a retry, or a forwarder multiplexing two clients upstream all reuse the socket, so the discarded datagram carries a different name than the one examined — silent detection loss, not deduplication. | A digest of the payload prefix is mixed into the comparison, so a byte-for-byte repeat (a genuine retransmit) is still skipped. Pinned by corpus case `dns_same_socket_burst` and by two named tests in `tests/detection.rs`. |
| 22 | **An exact static trail beats its whitelisted parent** (longest-match wins). `sensor.py` checks whitelist ancestry *before* trails, so `evil.evil.googleusercontent.com` listed as a trail still goes silent because some `*.googleusercontent.com`-style ancestor entry matches first. | A feed listing an exact name under a big platform domain is by construction more specific than the platform blanket — shadowing it turns 3,082 shipped trails (676 under cloudfront.net, 491 under amazonaws.com, ...) into dead entries. Precedence follows specificity: the exact trail fires when it has MORE labels than the closest whitelisted ancestor; on a tie or an exact whitelist hit, the whitelist wins. Conservative scope: wildcard/regexset trails and ALL heuristics stay fully suppressed by any whitelisted ancestor, so nothing broad starts firing inside whitelisted platforms. | The sensor detects where `sensor.py` was blind. Pinned by corpus case `trail_under_whitelist_parent` (`expect_rust_only`) and seven tests in `tests/detection.rs`. The Python sensor remains the parity oracle for everything else; see DELIBERATE DIVERGENCES in `tools/parity.py`. |
| 23 | **New `beaconing` heuristic with no `sensor.py` counterpart.** The retired Python sensor has no notion of traffic regularity, so a low-and-slow C2 channel reconnecting on a timer under every volume threshold was invisible to it. | The Rust sensor tracks per-(src, dst, dst_port) TCP SYN inter-arrival gaps and fires once per flow when the coefficient of variation drops to a timer-like level: ≥ 8 gaps, CV ≤ 0.2, interval in [5 s, 6 h]. Sub-5 s retries never advance the clock (a retry storm cannot manufacture regularity); an outage longer than 6 h resets the history. False-positive honesty: uptime monitors and mail pollers ARE beacons, so every event is rated `potential periodic beaconing (suspicious)` with a `(heuristic)` reference, never `malware`. Both endpoints are whitelist-checked, so a single noisy poller is silenced by whitelisting the address it beacons to rather than the local host. State is bounded (`HEURISTIC_MAX_KEYS` refusals counted in `state_saturations`, hourly prune of flows silent > 24 h). | The sensor detects what `sensor.py` could not. Silenced per-name with `DISABLED_HEURISTICS beaconing`; pinned by corpus case `tcp_periodic_beacon` (`expect_rust_only`) and three tests in `tests/detection.rs` plus six unit tests in `heuristics/beacon.rs`. See DELIBERATE DIVERGENCES in `tools/parity.py`. |

---

## 3. Not implemented

| Feature | Status | Guidance |
| --- | --- | --- |
| **`USE_FAST_PREFILTER` admission control** (`FAST_ADMIT_LEVEL`, `FAST_ADMIT_ADAPTIVE`) | Not implemented; the switch only enables SNI extraction. | The prefilter exists to keep packets out of Python. Native parsing makes load-shedding unnecessary; if a link still saturates, add capture workers. |
| **`core/trailsbin.py` mmap trail store** | Not needed. | One shared `Arc<TrailDb>` serves every worker thread; there are no worker processes to share a file mapping with. |
| **Windows / WinPcap** | Not supported. | The sensor is Linux-first (fanout is Linux-only); the code is otherwise POSIX and would need a build/test pass for other platforms. |
| **`-r -` (pcap on stdin)** | Not supported. | Use a named file or a FIFO path. |

---

## 4. Known edge cases

These are places where the port reproduces Python behaviour that may look wrong, or where a
difference is possible but unproven:

1. **IPv6 rendering is not RFC 5952.** `core/addr.py:compress_ipv6()` collapses the *last*
   longest zero run and strips leading zeros with a regex, so `::` renders as `::0` and
   `1:0:0:2:0:0:0:3` renders as `1:0:0:2::3`. Reproduced exactly, including the `0+`
   backtracking needed for a trailing all-zero group. IPv6 trail keys must be written in that
   same form to match — which is equally true of `sensor.py`.
2. **DNS question parsing ignores compression pointers.** A `0xc0` label-length byte is treated
   as a 192-byte label, matching Python. Such queries fail `VALID_DNS_NAME_REGEX` and are
   dropped on both sides.
3. **`.example`, `.local`, `.test`, `.arpa`, … are in `IGNORE_DNS_QUERY_SUFFIXES`**, so a DNS
   query for such a name is dropped before any trail check. Easy to trip over when writing test
   traffic (`tests/detection.rs` locks this in).
4. **HTTP headers are matched case-sensitively** against `"\r\nHost:"` etc., and a header whose
   terminating CRLF was cut off by the snap length is skipped. Both match Python.
5. **`SNAP_LEN` (2000) truncation** is applied to offline records too, so a `-s 0` capture is
   analysed on the same bytes live capture would have seen.
6. **A wildcard trail declaring a group named `g<digits>`** is refused, because those names
   identify which trail matched inside the combined alternation. CPython would accept the
   individual pattern but then fail to compile the combined one at first use.
7. **Two wildcard trails in the current real feed set are truncated** (unbalanced groups).
   CPython rejects them outright; the sensor repairs and matches them (deliberate
   difference 12). Both the repaired count and any unsalvageable pattern are reported at startup.
8. **`_last_syn` / `_last_udp` burst suppression is a single global slot**, not per flow: two
   interleaved flows within one second do not suppress each other, but a repeat of the *same*
   5-tuple in the same second does. Reproduced exactly.
9. **Per-worker heuristic state.** With N workers, scan counters are per worker, exactly as they
   are per process in `sensor.py`. `PACKET_FANOUT_HASH` keeps a flow on one worker, so a scan
   from one source to one target lands on one worker; a scan spread across many targets can
   still be split, and each worker needs to cross the threshold on its own. Set
   `CAPTURE_WORKERS 1` for single-worker semantics.
10. **Log-file interleaving.** Multiple workers append to the same daily file with one `write(2)`
    per event; `O_APPEND` writes of this size are atomic, so lines never interleave mid-record,
    but the ordering between workers is not deterministic.
