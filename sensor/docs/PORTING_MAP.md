# Maltrail sensor — porting map


> **Historical.** The retired Python sensor (`old/`) and the differential harness built around it
> — `tools/parity.py`, `tools/shadow_run.sh`, `tools/shadow_diff.py`, `tools/bench_compare.py` —
> were removed in 3.3, three releases after the cutover. Commands and results below that reference
> them record what was measured at the time; they are not runnable now. The corpus itself survives
> and is asserted by `tests/replay.rs`, and the deliberate divergences are listed in
> `docs/COMPATIBILITY.md` §2.
>
> `core/fastfilter.py` went the same way after 3.3: it was glue for the pcapy-ng in-C prefilter,
> and once the Python sensor was gone nothing imported it but its own unit test. Rows and code
> comments below still name it, and `sensor.py`, as the Python source each Rust module was ported
> from. Those names are provenance, not paths you can open - read them against git history.
>
> `core/parallel.py` went with them, for the reason the rows below give: the sensor uses
> threads, so there is no mmap ring, no packet copy and no IPC to carry. Nothing imported it
> but its own unit test. `BLOCK_MARKER` (the ring's slot states) went too; `BLOCK_LENGTH`
> stays, because `CAPTURE_BUFFER` is still rounded down to a whole number of blocks and
> `src/config.rs` mirrors that.

Traced against this repository (not from memory). Every row names the Python source of truth and
the Rust module that reproduces it.

## Entry points and process model

| Python | Rust | Notes |
| --- | --- | --- |
| `the retired Python sensor, sensor.py:main()` (optparse: `-c -r -q --console --offline --debug --profile`) | `src/main.rs` | Same flags, plus `-T`. Plugins (`-p`) were removed from Maltrail entirely. |
| `sensor.py:init()` | `src/main.rs::init()` | Log dir, trail load, capture open, diagnostics. Trail *updating* (`core/update.py`) stays in Python. |
| `sensor.py:monitor()` + `packet_handler` | `src/capture/mod.rs`, `src/worker.rs` | Run-to-completion worker per capture handle. |
| `sensor.py:_init_multiprocessing()` + `core/parallel.py:worker()` (mmap ring, `PROCESS_COUNT` processes) | *dropped* — replaced by per-worker threads | No ring buffer, no packet copy, no IPC. `PROCESS_COUNT` is still read (it is part of the log-throttle bucket, `core/log.py:257`). |
| `sensor.py:_fanout_count()` | `src/config.rs::fanout_count()` | Identical parsing (`""`/`None`/`<=1` → off, `true`/`auto`/`yes`/`on` → CPU count, integer → N). |
| `sensor.py:_src_hash()` / `USE_CAPTURE_AFFINITY` | *dropped* | `PACKET_FANOUT_HASH` gives kernel-side flow affinity, which is what the Python hack emulates. |
| `core/fastfilter.py` + `USE_FAST_PREFILTER` (pcapy-ng `loop_filtered`) | `src/worker.rs` (`FAST_FLOW_CUTOFF` head/SNI logic) | The sensor always parses in native code, so the C prefilter is unnecessary. The one *detection* the prefilter adds — SNI on TLS/QUIC handshakes → `_check_domain` — is ported and gated on the same config switches. |
| `core/fastfilter.py:guess_ip_offset()` + `sensor.py:_guess_dlt_ip_offset()` | `src/packet/dlt.rs` | Same scoring heuristic and same two-packets-agree learner. |

## Configuration

| Python | Rust |
| --- | --- |
| `core/settings.py:read_config()` | `src/config.rs::read_config()` — array blocks, `USE_/SET_/CHECK_/ENABLE_/SHOW_/DISABLE_` booleans, digit→int, `$VAR` expansion from settings/env, `_DIR` realpath, `MALTRAIL_<NAME>` env override, `CAPTURE_BUFFER` bytes/`kB|MB|GB`/`%`. |
| `core/settings.py` module constants | `src/settings.rs` (thresholds, regex sources, keyword tuples, `DLT_OFFSETS`, `IPPROTO_LUT`, `LOCALHOST_IP`, …) |
| `read_whitelist()`, `read_ignorelist()`, `read_ua()` | `src/whitelist.rs`, `src/ignore.rs`, `src/settings.rs::build_suspicious_ua_regex()` |
| `read_worst_asn()`, `read_cdn_ranges()`, `read_bogon_ranges()` | *not needed* — sensor path never calls `worst_asns()`/`cdn_ip()`/`bogon_ip()` (server/UI only). |

## Trails

| Python | Rust |
| --- | --- |
| `core/common.py:load_trails()` (CSV, 3 columns, `check_whitelisted` filter) | `src/trails/loader.rs` |
| `core/common.py:build_trails_regex()` (named-group alternation of wildcard `(static)` trails, ≤100 groups) | `src/trails/regexset.rs` |
| `core/trailsdict.py:TrailsDict` (interned pairs, frozen hash array, mmap bin) | `src/trails/mod.rs::TrailDb` — interned `(info, reference)` pairs + one `HashMap<Box<str>, u32>` plus native side maps for IPv4 / IPv4:port / IPv6 / IPv6:port so hot-path IP lookups never format a string. |
| `core/common.py:check_whitelisted()` | `src/whitelist.rs::check_whitelisted()` |
| `core/trailsbin.py` (mmap binary store) | *not ported* — Rust holds one shared `Arc<TrailDb>` across all workers, so there is nothing to share between processes. |
| `core/parallel.py:worker()` reload timer / `sensor.py:update_timer()` | `src/trails/mod.rs::TrailStore` + reload thread; workers pick up a new `Arc` via one relaxed atomic load. |

## Packet path

| Python (`sensor.py`) | Rust |
| --- | --- |
| `packet_handler()` DLT/VLAN offset resolution | `src/packet/dlt.rs::ip_offset()` |
| `_process_packet()` IPv4/IPv6 header parse, fragment skip | `src/packet/ip.rs`, driven from `src/process.rs` |
| TCP header parse, `flags == 2` SYN path, stealth flags | `src/packet/tcp.rs`, `src/process.rs` |
| UDP header parse | `src/packet/udp.rs` |
| ICMP / ICMPv6 / other `IPPROTO_LUT` protocols | `src/process.rs::other_proto()` |
| HTTP response (`HTTP/` prefix): sinkhole regex, `<title>` seizure, `Content-Type` | `src/protocols/http.rs::response()` |
| HTTP request: request line, `Host`, proxy/CONNECT/absolute-URI, `User-Agent`, URL trail `checks`, XFF, suspicious path/post regexes, direct download | `src/protocols/http.rs::request()` |
| DNS query name decode + guards, DNS exhaustion, type/class gate | `src/protocols/dns.rs` |
| DNS response: A-record walk → sinkhole/parking, NXDOMAIN counters, entropy/consonant | `src/protocols/dns.rs` |
| `_check_domain()` | `src/process.rs::check_domain()` |
| `_check_domain_member()`, `_check_domain_whitelisted()` | `src/whitelist.rs` |
| `_get_local_prefix()` | `src/heuristics/mod.rs::local_prefix()` |
| `_scan_track()`, `_connect_src_dst`, `_path_src_dst`, `_udp_scan`, `_scan_alerted`… | `src/heuristics/scan.rs` |
| `_subdomains`, `_dns_exhausted_domains` | `src/heuristics/dns_exhaustion.rs` |
| `NO_SUCH_NAME_COUNTERS` + hourly prune | `src/heuristics/nxdomain.rs` |
| `_result_cache`, `_local_cache` (`core/datatype.py:LRUDict`) | `src/lru.rs` + `src/state.rs` |
| `_last_syn`, `_last_logged_syn`, `_last_udp`, `_last_logged_udp` | `src/state.rs::WorkerState` |
| `core/tls_intel.py:parse_client_hello()` (SNI only) | `src/protocols/tls.rs` |
| `core/quic_sni.py:extract_sni_from_quic_initial()` | `src/protocols/quic.rs` |

## Event output

| Python | Rust |
| --- | --- |
| `core/log.py:safe_value()` | `src/event.rs::safe_value()` |
| `core/log.py:log_event()` (whitelist gate, condensing, throttle bucket, line format) | `src/output.rs::log_event()` |
| `core/log.py:flush_condensed_events()` | `src/output.rs::CondenseBuffer` |
| `core/log.py:get_event_log_handle()` (daily file, localtime, 0644) | `src/output.rs::EventLog` |
| `core/log.py:_send_datagram()` / `_endpoint_address()` | `src/output.rs::Datagram` |
| CEF (`core/settings.py:CEF_FORMAT`, `_cef_escape`, `_trails_signature_id`) | `src/output.rs::cef_line()` |
| Logstash JSON (`OrderedDict` field order) | `src/output.rs::logstash_line()` |
| `core/ignore.py:ignore_event()` (rules + `IGNORE_EVENTS_REGEX` vs `repr(event_tuple)`) | `src/ignore.rs` (includes a Python-`repr`-compatible tuple renderer) |
| `core/log.py:log_error()` (`single=` dedup) | `src/output.rs::log_error()` |
| `core/meta.py` condensed observable store (`USE_CONDENSED_STORAGE`) | `src/meta.rs` |

## Tests

| Python | Rust |
| --- | --- |
| the retired Python suite | `tests/detection.rs` (same cases, same expected trails) |
| `tests/_pcapgen.py` | `tests/support/mod.rs` packet builders + `tools/gen_corpus.py` |
| `core/testing.py:detect_test()` | `tools/parity.py --corpus detect` (same traffic, same expectations, run through both sensors) |
| `tests/test_addr.py`, `test_common.py`, `test_datatype.py`, `test_ignore.py`, `test_log_condense.py`, `test_trailsdict.py`, `test_config.py` | `tests/trails.rs`, and `#[cfg(test)] mod tests` in `src/addr.rs`, `src/lru.rs`, `src/ignore.rs`, `src/output.rs`, `src/config.rs` |
| doctests in `core/addr.py`, `core/common.py`, `core/log.py`, `sensor.py` | ported as `#[test]` assertions with the same inputs/outputs |
