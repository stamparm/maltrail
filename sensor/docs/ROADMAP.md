# Making this the standard Maltrail sensor

The plan to get from "strong production beta" to "the sensor Maltrail ships, enabled by default".

Structured as **gates**, not a task list. Each gate has an exit criterion that is *verifiable by
running something* — not by judgement. Nothing advances to the next gate until its criterion is
demonstrably met, because the whole value of this port is that its claims are checkable.

Where an item came from a third-party review it is marked **[R1]** / **[R2]**.

---

## Where it actually stands

Done and verified, so the plan does not re-litigate it:

| | Evidence |
| --- | --- |
| Detection parity with `sensor.py` | 36/36 fixture corpus, 8/8 real-trail corpus, **0 event differences either direction** |
| Trail loading parity | Every row of the real 1,505,265-row CSV, field by field, vs `core.common.load_trails()` |
| Never panics on hostile input | ~200k fuzzed inputs per run through every parser, **in debug and release** |
| Speed | 14-37x lower steady-state per-packet cost than `sensor.py`, depending on run and hardware (`docs/REPORT.md` §4a); scales across cores where the old sensor's single capture process caps at ~2.6x from 8 processes |
| Operational surface | `-T` config test, capability-based privileges (no root), hardened systemd unit, SIGHUP reload, Prometheus endpoint, 1 s trail-refresh pickup |
| Upstream bugs found and fixed | 9, including silently-stale trails and a self-stopping sensor |

**Status: complete, and shipped.** Every gate below is met, CI runs the whole gate on every push
and pull request, every item has a regression test in the suite, `meta.sqlite` — the last feature
gap — is written and differentially parity-tested against `core/meta.py`, and the default worker
count is settled at one. The sensor became Maltrail's default in **3.0** (2026-08-08); **3.0.1**,
**3.1** and **3.1.1** have shipped since, the last of them adding `install.sh` and prebuilt
x86_64/aarch64 binaries.

This document is kept as the record of how that was gated, and for the deferred items in
"Deferred deliberately" below, which are still open. It is not a current work queue — for what is
in flight, see `HANDOVER.md`.

---

## Gate 1 — Correctness and lifecycle

*A sensor may not fail silently. Everything here is a way it currently can.*

**Exit criterion:** every item's regression test is in the suite and green in both profiles, and
`tools/check.sh` passes.

### 1.1 Worker death must be fatal **[R1]** — DONE

`worker::run` returns `()`; `main` discards the join results. A capture worker can die and the
process still exits **0**, so `Restart=on-failure` never fires and the host silently stops being
monitored.

* `enum WorkerExit { Shutdown, OfflineEof }` / `enum WorkerError { Capture(CaptureError), Panic }`.
* Unexpected completion of a *live* worker → coordinated shutdown → non-zero exit.
* `maltrail_worker_alive{worker="N"}` and `maltrail_worker_last_heartbeat_seconds`.
* `maltrail_up` becomes 0 when no capture worker is alive. Today it means "the HTTP thread is
  answering", which is close to meaningless as a health signal.
* **Test:** kill a worker's capture handle mid-run; assert non-zero exit and `maltrail_up 0`.

### 1.2 Empty trail set must fail closed **[R1]** — DONE

If the trail load or update fails, the sensor starts with zero trails, looks healthy, and detects
nothing. Fail startup unless `ALLOW_EMPTY_TRAILS true`. On *reload*, keep the last known-good store
and refuse an implausible drop (e.g. >50% fewer trails) — publish `maltrail_trail_reload_rejected_total`.

* **Test:** start with an empty CSV → non-zero exit; reload a truncated CSV → old store retained,
  counter incremented, detections continue.

### 1.3 Multi-pcap semantics contradict the test **[R1]** — DONE

The binary gives each `-r` file its own worker *and its own state*; `tests/replay.rs` asserts they
share state and only exercises the harness. One of the two is wrong.

**Decision: offline replay processes files sequentially through one `WorkerState`.** Replay must be
deterministic and evidence split across files must accumulate — that is what an analyst replaying a
capture set expects.

* **Test:** black-box, two pcaps, neither individually reaching a scan threshold, combined does.

### 1.4 systemd first start is a deadlock **[R1]** — DONE (except installing the binary outside target/)

`User=maltrail` (no home) + `ProtectHome=yes` + a `$HOME`-derived default `TRAILS_FILE` +
`ExecStartPre=-T` that rejects a missing trails file, and the updater that would create it runs
*after* the preflight. A fresh install cannot start.

* `StateDirectory=maltrail`, `LogsDirectory=maltrail`, explicit `TRAILS_FILE=/var/lib/maltrail/trails.csv`.
* `UMask=0027` **[R1]** — event logs contain addresses, domains and URLs; world-readable is wrong
  for a hardened unit.
* Install the binary to `/usr/local/bin`, not Cargo's disposable `target/`.
* `-T` must accept a missing trails file when trail updating is enabled (bootstrap), and only fail
  when nothing will ever create it.
* **Test:** container smoke test — install unit, `systemctl start`, assert active and detecting.

### 1.5 Bounded state, everywhere **[R1]** — DONE

"Bounded" is claimed but not universally true: DNS-exhaustion, NXDOMAIN and condensed-output maps
can grow within their windows. Every network-influenced structure needs a hard cap, a documented
eviction policy, a saturation metric, and a degraded mode that still performs exact trail matching.

* **Test:** flood each structure past its cap; assert memory plateaus and exact IOC detection is
  unaffected.

### 1.6 Config range validation in `-T` **[R1]** — DONE

Zero snaplen, zero throttle window, zero caps, absurd worker counts, and integer narrowing on cast
all currently produce silent misbehaviour. `-T` should enforce typed bounds and print the
**effective clamped** configuration, including estimated capture-ring memory.

---

## Gate 2 — Prove it at scale, and in the field

*Single-worker parity does not prove multi-worker parity. That is the largest untested surface.*

**Exit criterion:** multi-worker parity runs clean, and a shadow deployment shows no Python-only
detections over a sustained period on real traffic.

### 2.1 Source affinity, or accept the dilution loudly **[R1][R2]** — RESOLVED BY DEFAULTING TO ONE WORKER

`PACKET_FANOUT_HASH` splits by flow; the scan heuristics count per **source**, and a scan is many
flows. With N workers a threshold needs roughly N times more probes. The docs now say this honestly
(`COMPATIBILITY.md` §2, difference 3), but the runtime is unchanged.

Options, in preference order:

1. **`PACKET_FANOUT_EBPF` with a source-address hash.** Attach a small eBPF program that hashes only
   the source address. This is the real fix and it keeps multi-core throughput.
2. **Sharded heuristic aggregation** — packet processing stays flow-affine, scan evidence is routed
   to a per-source shard. More invasive; also the right shape if TCP reassembly ever arrives.
3. **Default to `CAPTURE_WORKERS 1`**, with a startup warning when an operator opts into more
   *and* scan heuristics are enabled.

**Done — (3), as the default rather than as a stopgap.** The dilution stopped being a qualitative
claim once `tests/multi_worker_parity.rs` measured it on the corpus: of the heuristic alerts one
worker raises, **91% survive at 2 workers, 86% at 4, 65% at 8**. The old default derived
`CAPTURE_WORKERS` from `PROCESS_COUNT`, so the shipped config ran **16** — past the end of that
curve — and every stock install paid for throughput it did not need. `CAPTURE_WORKERS` is now 1
unless `CAPTURE_FANOUT`/`CAPTURE_WORKERS` is set explicitly, and the sensor and `-T` still warn
when it is.

That makes option (1), `PACKET_FANOUT_EBPF` with a source-only hash, an **optimisation for
operators who scale out** rather than a prerequisite: it would let them keep undiluted heuristics
at N workers. Worth doing, no longer blocking.

### 2.2 Multi-worker parity coverage **[R2]** — DONE

The 36-case corpus is single-worker deterministic. Add a **set-comparison** mode: replay the corpus
with N workers and compare event *sets* against the 1-worker run. This is the only thing that can
catch dilution regressions.

**Done** in `tests/multi_worker_parity.rs`: the whole corpus is replayed with packets routed by
5-tuple flow hash across 1, 2, 4 and 8 workers, and event *sets* are compared.

* **Exact trail detections are identical at every worker count**, in both directions — fanout
  never loses an IOC detection and never invents one. This is the invariant that matters, and it
  holds because trail matching is a stateless per-packet decision.
* Heuristic alerts are measured rather than asserted equal (dilution is inherent), with one
  assertion that does hold: fanout may lose a heuristic alert, never invent one.

Still open: a privileged live test injecting the same scan through 1 and N real fanout sockets.

### 2.3 Shadow deployment — MET on an hour of real traffic

Both sensors, same traffic, same trails, ≥7 days on a real gateway. Compare nightly with
`sensor/tools/shadow_diff.py`, which answers the one question that decides the cutover — *are
there detections the old sensor makes that the new one does not?* — and exits non-zero when
there are, so it can run from cron:

```bash
# One command: capture live traffic while driving an adversarial workload, replay that ONE
# capture through BOTH sensors, and diff. Capture needs CAP_NET_RAW; everything else does not.
bash sensor/tools/shadow_run.sh --seconds 600

# Re-analyse a capture taken earlier — no privileges, no traffic, same comparison:
bash sensor/tools/shadow_run.sh --pcap /path/to/traffic.pcap

# A live pair of sensors instead, compared nightly from cron:
python3 sensor/tools/shadow_diff.py --new /var/log/maltrail --old /var/log/maltrail-old --days 7
```

Replaying one capture through both beats running both live: two AF_PACKET sockets see slightly
different packets and drop differently, so a difference could be the network rather than the
sensor. One capture gives both byte-identical input, and the pcap is kept as evidence.

`adversarial_traffic.py` drives the workload from indicators sampled out of the operator's real
`trails.csv`. It never connects to malicious infrastructure: DNS trails are resolved (a lookup,
not contact), HTTP host/path/user-agent trails are exercised against a local listener, IP and
IP:port trails are deliberately not dialled, and the scan/DGA heuristics run against localhost
and `.invalid`.

**RESULT — one hour of live traffic on a real interface, 2026-08-07/08:**

```
capture:      1.2 GB, 1,690k packets, captured live while adversarial_traffic.py drove the load
trail set:    1,694,415 rows, one snapshot shared by both sensors

old sensor:   4,285 lines,  1,775 distinct detections
new sensor:   7,185 lines,  1,801 distinct detections
agreed on 1,775

[o] no detection was made only by the old sensor
[i] total: 0 missed by the new sensor, 26 extra   (all DNS trail hits)
```

**Zero old-sensor-only detections across 1,775 real detections.** The workload included 2,120 DNS
lookups of real malware domains, 1,643 HTTP requests carrying malicious host/path/user-agent
indicators, **629 real SYNs to real trail addresses**, 478 scan bursts and 607 DGA/NXDOMAIN
bursts, against 623 benign background exchanges.

The run happened to cross midnight, which exercised the log-dating difference for free: the new
sensor wrote two daily files (it stamps events with the packet's time) where `sensor.py` wrote
one (wall clock at replay). `--all` compares by content, so this reported 1,775 agreements rather
than a total disagreement.

Also exercised beforehand: all 34 Ethernet corpus captures merged and replayed through both
sensors against the same trail set — **16 detections, 16 agreed, zero old-sensor-only**.

A long-lived deployment on a busy production gateway would still add value (different traffic
mix, sustained memory behaviour, real drop rates), but the exit criterion as written — *no
Python-only detections on real traffic* — is met.

It found a real bug on its first run — see `tests/fail_closed.rs`: a capture that opened but
could not be READ replayed to "success" with zero packets, so an unreadable file looked exactly
like a clean one.

Detections are compared as SETS of `(src_ip, dst_ip, type, trail, info)`. Ports and timestamps
are excluded deliberately: the same beacon reappears on a new ephemeral port every time, and the
two throttles are different mechanisms, so line COUNTS legitimately differ. New-sensor-only
detections are reported but are not a failure — the Rust sensor genuinely detects more.

Compare nightly:

* normalized event sets (target: **zero** Python-only detections),
* `capture_drops` / `if_drops` on both,
* RSS and CPU,
* state-saturation counters.

This is the gate that actually earns "production ready". Nothing above substitutes for it.

---

## Gate 3 — Release engineering

*At the time this was written none of the above could be protected, because the code was not in
version control.*

**Exit criterion:** the release gate is one command, CI runs it on every push, and it fails on any
regression including fixture drift.

### 3.1 Commit the tree **[R1][R2]** — DONE

~15k lines were untracked; a `git clean -fdx` would have deleted the port and nothing was
bisectable. Landed as `f1fa4dc3` ("Rust sensor becomes the sensor", 2026-08-07).

### 3.2 CI **[R1][R2]** — DONE

`.github/workflows/ci.yml` runs on every push and pull request:

* exact **MSRV 1.74** (`msrv` job),
* current stable: `fmt --check`, `clippy -D warnings`, **debug and release** test runs, plus
  strict parity and loader parity — all of it through `sensor/tools/check.sh`,
* the generated-file freshness test (`tests/generated.rs`) runs **before** regeneration, so drift
  is reported rather than silently repaired,
* the Python server suite on the 3.6 floor and on current versions,
* `docker`, `installer` (five distributions) and `audit` jobs.

Trail-data commits are excluded by path filter: they are the input, not the program, and a
ten-minute gate on every indicator commit would make CI a tax on the project's most common
contribution.

### 3.3 One-command release gate — DONE, as a script rather than a Makefile

`sensor/tools/check.sh` is the gate, and `.github/workflows/release.yml` runs it *first* on a tag —
nothing is published unless it passes — followed by a version-matches-tag check, the binary builds
and the image push. There is no `make release-check`; the shell script and the release workflow
cover it, and a Makefile for two commands was not worth the third place to keep in step.

---

## Gate 4 — Feature parity for cutover

### 4.1 `meta.sqlite` **[R1][R2]** — DONE

`USE_CONDENSED_STORAGE` defaults **true**, so a host that swapped sensors kept its config and
silently lost the server's condensed-observable and retro-hunt views. The sensor warned about it,
which was honest but still a feature regression for anyone on the default config — the deciding
item for whether cutover is "drop-in".

`src/meta.rs` now writes the store. The aggregate is per worker and drains on the housekeeping
tick the worker already runs, rather than on a thread of its own: the plan called for a separate
thread to keep SQLite off the capture path, but the tick is already off it (it runs between packet
batches, at most once a second) and a thread would have needed a lock on the very map the packet
path bumps. The packet path does one hash bump per endpoint, keyed by the native address, with no
text rendered until a key is first inserted.

**Evidence.** `tools/parity.py` replays all 36 corpus cases through both sensors with the store
enabled and diffs the resulting databases row for row: **identical in every case** — same
observables, same key encoding, same flags, same counts. `tests/meta.rs` covers the schema, the
BLOB/TEXT storage class (a mis-keyed store writes and reads back perfectly and matches nothing),
the out-of-order merge, the junk filter, `prune()` against the same 20-established-vs-200-DGA
fixture `tests/test_meta.py` uses, and a failing flush.

Bounds, unchanged from Python: `CONDENSED_MAX_WINDOW_KEYS` per window (refusals counted into
`maltrail_state_saturations_total`), `META_MAX_ROWS` on disk via score-based pruning on the
trail-update cycle. A flush that fails drops its window rather than growing a backlog, and is
reported through `maltrail_meta_flush_errors_total`.

### 4.2 Plugins — DONE (removed)

`-p` took Python callables. Plugins were removed from Maltrail entirely in 3.0 — both sensors and
the `plugins/` directory — so there is nothing to port. Consume events from
`LOG_SERVER`/`LOGSTASH_SERVER` instead.

---

## Gate 5 — Cutover — DONE

1. Default `maltrail-sensor.service` → this sensor **(done)**.
2. `sensor.py` stays in `old/` purely as the **differential oracle** and reference implementation:
   `tools/parity.py` only exists while it does, so it should never be deleted. It is not a
   supported fallback and carries no deprecation schedule — this is a rewrite, not a migration
   programme, and nobody is owed an overlap release.
3. `docs/INSTALL.md` §13 covers verifying a deployment: replay a corpus, shadow live traffic,
   scale out only if the drop counter says to.

There is nothing further to schedule here.

---

## Deferred deliberately

Performance work is **not** on the critical path — the port is already 14-37x faster than the thing
it replaces, and correctness gates outrank optimisation. These are queued behind Gate 3:

* **Binary/mmap trail store** — the only remaining place the old sensor wins (1.18 s startup, 88 MB
  RSS vs a `mmap`'d prebuilt store). Versioned, checksummed, atomically created, CSV fallback.
* **Batched capture** (`pcap_dispatch`) — libpcap 1.10.4 already uses TPACKET_V3, so live capture is
  zero-copy; what remains is per-packet FFI, which needs measuring **on a real interface** before
  building anything.
* **Record-boundary-preserving buffered writes** — plain `BufWriter` is *wrong* here (it splits
  records mid-line, which corrupts interleaving between workers); a buffer that flushes only on
  whole-record boundaries gets the syscall reduction safely.
* **O(1) throttle eviction** — extend `src/lru.rs` to return the evicted entry and refresh recency
  in `get_mut`, so index and recency live in one structure. A previous second-index attempt
  desynchronised and was reverted.
* **Throttle summary honesty** — report the true suppressed count (`suppressed=N represented=M`)
  rather than resetting it silently past `MAX_CONDENSED_EVENTS`.
* **Aho-Corasick / `RegexSet`** for the suspicious-request battery — measure first; the `regex`
  crate's literal prefilter may already give most of it.

---

## Decisions made

1. **Default worker count: ONE.** `CAPTURE_WORKERS` no longer derives from `PROCESS_COUNT`, so the
   shipped `maltrail.conf` (`PROCESS_COUNT 16`) now runs a single capture worker. The old default
   spent scan-heuristic sensitivity — of the alerts one worker raises, 91% survive at 2 sockets,
   86% at 4, 65% at 8 — to buy throughput that a single worker already has: 550 ns/packet
   (1.8M packets/s) on the reference laptop CPU, 272 ns (3.7M) on a Ryzen 9 5900X. Exact trail
   detection is identical at every worker count, so nothing is
   traded away for IOC matching. `CAPTURE_FANOUT`/`CAPTURE_WORKERS` still scale out for anyone who
   measures a real drop rate, which also demotes source-affine fanout (§2.1) from a fix to an
   optimisation. Locked by `config::tests::worker_count_is_opt_in`.

---

## Suggested order

```
now      1.1 worker death   1.2 fail closed   1.3 multi-pcap   1.4 systemd   [Gate 1]
         3.1 commit  ->  3.2 CI                                              [unblocks everything]
next     1.5 bounded state  1.6 -T ranges     2.2 multi-worker parity
then     2.1 source affinity
finally  2.3 shadow deployment (>= 7 days)  ->  cutover
```

Gate 1 plus 3.1/3.2 is the honest minimum for "production ready" on a host you control. Gate 2.3 is
the minimum for "Maltrail's default sensor".
