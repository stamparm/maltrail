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
| Speed | 26-55x lower per-packet cost than `sensor.py` depending on traffic; scales across cores where the old sensor's single capture process caps at ~2.6x from 8 processes |
| Operational surface | `-T` config test, capability-based privileges (no root), hardened systemd unit, SIGHUP reload, Prometheus endpoint, 1 s trail-refresh pickup |
| Upstream bugs found and fixed | 9, including silently-stale trails and a self-stopping sensor |

**Not yet true:** `meta.sqlite` is not written, multi-worker behaviour has never been
parity-tested, and Gate 1.5 (bounded state everywhere) and 1.6 (config range validation in `-T`)
are open. CI now runs the whole gate on every push and pull request.

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

### 1.5 Bounded state, everywhere **[R1]**

"Bounded" is claimed but not universally true: DNS-exhaustion, NXDOMAIN and condensed-output maps
can grow within their windows. Every network-influenced structure needs a hard cap, a documented
eviction policy, a saturation metric, and a degraded mode that still performs exact trail matching.

* **Test:** flood each structure past its cap; assert memory plateaus and exact IOC detection is
  unaffected.

### 1.6 Config range validation in `-T` **[R1]**

Zero snaplen, zero throttle window, zero caps, absurd worker counts, and integer narrowing on cast
all currently produce silent misbehaviour. `-T` should enforce typed bounds and print the
**effective clamped** configuration, including estimated capture-ring memory.

---

## Gate 2 — Prove it at scale, and in the field

*Single-worker parity does not prove multi-worker parity. That is the largest untested surface.*

**Exit criterion:** multi-worker parity runs clean, and a shadow deployment shows no Python-only
detections over a sustained period on real traffic.

### 2.1 Source affinity, or accept the dilution loudly **[R1][R2]**

`PACKET_FANOUT_HASH` splits by flow; the scan heuristics count per **source**, and a scan is many
flows. With N workers a threshold needs roughly N times more probes. The docs now say this honestly
(`COMPATIBILITY.md` §3), but the runtime is unchanged.

Options, in preference order:

1. **`PACKET_FANOUT_EBPF` with a source-address hash.** Attach a small eBPF program that hashes only
   the source address. This is the real fix and it keeps multi-core throughput.
2. **Sharded heuristic aggregation** — packet processing stays flow-affine, scan evidence is routed
   to a per-source shard. More invasive; also the right shape if TCP reassembly ever arrives.
3. **Ship as-is with `CAPTURE_WORKERS 1` documented for heuristic fidelity** (done) and a startup
   warning when workers > 1 *and* scan heuristics are enabled.

Do (3) now as a stopgap, (1) before default cutover.

### 2.2 Multi-worker parity coverage **[R2]**

The 36-case corpus is single-worker deterministic. Add a **set-comparison** mode: replay the corpus
with N workers and compare event *sets* against the 1-worker run. This is the only thing that can
catch dilution regressions.

* Plus a privileged live test: inject the same scan through 1 and N workers, require equivalent
  alerts.

### 2.3 Shadow deployment

Both sensors, same traffic, same trails, ≥7 days on a real gateway. Compare nightly:

* normalized event sets (target: **zero** Python-only detections),
* `capture_drops` / `if_drops` on both,
* RSS and CPU,
* state-saturation counters.

This is the gate that actually earns "production ready". Nothing above substitutes for it.

---

## Gate 3 — Release engineering

*Right now none of the above can be protected, because the code is not in version control.*

**Exit criterion:** `make release-check` is one command, CI runs it on every push, and it fails on
any regression including fixture drift.

### 3.1 Commit the tree **[R1][R2]** — *needs your decision*

~15k lines untracked. A `git clean -fdx` deletes the port; nothing is bisectable. Branch name and
commit granularity are yours to choose; I will not commit unasked.

### 3.2 CI **[R1][R2]**

A GitHub workflow running:

* exact **MSRV 1.74** (declared but never verified — only 1.76 has been proven),
* current stable: `fmt --check`, `clippy -D warnings`, **debug and release** test runs,
* strict parity + loader parity,
* regenerate all fixtures then `git diff --exit-code` (catches generator drift),
* scheduled: real-trail corpus parity, longer fuzzing, systemd container smoke test.

### 3.3 One-command release gate

`make release-check` = build + both test profiles + parity + loader parity + real-trail parity +
`bench_compare.py`. "Is this releasable" should be a command, not a ritual.

---

## Gate 4 — Feature parity for cutover

### 4.1 `meta.sqlite` **[R1][R2]** — the one real feature gap

`USE_CONDENSED_STORAGE` defaults **true**. A host that swaps sensors keeps its config, and the
server's condensed-observable and retro-hunt views go dark. The sensor warns at startup and in `-T`,
which is correct but not sufficient if this becomes the default sensor.

Implement as a **bounded, batched writer on its own thread** — SQLite must never touch a capture
worker. Same schema the server already reads.

**This is the deciding item for whether cutover is "drop-in".** Without it, cutover is a feature
regression for anyone using the default config.

### 4.2 Plugins — explicitly not supported

`-p` takes Python callables. Out of scope for 1.0; documented, and the sensor refuses clearly rather
than ignoring the flag. Operators who need plugins keep the old sensor.

---

## Gate 5 — Cutover

1. Default `maltrail-sensor.service` → this sensor **(done)**; `maltrail-sensor-old.service` retained.
2. Naming: "sensor" / "old sensor" throughout **(done)**.
3. Migration guide with the rollback step (`systemctl start maltrail-sensor-old`), a documented
   config-compatibility statement, and the one feature that requires the old sensor.
4. Keep the old sensor as the **differential oracle** indefinitely — the parity harness is only
   possible while it exists. It should never be deleted, only demoted.
5. Deprecation policy: announce, one release of overlap, then default-off but still shipped.

---

## Deferred deliberately

Performance work is **not** on the critical path — the port is already 26-55x faster than the thing
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

## Three decisions only you can make

1. **Commit strategy.** Branch name and granularity for ~15k lines. Everything in Gate 3 is blocked
   on this.
2. **Is `meta.sqlite` a cutover gate, or may the default sensor ship without it?** If the former, it
   moves ahead of Gate 2.
3. **Default worker count.** Throughput (`PROCESS_COUNT` workers, diluted scan heuristics — matching
   the old sensor's default behaviour) or fidelity (`CAPTURE_WORKERS 1`, single-core capture). The
   honest answer may be "throughput, until source-affine fanout lands".

---

## Suggested order

```
now      1.1 worker death   1.2 fail closed   1.3 multi-pcap   1.4 systemd   [Gate 1]
         3.1 commit  ->  3.2 CI                                              [unblocks everything]
next     1.5 bounded state  1.6 -T ranges     2.2 multi-worker parity
then     4.1 meta.sqlite    2.1 source affinity
finally  2.3 shadow deployment (>= 7 days)  ->  cutover
```

Gate 1 plus 3.1/3.2 is the honest minimum for "production ready" on a host you control. Gate 2.3 is
the minimum for "Maltrail's default sensor".
