//! Multi-worker parity (ROADMAP Gate 2.2).
//!
//! Every parity result so far is single-worker. In production the sensor runs N workers joined
//! to one `PACKET_FANOUT_HASH` group, and the kernel splits traffic **by flow** — so each worker
//! sees a slice of the packets and keeps its own detection state. That is the largest untested
//! surface in the port, and it splits cleanly in two:
//!
//!   * **Exact trail matching is per packet and stateless.** Which worker a packet lands on
//!     cannot change whether its IOC is detected. If it ever does, fanout is silently losing
//!     detections, which is the worst bug this project can have. Asserted here.
//!
//!   * **Counting heuristics are per source, and a scan is many flows.** Flow-hashing scatters
//!     one scanner's probes across workers, so each worker sees a fraction of the evidence and a
//!     threshold needs roughly N times more probes to trip. This is inherent to hashing by flow
//!     while counting by source (COMPATIBILITY.md §3). Measured and reported here rather than
//!     asserted, so a regression shows up as a number moving.
//!
//! The kernel's fanout hash is not reproduced bit for bit — what matters is the property it
//! guarantees and that this models: **all packets of one flow go to one worker**.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use maltrail_sensor::capture::Handle;
use maltrail_sensor::testkit::*;

fn corpus_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests").join("corpus")
}

fn corpus_trails() -> Vec<(String, String, String)> {
    let path = corpus_dir().join("trails.csv");
    let Ok(text) = std::fs::read_to_string(path) else { return Vec::new() };
    text.lines()
        .filter(|l| !l.is_empty())
        .filter_map(|l| {
            let mut it = l.splitn(3, ',');
            Some((it.next()?.to_string(), it.next()?.to_string(), it.next()?.to_string()))
        })
        .collect()
}

fn harness() -> Harness {
    let owned = corpus_trails();
    let borrowed: Vec<(&str, &str, &str)> =
        owned.iter().map(|(a, b, c)| (a.as_str(), b.as_str(), c.as_str())).collect();
    Harness::with_options(
        &borrowed,
        HarnessOptions {
            use_heuristics: true,
            check_host_domains: true,
            check_missing_host: true,
            // Throttling is per worker and would confuse a SET comparison with a rate question.
            // This test is about which detections exist, not how often they are written.
            extra: vec!["EVENT_THROTTLE_MODE off".to_string()],
        },
    )
}

/// Flow hash over the 5-tuple, mirroring what `PACKET_FANOUT_HASH` guarantees: every packet of a
/// flow lands on the same worker. `ip_offset` is where the IP header starts.
fn flow_worker(packet: &[u8], ip_offset: usize, workers: usize) -> usize {
    let Some(&first) = packet.get(ip_offset) else { return 0 };
    let mut key: Vec<u8> = Vec::with_capacity(40);
    let (proto, transport_off) = match first >> 4 {
        4 => {
            let ihl = ((first & 0x0f) as usize) * 4;
            if packet.len() < ip_offset + ihl.max(20) {
                return 0;
            }
            key.extend_from_slice(&packet[ip_offset + 12..ip_offset + 20]); // src+dst
            (packet[ip_offset + 9], ip_offset + ihl)
        }
        6 => {
            if packet.len() < ip_offset + 40 {
                return 0;
            }
            key.extend_from_slice(&packet[ip_offset + 8..ip_offset + 40]); // src+dst
            (packet[ip_offset + 6], ip_offset + 40)
        }
        _ => return 0,
    };
    key.push(proto);
    // Ports, for TCP (6) and UDP (17) — the kernel includes them, and including them here is
    // what actually scatters a scanner's probes.
    if matches!(proto, 6 | 17) && packet.len() >= transport_off + 4 {
        key.extend_from_slice(&packet[transport_off..transport_off + 4]);
    }
    fnv_worker(&key, workers)
}

/// FNV-1a: any stable hash will do; this only has to be deterministic and well mixed.
fn fnv_worker(key: &[u8], workers: usize) -> usize {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in key {
        h ^= u64::from(*b);
        h = h.wrapping_mul(0x1000_0000_01b3);
    }
    (h % workers as u64) as usize
}

/// Source-affine distribution: hash the SOURCE address and nothing else, so every packet a host
/// sends lands on one worker regardless of which flow it belongs to.
///
/// This is the property `PACKET_FANOUT_CBPF` buys, and the reason it matters is that the scan
/// heuristics count per SOURCE while `PACKET_FANOUT_HASH` splits per FLOW - a scanner walking
/// ephemeral source ports is a new flow every probe, so its evidence is scattered across every
/// worker and no single one reaches the threshold.
fn source_worker(packet: &[u8], ip_offset: usize, workers: usize) -> usize {
    let Some(&first) = packet.get(ip_offset) else { return 0 };
    let src = match first >> 4 {
        4 if packet.len() >= ip_offset + 20 => &packet[ip_offset + 12..ip_offset + 16],
        6 if packet.len() >= ip_offset + 40 => &packet[ip_offset + 8..ip_offset + 24],
        _ => return 0,
    };
    fnv_worker(src, workers)
}

/// One detection, identified by what it *is* rather than when it was written.
type EventKey = (String, String, String, String, String);

fn key_of(e: &LoggedEvent) -> EventKey {
    (e.src_ip.clone(), e.dst_ip.clone(), e.trail_type.clone(), e.trail.clone(), e.info.clone())
}

fn is_heuristic(e: &LoggedEvent) -> bool {
    e.reference == "(heuristic)"
}

struct Outcome {
    exact: BTreeSet<EventKey>,
    heuristic: BTreeSet<EventKey>,
}

/// Replay `pcap` across `workers` independent workers, distributed by `dist`.
fn replay_across_with(pcap: &Path, workers: usize, dist: fn(&[u8], usize, usize) -> usize) -> Outcome {
    let mut hs: Vec<Harness> = (0..workers).map(|_| harness()).collect();
    let mut handle = Handle::open_offline(pcap).expect("open corpus pcap");
    let datalink = handle.datalink();

    while let Ok(Some(captured)) = handle.next_packet() {
        let data = captured.data.to_vec();
        // Resolve the link-layer offset with worker 0's learner, then route by flow. (Every
        // worker sees the same link type, so resolving once is faithful.)
        let Some(offset) = hs[0].state.dlt.resolve(datalink, &data) else { continue };
        let idx = dist(&data, offset, workers);
        hs[idx].feed(&data, captured.sec, captured.usec, offset);
    }

    let mut exact = BTreeSet::new();
    let mut heuristic = BTreeSet::new();
    for h in hs.iter_mut() {
        h.state.sink.flush_condensed();
        h.state.sink.flush_throttled_all();
        for e in h.events() {
            if is_heuristic(&e) {
                heuristic.insert(key_of(&e));
            } else {
                exact.insert(key_of(&e));
            }
        }
    }
    Outcome { exact, heuristic }
}

/// What the kernel does today: `PACKET_FANOUT_HASH`.
fn replay_across(pcap: &Path, workers: usize) -> Outcome {
    replay_across_with(pcap, workers, flow_worker)
}

fn corpus_pcaps() -> Vec<PathBuf> {
    let Ok(entries) = std::fs::read_dir(corpus_dir()) else { return Vec::new() };
    let mut out: Vec<PathBuf> = entries
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().and_then(|e| e.to_str()) == Some("pcap"))
        .collect();
    out.sort();
    out
}

/// THE invariant. An IOC detection is a per-packet, stateless decision, so it must be completely
/// independent of how many workers the traffic was split across. A single trail lost to fanout
/// would be a silent, permanent blind spot proportional to worker count.
#[test]
fn exact_trail_detections_are_identical_at_any_worker_count() {
    let pcaps = corpus_pcaps();
    assert!(!pcaps.is_empty(), "corpus missing; run: python3 sensor/tools/gen_corpus.py");

    for pcap in &pcaps {
        let one = replay_across(pcap, 1);
        for workers in [2usize, 4, 8] {
            let many = replay_across(pcap, workers);

            let lost: Vec<&EventKey> = one.exact.difference(&many.exact).collect();
            assert!(
                lost.is_empty(),
                "{}: {} exact detection(s) LOST at {workers} workers: {:?}",
                pcap.display(),
                lost.len(),
                lost
            );

            // The other direction matters too: fanout must not invent detections.
            let gained: Vec<&EventKey> = many.exact.difference(&one.exact).collect();
            assert!(
                gained.is_empty(),
                "{}: {} exact detection(s) APPEARED only at {workers} workers: {:?}",
                pcap.display(),
                gained.len(),
                gained
            );
        }
    }
}

/// Heuristic dilution, measured. Not an assertion of equality — flow-hashing genuinely scatters
/// a scanner's probes — but the numbers are printed so a change in them is visible, and the one
/// property that MUST hold is asserted: fanout may lose heuristic alerts, never invent them.
#[test]
fn heuristic_dilution_is_measured_and_never_invents_alerts() {
    let pcaps = corpus_pcaps();
    if pcaps.is_empty() {
        return;
    }

    let mut total_one = 0usize;
    let mut totals: Vec<(usize, usize)> = Vec::new();

    for workers in [2usize, 4, 8] {
        let mut kept = 0usize;
        let mut base = 0usize;
        for pcap in &pcaps {
            let one = replay_across(pcap, 1);
            let many = replay_across(pcap, workers);
            base += one.heuristic.len();
            kept += one.heuristic.intersection(&many.heuristic).count();

            let invented: Vec<&EventKey> = many.heuristic.difference(&one.heuristic).collect();
            assert!(
                invented.is_empty(),
                "{}: {workers} workers invented heuristic alert(s) a single worker did not raise: {:?}",
                pcap.display(),
                invented
            );
        }
        total_one = base;
        totals.push((workers, kept));
    }

    println!("[i] heuristic alerts with 1 worker: {total_one}");
    for (workers, kept) in &totals {
        let pct = (kept * 100).checked_div(total_one).unwrap_or(100);
        println!("[i]   {workers} workers: {kept} still raised ({pct}%)");
    }
    println!(
        "[i] loss here is inherent: PACKET_FANOUT_HASH splits by FLOW, the scan heuristics count \
         by SOURCE, and a scan is many flows (COMPATIBILITY.md §3). Set CAPTURE_WORKERS 1 for \
         undiluted heuristic fidelity."
    );
}

/// The point of source-affine fanout, measured against the flow hash it replaces.
///
/// `PACKET_FANOUT_HASH` splits by flow while the scan heuristics count by source, so a scanner's
/// probes are scattered and no worker reaches the threshold. Hashing the source alone puts every
/// packet a host sends on one worker, which is the condition those heuristics were written for.
///
/// This runs the real detection path over the real corpus and needs no kernel support, no root and
/// no live interface: the distribution is applied in userspace exactly as `flow_worker` already
/// was. What the kernel does with a CBPF program is asserted separately - here we are asking
/// whether the DISTRIBUTION is the right one, which is the part that decides whether alerts live.
#[test]
fn source_affine_fanout_keeps_the_scan_heuristics() {
    let pcaps = corpus_pcaps();
    if pcaps.is_empty() {
        return;
    }

    let mut base = 0usize;
    let mut rows: Vec<(usize, usize, usize)> = Vec::new();

    for workers in [2usize, 4, 8] {
        let (mut kept_src, mut kept_flow, mut total) = (0usize, 0usize, 0usize);
        for pcap in &pcaps {
            let one = replay_across_with(pcap, 1, source_worker);
            let src = replay_across_with(pcap, workers, source_worker);
            let flow = replay_across_with(pcap, workers, flow_worker);

            total += one.heuristic.len();
            kept_src += one.heuristic.intersection(&src.heuristic).count();
            kept_flow += one.heuristic.intersection(&flow.heuristic).count();

            // the invariant that holds for ANY distribution: never invent an alert
            let invented: Vec<&EventKey> = src.heuristic.difference(&one.heuristic).collect();
            assert!(invented.is_empty(), "{}: source-affine invented {:?}", pcap.display(), invented);

            // and exact trail detection stays a stateless per-packet decision
            assert_eq!(
                one.exact,
                src.exact,
                "{}: exact detections must be identical at {workers} workers",
                pcap.display()
            );
        }
        base = total;
        rows.push((workers, kept_src, kept_flow));
    }

    println!("[i] heuristic alerts with 1 worker: {base}");
    for (workers, kept_src, kept_flow) in &rows {
        let p_src = (kept_src * 100).checked_div(base).unwrap_or(100);
        let p_flow = (kept_flow * 100).checked_div(base).unwrap_or(100);
        println!("[i]   {workers} workers: source-affine {kept_src} ({p_src}%)  vs  flow-hash {kept_flow} ({p_flow}%)");
    }

    // The claim being made, in the strongest form the corpus supports: splitting by source costs
    // NOTHING at any worker count. If this ever fails, source affinity is not sufficient for some
    // heuristic and CAPTURE_WORKERS must stay 1 for it - which is worth failing the build over.
    for (workers, kept_src, _) in &rows {
        assert_eq!(*kept_src, base, "source-affine fanout lost heuristic alerts at {workers} workers");
    }
}
