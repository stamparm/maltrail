//! Reproducible benchmarks for the Rust sensor's packet path.
//!
//!     cargo bench --bench hotpath                      # default release profile
//!     cargo bench --profile release-lto --bench hotpath # with LTO
//!
//! Deliberately split so no number can be mistaken for another:
//!
//!  * **microbench**  — one isolated stage (header parse, trail lookup, DNS/HTTP/TLS parse).
//!    These are the fastest numbers and must NOT be quoted as sensor throughput.
//!  * **packet path** — `process_packet()` end to end on a realistic packet mix, with trails
//!    loaded, heuristics on and events written. This bounds one worker's software capability.
//!  * **replay**      — a whole pcap through the real capture handle + DLT + packet path.
//!
//! No external harness crate: warmup + timed repetition, printing ns/iteration, iterations per
//! second and (for the packet path) the line rate implied by the benchmarked packet-size mix.
//! Run on an otherwise idle machine.

use std::hint::black_box;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use maltrail_sensor::addr::{addr_to_int, Ip};
use maltrail_sensor::packet;
use maltrail_sensor::protocols::{dns, http, quic, tls};
use maltrail_sensor::testkit::*;
use maltrail_sensor::trails;
use maltrail_sensor::whitelist::Whitelist;

const WARMUP: Duration = Duration::from_millis(200);
const MEASURE: Duration = Duration::from_millis(700);

struct Measurement {
    name: &'static str,
    kind: &'static str,
    iterations: u64,
    elapsed: Duration,
    bytes: u64,
}

impl Measurement {
    fn ns_per_iter(&self) -> f64 {
        self.elapsed.as_nanos() as f64 / self.iterations as f64
    }

    fn per_second(&self) -> f64 {
        self.iterations as f64 / self.elapsed.as_secs_f64()
    }

    fn gbit(&self) -> f64 {
        if self.bytes == 0 {
            return 0.0;
        }
        (self.bytes as f64 * 8.0) / self.elapsed.as_secs_f64() / 1e9
    }
}

/// Time `body` for a fixed wall-clock budget. `bytes_per_iter` feeds the line-rate estimate
/// and may be 0 when a byte figure would be meaningless.
fn bench(name: &'static str, kind: &'static str, bytes_per_iter: u64, mut body: impl FnMut() -> u64) -> Measurement {
    let warm_end = Instant::now() + WARMUP;
    while Instant::now() < warm_end {
        black_box(body());
    }
    let started = Instant::now();
    let mut iterations = 0u64;
    while started.elapsed() < MEASURE {
        // batch so the clock read is amortised
        for _ in 0..64 {
            black_box(body());
        }
        iterations += 64;
    }
    let elapsed = started.elapsed();
    Measurement { name, kind, iterations, elapsed, bytes: iterations * bytes_per_iter }
}

fn report(results: &[Measurement]) {
    println!("\n{:<38} {:<12} {:>12} {:>16} {:>12}", "benchmark", "kind", "ns/iter", "iter/s", "Gbit/s");
    println!("{}", "-".repeat(94));
    for r in results {
        let gbit = if r.bytes == 0 { "-".to_string() } else { format!("{:.2}", r.gbit()) };
        println!("{:<38} {:<12} {:>12.1} {:>16.0} {:>12}", r.name, r.kind, r.ns_per_iter(), r.per_second(), gbit);
    }
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).parent().unwrap().to_path_buf()
}

fn corpus_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests").join("corpus")
}

/// A realistic-ish mix: mostly bulk TCP on 443, then SYNs, DNS, HTTP and a little ICMP/UDP.
fn packet_mix() -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    for i in 0..60u16 {
        let payload = vec![0x17u8; 1400];
        out.push(eth(
            &ipv4(6, "10.0.0.5", &format!("93.184.216.{}", i % 250), &tcp(50000 + i, 443, 0x10, &payload)),
            0x0800,
            None,
        ));
    }
    for i in 0..15u16 {
        out.push(eth(
            &ipv4(6, "10.0.0.5", &format!("93.184.216.{}", i % 250), &tcp(50000 + i, 443, 0x02, b"")),
            0x0800,
            None,
        ));
    }
    for i in 0..10u16 {
        out.push(eth(
            &ipv4(
                17,
                "10.0.0.5",
                "8.8.8.8",
                &udp(40000 + i, 53, &dns_query(&format!("host{i}.example.org"), 1, 1, 0x0100)),
            ),
            0x0800,
            None,
        ));
    }
    for i in 0..10u16 {
        let payload = http_get(&format!("/index{i}.html?id={i}"), Some("www.example.org"), "Mozilla/5.0");
        out.push(eth(&ipv4(6, "10.0.0.5", "93.184.216.34", &tcp(50000 + i, 80, 0x18, &payload)), 0x0800, None));
    }
    for _ in 0..5 {
        out.push(eth(&ipv4(1, "10.0.0.5", "8.8.4.4", &[0x08, 0x00, 0, 0, 0, 0, 0, 0]), 0x0800, None));
        out.push(eth(&ipv4(17, "10.0.0.5", "224.0.0.251", &udp(5353, 5353, &[0u8; 40])), 0x0800, None));
    }
    out
}

/// Pull the UDP payload of the single packet in the QUIC corpus pcap (pcap global header 24 +
/// record header 16 + Ethernet 14 + IPv4 20 + UDP 8).
fn quic_initial_from_corpus() -> Option<Vec<u8>> {
    let pcap = std::fs::read(corpus_dir().join("quic_sni.pcap")).ok()?;
    let start = 24 + 16 + 14 + 20 + 8;
    if pcap.len() > start {
        Some(pcap[start..].to_vec())
    } else {
        None
    }
}

fn main() {
    let mut results = Vec::new();

    // ---------------------------------------------------------------- microbenchmarks
    let syn = ipv4(6, "10.0.0.5", "66.66.66.66", &tcp(50000, 443, 0x02, b""));
    results.push(bench("ip+tcp header parse", "microbench", 0, || {
        let header = packet::parse_ip(black_box(&syn)).unwrap();
        let tcph = packet::parse_tcp(&syn, header.header_len).unwrap();
        tcph.dst_port as u64
    }));

    let dnsq = dns_query("www.example.org", 1, 1, 0x0100);
    results.push(bench("dns question decode", "microbench", 0, || {
        let q = dns::question(black_box(&dnsq)).unwrap();
        q.name.len() as u64
    }));

    let request = http_get("/index.html?id=1", Some("www.example.org"), "Mozilla/5.0");
    let request_text = String::from_utf8_lossy(&request).to_string();
    results.push(bench("http request line + host", "microbench", 0, || {
        let crlf = memchr::memmem::Finder::new("\r\n");
        let line = http::request_line(black_box(&request_text), &crlf, &memchr::memmem::Finder::new(" HTTP/")).unwrap();
        let host = http::header_value(&request_text, "\r\nHost:").unwrap_or("");
        (line.path.len() + host.len()) as u64
    }));

    let hello = tls::build_client_hello("www.example.org", true);
    results.push(bench("tls clienthello sni", "microbench", 0, || {
        tls::client_hello_sni(black_box(&hello)).map(|s| s.len() as u64).unwrap_or(0)
    }));

    if let Some(initial) = quic_initial_from_corpus() {
        results.push(bench("quic initial sni (hkdf+aes)", "microbench", 0, || {
            quic::extract_sni_from_quic_initial(black_box(&initial)).map(|s| s.len() as u64).unwrap_or(0)
        }));
    }

    // ---------------------------------------------------------------- trail lookups
    let real_trails = std::env::var("HOME")
        .ok()
        .map(|h| PathBuf::from(h).join(".maltrail").join("trails.csv"))
        .filter(|p| p.is_file());

    let db = match &real_trails {
        Some(path) => {
            let wl = Whitelist::load(&repo_root(), None);
            let started = Instant::now();
            let (db, stats) = trails::load(path, &wl).expect("load real trails");
            println!(
                "[i] trail set: {} real trails, loaded in {:.2}s, {:.1} MB resident",
                stats.loaded,
                started.elapsed().as_secs_f64(),
                db.memory_bytes() as f64 / (1024.0 * 1024.0)
            );
            db
        }
        None => {
            println!("[i] trail set: no ~/.maltrail/trails.csv, using a small fixture (lookup numbers optimistic)");
            build_db(&[("evil.example", "malware", "(static)"), ("66.66.66.66", "badnet", "(static)")])
        }
    };

    let miss_ip = Ip::V4(addr_to_int("203.0.113.7").unwrap());
    results.push(bench("trail lookup: ipv4 miss", "microbench", 0, || db.get_ip(black_box(miss_ip)).is_some() as u64));
    results.push(bench("trail lookup: ipv4+port miss", "microbench", 0, || {
        db.get_ip_port(black_box(miss_ip), black_box(443)).is_some() as u64
    }));
    results.push(bench("trail lookup: domain miss", "microbench", 0, || {
        db.get(black_box("this-domain-does-not-exist.example")).is_some() as u64
    }));

    // ---------------------------------------------------------------- full packet path
    let mix = packet_mix();
    let mix_bytes: u64 = mix.iter().map(|p| p.len() as u64).sum();
    let avg_size = mix_bytes as f64 / mix.len() as f64;
    let bytes_per_iter = avg_size as u64;
    println!("[i] packet mix: {} packets, average {:.0} bytes", mix.len(), avg_size);

    let trail_fixture: Vec<(&str, &str, &str)> = vec![
        ("evil.example", "malware (test)", "(static)"),
        ("66.66.66.66", "badnet", "(static)"),
        ("/malicious-login.php", "malware (test)", "(static)"),
    ];

    {
        let mut h = Harness::with_options(&trail_fixture, HarnessOptions::heuristics());
        let mut index = 0usize;
        let mut sec = 1_700_000_000u64;
        results.push(bench("process_packet (mixed traffic)", "packet path", bytes_per_iter, || {
            let packet = &mix[index % mix.len()];
            index += 1;
            if index % 4096 == 0 {
                sec += 1;
            }
            h.feed(packet, sec, 0, 14);
            packet.len() as u64
        }));
    }

    {
        let mut h = Harness::with_options(&trail_fixture, HarnessOptions::quiet());
        let mut index = 0usize;
        results.push(bench("process_packet (no heuristics)", "packet path", bytes_per_iter, || {
            let packet = &mix[index % mix.len()];
            index += 1;
            h.feed(packet, 1_700_000_000, 0, 14);
            packet.len() as u64
        }));
    }

    // Bulk TLS only: the shape that dominates a fat pipe.
    {
        let mut h = Harness::with_options(&trail_fixture, HarnessOptions::heuristics());
        let bulk =
            eth(&ipv4(6, "10.0.0.5", "93.184.216.34", &tcp(50000, 443, 0x10, &vec![0x17u8; 1400])), 0x0800, None);
        let bytes = bulk.len() as u64;
        results.push(bench("process_packet (bulk tls only)", "packet path", bytes, || {
            h.feed(&bulk, 1_700_000_000, 0, 14);
            1
        }));
    }

    // An exactly repeated 5-tuple in the same second is dropped by the _last_udp burst
    // filter before any DNS work happens; measured separately so the cache numbers below
    // cannot be confused with it.
    {
        let mut h = Harness::with_options(&trail_fixture, HarnessOptions::heuristics());
        let repeat = eth(
            &ipv4(17, "10.0.0.5", "8.8.8.8", &udp(40000, 53, &dns_query("www.example.org", 1, 1, 0x0100))),
            0x0800,
            None,
        );
        let bytes = repeat.len() as u64;
        results.push(bench("udp burst suppression (early out)", "packet path", bytes, || {
            h.feed(&repeat, 1_700_000_000, 0, 14);
            1
        }));
    }

    // The overwhelmingly common packet on a real link: established TCP data to an address that is
    // not a trail, carrying bytes the sensor will not act on. It matches nothing and its whole job
    // is to leave quickly. Benchmarked because the "does this look like HTTP" gate runs on every
    // one of them, so any cost there is paid at line rate - a per-call memmem::find here was
    // costing 26 ns/packet more than the prebuilt searcher `Statics` already held.
    {
        let mut h = Harness::with_options(&trail_fixture, HarnessOptions::heuristics());
        let payload = vec![0x17u8; 1400];
        let bulk: Vec<Vec<u8>> = (0..64u16)
            .map(|i| {
                eth(
                    &ipv4(6, "10.0.0.5", &format!("93.184.216.{}", i % 250), &tcp(50000 + i, 443, 0x10, &payload)),
                    0x0800,
                    None,
                )
            })
            .collect();
        let bytes = bulk.iter().map(|p| p.len() as u64).sum::<u64>() / bulk.len() as u64;
        let mut i = 0usize;
        results.push(bench("clean TCP pass-through (1400B)", "packet path", bytes, move || {
            h.feed(&bulk[i % bulk.len()], 1_700_000_000, 0, 14);
            i += 1;
            1
        }));
    }

    // The same filter on a FULL-SIZED datagram. The burst digest is the one part of this path
    // whose cost could scale with the packet, and the small DNS case above cannot show that:
    // hashing the whole payload instead of a bounded prefix measured 1141 ns on 1200 bytes,
    // roughly four times the entire mixed-traffic packet path, while looking free at 43 bytes.
    // QUIC put full-MTU UDP on ordinary networks, so this is the shape that matters.
    {
        let mut h = Harness::with_options(&trail_fixture, HarnessOptions::heuristics());
        let payload: Vec<u8> = (0..1200).map(|i| (i % 251) as u8).collect();
        let jumbo = eth(&ipv4(17, "10.0.0.5", "203.0.113.9", &udp(40000, 443, &payload)), 0x0800, None);
        let bytes = jumbo.len() as u64;
        results.push(bench("udp burst suppression (1200B payload)", "packet path", bytes, || {
            h.feed(&jumbo, 1_700_000_000, 0, 14);
            1
        }));
    }

    // Warm cache: a small set of distinct 5-tuples over the SAME domain, so the burst filter
    // does not fire but the domain result cache always hits. Two-label names are used on
    // purpose: a deeper name would also drive the DNS-exhaustion accumulator, and once that
    // trips it returns early and stops measuring the trail-lookup path at all. Packets are
    // pre-built so the loop measures the sensor, not `format!()`.
    {
        let mut h = Harness::with_options(&trail_fixture, HarnessOptions::heuristics());
        let warm: Vec<Vec<u8>> = (0..256u16)
            .map(|i| {
                eth(
                    &ipv4(17, "10.0.0.5", "8.8.8.8", &udp(40000 + i, 53, &dns_query("warmcache.com", 1, 1, 0x0100))),
                    0x0800,
                    None,
                )
            })
            .collect();
        let bytes = warm[0].len() as u64;
        let mut index = 0usize;
        results.push(bench("dns query, warm domain cache", "packet path", bytes, || {
            let packet = &warm[index % warm.len()];
            index += 1;
            h.feed(packet, 1_700_000_000, 0, 14);
            1
        }));
    }

    // Three labels, which is what turns the ACCUMULATOR path on: `label_count > 2` gates both
    // the DNS-exhaustion window and the tunnelling detector, so the two-label rows above measure
    // neither. A real network's DNS is overwhelmingly three labels or more, so this is the shape
    // that decides what those heuristics actually cost.
    //
    // Spread over 128 parent domains ON PURPOSE. Put 4096 subdomains under ONE parent and the
    // exhaustion window trips at 1000 and then returns early for every later query, so the row
    // measures the short-circuit rather than the accumulators - which is what the first version
    // of this bench did, and it read 336 ns instead of the real 2,400.
    {
        let mut h = Harness::with_options(&trail_fixture, HarnessOptions::heuristics());
        let subs: Vec<Vec<u8>> = (0..4096u32)
            .map(|i| {
                eth(
                    &ipv4(
                        17,
                        "10.0.0.5",
                        "8.8.8.8",
                        &udp(
                            40000 + (i % 1000) as u16,
                            53,
                            &dns_query(&format!("n{i}.host{}.org", i % 128), 1, 1, 0x0100),
                        ),
                    ),
                    0x0800,
                    None,
                )
            })
            .collect();
        let bytes = subs[0].len() as u64;
        let mut index = 0usize;
        results.push(bench("dns query, subdomain (accumulators)", "packet path", bytes, || {
            let packet = &subs[index % subs.len()];
            index += 1;
            h.feed(packet, 1_700_000_000, 0, 14);
            1
        }));
    }

    // Cold cache: a fresh domain every packet (the DGA-flood shape), pre-built for the same
    // reason. 4096 distinct two-label names is far past the 1000-entry result cache, and the
    // shallow name keeps the exhaustion accumulator (and its early return) out of the way.
    {
        let mut h = Harness::with_options(&trail_fixture, HarnessOptions::heuristics());
        let cold: Vec<Vec<u8>> = (0..4096u32)
            .map(|i| {
                eth(
                    &ipv4(
                        17,
                        "10.0.0.5",
                        "8.8.8.8",
                        &udp(40000 + (i % 1000) as u16, 53, &dns_query(&format!("cold{i}.com"), 1, 1, 0x0100)),
                    ),
                    0x0800,
                    None,
                )
            })
            .collect();
        let bytes = cold[0].len() as u64;
        let mut index = 0usize;
        results.push(bench("dns query, cold domain cache", "packet path", bytes, || {
            let packet = &cold[index % cold.len()];
            index += 1;
            h.feed(packet, 1_700_000_000, 0, 14);
            1
        }));
    }

    // ---------------------------------------------------------------- offline replay
    // One handle open + one worker state, reused across iterations, so the number is replay
    // throughput rather than harness construction.
    let soup = corpus_dir().join("mixed_soup.pcap");
    if soup.is_file() {
        let mut h = Harness::with_options(&trail_fixture, HarnessOptions::heuristics());
        let packets_per_file = {
            let mut probe = Harness::with_options(&trail_fixture, HarnessOptions::heuristics());
            probe.replay(&soup, false) as u64
        };
        let file_bytes = std::fs::metadata(&soup).map(|m| m.len()).unwrap_or(0);
        let mut m = bench("pcap replay (packets/s)", "replay", 0, || h.replay(&soup, false) as u64);
        // Re-express per packet rather than per file.
        m.iterations = m.iterations.saturating_mul(packets_per_file.max(1));
        m.bytes = (m.iterations / packets_per_file.max(1)) * file_bytes;
        results.push(m);
    }

    // ---------------------------------------------------------------- worker scaling
    // Software-path scaling only: N independent workers, each with its own state, replaying
    // the same mix. This is what PACKET_FANOUT parallelises; capture-side scaling has to be
    // measured on real hardware (see tools/fanout_check.sh).
    let cores = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1);
    println!("[i] worker scaling (available_parallelism = {cores}); software path only, no capture");
    let mut single_worker_pps = 0.0f64;
    for workers in [1usize, 2, 4, 8, 16] {
        if workers > cores {
            break;
        }
        let mix = std::sync::Arc::new(mix.clone());
        let started = Instant::now();
        let handles: Vec<_> = (0..workers)
            .map(|_| {
                let mix = mix.clone();
                std::thread::spawn(move || {
                    let fixture: Vec<(&str, &str, &str)> = vec![
                        ("evil.example", "malware (test)", "(static)"),
                        ("66.66.66.66", "badnet", "(static)"),
                        ("/malicious-login.php", "malware (test)", "(static)"),
                    ];
                    let mut h = Harness::with_options(&fixture, HarnessOptions::heuristics());
                    let deadline = Instant::now() + MEASURE;
                    let mut count = 0u64;
                    let mut index = 0usize;
                    while Instant::now() < deadline {
                        for _ in 0..1024 {
                            h.feed(&mix[index % mix.len()], 1_700_000_000, 0, 14);
                            index += 1;
                        }
                        count += 1024;
                    }
                    count
                })
            })
            .collect();
        let total: u64 = handles.into_iter().map(|h| h.join().unwrap_or(0)).sum();
        let elapsed = started.elapsed();
        let pps = total as f64 / elapsed.as_secs_f64();
        if workers == 1 {
            single_worker_pps = pps;
        }
        println!(
            "[i] scaling: {workers:>2} worker(s) -> {:>12.0} packets/s  ({:.2} Gbit/s, {:.2}x of one worker)",
            pps,
            pps * avg_size * 8.0 / 1e9,
            if single_worker_pps > 0.0 { pps / single_worker_pps } else { 1.0 }
        );
    }

    report(&results);

    println!(
        "\n[i] NOTE: 'microbench' rows are single isolated stages and are NOT sensor throughput.\n\
         [i]       'packet path' is process_packet() end to end (parse + detect + format + write)\n\
         [i]       over the printed packet-size mix; the Gbit/s column is that mix's line rate for\n\
         [i]       ONE worker. Multiply by the PACKET_FANOUT worker count for a system figure and\n\
         [i]       see docs/REPORT.md for measured multi-worker scaling.\n\
         [i]       'replay' opens the pcap once and reuses one worker state, so it is replay
         [i]       throughput (packets/s) rather than harness construction cost."
    );
}
