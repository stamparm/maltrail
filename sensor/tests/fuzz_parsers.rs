//! Deterministic fuzzing of every packet parser and of the whole packet path.
//!
//! This runs on stable Rust as part of `cargo test`, so the "must never panic on arbitrary
//! input" property is checked on every build rather than only when someone remembers to run
//! `cargo fuzz`. The nightly `cargo-fuzz` targets under `fuzz/` use the same entry points and
//! go deeper (coverage-guided); see `docs/ARCHITECTURE.md`.
//!
//! Strategy:
//!  * pure random bytes of every length up to a few hundred,
//!  * structured mutation of *valid* packets (bit flips, byte splices, truncation), which is
//!    what actually reaches the deep parsers,
//!  * adversarial length fields (IHL, DNS label lengths, TLS/QUIC length prefixes).

use maltrail_sensor::packet::{self, dlt, tunnel};
use maltrail_sensor::protocols::{dns, http, quic, tls};
use maltrail_sensor::testkit::*;

/// xorshift64*, so a failure is reproducible from its seed.
struct Rng(u64);

impl Rng {
    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    fn below(&mut self, n: usize) -> usize {
        if n == 0 {
            0
        } else {
            (self.next_u64() % n as u64) as usize
        }
    }

    fn byte(&mut self) -> u8 {
        (self.next_u64() >> 32) as u8
    }
}

/// Run every standalone parser over `data`. None of them may panic.
fn hammer_parsers(data: &[u8]) {
    let _ = packet::parse_ip(data);
    for header_len in [0usize, 20, 24, 40, 60, 1000] {
        let _ = packet::parse_tcp(data, header_len);
        let _ = packet::parse_udp(data, header_len);
        let _ = packet::udp_payload(data, header_len);
        let _ = packet::icmp_type(data, header_len);
    }
    for datalink in [0i32, 1, 9, 12, 113, 147, 9999] {
        let mut learner = dlt::DltLearner::default();
        let _ = learner.resolve(datalink, data);
    }
    let _ = dlt::guess_ip_offset(data, 64);

    // The tunnel parser turns attacker-supplied length fields (GRE's flag words, GENEVE's
    // opt_len) into an OFFSET that the packet path then parses at, so a wrong answer is not a
    // crash but a parse of somebody else's bytes. Feed it every header it might be handed.
    if let Ok(header) = packet::parse_ip(data) {
        if let Some(off) = tunnel::inner_ip_offset(data, 0, &header) {
            assert!(off <= data.len(), "tunnel offset {off} is past the end of a {}-byte packet", data.len());
            let _ = packet::parse_ip(&data[off..]);
        }
    }

    let _ = dns::qdcount(data);
    let _ = dns::flags_high(data);
    let _ = dns::flags_low(data);
    if let Some(q) = dns::question(data) {
        let _ = dns::question_type_class(data, q.name_end);
        let _ = dns::first_a_record(data, q.name_end);
        // and with a hostile name_end
        let _ = dns::first_a_record(data, usize::MAX - 4);
        let _ = dns::question_type_class(data, usize::MAX - 2);
    }

    let _ = tls::client_hello_sni(data);
    let _ = tls::parse_sni_extension(data, true);
    let _ = quic::extract_sni_from_quic_initial(data);

    let text = String::from_utf8_lossy(data);
    let _ = http::request_line(&text, &memchr::memmem::Finder::new("\r\n"), &memchr::memmem::Finder::new(" HTTP/"));
    let _ = http::header_value(&text, "\r\nHost:");
    let _ = http::header_value(&text, "\r\nUser-Agent:");
    let _ = http::unquote(&text);
    let _ = http::splitext(&text);
    let _ = http::urlparse_path_query(&text);
}

fn valid_seeds() -> Vec<Vec<u8>> {
    let mut seeds = vec![ipv4(6, "10.0.0.5", "66.66.66.66", &tcp(50000, 443, 0x02, b""))];
    seeds.push(ipv4(
        6,
        "10.0.0.5",
        "66.66.66.66",
        &tcp(50000, 80, 0x18, &http_get("/a/b.php?x=1", Some("evil.example"), "curl/8")),
    ));
    seeds.push(ipv4(17, "10.0.0.5", "8.8.8.8", &udp(40000, 53, &dns_query("evil.example", 1, 1, 0x0100))));
    seeds.push(ipv4(17, "8.8.8.8", "10.0.0.5", &udp(53, 40000, &dns_query("evil.example", 1, 1, 0x8083))));
    seeds.push(ipv4(1, "10.0.0.5", "66.66.66.66", &[0x08, 0x00, 0, 0, 0, 0, 0, 0]));
    seeds.push(ipv6(6, "dead::1", "dead::beef", &tcp(50000, 443, 0x02, b"")));
    seeds.push(ipv6(17, "dead::1", "dead::2", &udp(40000, 53, &dns_query("evil.example", 1, 1, 0x0100))));
    seeds.push(ipv4(
        6,
        "10.0.0.5",
        "203.0.113.30",
        &tcp(50000, 443, 0x18, &tls::build_client_hello("tls.example", true)),
    ));
    seeds.push(eth(&seeds[0].clone(), 0x0800, None));
    seeds.push(eth(&seeds[0].clone(), 0x0800, Some(100)));
    seeds.push(b"HTTP/1.1 200 OK\r\nServer: sinkhole\r\n\r\n".to_vec());
    // Encapsulated seeds: mutating these produces the length fields that matter - a GRE flag word
    // claiming options that are not there, a GENEVE opt_len past the end of the packet.
    let inner = eth(&seeds[0].clone(), 0x0800, None);
    seeds.push(vxlan("192.0.2.1", "192.0.2.2", 42, &inner));
    seeds.push(geneve("192.0.2.1", "192.0.2.2", 0x6558, 8, &inner));
    seeds.push(gre("192.0.2.1", "192.0.2.2", 0x0800, true, true, true, &seeds[0].clone()));
    seeds.push(erspan("192.0.2.1", "192.0.2.2", true, &inner));
    seeds
}

#[test]
fn parsers_survive_random_bytes() {
    let mut rng = Rng(0x1234_5678_9abc_def0);
    let mut buf = Vec::with_capacity(600);
    for _ in 0..20_000 {
        let len = rng.below(600);
        buf.clear();
        for _ in 0..len {
            buf.push(rng.byte());
        }
        hammer_parsers(&buf);
    }
}

#[test]
fn parsers_survive_patterned_bytes() {
    // Repeating patterns hit length-field edges that uniform random rarely does.
    for pattern in [0x00u8, 0x01, 0x0a, 0x20, 0x22, 0x25, 0x2e, 0x3f, 0x45, 0x60, 0x7f, 0x80, 0xc0, 0xff] {
        for len in 0..300usize {
            hammer_parsers(&vec![pattern; len]);
        }
    }
}

#[test]
fn parsers_survive_mutated_valid_packets() {
    let seeds = valid_seeds();
    let mut rng = Rng(0xdead_beef_cafe_1234);
    for seed in &seeds {
        for _ in 0..4_000 {
            let mut data = seed.clone();
            match rng.below(5) {
                // bit flip
                0 => {
                    if !data.is_empty() {
                        let i = rng.below(data.len());
                        data[i] ^= 1 << rng.below(8);
                    }
                }
                // byte overwrite
                1 => {
                    if !data.is_empty() {
                        let i = rng.below(data.len());
                        data[i] = rng.byte();
                    }
                }
                // truncate
                2 => {
                    let n = rng.below(data.len() + 1);
                    data.truncate(n);
                }
                // splice in random bytes
                3 => {
                    let n = rng.below(32);
                    for _ in 0..n {
                        let i = rng.below(data.len() + 1);
                        let b = rng.byte();
                        data.insert(i, b);
                    }
                }
                // corrupt a length-ish field near the front
                _ => {
                    for i in 0..data.len().min(8) {
                        if rng.below(3) == 0 {
                            data[i] = rng.byte();
                        }
                    }
                }
            }
            hammer_parsers(&data);
        }
    }
}

#[test]
fn the_whole_packet_path_survives_mutated_packets() {
    // Same mutation strategy, but driven through process_packet with a live trail set, event
    // formatting and the heuristics enabled - the deep paths only reachable end to end.
    let mut h = Harness::with_options(
        &[
            ("evil.example", "malware (test)", "(static)"),
            ("66.66.66.66", "badnet", "(static)"),
            ("66.66.66.66:443", "c2", "(static)"),
            ("dead::beef", "badnet6", "(static)"),
            ("/a/b.php", "malware (test)", "(static)"),
            ("dga[0-9]+\\.example\\.com", "malware (test)", "(static)"),
        ],
        HarnessOptions {
            use_heuristics: true,
            check_host_domains: true,
            check_missing_host: true,
            extra: vec!["USE_FAST_PREFILTER true".to_string(), "FAST_FLOW_CUTOFF 4".to_string()],
        },
    );

    let seeds = valid_seeds();
    let mut rng = Rng(0x0bad_c0de_0bad_c0de);
    for (seed_index, seed) in seeds.iter().enumerate() {
        for iteration in 0..3_000u64 {
            let mut data = seed.clone();
            match rng.below(4) {
                0 => {
                    if !data.is_empty() {
                        let i = rng.below(data.len());
                        data[i] ^= 1 << rng.below(8);
                    }
                }
                1 => {
                    let n = rng.below(data.len() + 1);
                    data.truncate(n);
                }
                2 => {
                    let n = rng.below(16);
                    for _ in 0..n {
                        let i = rng.below(data.len() + 1);
                        let b = rng.byte();
                        data.insert(i, b);
                    }
                }
                _ => {
                    for byte in data.iter_mut() {
                        if rng.below(20) == 0 {
                            *byte = rng.byte();
                        }
                    }
                }
            }
            // vary the offset so the "misaligned DLT offset" path is exercised too
            let offset = if rng.below(8) == 0 { rng.below(20) } else { 0 };
            h.feed(&data, 1_700_000_000 + iteration % 90, (iteration % 1_000_000) as u32, offset);
        }
        let errors = h.errors();
        assert!(
            errors.iter().all(|e| !e.to_lowercase().contains("panic")),
            "seed #{seed_index} produced a panic: {errors:?}"
        );
    }
}

#[test]
fn quic_and_tls_length_fields_are_fully_hostile() {
    // Walk every byte of a valid handshake/Initial and set it to the values most likely to
    // break a length calculation.
    let hello = tls::build_client_hello("tls.example", true);
    for i in 0..hello.len() {
        for value in [0x00u8, 0x01, 0x7f, 0x80, 0xfe, 0xff] {
            let mut data = hello.clone();
            data[i] = value;
            let _ = tls::client_hello_sni(&data);
        }
    }

    let mut initial = vec![0xc3u8];
    initial.extend_from_slice(&1u32.to_be_bytes());
    initial.push(8);
    initial.extend_from_slice(&[0xaa; 8]);
    initial.push(0);
    initial.push(0);
    initial.extend_from_slice(&[0x44, 0x00]);
    initial.extend_from_slice(&[0x55; 1200]);
    for i in 0..initial.len().min(64) {
        for value in [0x00u8, 0x40, 0x80, 0xc0, 0xff] {
            let mut data = initial.clone();
            data[i] = value;
            let _ = quic::extract_sni_from_quic_initial(&data);
        }
    }
}

#[test]
fn utf8_boundaries_in_http_helpers_are_safe() {
    // Multi-byte and invalid UTF-8 must not slice a character in half.
    let inputs: Vec<Vec<u8>> = vec![
        "GET /é HTTP/1.1\r\nHost: é.example\r\n\r\n".as_bytes().to_vec(),
        vec![0xf0, 0x9f, 0x92, 0xa9],
        vec![0xff, 0xfe, 0xfd],
        "%C3".as_bytes().to_vec(),
        "%C3%A9%".as_bytes().to_vec(),
        "a\u{10FFFF}b%20".as_bytes().to_vec(),
    ];
    for input in inputs {
        let text = String::from_utf8_lossy(&input);
        let _ = http::unquote(&text);
        let _ = http::request_line(&text, &memchr::memmem::Finder::new("\r\n"), &memchr::memmem::Finder::new(" HTTP/"));
        let _ = http::splitext(&text);
        let _ = http::urlparse_path_query(&text);
        for n in 0..text.len() {
            // slicing helpers must tolerate being handed partial input
            if text.is_char_boundary(n) {
                let _ = http::unquote(&text[..n]);
            }
        }
    }
}
