//! Extended, seed-randomised fuzzing of the same entry points `fuzz_parsers.rs` uses.
//!
//! `fuzz_parsers.rs` is deliberately deterministic - fixed RNG seeds, so CI tests the same inputs
//! on every build and a failure is always reproducible. That is the right default, but it means
//! the search never leaves those trajectories. This file runs the same hammer with a seed taken
//! strategies it does not: dictionary splices of protocol magic, inputs past a real MTU (its
//! random pass stops at 600 bytes), hostile `header_len` values, and length-field corruption
//! anywhere in the packet rather than only in the first eight bytes.
//!
//! The seed is FIXED by default, so CI stays reproducible. Override it to run a campaign; the
//! seed is printed either way, so anything this finds becomes a fixed-seed regression test.
//!
//! Budget: small by default so it costs CI almost nothing. Turn it up deliberately:
//!     MT_FUZZ_ITERS=3000000 cargo test --release --test fuzz_extended -- --nocapture

use maltrail_sensor::packet::{self, dlt, tunnel};
use maltrail_sensor::protocols::{dns, http, quic, tls};
use maltrail_sensor::testkit::*;

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
        (self.next_u64() >> 33) as u8
    }
}

fn env_num(key: &str, default: u64) -> u64 {
    std::env::var(key).ok().and_then(|v| v.parse().ok()).unwrap_or(default)
}

fn hammer(data: &[u8]) {
    let _ = packet::parse_ip(data);
    for header_len in [0usize, 20, 24, 40, 60, 1000, usize::MAX - 8] {
        let _ = packet::parse_tcp(data, header_len);
        let _ = packet::parse_udp(data, header_len);
        let _ = packet::udp_payload(data, header_len);
        let _ = packet::icmp_type(data, header_len);
    }
    for datalink in [0i32, 1, 9, 12, 113, 147, 276, 9999, -1, i32::MAX, i32::MIN] {
        let mut learner = dlt::DltLearner::default();
        let _ = learner.resolve(datalink, data);
    }
    for snap in [0usize, 1, 64, 1500, 65535] {
        let _ = dlt::guess_ip_offset(data, snap);
    }
    if let Ok(header) = packet::parse_ip(data) {
        if let Some(off) = tunnel::inner_ip_offset(data, 0, &header) {
            assert!(off <= data.len(), "tunnel offset {off} past the end of {} bytes", data.len());
            let _ = packet::parse_ip(&data[off..]);
        }
        // non-zero base: a tunnel inside a tunnel hands a non-zero offset back in
        for base in [1usize, 14, 20, data.len() / 2] {
            if base <= data.len() {
                if let Some(off) = tunnel::inner_ip_offset(data, base, &header) {
                    assert!(off <= data.len(), "tunnel offset {off} past the end (base {base})");
                }
            }
        }
    }
    let _ = dns::qdcount(data);
    let _ = dns::flags_high(data);
    let _ = dns::flags_low(data);
    if let Some(q) = dns::question(data) {
        let _ = dns::question_type_class(data, q.name_end);
        let _ = dns::first_a_record(data, q.name_end);
        for bogus in [0usize, 1, usize::MAX - 4, usize::MAX - 2, usize::MAX] {
            let _ = dns::first_a_record(data, bogus);
            let _ = dns::question_type_class(data, bogus);
        }
    }
    let _ = tls::client_hello_sni(data);
    let _ = tls::parse_sni_extension(data, true);
    let _ = tls::parse_sni_extension(data, false);
    let _ = quic::extract_sni_from_quic_initial(data);

    let text = String::from_utf8_lossy(data);
    let crlf = memchr::memmem::Finder::new("\r\n");
    let vhttp = memchr::memmem::Finder::new(" HTTP/");
    let _ = http::request_line(&text, &crlf, &vhttp);
    let _ = http::header_value(&text, "\r\nHost:");
    let _ = http::header_value(&text, "\r\nUser-Agent:");
    let _ = http::unquote(&text);
    let _ = http::splitext(&text);
    let _ = http::urlparse_path_query(&text);
}

fn seeds() -> Vec<Vec<u8>> {
    let mut s = vec![ipv4(6, "10.0.0.5", "66.66.66.66", &tcp(50000, 443, 0x02, b""))];
    s.push(ipv4(17, "10.0.0.5", "8.8.8.8", &udp(40000, 53, &dns_query("evil.example", 1, 1, 0x0100))));
    s.push(ipv6(6, "dead::1", "dead::beef", &tcp(50000, 443, 0x02, b"")));
    s.push(ipv4(1, "10.0.0.5", "66.66.66.66", &[0x08, 0x00, 0, 0, 0, 0, 0, 0]));
    let inner = eth(&s[0].clone(), 0x0800, None);
    s.push(vxlan("192.0.2.1", "192.0.2.2", 42, &inner));
    s.push(geneve("192.0.2.1", "192.0.2.2", 0x6558, 8, &inner));
    s.push(gre("192.0.2.1", "192.0.2.2", 0x0800, true, true, true, &s[0].clone()));
    s.push(erspan("192.0.2.1", "192.0.2.2", true, &inner));
    s.push(eth(&s[0].clone(), 0x0800, Some(100)));
    s
}

/// Splices of protocol magic that uniform random almost never produces.
const DICT: &[&[u8]] = &[
    &[0x16, 0x03, 0x01],
    &[0x16, 0x03, 0x03],
    &[0x00, 0x00], // TLS record + SNI ext id
    &[0xff, 0xff],
    &[0xff, 0xff, 0xff, 0xff],
    &[0x45],
    &[0x60], // max lengths, IP version nibbles
    &[0xc0, 0x0c],
    &[0xc0, 0x00], // DNS name compression pointers
    &[0x08, 0x00],
    &[0x86, 0xdd],
    &[0x81, 0x00], // ethertypes, VLAN
    &[0x2f],
    &[0x11],
    &[0x06], // GRE / UDP / TCP proto numbers
    b"HTTP/1.1 ",
    b" HTTP/1.0\r\n",
    b"\r\nHost:",
    b"%",
];

#[test]
fn extended_fuzz() {
    // Fixed by default, for the same reason fuzz_parsers.rs is: CI must test the same inputs on
    // every build and never fail for a reason the next run cannot reproduce. MT_FUZZ_SEED turns
    // this into a campaign - vary it in a loop to explore new ground deliberately.
    let seed = env_num("MT_FUZZ_SEED", 0x5bf0_3635_9e37_79b9);
    let iters = env_num("MT_FUZZ_ITERS", 40_000);
    println!("extended_fuzz: MT_FUZZ_SEED={seed} MT_FUZZ_ITERS={iters}");

    let mut rng = Rng(seed);
    let corpus = seeds();
    let mut buf: Vec<u8> = Vec::with_capacity(70_000);

    for i in 0..iters {
        buf.clear();
        match rng.below(4) {
            // pure random, and unlike fuzz_parsers.rs the length goes past a real MTU
            0 => {
                let len = match rng.below(10) {
                    0 => rng.below(65_536),
                    1 => rng.below(9_000),
                    _ => rng.below(700),
                };
                for _ in 0..len {
                    buf.push(rng.byte());
                }
            }
            // mutate a valid packet
            1 => {
                buf.extend_from_slice(&corpus[rng.below(corpus.len())]);
                let rounds = 1 + rng.below(6);
                for _ in 0..rounds {
                    if buf.is_empty() {
                        break;
                    }
                    match rng.below(5) {
                        0 => {
                            let i = rng.below(buf.len());
                            buf[i] ^= 1 << rng.below(8);
                        }
                        1 => {
                            let i = rng.below(buf.len());
                            buf[i] = rng.byte();
                        }
                        2 => {
                            let n = rng.below(buf.len() + 1);
                            buf.truncate(n);
                        }
                        3 => {
                            let d = DICT[rng.below(DICT.len())];
                            let at = rng.below(buf.len() + 1);
                            for (k, b) in d.iter().enumerate() {
                                buf.insert(at + k, *b);
                            }
                        }
                        _ => {
                            // overwrite a length-ish field ANYWHERE, not just the first 8 bytes
                            let i = rng.below(buf.len());
                            let v = if rng.below(2) == 0 { 0xff } else { rng.byte() };
                            buf[i] = v;
                            if i + 1 < buf.len() {
                                buf[i + 1] = v;
                            }
                        }
                    }
                }
            }
            // dictionary soup
            2 => {
                let n = 1 + rng.below(40);
                for _ in 0..n {
                    buf.extend_from_slice(DICT[rng.below(DICT.len())]);
                }
                let extra = rng.below(64);
                for _ in 0..extra {
                    buf.push(rng.byte());
                }
            }
            // patterned with a random pattern and length, including long runs
            _ => {
                let b = rng.byte();
                let len = if rng.below(8) == 0 { rng.below(65_536) } else { rng.below(400) };
                buf.resize(len, b);
            }
        }
        hammer(&buf);

        if i % 20_000 == 0 && i > 0 {
            println!("  {i}/{iters}");
        }
    }
}
