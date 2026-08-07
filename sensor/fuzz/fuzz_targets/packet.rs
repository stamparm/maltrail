#![no_main]
//! Link-layer + IP/TCP/UDP/ICMP header parsing. Must never panic.
use libfuzzer_sys::fuzz_target;
use maltrail_sensor::packet::{self, dlt};

fuzz_target!(|data: &[u8]| {
    let _ = packet::parse_ip(data);
    for header_len in [0usize, 20, 24, 40, 60] {
        let _ = packet::parse_tcp(data, header_len);
        let _ = packet::parse_udp(data, header_len);
        let _ = packet::udp_payload(data, header_len);
        let _ = packet::icmp_type(data, header_len);
    }
    for datalink in [0i32, 1, 9, 12, 113, 9999] {
        let mut learner = dlt::DltLearner::default();
        let _ = learner.resolve(datalink, data);
    }
    let _ = dlt::guess_ip_offset(data, 64);
});
