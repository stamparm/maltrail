#![no_main]
//! DNS question decoding and answer-section walking.
use libfuzzer_sys::fuzz_target;
use maltrail_sensor::protocols::dns;

fuzz_target!(|data: &[u8]| {
    let _ = dns::qdcount(data);
    let _ = dns::flags_high(data);
    let _ = dns::flags_low(data);
    if let Some(q) = dns::question(data) {
        let _ = dns::question_type_class(data, q.name_end);
        let _ = dns::first_a_record(data, q.name_end);
    }
    // hostile offsets, independent of what question() reported
    for name_end in [0usize, 12, 1024, usize::MAX - 8] {
        let _ = dns::question_type_class(data, name_end);
        let _ = dns::first_a_record(data, name_end);
    }
});
