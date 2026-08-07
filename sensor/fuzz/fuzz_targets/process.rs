#![no_main]
//! The whole packet path: parse -> detect -> format -> write, with trails loaded and the
//! heuristics enabled. One harness is built per process and reused across inputs so the
//! stateful paths (caches, scan windows, burst suppression) are exercised too.
use libfuzzer_sys::fuzz_target;
use maltrail_sensor::testkit::{Harness, HarnessOptions};
use std::sync::Mutex;
use std::sync::OnceLock;

static HARNESS: OnceLock<Mutex<Harness>> = OnceLock::new();

fuzz_target!(|data: &[u8]| {
    let harness = HARNESS.get_or_init(|| {
        Mutex::new(Harness::with_options(
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
                extra: vec!["USE_FAST_PREFILTER true".into(), "FAST_FLOW_CUTOFF 4".into()],
            },
        ))
    });
    let mut harness = harness.lock().unwrap();
    // The first byte steers the ip_offset and the timestamp so time-based paths move.
    let offset = data.first().copied().unwrap_or(0) as usize % 20;
    let sec = 1_700_000_000u64 + data.len() as u64 % 120;
    harness.feed(data, sec, 0, offset);
});
