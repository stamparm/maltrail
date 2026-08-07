//! Numeric option bounds (ROADMAP Gate 1.6).
//!
//! Each of these was accepted silently and produced a sensor that looked configured and
//! detected badly or not at all:
//!
//!   * `CAPTURE_SNAPLEN 0` — every packet truncated to nothing
//!   * `CAPTURE_TIMEOUT` — narrowed by an `as i32` cast; a wrapped negative value means poll()
//!     blocks forever, so shutdown is only noticed when a packet happens to arrive
//!   * `PROCESS_COUNT` — an absurd count tries to spawn that many threads
//!   * `EVENT_THROTTLE_*` — zero disables the bounding the throttle exists to provide
//!
//! Policy: clamp and report, never refuse to start. A sensor that will not run because of a
//! mistyped tunable protects nothing.

use std::path::PathBuf;

use maltrail_sensor::config::Config;

fn write_config(name: &str, extra: &str) -> (PathBuf, PathBuf) {
    let dir = std::env::temp_dir().join(format!("maltrail-ranges-{}-{}", std::process::id(), name));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("logs")).unwrap();
    std::fs::write(dir.join("trails.csv"), "").unwrap();
    let conf = dir.join("maltrail.conf");
    std::fs::write(
        &conf,
        format!(
            "MONITOR_INTERFACE any\n\
             CAPTURE_BUFFER 64MB\n\
             PROCESS_COUNT 2\n\
             UPDATE_PERIOD 999999999\n\
             DISABLE_CHECK_SUDO true\n\
             USE_CONDENSED_STORAGE false\n\
             SENSOR_NAME ranges\n\
             LOG_DIR {}\n\
             TRAILS_FILE {}\n\
             {extra}\n",
            dir.join("logs").display(),
            dir.join("trails.csv").display()
        ),
    )
    .unwrap();
    (dir, conf)
}

fn load(name: &str, extra: &str) -> Config {
    let (_dir, conf) = write_config(name, extra);
    Config::load(&conf).expect("configuration must still load — clamping never refuses to start")
}

#[test]
fn a_sane_configuration_reports_no_clamps() {
    let cfg = load("sane", "");
    assert!(cfg.clamps.is_empty(), "nothing should be clamped here: {:?}", cfg.clamps);
    assert!(cfg.capture_snaplen >= 68);
    assert!(cfg.capture_timeout_ms > 0);
}

#[test]
fn a_zero_snaplen_is_raised_to_something_parseable() {
    let cfg = load("snaplen", "CAPTURE_SNAPLEN 0");
    assert!(cfg.capture_snaplen >= 68, "got {}", cfg.capture_snaplen);
    assert!(cfg.clamps.iter().any(|c| c.contains("CAPTURE_SNAPLEN")), "{:?}", cfg.clamps);
}

#[test]
fn an_overflowing_capture_timeout_never_becomes_negative() {
    // The old `as i32` cast wrapped: 99999999999 became 1215752191, and other values became
    // negative — which libpcap/poll read as "block forever".
    let cfg = load("timeout", "CAPTURE_TIMEOUT 99999999999");
    assert!(cfg.capture_timeout_ms > 0, "a timeout must stay positive, got {}", cfg.capture_timeout_ms);
    assert!(cfg.capture_timeout_ms <= 60_000, "got {}", cfg.capture_timeout_ms);
    assert!(cfg.clamps.iter().any(|c| c.contains("CAPTURE_TIMEOUT")), "{:?}", cfg.clamps);
}

#[test]
fn an_absurd_worker_count_is_bounded() {
    let cfg = load("workers", "PROCESS_COUNT 999999");
    assert!(cfg.capture_workers <= 1024, "got {}", cfg.capture_workers);
    assert!(cfg.capture_workers >= 1);
    assert!(cfg.clamps.iter().any(|c| c.contains("CAPTURE_WORKERS")), "{:?}", cfg.clamps);
}

#[test]
fn zero_throttle_settings_cannot_disable_the_bound() {
    let cfg = load("throttle", "EVENT_THROTTLE_WINDOW 0\nEVENT_THROTTLE_BURST 0\nEVENT_THROTTLE_MAX_KEYS 0");
    assert!(cfg.event_throttle_window >= 1);
    assert!(cfg.event_throttle_burst >= 1);
    assert!(cfg.event_throttle_max_keys >= 1);
    assert_eq!(cfg.clamps.len(), 3, "all three must be reported: {:?}", cfg.clamps);
}

/// `CAPTURE_BUFFER` sizes the ring PER WORKER, which is the surprise on a many-core box: the
/// shipped default of 10% of RAM with one worker per core asks for more memory than the machine
/// has. `-T` prints this total so it is discovered before deployment, not during.
#[test]
fn capture_ring_memory_is_reported_per_worker() {
    let cfg = load("ring", "PROCESS_COUNT 8\nCAPTURE_BUFFER 100MB");
    assert_eq!(
        cfg.estimated_capture_memory_bytes(),
        cfg.capture_buffer * 8,
        "the estimate must multiply by the worker count"
    );
}
