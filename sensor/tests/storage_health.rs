//! Evidence-storage health.
//!
//! Maltrail is an IDS, so its event logs are evidence and the sensor never deletes them to
//! reclaim space. That makes a full disk a real operating condition, and the worst kind of
//! sensor failure: appends start failing, detections are lost, and the only outward sign is
//! that alerts stopped — which looks exactly like a quiet network.
//!
//! The answer is not a retention knob that destroys evidence. It is to make the condition
//! measurable long before it bites, and to ship the durable copy off-box.

use std::sync::Arc;

use maltrail_sensor::metrics::Registry;
use maltrail_sensor::output::free_bytes;
use maltrail_sensor::stats::render;

#[test]
fn free_bytes_reports_a_real_figure_for_a_real_directory() {
    let dir = std::env::temp_dir();
    let free = free_bytes(&dir).expect("statvfs on a temp dir must succeed");
    assert!(free > 0, "a writable temp dir should have some space");
}

#[test]
fn free_bytes_is_none_for_a_path_that_does_not_exist() {
    // Must degrade to "unknown", never to a bogus 0 that would page someone at 3 a.m.
    let missing = std::env::temp_dir().join("maltrail-no-such-directory-ffffffff");
    assert!(free_bytes(&missing).is_none());
}

#[test]
fn the_free_space_gauge_is_exported_when_the_sensor_writes_locally() {
    let registry = Arc::new(Registry::new(1).with_log_dir(Some(std::env::temp_dir())));
    let body = render(&registry, 1.0);

    assert!(body.contains("# TYPE maltrail_log_dir_free_bytes gauge"), "{body}");
    let value: u64 = body
        .lines()
        .find(|l| l.starts_with("maltrail_log_dir_free_bytes "))
        .and_then(|l| l.rsplit(' ').next())
        .and_then(|v| v.parse().ok())
        .expect("the gauge must carry a numeric value");
    assert!(value > 0, "got {value}");
}

#[test]
fn the_gauge_is_absent_when_events_only_go_off_box() {
    // DISABLE_LOCAL_LOG_STORAGE: nothing is written here, so local free space is meaningless
    // and reporting 0 would produce a permanent false alarm.
    let registry = Arc::new(Registry::new(1).with_log_dir(None));
    let body = render(&registry, 1.0);
    assert!(!body.contains("maltrail_log_dir_free_bytes"), "{body}");
}

/// The metric that says detections were produced and then LOST. It must always be exported,
/// including while it is zero, or an alert on it silently never fires.
#[test]
fn the_lost_detection_counter_is_always_exported() {
    let registry = Arc::new(Registry::new(1));
    let body = render(&registry, 0.0);
    assert!(body.contains("maltrail_local_log_errors_total 0"), "{body}");
}
