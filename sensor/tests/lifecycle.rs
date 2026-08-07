//! Worker lifecycle: a sensor that has stopped capturing must say so.
//!
//! These guard ROADMAP Gate 1.1. The bug they exist for: `worker::run` returned `()`, `main`
//! discarded every join result, and the process exited 0 no matter how a worker ended. A dead
//! capture worker therefore looked identical to a clean shutdown — `Restart=on-failure` never
//! fired, `maltrail_up` was the literal constant 1, and the host silently stopped being
//! monitored while its systemd unit stayed green.

use std::sync::atomic::Ordering;
use std::sync::Arc;

use maltrail_sensor::capture::Handle;
use maltrail_sensor::metrics::Registry;
use maltrail_sensor::stats::render;
use maltrail_sensor::worker::{WorkerError, WorkerExit};

/// Pull `name{...} value` (or `name value`) out of a Prometheus exposition body.
fn metric(body: &str, name: &str) -> Option<String> {
    body.lines()
        .filter(|line| !line.starts_with('#'))
        .find(|line| line.starts_with(name) && matches!(line.as_bytes().get(name.len()), Some(b' ') | Some(b'{')))
        .and_then(|line| line.rsplit(' ').next().map(|v| v.to_string()))
}

#[test]
fn up_is_zero_until_a_worker_is_capturing() {
    let registry = Arc::new(Registry::new(2));

    // Nothing has started yet. This is the state the old code reported as `maltrail_up 1`.
    let body = render(&registry, 0.0);
    assert_eq!(metric(&body, "maltrail_up").as_deref(), Some("0"), "{body}");
    assert_eq!(metric(&body, "maltrail_workers_alive").as_deref(), Some("0"));
    assert_eq!(metric(&body, "maltrail_workers_total").as_deref(), Some("2"));

    registry.slots[0].mark_alive();
    let body = render(&registry, 1.0);
    assert_eq!(metric(&body, "maltrail_up").as_deref(), Some("1"), "{body}");
    assert_eq!(metric(&body, "maltrail_workers_alive").as_deref(), Some("1"));

    // Per-worker liveness distinguishes a partial blind spot from a total outage: with
    // PACKET_FANOUT each worker owns a slice of the traffic.
    assert!(body.contains("maltrail_worker_alive{worker=\"0\"} 1"), "{body}");
    assert!(body.contains("maltrail_worker_alive{worker=\"1\"} 0"), "{body}");
}

#[test]
fn up_goes_back_to_zero_when_every_worker_dies() {
    let registry = Arc::new(Registry::new(2));
    registry.slots[0].mark_alive();
    registry.slots[1].mark_alive();
    assert_eq!(metric(&render(&registry, 1.0), "maltrail_up").as_deref(), Some("1"));

    // One dies: still monitoring, but only partially.
    registry.slots[0].mark_dead();
    let body = render(&registry, 2.0);
    assert_eq!(metric(&body, "maltrail_up").as_deref(), Some("1"), "{body}");
    assert_eq!(metric(&body, "maltrail_workers_alive").as_deref(), Some("1"));

    // All dead: this host is not being monitored, and the metric has to admit it.
    registry.slots[1].mark_dead();
    let body = render(&registry, 3.0);
    assert_eq!(metric(&body, "maltrail_up").as_deref(), Some("0"), "{body}");
    assert_eq!(metric(&body, "maltrail_workers_alive").as_deref(), Some("0"));
}

#[test]
fn heartbeat_advances_and_is_exported_per_worker() {
    let registry = Arc::new(Registry::new(1));
    assert_eq!(registry.slots[0].last_heartbeat(), 0, "no tick has happened yet");

    registry.slots[0].mark_alive();
    let first = registry.slots[0].last_heartbeat();
    assert!(first > 0, "mark_alive must seed the heartbeat");

    let body = render(&registry, 1.0);
    assert!(body.contains(&format!("maltrail_worker_last_heartbeat_seconds{{worker=\"0\"}} {first}")), "{body}");

    // A wedged worker keeps `alive` but stops advancing this, which is the only external way to
    // tell "stuck inside libpcap" from "idle interface".
    registry.slots[0].heartbeat();
    assert!(registry.slots[0].last_heartbeat() >= first);
}

/// A worker is only "alive" between entering and leaving its loop — and it is marked dead
/// however it leaves, including the paths that used to vanish silently.
#[test]
fn offline_replay_reports_eof_and_marks_itself_dead() {
    let pcap = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests").join("corpus").join("icmp.pcap");
    if !pcap.is_file() {
        eprintln!("[skip] {} is not present", pcap.display());
        return;
    }

    let registry = Arc::new(Registry::new(1));
    let ctx = maltrail_sensor::testkit::worker_context(&registry, 0);
    let handle = Handle::open_offline(&pcap).expect("open corpus pcap");

    let outcome = maltrail_sensor::worker::run(handle, ctx);

    assert_eq!(outcome.expect("a readable pcap is not a failure"), WorkerExit::OfflineEof);
    assert!(!registry.slots[0].is_alive(), "the worker must not still claim to be capturing");
    assert!(registry.slots[0].last_heartbeat() > 0, "it ran, so it must have left a heartbeat");
    assert!(registry.slots[0].packets_received.load(Ordering::Relaxed) > 0, "the replay should have seen packets");

    // Reaching EOF is an expected ending, so it must NOT be reported as a failure.
    assert_eq!(metric(&render(&registry, 1.0), "maltrail_up").as_deref(), Some("0"));
}

/// The two failure kinds have to stay distinguishable in the operator-facing text: "capture
/// failed" and "panicked" call for different responses (check the interface vs. file a bug).
#[test]
fn worker_errors_describe_themselves() {
    assert_eq!(WorkerError::Capture("no such device".into()).to_string(), "capture failed: no such device");
    assert_eq!(WorkerError::Panic.to_string(), "worker thread panicked");
}
