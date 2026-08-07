//! Live-capture and PACKET_FANOUT tests.
//!
//! These adapt to privileges: without `CAP_NET_RAW` they assert the *failure* path is clean
//! and well-signposted (no panic, a permission error, and — critically — no silent fallback to
//! independent sockets when fanout was requested). With privileges they additionally open a
//! real fanout group and check that every socket in it can be created and joined.
//!
//! The end-to-end "distributed, not duplicated" proof needs traffic and root, so it lives in
//! `sensor/tools/fanout_check.py`; run it once per deployment.

use std::os::unix::io::AsRawFd;
use std::path::PathBuf;

use maltrail_sensor::capture::{fanout, CaptureError, Handle};
use maltrail_sensor::config::{Config, FanoutMode};

fn have_capture_privileges() -> bool {
    // SAFETY: geteuid() has no preconditions.
    if unsafe { libc::geteuid() } == 0 {
        return true;
    }
    // A file capability or an ambient CAP_NET_RAW also works; probing is the only reliable way.
    pcap::Capture::from_device("lo").and_then(|d| d.timeout(50).snaplen(128).open()).is_ok()
}

fn test_config(workers: u32, filter: &str) -> Config {
    let dir = std::env::temp_dir().join("mt-capture-live");
    std::fs::create_dir_all(&dir).unwrap();
    let log_dir = dir.join("logs");
    std::fs::create_dir_all(&log_dir).unwrap();
    let trails = dir.join("trails.csv");
    std::fs::write(&trails, "never-matches.invalid,test,(static)\n").unwrap();
    let config = dir.join("live.conf");
    std::fs::write(
        &config,
        format!(
            "MONITOR_INTERFACE lo\n\
             CAPTURE_BUFFER 1MB\n\
             PROCESS_COUNT 1\n\
             UPDATE_PERIOD 999999999\n\
             DISABLE_CHECK_SUDO true\n\
             USE_CONDENSED_STORAGE false\n\
             CAPTURE_WORKERS {workers}\n\
             CAPTURE_TIMEOUT 50\n\
             CAPTURE_FILTER {filter}\n\
             LOG_DIR {}\n\
             TRAILS_FILE {}\n",
            log_dir.display(),
            trails.display()
        ),
    )
    .unwrap();
    let mut cfg = Config::load(&config).expect("live test config");
    cfg.root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).parent().unwrap().to_path_buf();
    cfg
}

#[test]
fn opening_a_live_handle_either_works_or_fails_cleanly() {
    let cfg = test_config(1, "udp");
    match Handle::open_live(&cfg, "lo", None) {
        Ok((handle, info)) => {
            assert!(!handle.is_offline());
            assert!(info.fanout_group.is_none());
            // loopback is DLT_EN10MB on Linux
            assert!(handle.datalink() >= 0);
        }
        Err(e) => {
            let text = e.to_string();
            assert!(matches!(e, CaptureError::Permission(_) | CaptureError::Pcap(_)), "unexpected error kind: {text}");
            println!("[skip] no capture privileges: {text}");
        }
    }
}

#[test]
fn a_bad_bpf_filter_is_reported_not_ignored() {
    // A filter that cannot compile must surface as an error rather than being silently
    // dropped (which would leave the sensor capturing everything). The offline equivalent is
    // covered unprivileged in src/capture/mod.rs; here we check the live path when we can.
    if !have_capture_privileges() {
        println!("[skip] needs root / CAP_NET_RAW for the live filter path");
        return;
    }
    let cfg = test_config(1, "this is not a valid filter !!!");
    match Handle::open_live(&cfg, "lo", None) {
        Ok(_) => panic!("an invalid BPF filter must not open successfully"),
        Err(e) => println!("[i] invalid filter rejected: {e}"),
    }
}

#[test]
fn fanout_is_refused_on_a_non_packet_socket() {
    // The guard that makes "fanout requested but unavailable" a hard error rather than a
    // silent fallback to duplicate delivery.
    let sock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let err = fanout::join(sock.as_raw_fd(), 4242, FanoutMode::Hash, 0).unwrap_err();
    assert!(err.to_string().contains("AF_PACKET"), "{err}");
}

#[test]
fn fanout_group_ids_are_stable_and_per_interface() {
    assert_eq!(fanout::default_group(0), fanout::default_group(0));
    assert_ne!(fanout::default_group(0), fanout::default_group(1));
}

#[test]
fn a_real_fanout_group_can_be_formed_when_privileged() {
    if !have_capture_privileges() {
        println!("[skip] needs root / CAP_NET_RAW; run tools/fanout_check.py for the full proof");
        return;
    }
    let cfg = test_config(4, "udp");
    let group = fanout::default_group(0);
    let mut handles = Vec::new();
    for i in 0..4 {
        match Handle::open_live(&cfg, "lo", Some(group)) {
            Ok((handle, info)) => {
                assert_eq!(info.fanout_group, Some(group));
                assert_eq!(info.fanout_mode, FanoutMode::Hash);
                handles.push(handle);
            }
            Err(e) => panic!("worker {i} could not join fanout group {group}: {e}"),
        }
    }
    assert_eq!(handles.len(), 4, "all four sockets must join the same group");

    // Each handle must be independently readable (a timeout is the expected result on an idle
    // loopback, and must NOT be reported as an error).
    for handle in handles.iter_mut() {
        match handle.next_packet() {
            Ok(_) => {}
            Err(e) => panic!("reading from a fanout socket failed: {e}"),
        }
    }
    println!("[i] formed a 4-socket PACKET_FANOUT group (hash) on lo");
}

#[test]
fn mismatched_fanout_modes_in_one_group_are_rejected_by_the_kernel() {
    if !have_capture_privileges() {
        println!("[skip] needs root / CAP_NET_RAW");
        return;
    }
    // The kernel refuses to mix modes within a group; the sensor must surface that instead of
    // proceeding with a half-formed group.
    let mut cfg = test_config(2, "udp");
    let group = fanout::default_group(7);
    let first = Handle::open_live(&cfg, "lo", Some(group)).expect("first socket");
    cfg.capture_fanout_mode = FanoutMode::Lb;
    let second = Handle::open_live(&cfg, "lo", Some(group));
    assert!(second.is_err(), "joining one group with two different modes must fail, not silently succeed");
    drop(first);
}
