//! Live-capture and PACKET_FANOUT tests.
//!
//! Unix only, and not incidentally: these inject packets through a raw socket, use a FIFO to
//! synchronise with the sensor, and join a Linux packet-socket fanout group. There is no Windows
//! equivalent of any of the three, so the file is gated rather than half-ported - the Windows
//! build gets the tests it can actually run instead of no test binary at all.
#![cfg(unix)]
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

/// The kernel's verdict on the source-hash program.
///
/// Everything else about source-affine fanout is provable without privileges: the DISTRIBUTION is
/// measured over the real corpus in `multi_worker_parity.rs`, and the PROGRAM is executed by an
/// interpreter in `capture::srcfanout`. What neither can answer is whether the kernel accepts the
/// program at all - `PACKET_FANOUT_CBPF` needs Linux 4.5+, and the in-kernel verifier is the only
/// authority on whether the instruction sequence is legal. That is what this asserts.
///
/// Note it also fails loudly if `PACKET_FANOUT_DATA` is refused, because a CBPF group with no
/// program attached demuxes every packet to worker 0 - a silent capture failure, and exactly the
/// outcome worth failing a build over.
#[test]
fn a_source_affine_fanout_group_is_accepted_by_the_kernel_when_privileged() {
    if !have_capture_privileges() {
        println!("[skip] needs root / CAP_NET_RAW to ask the kernel to load the program");
        return;
    }

    let mut cfg = test_config(2, "udp");
    cfg.capture_fanout_mode = FanoutMode::Source;
    let group = fanout::default_group(0).wrapping_add(7); // not the group the hash test uses

    let mut handles = Vec::new();
    for i in 0..2 {
        match Handle::open_live(&cfg, "lo", Some(group)) {
            Ok((handle, info)) => {
                assert_eq!(info.fanout_mode, FanoutMode::Source);
                assert_eq!(info.fanout_group, Some(group));
                handles.push(handle);
            }
            Err(e) => panic!(
                "worker {i} could not join a source-affine fanout group: {e}\n\
                 (PACKET_FANOUT_CBPF needs Linux 4.5+; a rejected program is a bug in srcfanout.rs)"
            ),
        }
    }
    assert_eq!(handles.len(), 2);

    for handle in handles.iter_mut() {
        // an idle loopback times out; that is a read, not an error
        if let Err(e) = handle.next_packet() {
            panic!("reading from a source-affine fanout socket failed: {e}");
        }
    }
    println!("[i] kernel accepted the source-hash cBPF program and formed a 2-socket group on lo");
}

/// Craft an IPv4/UDP packet with a chosen source address. The kernel fills the IP checksum when
/// it is zero under `IP_HDRINCL`, and an IPv4 UDP checksum is optional, so neither is computed.
fn udp_from(src: [u8; 4], dport: u16, payload: &[u8]) -> Vec<u8> {
    let total = 20 + 8 + payload.len();
    let mut p = Vec::with_capacity(total);
    p.extend_from_slice(&[0x45, 0x00]);
    p.extend_from_slice(&(total as u16).to_be_bytes());
    p.extend_from_slice(&[0, 0, 0, 0, 64, 17, 0, 0]); // id, frag, ttl, proto=UDP, csum=0
    p.extend_from_slice(&src);
    p.extend_from_slice(&[127, 0, 0, 1]);
    p.extend_from_slice(&40000u16.to_be_bytes());
    p.extend_from_slice(&dport.to_be_bytes());
    p.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    p.extend_from_slice(&[0, 0]);
    p.extend_from_slice(payload);
    p
}

/// The end-to-end claim, asked of the kernel rather than of a simulation.
///
/// `a_source_affine_fanout_group_is_accepted_by_the_kernel_when_privileged` proves the program is
/// LEGAL. It does not prove it DISTRIBUTES: a program that returns 0 for every packet - because
/// the kernel presented a packet layout neither branch matches - loads perfectly and funnels all
/// traffic to worker 0, which from the outside is indistinguishable from working.
///
/// So this sends real packets from many source addresses through a real fanout group and asserts
/// the two properties the whole feature rests on: one source is never split across workers, and
/// the workers are actually all used.
#[test]
fn source_affine_fanout_actually_separates_sources_in_the_kernel() {
    if !have_capture_privileges() {
        println!("[skip] needs root / CAP_NET_RAW to form the group and send from spoofed sources");
        return;
    }

    const WORKERS: usize = 4;
    const SOURCES: usize = 64;
    let dport: u16 = 24601;

    let mut cfg = test_config(WORKERS as u32, &format!("udp and dst port {dport}"));
    cfg.capture_fanout_mode = FanoutMode::Source;
    let group = fanout::default_group(0).wrapping_add(23);

    let mut handles = Vec::new();
    for i in 0..WORKERS {
        match Handle::open_live(&cfg, "lo", Some(group)) {
            Ok((h, info)) => {
                assert_eq!(info.fanout_mode, FanoutMode::Source);
                handles.push(h);
            }
            Err(e) => panic!("worker {i} could not join the source-affine group: {e}"),
        }
    }

    // raw socket with IP_HDRINCL so the source address is ours to choose
    // SAFETY: a socket() call with constant arguments; the fd is closed below.
    let raw = unsafe { libc::socket(libc::AF_INET, libc::SOCK_RAW, libc::IPPROTO_RAW) };
    assert!(raw >= 0, "raw socket: {}", std::io::Error::last_os_error());
    let one: libc::c_int = 1;
    // SAFETY: `one` is a live c_int of the size IP_HDRINCL expects.
    let rc = unsafe {
        libc::setsockopt(
            raw,
            libc::IPPROTO_IP,
            libc::IP_HDRINCL,
            &one as *const libc::c_int as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    assert_eq!(rc, 0, "IP_HDRINCL: {}", std::io::Error::last_os_error());

    // Built field by field from a zeroed struct rather than a literal: the BSDs and macOS carry a
    // leading `sin_len`, and their `sin_family` is a u8 where Linux's is a u16. A literal compiles
    // on exactly one of them, which is why this test file did not build for FreeBSD or macOS at
    // all - the sensor runs there, so its tests have to as well.
    // SAFETY: sockaddr_in is a plain repr(C) struct of integers; all-zero is a valid value.
    let mut dst: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    dst.sin_family = libc::AF_INET as _;
    dst.sin_port = dport.to_be();
    dst.sin_addr = libc::in_addr { s_addr: u32::from_be_bytes([127, 0, 0, 1]).to_be() };
    #[cfg(any(target_os = "freebsd", target_os = "netbsd", target_os = "openbsd", target_vendor = "apple"))]
    {
        dst.sin_len = std::mem::size_of::<libc::sockaddr_in>() as u8;
    }

    // Each source sends several packets on DIFFERENT source ports, so a flow hash would scatter
    // them and only source affinity can keep them together.
    for host in 0..SOURCES {
        for n in 0..4u8 {
            let pkt = udp_from([127, 9, (host / 256) as u8, (host % 256) as u8], dport, &[n; 16]);
            // SAFETY: `pkt` and `dst` are live for the call and correctly sized.
            let sent = unsafe {
                libc::sendto(
                    raw,
                    pkt.as_ptr() as *const libc::c_void,
                    pkt.len(),
                    0,
                    &dst as *const libc::sockaddr_in as *const libc::sockaddr,
                    std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
                )
            };
            assert!(sent > 0, "sendto: {}", std::io::Error::last_os_error());
        }
    }

    // Drain every worker, round-robin, until nothing new arrives for a while.
    //
    // The handles are non-blocking and the TPACKET_V3 ring only hands over a block when its retire
    // timeout expires, so a read taken straight after sendto() is empty BY CONSTRUCTION. The first
    // version of this loop treated that first empty read as "this worker is done" and concluded
    // the group had received nothing at all.
    let mut placement: std::collections::HashMap<[u8; 4], std::collections::BTreeSet<usize>> = Default::default();
    let mut per_worker = [0usize; WORKERS];
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    let mut quiet_rounds = 0;
    while std::time::Instant::now() < deadline && quiet_rounds < 20 {
        let mut got = 0usize;
        for (idx, handle) in handles.iter_mut().enumerate() {
            for _ in 0..(SOURCES * 8) {
                match handle.next_packet() {
                    Ok(Some(c)) => {
                        // loopback presents an Ethernet header; fall back to a bare IP header
                        let data = c.data;
                        let ip = if data.len() > 14 && data[14] >> 4 == 4 {
                            14
                        } else if !data.is_empty() && data[0] >> 4 == 4 {
                            0
                        } else {
                            continue;
                        };
                        if data.len() < ip + 20 {
                            continue;
                        }
                        let mut src = [0u8; 4];
                        src.copy_from_slice(&data[ip + 12..ip + 16]);
                        if src[0] != 127 || src[1] != 9 {
                            continue; // not ours
                        }
                        placement.entry(src).or_default().insert(idx);
                        per_worker[idx] += 1;
                        got += 1;
                    }
                    Ok(None) => break,
                    Err(e) => panic!("reading worker {idx}: {e}"),
                }
            }
        }
        if got == 0 {
            quiet_rounds += 1;
            std::thread::sleep(std::time::Duration::from_millis(25));
        } else {
            quiet_rounds = 0;
        }
    }

    // SAFETY: closing a descriptor we own.
    unsafe { libc::close(raw) };

    assert!(
        !placement.is_empty(),
        "no packets captured; the fanout group received nothing (per-worker: {per_worker:?})"
    );

    // 1. affinity: a source is never split
    let split: Vec<_> = placement.iter().filter(|(_, w)| w.len() > 1).collect();
    assert!(split.is_empty(), "sources split across workers despite source-affine fanout: {split:?}");

    // 2. distribution: the program must not be answering 0 for everything. THIS is the assertion
    //    that catches a packet layout the program does not understand - it loads, it is legal, and
    //    it silently funnels every packet to one worker.
    let used = per_worker.iter().filter(|&&n| n > 0).count();
    assert!(
        used > 1,
        "every packet landed on {used} worker(s): {per_worker:?} - the program is not reading the source address"
    );

    println!("[i] {} sources over {WORKERS} workers: {per_worker:?}, none split", placement.len());
}
