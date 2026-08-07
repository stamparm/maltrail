//! Multi-file offline replay shares one detection state (ROADMAP Gate 1.3).
//!
//! The contradiction this resolves: the binary gave every `-r` file its own worker AND its own
//! `WorkerState`, while `tests/replay.rs` asserted that several pcaps replayed through one
//! worker behave like a single stream. Only the test was true. In the binary, evidence split
//! across a capture set never accumulated — two files that between them cross a scan threshold
//! each stayed under it and nothing fired — and the result depended on how the per-file threads
//! happened to interleave, so a replay was not even deterministic.
//!
//! Decision (ROADMAP 1.3): offline replay processes files sequentially through one state. This
//! is a black-box test of the real binary, because the bug lived in `main`, not in the harness.

use std::path::PathBuf;
use std::process::Command;

fn binary() -> PathBuf {
    let mut path = std::env::current_exe().expect("test binary path");
    path.pop();
    if path.ends_with("deps") {
        path.pop();
    }
    path.join("maltrail-sensor")
}

/// `PORT_SCANNING_THRESHOLD` is 10 distinct destination ports from one source.
const THRESHOLD: u16 = 10;

fn write_pcap(path: &PathBuf, packets: &[(u32, Vec<u8>)]) {
    use std::io::Write;
    let mut out = Vec::new();
    out.extend_from_slice(&0xa1b2c3d4u32.to_le_bytes()); // magic
    out.extend_from_slice(&2u16.to_le_bytes()); // major
    out.extend_from_slice(&4u16.to_le_bytes()); // minor
    out.extend_from_slice(&0u32.to_le_bytes()); // thiszone
    out.extend_from_slice(&0u32.to_le_bytes()); // sigfigs
    out.extend_from_slice(&65535u32.to_le_bytes()); // snaplen
    out.extend_from_slice(&1u32.to_le_bytes()); // DLT_EN10MB
    for (sec, frame) in packets {
        out.extend_from_slice(&sec.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&(frame.len() as u32).to_le_bytes());
        out.extend_from_slice(&(frame.len() as u32).to_le_bytes());
        out.extend_from_slice(frame);
    }
    std::fs::File::create(path).unwrap().write_all(&out).unwrap();
}

/// One Ethernet+IPv4+TCP SYN from 10.0.0.9 to 66.66.66.66:`port`.
fn syn(port: u16) -> Vec<u8> {
    let mut tcp = Vec::new();
    tcp.extend_from_slice(&40000u16.to_be_bytes()); // sport
    tcp.extend_from_slice(&port.to_be_bytes()); // dport
    tcp.extend_from_slice(&0u32.to_be_bytes()); // seq
    tcp.extend_from_slice(&0u32.to_be_bytes()); // ack
    tcp.push(0x50); // data offset 5
    tcp.push(0x02); // SYN
    tcp.extend_from_slice(&8192u16.to_be_bytes());
    tcp.extend_from_slice(&0u16.to_be_bytes()); // checksum (unchecked)
    tcp.extend_from_slice(&0u16.to_be_bytes()); // urgent

    let total = 20 + tcp.len();
    let mut ip = vec![0x45, 0x00];
    ip.extend_from_slice(&(total as u16).to_be_bytes());
    ip.extend_from_slice(&0u16.to_be_bytes()); // id
    ip.extend_from_slice(&0u16.to_be_bytes()); // flags/frag
    ip.push(64); // ttl
    ip.push(6); // TCP
    ip.extend_from_slice(&0u16.to_be_bytes()); // checksum (unchecked)
    ip.extend_from_slice(&[10, 0, 0, 9]);
    ip.extend_from_slice(&[66, 66, 66, 66]);
    ip.extend_from_slice(&tcp);

    let mut frame = vec![0x00; 12];
    frame.extend_from_slice(&[0x08, 0x00]); // IPv4
    frame.extend_from_slice(&ip);
    frame
}

struct Fixture {
    dir: PathBuf,
}

impl Fixture {
    fn new(name: &str) -> Fixture {
        let dir = std::env::temp_dir().join(format!("maltrail-multipcap-{}-{}", std::process::id(), name));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("logs")).unwrap();
        std::fs::write(dir.join("trails.csv"), "203.0.113.77,placeholder,(static)\n").unwrap();
        std::fs::write(
            dir.join("maltrail.conf"),
            format!(
                "MONITOR_INTERFACE any\n\
                 CAPTURE_BUFFER 1MB\n\
                 PROCESS_COUNT 1\n\
                 UPDATE_PERIOD 999999999\n\
                 DISABLE_CHECK_SUDO true\n\
                 DISABLE_TRAIL_UPDATES true\n\
                 USE_CONDENSED_STORAGE false\n\
                 USE_HEURISTICS true\n\
                 SENSOR_NAME multipcap\n\
                 LOG_DIR {}\n\
                 TRAILS_FILE {}\n",
                dir.join("logs").display(),
                dir.join("trails.csv").display()
            ),
        )
        .unwrap();
        Fixture { dir }
    }

    /// Replay the given files in one invocation; return the event lines produced.
    fn replay(&self, files: &[PathBuf]) -> Vec<String> {
        let list = files.iter().map(|p| p.to_str().unwrap()).collect::<Vec<_>>().join(",");
        let status = Command::new(binary())
            .arg("-c")
            .arg(self.dir.join("maltrail.conf"))
            .arg("-r")
            .arg(&list)
            .arg("-q")
            .output()
            .expect("run maltrail-sensor");
        assert!(status.status.success(), "replay failed: {}", String::from_utf8_lossy(&status.stderr));

        let mut lines = Vec::new();
        for entry in std::fs::read_dir(self.dir.join("logs")).unwrap().flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) == Some("log")
                && path.file_name().and_then(|n| n.to_str()) != Some("error.log")
            {
                lines.extend(std::fs::read_to_string(&path).unwrap_or_default().lines().map(|l| l.to_string()));
            }
        }
        lines
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

#[test]
fn evidence_split_across_two_pcaps_still_adds_up() {
    if !binary().is_file() {
        eprintln!("[skip] {} not built", binary().display());
        return;
    }
    let fixture = Fixture::new("split");

    // Neither half reaches the port-scanning threshold on its own; together they pass it.
    let half = THRESHOLD / 2 + 1;
    let a = fixture.dir.join("a.pcap");
    let b = fixture.dir.join("b.pcap");
    write_pcap(&a, &(0..half).map(|i| (1_700_000_000 + i as u32, syn(1000 + i))).collect::<Vec<_>>());
    write_pcap(&b, &(0..half).map(|i| (1_700_000_010 + i as u32, syn(2000 + i))).collect::<Vec<_>>());

    let only_a = fixture.replay(std::slice::from_ref(&a));
    assert!(
        !only_a.iter().any(|l| l.contains("port scanning")),
        "half the probes must NOT trip the threshold, or this test proves nothing:\n{only_a:#?}"
    );

    let _ = std::fs::remove_dir_all(fixture.dir.join("logs"));
    std::fs::create_dir_all(fixture.dir.join("logs")).unwrap();

    let both = fixture.replay(&[a, b]);
    assert!(
        both.iter().any(|l| l.contains("port scanning")),
        "the two files together cross the threshold and must be detected as one stream:\n{both:#?}"
    );
}

#[test]
fn a_replay_of_the_same_files_is_deterministic() {
    if !binary().is_file() {
        eprintln!("[skip] {} not built", binary().display());
        return;
    }
    let fixture = Fixture::new("determinism");
    let a = fixture.dir.join("a.pcap");
    let b = fixture.dir.join("b.pcap");
    write_pcap(&a, &(0..6u16).map(|i| (1_700_000_000 + i as u32, syn(1000 + i))).collect::<Vec<_>>());
    write_pcap(&b, &(0..6u16).map(|i| (1_700_000_010 + i as u32, syn(2000 + i))).collect::<Vec<_>>());

    // With a worker per file this raced: which file's state saw which packet depended on thread
    // scheduling, so two runs of the same command could differ.
    let first = fixture.replay(&[a.clone(), b.clone()]);
    let _ = std::fs::remove_dir_all(fixture.dir.join("logs"));
    std::fs::create_dir_all(fixture.dir.join("logs")).unwrap();
    let second = fixture.replay(&[a, b]);

    let strip = |lines: Vec<String>| -> Vec<String> {
        // Drop the leading timestamp field; everything after it must match exactly.
        lines.into_iter().filter_map(|l| l.split_once("\" ").map(|(_, rest)| rest.to_string())).collect()
    };
    assert_eq!(strip(first), strip(second), "the same capture set must replay identically");
}
