//! The sensor must REFRESH `trails.csv` itself, like `sensor.py:init():update_timer()` does.
//!
//! This suite exists because of a real miss: the sensor originally only ever *read* the trails
//! file, so it silently ran on a four-week-old snapshot and detected a live asyncrat domain
//! (`511mon.kozow.com`) merely as its dynamic-DNS parent — the IOC had been added to
//! `trails/static/malware/asyncrat.txt` two weeks after that file was generated.
//!
//! These tests drive the real release binary, because the behaviour under test is a startup
//! side effect (spawning Maltrail's own updater), not a library call.

use std::path::{Path, PathBuf};
use std::process::Command;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).parent().unwrap().to_path_buf()
}

/// The release binary, if it has been built. Returns `None` so a plain `cargo test` (which does
/// not necessarily build the binary in release mode) skips rather than fails.
fn sensor_binary() -> Option<PathBuf> {
    for profile in ["release", "release-lto", "debug"] {
        let path = repo_root().join("sensor").join("target").join(profile).join("maltrail-sensor");
        if path.is_file() {
            return Some(path);
        }
    }
    None
}

struct Fixture {
    dir: PathBuf,
    config: PathBuf,
    trails: PathBuf,
}

impl Fixture {
    fn new(name: &str, extra: &str) -> Fixture {
        let dir = std::env::temp_dir().join(format!("mt-trail-update-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("logs")).unwrap();
        let trails = dir.join("trails.csv");
        let config = dir.join("sensor.conf");
        std::fs::write(
            &config,
            format!(
                "MONITOR_INTERFACE any\n\
                 CAPTURE_BUFFER 1MB\n\
                 PROCESS_COUNT 1\n\
                 UPDATE_PERIOD 86400\n\
                 USE_FEED_UPDATES false\n\
                 DISABLE_CHECK_SUDO true\n\
                 USE_HEURISTICS true\n\
                 USE_CONDENSED_STORAGE false\n\
                 SENSOR_NAME update-test\n\
                 LOG_DIR {}\n\
                 TRAILS_FILE {}\n\
                 {extra}\n",
                dir.join("logs").display(),
                trails.display()
            ),
        )
        .unwrap();
        Fixture { dir, config, trails }
    }

    /// Replay one pcap and return the sensor's stdout+stderr.
    fn run(&self, pcap: &Path) -> String {
        let binary = sensor_binary().expect("binary");
        let output = Command::new(binary)
            .current_dir(repo_root())
            .arg("-r")
            .arg(pcap)
            .arg("-c")
            .arg(&self.config)
            .arg("--offline")
            .output()
            .expect("run the sensor");
        let mut text = String::from_utf8_lossy(&output.stdout).to_string();
        text.push_str(&String::from_utf8_lossy(&output.stderr));
        text
    }

    fn events(&self) -> Vec<String> {
        let mut out = Vec::new();
        let Ok(entries) = std::fs::read_dir(self.dir.join("logs")) else { return out };
        for entry in entries.filter_map(|e| e.ok()) {
            let path = entry.path();
            if path.extension().map(|e| e == "log").unwrap_or(false)
                && path.file_name().map(|n| n != "error.log").unwrap_or(false)
            {
                if let Ok(text) = std::fs::read_to_string(&path) {
                    out.extend(text.lines().map(|l| l.to_string()));
                }
            }
        }
        out
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// A DNS query for a name that is present in the repository's static trails but would be absent
/// from any stale trails file.
fn dns_query_pcap(dir: &Path, name: &str) -> PathBuf {
    use maltrail_sensor::testkit::{dns_query, eth, ipv4, udp};
    let packet = eth(&ipv4(17, "10.13.13.2", "1.1.1.1", &udp(45857, 53, &dns_query(name, 1, 1, 0x0100))), 0x0800, None);
    let path = dir.join("query.pcap");
    let mut data: Vec<u8> = Vec::new();
    data.extend_from_slice(&0xa1b2c3d4u32.to_le_bytes());
    data.extend_from_slice(&2u16.to_le_bytes());
    data.extend_from_slice(&4u16.to_le_bytes());
    data.extend_from_slice(&0i32.to_le_bytes());
    data.extend_from_slice(&0u32.to_le_bytes());
    data.extend_from_slice(&65535u32.to_le_bytes());
    data.extend_from_slice(&1u32.to_le_bytes());
    data.extend_from_slice(&1_700_000_000u32.to_le_bytes());
    data.extend_from_slice(&0u32.to_le_bytes());
    data.extend_from_slice(&(packet.len() as u32).to_le_bytes());
    data.extend_from_slice(&(packet.len() as u32).to_le_bytes());
    data.extend_from_slice(&packet);
    std::fs::write(&path, data).unwrap();
    path
}

/// A trail that exists in the static trail files, with the info the CSV should carry for it.
/// Chosen to be the exact case that was missed in the field.
const STATIC_TRAIL: &str = "511mon.kozow.com";
const STATIC_TRAIL_INFO: &str = "asyncrat (malware)";
/// Its dynamic-DNS parent, which is what a stale sensor matches instead.
const PARENT_INFO: &str = "dynamic domain (suspicious)";

/// Push a file's mtime into the past, so it looks like the snapshot it is standing in for.
/// (`File::set_modified` would need Rust 1.75; the crate's MSRV is 1.74, so use `utimes`.)
fn backdate(path: &Path, secs: u64) {
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
    let when = libc::timeval { tv_sec: (now - secs) as libc::time_t, tv_usec: 0 };
    let times = [when, when];
    let c_path = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
    // SAFETY: `c_path` is NUL-terminated and `times` is a two-element array, as utimes(2) wants.
    let rc = unsafe { libc::utimes(c_path.as_ptr(), times.as_ptr()) };
    assert_eq!(rc, 0, "utimes({}) failed", path.display());
}

fn static_trail_is_in_the_repository() -> bool {
    let path = repo_root().join("trails").join("static").join("malware").join("asyncrat.txt");
    std::fs::read_to_string(path).map(|t| t.lines().any(|l| l.trim() == STATIC_TRAIL)).unwrap_or(false)
}

#[test]
fn a_missing_trails_file_is_built_at_startup() {
    let Some(_) = sensor_binary() else {
        println!("[skip] build the sensor first (cargo build --release)");
        return;
    };
    let fixture = Fixture::new("missing", "");
    assert!(!fixture.trails.exists());
    let pcap = dns_query_pcap(&fixture.dir, "example.org");
    let output = fixture.run(&pcap);
    assert!(fixture.trails.is_file(), "the sensor must build TRAILS_FILE at startup like sensor.py does.\n{output}");
    let size = std::fs::metadata(&fixture.trails).unwrap().len();
    assert!(size > 1_000_000, "the built trails file looks too small ({size} bytes)\n{output}");
}

#[test]
fn a_stale_trails_file_is_refreshed_and_new_static_iocs_are_detected() {
    // THE regression test for the field miss. A trails file that predates a static IOC must be
    // refreshed, and the IOC must then be detected with its own info - not merely as its parent.
    let Some(_) = sensor_binary() else {
        println!("[skip] build the sensor first (cargo build --release)");
        return;
    };
    if !static_trail_is_in_the_repository() {
        println!("[skip] {STATIC_TRAIL} is no longer in trails/static/malware/asyncrat.txt");
        return;
    }

    let fixture = Fixture::new("stale", "");
    // Reproduce the field situation: a trails file generated weeks ago that knows the dynamic-DNS
    // parent but not the newer IOC. The age matters — `core.update.update_trails()` rebuilds when
    // the file is older than UPDATE_PERIOD or older than any trail file, so a freshly written
    // stand-in would (correctly) be left alone.
    std::fs::write(&fixture.trails, format!("kozow.com,{PARENT_INFO},(static)\n")).unwrap();
    backdate(&fixture.trails, 30 * 86400);
    let stale_len = std::fs::metadata(&fixture.trails).unwrap().len();

    let pcap = dns_query_pcap(&fixture.dir, STATIC_TRAIL);
    let output = fixture.run(&pcap);

    let fresh_len = std::fs::metadata(&fixture.trails).unwrap().len();
    assert!(fresh_len > stale_len, "the stale trails file was not refreshed\n{output}");

    let events = fixture.events();
    assert_eq!(events.len(), 1, "expected exactly one detection, got {events:?}\n{output}");
    assert!(
        events[0].contains(STATIC_TRAIL) && events[0].contains(STATIC_TRAIL_INFO),
        "the refreshed trails must detect {STATIC_TRAIL} as {STATIC_TRAIL_INFO:?}, got:\n{}\n{output}",
        events[0]
    );
    assert!(
        !events[0].contains(PARENT_INFO),
        "matching only the dynamic-DNS parent means the trails were stale:\n{}",
        events[0]
    );
}

#[test]
fn disabling_updates_is_honoured_and_flagged() {
    let Some(_) = sensor_binary() else {
        println!("[skip] build the sensor first (cargo build --release)");
        return;
    };
    let fixture = Fixture::new("disabled", "DISABLE_TRAIL_UPDATES true");
    std::fs::write(&fixture.trails, "kozow.com,dynamic domain (suspicious),(static)\n").unwrap();
    let before = std::fs::metadata(&fixture.trails).unwrap().len();

    let pcap = dns_query_pcap(&fixture.dir, STATIC_TRAIL);
    let output = fixture.run(&pcap);

    assert_eq!(
        std::fs::metadata(&fixture.trails).unwrap().len(),
        before,
        "DISABLE_TRAIL_UPDATES must leave the trails file alone\n{output}"
    );
    assert!(output.contains("trail updates disabled"), "the operator must be told\n{output}");
}

#[test]
fn an_old_trails_file_is_reported_as_stale() {
    // With updates disabled and an old file, the sensor must say so: an old trails file looks
    // perfectly healthy while quietly missing everything added since.
    let Some(_) = sensor_binary() else {
        println!("[skip] build the sensor first (cargo build --release)");
        return;
    };
    let fixture = Fixture::new("stale-warn", "DISABLE_TRAIL_UPDATES true\nUPDATE_PERIOD 3600");
    std::fs::write(&fixture.trails, "kozow.com,dynamic domain (suspicious),(static)\n").unwrap();
    backdate(&fixture.trails, 30 * 86400);

    let pcap = dns_query_pcap(&fixture.dir, "example.org");
    let output = fixture.run(&pcap);
    assert!(
        output.contains("day(s) old") && output.contains("NOT being detected"),
        "a month-old trails file must be flagged loudly\n{output}"
    );
}

#[test]
fn the_updater_uses_maltrails_own_code() {
    // Guards against the update logic being reimplemented (and therefore drifting) in Rust.
    let script = repo_root().join("sensor").join("tools").join("update_trails.py");
    let text = std::fs::read_to_string(&script).expect("tools/update_trails.py");
    assert!(text.contains("from core.update import update_ipcat, update_trails"));
    assert!(text.contains("update_trails(offline=True)"), "offline mode must rebuild from static trails");
    assert!(text.contains("check_connection"), "connectivity fallback must match sensor.py");
}

// --- `-T` / --test-config -------------------------------------------------------------------

/// The configuration test must be usable as a deployment gate: exit 0 when a configuration would
/// work, non-zero when it would not, and never modify anything.
#[test]
fn config_test_passes_a_good_configuration_and_changes_nothing() {
    let Some(binary) = sensor_binary() else {
        println!("[skip] build the sensor first (cargo build --release)");
        return;
    };
    let fixture = Fixture::new("selftest-ok", "DISABLE_TRAIL_UPDATES true");
    std::fs::write(&fixture.trails, "evil.example,malware (test),(static)\n").unwrap();
    let before = std::fs::metadata(&fixture.trails).unwrap().len();

    let out = Command::new(&binary).current_dir(repo_root()).arg("-T").arg("-c").arg(&fixture.config).output().unwrap();
    let text = String::from_utf8_lossy(&out.stdout).to_string() + &String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "a workable configuration must pass:\n{text}");
    assert!(text.contains("configuration test PASSED"), "{text}");
    assert!(text.contains("capture filter") && text.contains("whitelist") && text.contains("trails"), "{text}");
    assert_eq!(
        std::fs::metadata(&fixture.trails).unwrap().len(),
        before,
        "a configuration TEST must not rewrite the trails file"
    );
}

#[test]
fn config_test_fails_a_broken_configuration() {
    let Some(binary) = sensor_binary() else {
        println!("[skip] build the sensor first (cargo build --release)");
        return;
    };
    // Missing trails file + a log directory that does not exist: both fatal for detection.
    let fixture = Fixture::new("selftest-bad", "DISABLE_TRAIL_UPDATES true\nLOG_DIR /nonexistent/maltrail-logs");
    let out = Command::new(&binary).current_dir(repo_root()).arg("-T").arg("-c").arg(&fixture.config).output().unwrap();
    let text = String::from_utf8_lossy(&out.stdout).to_string() + &String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success(), "a broken configuration must exit non-zero:\n{text}");
    assert!(text.contains("configuration test FAILED"), "{text}");
    assert!(text.contains("log directory"), "the unusable log directory must be named:\n{text}");
    assert!(text.contains("detect NOTHING"), "the missing trails file must be called out:\n{text}");
}

#[test]
fn config_test_rejects_an_invalid_capture_filter() {
    let Some(binary) = sensor_binary() else {
        println!("[skip] build the sensor first (cargo build --release)");
        return;
    };
    // A BPF filter that does not compile would otherwise only surface at capture time.
    let fixture = Fixture::new("selftest-bpf", "DISABLE_TRAIL_UPDATES true\nCAPTURE_FILTER not a valid filter !!!");
    std::fs::write(&fixture.trails, "evil.example,malware (test),(static)\n").unwrap();
    let out = Command::new(&binary).current_dir(repo_root()).arg("-T").arg("-c").arg(&fixture.config).output().unwrap();
    let text = String::from_utf8_lossy(&out.stdout).to_string() + &String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success(), "an uncompilable filter must fail the test:\n{text}");
    assert!(text.contains("does not compile"), "{text}");
}

/// SIGHUP must not kill the sensor.
///
/// Its default disposition is *terminate*, so before a handler existed `kill -HUP` — the reflex
/// for "reload your config" on any daemon — took the sensor down mid-capture. The handler requests
/// a trail reload instead. (The reload itself is consumed by the reload thread, which only runs
/// for live capture; the reload path it shares is covered by `tests/trails.rs`.)
#[test]
fn sighup_requests_a_reload_instead_of_killing_the_sensor() {
    let Some(binary) = sensor_binary() else {
        println!("[skip] build the sensor first (cargo build --release)");
        return;
    };
    let fixture = Fixture::new("sighup", "DISABLE_TRAIL_UPDATES true");
    std::fs::write(&fixture.trails, "evil.example,malware (test),(static)\n").unwrap();

    // A FIFO fed a complete pcap and then held open: the sensor finishes startup (so its signal
    // handlers are installed) and stays running instead of hitting EOF.
    let fifo = fixture.dir.join("feed.fifo");
    let c_fifo = std::ffi::CString::new(fifo.as_os_str().as_encoded_bytes()).unwrap();
    // SAFETY: a NUL-terminated path and a valid mode; failure is reported through the return value.
    assert_eq!(unsafe { libc::mkfifo(c_fifo.as_ptr(), 0o600) }, 0, "mkfifo");

    let pcap = dns_query_pcap(&fixture.dir, "example.org");
    let bytes = std::fs::read(&pcap).unwrap();
    let writer = std::thread::spawn(move || {
        use std::io::Write;
        if let Ok(mut f) = std::fs::OpenOptions::new().write(true).open(&fifo) {
            let _ = f.write_all(&bytes);
            let _ = f.flush();
            std::thread::sleep(std::time::Duration::from_secs(6));
        }
    });

    let mut child = Command::new(&binary)
        .current_dir(repo_root())
        .args(["-r", fixture.dir.join("feed.fifo").to_str().unwrap()])
        .arg("-c")
        .arg(&fixture.config)
        .arg("--offline")
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn the sensor");

    std::thread::sleep(std::time::Duration::from_secs(2));
    // SAFETY: `child.id()` is this process's own child, still alive at this point.
    unsafe { libc::kill(child.id() as libc::pid_t, libc::SIGHUP) };
    std::thread::sleep(std::time::Duration::from_millis(800));

    let still_running = child.try_wait().expect("try_wait").is_none();
    // SAFETY: same child pid.
    unsafe { libc::kill(child.id() as libc::pid_t, libc::SIGTERM) };
    let _ = child.wait();
    let _ = writer.join();

    assert!(still_running, "SIGHUP must not terminate the sensor — its default action would");
}
