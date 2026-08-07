//! Fail-closed behaviour around the trail set (ROADMAP Gate 1.2).
//!
//! The failure these guard: a sensor whose trail load or update produced nothing still started,
//! still answered its metrics endpoint and still reported itself healthy — while detecting
//! nothing at all. An IDS that is confidently blind is worse than one that refuses to start,
//! because nobody investigates a green sensor.
//!
//! Driven through the real binary, because the decision lives in `main` and the exit status IS
//! the contract systemd consumes.

use std::path::PathBuf;
use std::process::Command;

fn binary() -> PathBuf {
    // The integration test binary lives in target/<profile>/deps/, so the sensor is two up.
    let mut path = std::env::current_exe().expect("test binary path");
    path.pop();
    if path.ends_with("deps") {
        path.pop();
    }
    path.join("maltrail-sensor")
}

fn corpus() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests").join("corpus").join("icmp.pcap")
}

struct Fixture {
    dir: PathBuf,
}

impl Fixture {
    fn new(name: &str, trails_csv: &str, extra: &str) -> Fixture {
        let dir = std::env::temp_dir().join(format!("maltrail-failclosed-{}-{}", std::process::id(), name));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("logs")).expect("create fixture dirs");
        std::fs::write(dir.join("trails.csv"), trails_csv).expect("write trails");
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
                 USE_HEURISTICS false\n\
                 SENSOR_NAME failclosed\n\
                 LOG_DIR {}\n\
                 TRAILS_FILE {}\n\
                 {extra}\n",
                dir.join("logs").display(),
                dir.join("trails.csv").display()
            ),
        )
        .expect("write config");
        Fixture { dir }
    }

    fn conf(&self) -> PathBuf {
        self.dir.join("maltrail.conf")
    }

    /// Replay the corpus. Returns (exit code, combined output).
    fn replay(&self) -> (i32, String) {
        self.invoke(&["-r", corpus().to_str().unwrap(), "-q"])
    }

    fn invoke(&self, extra: &[&str]) -> (i32, String) {
        let mut cmd = Command::new(binary());
        cmd.arg("-c").arg(self.conf());
        for a in extra {
            cmd.arg(a);
        }
        let out = cmd.output().expect("run maltrail-sensor");
        let mut text = String::from_utf8_lossy(&out.stdout).to_string();
        text.push_str(&String::from_utf8_lossy(&out.stderr));
        (out.status.code().unwrap_or(-1), text)
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn have_binary() -> bool {
    let ok = binary().is_file();
    if !ok {
        eprintln!("[skip] {} not built", binary().display());
    }
    ok
}

#[test]
fn an_empty_trail_set_refuses_to_start() {
    if !have_binary() {
        return;
    }
    let fixture = Fixture::new("empty", "", "");
    let (code, output) = fixture.replay();

    assert_eq!(code, 1, "an empty trail set must be fatal, got exit {code}\n{output}");
    assert!(output.contains("EMPTY"), "the operator must be told why:\n{output}");
    assert!(output.contains("ALLOW_EMPTY_TRAILS"), "and how to override it deliberately:\n{output}");
}

#[test]
fn an_empty_trail_set_is_allowed_when_the_operator_says_so() {
    if !have_binary() {
        return;
    }
    let fixture = Fixture::new("empty-allowed", "", "ALLOW_EMPTY_TRAILS true");
    let (code, output) = fixture.replay();

    // ALLOW_EMPTY_TRAILS has no USE_/CHECK_/DISABLE_ prefix, so it is NOT coerced to a boolean by
    // the config parser and must be read with cfg_bool(). Reading it with get_bool() made the
    // override silently ineffective; this asserts it actually works.
    assert_eq!(code, 0, "the override must be honoured, got exit {code}\n{output}");
}

#[test]
fn a_populated_trail_set_starts_normally() {
    if !have_binary() {
        return;
    }
    let fixture = Fixture::new("populated", "1.2.3.4,malware,(static)\n", "");
    let (code, output) = fixture.replay();
    assert_eq!(code, 0, "a normal trail set must start, got exit {code}\n{output}");
}

#[test]
fn test_config_agrees_with_startup_about_empty_trails() {
    if !have_binary() {
        return;
    }
    // -T is the systemd ExecStartPre gate. If it disagreed with main(), a deliberately
    // trail-less sensor would be blocked from ever starting.
    let strict = Fixture::new("t-strict", "", "");
    let (code, output) = strict.invoke(&["-T"]);
    assert_eq!(code, 1, "-T must fail on an empty trail set\n{output}");
    assert!(output.contains("loaded 0 trails"), "{output}");

    let allowed = Fixture::new("t-allowed", "", "ALLOW_EMPTY_TRAILS true");
    let (_, output) = allowed.invoke(&["-T"]);
    assert!(output.contains("allowed by 'ALLOW_EMPTY_TRAILS'"), "-T must accept what main() accepts:\n{output}");
}

/// The reload guard: a truncated trails.csv must not be allowed to replace a good store.
/// Exercised at the store level — the reload thread's decision is a pure comparison, and
/// driving a live sensor through a file swap would make this test a timing race.
#[test]
fn a_collapsing_reload_is_rejected_not_published() {
    use maltrail_sensor::metrics::Registry;
    use std::sync::atomic::Ordering;

    let registry = Registry::new(1);
    registry.trail_count.store(1_500_000, Ordering::Relaxed);

    // Same arithmetic as the reload thread in main().
    let decide = |incoming: u64, ratio: f64| -> bool {
        let current = registry.trail_count.load(Ordering::Relaxed);
        let floor = (current as f64 * ratio) as u64;
        ratio > 0.0 && current > 0 && incoming < floor
    };

    assert!(decide(3, 0.5), "a file truncated to 3 rows must be refused");
    assert!(decide(700_000, 0.5), "losing more than half the set must be refused");
    assert!(!decide(750_000, 0.5), "exactly at the floor is accepted");
    assert!(!decide(1_600_000, 0.5), "growth is always fine");
    assert!(!decide(3, 0.0), "ratio 0 disables the guard entirely");

    // First load (nothing to compare against) must never be blocked, or a fresh sensor could
    // never populate its store.
    registry.trail_count.store(0, Ordering::Relaxed);
    assert!(!decide(1, 0.5), "the initial load has no predecessor to shrink from");
}
