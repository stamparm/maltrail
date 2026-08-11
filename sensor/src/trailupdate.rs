//! Trail updating — `sensor.py:init():update_timer()`.
//!
//! The sensor MUST refresh `TRAILS_FILE` itself, on startup and every `UPDATE_PERIOD`, exactly
//! like `sensor.py` does. Skipping it is not a cosmetic difference: static trails are added to
//! this repository continuously, so a sensor that only ever *reads* a trails file silently stops
//! detecting everything added since that file was written. (A four-week-old file cost a live
//! asyncrat domain: `511mon.kozow.com` entered `trails/static/malware/asyncrat.txt` two weeks
//! after the file was generated, so the sensor matched only its dynamic-DNS parent.)
//!
//! The update itself is **not** reimplemented. `tools/update_trails.py` is a thin wrapper around
//! `core.update.update_trails()`, so there is exactly one trail-update mechanism in the
//! repository and both sensors use it. That also means feeds, `UPDATE_SERVER`,
//! `USE_FEED_UPDATES`, `DISABLED_FEEDS`, `IP_MINIMUM_FEEDS`, `CUSTOM_TRAILS_DIR` and the rest
//! keep working with no duplicated logic.

use std::path::{Path, PathBuf};
use std::process::Command;

use crate::config::Config;

/// Where `tools/update_trails.py` lives, relative to the repository root.
pub fn updater_script(root: &Path) -> PathBuf {
    root.join("sensor").join("tools").join("update_trails.py")
}

/// The oldest Python the updater runs on, tested in CI rather than asserted.
///
/// This used to be 3.7 for exactly one reason - `core/update.py` called `str.isascii()` - which
/// wrote off every distribution whose default `python3` is 3.6: RHEL 8, CentOS 7, openSUSE Leap 15
/// / SLE 15, Amazon Linux 2. `_is_ascii()` now has a 3.6 path, so the floor is 3.6, and the whole
/// server test suite plus a full offline trail build run on 3.6.15 in CI.
pub const MIN_PYTHON: (u32, u32) = (3, 6);

/// What a candidate interpreter turned out to be.
pub struct PythonProbe {
    pub command: String,
    /// `None` when the command could not be run or its version could not be parsed.
    pub version: Option<(u32, u32, u32)>,
}

impl PythonProbe {
    pub fn is_supported(&self) -> bool {
        matches!(self.version, Some((major, minor, _)) if (major, minor) >= MIN_PYTHON)
    }

    pub fn version_string(&self) -> String {
        match self.version {
            Some((a, b, c)) => format!("{a}.{b}.{c}"),
            None => "unknown".to_string(),
        }
    }
}

/// Ask one interpreter what it is. Cheap: `-c` neither reads config nor touches the network.
fn probe(command: &str) -> Option<PythonProbe> {
    let out =
        Command::new(command).args(["-c", "import sys; print('%d.%d.%d' % sys.version_info[:3])"]).output().ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&out.stdout);
    let mut parts = text.trim().split('.').map(|p| p.parse::<u32>());
    let version = match (parts.next(), parts.next(), parts.next()) {
        (Some(Ok(a)), Some(Ok(b)), Some(Ok(c))) => Some((a, b, c)),
        _ => None,
    };
    Some(PythonProbe { command: command.to_string(), version })
}

/// The interpreter to drive the updater with. `MALTRAIL_PYTHON` overrides everything.
///
/// Returns the first candidate that is actually **new enough**, and falls back to the newest
/// unsuitable one it found so the caller can say what is wrong instead of "no python3".
///
/// Version-checking here is not pedantry, even now that the floor is 3.6: a host whose `python3`
/// is 3.5 or 2.7 (or a `python3` shim that is not Python at all) would otherwise pass a
/// "does it run" probe, report "updater and interpreter present" from `-T`, and then fail inside
/// `core/update.py` - leaving a sensor with an empty trail set, which detects nothing. Preferring
/// a versioned `python3.N` off PATH fixes such a host outright, because a usable interpreter is
/// usually installed alongside the unusable default.
pub fn python_probe() -> Option<PythonProbe> {
    if let Ok(value) = std::env::var("MALTRAIL_PYTHON") {
        if !value.is_empty() {
            // An explicit choice is honoured verbatim, right or wrong; reporting its version is
            // still useful when it turns out to be the wrong one.
            return Some(probe(&value).unwrap_or(PythonProbe { command: value, version: None }));
        }
    }
    // Newest first, then the unversioned names. A box whose `python3` is too old very often has
    // a newer `python3.11` sitting next to it.
    const CANDIDATES: &[&str] = &[
        "python3.14",
        "python3.13",
        "python3.12",
        "python3.11",
        "python3.10",
        "python3.9",
        "python3.8",
        "python3.7",
        "python3.6",
        "python3",
        "python",
    ];
    let mut fallback: Option<PythonProbe> = None;
    for candidate in CANDIDATES {
        let Some(found) = probe(candidate) else { continue };
        if found.is_supported() {
            return Some(found);
        }
        if fallback.as_ref().map_or(true, |best| found.version > best.version) {
            fallback = Some(found);
        }
    }
    fallback
}

/// The interpreter to drive it with, or `None` when there is no usable one.
pub fn python_interpreter() -> Option<String> {
    python_probe().filter(|p| p.is_supported()).map(|p| p.command)
}

#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    Updated,
    Disabled,
    Unavailable(String),
    Failed(String),
}

/// Run one update cycle, streaming the updater's own progress output to the console.
///
/// `offline` maps to `sensor.py`'s `--offline`: no network, but the trails file is still
/// *rebuilt* from the bundled static and custom trails — which is exactly why `sensor.py
/// --offline` still picks up newly added static IOCs.
pub fn run(cfg: &Config) -> Outcome {
    if cfg.disable_trail_updates {
        return Outcome::Disabled;
    }
    let script = updater_script(&cfg.root);
    if !script.is_file() {
        return Outcome::Unavailable(format!("missing '{}'", script.display()));
    }
    // Say WHICH interpreter is unusable and why. A bare "no python3 on PATH" is wrong and
    // misleading on a host that has one but too old to run the updater; that host gets an empty
    // trail set, and the only clue used to be an AttributeError from deep inside core/update.py.
    let python = match python_probe() {
        Some(found) if found.is_supported() => found.command,
        Some(found) => {
            let (major, minor) = MIN_PYTHON;
            return Outcome::Unavailable(format!(
                "'{}' is Python {}, but the updater needs {major}.{minor}+ (set MALTRAIL_PYTHON to a newer one)",
                found.command,
                found.version_string()
            ));
        }
        None => return Outcome::Unavailable("no python3 interpreter on PATH (set MALTRAIL_PYTHON)".to_string()),
    };

    let mut command = Command::new(&python);
    // Only chdir somewhere that exists. `chdir("")` fails with ENOENT and Rust reports it as if
    // the interpreter were missing, which sent me looking for a Python that was there all along.
    if cfg.root.is_dir() {
        command.current_dir(&cfg.root);
    }
    command.arg(&script).arg("-c").arg(&cfg.config_file);
    if cfg.offline {
        command.arg("--offline");
    }

    match command.status() {
        Ok(status) if status.success() => Outcome::Updated,
        Ok(status) => Outcome::Failed(match status.code() {
            Some(code) => format!("{python} exited with status {code}"),
            None => format!("{python} was terminated by a signal"),
        }),
        Err(e) => Outcome::Failed(format!("unable to run {python}: {e}")),
    }
}

/// How old `TRAILS_FILE` is, in seconds. Used to warn when an update did not actually refresh it.
pub fn trails_age_secs(path: &Path) -> Option<u64> {
    let modified = std::fs::metadata(path).and_then(|m| m.modified()).ok()?;
    std::time::SystemTime::now().duration_since(modified).ok().map(|d| d.as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn repo_root() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).parent().unwrap().to_path_buf()
    }

    #[test]
    fn the_updater_script_ships_with_the_repository() {
        let script = updater_script(&repo_root());
        assert!(script.is_file(), "missing {}", script.display());
        let text = std::fs::read_to_string(&script).unwrap();
        // It must delegate to Maltrail's own updater rather than reimplement anything.
        assert!(text.contains("from core.update import"), "the updater must call core.update");
        assert!(text.contains("update_trails"));
    }

    #[test]
    fn a_python_interpreter_is_discoverable() {
        // The Rust sensor lives in the Maltrail repository, so python3 is a reasonable
        // expectation; if it is missing the sensor warns loudly rather than silently skipping.
        assert!(python_interpreter().is_some(), "no python3 found; trail updates would be unavailable");
    }

    #[test]
    fn the_discovered_interpreter_is_new_enough_to_run_the_updater() {
        // An interpreter below the floor builds NO trails and the sensor detects nothing, so
        // probing that `python3 -V` merely runs is not enough - it has to be identified.
        let python = python_probe().expect("some python must be discoverable");
        assert!(
            python.is_supported(),
            "discovered {} (Python {}), below the {:?} floor",
            python.command,
            python.version_string(),
            MIN_PYTHON
        );
        let (major, minor, _) = python.version.expect("a supported probe has a version");
        assert!((major, minor) >= MIN_PYTHON);
    }

    #[test]
    fn version_support_is_decided_by_the_floor_not_by_running() {
        let probe = |v: Option<(u32, u32, u32)>| PythonProbe { command: "python3".into(), version: v };
        // 3.6 is the floor: RHEL 8 / CentOS 7 / Leap 15 / Amazon Linux 2 ship it as `python3`,
        // and core/update.py runs there (tests/run.sh + a full offline trail build, in CI).
        assert!(probe(Some((3, 6, 15))).is_supported(), "3.6 is the documented floor");
        assert!(!probe(Some((3, 5, 10))).is_supported(), "3.5 is below the floor");
        assert!(!probe(Some((2, 7, 18))).is_supported());
        assert!(probe(Some((3, 7, 0))).is_supported());
        assert!(probe(Some((3, 12, 3))).is_supported());
        // An interpreter we could not identify is not assumed to be fine.
        assert!(!probe(None).is_supported());
        assert_eq!(probe(None).version_string(), "unknown");
        assert_eq!(probe(Some((3, 11, 9))).version_string(), "3.11.9");
    }

    #[test]
    fn trails_age_is_reported() {
        let dir = std::env::temp_dir().join("mt-trailupdate-age");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("trails.csv");
        std::fs::write(&path, "x,y,z\n").unwrap();
        let age = trails_age_secs(&path).expect("age");
        assert!(age < 60, "a just-written file should be young, got {age}s");
        assert!(trails_age_secs(Path::new("/nonexistent/trails.csv")).is_none());
    }
}
