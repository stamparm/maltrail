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

/// The interpreter to drive it with. `MALTRAIL_PYTHON` overrides.
pub fn python_interpreter() -> Option<String> {
    if let Ok(value) = std::env::var("MALTRAIL_PYTHON") {
        if !value.is_empty() {
            return Some(value);
        }
    }
    for candidate in ["python3", "python"] {
        // A cheap probe; `-V` neither reads config nor touches the network.
        if Command::new(candidate)
            .arg("-V")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
        {
            return Some(candidate.to_string());
        }
    }
    None
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
    let Some(python) = python_interpreter() else {
        return Outcome::Unavailable("no python3 interpreter on PATH (set MALTRAIL_PYTHON)".to_string());
    };

    let mut command = Command::new(&python);
    command.current_dir(&cfg.root).arg(&script).arg("-c").arg(&cfg.config_file);
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
