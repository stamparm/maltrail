//! Generated-file freshness.
//!
//! `src/settings_gen.rs` is produced by `tools/gen_settings.py` from `core/settings.py` and then
//! compiled in. The Python sensor reads those same constants **at runtime**. So if someone bumps
//! `PORT_SCANNING_THRESHOLD` (or a whitelist keyword, or a suspicious-UA pattern) in
//! `core/settings.py` and does not regenerate, the two sensors silently disagree — and the
//! differential parity harness *cannot* catch it, because it compares two sensors that are each
//! internally consistent.
//!
//! That is a whole class of divergence that no amount of parity testing closes. This test closes
//! it: regenerate into a temp file, apply the same `rustfmt` pass `tools/check.sh` applies, and
//! require the result to be byte-identical to what is checked in.

use std::path::PathBuf;
use std::process::Command;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).parent().unwrap().to_path_buf()
}

fn python() -> Option<String> {
    for candidate in ["python3", "python"] {
        let ok = Command::new(candidate)
            .arg("-V")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if ok {
            return Some(candidate.to_string());
        }
    }
    None
}

#[test]
fn settings_gen_is_in_sync_with_core_settings_py() {
    let Some(python) = python() else {
        println!("[skip] no python interpreter to regenerate with");
        return;
    };
    let root = repo_root();
    let script = root.join("sensor").join("tools").join("gen_settings.py");
    if !script.is_file() {
        println!("[skip] tools/gen_settings.py is missing");
        return;
    }

    let fresh = std::env::temp_dir().join(format!("mt-settings-gen-{}.rs", std::process::id()));
    let status = Command::new(&python)
        .current_dir(&root)
        .arg(&script)
        .arg("-o")
        .arg(&fresh)
        .stdout(std::process::Stdio::null())
        .status()
        .expect("run gen_settings.py");
    assert!(status.success(), "gen_settings.py failed");

    // The generator emits valid but unformatted Rust (one long line per table); `check.sh`
    // formats it, so the comparison has to format too or it would always differ.
    let rustfmt = Command::new("rustfmt")
        .arg("--edition")
        .arg("2021")
        .arg("--config-path")
        .arg(root.join("sensor").join("rustfmt.toml"))
        .arg(&fresh)
        .status();
    if !matches!(rustfmt, Ok(s) if s.success()) {
        println!("[skip] rustfmt unavailable; cannot compare formatted output");
        let _ = std::fs::remove_file(&fresh);
        return;
    }

    let regenerated = std::fs::read_to_string(&fresh).expect("read regenerated");
    let checked_in = std::fs::read_to_string(root.join("sensor").join("src").join("settings_gen.rs"))
        .expect("read src/settings_gen.rs");
    let _ = std::fs::remove_file(&fresh);

    if regenerated != checked_in {
        // Name the first differing line: "they differ" is not actionable at 26 kB.
        let first_diff = regenerated
            .lines()
            .zip(checked_in.lines())
            .enumerate()
            .find(|(_, (a, b))| a != b)
            .map(|(i, (a, b))| format!("line {}:\n  regenerated: {a}\n  checked in : {b}", i + 1))
            .unwrap_or_else(|| {
                format!(
                    "length differs: regenerated {} lines, checked in {} lines",
                    regenerated.lines().count(),
                    checked_in.lines().count()
                )
            });
        panic!(
            "src/settings_gen.rs is STALE with respect to core/settings.py.\n\
             The two sensors would silently disagree about a constant, and the parity harness \
             cannot see it.\n\
             Regenerate with:  python3 sensor/tools/gen_settings.py && \
             rustfmt --edition 2021 --config-path sensor/rustfmt.toml sensor/src/settings_gen.rs\n\n{first_diff}"
        );
    }
}
