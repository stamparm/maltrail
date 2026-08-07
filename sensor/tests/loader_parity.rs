//! Differential loader test: the Rust loader vs `core.common.load_trails()`, on the REAL
//! trails.csv, row by row.
//!
//! Every other trail test checks the Rust loader against itself. This one runs Python's loader as
//! an oracle (`tools/dump_trails.py`) and compares:
//!
//!   * the number of rows accepted, and the number of distinct keys,
//!   * the three fields of EVERY accepted row (so a CSV-splitting difference on quoted rows —
//!     regex trails routinely contain commas, e.g. `[a-z]{1,3}` — cannot hide),
//!   * which wildcard trails end up in the alternation, in which order,
//!   * which wildcard trails CPython's `re` rejects.
//!
//! It runs against whatever trails.csv the machine has, so it keeps working after a trail update
//! instead of drifting away from a checked-in fixture.

use std::path::PathBuf;
use std::process::Command;

use maltrail_sensor::trails::{self, LoadOptions};
use maltrail_sensor::whitelist::Whitelist;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).parent().unwrap().to_path_buf()
}

fn real_trails_file() -> Option<PathBuf> {
    let path = PathBuf::from(std::env::var("HOME").ok()?).join(".maltrail").join("trails.csv");
    path.is_file().then_some(path)
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

struct Dump {
    count: usize,
    unique: usize,
    patterns: Vec<String>,
    rejected: Vec<String>,
    path: PathBuf,
}

/// Run the Python oracle and parse its header. Rows stay on disk (there are ~1.5M of them).
fn python_dump(trails_csv: &PathBuf) -> Option<Dump> {
    let python = python()?;
    let script = repo_root().join("sensor").join("tools").join("dump_trails.py");
    if !script.is_file() {
        return None;
    }
    let out = std::env::temp_dir().join(format!("mt-loader-parity-{}.dump", std::process::id()));
    let status = Command::new(&python)
        .current_dir(repo_root())
        .arg(&script)
        .arg("--trails")
        .arg(trails_csv)
        .arg("-o")
        .arg(&out)
        .status()
        .ok()?;
    assert!(status.success(), "the Python trail dump failed; parity cannot be established");

    let text = std::fs::read_to_string(&out).expect("dump");
    let mut dump = Dump { count: 0, unique: 0, patterns: Vec::new(), rejected: Vec::new(), path: out };
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("#count ") {
            dump.count = rest.parse().unwrap();
        } else if let Some(rest) = line.strip_prefix("#unique ") {
            dump.unique = rest.parse().unwrap();
        } else if let Some(rest) = line.strip_prefix("#regex-pattern ") {
            dump.patterns.push(rest.to_string());
        } else if let Some(rest) = line.strip_prefix("#wildcard-rejected ") {
            dump.rejected.push(rest.to_string());
        } else if !line.starts_with('#') {
            break;
        }
    }
    Some(dump)
}

#[test]
fn every_row_python_loads_is_loaded_identically_by_rust() {
    let Some(csv) = real_trails_file() else {
        println!("[skip] no ~/.maltrail/trails.csv on this machine");
        return;
    };
    let Some(dump) = python_dump(&csv) else {
        println!("[skip] no python interpreter / dump_trails.py to compare against");
        return;
    };

    let wl = Whitelist::load(&repo_root(), None);
    // Strict mode: reproduce build_trails_regex() exactly, so the wildcard sets must match too.
    let strict = LoadOptions { repair_truncated_trails: false };
    let (db, stats) = trails::load_with(&csv, &wl, strict).unwrap();

    assert_eq!(stats.loaded, dump.count, "Rust accepted {} rows, Python accepted {}", stats.loaded, dump.count);
    assert_eq!(db.len(), dump.unique, "distinct-key count differs from Python's dict length");

    // Every row, field by field.
    let text = std::fs::read_to_string(&dump.path).unwrap();
    let mut rows = 0usize;
    let mut bad: Vec<String> = Vec::new();
    for line in text.lines().filter(|l| !l.starts_with('#')) {
        let mut it = line.split('\u{1f}');
        let (Some(trail), Some(info), Some(reference)) = (it.next(), it.next(), it.next()) else { continue };
        rows += 1;
        match db.get(trail) {
            None => {
                if bad.len() < 10 {
                    bad.push(format!("missing: {trail:?}"));
                }
            }
            Some(found) if found.info != info || found.reference != reference => {
                if bad.len() < 10 {
                    bad.push(format!(
                        "{trail:?}: rust ({:?}, {:?}) python ({info:?}, {reference:?})",
                        found.info, found.reference
                    ));
                }
            }
            Some(_) => {}
        }
    }
    assert_eq!(rows, dump.count, "the dump is truncated");
    assert!(bad.is_empty(), "{} row(s) differ from Python, e.g.:\n{}", bad.len(), bad.join("\n"));

    // The wildcard alternation: same trails, same order, same rejections.
    let rust_patterns: Vec<String> = db.regex().patterns().to_vec();
    assert_eq!(
        rust_patterns, dump.patterns,
        "the wildcard-trail alternation differs from build_trails_regex()\nrust: {rust_patterns:#?}\npython: {:#?}",
        dump.patterns
    );
    let mut rust_rejected: Vec<String> = db.regex().skipped().to_vec();
    let mut py_rejected = dump.rejected.clone();
    rust_rejected.sort();
    py_rejected.sort();
    assert_eq!(rust_rejected, py_rejected, "the two engines disagree about which wildcard trails are compilable");

    println!(
        "[i] loader parity: {rows} rows, {} unique, {} wildcard pattern(s), {} rejected - identical to Python",
        db.len(),
        rust_patterns.len(),
        rust_rejected.len()
    );
    let _ = std::fs::remove_file(&dump.path);
}

#[test]
fn repairing_mangled_patterns_only_ever_adds_wildcard_trails() {
    // `REPAIR_TRUNCATED_TRAILS` (on by default) is the one deliberate detection difference from
    // sensor.py: patterns that Maltrail's own trail generation mangles - `core/update.py`
    // truncates any non-path trail at the first '?', which decapitates regex trails containing
    // e.g. `sing-?post` - are repaired and matched instead of being dropped silently.
    //
    // Whatever it does, it must be PURELY ADDITIVE: same rows, same keys, same values, and a
    // wildcard set that is a superset of Python's. Anything else would be a regression.
    let Some(csv) = real_trails_file() else {
        println!("[skip] no ~/.maltrail/trails.csv on this machine");
        return;
    };
    let wl = Whitelist::load(&repo_root(), None);
    let (strict, s1) = trails::load_with(&csv, &wl, LoadOptions { repair_truncated_trails: false }).unwrap();
    let (repaired, s2) = trails::load_with(&csv, &wl, LoadOptions { repair_truncated_trails: true }).unwrap();

    assert_eq!(s1.loaded, s2.loaded, "repair must not change which rows load");
    assert_eq!(s1.malformed, s2.malformed);
    assert_eq!(strict.len(), repaired.len(), "repair must not change the key set");
    assert_eq!(strict.ip4_count(), repaired.ip4_count());

    for pattern in strict.regex().patterns() {
        assert!(
            repaired.regex().patterns().contains(pattern),
            "repair dropped a wildcard trail Python keeps: {pattern}"
        );
    }
    assert!(repaired.regex().len() >= strict.regex().len(), "repair must only ever add wildcard trails");
    // Everything extra must be accounted for as a repair, and nothing may be lost twice over.
    assert_eq!(
        repaired.regex().len() - strict.regex().len(),
        repaired.regex().repaired().len(),
        "the extra wildcard trails must be exactly the repaired ones"
    );
    assert!(repaired.regex().skipped().is_empty() || !repaired.regex().repaired().is_empty());

    println!(
        "[i] strict: {} wildcard trail(s); repaired: {} (+{} recovered: {:?})",
        strict.regex().len(),
        repaired.regex().len(),
        repaired.regex().repaired().len(),
        repaired.regex().repaired().iter().map(|p| format!("{:.60}...", p)).collect::<Vec<_>>()
    );
}
