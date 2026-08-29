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
//! it: regenerate into a temp file and require the same *constants*, ignoring layout.
//!
//! It deliberately does NOT compare bytes. It used to, after running `rustfmt` on the regenerated
//! copy, and that made it fail for reasons that have nothing to do with a stale constant:
//!
//!   * `check.sh` regenerates `src/settings_gen.rs` in place. If that run then died — a missing
//!     `rustfmt`, Ctrl-C — it left the working tree holding the generator's raw, unformatted
//!     output, and the next run reported the file as "STALE with respect to core/settings.py"
//!     when every constant in it was correct and only the line breaks differed.
//!   * `rustfmt` output is not stable across versions, so a contributor whose toolchain differs
//!     from whoever last regenerated saw the same false failure.
//!
//! Formatting is `cargo fmt --check`'s job, one step later in `check.sh`. This test's job is the
//! values, so it compares those and says which one moved.

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
    let status = Command::new(python)
        .current_dir(&root)
        .arg(&script)
        .arg("-o")
        .arg(&fresh)
        .stdout(std::process::Stdio::null())
        .status()
        .expect("run gen_settings.py");
    assert!(status.success(), "gen_settings.py failed");

    let regenerated = std::fs::read_to_string(&fresh).expect("read regenerated");
    let checked_in = std::fs::read_to_string(root.join("sensor").join("src").join("settings_gen.rs"))
        .expect("read src/settings_gen.rs");
    let _ = std::fs::remove_file(&fresh);

    let fresh_items = constants(&regenerated);
    let checked_items = constants(&checked_in);
    assert!(!fresh_items.is_empty(), "the generator produced no constants at all");

    // Every `pub const` in the file must actually be compared. Without this, a parser that quietly
    // stops recognising some declarations reduces the test to a subset and still reports success —
    // which is precisely how a stale constant survived here. Coverage is asserted, not assumed.
    for (label, source, items) in
        [("src/settings_gen.rs", &checked_in, &checked_items), ("the regenerated file", &regenerated, &fresh_items)]
    {
        let declared = source.lines().filter(|line| line.trim_start().starts_with("pub const ")).count();
        assert_eq!(
            declared,
            items.len(),
            "{label} declares {declared} constant(s) but only {} were parsed for comparison.\n\
             The parser in this test is skipping declarations, so the check is weaker than it looks.",
            items.len()
        );
    }

    let mut problems = Vec::new();
    for (name, value) in &fresh_items {
        match checked_items.iter().find(|(n, _)| n == name) {
            None => problems.push(format!("  {name}: MISSING from src/settings_gen.rs")),
            Some((_, checked)) if checked != value => problems.push(format!(
                "  {name}:\n    core/settings.py says: {}\n    checked in           : {}",
                clip(value),
                clip(checked)
            )),
            Some(_) => {}
        }
    }
    for (name, _) in &checked_items {
        if !fresh_items.iter().any(|(n, _)| n == name) {
            problems.push(format!("  {name}: checked in, but the generator no longer emits it"));
        }
    }

    assert!(
        problems.is_empty(),
        "src/settings_gen.rs disagrees with core/settings.py about {} constant(s).\n\
         The two sensors would silently disagree, and the parity harness cannot see it.\n\
         Regenerate with:  python3 sensor/tools/gen_settings.py && \\\n\
         \x20  rustfmt --edition 2021 --config-path sensor/rustfmt.toml sensor/src/settings_gen.rs\n\n{}",
        problems.len(),
        problems.join("\n")
    );
}

/// `pub const NAME: TYPE = VALUE;` pairs, with layout normalised away.
fn constants(source: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    // Statements end at `;` followed by a newline, which the generator and rustfmt both produce
    // and which cannot occur inside the string literals here (they are all single-line).
    for statement in source.split(";\n") {
        let Some(rest) = declaration(statement) else { continue };
        let Some((name, value)) = rest.split_once('=') else { continue };
        let Some((name, _type)) = name.split_once(':') else { continue };
        out.push((name.trim().to_string(), normalise(value)));
    }
    out
}

/// The `pub const ...` declaration inside one `;\n`-delimited chunk, or `None`.
///
/// The declaration is NOT necessarily at the start of the chunk: everything between the previous
/// statement's `;\n` and this one — a doc comment, an attribute, a blank line — sits in front of
/// it. This used to be `chunk.trim_start().strip_prefix("pub const ")`, which therefore skipped
/// every *documented* constant silently: 8 of the 47 in `settings_gen.rs`, including
/// `SUSPICIOUS_UA_REGEX`, `DLT_OFFSETS`, `IPPROTO_LUT` and `SUSPICIOUS_HTTP_REQUEST_REGEXES`.
/// A stale `SUSPICIOUS_UA_REGEX` (a pattern added to `data/ua.txt` and never regenerated) passed
/// this test for exactly that reason, which is the whole failure this file exists to prevent.
///
/// `rfind` rather than `find`: a chunk holds at most one declaration — the one its terminating
/// `;` closes — and taking the last match cannot pick up a mention inside a preceding comment.
fn declaration(chunk: &str) -> Option<&str> {
    const KEY: &str = "pub const ";
    if let Some(rest) = chunk.trim_start().strip_prefix(KEY) {
        return Some(rest);
    }
    chunk.rfind(&format!("\n{KEY}")).map(|at| &chunk[at + 1 + KEY.len()..])
}

/// Strip everything that is layout and keep everything that is meaning.
///
/// Whitespace **outside** string literals is dropped entirely, so a table `rustfmt` wrapped over
/// twenty lines equals the generator's one-liner. Whitespace **inside** a literal is preserved to
/// the byte, because it is part of the constant — `WHITELIST_UA_REGEX` really does contain
/// `internal dummy connection`, and collapsing that would let a genuine change slip through.
/// A trailing comma before a closing bracket is also dropped, since `rustfmt` removes it.
fn normalise(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out = String::with_capacity(value.len());
    let mut i = 0;
    while i < bytes.len() {
        // Raw string literal: r"...", r#"..."#, r##"..."## — copied verbatim to its matching end.
        if bytes[i] == b'r' {
            let mut hashes = 0;
            while i + 1 + hashes < bytes.len() && bytes[i + 1 + hashes] == b'#' {
                hashes += 1;
            }
            if i + 1 + hashes < bytes.len() && bytes[i + 1 + hashes] == b'"' {
                let terminator = format!("\"{}", "#".repeat(hashes));
                let body_start = i + 1 + hashes + 1;
                if let Some(end) = value[body_start..].find(&terminator) {
                    out.push_str(&value[i..body_start + end + terminator.len()]);
                    i = body_start + end + terminator.len();
                    continue;
                }
            }
        }
        // Ordinary string literal, honouring backslash escapes.
        if bytes[i] == b'"' {
            out.push('"');
            i += 1;
            while i < bytes.len() {
                out.push(bytes[i] as char);
                if bytes[i] == b'\\' && i + 1 < bytes.len() {
                    out.push(bytes[i + 1] as char);
                    i += 2;
                    continue;
                }
                if bytes[i] == b'"' {
                    i += 1;
                    break;
                }
                i += 1;
            }
            continue;
        }
        if !bytes[i].is_ascii_whitespace() {
            out.push(bytes[i] as char);
        }
        i += 1;
    }
    out.replace(",]", "]").replace(",)", ")").replace(",}", "}")
}

fn clip(value: &str) -> String {
    const MAX: usize = 160;
    if value.chars().count() <= MAX {
        return value.to_string();
    }
    let head: String = value.chars().take(MAX).collect();
    format!("{head}... ({} chars)", value.chars().count())
}
