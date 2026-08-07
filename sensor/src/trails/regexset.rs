//! `core/common.py:build_trails_regex()` — the named-group alternation of wildcard/regex
//! `(static)` trails that `sensor.py:_check_domain()` falls back to.
//!
//! Python builds `"|(?P<g0>pat0)|(?P<g1>pat1)..."` and, on a match, recovers the original
//! trail key ("candidate") by splitting the regex source back apart. Here the patterns are
//! simply kept in group order, which is the same value that split-and-strip recovers.

use crate::pyre;

/// The compiled form of the combined wildcard-trail alternation.
///
/// The `regex` crate handles everything Maltrail's trails normally use and is the fast path.
/// A trail that needs look-around or a backreference (CPython accepts those, the crate does
/// not) forces the whole alternation onto `fancy-regex`, which is a backtracking engine like
/// CPython's - that keeps the two sensors matching the same trail set instead of silently
/// dropping one. Unlike CPython, `fancy-regex` has a backtrack limit and returns an error
/// rather than hanging, so a pathological pattern degrades to "no match" instead of a stall.
enum Engine {
    Fast(regex::Regex),
    Backtracking(fancy_regex::Regex),
}

pub struct TrailRegex {
    regex: Option<Engine>,
    /// group index -> the trail key that produced it (Python's `candidate`). This is always the
    /// VERBATIM CSV key, even when the compiled form was repaired, because it is what the trail
    /// lookup is keyed on.
    patterns: Vec<String>,
    source: String,
    skipped: Vec<String>,
    /// trails whose pattern was truncated in the feed and repaired (see `repair_truncated`)
    repaired: Vec<String>,
    /// true when the backtracking engine was needed
    fancy: bool,
}

/// `re.search(r"[\].][*+]|\[[a-z0-9_.\-]+\]", trail, re.I)` — is this trail a wildcard /
/// regex trail rather than a literal?
pub fn is_wildcard_trail(trail: &str) -> bool {
    let b = trail.as_bytes();
    for i in 0..b.len() {
        // [\].][*+]
        if (b[i] == b']' || b[i] == b'.') && i + 1 < b.len() && (b[i + 1] == b'*' || b[i + 1] == b'+') {
            return true;
        }
        // \[[a-z0-9_.\-]+\]  (case-insensitive)
        if b[i] == b'[' {
            let mut j = i + 1;
            while j < b.len() && (b[j].is_ascii_alphanumeric() || b[j] == b'_' || b[j] == b'.' || b[j] == b'-') {
                j += 1;
            }
            if j > i + 1 && j < b.len() && b[j] == b']' {
                return true;
            }
        }
    }
    false
}

/// Group-syntax constraints CPython enforces but `fancy-regex` does not, plus the one
/// constraint this module adds:
///
///  * a duplicate `(?P<name>` is a hard error in CPython ("redefinition of group name"),
///  * `(?<name>` is not valid CPython syntax at all (only `(?P<name>` is),
///  * a group named `g<digits>` would collide with the `g0..g99` names this module assigns
///    to the members of the combined alternation, which is what identifies *which* trail
///    matched — so such a trail is refused rather than silently mis-attributed.
fn python_group_syntax_ok(pattern: &str) -> bool {
    let bytes = pattern.as_bytes();
    let mut names: Vec<&str> = Vec::new();
    let mut i = 0usize;
    while i + 2 < bytes.len() {
        if bytes[i] == b'\\' {
            i += 2;
            continue;
        }
        if bytes[i] == b'(' && bytes[i + 1] == b'?' {
            let rest = &bytes[i + 2..];
            let name_start = if rest.first() == Some(&b'P') && rest.get(1) == Some(&b'<') {
                i + 4
            } else if rest.first() == Some(&b'<') && !matches!(rest.get(1), Some(b'=') | Some(b'!')) {
                // `(?<name>` — invalid in CPython
                return false;
            } else {
                i += 2;
                continue;
            };
            let Some(end) = pattern[name_start..].find('>') else { return false };
            let name = &pattern[name_start..name_start + end];
            if names.contains(&name) {
                return false; // redefinition of group name
            }
            if let Some(digits) = name.strip_prefix('g') {
                if !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit()) {
                    return false; // would collide with the alternation's own group names
                }
            }
            names.push(name);
            i = name_start + end + 1;
            continue;
        }
        i += 1;
    }
    true
}

/// Real trail feeds ship wildcard patterns that were **truncated in transit**, leaving an
/// unterminated group — e.g. `\b[a-z0-9]{1,3}\-(aegin|aiful|...|nzpost|b` (cut mid-word after the
/// last `|`). CPython refuses those outright, so `sensor.py` silently drops the whole indicator.
///
/// They can be salvaged: drop the trailing *incomplete* alternative and close the open groups.
/// Dropping it matters — keeping `|b` would leave a one-character alternative that matches far
/// more than the feed intended (`x-b` would hit), i.e. repairing naively would manufacture false
/// positives. Everything up to the last complete `|` is intact and is kept.
///
/// Returns the repaired pattern, or `None` when the damage is not of this shape.
pub fn repair_truncated(pattern: &str) -> Option<String> {
    let b = pattern.as_bytes();
    // Track group depth, and remember where the last top-of-stack alternative started.
    let mut depth = 0usize;
    let mut last_alt_at: Vec<Option<usize>> = vec![None];
    let mut in_class = false;
    let mut i = 0usize;
    while i < b.len() {
        match b[i] {
            b'\\' => {
                i += 2;
                continue;
            }
            b'[' if !in_class => in_class = true,
            b']' if in_class => in_class = false,
            b'(' if !in_class => {
                depth += 1;
                last_alt_at.push(None);
            }
            b')' if !in_class && depth > 0 => {
                depth -= 1;
                last_alt_at.pop();
            }
            b'|' if !in_class => {
                if let Some(top) = last_alt_at.last_mut() {
                    *top = Some(i);
                }
            }
            _ => {}
        }
        i += 1;
    }

    if depth == 0 || in_class {
        return None; // not an unterminated-group truncation
    }
    // Cut at the last `|` inside the innermost unclosed group, then close every open group.
    let cut = (*last_alt_at.last()?)?;
    let mut repaired = pattern[..cut].to_string();
    for _ in 0..depth {
        repaired.push(')');
    }
    if pyre::build(&repaired).is_ok() || pyre::build_fancy(&repaired).is_ok() {
        Some(repaired)
    } else {
        None
    }
}

/// Can this pattern be compiled at all (by either engine)? This is the exact decision
/// `TrailRegexBuilder::offer()` makes, and it must agree with CPython's `re.compile()` —
/// asserted from Python-generated vectors in `tests/vectors.rs`.
pub fn can_compile_trail(pattern: &str) -> bool {
    python_group_syntax_ok(pattern) && (pyre::build(pattern).is_ok() || pyre::build_fancy(pattern).is_ok())
}

/// `re.escape(trail) != trail` — Python only keeps trails that actually carry regex
/// metacharacters.
fn has_metacharacters(trail: &str) -> bool {
    pyre::escape(trail) != trail
}

pub struct TrailRegexBuilder {
    patterns: Vec<String>,
    source: String,
    skipped: Vec<String>,
    repaired: Vec<String>,
    needs_fancy: bool,
    /// Repair feed-mangled patterns instead of dropping them (see `repair_truncated`). ON by
    /// default; `REPAIR_TRUNCATED_TRAILS false` restores Python's drop-it-silently behaviour.
    repair: bool,
}

impl Default for TrailRegexBuilder {
    fn default() -> TrailRegexBuilder {
        TrailRegexBuilder {
            patterns: Vec::new(),
            source: String::new(),
            skipped: Vec::new(),
            repaired: Vec::new(),
            needs_fancy: false,
            repair: true,
        }
    }
}

impl TrailRegexBuilder {
    /// `repair = false` reproduces `build_trails_regex()` exactly: a pattern CPython's `re`
    /// rejects is dropped, and the trail is simply never matched.
    pub fn with_repair(repair: bool) -> TrailRegexBuilder {
        TrailRegexBuilder { repair, ..TrailRegexBuilder::default() }
    }

    /// Offer a trail in CSV order, exactly where `build_trails_regex()` would see it.
    pub fn offer(&mut self, trail: &str, reference: &str) {
        // Reference: https://stackoverflow.com/questions/478458 (100-group limit)
        if self.patterns.len() >= 100 {
            return;
        }
        if !reference.contains("static") || !is_wildcard_trail(trail) || !has_metacharacters(trail) {
            return;
        }
        // The pattern that actually gets compiled. Normally the trail verbatim; for a trail
        // truncated in the feed, a repaired form (the CSV key is still what we look up).
        let compiled = if can_compile_trail(trail) {
            trail.to_string()
        } else if !self.repair {
            // Python: `except re.error: continue` — the trail is silently not matched.
            self.skipped.push(trail.to_string());
            return;
        } else {
            match repair_truncated(trail) {
                Some(repaired) => {
                    self.repaired.push(trail.to_string());
                    repaired
                }
                None => {
                    // Beyond salvage (CPython rejects it too). Recorded so it shows up in the
                    // startup diagnostics rather than vanishing silently.
                    self.skipped.push(trail.to_string());
                    return;
                }
            }
        };
        if pyre::build(&compiled).is_err() {
            // Only `fancy-regex` can express this one (look-around / backreference), so the
            // whole alternation has to use the backtracking engine.
            self.needs_fancy = true;
        }
        if !self.source.is_empty() {
            self.source.push('|');
        }
        self.source.push_str(&format!("(?P<g{}>{})", self.patterns.len(), compiled));
        self.patterns.push(trail.to_string());
    }

    pub fn build(self) -> TrailRegex {
        let mut fancy = false;
        let regex = if self.source.is_empty() {
            None
        } else {
            let fast = if self.needs_fancy { None } else { pyre::build(&self.source).ok() };
            match fast {
                Some(re) => Some(Engine::Fast(re)),
                None => match pyre::build_fancy(&self.source) {
                    Ok(re) => {
                        fancy = true;
                        Some(Engine::Backtracking(re))
                    }
                    Err(e) => {
                        crate::output::log_error(
                            &format!(
                                "unable to compile the combined wildcard-trail regex ({e}); \
                                 wildcard trail matching is disabled"
                            ),
                            true,
                        );
                        None
                    }
                },
            }
        };
        TrailRegex {
            regex,
            patterns: self.patterns,
            source: self.source,
            skipped: self.skipped,
            repaired: self.repaired,
            fancy,
        }
    }
}

/// The result of a wildcard-trail match: the matched span plus the trail key to look up.
pub struct RegexHit<'a> {
    pub start: usize,
    pub end: usize,
    pub candidate: &'a str,
}

impl TrailRegex {
    pub fn is_empty(&self) -> bool {
        self.regex.is_none()
    }

    pub fn len(&self) -> usize {
        self.patterns.len()
    }

    pub fn skipped(&self) -> &[String] {
        &self.skipped
    }

    /// Trails whose feed-truncated pattern was repaired before compiling.
    pub fn repaired(&self) -> &[String] {
        &self.repaired
    }

    /// The trail keys that made it into the alternation, in group order — i.e. exactly the
    /// patterns `build_trails_regex()` would have concatenated. Used by the loader-parity test.
    pub fn patterns(&self) -> &[String] {
        &self.patterns
    }

    pub fn source(&self) -> &str {
        &self.source
    }

    /// True when the alternation needed the backtracking engine (look-around / backreference).
    pub fn uses_backtracking(&self) -> bool {
        self.fancy
    }

    /// `match = re.search(trails._regex, query)` plus the group -> candidate recovery.
    pub fn find(&self, query: &str) -> Option<RegexHit<'_>> {
        let (start, end, group) = match self.regex.as_ref()? {
            Engine::Fast(re) => {
                let caps = re.captures(query)?;
                let whole = caps.get(0)?;
                let group = self
                    .patterns
                    .iter()
                    .enumerate()
                    .find(|(idx, _)| caps.name(&format!("g{idx}")).is_some())
                    .map(|(idx, _)| idx)?;
                (whole.start(), whole.end(), group)
            }
            Engine::Backtracking(re) => {
                // An error (e.g. the backtrack limit) is treated as "no match": a hostile
                // query must never stall or abort the packet path.
                let caps = re.captures(query).ok()??;
                let whole = caps.get(0)?;
                let group = self
                    .patterns
                    .iter()
                    .enumerate()
                    .find(|(idx, _)| caps.name(&format!("g{idx}")).is_some())
                    .map(|(idx, _)| idx)?;
                (whole.start(), whole.end(), group)
            }
        };
        Some(RegexHit { start, end, candidate: &self.patterns[group] })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wildcard_detection_matches_python_regex() {
        assert!(is_wildcard_trail("evil.*"));
        assert!(is_wildcard_trail("bad].+"));
        assert!(is_wildcard_trail("[a-z0-9]host.com"));
        assert!(is_wildcard_trail("x[abc_.-]y"));
        assert!(!is_wildcard_trail("evil.com"));
        assert!(!is_wildcard_trail("1.2.3.4"));
        assert!(!is_wildcard_trail("[]"));
        assert!(!is_wildcard_trail("[unclosed"));
    }

    #[test]
    fn only_static_wildcards_with_metacharacters_are_kept() {
        let mut b = TrailRegexBuilder::default();
        b.offer("evil.*\\.com", "(static)");
        b.offer("plain.com", "(static)");
        b.offer("feed.*\\.com", "abuse.ch"); // not static
        let r = b.build();
        assert_eq!(r.len(), 1);
        assert!(!r.is_empty());
        assert_eq!(r.source(), "(?P<g0>evil.*\\.com)");
    }

    #[test]
    fn group_recovery_returns_the_trail_key() {
        let mut b = TrailRegexBuilder::default();
        b.offer("aaa[0-9]+\\.com", "(static)");
        b.offer("bbb[0-9]+\\.net", "(static)");
        let r = b.build();
        let hit = r.find("www.bbb42.net").expect("match");
        assert_eq!(hit.candidate, "bbb[0-9]+\\.net");
        assert_eq!(&"www.bbb42.net"[hit.start..hit.end], "bbb42.net");
        assert!(r.find("nothing.here").is_none());
    }

    #[test]
    fn group_syntax_matches_cpython() {
        assert!(python_group_syntax_ok(r"(?P<a>x)(?P<b>y)"));
        assert!(!python_group_syntax_ok(r"(?P<dup>a)(?P<dup>b)"), "CPython rejects a redefinition");
        assert!(!python_group_syntax_ok(r"(?<name>x)"), "CPython has no (?<name> syntax");
        assert!(python_group_syntax_ok(r"(?<=look)behind"), "lookbehind is not a group name");
        assert!(python_group_syntax_ok(r"(?<!neg)lookbehind"));
        assert!(!python_group_syntax_ok(r"(?P<g0>x)"), "would collide with our own group names");
        assert!(python_group_syntax_ok(r"(?P<gx>x)"));
        assert!(python_group_syntax_ok(r"plain[a-z]+"));
        assert!(python_group_syntax_ok(r"escaped\\(?not-a-group"));
    }

    #[test]
    fn lookaround_patterns_use_the_backtracking_engine() {
        // CPython accepts look-around; the regex crate does not. The trail must still match.
        let mut b = TrailRegexBuilder::default();
        b.offer(r"evil(?=\.com)[a-z.]*", "(static)");
        let r = b.build();
        assert_eq!(r.len(), 1);
        assert!(r.uses_backtracking());
        assert!(r.skipped().is_empty());
        let hit = r.find("www.evil.com").expect("lookahead trail must match");
        assert_eq!(hit.candidate, r"evil(?=\.com)[a-z.]*");
        assert!(r.find("evil.net").is_none());
    }

    #[test]
    fn feed_truncated_patterns_are_repaired_not_dropped() {
        // The real shape seen in trails.csv: an alternation cut mid-word after the last `|`.
        let truncated = r"\b[a-z0-9]{1,3}\-(aegin|aiful|amazon|nzpost|b";
        assert!(!can_compile_trail(truncated), "the raw pattern must not compile");
        let repaired = repair_truncated(truncated).expect("repairable");
        assert_eq!(repaired, r"\b[a-z0-9]{1,3}\-(aegin|aiful|amazon|nzpost)");

        let mut b = TrailRegexBuilder::default();
        b.offer(truncated, "(static)");
        let r = b.build();
        assert_eq!(r.len(), 1, "the trail must be kept");
        assert!(r.skipped().is_empty());
        assert_eq!(r.repaired(), &[truncated.to_string()]);
        // it matches the intact alternatives ...
        let hit = r.find("x-nzpost.example").expect("intact alternative must match");
        assert_eq!(hit.candidate, truncated, "the lookup key stays the verbatim CSV trail");
        assert!(r.find("x-amazon.example").is_some());
        // ... and NOT the dropped one-character fragment, which would be a false-positive cannon
        assert!(r.find("x-b.example").is_none(), "the truncated fragment must not be matched");
    }

    #[test]
    fn repair_only_applies_to_unterminated_groups() {
        // broken, but with no unterminated group -> not our shape
        assert!(repair_truncated(r"a{bad").is_none());
        assert!(repair_truncated(r"(a|b)").is_none(), "a valid pattern needs no repair");
        assert!(repair_truncated(r"[unterminated").is_none(), "an open class is not handled");
        // an unterminated group with no alternative at all cannot be salvaged meaningfully
        assert!(repair_truncated(r"\b(onlyone").is_none());
        // nested groups are closed in the right number
        let repaired = repair_truncated(r"\b(a|b(c|d)|e").expect("repairable");
        assert_eq!(repaired, r"\b(a|b(c|d))");
        assert!(pyre::build(&repaired).is_ok());
    }

    #[test]
    fn truly_uncompilable_patterns_are_skipped_by_both_engines() {
        // An unterminated group with no complete alternative to fall back on cannot be salvaged:
        // truncating at "the last |" would leave nothing of the indicator.
        let mut b = TrailRegexBuilder::default();
        b.offer(r"\b(onlyone[a-z]*", "(static)");
        let r = b.build();
        assert_eq!(r.len(), 0);
        assert_eq!(r.skipped().len(), 1);
        assert!(r.repaired().is_empty());
        assert!(r.is_empty());
    }

    #[test]
    fn group_cap_is_one_hundred() {
        let mut b = TrailRegexBuilder::default();
        for i in 0..150 {
            b.offer(&format!("t{i}[0-9]+\\.com"), "(static)");
        }
        assert_eq!(b.build().len(), 100);
    }
}
