//! Python `re` compatibility shims.
//!
//! Two jobs:
//!  1. `escape()` reproduces `re.escape()` (CPython >= 3.7 semantics) so that the
//!     `data/ua.txt` loader builds the *same* `SUSPICIOUS_UA_REGEX` alternation as
//!     `core/settings.py:read_ua()`.
//!  2. `translate()` rewrites the handful of Python-only constructs that appear in
//!     Maltrail's patterns into `regex`-crate syntax. Only `\Z` (Python: end of
//!     string) differs; the crate spells it `\z`. Everything else Maltrail uses
//!     (`\A`, `\b`, `\d`, `\w`, `(?i)`, `(?im)`, `(?P<name>...)`, non-greedy,
//!     bounded repetition, escaped punctuation from `re.escape`) is accepted as-is.

/// CPython's `re._special_chars_map` (3.7+): only characters that can carry special
/// meaning are escaped.
const SPECIAL: &[u8] = b"()[]{}?*+-|^$\\.&~# \t\n\r\x0b\x0c";

pub fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 8);
    for ch in s.chars() {
        if (ch as u32) < 128 && SPECIAL.contains(&(ch as u8)) {
            out.push('\\');
        }
        out.push(ch);
    }
    out
}

/// Classify a `{` in a Python pattern: is it the start of a repetition, and if so does it
/// need rewriting for the `regex` crate?
enum Brace {
    /// Not a repetition — Python treats it as a literal, the crate refuses to parse it.
    Literal,
    /// A repetition the crate accepts verbatim (`{n}`, `{n,}`, `{n,m}`).
    Keep,
    /// Python's `{,m}` (== `{0,m}`), which the crate rejects; rewrite with an explicit 0.
    LowerBoundOmitted(usize),
}

fn classify_brace(b: &[u8], start: usize) -> Brace {
    // start points at '{'
    let mut i = start + 1;
    let lo_start = i;
    while i < b.len() && b[i].is_ascii_digit() {
        i += 1;
    }
    let lo_digits = i - lo_start;
    let mut saw_comma = false;
    if i < b.len() && b[i] == b',' {
        saw_comma = true;
        i += 1;
        while i < b.len() && b[i].is_ascii_digit() {
            i += 1;
        }
    }
    if i >= b.len() || b[i] != b'}' {
        return Brace::Literal;
    }
    let hi_digits = i - lo_start - lo_digits - usize::from(saw_comma);
    if lo_digits == 0 {
        // "{}" / "{,}" are literals in Python; "{,m}" is a repetition with lower bound 0.
        if saw_comma && hi_digits > 0 {
            return Brace::LowerBoundOmitted(i);
        }
        return Brace::Literal;
    }
    Brace::Keep
}

/// Rewrite a Python pattern for the `regex` crate. Character-class aware so a literal
/// `\Z` inside `[...]` is left alone (Python treats it as an escape there too, but the
/// crate rejects it, so it is rewritten to `\x5a`).
///
/// Two constructs are rewritten:
///  * `\Z` -> `\z` (both mean end-of-string).
///  * a `{` that does not open a valid repetition -> `\{`. Python's parser falls back to
///    treating such a brace as a literal (e.g. the shipped SSTI pattern `\${[^&]+\}` and
///    the Shellshock user-agent `\(\) { :;`), whereas the crate rejects it outright.
///    `{,m}` becomes `{0,m}` for the same reason.
pub fn translate(pattern: &str) -> String {
    let b = pattern.as_bytes();
    let mut out = String::with_capacity(pattern.len() + 8);
    let mut i = 0usize;
    let mut in_class = false;
    while i < b.len() {
        let c = b[i];
        if c == b'\\' && i + 1 < b.len() {
            let n = b[i + 1];
            match n {
                b'Z' if !in_class => out.push_str("\\z"),
                b'Z' => out.push_str("\\x5a"),
                // \p{...} / \P{...} are Unicode-class escapes for the crate; keep the
                // brace group intact instead of escaping it below.
                b'p' | b'P' if !in_class && b.get(i + 2) == Some(&b'{') => {
                    if let Some(close) = b[i + 2..].iter().position(|&x| x == b'}') {
                        out.push_str(&pattern[i..i + 2 + close + 1]);
                        i += 2 + close + 1;
                        continue;
                    }
                    out.push('\\');
                    out.push(n as char);
                }
                _ => {
                    out.push('\\');
                    // Copy the whole escape (may be multi-byte for a UTF-8 char).
                    let start = i + 1;
                    let mut end = start + 1;
                    while end < b.len() && (b[end] & 0xc0) == 0x80 {
                        end += 1;
                    }
                    out.push_str(&pattern[start..end]);
                    i = end;
                    continue;
                }
            }
            i += 2;
            continue;
        }
        if !in_class && c == b'{' {
            match classify_brace(b, i) {
                Brace::Literal => {
                    out.push_str("\\{");
                    i += 1;
                    continue;
                }
                Brace::Keep => {}
                Brace::LowerBoundOmitted(close) => {
                    out.push_str("{0");
                    out.push_str(&pattern[i + 1..=close]);
                    i = close + 1;
                    continue;
                }
            }
        }
        if !in_class && c == b'[' {
            in_class = true;
        } else if in_class && c == b']' {
            in_class = false;
        }
        // Copy one (possibly multi-byte) character.
        let mut end = i + 1;
        while end < b.len() && (b[end] & 0xc0) == 0x80 {
            end += 1;
        }
        out.push_str(&pattern[i..end]);
        i = end;
    }
    out
}

/// Compile a Maltrail-internal pattern. Panicking here is correct: these patterns are
/// compiled once at startup from constants we control, and a broken one is a build bug.
pub fn compile(pattern: &str) -> regex::Regex {
    build(pattern).unwrap_or_else(|e| panic!("internal regex {pattern:?} failed to compile: {e}"))
}

/// In Python, escaping any ASCII punctuation yields that literal character (only unknown
/// *alphanumeric* escapes are errors). The `regex` crate is stricter and rejects a few of
/// them (`\>` for instance, which appears in `data/ua.txt`). Rewriting every punctuation
/// escape as an explicit `\x{..}` codepoint is always literal and always accepted.
fn hex_escape_punctuation(pattern: &str) -> String {
    let b = pattern.as_bytes();
    let mut out = String::with_capacity(pattern.len() + 16);
    let mut i = 0usize;
    while i < b.len() {
        if b[i] == b'\\' && i + 1 < b.len() {
            let n = b[i + 1];
            if n.is_ascii() && !n.is_ascii_alphanumeric() && n != b'_' {
                out.push_str(&format!("\\x{{{:x}}}", n));
                i += 2;
                continue;
            }
            out.push('\\');
            out.push(n as char);
            i += 2;
            continue;
        }
        let mut end = i + 1;
        while end < b.len() && (b[end] & 0xc0) == 0x80 {
            end += 1;
        }
        out.push_str(&pattern[i..end]);
        i = end;
    }
    out
}

/// Why a Python pattern could not be turned into a `regex::Regex`.
#[derive(Debug)]
pub enum Error {
    Regex(regex::Error),
    /// CPython itself rejects the pattern, so Maltrail's loaders must treat it as
    /// non-compiling too (otherwise Rust would keep a trail/user-agent pattern that the
    /// Python sensor escapes into a literal).
    PythonIncompatible(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Regex(e) => write!(f, "{e}"),
            Error::PythonIncompatible(msg) => f.write_str(msg),
        }
    }
}

impl std::error::Error for Error {}

/// CPython >= 3.11 raises "global flags not at the start of the expression" for a bare
/// `(?i)` / `(?im)` group anywhere but position 0. The `regex` crate happily accepts it,
/// so the check has to be explicit to keep the two loaders in agreement.
fn has_late_global_flags(pattern: &str) -> bool {
    let b = pattern.as_bytes();
    let mut i = 0usize;
    let mut in_class = false;
    while i < b.len() {
        match b[i] {
            b'\\' => {
                i += 2;
                continue;
            }
            b'[' if !in_class => in_class = true,
            b']' if in_class => in_class = false,
            b'(' if !in_class && i > 0 && b.get(i + 1) == Some(&b'?') => {
                let mut j = i + 2;
                while j < b.len() && matches!(b[j], b'a' | b'i' | b'L' | b'm' | b's' | b'u' | b'x') {
                    j += 1;
                }
                if j > i + 2 && b.get(j) == Some(&b')') {
                    return true;
                }
            }
            _ => {}
        }
        i += 1;
    }
    false
}

fn builder(pattern: &str) -> regex::RegexBuilder {
    let mut b = regex::RegexBuilder::new(pattern);
    // The user-agent alternation from data/ua.txt has ~1300 branches and exceeds the
    // crate's default 10 MB program-size limit.
    b.size_limit(256 << 20).dfa_size_limit(64 << 20);
    b
}

/// Compile a Python pattern with the `regex` crate.
pub fn build(pattern: &str) -> Result<regex::Regex, Error> {
    if has_late_global_flags(pattern) {
        return Err(Error::PythonIncompatible("global flags not at the start of the expression".to_string()));
    }
    let translated = translate(pattern);
    match builder(&translated).build() {
        Ok(re) => Ok(re),
        Err(first) => {
            // Second chance with every punctuation escape spelled out as a codepoint.
            let strict = hex_escape_punctuation(&translated);
            if strict == translated {
                return Err(Error::Regex(first));
            }
            builder(&strict).build().map_err(|_| Error::Regex(first))
        }
    }
}

/// Operator-supplied patterns may use look-around (the shipped `REMOTE_SEVERITY_REGEX`
/// does), which the `regex` crate cannot express, so those go through `fancy-regex`.
pub fn build_fancy(pattern: &str) -> Result<fancy_regex::Regex, Error> {
    if has_late_global_flags(pattern) {
        return Err(Error::PythonIncompatible("global flags not at the start of the expression".to_string()));
    }
    fancy_regex::RegexBuilder::new(&translate(pattern)).build().map_err(|e| Error::PythonIncompatible(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escape_matches_cpython() {
        // Verified against CPython 3.12 re.escape().
        assert_eq!(escape("Mozilla/5.0 (compatible; MSIE 9.0)"), r"Mozilla/5\.0\ \(compatible;\ MSIE\ 9\.0\)");
        assert_eq!(escape("a-b"), r"a\-b");
        assert_eq!(escape("plain_Text9"), "plain_Text9");
        assert_eq!(escape("a#b~c&d"), r"a\#b\~c\&d");
        assert_eq!(escape("x\ty"), "x\\\ty");
    }

    #[test]
    fn translate_end_anchor() {
        assert_eq!(translate(r"\A[a-z]+\Z"), r"\A[a-z]+\z");
        assert_eq!(translate(r"[\Z]"), r"[\x5a]");
        assert_eq!(translate(r"\d+\.\d+\Z"), r"\d+\.\d+\z");
        assert_eq!(translate(r"a\\Zb"), r"a\\Zb");
    }

    #[test]
    fn translate_literal_braces() {
        // Python keeps a non-repetition '{' as a literal; the regex crate refuses to.
        assert_eq!(translate(r"\${[^&]+\}"), r"\$\{[^&]+\}");
        assert_eq!(translate(r"\(\) { :;"), r"\(\) \{ :;");
        assert_eq!(translate("a{}b"), r"a\{}b");
        assert_eq!(translate("a{ }b"), r"a\{ }b");
        // valid repetitions are untouched
        assert_eq!(translate("a{2}"), "a{2}");
        assert_eq!(translate("a{2,}"), "a{2,}");
        assert_eq!(translate("a{2,5}?"), "a{2,5}?");
        assert_eq!(translate("[{]"), "[{]");
        // Python's omitted lower bound
        assert_eq!(translate("a{,5}"), "a{0,5}");
        // Unicode class escapes keep their brace group
        assert_eq!(translate(r"\p{Greek}+"), r"\p{Greek}+");
    }

    #[test]
    fn literal_brace_patterns_compile_and_match_like_python() {
        let re = build(r"\${[^&]+\}").unwrap();
        assert!(re.is_match("x=${7*7}"));
        assert!(!re.is_match("x=$7*7"));
        let re = build(r"(?i)\(\) { :;").unwrap();
        assert!(re.is_match("() { :; }; echo vulnerable"));
        let re = build("a{,5}").unwrap();
        assert!(re.is_match(""));
    }

    #[test]
    fn compiles_maltrail_patterns() {
        for p in [
            r"\A[a-zA-Z0-9.-]*\.[a-zA-Z0-9-]+\Z",
            r"(?i)\A([rd]?ns|nf|mx|nic)\d*\.",
            r"\A\d+\-\d+\-\d+\-\d+\Z",
            r"(?im)^(X-Sinkhole|Server): (malware-?)?sinkhole",
            r"\A[\w./-]*/[\w.]*\b(aarch|amd64\b|x86)\Z",
            r"(\w+=)[^&=]+",
            r"\b(CF-Connecting-IP|True-Client-IP|X-Forwarded-For):\s*([0-9.]+)",
        ] {
            assert!(build(p).is_ok(), "{p}");
        }
    }

    #[test]
    fn python_rejects_late_global_flags() {
        // the one data/ua.txt line CPython refuses to compile
        assert!(has_late_global_flags(r"(?i)a|(?i)b"));
        assert!(build(r"(?i)a|(?i)b").is_err());
        // a leading flag group is fine, and scoped flags are fine anywhere
        assert!(!has_late_global_flags(r"(?i)abc"));
        assert!(!has_late_global_flags(r"a(?i:b)c"));
        assert!(!has_late_global_flags(r"a(?P<n>b)c"));
        assert!(!has_late_global_flags(r"a(?!b)c"));
        assert!(!has_late_global_flags(r"a\(?i\)b"));
    }

    #[test]
    fn punctuation_escapes_the_crate_dislikes_still_compile() {
        // from data/ua.txt: Python treats \> as a literal '>'
        let re = build(r"<script src=[^\>]*>").unwrap();
        assert!(re.is_match("<script src=x>"));
    }

    #[test]
    fn fancy_handles_lookahead() {
        let re = build_fancy(r"(?P<high>malware(?! (distribution|site)))|(?P<low>reputation)").unwrap();
        let hit = re.captures("known malware c2").unwrap().expect("lookahead should match");
        assert!(hit.name("high").is_some());
        // the negative lookahead suppresses the match entirely here
        assert!(matches!(re.captures("malware distribution"), Ok(None)));
        assert!(re.captures("reputation x").unwrap().unwrap().name("low").is_some());
    }
}
