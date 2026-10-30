//! Runtime settings: the generated constants plus the compiled regexes / multi-pattern
//! matchers built from them.
//!
//! Everything here is built exactly once at startup and then only read, so the packet
//! path never compiles a regex and never takes a lock.

use crate::fasthash::FastSet;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use aho_corasick::AhoCorasick;
use regex::Regex;

pub use crate::settings_gen::*;

/// Hard cap on the number of distinct `(src_ip, trail)` groups the condense buffer may hold
/// between flushes.
///
/// Not a `core/settings.py` constant: `MAX_CONDENSED_EVENTS` bounds each GROUP but
/// never the number of groups, and the map only shrinks on the flush period. Both halves of
/// the key are attacker-influenced, so that is unbounded growth on a busy link. At the cap the
/// event is written through the normal throttled path rather than aggregated — an event is a
/// detection and must never be dropped to save memory.
pub const MAX_CONDENSED_KEYS: usize = 50_000;

use crate::pyre;

/// `core/settings.py:ROOT_DIR` equivalent: the Maltrail checkout that owns `data/`.
pub fn resolve_root(config_file: &Path) -> PathBuf {
    if let Ok(env) = std::env::var("MALTRAIL_ROOT") {
        if !env.is_empty() {
            return absolute(PathBuf::from(env));
        }
    }
    // maltrail.conf lives at the repository root next to data/, html/, core/.
    if let Some(dir) = config_file.parent() {
        if dir.join("data").is_dir() {
            return absolute(dir.to_path_buf());
        }
    }
    // Fall back to walking up from the executable (sensor/target/<profile>/bin).
    if let Ok(exe) = std::env::current_exe() {
        let mut cur = exe.parent().map(|p| p.to_path_buf());
        while let Some(dir) = cur {
            if dir.join("data").is_dir() && dir.join("maltrail.conf").is_file() {
                return dir;
            }
            cur = dir.parent().map(|p| p.to_path_buf());
        }
    }
    std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
}

/// Absolute form of `path`, without requiring it to exist (`std::path::absolute` is 1.79, the
/// MSRV here is 1.74).
///
/// `resolve_root` MUST return an absolute directory. `-c maltrail.conf` (a relative name, which
/// is also the built-in default) has `""` for a parent, and an empty root is not merely untidy:
/// `trailupdate::run` passes it to `Command::current_dir`, and `chdir("")` fails with ENOENT, so
/// the trail update died with "unable to run python3.12: No such file or directory" — an error
/// about the interpreter, which was present and fine. The sensor then ran on with an empty trail
/// set, detecting nothing.
///
/// Measured in the Docker image, where the binary lives in /usr/local/bin so the walk up from the
/// executable finds no repository and the relative default is what remains. A tarball install
/// that puts the binary on PATH lands in exactly the same place; the systemd unit does not,
/// because /opt/maltrail/sensor/target/release/maltrail-sensor finds ../../../maltrail.conf and
/// that path is absolute.
fn absolute(path: PathBuf) -> PathBuf {
    if path.as_os_str().is_empty() {
        return std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    }
    if path.is_absolute() {
        return path;
    }
    match std::env::current_dir() {
        Ok(cwd) => cwd.join(path),
        Err(_) => path,
    }
}

/// Iterate stripped, non-blank, non-comment lines (`core/settings.py:_iter_file_lines`).
pub fn iter_file_lines(path: &Path) -> Vec<String> {
    let Ok(data) = std::fs::read(path) else {
        return Vec::new();
    };
    let text = String::from_utf8_lossy(&data);
    text.lines().map(|l| l.trim().to_string()).filter(|l| !l.is_empty() && !l.starts_with('#')).collect()
}

/// `core/settings.py:read_ua()` — rebuild SUSPICIOUS_UA_REGEX from `data/ua.txt` so an
/// operator editing that file affects the sensor exactly as it affects
/// `core/settings.py`. Falls back to the generated snapshot when the file is unavailable.
pub fn build_suspicious_ua_regex(root: &Path) -> String {
    let lines = iter_file_lines(&root.join("data").join("ua.txt"));
    if lines.is_empty() {
        return SUSPICIOUS_UA_REGEX.to_string();
    }
    let mut items = Vec::with_capacity(lines.len());
    for line in lines {
        if line.contains(" (compatible") {
            items.push(pyre::escape(&line));
        } else if pyre::is_valid(&line) {
            items.push(line);
        } else {
            items.push(pyre::escape(&line));
        }
    }
    format!("(?i){}", items.join("|"))
}

pub struct Statics {
    /// Prebuilt substring searchers for the fixed needles the packet path looks for. Building a
    /// `memmem::Finder` is not free; on short payloads it dominates the search itself.
    pub f_crlf: memchr::memmem::Finder<'static>,
    pub f_crlf2: memchr::memmem::Finder<'static>,
    pub f_sp_http: memchr::memmem::Finder<'static>,
    pub f_http_slash: memchr::memmem::Finder<'static>,
    pub f_host: memchr::memmem::Finder<'static>,
    pub f_user_agent: memchr::memmem::Finder<'static>,
    pub f_content_type: memchr::memmem::Finder<'static>,
    pub root: PathBuf,

    // --- domain / DNS ---
    pub valid_dns_name: Regex,
    /// `(?i)\A([rd]?ns|nf|mx|nic)\d*\.` — infrastructure-name exclusion in `check_domain`
    pub ns_like_prefix: Regex,
    /// `\A\d+\-\d+\-\d+\-\d+\Z` — dashed-IP subdomain exclusion (DNS exhaustion)
    pub dashed_quad: Regex,
    /// `bl\b` — generic DNSBL guard
    /// `bl\b` - the generic "this is a blocklist zone" test.
    ///
    /// Paired with `bl_word_prefilter` below: the regex can only match a string that contains the
    /// two bytes "bl", and running a regex engine to discover that a name does not is most of what
    /// the check cost on the DNS path, where it runs per query.
    pub bl_word: Regex,
    /// `(\.onion)(\..*)` — tor2web rewrite
    pub onion_suffix: Regex,

    // --- HTTP ---
    pub generic_sinkhole: Regex,
    pub seized_domain: Regex,
    pub suspicious_direct_ip_url: Regex,
    /// `\A\d+\.[0-9.]+\Z` — "Host is a bare dotted address"
    pub dotted_host: Regex,
    pub whitelist_ua: Regex,
    pub suspicious_ua: Option<Regex>,
    pub suspicious_http_request: Vec<(&'static str, Regex)>,
    pub suspicious_http_path: Vec<(&'static str, Regex)>,
    /// the "potential remote code execution" entry, reused as the absolute-URI FP guard
    pub code_execution: Regex,
    /// `(\w+=)[^&=]+` — parameter-value stripping for URL trail candidates
    pub param_value: Regex,
    /// `(http://[^/]+/)(.+)` — proxy-probe trail rewrite (stage 1)
    pub proxy_probe_path: Regex,
    /// `(http://)([^/(]+)` — proxy-probe trail rewrite (stage 2)
    pub proxy_probe_host: Regex,
    /// bytes regex over the raw packet for forwarded-for headers. Asked only after
    /// `has_forwarded_for_header()`: it is a case-insensitive alternation with no usable literal
    /// prefix, so asking it for capture groups meant a DFA walk over the whole packet on every
    /// HTTP request - and virtually no request carries any of these headers. Matching
    /// `"<name>:"` first is exactly implied by the regex (the colon is contiguous in the
    /// pattern), so the pre-condition can never hide a match.
    pub forwarded_for: regex::bytes::Regex,

    // --- multi-substring scanners ---
    pub pre_condition: AhoCorasick,
    pub proxy_probe_pre_condition: AhoCorasick,
    pub whitelist_request_paths: AhoCorasick,
    pub whitelist_direct_download: AhoCorasick,
    pub whitelist_long_domain: AhoCorasick,
    pub local_subdomain_lookups: AhoCorasick,
    pub condense_on_info: AhoCorasick,

    // These sets are FIXED at startup from compiled-in constants and never take a key from the
    // network, so `FxHasher` is safe here: HashDoS requires an attacker to INSERT colliding keys,
    // and nothing can be inserted. They are probed on every DNS question / HTTP response, and
    // SipHash on those probes showed up as 4.7% of the DNS path.
    pub ignore_dns_query_suffixes: FastSet<&'static str>,
    pub suspicious_content_types: FastSet<&'static str>,
    pub suspicious_download_extensions: FastSet<&'static str>,
}

static STATICS: OnceLock<Statics> = OnceLock::new();

pub fn init(root: PathBuf) -> &'static Statics {
    STATICS.get_or_init(|| Statics::build(root))
}

/// Panics if `init()` has not run; every caller is downstream of `main()`.
/// `VALID_DNS_NAME_REGEX` (`\A[a-zA-Z0-9._-]*\.[a-zA-Z0-9-]+\Z`), hand-coded.
///
/// Every DNS question runs this. A compiled regex costs ~100 ns on a short name; the pattern is
/// two character classes and an anchor, so a byte loop does it in single-digit nanoseconds.
/// `tests/vectors.rs` compares this against CPython's `re` over a generated corpus.
#[inline]
pub fn is_valid_dns_name(name: &str) -> bool {
    let b = name.as_bytes();
    // `[a-zA-Z0-9-]+` at the end, preceded by a literal '.'
    let mut i = b.len();
    while i > 0 {
        let c = b[i - 1];
        if c.is_ascii_alphanumeric() || c == b'-' {
            i -= 1;
        } else {
            break;
        }
    }
    if i == b.len() || i == 0 || b[i - 1] != b'.' {
        return false; // no trailing label, or no dot before it
    }
    // `[a-zA-Z0-9._-]*` for everything before that dot. The underscore is deliberate: it is legal
    // in a queried name (SRV, _dmarc, DKIM selectors) and common among dynamic-DNS hosts, and
    // without it 134 static trails could never match - the query was rejected before lookup.
    // It stays out of the trailing label above, where no real TLD has one.
    b[..i - 1].iter().all(|c| c.is_ascii_alphanumeric() || *c == b'.' || *c == b'-' || *c == b'_')
}

/// Does `packet` carry `CF-Connecting-IP:`, `True-Client-IP:` or `X-Forwarded-For:`, ASCII
/// case-insensitively, anywhere in it? The literal pre-condition for `forwarded_for`.
///
/// It was a case-insensitive Aho-Corasick search, which cannot use its SIMD prefilter and walks
/// every byte: 2,467 of the 9,067 instructions an ordinary HTTP request cost (callgrind, refnet's
/// requests). Every match of those patterns ends at a `:`, so asking at each colon whether the
/// bytes before it end with one of the names is the same question, and a request has only a
/// handful of colons. `forwarded_for_check_agrees_with_aho_corasick` holds the two to the same
/// answer.
#[inline]
pub fn has_forwarded_for_header(packet: &[u8]) -> bool {
    const NAMES: [&[u8]; 3] = [b"CF-Connecting-IP", b"True-Client-IP", b"X-Forwarded-For"];
    for colon in memchr::memchr_iter(b':', packet) {
        let before = &packet[..colon];
        // every name ends in "ip" or "for": one byte rules out nearly every colon
        if !matches!(before.last(), Some(b'p' | b'P' | b'r' | b'R')) {
            continue;
        }
        if NAMES
            .iter()
            .any(|name| before.len() >= name.len() && before[before.len() - name.len()..].eq_ignore_ascii_case(name))
        {
            return true;
        }
    }
    false
}

/// `\A\d+\-\d+\-\d+\-\d+\Z`, hand-coded — the dashed-quad first label check.
#[inline]
pub fn is_dashed_quad(label: &str) -> bool {
    // One pass that fails on the first letter, which is where nearly every label fails.
    let (mut groups, mut digits) = (1, 0);
    for &c in label.as_bytes() {
        if c == b'-' {
            if digits == 0 {
                return false;
            }
            groups += 1;
            digits = 0;
        } else if c.is_ascii_digit() {
            digits += 1;
        } else {
            return false;
        }
    }
    digits > 0 && groups == 4
}

pub fn statics() -> &'static Statics {
    STATICS.get().expect("settings::init() must run before statics()")
}

fn ac(patterns: &[&str]) -> AhoCorasick {
    AhoCorasick::new(patterns).expect("aho-corasick build")
}

/// `ac()` for patterns that have to match regardless of case, which is how HTTP header names
/// arrive on the wire. Kept as the oracle `has_forwarded_for_header` is tested against.
#[cfg(test)]
fn ac_nocase(patterns: &[&str]) -> AhoCorasick {
    aho_corasick::AhoCorasickBuilder::new().ascii_case_insensitive(true).build(patterns).expect("aho-corasick build")
}

impl Statics {
    pub fn build(root: PathBuf) -> Statics {
        let ua_src = build_suspicious_ua_regex(&root);
        let suspicious_ua = match pyre::build(&ua_src) {
            Ok(re) => Some(re),
            Err(e) => {
                crate::ceprintln!("[!] unable to compile SUSPICIOUS_UA_REGEX ({e}); user-agent heuristic disabled");
                None
            }
        };

        let mut suspicious_http_request = Vec::with_capacity(SUSPICIOUS_HTTP_REQUEST_REGEXES.len());
        for (desc, src) in SUSPICIOUS_HTTP_REQUEST_REGEXES {
            // case-insensitive, `.` matches newlines (re.I | re.DOTALL)
            suspicious_http_request.push((*desc, pyre::compile(&format!("(?is){src}"))));
        }
        let code_execution = SUSPICIOUS_HTTP_REQUEST_REGEXES
            .iter()
            .find(|(desc, _)| desc.contains("code execution"))
            .map(|(_, src)| pyre::compile(&format!("(?is){src}")))
            .expect("SUSPICIOUS_HTTP_REQUEST_REGEXES must carry a 'code execution' entry");

        let mut suspicious_http_path = Vec::with_capacity(SUSPICIOUS_HTTP_PATH_REGEXES.len());
        for (desc, src) in SUSPICIOUS_HTTP_PATH_REGEXES {
            suspicious_http_path.push((*desc, pyre::compile(&format!("(?i){src}"))));
        }

        Statics {
            f_crlf: memchr::memmem::Finder::new("\r\n").into_owned(),
            f_crlf2: memchr::memmem::Finder::new("\r\n\r\n").into_owned(),
            f_sp_http: memchr::memmem::Finder::new(" HTTP/").into_owned(),
            f_http_slash: memchr::memmem::Finder::new("HTTP/").into_owned(),
            f_host: memchr::memmem::Finder::new("\r\nHost:").into_owned(),
            f_user_agent: memchr::memmem::Finder::new("\r\nUser-Agent:").into_owned(),
            f_content_type: memchr::memmem::Finder::new("\r\nContent-Type:").into_owned(),

            root,
            valid_dns_name: pyre::compile(VALID_DNS_NAME_REGEX),
            ns_like_prefix: pyre::compile(r"(?i)\A([rd]?ns|nf|mx|nic)\d*\."),
            dashed_quad: pyre::compile(r"\A\d+\-\d+\-\d+\-\d+\Z"),
            bl_word: pyre::compile(r"bl\b"),
            onion_suffix: pyre::compile(r"(\.onion)(\..*)"),

            generic_sinkhole: pyre::compile(GENERIC_SINKHOLE_REGEX),
            seized_domain: pyre::compile(r"domain name has been seized by|Domain Seized|Domain Seizure"),
            suspicious_direct_ip_url: pyre::compile(SUSPICIOUS_DIRECT_IP_URL_REGEX),
            dotted_host: pyre::compile(r"\A\d+\.[0-9.]+\Z"),
            whitelist_ua: pyre::compile(&format!("(?i){WHITELIST_UA_REGEX}")),
            suspicious_ua,
            suspicious_http_request,
            suspicious_http_path,
            code_execution,
            param_value: pyre::compile(r"(\w+=)[^&=]+"),
            proxy_probe_path: pyre::compile(r"(http://[^/]+/)(.+)"),
            proxy_probe_host: pyre::compile(r"(http://)([^/(]+)"),
            // `unicode(false)` is what makes the Aho-Corasick pre-condition below EXACT rather
            // than merely usually right. The crate's default folds Unicode, so `(?i)k` would also
            // match U+212A KELVIN SIGN and `\b`/`\s` would be Unicode classes. That accepts a
            // header the ASCII pre-filter does not, so the two would disagree. ASCII on both
            // sides keeps them exact.
            forwarded_for: regex::bytes::RegexBuilder::new(
                r"\b(CF-Connecting-IP|True-Client-IP|X-Forwarded-For):\s*([0-9.]+)",
            )
            .case_insensitive(true)
            .unicode(false)
            .build()
            .expect("forwarded-for regex"),

            pre_condition: ac(SUSPICIOUS_HTTP_REQUEST_PRE_CONDITION),
            proxy_probe_pre_condition: ac(SUSPICIOUS_PROXY_PROBE_PRE_CONDITION),
            whitelist_request_paths: ac(WHITELIST_HTTP_REQUEST_PATHS),
            whitelist_direct_download: ac(WHITELIST_DIRECT_DOWNLOAD_KEYWORDS),
            whitelist_long_domain: ac(WHITELIST_LONG_DOMAIN_NAME_KEYWORDS),
            local_subdomain_lookups: ac(LOCAL_SUBDOMAIN_LOOKUPS),
            condense_on_info: ac(CONDENSE_ON_INFO_KEYWORDS),

            ignore_dns_query_suffixes: IGNORE_DNS_QUERY_SUFFIXES.iter().copied().collect(),
            suspicious_content_types: SUSPICIOUS_CONTENT_TYPES.iter().copied().collect(),
            suspicious_download_extensions: SUSPICIOUS_DIRECT_DOWNLOAD_EXTENSIONS.iter().copied().collect(),
        }
    }
}

/// `IPPROTO_LUT` lookup (protocol number -> Maltrail label).
pub fn ipproto_label(proto: u8) -> Option<&'static str> {
    IPPROTO_LUT.iter().find(|(n, _)| *n == proto).map(|(_, l)| *l)
}

/// `DLT_OFFSETS` lookup.
pub fn dlt_offset(datalink: i32) -> Option<usize> {
    DLT_OFFSETS.iter().find(|(d, _)| *d == datalink).map(|(_, o)| *o)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn root() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).parent().unwrap().to_path_buf()
    }

    #[test]
    fn forwarded_for_check_agrees_with_aho_corasick() {
        let oracle = ac_nocase(&["CF-Connecting-IP:", "True-Client-IP:", "X-Forwarded-For:"]);
        let check = |input: &[u8]| {
            assert_eq!(has_forwarded_for_header(input), oracle.is_match(input), "{:?}", String::from_utf8_lossy(input));
        };
        // every name, cut at every length, in every case pattern a 3-bit mask can make, with and
        // without the colon, at the start, in the middle and at the very end of the input
        for name in ["CF-Connecting-IP", "True-Client-IP", "X-Forwarded-For", "X-Forwarded-Host"] {
            for cut in 0..=name.len() {
                for mask in 0..8u32 {
                    let cased: String = name[..cut]
                        .chars()
                        .enumerate()
                        .map(
                            |(i, c)| {
                                if mask >> (i % 3) & 1 == 1 {
                                    c.to_ascii_lowercase()
                                } else {
                                    c.to_ascii_uppercase()
                                }
                            },
                        )
                        .collect();
                    for tail in ["", ":", ": 1.2.3.4", " :", "::"] {
                        for frame in [
                            format!("{cased}{tail}"),
                            format!("GET / HTTP/1.1\r\n{cased}{tail}\r\n"),
                            format!("x{cased}{tail}"),
                        ] {
                            check(frame.as_bytes());
                        }
                    }
                }
            }
        }
        // random bytes drawn mostly from the names' own letters, colons and separators, so that
        // near misses are common: 200,000 inputs of up to 64 bytes
        let alphabet = b"CFTXcftx-:IPipFfOoRrWwAaDdEeNnGgUuLl \r\n0.";
        let mut state = 0x2545_f491_4f6c_dd1du64;
        for _ in 0..200_000 {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            let len = (state % 65) as usize;
            let mut input = Vec::with_capacity(len);
            let mut x = state;
            for _ in 0..len {
                x = x.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
                input.push(alphabet[(x >> 33) as usize % alphabet.len()]);
            }
            check(&input);
        }
        // and the positive control: the oracle does say yes, so the loop above cannot pass vacuously
        assert!(has_forwarded_for_header(b"GET /\r\nx-forwarded-for: 1.2.3.4\r\n"));
        assert!(!has_forwarded_for_header(b"GET /\r\nX-Forwarded-Host: 1.2.3.4\r\n"));
    }

    #[test]
    fn dashed_quad_agrees_with_the_regex_exhaustively() {
        let re = regex::Regex::new(r"\A\d+-\d+-\d+-\d+\z").unwrap();
        let mut frontier = vec![String::new()];
        for _ in 0..9 {
            frontier = frontier.iter().flat_map(|s| ["1", "-", "a"].map(|c| format!("{s}{c}"))).collect();
            for s in &frontier {
                assert_eq!(is_dashed_quad(s), re.is_match(s), "{s:?}");
            }
        }
        assert!(is_dashed_quad("10-0-0-1") && !is_dashed_quad("") && !is_dashed_quad("1-2-3-4-5"));
    }

    #[test]
    fn the_repository_root_is_always_absolute() {
        // `-c maltrail.conf` used to yield "" here, and an empty root made the trail update fail
        // with ENOENT from chdir("") - reported as a missing Python interpreter. See absolute().
        for candidate in ["maltrail.conf", "conf/maltrail.conf", "./maltrail.conf"] {
            let resolved = resolve_root(Path::new(candidate));
            assert!(resolved.is_absolute(), "resolve_root({candidate:?}) -> {resolved:?}");
            assert!(resolved.is_dir(), "resolve_root({candidate:?}) -> {resolved:?} is not a directory");
        }
        assert!(resolve_root(&root().join("maltrail.conf")).is_absolute());
    }

    #[test]
    fn absolute_paths_survive_and_relative_ones_are_anchored() {
        let cwd = std::env::current_dir().unwrap();
        assert_eq!(absolute(PathBuf::new()), cwd);
        assert_eq!(absolute(PathBuf::from("maltrail.conf")), cwd.join("maltrail.conf"));
        // What counts as absolute is platform-specific: on Windows "/opt/maltrail" has no volume,
        // so it is relative to the current drive and gets one prepended. A drive-lettered path is
        // the Windows equivalent of the property being asserted.
        let already_absolute = if cfg!(windows) { "C:\\opt\\maltrail" } else { "/opt/maltrail" };
        assert_eq!(absolute(PathBuf::from(already_absolute)), PathBuf::from(already_absolute));
    }

    #[test]
    fn all_internal_regexes_compile() {
        let s = Statics::build(root());
        assert!(s.suspicious_ua.is_some(), "data/ua.txt must compile as one alternation");
        assert_eq!(s.suspicious_http_request.len(), SUSPICIOUS_HTTP_REQUEST_REGEXES.len());
        assert!(!s.suspicious_http_path.is_empty());
    }

    #[test]
    fn ua_regex_matches_python_snapshot() {
        // Proves read_ua()'s decision procedure (verbatim vs re.escape) reaches the same
        // result in Rust as in CPython for every line of data/ua.txt.
        let built = build_suspicious_ua_regex(&root());
        assert_eq!(built, SUSPICIOUS_UA_REGEX);
    }

    #[test]
    fn ipproto_and_dlt_tables() {
        assert_eq!(ipproto_label(1), Some("ICMP"));
        assert_eq!(ipproto_label(58), Some("ICMPV6"));
        assert_eq!(ipproto_label(6), Some("TCP"));
        assert_eq!(ipproto_label(17), Some("UDP"));
        assert_eq!(ipproto_label(200), None);
        assert_eq!(dlt_offset(1), Some(14));
        assert_eq!(dlt_offset(113), Some(16));
        assert_eq!(dlt_offset(12), Some(0));
        assert_eq!(dlt_offset(9999), None);
    }

    #[test]
    fn hand_coded_matchers_agree_with_the_compiled_regexes() {
        // The two hot regexes are hand-coded; they must agree with the compiled patterns on
        // everything, including the awkward cases. (tests/vectors.rs additionally compares the
        // compiled pattern against CPython's own `re`.)
        let s = Statics::build(root());
        let cases = [
            "evil.com",
            "a.b.c.d",
            "x.y",
            ".com",
            "com",
            "",
            ".",
            "..",
            "-.-",
            "a-b.c-d",
            "EVIL.COM",
            "1.2.3.4",
            "under_score.com",
            "sp ace.com",
            "tra.iling.",
            "a..b",
            "xn--d1acufc.xn--p1ai",
            "a.b-",
            "-a.b",
            "a.b.",
            "9.9",
            "a1-b2.c3",
        ];
        for case in cases {
            assert_eq!(
                is_valid_dns_name(case),
                s.valid_dns_name.is_match(case),
                "is_valid_dns_name disagrees with VALID_DNS_NAME_REGEX on {case:?}"
            );
        }
        for case in ["1-2-3-4", "10-20-30-40", "1-2-3", "1-2-3-4-5", "a-2-3-4", "1-2-3-", "-1-2-3-4", "", "1234"] {
            assert_eq!(
                is_dashed_quad(case),
                s.dashed_quad.is_match(case),
                "is_dashed_quad disagrees with the compiled pattern on {case:?}"
            );
        }
    }

    #[test]
    fn valid_dns_name_semantics() {
        let s = Statics::build(root());
        assert!(s.valid_dns_name.is_match("evil.com"));
        assert!(s.valid_dns_name.is_match("a.b.example.com"));
        assert!(!s.valid_dns_name.is_match("nodot"));
        // The underscore is accepted in every label but the last: legal in a queried name, and
        // 134 static trails were unreachable while it was refused outright.
        assert!(s.valid_dns_name.is_match("under_score.com"));
        assert!(s.valid_dns_name.is_match("_dmarc.example.com"));
        assert!(!s.valid_dns_name.is_match("evil.tld_x"));
    }
}
