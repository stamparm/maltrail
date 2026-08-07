//! Terminal colouring, a port of `core/colorized.py`.
//!
//! Python installs a `ColorizedStream` wrapper over `sys.stdout` **and** `sys.stderr` when
//! stdout is a TTY, so both the operational output and the `--console` event stream are
//! coloured. The same rules, in the same order, are applied here.
//!
//! Colouring is decided once at startup: if stdout is not a TTY (a pipe, a log file, a
//! systemd journal) nothing is emitted, so redirected output stays byte-identical to the
//! uncoloured form.

use std::sync::OnceLock;

use regex::Regex;

// core/enums.py:COLOR
const LIGHT_BLUE: &str = "\x1b[94m";
const LIGHT_YELLOW: &str = "\x1b[93m";
const LIGHT_CYAN: &str = "\x1b[96m";
const BOLD_LIGHT_RED: &str = "\x1b[91;1m";
const BOLD_WHITE: &str = "\x1b[97;1m";
const BOLD_LIGHT_GREEN: &str = "\x1b[92;1m";
const BOLD_LIGHT_MAGENTA: &str = "\x1b[95;1m";
const LIGHT_GRAY: &str = "\x1b[37m";
const LIGHT_RED: &str = "\x1b[91m";
const YELLOW: &str = "\x1b[33m";
const BLUE: &str = "\x1b[34m";
const WHITE: &str = "\x1b[97m";
const UNDERLINE: &str = "\x1b[4m";
const RESET: &str = "\x1b[0m";

// core/enums.py:BACKGROUND
const BG_BLUE: &str = "\x1b[44m";
const BG_MAGENTA: &str = "\x1b[45m";
const BG_RED: &str = "\x1b[41m";
const BG_YELLOW: &str = "\x1b[43m";
const BG_GREEN: &str = "\x1b[42m";
const BG_CYAN: &str = "\x1b[46m";
const BG_DARK_GRAY: &str = "\x1b[100m";

/// `_log_colors` — the marker character inside `[x]`.
fn log_color(marker: char) -> Option<&'static str> {
    Some(match marker {
        'i' => LIGHT_BLUE,
        '!' => LIGHT_YELLOW,
        '*' => LIGHT_CYAN,
        'x' => BOLD_LIGHT_RED,
        '?' => LIGHT_YELLOW,
        'o' => BOLD_WHITE,
        '+' => BOLD_LIGHT_GREEN,
        '^' => BOLD_LIGHT_GREEN,
        _ => return None,
    })
}

/// `_type_colors` — the event's trail type.
fn type_color(trail_type: &str) -> &'static str {
    match trail_type {
        "DNS" => BG_BLUE,
        "UA" => BG_MAGENTA,
        "IP" | "IPORT" => BG_RED,
        "URL" => BG_YELLOW,
        "HTTP" => BG_GREEN,
        "PATH" => BG_CYAN,
        "PORT" => BG_DARK_GRAY,
        _ => WHITE,
    }
}

/// `_info_colors` — the severity word inside the info field.
fn info_color(word: &str) -> Option<&'static str> {
    Some(match word {
        "malware" => LIGHT_RED,
        "suspicious" => LIGHT_YELLOW,
        "malicious" => YELLOW,
        _ => return None,
    })
}

struct Patterns {
    marker: Regex,
    product: Regex,
    url: Regex,
    usage: Regex,
    event_type: Regex,
    first_quoted: Regex,
    info_word: Regex,
    parenthesised: Regex,
    single_quoted: Regex,
}

fn patterns() -> &'static Patterns {
    static PATTERNS: OnceLock<Patterns> = OnceLock::new();
    PATTERNS.get_or_init(|| Patterns {
        marker: Regex::new(r"^(\s*)\[(.)\]").expect("marker"),
        // `(sensor)` is this sensor; `(old sensor)` is the Python reference implementation, which
        // is still run by the differential parity harness.
        product: Regex::new(r"\((old sensor|rust sensor|sensor|server)\)").expect("product"),
        url: Regex::new(r"https?://[\w.:/?=]+").expect("url"),
        usage: Regex::new(r"(?s)^(.*Usage: )(.+)$").expect("usage"),
        event_type: Regex::new(r"(TCP|UDP|ICMP|ICMPV6|IGMP|GRE|ESP|AH|SCTP) ([A-Z]+)").expect("event type"),
        first_quoted: Regex::new(r#""([^"]+)""#).expect("first quoted"),
        info_word: Regex::new(r"\((malware|suspicious|malicious)\)").expect("info word"),
        parenthesised: Regex::new(r"\(([^)]+)\)").expect("parenthesised"),
        single_quoted: Regex::new(r"([^\w])'([^']+)'").expect("single quoted"),
    })
}

static ENABLED: OnceLock<bool> = OnceLock::new();

/// `core/colorized.py:init_output()` — colour only when stdout is a TTY. `force` mirrors a
/// `NO_COLOR`-style opt-out and is also what the tests use.
pub fn init(force: Option<bool>) {
    let enabled = match force {
        Some(value) => value,
        None => {
            if std::env::var_os("NO_COLOR").is_some() {
                false
            } else {
                // SAFETY: isatty() only inspects the descriptor and cannot fail unsafely.
                unsafe { libc::isatty(libc::STDOUT_FILENO) == 1 }
            }
        }
    };
    let _ = ENABLED.set(enabled);
}

pub fn enabled() -> bool {
    *ENABLED.get().unwrap_or(&false)
}

/// Apply `ColorizedStream.write()`'s rules to one line of output.
pub fn colorize(text: &str) -> std::borrow::Cow<'_, str> {
    if !enabled() {
        return std::borrow::Cow::Borrowed(text);
    }
    std::borrow::Cow::Owned(colorize_always(text))
}

/// The transformation itself, independent of whether colouring is enabled (so it is testable).
pub fn colorize_always(text: &str) -> String {
    let p = patterns();
    let mut out = text.to_string();

    // 1. the "[i]" / "[!]" / ... marker
    if let Some(caps) = p.marker.captures(&out) {
        let whole = caps.get(0).map(|m| m.as_str().to_string()).unwrap_or_default();
        let indent = caps.get(1).map(|m| m.as_str().to_string()).unwrap_or_default();
        let marker = caps.get(2).and_then(|m| m.as_str().chars().next());
        if let Some(marker) = marker {
            if let Some(color) = log_color(marker) {
                out = out.replacen(&whole, &format!("{indent}[{color}{marker}{RESET}]"), 1);
            }
        }
    }

    // 2. the banner
    if out.contains("Maltrail (") {
        out = p
            .product
            .replace_all(&out, |caps: &regex::Captures| {
                let name = caps.get(1).map(|m| m.as_str()).unwrap_or("");
                let color = if name == "server" { BOLD_LIGHT_MAGENTA } else { BOLD_LIGHT_GREEN };
                format!("({color}{name}{RESET})")
            })
            .to_string();
        out = p
            .url
            .replace_all(&out, |caps: &regex::Captures| {
                format!("{BLUE}{UNDERLINE}{}{RESET}", caps.get(0).map(|m| m.as_str()).unwrap_or(""))
            })
            .to_string();
    }

    // 3. usage text
    if out.contains("Usage: ") {
        out = p
            .usage
            .replace(&out, |caps: &regex::Captures| {
                format!(
                    "{}{BOLD_WHITE}{}{RESET}",
                    caps.get(1).map(|m| m.as_str()).unwrap_or(""),
                    caps.get(2).map(|m| m.as_str()).unwrap_or("")
                )
            })
            .to_string();
    }

    // 4. event lines (they start with a quoted timestamp: `"2026-...`)
    if out.starts_with("\"2") {
        out = p
            .event_type
            .replace_all(&out, |caps: &regex::Captures| {
                let proto = caps.get(1).map(|m| m.as_str()).unwrap_or("");
                let trail_type = caps.get(2).map(|m| m.as_str()).unwrap_or("");
                format!("{proto} {}{trail_type}{RESET}", type_color(trail_type))
            })
            .to_string();
        // only the FIRST quoted run (the timestamp)
        out = p
            .first_quoted
            .replace(&out, |caps: &regex::Captures| {
                format!("\"{LIGHT_GRAY}{}{RESET}\"", caps.get(1).map(|m| m.as_str()).unwrap_or(""))
            })
            .to_string();
        out = p
            .info_word
            .replace_all(&out, |caps: &regex::Captures| {
                let word = caps.get(1).map(|m| m.as_str()).unwrap_or("");
                format!("({}{word}{RESET})", info_color(word).unwrap_or(WHITE))
            })
            .to_string();
        out = p
            .parenthesised
            .replace_all(&out, |caps: &regex::Captures| {
                let inner = caps.get(1).map(|m| m.as_str()).unwrap_or("");
                if info_color(inner).is_some() {
                    // already handled above; leave it alone
                    caps.get(0).map(|m| m.as_str()).unwrap_or("").to_string()
                } else {
                    format!("({LIGHT_GRAY}{inner}{RESET})")
                }
            })
            .to_string();
    }

    // 5. single-quoted values anywhere
    out = p
        .single_quoted
        .replace_all(&out, |caps: &regex::Captures| {
            format!(
                "{}'{LIGHT_GRAY}{}{RESET}'",
                caps.get(1).map(|m| m.as_str()).unwrap_or(""),
                caps.get(2).map(|m| m.as_str()).unwrap_or("")
            )
        })
        .to_string();

    out
}

/// `println!` with colouring applied.
#[macro_export]
macro_rules! cprintln {
    () => { println!() };
    ($($arg:tt)*) => {{
        let line = format!($($arg)*);
        println!("{}", $crate::colorized::colorize(&line));
    }};
}

/// `eprintln!` with colouring applied.
#[macro_export]
macro_rules! ceprintln {
    () => { eprintln!() };
    ($($arg:tt)*) => {{
        let line = format!($($arg)*);
        eprintln!("{}", $crate::colorized::colorize(&line));
    }};
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn colours_the_log_marker() {
        assert_eq!(colorize_always("[i] hello"), format!("[{LIGHT_BLUE}i{RESET}] hello"));
        assert_eq!(colorize_always("[!] warn"), format!("[{LIGHT_YELLOW}!{RESET}] warn"));
        assert_eq!(colorize_always("[^] running..."), format!("[{BOLD_LIGHT_GREEN}^{RESET}] running..."));
        // an unknown marker is left alone
        assert_eq!(colorize_always("[z] nope"), "[z] nope");
    }

    #[test]
    fn colours_the_banner_and_url() {
        let text = colorize_always("Maltrail (sensor) #v2.2 {https://maltrail.github.io}");
        assert!(text.contains(&format!("({BOLD_LIGHT_GREEN}sensor{RESET})")), "{text}");
        let old = colorize_always("Maltrail (old sensor) #v2.2 {https://maltrail.github.io}");
        assert!(old.contains(&format!("({BOLD_LIGHT_GREEN}old sensor{RESET})")), "{old}");
        assert!(text.contains(&format!("{BLUE}{UNDERLINE}https://maltrail.github.io{RESET}")), "{text}");
    }

    #[test]
    fn colours_an_event_line() {
        // Exact output is pinned against core/colorized.py in tests/vectors.rs; here we assert
        // the properties that matter for readability.
        let line = "\"2026-08-05 23:31:02.122079\" Laptop 10.13.13.2 - 221.8.69.25 - ICMP IP \
                    221.8.69.25 \"sinkhole conficker (malware)\" (static)";
        let text = colorize_always(line);
        assert!(text.contains(&format!("ICMP {BG_RED}IP{RESET}")), "{text}");
        assert!(text.contains(&format!("\"{LIGHT_GRAY}2026-08-05 23:31:02.122079{RESET}\"")), "{text}");
        assert!(text.contains(LIGHT_RED), "the malware severity word must be coloured: {text}");
        assert!(text.contains(&format!("({LIGHT_GRAY}static{RESET})")), "{text}");
    }

    #[test]
    fn colours_every_trail_type() {
        for (trail_type, expected) in [
            ("DNS", BG_BLUE),
            ("UA", BG_MAGENTA),
            ("IP", BG_RED),
            ("IPORT", BG_RED),
            ("URL", BG_YELLOW),
            ("HTTP", BG_GREEN),
            ("PATH", BG_CYAN),
            ("PORT", BG_DARK_GRAY),
        ] {
            let line = format!("\"2026-01-01 00:00:00.000000\" s 1.2.3.4 1 5.6.7.8 2 TCP {trail_type} t i r");
            let text = colorize_always(&line);
            assert!(text.contains(&format!("TCP {expected}{trail_type}{RESET}")), "{trail_type}: {text}");
        }
    }

    #[test]
    fn colours_single_quoted_values() {
        let text = colorize_always("[i] using configuration file '/tmp/maltrail.conf'");
        assert!(text.contains(&format!("'{LIGHT_GRAY}/tmp/maltrail.conf{RESET}'")), "{text}");
    }

    #[test]
    fn non_event_lines_are_not_event_coloured() {
        // "IP" in a diagnostic line must not get a background colour
        let text = colorize_always("[i] trails: ipv4=1 TCP IP something");
        assert!(!text.contains(BG_RED), "{text}");
    }

    #[test]
    fn disabled_colouring_is_a_no_op() {
        // colorize() consults the global switch; the tests above use colorize_always()
        let line = "[i] hello";
        if !enabled() {
            assert_eq!(colorize(line), line);
        }
    }
}
