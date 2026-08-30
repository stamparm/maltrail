//! `core/ignore.py` — event ignore rules and `IGNORE_EVENTS_REGEX`.
//!
//! Address and port fields accept a network or a range as well as a literal, because the literal
//! form alone is unusable at the scale people actually hit: issue #19142 is an operator with
//! 5-10k events a day whose only way to silence their own subnet was to write out every address
//! in it. A CIDR and a dash range are the same containment test, so both reduce to one inclusive
//! interval and nothing in the matcher has to know which spelling produced it.
//!
//! A token that is not a valid network or range stays an exact string comparison, so every rule
//! written before this existed keeps meaning exactly what it meant.

use std::collections::HashSet;
use std::path::Path;

use crate::addr::{addr_to_int, make_mask, parse_ipv6};
use crate::event::Event;

/// One address field of a rule.
#[derive(Debug, Clone, PartialEq, Eq)]
enum HostRule {
    Any,
    Exact(String),
    /// Inclusive interval; a CIDR is just the range its mask spans.
    V4(u32, u32),
    V6(u128, u128),
}

/// One port field of a rule.
#[derive(Debug, Clone, PartialEq, Eq)]
enum PortRule {
    Any,
    /// Compared as text: a non-port protocol writes "-" here, not a number.
    Exact(String),
    Range(u16, u16),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Rule {
    src_ip: HostRule,
    src_port: PortRule,
    dst_ip: HostRule,
    dst_port: PortRule,
}

#[derive(Debug, Default)]
pub struct IgnoreRules {
    /// `IGNORE_EVENTS` — (src_ip, src_port, dst_ip, dst_port), `*` matching anything.
    rules: Vec<Rule>,
    /// Raw tuples already seen, so the same line in both the shipped and the user file is one rule.
    seen: HashSet<(String, String, String, String)>,
    regex: Option<fancy_regex::Regex>,
    /// Set when any rule needs an address parsed to a number. Without a single range rule the
    /// matcher does exactly the string comparisons it always did.
    needs_numeric: bool,
}

/// Parse one address token into a matcher.
fn parse_host(token: &str) -> HostRule {
    if token == "*" {
        return HostRule::Any;
    }
    if let Some((addr, bits)) = token.split_once('/') {
        if let Some(rule) = cidr(addr, bits) {
            return rule;
        }
    } else if let Some((lo, hi)) = token.split_once('-') {
        if let Some(rule) = range(lo, hi) {
            return rule;
        }
    }
    HostRule::Exact(token.to_string())
}

fn cidr(addr: &str, bits: &str) -> Option<HostRule> {
    let bits: u32 = bits.parse().ok()?;
    if let Some(v4) = addr_to_int(addr) {
        if bits > 32 {
            return None;
        }
        let mask = make_mask(bits);
        return Some(HostRule::V4(v4 & mask, (v4 & mask) | !mask));
    }
    let v6 = parse_ipv6(addr)?;
    if bits > 128 {
        return None;
    }
    // Shifting by the full width is undefined, so the all-ones mask is spelled out.
    let mask: u128 = if bits == 0 { 0 } else { u128::MAX << (128 - bits) };
    Some(HostRule::V6(v6 & mask, (v6 & mask) | !mask))
}

fn range(lo: &str, hi: &str) -> Option<HostRule> {
    if let Some(start) = addr_to_int(lo) {
        // "192.168.1.10-20" is the shorthand people write; the right side is the last octet only.
        let end = match addr_to_int(hi) {
            Some(v) => v,
            None => {
                let last: u32 = hi.parse().ok()?;
                if last > 255 {
                    return None;
                }
                (start & 0xffff_ff00) | last
            }
        };
        return if end >= start { Some(HostRule::V4(start, end)) } else { None };
    }
    let start = parse_ipv6(lo)?;
    let end = parse_ipv6(hi)?;
    if end >= start {
        Some(HostRule::V6(start, end))
    } else {
        None
    }
}

fn parse_port(token: &str) -> PortRule {
    if token == "*" {
        return PortRule::Any;
    }
    if let Some((lo, hi)) = token.split_once('-') {
        if let (Ok(lo), Ok(hi)) = (lo.parse::<u16>(), hi.parse::<u16>()) {
            if hi >= lo {
                return PortRule::Range(lo, hi);
            }
        }
    }
    PortRule::Exact(token.to_string())
}

impl HostRule {
    fn is_numeric(&self) -> bool {
        matches!(self, HostRule::V4(..) | HostRule::V6(..))
    }

    /// `text` is the address as it appears in the event; `v4`/`v6` are it parsed, computed once
    /// per event by the caller rather than once per rule.
    fn matches(&self, text: &str, v4: Option<u32>, v6: Option<u128>) -> bool {
        match self {
            HostRule::Any => true,
            HostRule::Exact(want) => want == text,
            HostRule::V4(lo, hi) => v4.is_some_and(|a| a >= *lo && a <= *hi),
            HostRule::V6(lo, hi) => v6.is_some_and(|a| a >= *lo && a <= *hi),
        }
    }
}

impl PortRule {
    fn matches(&self, text: &str) -> bool {
        match self {
            PortRule::Any => true,
            PortRule::Exact(want) => want == text,
            PortRule::Range(lo, hi) => text.parse::<u16>().is_ok_and(|p| p >= *lo && p <= *hi),
        }
    }
}

impl IgnoreRules {
    /// `core/settings.py:read_ignorelist()` + `IGNORE_EVENTS_REGEX` compilation.
    pub fn load(root: &Path, user_ignorelist: Option<&Path>, events_regex: &str) -> IgnoreRules {
        let mut out = IgnoreRules::default();
        let mut files = vec![root.join("data").join("ignore_events.txt")];
        if let Some(p) = user_ignorelist {
            files.push(p.to_path_buf());
        }
        for file in files {
            out.add_file(&file);
        }

        if !events_regex.is_empty() {
            match crate::pyre::build_fancy(events_regex) {
                Ok(re) => out.regex = Some(re),
                Err(e) => {
                    // Python warns once and keeps logging rather than dropping every event.
                    crate::cprintln!(
                        "[!] invalid regular expression in option 'IGNORE_EVENTS_REGEX' ('{events_regex}'): {e}"
                    );
                }
            }
        }
        out
    }

    fn add_file(&mut self, path: &Path) {
        let Ok(data) = std::fs::read(path) else { return };
        for line in String::from_utf8_lossy(&data).lines() {
            // re.sub(r"\s+", "", line) — all whitespace removed, not just the ends
            let line: String = line.chars().filter(|c| !c.is_whitespace()).collect();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if line.matches(';').count() == 3 {
                let mut it = line.split(';');
                let a = it.next().unwrap_or_default().to_string();
                let b = it.next().unwrap_or_default().to_string();
                let c = it.next().unwrap_or_default().to_string();
                let d = it.next().unwrap_or_default().to_string();
                self.add(a, b, c, d);
            }
        }
    }

    pub fn len(&self) -> usize {
        self.rules.len()
    }

    pub fn is_empty(&self) -> bool {
        self.rules.is_empty() && self.regex.is_none()
    }

    /// `core/ignore.py:ignore_event()`
    pub fn ignore_event(&self, event: &Event) -> bool {
        if let Some(re) = &self.regex {
            // A regex error must never propagate out of the packet path.
            if matches!(re.is_match(&event.py_repr()), Ok(true)) {
                return true;
            }
        }
        if self.rules.is_empty() {
            return false;
        }
        let src_port = event.src_port.as_plain();
        let dst_port = event.dst_port.as_plain();
        let dst_ip = event.dst_ip.as_plain();

        // Parsed at most once per event, and not at all unless some rule is a range. An ignore
        // list of literals costs exactly what it did before.
        let (src4, src6, dst4, dst6) = if self.needs_numeric {
            (addr_to_int(&event.src_ip), parse_ipv6(&event.src_ip), addr_to_int(&dst_ip), parse_ipv6(&dst_ip))
        } else {
            (None, None, None, None)
        };

        for rule in &self.rules {
            if !rule.src_ip.matches(&event.src_ip, src4, src6) {
                continue;
            }
            if !rule.src_port.matches(&src_port) {
                continue;
            }
            if !rule.dst_ip.matches(&dst_ip, dst4, dst6) {
                continue;
            }
            if !rule.dst_port.matches(&dst_port) {
                continue;
            }
            return true;
        }
        false
    }

    fn add(&mut self, a: String, b: String, c: String, d: String) {
        if !self.seen.insert((a.clone(), b.clone(), c.clone(), d.clone())) {
            return;
        }
        let rule =
            Rule { src_ip: parse_host(&a), src_port: parse_port(&b), dst_ip: parse_host(&c), dst_port: parse_port(&d) };
        self.needs_numeric |= rule.src_ip.is_numeric() || rule.dst_ip.is_numeric();
        self.rules.push(rule);
    }

    #[cfg(test)]
    pub fn add_rule_for_test(&mut self, rule: (&str, &str, &str, &str)) {
        self.add(rule.0.into(), rule.1.into(), rule.2.into(), rule.3.into());
    }
}

/// Exposed for `tests/vectors.rs`, which replays Python's answers for the same rules.
pub fn rule_matches_for_test(kind: &str, rule: &str, value: &str) -> bool {
    match kind {
        "host" => parse_host(rule).matches(value, addr_to_int(value), parse_ipv6(value)),
        "port" => parse_port(rule).matches(value),
        other => panic!("unknown vector kind {other:?}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::{proto, trail_type, Event};

    fn sample() -> Event {
        Event::new(
            1,
            0,
            "192.168.0.3",
            50000u16,
            "1.2.3.4",
            22u16,
            proto::TCP,
            trail_type::IP,
            "1.2.3.4",
            "known attacker",
            "(static)",
        )
    }

    #[test]
    fn wildcard_rules() {
        let mut r = IgnoreRules::default();
        r.add_rule_for_test(("192.168.0.3", "*", "*", "*"));
        assert!(r.ignore_event(&sample()));

        let mut r = IgnoreRules::default();
        r.add_rule_for_test(("*", "*", "*", "22"));
        assert!(r.ignore_event(&sample()));

        let mut r = IgnoreRules::default();
        r.add_rule_for_test(("*", "*", "*", "23"));
        assert!(!r.ignore_event(&sample()));
    }

    fn event_from(src: &str, sport: u16, dst: &str, dport: u16) -> Event {
        Event::new(1, 0, src, sport, dst, dport, proto::TCP, trail_type::IP, dst, "known attacker", "(static)")
    }

    fn ignores(rule: (&str, &str, &str, &str), e: &Event) -> bool {
        let mut r = IgnoreRules::default();
        r.add_rule_for_test(rule);
        r.ignore_event(e)
    }

    /// #19142: an operator with 5-10k events a day could only silence their own subnet by writing
    /// out every address in it.
    #[test]
    fn a_cidr_covers_its_network_and_stops_at_the_edges() {
        let inside = event_from("192.168.1.77", 50000, "1.2.3.4", 22);
        assert!(ignores(("192.168.1.0/24", "*", "*", "*"), &inside));

        // the boundaries either side of the /24 must NOT be swallowed
        assert!(!ignores(("192.168.1.0/24", "*", "*", "*"), &event_from("192.168.0.255", 1, "1.2.3.4", 22)));
        assert!(!ignores(("192.168.1.0/24", "*", "*", "*"), &event_from("192.168.2.0", 1, "1.2.3.4", 22)));

        // /32 is one host, /0 is everything
        assert!(ignores(("192.168.1.77/32", "*", "*", "*"), &inside));
        assert!(!ignores(("192.168.1.78/32", "*", "*", "*"), &inside));
        assert!(ignores(("0.0.0.0/0", "*", "*", "*"), &inside));

        // a host address with a mask means the network it sits in, not just itself
        assert!(ignores(("192.168.1.77/24", "*", "*", "*"), &event_from("192.168.1.1", 1, "1.2.3.4", 22)));
    }

    #[test]
    fn dash_ranges_work_in_both_spellings() {
        let e = event_from("10.0.0.7", 50000, "1.2.3.4", 22);
        assert!(ignores(("10.0.0.1-10.0.0.15", "*", "*", "*"), &e));
        assert!(ignores(("10.0.0.1-15", "*", "*", "*"), &e), "the last-octet shorthand people actually write");
        assert!(!ignores(("10.0.0.8-15", "*", "*", "*"), &e));
        assert!(!ignores(("10.0.0.1-6", "*", "*", "*"), &e));

        // inclusive at both ends
        assert!(ignores(("10.0.0.7-7", "*", "*", "*"), &e));
    }

    #[test]
    fn port_ranges_cover_the_destination_and_the_source() {
        let e = event_from("10.0.0.7", 50000, "1.2.3.4", 8080);
        assert!(ignores(("*", "*", "*", "8000-8100"), &e));
        assert!(!ignores(("*", "*", "*", "8081-8100"), &e));
        assert!(ignores(("*", "1024-65535", "*", "*"), &e), "ephemeral source ports");
        assert!(!ignores(("*", "1-1023", "*", "*"), &e));
    }

    #[test]
    fn ipv6_networks_and_ranges() {
        let e = event_from("2001:db8::5", 50000, "dead::beef", 443);
        assert!(ignores(("2001:db8::/32", "*", "*", "*"), &e));
        assert!(!ignores(("2001:db9::/32", "*", "*", "*"), &e));
        assert!(ignores(("2001:db8::1-2001:db8::ff", "*", "*", "*"), &e));
        assert!(!ignores(("2001:db8::6-2001:db8::ff", "*", "*", "*"), &e));
        assert!(ignores(("*", "*", "dead::/16", "*"), &e), "destination side too");
    }

    /// Every rule written before ranges existed must keep meaning exactly what it meant.
    #[test]
    fn literals_and_nonsense_stay_exact_comparisons() {
        let e = event_from("192.168.0.3", 50000, "1.2.3.4", 22);
        assert!(ignores(("192.168.0.3", "*", "*", "*"), &e));
        assert!(!ignores(("192.168.0.4", "*", "*", "*"), &e));

        // A malformed network is NOT silently widened into something that matches more than the
        // operator wrote - it degrades to a literal, which matches nothing, and is visible as a
        // rule that does not work rather than one that quietly ignores half the network.
        assert!(!ignores(("192.168.1.0/33", "*", "*", "*"), &event_from("192.168.1.5", 1, "1.2.3.4", 22)));
        assert!(!ignores(("192.168.1.0/abc", "*", "*", "*"), &event_from("192.168.1.5", 1, "1.2.3.4", 22)));
        assert!(
            !ignores(("10.0.0.20-10.0.0.1", "*", "*", "*"), &event_from("10.0.0.5", 1, "1.2.3.4", 22)),
            "a backwards range must not be reinterpreted as forwards"
        );
        assert!(!ignores(("10.0.0.1-999", "*", "*", "*"), &event_from("10.0.0.5", 1, "1.2.3.4", 22)));

        // a port field is not always a number: ICMP writes "-"
        let icmp = Event::new(
            1,
            0,
            "10.0.0.1",
            "-",
            "10.0.0.2",
            "-",
            proto::ICMP,
            trail_type::IP,
            "10.0.0.2",
            "x",
            "(static)",
        );
        assert!(ignores(("*", "-", "*", "-"), &icmp));
        assert!(!ignores(("*", "*", "*", "1-100"), &icmp), "a range must not match a non-numeric port");
    }

    /// A range on one field must not loosen the others.
    #[test]
    fn fields_are_still_combined_with_and() {
        let e = event_from("192.168.1.5", 50000, "1.2.3.4", 22);
        assert!(ignores(("192.168.1.0/24", "*", "*", "22"), &e));
        assert!(!ignores(("192.168.1.0/24", "*", "*", "23"), &e));
        assert!(!ignores(("192.168.2.0/24", "*", "*", "22"), &e));
    }

    #[test]
    fn regex_matches_repr() {
        let r = IgnoreRules::load(Path::new("/nonexistent"), None, "known attacker");
        assert!(r.ignore_event(&sample()));
        let r = IgnoreRules::load(Path::new("/nonexistent"), None, "sql injection|1\\.2\\.3\\.9");
        assert!(!r.ignore_event(&sample()));
    }

    #[test]
    fn invalid_regex_is_disabled_not_fatal() {
        let r = IgnoreRules::load(Path::new("/nonexistent"), None, "(unbalanced");
        assert!(!r.ignore_event(&sample()));
    }

    #[test]
    fn shipped_ignore_file_has_only_comments() {
        let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).parent().unwrap().to_path_buf();
        let r = IgnoreRules::load(&root, None, "");
        assert_eq!(r.len(), 0);
    }
}
