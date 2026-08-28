//! Heuristic detectors and their bounded state.

pub mod beacon;
pub mod dns_exhaustion;
pub mod dns_tunneling;
pub mod nxdomain;
pub mod scan;

use crate::addr::Ip;

/// `sensor.py:_HEURISTIC_NAMES` — the heuristics an operator can mute individually via
/// `DISABLED_HEURISTICS`.
pub const HEURISTIC_NAMES: [&str; 8] = [
    "port_scanning",
    "udp_scanning",
    "infection",
    "web_scanning",
    "dns_exhaustion",
    "long_domain",
    "beaconing",
    "dns_tunneling",
];

/// Hard cap on the number of distinct keys any one heuristic accumulator may hold.
///
/// Every one of these structures is keyed by something an ATTACKER chooses — a queried domain,
/// a source/destination pair — so "it resets every hour" is a time bound, not a memory bound: a
/// fast link gives an adversary an hour to insert as many keys as it can send packets.
///
/// The policy at the cap is to REFUSE THE NEW KEY, never to evict an existing one. Eviction
/// under flood would let an attacker push their own earlier evidence out of the window, which
/// is a detection-evasion primitive; refusal means the sensor keeps what it already saw and
/// merely stops learning new *heuristic* subjects. Exact trail matching is completely
/// unaffected — it does not consult these maps — so a saturated sensor still detects every
/// known-bad indicator. That is the degraded mode: heuristics narrow, IOC coverage does not.
///
/// Matches `scan::SCAN_MAX_KEYS`, which has always enforced exactly this.
pub const HEURISTIC_MAX_KEYS: usize = scan::SCAN_MAX_KEYS;

/// `sensor.py:_get_local_prefix()` — the most common `A.B.` prefix among the source
/// addresses currently tracked by the scan accumulators.
///
/// Python computes `re.sub(r"\d+\.\d+\Z", "", ip)` over the *rendered* address, so an
/// IPv4 source contributes `A.B.` and an IPv6 source contributes its whole rendered form
/// (the pattern does not match there). Ties are broken by the larger candidate string,
/// matching `sorted(..., reverse=True)`.
pub fn local_prefix(sources: impl Iterator<Item = Ip>, cached: &mut Option<String>) -> String {
    let mut counts: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    for ip in sources {
        let rendered = ip.render();
        let candidate = strip_last_two_octets(rendered.as_str());
        *counts.entry(candidate).or_insert(0) += 1;
    }
    let best = counts
        .into_iter()
        .max_by(|(a_key, a_count), (b_key, b_count)| a_count.cmp(b_count).then_with(|| a_key.cmp(b_key)))
        .map(|(key, _)| key)
        .unwrap_or_default();

    if !best.is_empty() {
        *cached = Some(best.clone());
        return best;
    }
    // Python falls back to the last non-empty value it cached, then to '_'.
    cached.clone().unwrap_or_else(|| "_".to_string())
}

/// `re.sub(r"\d+\.\d+\Z", "", value)`, borrowing — the hot path counts prefixes without
/// allocating one `String` per source address.
pub fn strip_last_two_octets_str(value: &str) -> &str {
    let b = value.as_bytes();
    // Walk back over: digits, '.', digits anchored at the end.
    let mut i = b.len();
    let mut digits2 = 0;
    while i > 0 && b[i - 1].is_ascii_digit() {
        i -= 1;
        digits2 += 1;
    }
    if digits2 == 0 || i == 0 || b[i - 1] != b'.' {
        return value;
    }
    i -= 1; // the '.'
    let mut digits1 = 0;
    while i > 0 && b[i - 1].is_ascii_digit() {
        i -= 1;
        digits1 += 1;
    }
    if digits1 == 0 {
        return value;
    }
    &value[..i]
}

fn strip_last_two_octets(value: &str) -> String {
    strip_last_two_octets_str(value).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::addr::{addr_to_int, parse_ipv6};

    fn v4(s: &str) -> Ip {
        Ip::V4(addr_to_int(s).unwrap())
    }

    #[test]
    fn strips_last_two_octets_like_python() {
        assert_eq!(strip_last_two_octets("10.0.0.5"), "10.0.");
        assert_eq!(strip_last_two_octets("192.168.1.1"), "192.168.");
        assert_eq!(strip_last_two_octets("dead::beef"), "dead::beef");
        assert_eq!(strip_last_two_octets("1.2"), "");
        assert_eq!(strip_last_two_octets("nodigits"), "nodigits");
    }

    #[test]
    fn most_common_prefix_wins() {
        let sources = vec![v4("10.0.0.5"), v4("10.0.1.6"), v4("172.16.0.1")];
        let mut cached = None;
        assert_eq!(local_prefix(sources.into_iter(), &mut cached), "10.0.");
        assert_eq!(cached.as_deref(), Some("10.0."));
    }

    #[test]
    fn ties_break_on_the_larger_string() {
        let sources = vec![v4("10.0.0.5"), v4("172.16.0.1")];
        let mut cached = None;
        assert_eq!(local_prefix(sources.into_iter(), &mut cached), "172.16.");
    }

    #[test]
    fn empty_falls_back_to_cache_then_underscore() {
        let mut cached = None;
        assert_eq!(local_prefix(std::iter::empty(), &mut cached), "_");
        let mut cached = Some("10.0.".to_string());
        assert_eq!(local_prefix(std::iter::empty(), &mut cached), "10.0.");
    }

    #[test]
    fn ipv6_sources_contribute_their_whole_rendering() {
        let sources = vec![Ip::V6(parse_ipv6("dead::1").unwrap())];
        let mut cached = None;
        assert_eq!(local_prefix(sources.into_iter(), &mut cached), "dead::1");
    }
}
