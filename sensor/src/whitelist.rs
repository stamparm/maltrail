//! Whitelisting, ported from `core/settings.py:read_whitelist()` and
//! `core/common.py:check_whitelisted()` / `sensor.py:_check_domain_member()`.

use std::collections::HashSet;
use std::path::Path;

use crate::addr::{addr_to_int, make_mask, parse_canonical_ip, Ip};
use crate::settings;

#[derive(Default, Debug)]
pub struct Whitelist {
    /// `WHITELIST` — verbatim entries (domains, IP literals, bare words).
    exact: HashSet<String>,
    /// Cache-resident negative prefilter over `exact`, same idea as the trail store's: the
    /// whitelist parent walk probes once per label level, and almost every probe misses. ~7 kB for
    /// 3,440 entries, so it stays in L1. Never a false negative — see `trails::table::NegativeFilter`.
    exact_filter: Vec<u64>,
    /// `WHITELIST_RANGES` — (masked prefix, mask) pairs.
    ranges: Vec<(u32, u32)>,
    /// Native mirrors of the exact set, so an IP check needs no text rendering. Only
    /// entries whose canonical Maltrail rendering equals the configured text are
    /// mirrored, which makes the native check exactly equivalent to Python's string
    /// comparison.
    // Same argument as the trail store: the whitelist is fixed at load, so FxHash is safe here.
    // (`exact` stays on the default hasher — it is probed with attacker-chosen domain strings and
    // is the one whitelist structure whose LOOKUP keys come off the wire.)
    ip4: crate::fasthash::FastSet<u32>,
    ip6: crate::fasthash::FastSet<u128>,
}

impl Whitelist {
    /// `read_whitelist()`: `data/whitelist.txt` then the optional `USER_WHITELIST`.
    pub fn load(root: &Path, user_whitelist: Option<&Path>) -> Whitelist {
        let mut wl = Whitelist::default();
        let mut files = vec![root.join("data").join("whitelist.txt")];
        if let Some(p) = user_whitelist {
            files.push(p.to_path_buf());
        }
        for file in files {
            for line in settings::iter_file_lines(&file) {
                wl.add(&line);
            }
        }
        wl.build_exact_filter();
        wl
    }

    fn add(&mut self, line: &str) {
        if let Some((prefix, mask)) = parse_cidr4(line) {
            let m = make_mask(mask);
            self.ranges.push((prefix & m, m));
            return;
        }
        if let Some(ip) = parse_canonical_ip(line) {
            match ip {
                Ip::V4(v) => {
                    self.ip4.insert(v);
                }
                Ip::V6(v) => {
                    self.ip6.insert(v);
                }
            }
        }
        self.exact.insert(line.to_string());
    }

    pub fn len(&self) -> usize {
        self.exact.len()
    }

    pub fn is_empty(&self) -> bool {
        self.exact.is_empty()
    }

    pub fn range_count(&self) -> usize {
        self.ranges.len()
    }

    /// `core/common.py:check_whitelisted()` for arbitrary trail text.
    pub fn check_whitelisted(&self, trail: &str) -> bool {
        // Through the prefilter, not `exact` directly: the trail loader calls this once per
        // CSV row (1.6 M of them) and virtually every call misses, so paying SipHash over
        // the whole file is most of what this check costs.
        if self.contains_exact(trail) {
            return true;
        }
        // Only a BARE dotted quad is range-matched (guards against "10.0.0.1.evil.com").
        if is_dotted_quad(trail) {
            if let Some(v) = addr_to_int(trail) {
                return self.match_ranges(v);
            }
        }
        false
    }

    /// Allocation-free equivalent for a parsed address.
    pub fn check_whitelisted_ip(&self, ip: Ip) -> bool {
        match ip {
            Ip::V4(v) => self.ip4.contains(&v) || self.match_ranges(v),
            Ip::V6(v) => self.ip6.contains(&v),
        }
    }

    fn match_ranges(&self, value: u32) -> bool {
        self.ranges.iter().any(|(prefix, mask)| value & mask == *prefix)
    }

    /// `sensor.py:_check_domain_member()`
    pub fn check_domain_member(&self, query: &str) -> bool {
        self.check_domain_member_depth(query) > 0
    }

    /// Label count of the most specific whitelisted entry matching `query` or one of its
    /// parents (0 = none). The DEPTH, not just the verdict, is what longest-match precedence
    /// compares against a matched trail: an exact-name trail more specific than its closest
    /// whitelisted ancestor is allowed to fire (see `process.rs`).
    pub fn check_domain_member_depth(&self, query: &str) -> u32 {
        match self.check_domain_member_entry(query) {
            Some(entry) => (entry.as_bytes().iter().filter(|&&b| b == b'.').count() + 1) as u32,
            None => 0,
        }
    }

    /// The most specific whitelisted entry matching `query` or one of its parent domains.
    /// Same walk as `check_domain_member`, but returns WHICH entry matched so callers can
    /// apply longest-match precedence against a trail hit. Borrowed from `self`, which is
    /// fixed after load.
    pub fn check_domain_member_entry(&self, query: &str) -> Option<&str> {
        let lowered = if query.bytes().any(|b| b.is_ascii_uppercase()) {
            std::borrow::Cow::Owned(query.to_ascii_lowercase())
        } else {
            std::borrow::Cow::Borrowed(query)
        };
        if let Some(entry) = self.exact_entry(&lowered) {
            return Some(entry.as_str());
        }
        for i in memchr::memchr_iter(b'.', lowered.as_bytes()) {
            if let Some(entry) = self.exact_entry(&lowered[i + 1..]) {
                return Some(entry.as_str());
            }
        }
        None
    }

    /// Prefiltered lookup in `exact`, returning the stored entry.
    #[inline]
    fn exact_entry(&self, candidate: &str) -> Option<&String> {
        if self.exact_filter.is_empty() {
            return self.exact.get(candidate);
        }
        let h = crate::trails::table::hash_bytes(candidate.as_bytes());
        let bits = self.exact_filter.len() * 64;
        let a = (h as usize) & (bits - 1);
        let b = ((h >> 32) as usize).wrapping_mul(0x9e37_79b9) & (bits - 1);
        if (self.exact_filter[a >> 6] >> (a & 63)) & 1 == 0 || (self.exact_filter[b >> 6] >> (b & 63)) & 1 == 0 {
            return None;
        }
        self.exact.get(candidate)
    }

    /// Prefiltered membership test for `exact`.
    #[inline]
    fn contains_exact(&self, candidate: &str) -> bool {
        if self.exact_filter.is_empty() {
            return self.exact.contains(candidate);
        }
        let h = crate::trails::table::hash_bytes(candidate.as_bytes());
        let bits = self.exact_filter.len() * 64;
        let a = (h as usize) & (bits - 1);
        let b = ((h >> 32) as usize).wrapping_mul(0x9e37_79b9) & (bits - 1);
        if (self.exact_filter[a >> 6] >> (a & 63)) & 1 == 0 || (self.exact_filter[b >> 6] >> (b & 63)) & 1 == 0 {
            return false;
        }
        self.exact.contains(candidate)
    }

    /// Build the prefilter once the entry set is final.
    fn build_exact_filter(&mut self) {
        let bits = (self.exact.len().saturating_mul(16)).max(1024).next_power_of_two();
        let mut filter = vec![0u64; bits / 64];
        for entry in &self.exact {
            let h = crate::trails::table::hash_bytes(entry.as_bytes());
            let a = (h as usize) & (bits - 1);
            let b = ((h >> 32) as usize).wrapping_mul(0x9e37_79b9) & (bits - 1);
            filter[a >> 6] |= 1u64 << (a & 63);
            filter[b >> 6] |= 1u64 << (b & 63);
        }
        self.exact_filter = filter;
    }

    #[cfg(test)]
    pub fn insert_for_test(&mut self, entry: &str) {
        self.add(entry);
        // Tests build a whitelist entry-by-entry; the prefilter must be rebuilt or it would
        // (correctly, per its contract) report the new entry as absent.
        self.build_exact_filter();
    }
}

/// `sensor.py:_check_domain_member()` — is the query, or any of its parent domains, in
/// the given collection? The query is lower-cased first, exactly like Python.
pub fn check_domain_member(query: &str, contains: impl Fn(&str) -> bool) -> bool {
    let lowered = if query.bytes().any(|b| b.is_ascii_uppercase()) {
        std::borrow::Cow::Owned(query.to_ascii_lowercase())
    } else {
        std::borrow::Cow::Borrowed(query)
    };
    let q = lowered.as_ref();
    if contains(q) {
        return true;
    }
    for i in memchr::memchr_iter(b'.', q.as_bytes()) {
        if contains(&q[i + 1..]) {
            return true;
        }
    }
    false
}

/// The domain part Python extracts before the whitelist test:
/// `re.split(r"(?i)[^A-Z0-9._-]", query or "")[0]`
pub fn whitelist_domain_token(query: &str) -> &str {
    let idx = query
        .bytes()
        .position(|b| !(b.is_ascii_alphanumeric() || b == b'.' || b == b'_' || b == b'-'))
        .unwrap_or(query.len());
    &query[..idx]
}

fn is_dotted_quad(value: &str) -> bool {
    // re.match(r"\A(?:\d{1,3}\.){3}\d{1,3}\Z", trail)
    let mut parts = 0;
    for part in value.split('.') {
        if part.is_empty() || part.len() > 3 || !part.bytes().all(|b| b.is_ascii_digit()) {
            return false;
        }
        parts += 1;
    }
    parts == 4
}

/// `re.search(r"\A\d+\.\d+\.\d+\.\d+/\d+\Z", line)` + split
fn parse_cidr4(line: &str) -> Option<(u32, u32)> {
    let (addr, mask) = line.split_once('/')?;
    if !is_dotted_quad(addr) || mask.is_empty() || !mask.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let bits: u32 = mask.parse().ok()?;
    // Python catches (IndexError, ValueError) and falls back to a verbatim entry; a mask
    // above 32 is accepted by make_mask() in Python (shifting by a negative raises
    // ValueError -> verbatim). Reproduce by rejecting >32 here.
    if bits > 32 {
        return None;
    }
    Some((addr_to_int(addr)?, bits))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn root() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).parent().unwrap().to_path_buf()
    }

    #[test]
    fn check_domain_member_doctests() {
        let set: HashSet<String> = ["evil.com".to_string()].into_iter().collect();
        assert!(check_domain_member("www.evil.com", |c| set.contains(c)));
        assert!(check_domain_member("a.b.example.com", |c| c == "example.com"));
        assert!(!check_domain_member("good.com", |c| set.contains(c)));
    }

    #[test]
    fn member_depth_and_entry() {
        let mut wl = Whitelist::default();
        wl.insert_for_test("platform.test");
        wl.insert_for_test("a.b.exact.test");
        // the closest (most specific) ancestor wins, and its label count is the depth
        assert_eq!(wl.check_domain_member_depth("host.platform.test"), 2);
        assert_eq!(wl.check_domain_member_entry("host.platform.test"), Some("platform.test"));
        assert_eq!(wl.check_domain_member_depth("platform.test"), 2);
        // case-insensitive, exactly like Python's lowered walk
        assert_eq!(wl.check_domain_member_entry("HOST.Platform.TEST"), Some("platform.test"));
        // exact multi-label entry: depth counts ITS labels
        assert_eq!(wl.check_domain_member_depth("x.a.b.exact.test"), 4);
        assert_eq!(wl.check_domain_member_entry("x.a.b.exact.test"), Some("a.b.exact.test"));
        assert_eq!(wl.check_domain_member_entry("nothing.here.test"), None);
        assert_eq!(wl.check_domain_member_depth("nothing.here.test"), 0);
    }

    #[test]
    fn cidr_and_exact() {
        let mut wl = Whitelist::default();
        wl.insert_for_test("10.0.5.0/16");
        wl.insert_for_test("evil.example");
        wl.insert_for_test("8.8.8.8");
        // non-network-aligned CIDR still matches its subnet (prefix is masked on load)
        assert!(wl.check_whitelisted("10.0.9.9"));
        assert!(wl.check_whitelisted("evil.example"));
        assert!(wl.check_whitelisted("8.8.8.8"));
        assert!(!wl.check_whitelisted("11.0.0.1"));
        assert!(!wl.check_whitelisted("10.9.9.9"), "10.0.5.0/16 masks to 10.0.0.0/16");
        // whitelist-bypass guard: a domain that merely starts with a whitelisted IP
        assert!(!wl.check_whitelisted("10.0.0.1.evil.com"));
        assert!(wl.check_whitelisted_ip(Ip::V4(addr_to_int("10.0.1.2").unwrap())));
        assert!(wl.check_whitelisted_ip(Ip::V4(addr_to_int("8.8.8.8").unwrap())));
        assert!(!wl.check_whitelisted_ip(Ip::V4(addr_to_int("1.2.3.4").unwrap())));
    }

    #[test]
    fn ipv6_exact_entry_is_mirrored() {
        let mut wl = Whitelist::default();
        wl.insert_for_test("::1");
        assert!(wl.check_whitelisted("::1"));
        assert!(wl.check_whitelisted_ip(Ip::V6(1)));
    }

    #[test]
    fn whitelist_token_extraction() {
        assert_eq!(whitelist_domain_token("evil.com"), "evil.com");
        assert_eq!(whitelist_domain_token("evil.com/path"), "evil.com");
        assert_eq!(whitelist_domain_token("evil.com:80"), "evil.com");
        assert_eq!(whitelist_domain_token(""), "");
    }

    #[test]
    fn shipped_whitelist_loads() {
        let wl = Whitelist::load(&root(), None);
        assert!(wl.len() > 1000, "data/whitelist.txt should be sizeable, got {}", wl.len());
        assert!(wl.check_whitelisted("localhost"));
        assert!(wl.check_whitelisted("127.0.0.1"));
        assert!(wl.check_whitelisted_ip(Ip::V4(0x7f00_0001)));
    }
}
