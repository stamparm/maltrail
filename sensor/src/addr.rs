//! Address helpers, byte-for-byte compatible with `core/addr.py`.
//!
//! Compatibility notes (these are quirks of the Python implementation that MUST be
//! reproduced, because trail keys and event fields are compared as text):
//!
//! * `inet_ntoa6` does **not** produce RFC 5952 canonical text. `compress_ipv6()`
//!   collapses the *last longest* run of `0000:` groups and then strips leading
//!   zeros, which for example renders `1::` as `1::0`. Reproduced exactly.
//! * `addr_port()` brackets a literal only when it contains `':'` **and** no `'.'`.

use crate::smallstr::SmallStr;

/// Rendered address (max 39 chars for IPv6) with room to spare.
pub type AddrStr = SmallStr<48>;
/// Rendered `addr:port` / `[addr]:port` key.
pub type KeyStr = SmallStr<64>;

/// Native IP address used throughout the hot path (no text until an event is emitted).
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
pub enum Ip {
    V4(u32),
    V6(u128),
}

impl Ip {
    #[inline]
    pub fn version(self) -> u8 {
        match self {
            Ip::V4(_) => 4,
            Ip::V6(_) => 6,
        }
    }

    #[inline]
    pub fn is_v6(self) -> bool {
        matches!(self, Ip::V6(_))
    }

    /// `LOCALHOST_IP[ip_version]` comparison from `sensor.py` (`127.0.0.1` / `::1`).
    #[inline]
    pub fn is_localhost(self) -> bool {
        match self {
            Ip::V4(v) => v == 0x7f00_0001,
            Ip::V6(v) => v == 1,
        }
    }

    /// `core/common.py:is_local()` — the Python regex only ever matches IPv4 text.
    #[inline]
    pub fn is_local(self) -> bool {
        match self {
            Ip::V4(v) => {
                let a = (v >> 24) as u8;
                let b = (v >> 16) as u8;
                a == 127 || a == 10 || (a == 172 && (16..=31).contains(&b)) || (a == 192 && b == 168)
            }
            Ip::V6(_) => false,
        }
    }

    #[inline]
    pub fn render(self) -> AddrStr {
        let mut out = AddrStr::new();
        self.render_into(&mut out);
        out
    }

    #[inline]
    pub fn render_into(self, out: &mut AddrStr) {
        match self {
            Ip::V4(v) => {
                out.push_u8_dec((v >> 24) as u8);
                out.push_byte(b'.');
                out.push_u8_dec((v >> 16) as u8);
                out.push_byte(b'.');
                out.push_u8_dec((v >> 8) as u8);
                out.push_byte(b'.');
                out.push_u8_dec(v as u8);
            }
            Ip::V6(v) => {
                let mut expanded = SmallStr::<40>::new();
                let bytes = v.to_be_bytes();
                for g in 0..8 {
                    if g > 0 {
                        expanded.push_byte(b':');
                    }
                    push_hex4(&mut expanded, bytes[g * 2], bytes[g * 2 + 1]);
                }
                compress_ipv6_into(expanded.as_str(), out);
            }
        }
    }

    /// `core/addr.py:addr_port()`
    #[inline]
    pub fn addr_port(self, port: u16) -> KeyStr {
        let mut out = KeyStr::new();
        match self {
            Ip::V4(_) => {
                let a = self.render();
                out.push_str(a.as_str());
                out.push_byte(b':');
                out.push_u16(port);
            }
            Ip::V6(_) => {
                let a = self.render();
                out.push_byte(b'[');
                out.push_str(a.as_str());
                out.push_byte(b']');
                out.push_byte(b':');
                out.push_u16(port);
            }
        }
        out
    }
}

#[inline]
fn push_hex4(out: &mut SmallStr<40>, hi: u8, lo: u8) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    out.push_byte(HEX[(hi >> 4) as usize]);
    out.push_byte(HEX[(hi & 0xf) as usize]);
    out.push_byte(HEX[(lo >> 4) as usize]);
    out.push_byte(HEX[(lo & 0xf) as usize]);
}

#[inline]
fn is_word(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

/// `core/addr.py:compress_ipv6()` — see module docs for why this is not RFC 5952.
pub fn compress_ipv6(address: &str) -> String {
    let mut out = AddrStr::new();
    compress_ipv6_into(address, &mut out);
    out.as_str().to_owned()
}

fn compress_ipv6_into(address: &str, out: &mut AddrStr) {
    let b = address.as_bytes();

    // Step 1: re.findall("(?:0000:)+", address) -> maximal runs of the 5-byte unit
    // "0000:". Python picks `sorted(zeros, key=len)[-1]` (the LAST longest run) and
    // then `.replace(run, ':', 1)` which rewrites the FIRST occurrence of that text.
    // Since no run is longer than the maximum, the first occurrence of the maximal
    // text starts at the first run whose length equals the maximum.
    const UNIT: &[u8] = b"0000:";
    let mut best_units = 0usize;
    let mut first_best_at = usize::MAX;
    let mut i = 0usize;
    while i + UNIT.len() <= b.len() {
        if &b[i..i + UNIT.len()] == UNIT {
            let start = i;
            let mut units = 0usize;
            while i + UNIT.len() <= b.len() && &b[i..i + UNIT.len()] == UNIT {
                units += 1;
                i += UNIT.len();
            }
            if units > best_units {
                best_units = units;
                first_best_at = start;
            }
        } else {
            i += 1;
        }
    }

    if best_units == 0 {
        out.push_str(address);
        return;
    }

    // Apply the replacement into a scratch buffer.
    let mut collapsed = SmallStr::<48>::new();
    collapsed.push_str(&address[..first_best_at]);
    collapsed.push_byte(b':');
    collapsed.push_str(&address[first_best_at + best_units * UNIT.len()..]);

    // Step 2: re.sub(r"(\A|:)0+(\w)", r"\g<1>\g<2>", address)
    let s = collapsed.as_str().as_bytes();
    let mut i = 0usize;
    while i < s.len() {
        let mut matched = false;
        // Alternation order: `\A` (empty, only at position 0) then `:`.
        let anchors: [Option<usize>; 2] =
            [if i == 0 { Some(0) } else { None }, if s[i] == b':' { Some(1) } else { None }];
        for anchor in anchors.into_iter().flatten() {
            let mut j = i + anchor;
            let zstart = j;
            while j < s.len() && s[j] == b'0' {
                j += 1;
            }
            // `0+` is greedy but BACKTRACKS: give characters back one at a time until the
            // trailing `(\w)` can match. Without this, a group that is all zeros and sits at
            // the end of the string (":0000") would not be shortened at all, whereas Python
            // yields ":0".
            let mut k = j;
            loop {
                if k > zstart && k < s.len() && is_word(s[k]) {
                    if anchor == 1 {
                        out.push_byte(b':');
                    }
                    out.push_byte(s[k]);
                    i = k + 1;
                    matched = true;
                    break;
                }
                if k <= zstart {
                    break;
                }
                k -= 1;
            }
            if matched {
                break;
            }
        }
        if !matched {
            out.push_byte(s[i]);
            i += 1;
        }
    }

    // Step 3: a collapsed leading run yields a single ':' -> make it '::'.
    if out.as_str().starts_with(':') && !out.as_str().starts_with("::") {
        let tail = *out;
        out.clear();
        out.push_byte(b':');
        out.push_str(tail.as_str());
    }
}

/// `core/addr.py:inet_ntoa6()`
pub fn inet_ntoa6(packed: &[u8; 16]) -> String {
    Ip::V6(u128::from_be_bytes(*packed)).render().as_str().to_owned()
}

/// `core/addr.py:addr_to_int()` — parses only a plain dotted quad (no validation of
/// octet range beyond what Python's `int()` accepts, but Python raises on >255? No:
/// `addr_to_int("300.1.2.3")` returns a shifted value. Callers always guard with a
/// dotted-quad regex first, so we require 0..=255 and reject otherwise.
pub fn addr_to_int(value: &str) -> Option<u32> {
    let mut parts = value.split('.');
    let mut out: u32 = 0;
    for _ in 0..4 {
        let p = parts.next()?;
        if p.is_empty() || p.len() > 3 || !p.bytes().all(|c| c.is_ascii_digit()) {
            return None;
        }
        let v: u32 = p.parse().ok()?;
        if v > 255 {
            return None;
        }
        out = (out << 8) | v;
    }
    if parts.next().is_some() {
        return None;
    }
    Some(out)
}

/// `core/addr.py:make_mask()`
pub fn make_mask(bits: u32) -> u32 {
    if bits >= 32 {
        return 0xffff_ffff;
    }
    // /0 has to be spelled out: `1u32 << 32` panics in debug and wraps to `1u32 << 0` in release,
    // which would turn a /0 into a /32. Python has no fixed width and simply returns 0, so this
    // was a divergence as well as a panic - reachable from any whitelist file carrying 0.0.0.0/0.
    if bits == 0 {
        return 0;
    }
    0xffff_ffffu32 ^ ((1u32 << (32 - bits)) - 1)
}

/// `core/addr.py:addr_port()` for values that are already text.
pub fn addr_port_str(addr: &str, port: &str) -> String {
    if addr.contains(':') && !addr.contains('.') {
        format!("[{}]:{}", addr.trim_matches(|c| c == '[' || c == ']'), port)
    } else {
        format!("{}:{}", addr, port)
    }
}

/// `core/addr.py:parse_host_port()`
pub fn parse_host_port(value: &str) -> (String, Option<u16>) {
    let value = value.trim();
    let (host, port) = if value.starts_with('[') && value.contains(']') {
        let rest = &value[1..];
        let idx = rest.find(']').unwrap();
        let host = &rest[..idx];
        let after = &rest[idx + 1..];
        let port = after.strip_prefix(':').unwrap_or_default();
        (host, port)
    } else {
        match value.matches(':').count() {
            0 => (value, ""),
            // One colon is host:port. More than one is a bare IPv6 literal unless the last
            // colon is followed by a port, which rfind() is what distinguishes.
            1 => {
                let idx = value.find(':').unwrap();
                (&value[..idx], &value[idx + 1..])
            }
            _ => {
                let idx = value.rfind(':').unwrap();
                (&value[..idx], &value[idx + 1..])
            }
        }
    };

    let parsed =
        if port.is_empty() || !port.bytes().all(|c| c.is_ascii_digit()) { None } else { port.parse::<u16>().ok() };
    (host.to_owned(), parsed)
}

/// Parse a bare dotted-quad or IPv6 literal into the native form, but only accept it
/// when re-rendering it with Maltrail's own formatter yields exactly the input. That
/// guarantees a native-keyed lookup is equivalent to Python's string comparison.
pub fn parse_canonical_ip(text: &str) -> Option<Ip> {
    if let Some(v) = addr_to_int(text) {
        let ip = Ip::V4(v);
        if ip.render().as_str() == text {
            return Some(ip);
        }
        return None;
    }
    if !text.contains(':') {
        return None;
    }
    let v = parse_ipv6(text)?;
    let ip = Ip::V6(v);
    if ip.render().as_str() == text {
        return Some(ip);
    }
    None
}

/// Standard IPv6 literal parser (`::` compression, optional trailing IPv4 form).
pub fn parse_ipv6(text: &str) -> Option<u128> {
    if text.is_empty() || text.len() > 45 {
        return None;
    }
    let (head, tail) = match text.split_once("::") {
        Some((h, t)) => {
            if t.contains("::") {
                return None;
            }
            (h, Some(t))
        }
        None => (text, None),
    };

    let mut groups: Vec<u16> = Vec::with_capacity(8);
    let mut trailing: Vec<u16> = Vec::with_capacity(8);

    fn parse_groups(s: &str, out: &mut Vec<u16>) -> Option<()> {
        if s.is_empty() {
            return Some(());
        }
        let mut it = s.split(':').peekable();
        while let Some(part) = it.next() {
            if part.is_empty() {
                return None;
            }
            if it.peek().is_none() && part.contains('.') {
                let v4 = addr_to_int(part)?;
                out.push((v4 >> 16) as u16);
                out.push((v4 & 0xffff) as u16);
                break;
            }
            if part.len() > 4 || !part.bytes().all(|c| c.is_ascii_hexdigit()) {
                return None;
            }
            out.push(u16::from_str_radix(part, 16).ok()?);
        }
        Some(())
    }

    parse_groups(head, &mut groups)?;
    if let Some(t) = tail {
        parse_groups(t, &mut trailing)?;
        if groups.len() + trailing.len() > 7 {
            return None;
        }
        while groups.len() + trailing.len() < 8 {
            groups.push(0);
        }
        groups.extend_from_slice(&trailing);
    }
    if groups.len() != 8 {
        return None;
    }
    let mut out: u128 = 0;
    for g in groups {
        out = (out << 16) | g as u128;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipv4_render() {
        assert_eq!(Ip::V4(16909060).render().as_str(), "1.2.3.4");
        assert_eq!(Ip::V4(0).render().as_str(), "0.0.0.0");
        assert_eq!(Ip::V4(0xffff_ffff).render().as_str(), "255.255.255.255");
    }

    #[test]
    fn addr_to_int_doctest() {
        assert_eq!(addr_to_int("1.2.3.4"), Some(16909060));
    }

    #[test]
    fn make_mask_doctest() {
        assert_eq!(Ip::V4(make_mask(24)).render().as_str(), "255.255.255.0");
        assert_eq!(Ip::V4(make_mask(32)).render().as_str(), "255.255.255.255");
        // /0 matches Python's make_mask(0) == 0, and does not panic or wrap to /32
        assert_eq!(make_mask(0), 0);
        assert_eq!(Ip::V4(make_mask(0)).render().as_str(), "0.0.0.0");
    }

    #[test]
    fn compress_ipv6_doctest() {
        assert_eq!(compress_ipv6("0000:0000:0000:0000:0000:0000:0000:0001"), "::1");
    }

    #[test]
    fn compress_ipv6_backtracks_a_trailing_zero_group() {
        // Python's `0+(\w)` backtracks, so an all-zero final group collapses to a single 0.
        assert_eq!(compress_ipv6("0000:0000:0000:0000:0000:0000:0000:0000"), "::0");
        assert_eq!(compress_ipv6("0001:0000:0000:0000:0000:0000:0000:0000"), "1::0");
        // the LAST longest run wins (3 groups beats 2), so the middle 2:: stays expanded
        assert_eq!(compress_ipv6("0001:0000:0000:0002:0000:0000:0000:0003"), "1:0:0:2::3");
    }

    #[test]
    fn inet_ntoa6_doctest() {
        let mut p = [0u8; 16];
        p[15] = 1;
        assert_eq!(inet_ntoa6(&p), "::1");
    }

    #[test]
    fn addr_port_doctest() {
        assert_eq!(Ip::V4(addr_to_int("1.2.3.4").unwrap()).addr_port(80).as_str(), "1.2.3.4:80");
        let v6 = parse_ipv6("dead::beef").unwrap();
        assert_eq!(Ip::V6(v6).addr_port(53).as_str(), "[dead::beef]:53");
    }

    #[test]
    fn parse_host_port_doctests() {
        assert_eq!(parse_host_port("1.2.3.4:8080"), ("1.2.3.4".into(), Some(8080)));
        assert_eq!(parse_host_port("[fe80::1]:514"), ("fe80::1".into(), Some(514)));
        assert_eq!(parse_host_port("example.com:53"), ("example.com".into(), Some(53)));
        assert_eq!(parse_host_port("example.com"), ("example.com".into(), None));
    }

    #[test]
    fn is_local_doctests() {
        let l = |s: &str| Ip::V4(addr_to_int(s).unwrap()).is_local();
        assert!(l("127.0.0.1"));
        assert!(l("10.0.0.5"));
        assert!(l("192.168.1.1"));
        assert!(!l("8.8.8.8"));
        assert!(l("172.20.5.5"));
        assert!(l("172.31.255.255"));
        assert!(!l("172.15.0.1"));
        assert!(!l("172.32.0.1"));
    }

    #[test]
    fn ipv6_parse_roundtrip() {
        for s in ["::1", "dead::beef", "fe80::1", "2001:db8::1", "::"] {
            let v = parse_ipv6(s).expect(s);
            let _ = Ip::V6(v).render();
        }
        assert!(parse_ipv6("1:::2").is_none());
        assert!(parse_ipv6("gggg::1").is_none());
        assert_eq!(parse_ipv6("::ffff:1.2.3.4"), Some(0xffff_0102_0304));
    }
}
