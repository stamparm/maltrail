//! Application-protocol extraction: DNS, HTTP, TLS and QUIC.

pub mod dns;
pub mod hello;
pub mod http;
pub mod quic;
pub mod tls;

/// `haystack.contains(needle)` for a short literal needle on a short haystack - a DNS name or
/// a URL path. `str::contains` with a `&str` pattern sets up a Two-Way searcher on every call,
/// which on a 20-byte name costs more than the search; this finds the needle's first byte with
/// memchr and compares from there. Measured as ~250-480 instructions per DNS query per call
/// site before, on the three such checks every query passes through.
#[inline]
pub fn has(haystack: &str, needle: &str) -> bool {
    let (hay, needle) = (haystack.as_bytes(), needle.as_bytes());
    let Some(&first) = needle.first() else { return true };
    let mut from = 0;
    while let Some(i) = memchr::memchr(first, &hay[from..]) {
        let at = from + i;
        if hay[at..].starts_with(needle) {
            return true;
        }
        from = at + 1;
    }
    false
}

#[cfg(test)]
mod tests {
    #[test]
    fn has_agrees_with_str_contains() {
        let hays =
            ["", "x", "xn--", "a.xn--pple-43d.com", "xnxn-", "foo.onion.", "onion", "a//b", "://", "acme-x", "aacme"];
        for hay in hays {
            for needle in ["xn--", ".onion.", "acme-", "//", "://", "a", ""] {
                assert_eq!(super::has(hay, needle), hay.contains(needle), "{hay:?} / {needle:?}");
            }
        }
    }
}
