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
///
/// Below 64 bytes - every DNS name in practice - the first byte is found by a plain loop:
/// memchr's vector setup costs more than scanning a name that short.
#[inline]
pub fn has(haystack: &str, needle: &str) -> bool {
    let (hay, needle) = (haystack.as_bytes(), needle.as_bytes());
    let Some(&first) = needle.first() else { return true };
    if hay.len() < 64 {
        return (0..hay.len()).any(|i| hay[i] == first && hay[i..].starts_with(needle));
    }
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

/// Offsets of the '.' separators in a name, by a plain byte loop (see `has`).
#[inline]
pub fn dots(name: &[u8]) -> impl Iterator<Item = usize> + '_ {
    name.iter().enumerate().filter(|(_, &b)| b == b'.').map(|(i, _)| i)
}

#[cfg(test)]
mod tests {
    #[test]
    fn has_agrees_with_str_contains() {
        let long = format!("{}.onion.x//y", "a".repeat(80));
        let hays = [
            "",
            "x",
            "xn--",
            "a.xn--pple-43d.com",
            "xnxn-",
            "foo.onion.",
            "onion",
            "a//b",
            "://",
            "acme-x",
            "aacme",
            &long,
        ];
        for hay in hays {
            for needle in ["xn--", ".onion.", "acme-", "//", "://", "a", ""] {
                assert_eq!(super::has(hay, needle), hay.contains(needle), "{hay:?} / {needle:?}");
            }
        }
    }
}
