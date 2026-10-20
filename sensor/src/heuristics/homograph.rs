//! IDN homographs (`аpple.com` with a Cyrillic `а`) — a NEW heuristic, with no `sensor.py`
//! counterpart.
//!
//! Every `xn--` label is Punycode-decoded (RFC 3492) and each character mapped through a small
//! table of glyphs that render IDENTICALLY to a Latin letter. If that turns the whole label into
//! ASCII, and the rewritten name is (a subdomain of) an entry in `data/whitelist.txt` — the
//! popular domains a lookalike is built to impersonate — while the real name is not, the name is
//! a homograph of that entry. A legitimate IDN never collapses onto `paypal.com` exactly.
//!
//! Deliberately narrow: accented Latin (`ü`, `é`) is NOT mapped. Those letters look different in
//! an address bar, and mapping them would flag ordinary European IDNs (`münchen`) that happen to
//! spell a listed ASCII name. Unicode's full confusables table is far larger; this subset covers
//! the Cyrillic, Greek and Armenian lookalikes that real homograph registrations use.

use crate::whitelist::Whitelist;

/// The Latin letter `c` renders identically to, or `None`.
fn latin_twin(c: char) -> Option<char> {
    Some(match c {
        // Cyrillic
        'а' => 'a',
        'с' => 'c',
        'ԁ' => 'd',
        'е' => 'e',
        'һ' => 'h',
        'і' => 'i',
        'ј' => 'j',
        'ӏ' => 'l',
        'о' => 'o',
        'р' => 'p',
        'ԛ' => 'q',
        'ѕ' => 's',
        'у' => 'y',
        'ԝ' => 'w',
        'х' => 'x',
        // Greek
        'α' => 'a',
        'ϲ' => 'c',
        'ι' => 'i',
        'ϳ' => 'j',
        'κ' => 'k',
        'ν' => 'v',
        'ο' => 'o',
        'ρ' => 'p',
        'υ' => 'u',
        'χ' => 'x',
        // Armenian
        'հ' => 'h',
        'ո' => 'n',
        'օ' => 'o',
        'ս' => 'u',
        // Latin lookalikes outside ASCII
        'ı' => 'i',
        'ɑ' => 'a',
        'ɡ' => 'g',
        'ɩ' => 'i',
        _ => return None,
    })
}

/// RFC 3492 decoding of one label's Punycode part (after `xn--`). `None` on malformed input.
pub fn punycode_decode(input: &str) -> Option<String> {
    const BASE: u32 = 36;
    const TMIN: u32 = 1;
    const TMAX: u32 = 26;
    fn adapt(delta: u32, points: u32, first: bool) -> u32 {
        let mut delta = if first { delta / 700 } else { delta / 2 };
        delta += delta / points;
        let mut k = 0;
        while delta > ((BASE - TMIN) * TMAX) / 2 {
            delta /= BASE - TMIN;
            k += BASE;
        }
        k + (BASE - TMIN + 1) * delta / (delta + 38)
    }
    if input.len() > 63 {
        return None;
    }
    let (basic, extended) = match input.rfind('-') {
        Some(i) => (&input[..i], &input[i + 1..]),
        None => ("", input),
    };
    if !basic.is_ascii() {
        return None;
    }
    let mut out: Vec<char> = basic.chars().collect();
    let (mut n, mut i, mut bias) = (128u32, 0u32, 72u32);
    let mut digits = extended.bytes();
    let mut pending = digits.len();
    while pending > 0 {
        let old_i = i;
        let mut w = 1u32;
        let mut k = BASE;
        loop {
            let c = digits.next()?;
            pending -= 1;
            let digit = match c {
                b'a'..=b'z' => c - b'a',
                b'A'..=b'Z' => c - b'A',
                b'0'..=b'9' => c - b'0' + 26,
                _ => return None,
            } as u32;
            i = i.checked_add(digit.checked_mul(w)?)?;
            let t = if k <= bias {
                TMIN
            } else if k >= bias + TMAX {
                TMAX
            } else {
                k - bias
            };
            if digit < t {
                break;
            }
            w = w.checked_mul(BASE - t)?;
            k += BASE;
        }
        let points = out.len() as u32 + 1;
        bias = adapt(i - old_i, points, old_i == 0);
        n = n.checked_add(i / points)?;
        i %= points;
        out.insert(i as usize, char::from_u32(n)?);
        i += 1;
    }
    Some(out.into_iter().collect())
}

/// The whitelisted domain `query` impersonates, if it is a homograph of one.
pub fn impersonated<'a>(query: &str, whitelist: &'a Whitelist) -> Option<&'a str> {
    if !crate::protocols::has(query, "xn--") {
        return None;
    }
    let labels: Vec<&str> = query.split('.').collect();
    let mut rewritten: Vec<bool> = Vec::with_capacity(labels.len());
    let mut skeleton: Vec<String> = Vec::with_capacity(labels.len());
    for label in &labels {
        let twin = label
            .get(..4)
            .filter(|p| p.eq_ignore_ascii_case("xn--"))
            .and_then(|_| punycode_decode(&label[4..]))
            .and_then(|decoded| decoded.chars().map(|c| if c.is_ascii() { Some(c) } else { latin_twin(c) }).collect());
        rewritten.push(twin.is_some());
        skeleton.push(twin.unwrap_or_else(|| label.to_string()));
    }
    let entry = whitelist.check_domain_member_entry(&skeleton.join("."))?;
    // The disguise must be INSIDE the impersonated name: `xn--...example.com` matching a listed
    // `example.com` is just an IDN subdomain of a real site.
    let covered = entry.split('.').count();
    if covered < 2 || covered > labels.len() || !rewritten[labels.len() - covered..].contains(&true) {
        return None;
    }
    Some(entry)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn whitelist(entries: &[&str]) -> Whitelist {
        let mut w = Whitelist::default();
        for e in entries {
            w.insert_for_test(e);
        }
        w
    }

    #[test]
    fn decodes_rfc3492_labels() {
        // reference values from Python's `str.encode("punycode")`
        assert_eq!(punycode_decode("pple-43d").as_deref(), Some("\u{430}pple"));
        assert_eq!(punycode_decode("80ak6aa92e").as_deref(), Some("\u{430}\u{440}\u{440}\u{4cf}\u{435}"));
        assert_eq!(punycode_decode("mnchen-3ya").as_deref(), Some("m\u{fc}nchen"));
        assert_eq!(punycode_decode("p1ai").as_deref(), Some("\u{440}\u{444}"));
        assert_eq!(punycode_decode("bcher-kva").as_deref(), Some("b\u{fc}cher"));
        assert_eq!(punycode_decode("!!"), None);
        assert_eq!(punycode_decode("zzzzzzzzzzzz"), None, "overflow must fail, not wrap");
    }

    #[test]
    fn a_lookalike_of_a_listed_domain_is_caught() {
        let w = whitelist(&["apple.com", "paypal.com", "example.com", "co.uk"]);
        // Cyrillic а + pple
        assert_eq!(impersonated("xn--pple-43d.com", &w), Some("apple.com"));
        // all-Cyrillic аррӏе
        assert_eq!(impersonated("xn--80ak6aa92e.com", &w), Some("apple.com"));
        // a subdomain of the lookalike still names what it impersonates
        assert_eq!(impersonated("login.xn--pple-43d.com", &w), Some("apple.com"));
    }

    #[test]
    fn ordinary_idns_are_left_alone() {
        let w = whitelist(&["apple.com", "munchen.de", "bucher.de", "example.com", "co.uk"]);
        // accented letters are not mapped: münchen.de is not a homograph of munchen.de
        assert_eq!(impersonated("xn--mnchen-3ya.de", &w), None);
        assert_eq!(impersonated("xn--bcher-kva.de", &w), None);
        // an IDN subdomain of a real site is not a disguise of that site
        assert_eq!(impersonated("xn--pple-43d.example.com", &w), None);
        // a Cyrillic word that is no listed name
        assert_eq!(impersonated("xn--80ak6aa92e.xn--p1ai", &w), None);
        // the plain ASCII names themselves
        assert_eq!(impersonated("apple.com", &w), None);
    }
}
