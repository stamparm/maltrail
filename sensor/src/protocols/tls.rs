//! TLS ClientHello SNI extraction — the `sni` half of
//! `core/tls_intel.py:parse_client_hello()`.
//!
//! Only the SNI is needed: `core/fastfilter.py:head_sni()` feeds it straight into
//! `_check_domain`. JA3/JA4/certificate parsing lives on the reporting side and is not
//! part of the sensor's detection path.
//!
//! All reads are bounds-checked; a malformed or truncated handshake yields `None`.

/// Bounds-checked sequential reader (`core/tls_intel.py:_Reader`).
struct Reader<'a> {
    b: &'a [u8],
    p: usize,
}

impl<'a> Reader<'a> {
    fn new(b: &'a [u8]) -> Reader<'a> {
        Reader { b, p: 0 }
    }

    fn u8(&mut self) -> Option<u8> {
        let v = *self.b.get(self.p)?;
        self.p += 1;
        Some(v)
    }

    fn u16(&mut self) -> Option<u16> {
        let s = self.b.get(self.p..self.p + 2)?;
        self.p += 2;
        Some(u16::from_be_bytes([s[0], s[1]]))
    }

    fn u24(&mut self) -> Option<u32> {
        let s = self.b.get(self.p..self.p + 3)?;
        self.p += 3;
        Some(((s[0] as u32) << 16) | ((s[1] as u32) << 8) | s[2] as u32)
    }

    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let s = self.b.get(self.p..self.p.checked_add(n)?)?;
        self.p += n;
        Some(s)
    }

    fn left(&self) -> usize {
        self.b.len().saturating_sub(self.p)
    }
}

/// `core/tls_intel.py:_is_hostname()` — an ASCII A-label host (RFC 6066).
/// `lowercase_only` mirrors the two slightly different patterns in the Python tree:
/// `tls_intel` lower-cases first and validates `[a-z0-9_]`, while `quic_sni` validates
/// case-insensitively without lower-casing.
pub fn is_hostname(value: &str, lowercase_only: bool) -> bool {
    if value.is_empty() || value.len() > 253 {
        return false;
    }
    let ok_first = |c: u8| {
        c.is_ascii_digit()
            || c == b'_'
            || (if lowercase_only { c.is_ascii_lowercase() } else { c.is_ascii_alphabetic() })
    };
    let ok_rest = |c: u8| ok_first(c) || c == b'-';

    let mut labels = 0usize;
    for label in value.split('.') {
        let bytes = label.as_bytes();
        if bytes.is_empty() || bytes.len() > 63 {
            return false;
        }
        if !ok_first(bytes[0]) {
            return false;
        }
        if !bytes[1..].iter().copied().all(ok_rest) {
            return false;
        }
        labels += 1;
    }
    // The pattern requires at least one "label." group before the final label.
    labels >= 2
}

/// Extract the SNI from a TLS record (`0x16 ...`) or a bare handshake message.
/// Returns the lower-cased host name, matching `core/tls_intel.py:_parse_sni()`.
pub fn client_hello_sni(data: &[u8]) -> Option<String> {
    let mut r = Reader::new(data);
    if r.b.first() == Some(&0x16) {
        r.take(5)?; // optional TLS record header
    }
    if r.u8()? != 0x01 {
        return None; // not a ClientHello
    }
    let _hlen = r.u24()?;
    let _legacy_version = r.u16()?;
    r.take(32)?; // random
    let sid_len = r.u8()? as usize;
    r.take(sid_len)?;
    let cs_len = r.u16()? as usize;
    // Python advances straight to the end of the cipher list (clamped by the reader).
    let cend = r.p.checked_add(cs_len)?;
    if cend > r.b.len() {
        return None;
    }
    r.p = cend;
    let comp_len = r.u8()? as usize;
    r.take(comp_len)?;

    if r.left() < 2 {
        return None;
    }
    let ext_total = r.u16()? as usize;
    let eend = (r.p + ext_total).min(r.b.len());
    while r.p + 4 <= eend {
        let etype = r.u16()?;
        let elen = r.u16()? as usize;
        if r.p + elen > r.b.len() {
            break;
        }
        let body = r.take(elen)?;
        if etype == 0x0000 {
            return parse_sni_extension(body, true);
        }
    }
    None
}

/// `core/tls_intel.py:_parse_sni()` / `core/quic_sni.py`'s inline equivalent.
pub fn parse_sni_extension(body: &[u8], lowercase: bool) -> Option<String> {
    let mut r = Reader::new(body);
    if r.left() < 2 {
        return None;
    }
    r.u16()?; // server_name_list length
    while r.left() >= 3 {
        let ntype = r.u8()?;
        let nlen = r.u16()? as usize;
        let name = r.take(nlen)?;
        if ntype == 0x00 {
            let host = std::str::from_utf8(name).ok()?;
            if !host.is_ascii() {
                return None;
            }
            let host = if lowercase { host.to_ascii_lowercase() } else { host.to_string() };
            return if is_hostname(&host, lowercase) { Some(host) } else { None };
        }
    }
    None
}

/// Build a minimal TLS ClientHello carrying `sni` — mirrors
/// `tests/_pcapgen.py:tls_client_hello()`. Public so tests, benches, the fuzz targets and
/// the corpus generator all build the same bytes.
pub fn build_client_hello(sni: &str, with_record: bool) -> Vec<u8> {
    let s = sni.as_bytes();
    let mut srv = vec![0x00];
    srv.extend_from_slice(&(s.len() as u16).to_be_bytes());
    srv.extend_from_slice(s);
    let mut lst = (srv.len() as u16).to_be_bytes().to_vec();
    lst.extend_from_slice(&srv);
    let mut ext = vec![0x00, 0x00];
    ext.extend_from_slice(&(lst.len() as u16).to_be_bytes());
    ext.extend_from_slice(&lst);

    let mut body = vec![0x03, 0x03];
    body.extend_from_slice(&[0x11; 32]);
    body.push(0x00);
    body.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]);
    body.extend_from_slice(&[0x01, 0x00]);
    body.extend_from_slice(&(ext.len() as u16).to_be_bytes());
    body.extend_from_slice(&ext);

    let mut hs = vec![0x01];
    let l = (body.len() as u32).to_be_bytes();
    hs.extend_from_slice(&l[1..]);
    hs.extend_from_slice(&body);

    if with_record {
        let mut out = vec![0x16, 0x03, 0x03];
        out.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        out.extend_from_slice(&hs);
        out
    } else {
        hs
    }
}

#[cfg(test)]
mod tests {
    use super::build_client_hello as client_hello;
    use super::*;

    #[test]
    fn extracts_sni_with_and_without_record_header() {
        assert_eq!(client_hello_sni(&client_hello("evil.com", true)).as_deref(), Some("evil.com"));
        assert_eq!(client_hello_sni(&client_hello("evil.com", false)).as_deref(), Some("evil.com"));
    }

    #[test]
    fn lowercases_the_host() {
        assert_eq!(client_hello_sni(&client_hello("EVIL.CoM", true)).as_deref(), Some("evil.com"));
    }

    #[test]
    fn rejects_junk_hosts() {
        // single label, trailing dot, and non-host characters are all refused
        assert_eq!(client_hello_sni(&client_hello("localhost", true)), None);
        assert_eq!(client_hello_sni(&client_hello("evil.com.", true)), None);
        assert_eq!(client_hello_sni(&client_hello("ev il.com", true)), None);
        assert_eq!(client_hello_sni(&client_hello("", true)), None);
    }

    #[test]
    fn truncated_and_hostile_input_never_panics() {
        let full = client_hello("evil.com", true);
        for n in 0..full.len() {
            let _ = client_hello_sni(&full[..n]);
        }
        for pattern in [0x00u8, 0x16, 0x01, 0xff] {
            for n in 0..64 {
                let _ = client_hello_sni(&vec![pattern; n]);
            }
        }
        // an extension length that claims more than the buffer holds
        let mut bad = client_hello("evil.com", false);
        let len = bad.len();
        bad[len - 2] = 0xff;
        bad[len - 1] = 0xff;
        let _ = client_hello_sni(&bad);
    }

    #[test]
    fn hostname_validation_matches_the_python_regexes() {
        assert!(is_hostname("evil.com", true));
        assert!(is_hostname("a.b.c.example", true));
        assert!(is_hostname("_dmarc.example.com", true));
        assert!(!is_hostname("EVIL.com", true), "tls_intel validates after lower-casing");
        assert!(is_hostname("EVIL.com", false), "quic_sni validates case-insensitively");
        assert!(!is_hostname("nodot", true));
        assert!(!is_hostname("-bad.com", true));
        assert!(!is_hostname("bad..com", true));
        assert!(!is_hostname(&"a".repeat(254), true));
        assert!(!is_hostname(&format!("{}.com", "a".repeat(64)), true));
    }

    #[test]
    fn non_host_name_entries_are_skipped() {
        // an SNI list whose first entry is not host_name(0) must not yield a bogus name
        let mut srv = vec![0x02, 0x00, 0x03];
        srv.extend_from_slice(b"abc");
        let mut lst = (srv.len() as u16).to_be_bytes().to_vec();
        lst.extend_from_slice(&srv);
        assert_eq!(parse_sni_extension(&lst, true), None);
    }
}
