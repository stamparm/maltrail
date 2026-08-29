//! TLS ClientHello SNI extraction and client fingerprinting — a port of
//! `core/tls_intel.py:parse_client_hello()`.
//!
//! The SNI feeds `core/fastfilter.py:head_sni()`'s domain check on encrypted traffic; the
//! JA3/JA4 client fingerprints are matched against the trail set the same way certificate
//! SHA-1s are (fingerprint feeds publish exactly these digests). Certificate parsing for the
//! *reporting* side lives in `core/tls_intel.py`; the sensor's server-flight half is in
//! `server_certificate_der` below.
//!
//! All reads are bounds-checked; a malformed or truncated handshake yields `None`, never a
//! panic. The byte-level tolerances mirror the Python parser exactly, so both produce the
//! same JA3/JA4 for the same captured bytes.

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

/// What a ClientHello yields once parsed: the SNI (if any) plus both client fingerprints.
pub struct ClientHello {
    pub sni: Option<String>,
    /// MD5 of the JA3 string - the form JA3 feeds publish (`ja3` in `core/tls_intel.py`).
    pub ja3: String,
    /// The JA4 client fingerprint, `t13d0605h2_..._...`.
    pub ja4: String,
}

/// `core/tls_intel.py:_is_grease()` - the reserved "GREASE" values a real stack may sprinkle
/// through its cipher and extension lists; fingerprints must ignore them or every
/// GREASE-generating client would hash uniquely.
fn is_grease(v: u16) -> bool {
    let hb = (v >> 8) & 0xff;
    let lb = v & 0xff;
    hb == lb && (lb & 0x0f) == 0x0a
}

/// Parse a TLS record (`0x16 ...`) or bare handshake message into SNI + JA3 + JA4,
/// byte-for-byte compatible with `core/tls_intel.py:_parse_client_hello()`: same tolerances
/// for truncation (the extension region is parsed as far as the buffer reaches, the fixed
/// fields are not), same GREASE filtering, same string forms before hashing.
pub fn parse_client_hello(data: &[u8]) -> Option<ClientHello> {
    let mut r = Reader::new(data);
    if r.b.first() == Some(&0x16) {
        r.take(5)?; // optional TLS record header
    }
    if r.u8()? != 0x01 {
        return None; // not a ClientHello
    }
    let hlen = r.u24()? as usize;
    // Python caps the message end at what actually arrived and parses on ("tolerate
    // truncation; parse what we have") rather than failing - so an overlong hlen is not an
    // error here either; every read below is bounds-checked on its own.
    let _ = hlen;
    let legacy_version = r.u16()?;
    r.take(32)?; // random
    let sid_len = r.u8()? as usize;
    r.take(sid_len)?;
    let cs_len = r.u16()? as usize;
    let cend = r.p.checked_add(cs_len)?;
    if cend > r.b.len() {
        return None; // Python's reader raises past the buffer; the whole parse fails there
    }
    let mut ciphers = Vec::with_capacity(cs_len / 2);
    while r.p + 2 <= cend {
        let c = r.u16()?;
        if !is_grease(c) {
            ciphers.push(c);
        }
    }
    r.p = cend;
    let comp_len = r.u8()? as usize;
    r.take(comp_len)?;

    let mut sni = None;
    let mut alpn0: Option<Vec<u8>> = None;
    let mut ext_types = Vec::new();
    let mut curves = Vec::new();
    let mut ecpf = Vec::new();
    let mut sig_algs = Vec::new();
    let mut sup_vers = Vec::new();
    if r.left() >= 2 {
        let ext_total = r.u16()? as usize;
        let eend = (r.p + ext_total).min(r.b.len());
        while r.p + 4 <= eend {
            let etype = r.u16()?;
            let elen = r.u16()? as usize;
            if r.p + elen > r.b.len() {
                break;
            }
            let body = r.take(elen)?;
            if !is_grease(etype) {
                ext_types.push(etype);
            }
            match etype {
                // `_parse_sni()` takes the name bytes BEFORE looking at the entry type, and
                // its `take()` raises past the body - a raised exception fails the WHOLE
                // Python parse, unlike every list helper here (they loop on `left()`).
                0x0000 => match parse_sni_extension(body, true) {
                    Ok(parsed) => sni = parsed,
                    Err(FatalTruncation) => return None,
                },
                0x000a => curves = u16_list(body, true, true)?,
                0x000b => ecpf = u8_list(body, true)?,
                0x000d => sig_algs = u16_list(body, true, true)?,
                // `_parse_alpn_first()` is the one helper that can RAISE past its buffer
                // (the others loop on `left()`), and a raised exception fails the WHOLE
                // Python parse - hence the Err arm. A short header only means "no ALPN".
                0x0010 => match alpn_first(body) {
                    Ok(alpn) => alpn0 = alpn,
                    Err(FatalTruncation) => return None,
                },
                0x002b => sup_vers = u8len_u16_list(body, true)?,
                _ => {}
            }
        }
    }

    // JA3: version,ciphers,extensions,curves,ecpf - dash-joined decimal lists.
    // One String per list instead of one per ELEMENT plus a Vec plus the join buffer. `write!`
    // of a u16 into a String appends the same decimal digits `to_string()` would produce.
    use core::fmt::Write as _;
    let join_dec = |list: &[u16]| {
        let mut out = String::with_capacity(list.len() * 6);
        for (i, v) in list.iter().enumerate() {
            if i > 0 {
                out.push('-');
            }
            let _ = write!(out, "{v}");
        }
        out
    };
    let ja3_str = format!(
        "{},{},{},{},{}",
        legacy_version,
        join_dec(&ciphers),
        join_dec(&ext_types),
        join_dec(&curves),
        join_dec(&(ecpf.iter().map(|b| *b as u16).collect::<Vec<_>>())),
    );
    use md5::Digest as Md5Digest;
    let ja3 = hex_lowercase(&md5::Md5::digest(ja3_str.as_bytes()));

    // JA4 (client): ja4_a _ ja4_b _ ja4_c.
    let ver = sup_vers.iter().copied().max().unwrap_or(legacy_version);
    let ver2 = match ver {
        0x0304 => "13",
        0x0303 => "12",
        0x0302 => "11",
        0x0301 => "10",
        0x0300 => "s3",
        _ => "00",
    };
    let sni_flag = if sni.is_some() { "d" } else { "i" };
    let nc = ciphers.len().min(99);
    let ne = ext_types.len().min(99);
    // First protocol's first+last byte, chr()-mapped exactly like the reference: `u8 as char`
    // IS chr(byte) (U+0000..U+00FF), so a non-ASCII ALPN byte lands in ja4_a verbatim - which
    // is what core/tls_intel.py produces too (chr() never raises for a byte; there is no
    // UnicodeEncodeError on this path).
    let alpn2 = match alpn0 {
        Some(ref p) if !p.is_empty() => format!("{}{}", p[0] as char, p[p.len() - 1] as char),
        _ => "00".to_string(), // no ALPN extension, or an empty protocol list
    };
    let ja4_a = format!("t{ver2}{sni_flag}{nc:02}{ne:02}{alpn2}");
    let mut sorted_ciphers = ciphers.clone();
    sorted_ciphers.sort_unstable();
    let join_hex4 = |list: &[u16]| {
        let mut out = String::with_capacity(list.len() * 5);
        for (i, v) in list.iter().enumerate() {
            if i > 0 {
                out.push(',');
            }
            let _ = write!(out, "{v:04x}");
        }
        out
    };
    let ja4_b_str = join_hex4(&sorted_ciphers);
    let mut exts_for_c: Vec<u16> = ext_types.iter().copied().filter(|e| *e != 0x0000 && *e != 0x0010).collect();
    exts_for_c.sort_unstable();
    let ja4_c_str = format!("{}_{}", join_hex4(&exts_for_c), join_hex4(&sig_algs));
    // NOTE: `md5::Digest` and `sha2::Digest` are the same `digest::Digest` trait (both crates
    // build on digest 0.10), so the single import above serves Sha256::digest too.
    // Only the first 12 hex chars are kept, so render 6 bytes rather than 32 and discard 20.
    let sha256_12 = |s: &[u8]| hex_lowercase(&sha2::Sha256::digest(s)[..6]);
    let ja4 = format!("{}_{}_{}", ja4_a, sha256_12(ja4_b_str.as_bytes()), sha256_12(ja4_c_str.as_bytes()));

    Some(ClientHello { sni, ja3, ja4 })
}

/// Extract the SNI from a TLS record (`0x16 ...`) or a bare handshake message.
/// Returns the lower-cased host name, matching `core/tls_intel.py:_parse_sni()`.
pub fn client_hello_sni(data: &[u8]) -> Option<String> {
    parse_client_hello(data).and_then(|ch| ch.sni)
}

/// Lower-case hex, written a nibble at a time.
///
/// Was `bytes.iter().map(|b| format!("{b:02x}")).collect()`, which allocates a String PER BYTE
/// and then a final one to concatenate them - 33 allocations to render a 32-byte digest. Every
/// TLS ClientHello on the wire pays this three times (one MD5 for JA3, two SHA-256 for JA4).
/// Byte-for-byte identical output; `{:02x}` on a u8 is exactly these two nibbles.
fn hex_lowercase(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

/// `core/tls_intel.py:_u16_list()`
fn u16_list(body: &[u8], skip_len2: bool, drop_grease: bool) -> Option<Vec<u16>> {
    let mut r = Reader::new(body);
    if skip_len2 && r.left() >= 2 {
        r.u16();
    }
    let mut out = Vec::new();
    while r.left() >= 2 {
        let v = r.u16()?;
        if drop_grease && is_grease(v) {
            continue;
        }
        out.push(v);
    }
    Some(out)
}

/// `core/tls_intel.py:_u8_list()`
fn u8_list(body: &[u8], skip_len1: bool) -> Option<Vec<u8>> {
    let mut r = Reader::new(body);
    if skip_len1 && r.left() >= 1 {
        r.u8();
    }
    let mut out = Vec::new();
    while r.left() >= 1 {
        out.push(r.u8()?);
    }
    Some(out)
}

/// `core/tls_intel.py:_u8len_u16_list()`
fn u8len_u16_list(body: &[u8], drop_grease: bool) -> Option<Vec<u16>> {
    let mut r = Reader::new(body);
    if r.left() >= 1 {
        r.u8(); // 1-byte list length
    }
    let mut out = Vec::new();
    while r.left() >= 2 {
        let v = r.u16()?;
        if drop_grease && is_grease(v) {
            continue;
        }
        out.push(v);
    }
    Some(out)
}

/// Marks the one fatal malformation these helpers can hit: declared bytes running past the
/// extension body, which Python's `_Trunc` turns into "no fingerprint at all".
#[derive(Debug, PartialEq, Eq)]
pub struct FatalTruncation;

/// `core/tls_intel.py:_parse_alpn_first()` - the first protocol name offered, raw bytes.
///
/// Three outcomes, because the Python helper mixes two failure styles: a cut-short fixed
/// header makes it RETURN None ("no ALPN offered" - parsing continues), while protocol-name
/// bytes overrunning the body make its `take()` RAISE `_Trunc` - and a raised exception
/// fails the WHOLE parse. `Ok(None)` vs `Err(FatalTruncation)` keeps those apart.
fn alpn_first(body: &[u8]) -> Result<Option<Vec<u8>>, FatalTruncation> {
    let mut r = Reader::new(body);
    if r.left() >= 2 {
        r.p += 2; // alpn list length (bounds only - the name length below is what matters)
        if r.left() >= 1 {
            let plen = r.u8().unwrap() as usize;
            return if r.left() >= plen {
                Ok(Some(r.take(plen).unwrap().to_vec()))
            } else {
                Err(FatalTruncation) // `_Trunc` on the Python side: no fingerprint at all
            };
        }
    }
    Ok(None)
}

/// `core/tls_intel.py:_parse_sni()`. Three outcomes, like `alpn_first`: `Ok(None)` covers
/// every survivable malformation (short list header, non-UTF8/non-ASCII/junk host, no
/// host_name entry), while `Err(FatalTruncation)` marks the one fatal case - an entry whose
/// declared name length overruns the extension body, where Python's `take()` raises `_Trunc`
/// and the WHOLE ClientHello parse is discarded. (The QUIC path uses `quic.rs`'s own parser,
/// which treats that overrun as survivable - faithfully to `core/quic_sni.py`.)
pub fn parse_sni_extension(body: &[u8], lowercase: bool) -> Result<Option<String>, FatalTruncation> {
    let mut r = Reader::new(body);
    if r.left() >= 2 {
        r.p += 2; // server_name_list length (bounds only)
        while r.left() >= 3 {
            // header reads cannot fail under `left() >= 3`
            let ntype = r.u8().unwrap();
            let nlen = r.u16().unwrap() as usize;
            let Some(name) = r.take(nlen) else { return Err(FatalTruncation) };
            if ntype == 0x00 {
                let Ok(host) = std::str::from_utf8(name) else { return Ok(None) };
                if !host.is_ascii() {
                    return Ok(None);
                }
                let host = if lowercase { host.to_ascii_lowercase() } else { host.to_string() };
                return Ok(if is_hostname(&host, lowercase) { Some(host) } else { None });
            }
        }
    }
    Ok(None)
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
    use vectors::FromHex;

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
        assert_eq!(parse_sni_extension(&lst, true), Ok(None));
    }

    /// Vectors generated by `core/tls_intel.py:parse_client_hello()` over these exact bytes -
    /// the cross-language contract the trail matching depends on. Regenerate with:
    ///
    ///   python3 -c "import sys; sys.path.insert(0,'.'); \
    ///     from core.tls_intel import parse_client_hello as p; \
    ///     h=bytes.fromhex('<R1HEX>'); o=p(h); print(o['sni'],o['ja3'],o['ja4'])"
    #[test]
    fn ja3_ja4_match_the_python_reference_implementation() {
        // hello 1: TLS 1.3-ish stack, SNI + ALPN + supported_versions, no GREASE
        let r1 = Vec::from_hex("1603010086010000820303111111111111111111111111111111111111111111111111111111111111111100000c13011302c02bc02f009c009e0100004d000a00080006001d00170018000d000800060403080404010010000e000c02683208687474702f312e31002b000504030403030000001600140000116d61696c2e6576696c2e6578616d706c65");
        let ch1 = parse_client_hello(&r1).expect("well-formed hello parses");
        assert_eq!(ch1.sni.as_deref(), Some("mail.evil.example"));
        assert_eq!(ch1.ja3, "d190f828263095de150a20b19136e314");
        assert_eq!(ch1.ja4, "t13d0605h2_72b63408b255_beb9f91c6f80");

        // hello 2: GREASE ciphers/extensions dropped from the fingerprint, EC point formats
        // carried into JA3's last field, no SNI ('i'), no ALPN ("00"), legacy version only
        let r2 = Vec::from_hex("16030100500100004c030322222222222222222222222222222222222222222222222222222222222222220000081a1a13013a3ac02f0100001b000b0003020001000a000600041a1a001d000d0006000408040401");
        let ch2 = parse_client_hello(&r2).expect("well-formed hello parses");
        assert_eq!(ch2.sni, None);
        assert_eq!(ch2.ja3, "a20735de562085796a564839bc8368cc");
        assert_eq!(ch2.ja4, "t12i020300_c1929292aa6b_7c9dbb57f4ec");

        // and the SNI-only helper still agrees with the full parse on both
        assert_eq!(client_hello_sni(&r1), ch1.sni);
        assert_eq!(client_hello_sni(&r2), None);
    }

    #[test]
    fn truncated_fingerprints_never_panic_and_may_still_parse() {
        let full = client_hello("evil.com", true);
        for n in 0..full.len() {
            let _ = parse_client_hello(&full[..n]);
        }
    }
}

#[cfg(test)]
/// hex literal helper so the python-generated vectors read as one token
mod vectors {
    pub trait FromHex {
        fn from_hex(s: &str) -> Vec<u8>;
    }
    impl FromHex for Vec<u8> {
        fn from_hex(s: &str) -> Vec<u8> {
            (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
        }
    }
}

/// The leaf (first) certificate of a TLS **server** flight, as raw DER.
///
/// `core/tls_intel.py` parses this on the reporting side for CN/SAN; the sensor needs the bytes
/// themselves, because the indicator published by threat feeds is the certificate's SHA-1
/// fingerprint (abuse.ch SSLBL and friends list exactly that).
///
/// # What this can and cannot see
///
/// TLS 1.3 encrypts the Certificate message, so this only ever fires on 1.2 and below. That is
/// not the limitation it sounds like for this purpose: the negotiated version is capped by what
/// the *client* offers, and the implants these fingerprints identify — .NET RATs, old Java team
/// servers, hand-rolled stacks — offer 1.2. Self-signed single-certificate flights, which is
/// what a C2 typically presents, also fit inside one TCP segment, so they survive the sensor's
/// lack of stream reassembly. A chained CA-issued certificate usually will not, and is missed.
///
/// Walks the record layer because ServerHello and Certificate are separate handshake messages
/// that share a flight and are frequently coalesced into one record or split across several.
/// Every read is bounds-checked; malformed input yields `None`, never a panic.
pub fn server_certificate_der(data: &[u8]) -> Option<&[u8]> {
    let mut r = Reader::new(data);
    // Reassemble nothing: scan the handshake messages that are present in THIS buffer.
    while r.left() >= 5 {
        if *r.b.get(r.p)? != 0x16 {
            return None; // not (or no longer) a handshake record
        }
        r.take(3)?; // content type + legacy version
        let rec_len = r.u16()? as usize;
        let body = r.take(rec_len.min(r.left()))?;

        let mut h = Reader::new(body);
        while h.left() >= 4 {
            let msg_type = h.u8()?;
            let msg_len = h.u24()? as usize;
            // A message may be truncated by the snaplen or by segmentation; take what is here.
            let msg = h.take(msg_len.min(h.left()))?;
            if msg_type != 0x0b {
                continue; // 11 == Certificate
            }
            let mut c = Reader::new(msg);
            let list_len = c.u24()? as usize;
            let list = c.take(list_len.min(c.left()))?;
            let mut l = Reader::new(list);
            let cert_len = l.u24()? as usize;
            // Only a complete leaf certificate can be fingerprinted: hashing a truncated one
            // produces a digest that matches nothing, which would look like "no detection"
            // rather than "could not see it".
            if cert_len == 0 || cert_len > l.left() {
                return None;
            }
            return l.take(cert_len);
        }
    }
    None
}

#[cfg(test)]
mod cert_tests {
    use super::*;

    /// Wrap a DER blob in Certificate -> handshake -> record, as a server would send it.
    fn flight(der: &[u8], with_server_hello: bool) -> Vec<u8> {
        let mut hs = Vec::new();
        if with_server_hello {
            // A minimal ServerHello ahead of it, since that is the real coalesced shape.
            let sh_body = vec![0u8; 38];
            hs.push(0x02);
            hs.extend_from_slice(&[0, 0, sh_body.len() as u8]);
            hs.extend_from_slice(&sh_body);
        }
        let mut certmsg = Vec::new();
        let entry_len = der.len();
        let list_len = entry_len + 3;
        certmsg.extend_from_slice(&[(list_len >> 16) as u8, (list_len >> 8) as u8, list_len as u8]);
        certmsg.extend_from_slice(&[(entry_len >> 16) as u8, (entry_len >> 8) as u8, entry_len as u8]);
        certmsg.extend_from_slice(der);
        hs.push(0x0b);
        hs.extend_from_slice(&[(certmsg.len() >> 16) as u8, (certmsg.len() >> 8) as u8, certmsg.len() as u8]);
        hs.extend_from_slice(&certmsg);

        let mut out = vec![0x16, 0x03, 0x03, (hs.len() >> 8) as u8, hs.len() as u8];
        out.extend_from_slice(&hs);
        out
    }

    #[test]
    fn extracts_the_leaf_certificate() {
        let der: Vec<u8> = (0..200u32).map(|i| i as u8).collect();
        assert_eq!(server_certificate_der(&flight(&der, false)), Some(&der[..]));
    }

    #[test]
    fn skips_the_server_hello_in_the_same_flight() {
        let der: Vec<u8> = (0..300u32).map(|i| (i % 251) as u8).collect();
        assert_eq!(server_certificate_der(&flight(&der, true)), Some(&der[..]));
    }

    #[test]
    fn a_client_hello_is_not_a_certificate() {
        assert_eq!(server_certificate_der(&build_client_hello("example.com", true)), None);
    }

    #[test]
    fn a_truncated_certificate_is_refused_rather_than_half_hashed() {
        let der: Vec<u8> = (0..400u32).map(|i| i as u8).collect();
        let full = flight(&der, false);
        for cut in [8, 20, 60, 120, full.len() - 1] {
            assert_eq!(server_certificate_der(&full[..cut]), None, "cut at {cut}");
        }
    }

    #[test]
    fn never_panics_on_arbitrary_input() {
        let mut state = 0x1234_5678u32;
        for _ in 0..20_000 {
            let mut buf = Vec::new();
            state = state.wrapping_mul(1_103_515_245).wrapping_add(12_345);
            let n = (state >> 16) as usize % 300;
            for _ in 0..n {
                state = state.wrapping_mul(1_103_515_245).wrapping_add(12_345);
                buf.push((state >> 16) as u8);
            }
            if !buf.is_empty() {
                buf[0] = 0x16; // steer most of it into the parser proper
            }
            let _ = server_certificate_der(&buf);
        }
    }
}
