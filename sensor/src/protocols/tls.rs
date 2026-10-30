//! TLS ClientHello SNI extraction and client fingerprinting — a port of
//! `core/tls_intel.py:parse_client_hello()`.
//!
//! The SNI feeds the domain check on encrypted traffic; the
//! JA3/JA4 client fingerprints are matched against the trail set the same way certificate
//! SHA-1s are (fingerprint feeds publish exactly these digests). Certificate parsing for the
//! *reporting* side lives in `core/tls_intel.py`; the sensor's server-flight half is in
//! `server_certificate_der` below.
//!
//! All reads are bounds-checked; a malformed or truncated handshake yields `None`, never a
//! panic. The byte-level tolerances mirror `core/tls_intel.py` exactly, so both produce the
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
/// `lowercase_only` mirrors the two slightly different patterns in `core/`:
/// `tls_intel` lower-cases first and validates `[a-z0-9_]`, while `quic_sni` validates
/// case-insensitively without lower-casing.
pub fn is_hostname(value: &str, lowercase_only: bool) -> bool {
    is_hostname_bytes(value.as_bytes(), lowercase_only)
}

/// `is_hostname` in one pass over raw bytes; anything non-ASCII fails it.
fn is_hostname_bytes(b: &[u8], lowercase_only: bool) -> bool {
    if b.is_empty() || b.len() > 253 {
        return false;
    }
    let mut dots = 0usize;
    let mut label = 0usize;
    for &c in b {
        if c == b'.' {
            if label == 0 {
                return false;
            }
            dots += 1;
            label = 0;
            continue;
        }
        let letter = if lowercase_only { c.is_ascii_lowercase() } else { c.is_ascii_alphabetic() };
        if !(letter || c.is_ascii_digit() || c == b'_' || (c == b'-' && label > 0)) {
            return false;
        }
        label += 1;
        if label > 63 {
            return false;
        }
    }
    // The pattern requires at least one "label." group before the final label.
    label > 0 && dots >= 1
}

pub use crate::trails::{FP_JA3, FP_JA4};

/// What a ClientHello yields once parsed: the SNI (if any) plus both client fingerprints.
pub struct ClientHello<'a> {
    /// Borrowed from the packet unless lower-casing changed it.
    pub sni: Option<std::borrow::Cow<'a, str>>,
    /// MD5 of the JA3 string - the form JA3 feeds publish (`ja3` in `core/tls_intel.py`).
    pub ja3: String,
    /// The JA4 client fingerprint, `t13d0605h2_..._...`.
    pub ja4: String,
}

impl ClientHello<'_> {
    /// Detached from the bytes it was parsed from.
    pub fn into_owned(self) -> ClientHello<'static> {
        ClientHello { sni: self.sni.map(|s| std::borrow::Cow::Owned(s.into_owned())), ja3: self.ja3, ja4: self.ja4 }
    }
}

/// `core/tls_intel.py:_is_grease()` - the reserved "GREASE" values a real stack may sprinkle
/// through its cipher and extension lists; fingerprints must ignore them or every
/// GREASE-generating client would hash uniquely.
fn is_grease(v: u16) -> bool {
    let hb = (v >> 8) & 0xff;
    let lb = v & 0xff;
    hb == lb && (lb & 0x0f) == 0x0a
}

/// The SNI alone (lower-cased, as `core/tls_intel.py:_parse_sni()` returns it), read the way
/// `parse_client_hello` reads it but without building the fingerprints - for the first segment of a ClientHello whose rest is still in flight, which is
/// parsed in full once it has arrived.
pub fn client_hello_sni(data: &[u8]) -> Option<String> {
    let mut r = Reader::new(data);
    if r.b.first() == Some(&0x16) {
        r.take(5)?;
    }
    if r.u8()? != 0x01 {
        return None;
    }
    r.u24()?;
    r.take(2 + 32)?;
    let sid_len = r.u8()? as usize;
    r.take(sid_len)?;
    let cs_len = r.u16()? as usize;
    r.take(cs_len)?;
    let comp_len = r.u8()? as usize;
    r.take(comp_len)?;
    let ext_total = r.u16()? as usize;
    let eend = (r.p + ext_total).min(r.b.len());
    while r.p + 4 <= eend {
        let etype = r.u16()?;
        let elen = r.u16()? as usize;
        if r.p + elen > r.b.len() {
            return None;
        }
        let body = r.take(elen)?;
        if etype == 0x0000 {
            return sni_extension(body, true).ok().flatten().map(std::borrow::Cow::into_owned);
        }
    }
    None
}

/// Parse a TLS record (`0x16 ...`) or bare handshake message into SNI + JA3 + JA4,
/// byte-for-byte compatible with `core/tls_intel.py:_parse_client_hello()`: same tolerances
/// for truncation (the extension region is parsed as far as the buffer reaches, the fixed
/// fields are not), same GREASE filtering, same string forms before hashing.
pub fn parse_client_hello(data: &[u8]) -> Option<ClientHello<'_>> {
    parse_client_hello_with(data, FP_JA3 | FP_JA4)
}

/// `parse_client_hello`, computing only the fingerprints in `want` (`FP_JA3`, `FP_JA4`); the
/// others are left empty. Whether the hello parses, and its SNI, do not depend on `want`.
pub fn parse_client_hello_with(data: &[u8], want: u8) -> Option<ClientHello<'_>> {
    parse_client_hello_over(data, want, b't')
}

/// `parse_client_hello_with` for a ClientHello carried by `transport`: `b't'` (TCP) or `b'q'`
/// (QUIC), the first character of JA4 - `core/tls_intel.py:parse_client_hello(data, transport)`.
pub fn parse_client_hello_over(data: &[u8], want: u8, transport: u8) -> Option<ClientHello<'_>> {
    thread_local! {
        static SCRATCH: std::cell::RefCell<Scratch> = std::cell::RefCell::new(Scratch::default());
    }
    SCRATCH.with(|scratch| parse_client_hello_into(data, want, transport, &mut scratch.borrow_mut()))
}

/// The working lists of one parse. Kept per thread and cleared, not freed, so a ClientHello
/// costs the three Strings it returns instead of a dozen allocations.
#[derive(Default)]
struct Scratch {
    ciphers: Vec<u16>,
    ext_types: Vec<u16>,
    curves: Vec<u16>,
    ecpf: Vec<u8>,
    sig_algs: Vec<u16>,
    sup_vers: Vec<u16>,
    sorted: Vec<u16>,
    ja3_str: String,
    ja4_b: String,
    ja4_c: String,
}

fn parse_client_hello_into<'a>(data: &'a [u8], want: u8, transport: u8, w: &mut Scratch) -> Option<ClientHello<'a>> {
    let mut r = Reader::new(data);
    if r.b.first() == Some(&0x16) {
        r.take(5)?; // optional TLS record header
    }
    if r.u8()? != 0x01 {
        return None; // not a ClientHello
    }
    let hlen = r.u24()? as usize;
    // `core/tls_intel.py` caps the message end at what actually arrived and parses on ("tolerate
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
        return None; // tls_intel.py's reader raises past the buffer; the whole parse fails there
    }
    w.ciphers.clear();
    while r.p + 2 <= cend {
        let c = r.u16()?;
        if !is_grease(c) {
            w.ciphers.push(c);
        }
    }
    r.p = cend;
    let comp_len = r.u8()? as usize;
    r.take(comp_len)?;

    let mut sni = None;
    let mut alpn0: Option<&[u8]> = None;
    for list in [&mut w.ext_types, &mut w.curves, &mut w.sig_algs, &mut w.sup_vers] {
        list.clear();
    }
    w.ecpf.clear();
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
                w.ext_types.push(etype);
            }
            match etype {
                // `_parse_sni()` takes the name bytes BEFORE looking at the entry type, and
                // its `take()` raises past the body - a raised exception fails the WHOLE
                // tls_intel.py parse, unlike every list helper here (they loop on `left()`).
                0x0000 => match sni_extension(body, true) {
                    Ok(parsed) => sni = parsed,
                    Err(FatalTruncation) => return None,
                },
                0x000a => u16_list(body, true, true, &mut w.curves),
                0x000b => u8_list(body, true, &mut w.ecpf),
                0x000d => u16_list(body, true, true, &mut w.sig_algs),
                // `_parse_alpn_first()` is the one helper that can RAISE past its buffer
                // (the others loop on `left()`), and a raised exception fails the WHOLE
                // tls_intel.py parse - hence the Err arm. A short header only means "no ALPN".
                0x0010 => match alpn_first(body) {
                    Ok(alpn) => alpn0 = alpn,
                    Err(FatalTruncation) => return None,
                },
                0x002b => u8len_u16_list(body, true, &mut w.sup_vers),
                _ => {}
            }
        }
    }

    if want & (FP_JA3 | FP_JA4) == 0 {
        return Some(ClientHello { sni, ja3: String::new(), ja4: String::new() });
    }
    let ja3 = if want & FP_JA3 != 0 { ja3_digest(legacy_version, w) } else { String::new() };
    if want & FP_JA4 == 0 {
        return Some(ClientHello { sni, ja3, ja4: String::new() });
    }

    // JA4 (client): ja4_a _ ja4_b _ ja4_c.
    let ver = w.sup_vers.iter().copied().max().unwrap_or(legacy_version);
    let ver2 = match ver {
        0x0304 => "13",
        0x0303 => "12",
        0x0302 => "11",
        0x0301 => "10",
        0x0300 => "s3",
        _ => "00",
    };
    let nc = w.ciphers.len().min(99);
    let ne = w.ext_types.len().min(99);
    let mut ja4 = String::with_capacity(40);
    ja4.push(transport as char);
    ja4.push_str(ver2);
    ja4.push(if sni.is_some() { 'd' } else { 'i' });
    for n in [nc, ne] {
        ja4.push((b'0' + (n / 10) as u8) as char);
        ja4.push((b'0' + (n % 10) as u8) as char);
    }
    // First protocol's first+last byte, chr()-mapped exactly like the reference: `u8 as char`
    // IS chr(byte) (U+0000..U+00FF), so a non-ASCII ALPN byte lands in ja4_a verbatim - which
    // is what core/tls_intel.py produces too (chr() never raises for a byte; there is no
    // UnicodeEncodeError on this path).
    match alpn0 {
        Some(p) if !p.is_empty() => {
            ja4.push(p[0] as char);
            ja4.push(p[p.len() - 1] as char);
        }
        _ => ja4.push_str("00"), // no ALPN extension, or an empty protocol list
    }

    fn push_hex4(out: &mut String, list: &[u16]) {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        for (i, v) in list.iter().enumerate() {
            if i > 0 {
                out.push(',');
            }
            for shift in [12, 8, 4, 0] {
                out.push(HEX[(v >> shift) as usize & 0xf] as char);
            }
        }
    }
    w.sorted.clear();
    w.sorted.extend_from_slice(&w.ciphers);
    w.sorted.sort_unstable();
    w.ja4_b.clear();
    push_hex4(&mut w.ja4_b, &w.sorted);
    w.sorted.clear();
    w.sorted.extend(w.ext_types.iter().copied().filter(|e| *e != 0x0000 && *e != 0x0010));
    w.sorted.sort_unstable();
    w.ja4_c.clear();
    push_hex4(&mut w.ja4_c, &w.sorted);
    // No "_" when there are no signature algorithms (TLS 1.0/1.1 clients): FoxIO's spec, and what
    // Wireshark computes - see `core/tls_intel.py`.
    if !w.sig_algs.is_empty() {
        w.ja4_c.push('_');
        push_hex4(&mut w.ja4_c, &w.sig_algs);
    }
    ja4.push('_');
    push_sha256_12(&mut ja4, &w.ja4_b);
    ja4.push('_');
    push_sha256_12(&mut ja4, &w.ja4_c);

    Some(ClientHello { sni, ja3, ja4 })
}

/// Decimal, written directly: `write!` through core::fmt was the largest single cost of the
/// whole parse on a browser's 19-extension ClientHello.
fn push_dec(out: &mut String, v: u16) {
    let mut buf = [0u8; 5];
    let mut i = buf.len();
    let mut v = v;
    loop {
        i -= 1;
        buf[i] = b'0' + (v % 10) as u8;
        v /= 10;
        if v == 0 {
            break;
        }
    }
    for &d in &buf[i..] {
        out.push(d as char);
    }
}

fn append_dec(out: &mut String, list: &[u16]) {
    for (i, v) in list.iter().enumerate() {
        if i > 0 {
            out.push('-');
        }
        push_dec(out, *v);
    }
}

/// The JA3 digest: MD5 of version,ciphers,extensions,curves,ecpf - dash-joined decimal lists.
fn ja3_digest(legacy_version: u16, w: &mut Scratch) -> String {
    let ja3_str = &mut w.ja3_str;
    ja3_str.clear();
    push_dec(ja3_str, legacy_version);
    ja3_str.push(',');
    append_dec(ja3_str, &w.ciphers);
    ja3_str.push(',');
    append_dec(ja3_str, &w.ext_types);
    ja3_str.push(',');
    append_dec(ja3_str, &w.curves);
    ja3_str.push(',');
    for (i, b) in w.ecpf.iter().enumerate() {
        if i > 0 {
            ja3_str.push('-');
        }
        push_dec(ja3_str, *b as u16);
    }
    use md5::Digest as Md5Digest;
    hex_lowercase(&md5::Md5::digest(ja3_str.as_bytes()))
}

/// Append the first 12 hex characters of SHA-256, as JA4 uses them, memoized per thread.
///
/// A network has few distinct TLS client stacks, and JA4's cipher and extension lists are sorted,
/// so the same two strings come back on almost every ClientHello - Chrome's shuffled extension
/// order included. The two SHA-256s were a quarter of the packet path on a handshake-heavy mix,
/// and a Raspberry Pi 4 has no SHA instructions to hide them. The memo is keyed by the exact
/// input, so a hit is the same answer, and it is emptied when full, so it cannot grow.
fn push_sha256_12(out: &mut String, input: &str) {
    use crate::fasthash::StrMap;
    use std::cell::RefCell;
    const MAX_ENTRIES: usize = 256;
    thread_local! {
        static MEMO: RefCell<StrMap<Box<str>, [u8; 12]>> = RefCell::new(StrMap::default());
    }
    MEMO.with(|memo| {
        let mut memo = memo.borrow_mut();
        let hex = match memo.get(input) {
            Some(hit) => *hit,
            None => {
                // `md5::Digest` and `sha2::Digest` are the same `digest::Digest` trait. Only the
                // first 12 hex chars are kept, so render 6 bytes rather than 32.
                use sha2::Digest as _;
                const HEX: &[u8; 16] = b"0123456789abcdef";
                let digest = sha2::Sha256::digest(input.as_bytes());
                let mut hex = [0u8; 12];
                for (i, b) in digest[..6].iter().enumerate() {
                    hex[2 * i] = HEX[(b >> 4) as usize];
                    hex[2 * i + 1] = HEX[(b & 0x0f) as usize];
                }
                if memo.len() >= MAX_ENTRIES {
                    memo.clear();
                }
                memo.insert(input.into(), hex);
                hex
            }
        };
        out.extend(hex.iter().map(|&c| c as char));
    })
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
fn u16_list(body: &[u8], skip_len2: bool, drop_grease: bool, out: &mut Vec<u16>) {
    let mut r = Reader::new(body);
    if skip_len2 && r.left() >= 2 {
        r.u16();
    }
    out.clear();
    while let Some(v) = r.u16() {
        if drop_grease && is_grease(v) {
            continue;
        }
        out.push(v);
    }
}

/// `core/tls_intel.py:_u8_list()`
fn u8_list(body: &[u8], skip_len1: bool, out: &mut Vec<u8>) {
    let mut r = Reader::new(body);
    if skip_len1 && r.left() >= 1 {
        r.u8();
    }
    out.clear();
    while let Some(v) = r.u8() {
        out.push(v);
    }
}

/// `core/tls_intel.py:_u8len_u16_list()`
fn u8len_u16_list(body: &[u8], drop_grease: bool, out: &mut Vec<u16>) {
    let mut r = Reader::new(body);
    if r.left() >= 1 {
        r.u8(); // 1-byte list length
    }
    out.clear();
    while let Some(v) = r.u16() {
        if drop_grease && is_grease(v) {
            continue;
        }
        out.push(v);
    }
}

/// Marks the one fatal malformation these helpers can hit: declared bytes running past the
/// extension body, which `core/tls_intel.py`'s `_Trunc` turns into "no fingerprint at all".
#[derive(Debug, PartialEq, Eq)]
pub struct FatalTruncation;

/// `core/tls_intel.py:_parse_alpn_first()` - the first protocol name offered, raw bytes.
///
/// Three outcomes, because the `core/tls_intel.py` helper mixes two failure styles: a cut-short fixed
/// header makes it RETURN None ("no ALPN offered" - parsing continues), while protocol-name
/// bytes overrunning the body make its `take()` RAISE `_Trunc` - and a raised exception
/// fails the WHOLE parse. `Ok(None)` vs `Err(FatalTruncation)` keeps those apart.
fn alpn_first(body: &[u8]) -> Result<Option<&[u8]>, FatalTruncation> {
    let mut r = Reader::new(body);
    if r.left() >= 2 {
        r.p += 2; // alpn list length (bounds only - the name length below is what matters)
        if r.left() >= 1 {
            let plen = r.u8().unwrap() as usize;
            return if r.left() >= plen {
                Ok(Some(r.take(plen).unwrap()))
            } else {
                Err(FatalTruncation) // `_Trunc` in tls_intel.py: no fingerprint at all
            };
        }
    }
    Ok(None)
}

/// `core/tls_intel.py:_parse_sni()`. Three outcomes, like `alpn_first`: `Ok(None)` covers
/// every survivable malformation (short list header, non-UTF8/non-ASCII/junk host, no
/// host_name entry), while `Err(FatalTruncation)` marks the one fatal case - an entry whose
/// declared name length overruns the extension body, where tls_intel.py's `take()` raises `_Trunc`
/// and the WHOLE ClientHello parse is discarded. (The QUIC path uses `quic.rs`'s own parser,
/// which treats that overrun as survivable - faithfully to `core/quic_sni.py`.)
pub fn parse_sni_extension(body: &[u8], lowercase: bool) -> Result<Option<String>, FatalTruncation> {
    sni_extension(body, lowercase).map(|host| host.map(std::borrow::Cow::into_owned))
}

/// `parse_sni_extension`, borrowing the name from `body` when it needs no lower-casing.
fn sni_extension(body: &[u8], lowercase: bool) -> Result<Option<std::borrow::Cow<'_, str>>, FatalTruncation> {
    use std::borrow::Cow;
    let mut r = Reader::new(body);
    if r.left() >= 2 {
        r.p += 2; // server_name_list length (bounds only)
        while r.left() >= 3 {
            // header reads cannot fail under `left() >= 3`
            let ntype = r.u8().unwrap();
            let nlen = r.u16().unwrap() as usize;
            let Some(name) = r.take(nlen) else { return Err(FatalTruncation) };
            if ntype == 0x00 {
                // Validated on the raw bytes, letters of either case: lower-casing first and then
                // accepting only lower case is the same test, and a non-ASCII or non-UTF-8 name
                // fails it either way.
                if !is_hostname_bytes(name, false) {
                    return Ok(None);
                }
                // SAFETY: `is_hostname_bytes` accepted it, so every byte is ASCII.
                let host = unsafe { std::str::from_utf8_unchecked(name) };
                return Ok(Some(if lowercase && name.iter().any(u8::is_ascii_uppercase) {
                    Cow::Owned(host.to_ascii_lowercase())
                } else {
                    Cow::Borrowed(host)
                }));
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

    #[test]
    fn sni_alone_agrees_with_the_full_parse() {
        for sni in ["evil.example", "a.b.c.example.com"] {
            let hello = client_hello(sni, true);
            assert_eq!(client_hello_sni(&hello), parse_client_hello(&hello).unwrap().sni.map(|s| s.into_owned()));
            for n in 0..hello.len() {
                let _ = client_hello_sni(&hello[..n]);
            }
        }
        assert_eq!(client_hello_sni(&client_hello("evil.example", false)).as_deref(), Some("evil.example"));
    }
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
    fn hostname_validation_agrees_with_the_regexes_exhaustively() {
        // Every string up to 6 bytes over an alphabet that exercises each rule, plus label and
        // total length edges; the patterns are core/tls_intel.py's and core/quic_sni.py's.
        let lower = regex::Regex::new(r"\A([a-z0-9_][a-z0-9_-]{0,62}\.)+[a-z0-9_][a-z0-9_-]{0,62}\z").unwrap();
        let any =
            regex::Regex::new(r"\A([a-zA-Z0-9_][a-zA-Z0-9_-]{0,62}\.)+[a-zA-Z0-9_][a-zA-Z0-9_-]{0,62}\z").unwrap();
        let alphabet = ["a", "Z", "0", "_", "-", ".", "\u{e9}"];
        let mut cases = vec![String::new()];
        let mut frontier = vec![String::new()];
        for _ in 0..6 {
            frontier = frontier.iter().flat_map(|s| alphabet.iter().map(move |c| format!("{s}{c}"))).collect();
            cases.extend(frontier.iter().cloned());
        }
        for (label, total) in [(63, 0), (64, 0), (63, 253 - 64), (63, 254 - 64)] {
            cases.push(format!("{}.{}", "a".repeat(total.max(1)), "b".repeat(label)));
        }
        for s in &cases {
            let ok = |re: &regex::Regex| s.len() <= 253 && re.is_match(s);
            assert_eq!(is_hostname(s, true), ok(&lower), "{s:?} lower-case only");
            assert_eq!(is_hostname(s, false), ok(&any), "{s:?} either case");
        }
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
        assert_eq!(client_hello_sni(&r1).as_deref(), ch1.sni.as_deref());
        assert_eq!(client_hello_sni(&r2), None);
    }

    #[test]
    fn skipped_fingerprints_change_nothing_else() {
        let hellos = [build_client_hello("www.example.org", true), Vec::from_hex("1603010086010000820303111111111111111111111111111111111111111111111111111111111111111100000c13011302c02bc02f009c009e0100004d000a00080006001d00170018000d000800060403080404010010000e000c02683208687474702f312e31002b000504030403030000001600140000116d61696c2e6576696c2e6578616d706c65"), Vec::from_hex("16030100500100004c030322222222222222222222222222222222222222222222222222222222222222220000081a1a13013a3ac02f0100001b000b0003020001000a000600041a1a001d000d0006000408040401")];
        for h in &hellos {
            let full = parse_client_hello(h).unwrap();
            for want in [0, FP_JA3, FP_JA4] {
                let part = parse_client_hello_with(h, want).unwrap();
                assert_eq!(part.sni, full.sni);
                assert_eq!(part.ja3, if want & FP_JA3 != 0 { full.ja3.clone() } else { String::new() });
                assert_eq!(part.ja4, if want & FP_JA4 != 0 { full.ja4.clone() } else { String::new() });
            }
            for n in 0..h.len() {
                assert_eq!(parse_client_hello_with(&h[..n], 0).is_some(), parse_client_hello(&h[..n]).is_some());
            }
        }
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
